//! Hidden-process detection.
//!
//! Uses per-platform native APIs to enumerate running processes and
//! compares the result against an independent liveness probe. Any
//! PID that responds to the liveness probe but is *not* present in
//! the enumerated list is reported as potentially hidden by a
//! kernel- or userland-level rootkit.
//!
//! Platform matrix:
//!
//! | Platform | Enumeration                                     | Liveness probe                       |
//! |----------|-------------------------------------------------|---------------------------------------|
//! | Linux    | `/proc` directory listing                       | `kill(pid, 0)` via `nix`              |
//! | macOS    | `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_ALL)`    | `kill(pid, 0)` via `nix`              |
//! | Windows  | `CreateToolhelp32Snapshot` + `Process32NextW`   | `OpenProcess(…QUERY_LIMITED_INFORMATION…)` |
//! | Other    | no-op (returns empty list)                      | —                                     |

/// A PID that passed the liveness probe but did not appear in the
/// enumerated process list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenPid {
    pub pid: u32,
}

/// Scan for hidden processes.
///
/// `max_pid` bounds the upper end of the PID range probed with
/// `kill(pid, 0)` on Unix. On Linux this must be at least
/// `/proc/sys/kernel/pid_max`; values beyond that just waste cycles.
/// On macOS the same upper bound is used. On Windows the parameter
/// is only used to cap the Toolhelp32-derived probe range.
pub fn scan(max_pid: u32) -> Vec<HiddenPid> {
    #[cfg(target_os = "linux")]
    {
        linux_impl::scan(max_pid)
    }
    #[cfg(target_os = "macos")]
    {
        macos_impl::scan(max_pid)
    }
    #[cfg(target_os = "windows")]
    {
        windows_impl::scan(max_pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = max_pid;
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Shared Unix helper: `kill(pid, 0)` → Ok() iff process exists and caller has
// permission to signal it. `EPERM` is deliberately treated as "not present"
// so unprivileged runs don't flood with false positives.
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unix_pid_exists(pid: u32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    let Ok(raw_pid) = i32::try_from(pid) else {
        return false;
    };
    matches!(kill(Pid::from_raw(raw_pid), None), Ok(()))
}

// ---------------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::{unix_pid_exists, HiddenPid};
    use std::collections::HashSet;

    /// Enumerate PIDs visible via `/proc` directory listing.
    fn enumerate_proc_pids() -> HashSet<u32> {
        let mut pids = HashSet::new();

        let entries = match std::fs::read_dir("/proc") {
            Ok(e) => e,
            Err(_) => return pids,
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Ok(pid) = name.parse::<u32>() {
                pids.insert(pid);
            }
        }

        pids
    }

    pub fn scan(max_pid: u32) -> Vec<HiddenPid> {
        let visible = enumerate_proc_pids();
        let mut hidden = Vec::new();

        for pid in 1..=max_pid {
            if !visible.contains(&pid) && unix_pid_exists(pid) {
                hidden.push(HiddenPid { pid });
            }
        }

        hidden
    }
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::{unix_pid_exists, HiddenPid};
    use std::collections::HashSet;
    use std::mem;
    use std::os::raw::{c_int, c_uint, c_void};

    // `sysctl(3)` MIB selectors for `kinfo_proc`.
    // From <sys/sysctl.h>.
    const CTL_KERN: c_int = 1;
    const KERN_PROC: c_int = 14;
    const KERN_PROC_ALL: c_int = 0;

    // Size of `struct kinfo_proc` on macOS (arm64 and x86_64). Known
    // stable value; we only ever index into `kp_proc.p_pid`, which on
    // 64-bit Darwin sits at offset 40 of `struct extern_proc`:
    //   p_un        (union, 16 bytes)
    //   p_vmspace*  (8 bytes, offset 16)
    //   p_sigacts*  (8 bytes, offset 24)
    //   p_flag      (4 bytes, offset 32)
    //   p_stat      (1 byte,  offset 36) + 3 bytes padding
    //   p_pid       (4 bytes, offset 40)  ← this field
    const KINFO_PROC_SIZE: usize = 648;
    const KINFO_PROC_PID_OFFSET: usize = 40;

    /// Call `sysctl` twice: first to discover the size of the result
    /// buffer, then again to populate it. Returns the raw bytes the
    /// kernel wrote.
    fn sysctl_proc_all() -> Option<Vec<u8>> {
        let mut mib: [c_int; 3] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL];
        let mut size: libc::size_t = 0;

        // First call: size query.
        // SAFETY: `mib` is a fixed-length array of valid selector
        // values; we pass a null output pointer so sysctl only
        // populates `size`. No memory is read or written by the
        // kernel beyond the integers we own.
        let ret = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as c_uint,
                std::ptr::null_mut::<c_void>(),
                &mut size,
                std::ptr::null_mut::<c_void>(),
                0,
            )
        };
        if ret != 0 || size == 0 {
            return None;
        }

        // Over-allocate slightly in case processes spawn between the
        // two sysctl calls.
        let mut buf = vec![0u8; size + KINFO_PROC_SIZE];
        let mut actual = buf.len() as libc::size_t;

        // SAFETY: `buf` is a mutable owned allocation of `actual`
        // bytes; `sysctl` writes up to `actual` bytes into it and
        // updates `actual` with the number actually written.
        let ret = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as c_uint,
                buf.as_mut_ptr() as *mut c_void,
                &mut actual,
                std::ptr::null_mut::<c_void>(),
                0,
            )
        };
        if ret != 0 {
            return None;
        }
        buf.truncate(actual);
        Some(buf)
    }

    /// Walk the raw `sysctl` buffer, extracting one `p_pid` per
    /// `KINFO_PROC_SIZE`-sized record.
    fn enumerate_sysctl_pids() -> HashSet<u32> {
        let mut pids = HashSet::new();
        let buf = match sysctl_proc_all() {
            Some(b) => b,
            None => return pids,
        };

        let mut cursor = 0usize;
        while cursor + KINFO_PROC_PID_OFFSET + mem::size_of::<i32>() <= buf.len() {
            let slice = &buf[cursor + KINFO_PROC_PID_OFFSET
                ..cursor + KINFO_PROC_PID_OFFSET + mem::size_of::<i32>()];
            let pid = i32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]]);
            if pid > 0 {
                pids.insert(pid as u32);
            }
            cursor += KINFO_PROC_SIZE;
        }
        pids
    }

    pub fn scan(max_pid: u32) -> Vec<HiddenPid> {
        let visible = enumerate_sysctl_pids();
        if visible.is_empty() {
            // sysctl failed entirely; don't fabricate hidden-process
            // alerts from that.
            return Vec::new();
        }

        let mut hidden = Vec::new();
        for pid in 1..=max_pid {
            if !visible.contains(&pid) && unix_pid_exists(pid) {
                hidden.push(HiddenPid { pid });
            }
        }
        hidden
    }
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::HiddenPid;
    use std::collections::HashSet;

    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    /// Enumerate PIDs via the ToolHelp32 snapshot API.
    fn enumerate_snapshot_pids() -> Option<HashSet<u32>> {
        let mut pids = HashSet::new();

        // SAFETY: `CreateToolhelp32Snapshot` returns a handle we own
        // and must close exactly once; we close it at the bottom.
        let snap: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()? };

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        // SAFETY: `entry.dwSize` is set correctly before calling
        // `Process32FirstW`, as the docs require. Both calls read
        // through `&mut entry` which lives for the duration of the
        // loop.
        unsafe {
            if Process32FirstW(snap, &mut entry).is_ok() {
                loop {
                    if entry.th32ProcessID != 0 {
                        pids.insert(entry.th32ProcessID);
                    }
                    if Process32NextW(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snap);
        }

        Some(pids)
    }

    /// Liveness probe using OpenProcess with the least privileged
    /// access right that still works. Returns true iff the process
    /// exists and we can obtain a handle. Access-denied and
    /// invalid-parameter errors are treated as "not present" to
    /// avoid false positives for protected system PIDs no user-mode
    /// process can open.
    fn pid_exists(pid: u32) -> bool {
        // SAFETY: OpenProcess returns either a valid HANDLE we own
        // or an Err; we close the valid handle immediately.
        unsafe {
            match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(handle) => {
                    let _ = CloseHandle(handle);
                    true
                }
                Err(_) => false,
            }
        }
    }

    pub fn scan(max_pid: u32) -> Vec<HiddenPid> {
        let visible = match enumerate_snapshot_pids() {
            Some(v) if !v.is_empty() => v,
            _ => return Vec::new(),
        };

        // Windows PIDs are always multiples of 4. Probe every multiple
        // of 4 up to the larger of `max_pid` and the highest PID the
        // snapshot already enumerated, so we don't miss a hidden PID
        // that happens to be higher than the largest visible one.
        let Some(snapshot_max) = visible.iter().copied().max() else {
            return Vec::new();
        };
        let upper = max_pid.max(snapshot_max);

        let mut hidden = Vec::new();
        let mut pid: u32 = 4;
        while pid <= upper {
            if !visible.contains(&pid) && pid_exists(pid) {
                hidden.push(HiddenPid { pid });
            }
            match pid.checked_add(4) {
                Some(next) => pid = next,
                None => break,
            }
        }
        hidden
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_runs_to_completion_on_clean_system() {
        // The scan must always return a concrete (possibly empty)
        // list without panicking, even in environments where process
        // enumeration APIs are restricted (CI containers, PID
        // namespaces, sandboxed macOS runners).
        // We don't assert emptiness: on shared hosts, PID namespace
        // boundaries can legitimately make some PIDs answer to the
        // liveness probe while not appearing in this process's
        // enumerated view, and that's outside the module's control.
        let _ = scan(4096);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn test_own_pid_is_visible_and_not_reported_hidden() {
        // The test process itself must be present in the enumerated
        // list and therefore never appear in the hidden list.
        let my_pid = std::process::id();
        let hidden = scan(my_pid.saturating_add(1));
        assert!(
            !hidden.iter().any(|h| h.pid == my_pid),
            "own PID unexpectedly reported as hidden: {:?}",
            hidden
        );
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    #[test]
    fn test_noop_on_unsupported_platform() {
        assert!(scan(100_000).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_scan_handles_max_pid_zero() {
        // Range `1..=0` is empty — must return no hits and not panic.
        let hidden = scan(0);
        assert!(hidden.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_sysctl_scan_runs_cleanly() {
        // On a real macOS host sysctl must return at least this
        // process itself. We only require that the enumeration
        // completes; emptiness would be acceptable in a heavily
        // sandboxed CI runner (scan returns an empty hidden list in
        // that case) so we don't assert any specific PID count.
        let _ = scan(std::process::id().saturating_add(1));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_snapshot_scan_runs_cleanly() {
        // The Toolhelp32 snapshot must never cause the scan to
        // panic. Emptiness is tolerated on PID-namespaced builds.
        let _ = scan(std::process::id().saturating_add(1));
    }
}
