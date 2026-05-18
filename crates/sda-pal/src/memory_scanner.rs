//! Memory scanning PAL (Phase E4 of the EDR Parity workstream).
//!
//! Defines the [`MemoryScanner`] trait which enumerates committed
//! memory regions of a target process and reads bounded byte slices
//! out of them, plus per-OS implementations and a `MockMemoryScanner`
//! for unit / E2E tests.
//!
//! Safety invariants (see `docs/edr-parity/ARCHITECTURE.md` § 9.4):
//!
//! * The PAL **NEVER** enumerates the agent's own pid. The
//!   per-OS implementations all short-circuit `enumerate(self_pid)`
//!   and `read(self_pid, ..)` and return an empty / `PermissionDenied`
//!   result.  The memory-scanner module enforces the same invariant
//!   one layer up so a future PAL backend can't accidentally drop
//!   this guarantee.
//!
//! * Reads are bounded by `len`; the caller owns the destination
//!   buffer.  Implementations MUST NOT seek past the requested
//!   region.
//!
//! * Linux `/proc/<pid>/mem` requires `CAP_SYS_PTRACE` for processes
//!   outside the agent's UID.  Windows `ReadProcessMemory` requires
//!   `SeDebugPrivilege` (SYSTEM-granted).  macOS `task_for_pid`
//!   requires the `com.apple.security.cs.debugger` entitlement or
//!   root.  In CI we exercise the [`MockMemoryScanner`] which is
//!   capability-free.

use std::io;

/// Permission bits attached to a [`MemoryRegion`].
///
/// Modelled on the POSIX `PROT_*` triple plus a Windows-friendly
/// `executable` flag so the `RWX` filter is platform-agnostic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemoryPermissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl MemoryPermissions {
    /// True if all three bits are set — the high-signal indicator the
    /// memory scanner module uses to flag regions for YARA scanning.
    pub fn is_rwx(&self) -> bool {
        self.readable && self.writable && self.executable
    }
}

/// Where a [`MemoryRegion`] is backed.
///
/// `Anonymous` (heap, stack, shared-memory) and `Jit` (W+X mappings
/// without a backing file — classic shellcode allocation pattern)
/// are the high-signal kinds.  `FileBacked` regions are typically
/// uninteresting for memory scanning because the on-disk file is
/// already covered by FIM + YARA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingKind {
    Anonymous,
    FileBacked(String),
    Jit,
}

impl MappingKind {
    pub fn is_file_backed(&self) -> bool {
        matches!(self, MappingKind::FileBacked(_))
    }
}

/// A single committed memory region within a target process.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Inclusive lower bound of the region (virtual address).
    pub base: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// Permission bits at the moment of enumeration.
    pub permissions: MemoryPermissions,
    /// What backs the region (anonymous / file-backed / JIT).
    pub mapping: MappingKind,
}

impl MemoryRegion {
    /// Inclusive end of the region.  Saturates on overflow so a
    /// pathological 2^64-sized region doesn't wrap.
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.size)
    }

    /// True if the region is RWX OR anonymous OR JIT — the union of
    /// region kinds the memory scanner module reads + hands to YARA.
    /// Plain RW or RX file-backed mappings are excluded.
    pub fn is_interesting(&self) -> bool {
        if self.permissions.is_rwx() {
            return true;
        }
        match &self.mapping {
            MappingKind::Anonymous | MappingKind::Jit => true,
            MappingKind::FileBacked(_) => false,
        }
    }
}

/// Memory scanner trait.
///
/// Per-OS implementations live in `linux_imp`, `windows_imp` and
/// `macos_imp` below.  Tests use [`MockMemoryScanner`] which lets
/// the caller pre-populate regions + read buffers.
pub trait MemoryScanner: Send + Sync {
    /// Enumerate committed regions of `pid`.
    ///
    /// MUST return an empty vector if `pid == self_pid` (the agent
    /// process).  Other implementation-specific errors should bubble
    /// up via `io::Error`.
    fn enumerate(&self, pid: u32) -> io::Result<Vec<MemoryRegion>>;

    /// Copy at most `len` bytes from `[base, base + len)` of `pid`'s
    /// virtual address space into `buf`.
    ///
    /// Returns the number of bytes actually read (may be less than
    /// `len` when the region is shorter than requested).  MUST refuse
    /// to read from the agent's own pid.
    fn read(&self, pid: u32, base: u64, len: usize, buf: &mut [u8]) -> io::Result<usize>;

    /// Return the pid of the calling agent process.  Used by the
    /// memory-scanner module + per-OS implementations to enforce the
    /// self-pid exclusion invariant.  The default impl returns the
    /// host pid via `std::process::id()`.
    fn self_pid(&self) -> u32 {
        std::process::id()
    }
}

/// Build the default memory scanner for the current platform.
///
/// Returns a [`Box<dyn MemoryScanner>`] so callers can swap in a mock
/// or AMSI-wrapped variant for tests.
pub fn default_memory_scanner() -> Box<dyn MemoryScanner> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux_imp::LinuxMemoryScanner::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows_imp::WindowsMemoryScanner::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos_imp::MacosMemoryScanner::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Box::new(UnsupportedMemoryScanner)
    }
}

/// Stub backend used on platforms (BSD, illumos, …) that don't yet
/// have a real implementation.  Always returns
/// `ErrorKind::Unsupported` so the memory-scanner module logs a
/// warning and stays idle.
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub struct UnsupportedMemoryScanner;

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
impl MemoryScanner for UnsupportedMemoryScanner {
    fn enumerate(&self, _pid: u32) -> io::Result<Vec<MemoryRegion>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "memory scanning not supported on this platform",
        ))
    }
    fn read(&self, _pid: u32, _base: u64, _len: usize, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "memory reads not supported on this platform",
        ))
    }
}

// ---------------------------------------------------------------------------
// Linux: /proc/<pid>/maps + /proc/<pid>/mem
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub mod linux_imp {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    /// `/proc/<pid>/maps`-backed memory scanner.
    ///
    /// `enumerate` parses one line per region; `read` opens
    /// `/proc/<pid>/mem` and pseeks to `base` before pulling at most
    /// `len` bytes.  Both operations refuse `pid == self_pid`.
    pub struct LinuxMemoryScanner {
        self_pid: u32,
    }

    impl LinuxMemoryScanner {
        pub fn new() -> Self {
            Self {
                self_pid: std::process::id(),
            }
        }
    }

    impl Default for LinuxMemoryScanner {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MemoryScanner for LinuxMemoryScanner {
        fn enumerate(&self, pid: u32) -> io::Result<Vec<MemoryRegion>> {
            if pid == self.self_pid {
                return Ok(Vec::new());
            }
            let path = format!("/proc/{pid}/maps");
            let content = std::fs::read_to_string(&path)?;
            Ok(parse_proc_maps(&content))
        }

        fn read(&self, pid: u32, base: u64, len: usize, buf: &mut [u8]) -> io::Result<usize> {
            if pid == self.self_pid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refusing to read the agent's own memory",
                ));
            }
            let path = format!("/proc/{pid}/mem");
            let mut file = File::open(&path)?;
            file.seek(SeekFrom::Start(base))?;
            let cap = len.min(buf.len());
            let slice = &mut buf[..cap];
            let mut read_total = 0usize;
            while read_total < cap {
                let n = file.read(&mut slice[read_total..])?;
                if n == 0 {
                    break;
                }
                read_total += n;
            }
            Ok(read_total)
        }

        fn self_pid(&self) -> u32 {
            self.self_pid
        }
    }

    /// Parse the body of a `/proc/<pid>/maps` file into a vector of
    /// [`MemoryRegion`]s.  Exposed for unit tests so we can exercise
    /// the parser without needing a real process.
    pub fn parse_proc_maps(content: &str) -> Vec<MemoryRegion> {
        let mut out = Vec::new();
        for line in content.lines() {
            if let Some(region) = parse_maps_line(line) {
                out.push(region);
            }
        }
        out
    }

    fn parse_maps_line(line: &str) -> Option<MemoryRegion> {
        // Format: `start-end perms offset dev inode [pathname]`
        // Example: `7f1c00000000-7f1c00021000 rw-p 00000000 00:00 0 [heap]`
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let perms = parts.next()?;
        let _offset = parts.next()?;
        let _dev = parts.next()?;
        let _inode = parts.next()?;
        let rest: String = parts.collect::<Vec<&str>>().join(" ");

        let (start_s, end_s) = range.split_once('-')?;
        let start = u64::from_str_radix(start_s, 16).ok()?;
        let end = u64::from_str_radix(end_s, 16).ok()?;
        if end <= start {
            return None;
        }

        let permissions = parse_perms(perms);
        let mapping = classify_mapping(&rest, &permissions);

        Some(MemoryRegion {
            base: start,
            size: end - start,
            permissions,
            mapping,
        })
    }

    fn parse_perms(s: &str) -> MemoryPermissions {
        let bytes = s.as_bytes();
        MemoryPermissions {
            readable: bytes.first() == Some(&b'r'),
            writable: bytes.get(1) == Some(&b'w'),
            executable: bytes.get(2) == Some(&b'x'),
        }
    }

    fn classify_mapping(path: &str, perms: &MemoryPermissions) -> MappingKind {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            // No backing file at all — classic anonymous mapping.  If
            // it's also W+X, classify as JIT for higher-signal alerts.
            if perms.writable && perms.executable {
                return MappingKind::Jit;
            }
            return MappingKind::Anonymous;
        }
        // Special tags: `[heap]`, `[stack]`, `[stack:tid]`, `[vdso]`,
        // `[vsyscall]`, `[anon:*]`, `[anon_shmem:*]`.
        if trimmed.starts_with('[') {
            if perms.writable && perms.executable {
                return MappingKind::Jit;
            }
            return MappingKind::Anonymous;
        }
        // File-backed.  W+X file-backed mappings are extremely
        // suspicious — flag them as JIT so the scanner module
        // surfaces them.
        if perms.writable && perms.executable {
            return MappingKind::Jit;
        }
        MappingKind::FileBacked(trimmed.to_string())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const SAMPLE_MAPS: &str = "\
00400000-0040b000 r-xp 00000000 fd:00 1234 /usr/bin/cat
0060a000-0060b000 r--p 0000a000 fd:00 1234 /usr/bin/cat
0060b000-0060c000 rw-p 0000b000 fd:00 1234 /usr/bin/cat
014a3000-014c4000 rw-p 00000000 00:00 0 [heap]
7f1c00000000-7f1c00021000 rw-p 00000000 00:00 0
7ffe1234a000-7ffe1234b000 r-xp 00000000 00:00 0 [vdso]
7ffe5678a000-7ffe5678b000 rwxp 00000000 00:00 0
7ffe9abc0000-7ffe9abc1000 rwxp 00000000 fd:00 9999 /tmp/loader.so
";

        #[test]
        fn parses_canonical_maps_lines() {
            let regions = parse_proc_maps(SAMPLE_MAPS);
            assert_eq!(regions.len(), 8);
            // First region: file-backed RX.
            assert_eq!(regions[0].base, 0x0040_0000);
            assert_eq!(regions[0].size, 0xb000);
            assert!(regions[0].permissions.readable);
            assert!(!regions[0].permissions.writable);
            assert!(regions[0].permissions.executable);
            assert!(regions[0].mapping.is_file_backed());
        }

        #[test]
        fn detects_anonymous_heap_mapping() {
            let regions = parse_proc_maps(SAMPLE_MAPS);
            let heap = regions
                .iter()
                .find(|r| r.base == 0x014a_3000)
                .expect("heap line present");
            assert!(matches!(heap.mapping, MappingKind::Anonymous));
            assert!(heap.permissions.writable);
            assert!(!heap.permissions.executable);
        }

        #[test]
        fn detects_anonymous_unnamed_mapping() {
            let regions = parse_proc_maps(SAMPLE_MAPS);
            let anon = regions
                .iter()
                .find(|r| r.base == 0x7f1c_0000_0000)
                .expect("anon line present");
            assert!(matches!(anon.mapping, MappingKind::Anonymous));
        }

        #[test]
        fn detects_jit_anon_rwx_mapping() {
            let regions = parse_proc_maps(SAMPLE_MAPS);
            let jit = regions
                .iter()
                .find(|r| r.base == 0x7ffe_5678_a000)
                .expect("rwx anon line present");
            assert!(matches!(jit.mapping, MappingKind::Jit));
            assert!(jit.permissions.is_rwx());
            assert!(jit.is_interesting());
        }

        #[test]
        fn detects_jit_file_backed_rwx_mapping() {
            let regions = parse_proc_maps(SAMPLE_MAPS);
            let suspicious = regions
                .iter()
                .find(|r| r.base == 0x7ffe_9abc_0000)
                .expect("rwx file-backed line present");
            assert!(matches!(suspicious.mapping, MappingKind::Jit));
        }

        #[test]
        fn is_interesting_only_for_rwx_anon_or_jit() {
            let regions = parse_proc_maps(SAMPLE_MAPS);
            let rx_text = &regions[0]; // r-xp file-backed → boring
            assert!(!rx_text.is_interesting());
            let rw_text = &regions[2]; // rw-p file-backed → boring
            assert!(!rw_text.is_interesting());
            // Heap (rw-p anon) is interesting because anonymous.
            let heap = regions
                .iter()
                .find(|r| r.base == 0x014a_3000)
                .expect("heap");
            assert!(heap.is_interesting());
        }

        #[test]
        fn ignores_garbage_lines() {
            let regions = parse_proc_maps("garbage\nnot a maps line\n\n");
            assert!(regions.is_empty());
        }

        #[test]
        fn enumerate_for_self_pid_returns_empty() {
            // Don't actually need /proc here — the trait short-circuits
            // BEFORE touching /proc/<pid>/maps.
            let scanner = LinuxMemoryScanner::new();
            let regions = scanner.enumerate(scanner.self_pid()).unwrap();
            assert!(regions.is_empty());
        }

        #[test]
        fn read_for_self_pid_is_permission_denied() {
            let scanner = LinuxMemoryScanner::new();
            let mut buf = [0u8; 8];
            let err = scanner
                .read(scanner.self_pid(), 0x1000, 8, &mut buf)
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        }

        #[test]
        fn enumerate_unknown_pid_returns_io_error() {
            let scanner = LinuxMemoryScanner::new();
            // pid 2^31 is guaranteed not to exist on Linux — `pid_max`
            // caps at 2^22.
            let result = scanner.enumerate(2_147_483_647);
            assert!(result.is_err());
        }
    }
}

// ---------------------------------------------------------------------------
// Windows: VirtualQueryEx + ReadProcessMemory
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub mod windows_imp {
    use super::*;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};

    /// RAII guard that closes a Win32 `HANDLE` on drop.
    ///
    /// Used by [`WindowsMemoryScanner`] so that handle ownership
    /// follows scope. If anything between `OpenProcess` and the
    /// final return panics — including the `unsafe` blocks around
    /// `VirtualQueryEx` and `ReadProcessMemory` — the handle is
    /// still released by the unwind. This is the defence-in-depth
    /// pattern the Devin Review bot recommended on PR #25 and
    /// mirrors how the kernel-mode Windows code is expected to
    /// manage its own handles in E6.1.
    struct ProcessHandleGuard(HANDLE);

    impl Drop for ProcessHandleGuard {
        fn drop(&mut self) {
            // CloseHandle on an invalid handle returns an error,
            // which we explicitly ignore: closing an already-closed
            // handle isn't actionable from Drop.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    impl ProcessHandleGuard {
        fn raw(&self) -> HANDLE {
            self.0
        }
    }

    /// Windows `VirtualQueryEx`-backed memory scanner.
    ///
    /// Opens the target process with `PROCESS_QUERY_INFORMATION |
    /// PROCESS_VM_READ`, walks committed regions via repeated
    /// `VirtualQueryEx` calls, and pulls byte slices via
    /// `ReadProcessMemory`.  Requires `SeDebugPrivilege` (granted to
    /// SYSTEM) to read processes outside the caller's session.
    ///
    /// In CI we exercise [`super::MockMemoryScanner`] because the
    /// CI account doesn't hold `SeDebugPrivilege`.
    pub struct WindowsMemoryScanner {
        self_pid: u32,
    }

    impl WindowsMemoryScanner {
        pub fn new() -> Self {
            Self {
                self_pid: std::process::id(),
            }
        }
    }

    impl Default for WindowsMemoryScanner {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MemoryScanner for WindowsMemoryScanner {
        fn enumerate(&self, pid: u32) -> io::Result<Vec<MemoryRegion>> {
            if pid == self.self_pid {
                return Ok(Vec::new());
            }
            // SAFETY: every `unsafe` block wraps a single Win32 call.
            // The handle is owned by `ProcessHandleGuard` from the
            // moment `OpenProcess` succeeds, so any panic — or new
            // early-return added in future revisions — still releases
            // it via the guard's `Drop`.
            use windows::Win32::System::Memory::{
                VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE,
                PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS,
                PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
            };
            use windows::Win32::System::Threading::{
                OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            };

            let raw_handle = unsafe {
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                    .map_err(|e| io::Error::other(format!("OpenProcess failed: {e}")))?
            };
            let handle_guard = ProcessHandleGuard(raw_handle);
            let mut out = Vec::new();
            let mut address: usize = 0;
            loop {
                let mut info = MEMORY_BASIC_INFORMATION::default();
                let written = unsafe {
                    VirtualQueryEx(
                        handle_guard.raw(),
                        Some(address as *const _),
                        &mut info,
                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                };
                if written == 0 {
                    break;
                }
                if info.State == MEM_COMMIT {
                    let permissions = match info.Protect {
                        p if p == PAGE_READONLY => MemoryPermissions {
                            readable: true,
                            ..Default::default()
                        },
                        p if p == PAGE_READWRITE || p == PAGE_WRITECOPY => MemoryPermissions {
                            readable: true,
                            writable: true,
                            ..Default::default()
                        },
                        p if p == PAGE_EXECUTE => MemoryPermissions {
                            executable: true,
                            ..Default::default()
                        },
                        p if p == PAGE_EXECUTE_READ => MemoryPermissions {
                            readable: true,
                            executable: true,
                            ..Default::default()
                        },
                        p if p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY => {
                            MemoryPermissions {
                                readable: true,
                                writable: true,
                                executable: true,
                            }
                        }
                        p if p == PAGE_NOACCESS => MemoryPermissions::default(),
                        _ => MemoryPermissions::default(),
                    };
                    // VirtualQueryEx does not surface a filename — we
                    // approximate by classifying MEM_PRIVATE as
                    // Anonymous and MEM_IMAGE / MEM_MAPPED as
                    // FileBacked("").  RWX private allocations are
                    // flagged as Jit just like Linux.
                    use windows::Win32::System::Memory::{MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE};
                    let mapping = if info.Type == MEM_PRIVATE {
                        if permissions.is_rwx() {
                            MappingKind::Jit
                        } else {
                            MappingKind::Anonymous
                        }
                    } else if info.Type == MEM_IMAGE || info.Type == MEM_MAPPED {
                        if permissions.is_rwx() {
                            MappingKind::Jit
                        } else {
                            MappingKind::FileBacked(String::new())
                        }
                    } else {
                        MappingKind::Anonymous
                    };
                    out.push(MemoryRegion {
                        base: info.BaseAddress as u64,
                        size: info.RegionSize as u64,
                        permissions,
                        mapping,
                    });
                }
                let next = (info.BaseAddress as usize).saturating_add(info.RegionSize);
                if next <= address {
                    // Guard against infinite loops if VirtualQueryEx
                    // returns a degenerate region.
                    break;
                }
                address = next;
            }
            unsafe {
                let _ = CloseHandle(handle);
            }
            Ok(out)
        }

        fn read(&self, pid: u32, base: u64, len: usize, buf: &mut [u8]) -> io::Result<usize> {
            if pid == self.self_pid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refusing to read the agent's own memory",
                ));
            }
            use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
            use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

            let cap = len.min(buf.len());
            let raw_handle = unsafe {
                OpenProcess(PROCESS_VM_READ, false, pid)
                    .map_err(|e| io::Error::other(format!("OpenProcess failed: {e}")))?
            };
            // Take ownership of the handle immediately so the guard
            // releases it on any return path — including a panic in
            // the `ReadProcessMemory` `unsafe` block below.
            let handle_guard = ProcessHandleGuard(raw_handle);
            let mut bytes_read: usize = 0;
            let ok = unsafe {
                ReadProcessMemory(
                    handle_guard.raw(),
                    base as *const _,
                    buf.as_mut_ptr() as *mut _,
                    cap,
                    Some(&mut bytes_read),
                )
            };
            ok.map_err(|e| io::Error::other(format!("ReadProcessMemory failed: {e}")))?;
            Ok(bytes_read)
        }

        fn self_pid(&self) -> u32 {
            self.self_pid
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn enumerate_for_self_pid_returns_empty() {
            let scanner = WindowsMemoryScanner::new();
            let regions = scanner.enumerate(scanner.self_pid()).unwrap();
            assert!(regions.is_empty());
        }

        #[test]
        fn read_for_self_pid_is_permission_denied() {
            let scanner = WindowsMemoryScanner::new();
            let mut buf = [0u8; 4];
            let err = scanner
                .read(scanner.self_pid(), 0x1000, 4, &mut buf)
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        }
    }
}

// ---------------------------------------------------------------------------
// macOS: task_for_pid + mach_vm_region + mach_vm_read_overwrite
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub mod macos_imp {
    use super::*;

    /// macOS `mach_vm_region`-backed memory scanner.
    ///
    /// `task_for_pid` requires either root or the
    /// `com.apple.security.cs.debugger` entitlement on the running
    /// agent binary.  CI exercises [`super::MockMemoryScanner`] (no
    /// entitlement).
    pub struct MacosMemoryScanner {
        self_pid: u32,
    }

    impl MacosMemoryScanner {
        pub fn new() -> Self {
            Self {
                self_pid: std::process::id(),
            }
        }
    }

    impl Default for MacosMemoryScanner {
        fn default() -> Self {
            Self::new()
        }
    }

    // The real Mach FFI surface lives in the `mach2` crate which we
    // don't want to add as a workspace dep just for the scanner.
    // Until the productisation work in E6.3 lands a signed
    // SystemExtension carrying these calls, the user-mode macOS
    // implementation returns `Unsupported` and lets the agent log a
    // warning.  The trait still gates self-pid + provides a
    // testable seam.
    impl MemoryScanner for MacosMemoryScanner {
        fn enumerate(&self, pid: u32) -> io::Result<Vec<MemoryRegion>> {
            if pid == self.self_pid {
                return Ok(Vec::new());
            }
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "macOS task_for_pid requires com.apple.security.cs.debugger; \
                 see docs/edr-parity/PRODUCTISATION-MACOS.md (Phase E6.3)",
            ))
        }

        fn read(&self, pid: u32, _base: u64, _len: usize, _buf: &mut [u8]) -> io::Result<usize> {
            if pid == self.self_pid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refusing to read the agent's own memory",
                ));
            }
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "macOS mach_vm_read_overwrite requires com.apple.security.cs.debugger",
            ))
        }

        fn self_pid(&self) -> u32 {
            self.self_pid
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn enumerate_for_self_pid_returns_empty() {
            let scanner = MacosMemoryScanner::new();
            let regions = scanner.enumerate(scanner.self_pid()).unwrap();
            assert!(regions.is_empty());
        }

        #[test]
        fn enumerate_other_pid_returns_unsupported_in_user_mode() {
            let scanner = MacosMemoryScanner::new();
            let err = scanner
                .enumerate(scanner.self_pid().wrapping_add(1))
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        }

        #[test]
        fn read_for_self_pid_is_permission_denied() {
            let scanner = MacosMemoryScanner::new();
            let mut buf = [0u8; 4];
            let err = scanner
                .read(scanner.self_pid(), 0x1000, 4, &mut buf)
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        }
    }
}

// ---------------------------------------------------------------------------
// Mock backend — exercised by every E4 unit + E2E test.
// ---------------------------------------------------------------------------

/// In-memory mock backend used by unit + E2E tests.
///
/// Tests pre-populate `regions` (keyed on pid) and `reads` (keyed on
/// `(pid, base)`).  The mock honours the self-pid exclusion contract
/// exactly like the real backends.
pub struct MockMemoryScanner {
    inner: std::sync::Mutex<MockState>,
    self_pid: u32,
}

struct MockState {
    regions: std::collections::BTreeMap<u32, Vec<MemoryRegion>>,
    reads: std::collections::BTreeMap<(u32, u64), Vec<u8>>,
    enumerate_calls: u64,
    read_calls: u64,
}

impl Default for MockMemoryScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl MockMemoryScanner {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(MockState {
                regions: Default::default(),
                reads: Default::default(),
                enumerate_calls: 0,
                read_calls: 0,
            }),
            // Default self-pid mirrors the host pid so unit tests
            // don't have to care.  E2E tests can override via
            // [`Self::with_self_pid`].
            self_pid: std::process::id(),
        }
    }

    /// Construct a mock with a deliberately-different self-pid so
    /// tests can confirm the agent-process exclusion fires.
    pub fn with_self_pid(self_pid: u32) -> Self {
        let mut s = Self::new();
        s.self_pid = self_pid;
        s
    }

    pub fn set_regions(&self, pid: u32, regions: Vec<MemoryRegion>) {
        self.inner.lock().unwrap().regions.insert(pid, regions);
    }

    pub fn set_read(&self, pid: u32, base: u64, bytes: Vec<u8>) {
        self.inner.lock().unwrap().reads.insert((pid, base), bytes);
    }

    pub fn enumerate_calls(&self) -> u64 {
        self.inner.lock().unwrap().enumerate_calls
    }

    pub fn read_calls(&self) -> u64 {
        self.inner.lock().unwrap().read_calls
    }
}

impl MemoryScanner for MockMemoryScanner {
    fn enumerate(&self, pid: u32) -> io::Result<Vec<MemoryRegion>> {
        let mut state = self.inner.lock().unwrap();
        state.enumerate_calls += 1;
        if pid == self.self_pid {
            return Ok(Vec::new());
        }
        Ok(state.regions.get(&pid).cloned().unwrap_or_default())
    }

    fn read(&self, pid: u32, base: u64, len: usize, buf: &mut [u8]) -> io::Result<usize> {
        let mut state = self.inner.lock().unwrap();
        state.read_calls += 1;
        if pid == self.self_pid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "mock: refusing to read the agent's own memory",
            ));
        }
        let bytes = match state.reads.get(&(pid, base)) {
            Some(b) => b.clone(),
            None => return Ok(0),
        };
        let cap = len.min(buf.len()).min(bytes.len());
        buf[..cap].copy_from_slice(&bytes[..cap]);
        Ok(cap)
    }

    fn self_pid(&self) -> u32 {
        self.self_pid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(base: u64, size: u64, rwx: bool, kind: MappingKind) -> MemoryRegion {
        MemoryRegion {
            base,
            size,
            permissions: if rwx {
                MemoryPermissions {
                    readable: true,
                    writable: true,
                    executable: true,
                }
            } else {
                MemoryPermissions {
                    readable: true,
                    writable: false,
                    executable: false,
                }
            },
            mapping: kind,
        }
    }

    #[test]
    fn memory_region_end_saturates_on_overflow() {
        let r = MemoryRegion {
            base: u64::MAX - 4,
            size: u64::MAX,
            permissions: MemoryPermissions::default(),
            mapping: MappingKind::Anonymous,
        };
        assert_eq!(r.end(), u64::MAX);
    }

    #[test]
    fn memory_permissions_is_rwx_only_when_all_three_set() {
        assert!(MemoryPermissions {
            readable: true,
            writable: true,
            executable: true,
        }
        .is_rwx());
        assert!(!MemoryPermissions {
            readable: true,
            writable: true,
            executable: false,
        }
        .is_rwx());
        assert!(!MemoryPermissions::default().is_rwx());
    }

    #[test]
    fn mock_returns_canned_regions_for_known_pid() {
        let m = MockMemoryScanner::with_self_pid(99);
        m.set_regions(
            123,
            vec![region(0x1000, 0x100, true, MappingKind::Anonymous)],
        );
        let regions = m.enumerate(123).unwrap();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].base, 0x1000);
        assert!(regions[0].permissions.is_rwx());
    }

    #[test]
    fn mock_enumerates_to_empty_for_unknown_pid() {
        let m = MockMemoryScanner::with_self_pid(99);
        assert!(m.enumerate(555).unwrap().is_empty());
    }

    #[test]
    fn mock_enumerate_for_self_pid_always_returns_empty() {
        let m = MockMemoryScanner::with_self_pid(42);
        m.set_regions(42, vec![region(0x1000, 0x100, true, MappingKind::Jit)]);
        // Even though we set regions for pid 42, the self-pid filter
        // wins.
        let regions = m.enumerate(42).unwrap();
        assert!(regions.is_empty());
    }

    #[test]
    fn mock_read_returns_canned_bytes() {
        let m = MockMemoryScanner::with_self_pid(99);
        m.set_read(123, 0x1000, b"hello memory".to_vec());
        let mut buf = [0u8; 12];
        let n = m.read(123, 0x1000, 12, &mut buf).unwrap();
        assert_eq!(n, 12);
        assert_eq!(&buf, b"hello memory");
    }

    #[test]
    fn mock_read_truncates_to_buf_capacity() {
        let m = MockMemoryScanner::with_self_pid(99);
        m.set_read(123, 0x1000, b"abcdefghij".to_vec());
        let mut buf = [0u8; 4];
        let n = m.read(123, 0x1000, 4, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf, b"abcd");
    }

    #[test]
    fn mock_read_for_self_pid_is_permission_denied() {
        let m = MockMemoryScanner::with_self_pid(42);
        let mut buf = [0u8; 4];
        let err = m.read(42, 0x1000, 4, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn mock_read_returns_zero_for_unknown_region() {
        let m = MockMemoryScanner::with_self_pid(99);
        let mut buf = [0u8; 4];
        let n = m.read(123, 0x4000, 4, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn mock_counters_track_calls() {
        let m = MockMemoryScanner::with_self_pid(99);
        m.set_regions(
            123,
            vec![region(0x1000, 0x100, true, MappingKind::Anonymous)],
        );
        m.set_read(123, 0x1000, b"x".to_vec());
        let _ = m.enumerate(123).unwrap();
        let _ = m.enumerate(123).unwrap();
        let mut buf = [0u8; 1];
        let _ = m.read(123, 0x1000, 1, &mut buf).unwrap();
        assert_eq!(m.enumerate_calls(), 2);
        assert_eq!(m.read_calls(), 1);
    }
}
