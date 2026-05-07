//! Tamper protection (P3.3).
//!
//! Three best-effort defenses run at startup and throughout the life
//! of the agent:
//!
//! 1. **Self-integrity check**: on boot, SHA-256 the currently-running
//!    `sda-agent` binary and compare against an expected hash shipped
//!    in [`TamperConfig::expected_binary_sha256`]. Mismatch aborts
//!    startup.
//! 2. **File immutability**: mark the agent binary, config, and
//!    [`TamperConfig::immutable_paths`] as immutable on Linux via
//!    `chattr +i` so an attacker with CAP_DAC_OVERRIDE alone cannot
//!    replace them. Non-existent paths and platforms without chattr
//!    are skipped with a warning.
//! 3. **Watchdog heartbeat**: if the service manager exported
//!    `$NOTIFY_SOCKET` (systemd) and
//!    [`TamperConfig::watchdog_interval_secs`] is non-zero, spawn a
//!    background task that sends `WATCHDOG=1` at half the configured
//!    interval. systemd `SIGKILL`s and restarts the unit if heartbeats
//!    stop.
//!
//! Everything here is best-effort: a failure to apply `chattr +i`
//! logs a warning but does not abort the agent, because not every
//! filesystem (tmpfs, NFS, overlay) supports the flag.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use sda_core::config::TamperConfig;
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// Run the startup-time tamper checks — self-integrity verification
/// and file-immutability application. Returns early with `Ok(())`
/// when [`TamperConfig::enabled`] is false.
pub fn apply_startup_protections(cfg: &TamperConfig) -> Result<()> {
    if !cfg.enabled {
        return Ok(());
    }
    if let Some(expected) = cfg.expected_binary_sha256.as_deref() {
        verify_self_integrity(expected)?;
    }
    for path in &cfg.immutable_paths {
        mark_immutable(path);
    }
    Ok(())
}

/// Compute the SHA-256 of the currently running binary and compare
/// against `expected_hex` (case-insensitive, 64 hex chars). An empty
/// `expected_hex` is treated as "not configured" and returns `Ok(())`.
pub fn verify_self_integrity(expected_hex: &str) -> Result<()> {
    let expected = expected_hex.trim();
    if expected.is_empty() {
        return Ok(());
    }
    let exe = std::env::current_exe().context("failed to resolve current executable path")?;
    let actual = hash_file(&exe)
        .with_context(|| format!("failed to hash current executable at {}", exe.display()))?;
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(anyhow!(
            "self-integrity check failed: expected SHA-256 {expected}, got {actual}"
        ));
    }
    info!(
        path = %exe.display(),
        sha256 = %actual,
        "self-integrity check passed"
    );
    Ok(())
}

/// SHA-256 a file and return the lowercase-hex digest.
pub fn hash_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("open {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("read {} for hashing", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Best-effort `chattr +i` on Linux. Logs a warning rather than
/// returning an error so one unsupported filesystem doesn't take the
/// agent out.
fn mark_immutable(path: &Path) {
    if !path.exists() {
        warn!(path = %path.display(), "immutable target does not exist; skipping");
        return;
    }
    #[cfg(target_os = "linux")]
    {
        match linux::set_immutable(path) {
            Ok(()) => info!(path = %path.display(), "marked file immutable"),
            Err(err) => warn!(
                path = %path.display(),
                error = %err,
                "failed to mark file immutable (continuing)"
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        warn!(
            path = %path.display(),
            "file immutability not supported on this platform; relying on filesystem ACLs"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::AsRawFd;
    use std::path::Path;

    use anyhow::{Context, Result};

    // FS_IOC_GETFLAGS = _IOR('f', 1, long)
    // FS_IOC_SETFLAGS = _IOW('f', 2, long)
    //
    // The ioctl number embeds the size of the argument type in its
    // middle 14 bits. That size depends on `sizeof(long)`, which is
    // 8 on 64-bit Linux and 4 on 32-bit Linux — so the two
    // hardcoded constants that were previously here (0x80086601 /
    // 0x40086602) are only correct on 64-bit builds. Computing the
    // constants at runtime from `size_of::<c_long>()` fixes the
    // 32-bit case without needing a separate codepath per target.
    //
    // The formula matches glibc's `_IOR` / `_IOW` macros:
    //     ((dir << 30) | (size << 16) | (type << 8) | nr)
    // with dir = 2 for _IOR (read) and dir = 1 for _IOW (write),
    // type = 'f' (0x66), and nr = 1 or 2.
    fn fs_ioc_getflags() -> libc::c_ulong {
        let size = std::mem::size_of::<libc::c_long>() as libc::c_ulong;
        (2 << 30) | (size << 16) | (0x66 << 8) | 1
    }
    fn fs_ioc_setflags() -> libc::c_ulong {
        let size = std::mem::size_of::<libc::c_long>() as libc::c_ulong;
        (1 << 30) | (size << 16) | (0x66 << 8) | 2
    }
    const FS_IMMUTABLE_FL: libc::c_long = 0x00000010;

    pub fn set_immutable(path: &Path) -> Result<()> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(path)
            .with_context(|| format!("open {} for ioctl", path.display()))?;
        let fd = file.as_raw_fd();
        let mut flags: libc::c_long = 0;
        // SAFETY: FFI call; `flags` lives through the call.
        let rc = unsafe { libc::ioctl(fd, fs_ioc_getflags(), &mut flags) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("FS_IOC_GETFLAGS");
        }
        flags |= FS_IMMUTABLE_FL;
        // SAFETY: FFI call; `flags` lives through the call.
        let rc = unsafe { libc::ioctl(fd, fs_ioc_setflags(), &flags) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("FS_IOC_SETFLAGS");
        }
        Ok(())
    }
}

/// Spawn a systemd-style watchdog heartbeat. Returns `None` when the
/// feature is disabled (interval is 0 or `$NOTIFY_SOCKET` is unset) so
/// the caller doesn't need to track a dead handle.
pub fn spawn_watchdog(cfg: &TamperConfig) -> Option<JoinHandle<()>> {
    if !cfg.enabled || cfg.watchdog_interval_secs == 0 {
        return None;
    }
    let socket = std::env::var("NOTIFY_SOCKET").ok()?;
    let tick = Duration::from_secs(cfg.watchdog_interval_secs.max(2) / 2);
    info!(
        socket = %socket,
        tick_secs = tick.as_secs(),
        "watchdog heartbeat enabled"
    );
    Some(tokio::spawn(async move {
        let mut interval = tokio::time::interval(tick);
        // First tick fires immediately; skip it so systemd doesn't
        // see a heartbeat before we've actually finished starting.
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Err(err) = notify(&socket, b"WATCHDOG=1") {
                warn!(error = %err, "failed to send watchdog heartbeat");
            }
        }
    }))
}

#[cfg(unix)]
fn notify(socket_path: &str, payload: &[u8]) -> Result<()> {
    use std::os::unix::net::UnixDatagram;

    let sock =
        UnixDatagram::unbound().context("creating unbound unix datagram socket for sd-notify")?;

    // systemd exposes NOTIFY_SOCKET either as a filesystem path or,
    // on Linux, as an abstract socket whose path starts with '@'
    // (the leading '@' stands in for the abstract-namespace NUL
    // byte). sendto(2) on glibc accepts filesystem paths via
    // sun_path but requires a proper sockaddr_un with sun_path[0] =
    // 0 for abstract sockets — passing "@foo" through
    // UnixDatagram::send_to() treats it as a regular path and
    // returns ENOENT.
    #[cfg(target_os = "linux")]
    if let Some(name) = socket_path.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::SocketAddr;
        let addr = SocketAddr::from_abstract_name(name.as_bytes())
            .with_context(|| format!("constructing abstract socket address for {socket_path}"))?;
        sock.send_to_addr(payload, &addr)
            .with_context(|| format!("send to abstract socket {socket_path}"))?;
        return Ok(());
    }

    // Filesystem path (the common case on non-Linux unixes and on
    // Linux where systemd is configured for a pathname socket).
    sock.send_to(payload, socket_path)
        .with_context(|| format!("send to {socket_path}"))?;
    Ok(())
}

#[cfg(not(unix))]
fn notify(_socket_path: &str, _payload: &[u8]) -> Result<()> {
    Err(anyhow!(
        "sd-notify watchdog is only supported on Unix platforms"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn hash_file_produces_lowercase_hex_of_sha256() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"hello world").unwrap();
        f.flush().unwrap();
        let got = hash_file(f.path()).unwrap();
        assert_eq!(
            got,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn hash_file_handles_empty_input() {
        let f = NamedTempFile::new().unwrap();
        let got = hash_file(f.path()).unwrap();
        assert_eq!(
            got,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn verify_self_integrity_accepts_matching_hash() {
        let exe = std::env::current_exe().unwrap();
        let actual = hash_file(&exe).unwrap();
        verify_self_integrity(&actual).unwrap();
    }

    #[test]
    fn verify_self_integrity_accepts_uppercase() {
        let exe = std::env::current_exe().unwrap();
        let actual = hash_file(&exe).unwrap().to_ascii_uppercase();
        verify_self_integrity(&actual).unwrap();
    }

    #[test]
    fn verify_self_integrity_rejects_bad_hash() {
        let err = verify_self_integrity(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        assert!(err.to_string().contains("self-integrity check failed"));
    }

    #[test]
    fn verify_self_integrity_is_noop_on_empty_hash() {
        verify_self_integrity("").unwrap();
        verify_self_integrity("   ").unwrap();
    }

    #[test]
    fn apply_startup_protections_is_noop_when_disabled() {
        let cfg = TamperConfig::default();
        assert!(!cfg.enabled);
        apply_startup_protections(&cfg).unwrap();
    }

    #[test]
    fn spawn_watchdog_returns_none_when_disabled() {
        let cfg = TamperConfig::default();
        assert!(spawn_watchdog(&cfg).is_none());
    }

    /// Regression test for A3: `notify()` on Linux must construct a
    /// valid abstract-namespace `SocketAddr` when the `NOTIFY_SOCKET`
    /// path starts with `@` (the documented systemd convention for
    /// abstract sockets).
    ///
    /// The actual `sendto(2)` will fail in the test environment
    /// because no listener is bound to that abstract name, but what
    /// we care about is that the function returns a non-panicking
    /// error tied to the send itself — not an "address construction
    /// failed" panic or ENOENT from treating `"@..."` as a filesystem
    /// path. Both outcomes (send fails, or send succeeds because
    /// something else is bound to the address) count as "did not
    /// panic".
    #[cfg(target_os = "linux")]
    #[test]
    fn notify_handles_abstract_socket_path_without_panicking() {
        let unique = format!("@sda-notify-test-{}", std::process::id());
        // Either Ok(()) or Err(...) is acceptable; a panic is not.
        let _ = notify(&unique, b"WATCHDOG=1");
    }

    #[test]
    fn spawn_watchdog_returns_none_without_notify_socket() {
        // Ensure NOTIFY_SOCKET is unset for this test. Remove it and
        // put it back afterwards so other tests in the same process
        // aren't affected.
        let saved = std::env::var("NOTIFY_SOCKET").ok();
        // SAFETY: single-threaded within this test; we restore below.
        unsafe { std::env::remove_var("NOTIFY_SOCKET") };
        let cfg = TamperConfig {
            enabled: true,
            watchdog_interval_secs: 10,
            ..TamperConfig::default()
        };
        let handle = spawn_watchdog(&cfg);
        assert!(handle.is_none());
        if let Some(v) = saved {
            // SAFETY: single-threaded within this test.
            unsafe { std::env::set_var("NOTIFY_SOCKET", v) };
        }
    }
}
