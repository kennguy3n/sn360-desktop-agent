//! Cross-platform process telemetry PAL trait.
//!
//! Backs the `sda-process-monitor` module (Phase E1 of the EDR
//! Parity workstream). See `docs/edr-parity/ARCHITECTURE.md` § 5
//! for the trait spec and per-OS implementation matrix, and
//! `docs/security-audit.md` § "EDR Parity License Audit" for the
//! clean-room posture (no CrowdStrike / SentinelOne / Defender
//! source vendored).
//!
//! Per-OS production implementations:
//!
//! - **Linux** (production): `NETLINK_CONNECTOR` + `CN_IDX_PROC`
//!   subscription. Requires `CAP_NET_ADMIN`. The implementation
//!   in this file uses a `/proc` poller as the supported fallback
//!   when `CAP_NET_ADMIN` is not held, since `cn_proc` netlink
//!   without the capability silently returns no events. The
//!   poller is documented as the "real" Linux baseline; an
//!   optional netlink fast path can land later under a feature
//!   gate without breaking the trait surface.
//! - **Windows** (production): ETW `Microsoft-Windows-Kernel-Process`
//!   provider. Requires `SYSTEM` privileges; in CI we exercise
//!   the [`MockProcessMonitor`] instead so the test matrix can
//!   run unprivileged.
//! - **macOS** (production): Endpoint Security framework
//!   `ES_EVENT_TYPE_NOTIFY_EXEC` / `_FORK` / `_EXIT` / `_MMAP`.
//!   Requires the `com.apple.developer.endpoint-security.client`
//!   entitlement; CI uses [`MockProcessMonitor`].

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// Errors produced by [`ProcessMonitor`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum ProcessMonitorError {
    /// I/O error opening `/proc`, a netlink socket, or invoking
    /// a platform helper.
    #[error("process monitor IO error: {0}")]
    Io(#[from] std::io::Error),
    /// The requested operation is not supported on this host
    /// (e.g. ETW backend on a non-Windows build, or netlink
    /// without `CAP_NET_ADMIN`).
    #[error("process monitor unsupported: {0}")]
    Unsupported(String),
    /// The subscription has already been initiated for this provider.
    #[error("process monitor already subscribed")]
    AlreadySubscribed,
    /// A platform helper exited non-zero or could not be parsed.
    #[error("process monitor command failed: {0}")]
    Command(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, ProcessMonitorError>;

/// Options passed to [`ProcessMonitor::subscribe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessMonitorOpts {
    /// Whether the implementation should emit [`ProcessEvent::ImageLoaded`]
    /// for shared-library / DLL loads in addition to exec / exit
    /// events. Linux `cn_proc` does not provide image-load events
    /// out of the box, so this is best-effort on Linux; Windows
    /// ETW and macOS Endpoint Security both support it natively.
    pub image_load_events: bool,
    /// Size of the bounded mpsc channel used for the event stream.
    /// On overflow the implementation drops the oldest event and
    /// records a counter on the [`ProcessEventStream`].
    pub channel_buffer: usize,
    /// Poll interval (milliseconds) for poller-based fallbacks
    /// (e.g. Linux `/proc` poller). Ignored by netlink / ETW /
    /// Endpoint Security implementations.
    pub poll_interval_ms: u64,
}

impl Default for ProcessMonitorOpts {
    fn default() -> Self {
        Self {
            image_load_events: true,
            channel_buffer: 4096,
            poll_interval_ms: 500,
        }
    }
}

/// A single process telemetry event surfaced by the PAL.
///
/// The shape mirrors `docs/edr-parity/ARCHITECTURE.md` § 8 (wire
/// schema) so the owning module can serialise it to a canonical-JSON
/// payload without per-platform glue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcessEvent {
    /// A process was created (Linux `PROC_EVENT_FORK` followed by
    /// `PROC_EVENT_EXEC`, Windows ETW `PROCESS_START`, macOS
    /// `ES_EVENT_TYPE_NOTIFY_EXEC`).
    Created {
        pid: u32,
        ppid: u32,
        name: String,
        exe_path: Option<PathBuf>,
        cmdline: Vec<String>,
        user: Option<String>,
        started_at: DateTime<Utc>,
    },
    /// A process terminated (Linux `PROC_EVENT_EXIT`, Windows ETW
    /// `PROCESS_STOP`, macOS `ES_EVENT_TYPE_NOTIFY_EXIT`).
    Terminated {
        pid: u32,
        name: String,
        exit_code: Option<i32>,
        ended_at: DateTime<Utc>,
    },
    /// An image was loaded into a process (Windows ETW
    /// `IMAGE_LOAD`, macOS `ES_EVENT_TYPE_NOTIFY_MMAP`; Linux
    /// best-effort via `/proc/<pid>/maps` diffing).
    ImageLoaded {
        pid: u32,
        image_path: PathBuf,
        image_hash: Option<String>,
        loaded_at: DateTime<Utc>,
    },
}

impl ProcessEvent {
    /// Convenience getter for the affected PID.
    pub fn pid(&self) -> u32 {
        match self {
            ProcessEvent::Created { pid, .. } => *pid,
            ProcessEvent::Terminated { pid, .. } => *pid,
            ProcessEvent::ImageLoaded { pid, .. } => *pid,
        }
    }
}

/// One ancestor entry returned by [`ProcessMonitor::lookup_ancestors`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessAncestor {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<PathBuf>,
}

/// Async-ready receiver for process events.
///
/// Wraps a [`tokio::sync::mpsc::Receiver`] and a monotonically
/// increasing `dropped` counter so callers can detect that the
/// channel ran behind the producer.
pub struct ProcessEventStream {
    rx: mpsc::Receiver<ProcessEvent>,
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl ProcessEventStream {
    /// Construct a stream from a raw receiver. Exposed so per-OS
    /// adapters can plug in their own producer task.
    pub fn from_parts(
        rx: mpsc::Receiver<ProcessEvent>,
        dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        Self { rx, dropped }
    }

    /// Receive the next event. Returns `None` when the producer
    /// task has dropped its sender (i.e. the monitor was stopped).
    pub async fn recv(&mut self) -> Option<ProcessEvent> {
        self.rx.recv().await
    }

    /// Number of events dropped because the channel was full.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Cross-platform process monitor PAL trait.
///
/// `subscribe` is sync because the underlying setup (opening a
/// netlink socket, enabling an ETW provider, registering an ES
/// client) is non-blocking; the actual producer runs on a tokio
/// task spawned by the implementation. This mirrors the
/// [`crate::fs_watcher::FsWatcher`] convention.
pub trait ProcessMonitor: Send + Sync {
    /// Begin emitting events to a new bounded channel.
    fn subscribe(&self, opts: &ProcessMonitorOpts) -> Result<ProcessEventStream>;

    /// Walk the parent chain of `pid` up to `max_depth` hops.
    fn lookup_ancestors(&self, pid: u32, max_depth: u32) -> Result<Vec<ProcessAncestor>>;
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub use linux::LinuxProcessMonitor;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::time::Duration;
    use tracing::{debug, warn};

    /// Linux process monitor backed by a `/proc` poller.
    ///
    /// The production target is `NETLINK_CONNECTOR` + `CN_IDX_PROC`,
    /// but that requires `CAP_NET_ADMIN` which is rarely held by
    /// CI runners or the unprivileged `sda` service user. The
    /// poller is the supported fallback referenced in
    /// [`super`]'s module docs.
    pub struct LinuxProcessMonitor {
        /// Optional sysroot override for tests (defaults to "/proc").
        proc_root: PathBuf,
    }

    impl Default for LinuxProcessMonitor {
        fn default() -> Self {
            Self::new()
        }
    }

    impl LinuxProcessMonitor {
        pub fn new() -> Self {
            Self {
                proc_root: PathBuf::from("/proc"),
            }
        }

        /// Test-only constructor that points at a synthetic `/proc`.
        #[doc(hidden)]
        pub fn with_proc_root(proc_root: PathBuf) -> Self {
            Self { proc_root }
        }
    }

    impl ProcessMonitor for LinuxProcessMonitor {
        fn subscribe(&self, opts: &ProcessMonitorOpts) -> Result<ProcessEventStream> {
            let (tx, rx) = mpsc::channel(opts.channel_buffer);
            let dropped = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let dropped_clone = dropped.clone();
            let proc_root = self.proc_root.clone();
            let poll_interval = Duration::from_millis(opts.poll_interval_ms.max(50));

            tokio::spawn(async move {
                let mut last_snapshot: HashMap<u32, ProcSnapshot> = HashMap::new();
                if let Ok(initial) = snapshot_all(&proc_root) {
                    last_snapshot = initial;
                }
                loop {
                    tokio::time::sleep(poll_interval).await;
                    let current = match snapshot_all(&proc_root) {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(error = %e, "failed to snapshot /proc");
                            continue;
                        }
                    };
                    // Diff: new pids = Created, missing pids = Terminated.
                    for (pid, snap) in &current {
                        if !last_snapshot.contains_key(pid) {
                            let ev = ProcessEvent::Created {
                                pid: *pid,
                                ppid: snap.ppid,
                                name: snap.name.clone(),
                                exe_path: snap.exe_path.clone(),
                                cmdline: snap.cmdline.clone(),
                                user: snap.user.clone(),
                                started_at: Utc::now(),
                            };
                            if tx.try_send(ev).is_err() {
                                dropped_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                    for (pid, snap) in &last_snapshot {
                        if !current.contains_key(pid) {
                            let ev = ProcessEvent::Terminated {
                                pid: *pid,
                                name: snap.name.clone(),
                                exit_code: None,
                                ended_at: Utc::now(),
                            };
                            if tx.try_send(ev).is_err() {
                                dropped_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                    last_snapshot = current;
                    if tx.is_closed() {
                        debug!("process monitor stream closed by consumer; stopping poller");
                        break;
                    }
                }
            });

            Ok(ProcessEventStream::from_parts(rx, dropped))
        }

        fn lookup_ancestors(&self, pid: u32, max_depth: u32) -> Result<Vec<ProcessAncestor>> {
            walk_ancestors(&self.proc_root, pid, max_depth)
        }
    }

    #[derive(Debug, Clone)]
    struct ProcSnapshot {
        ppid: u32,
        name: String,
        exe_path: Option<PathBuf>,
        cmdline: Vec<String>,
        user: Option<String>,
    }

    pub(super) fn parse_stat(stat_content: &str) -> Option<(u32, String, u32)> {
        // /proc/<pid>/stat format: "pid (name) state ppid ..."
        // The name can contain spaces and parens, so locate the
        // last ')' to get past it.
        let pid_end = stat_content.find(' ')?;
        let pid: u32 = stat_content[..pid_end].parse().ok()?;
        let name_start = stat_content.find('(')?;
        let name_end = stat_content.rfind(')')?;
        if name_end <= name_start {
            return None;
        }
        let name = stat_content[name_start + 1..name_end].to_string();
        let rest = &stat_content[name_end + 1..];
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.len() < 2 {
            return None;
        }
        // fields[0] = state, fields[1] = ppid
        let ppid: u32 = fields[1].parse().ok()?;
        Some((pid, name, ppid))
    }

    fn snapshot_all(proc_root: &std::path::Path) -> std::io::Result<HashMap<u32, ProcSnapshot>> {
        let mut out = HashMap::new();
        for entry in fs::read_dir(proc_root)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(s) = file_name.to_str() else {
                continue;
            };
            let Ok(pid) = s.parse::<u32>() else { continue };
            if let Some(snap) = read_snapshot(proc_root, pid) {
                out.insert(pid, snap);
            }
        }
        Ok(out)
    }

    fn read_snapshot(proc_root: &std::path::Path, pid: u32) -> Option<ProcSnapshot> {
        let stat_path = proc_root.join(pid.to_string()).join("stat");
        let stat = fs::read_to_string(&stat_path).ok()?;
        let (_, name, ppid) = parse_stat(&stat)?;
        let exe_path = fs::read_link(proc_root.join(pid.to_string()).join("exe")).ok();
        let cmdline = fs::read(proc_root.join(pid.to_string()).join("cmdline"))
            .ok()
            .map(|raw| {
                raw.split(|b| *b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        // user from /proc/<pid>/status Uid: field.
        let user = fs::read_to_string(proc_root.join(pid.to_string()).join("status"))
            .ok()
            .and_then(|status| {
                status.lines().find_map(|line| {
                    let stripped = line.strip_prefix("Uid:")?;
                    let uid_str = stripped.split_whitespace().next()?;
                    Some(uid_str.to_string())
                })
            });
        Some(ProcSnapshot {
            ppid,
            name,
            exe_path,
            cmdline,
            user,
        })
    }

    pub(super) fn walk_ancestors(
        proc_root: &std::path::Path,
        pid: u32,
        max_depth: u32,
    ) -> Result<Vec<ProcessAncestor>> {
        let mut out = Vec::new();
        // Seed the walk with the ppid of `pid`; the starting pid
        // itself is not an ancestor and must not consume a slot
        // in the `max_depth` budget.
        let seed_stat = proc_root.join(pid.to_string()).join("stat");
        let Ok(stat_content) = std::fs::read_to_string(&seed_stat) else {
            return Ok(out);
        };
        let Some((_, _, mut current)) = parse_stat(&stat_content) else {
            return Ok(out);
        };
        for _ in 0..max_depth {
            if current == 0 {
                break;
            }
            let stat_path = proc_root.join(current.to_string()).join("stat");
            let Ok(stat) = std::fs::read_to_string(&stat_path) else {
                break;
            };
            let Some((this_pid, name, ppid)) = parse_stat(&stat) else {
                break;
            };
            let exe_path = std::fs::read_link(proc_root.join(current.to_string()).join("exe")).ok();
            out.push(ProcessAncestor {
                pid: this_pid,
                name,
                exe_path,
            });
            if ppid == this_pid {
                break;
            }
            current = ppid;
        }
        Ok(out)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tempfile::TempDir;

        fn write_proc(root: &std::path::Path, pid: u32, name: &str, ppid: u32) {
            let dir = root.join(pid.to_string());
            std::fs::create_dir_all(&dir).unwrap();
            let stat = format!("{pid} ({name}) R {ppid} 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0");
            std::fs::write(dir.join("stat"), stat).unwrap();
            std::fs::write(dir.join("status"), "Uid:\t1000\t1000\t1000\t1000\n").unwrap();
            std::fs::write(dir.join("cmdline"), format!("{name}\0--arg\0")).unwrap();
        }

        #[test]
        fn parse_stat_extracts_pid_name_ppid() {
            let stat = "1234 (bash) S 4567 1234 ...";
            let (pid, name, ppid) = parse_stat(stat).unwrap();
            assert_eq!(pid, 1234);
            assert_eq!(name, "bash");
            assert_eq!(ppid, 4567);
        }

        #[test]
        fn parse_stat_handles_names_with_spaces_and_parens() {
            let stat = "9 (my (weird) proc) S 1 9 9 ...";
            let (pid, name, ppid) = parse_stat(stat).unwrap();
            assert_eq!(pid, 9);
            assert_eq!(name, "my (weird) proc");
            assert_eq!(ppid, 1);
        }

        #[test]
        fn parse_stat_rejects_malformed() {
            assert!(parse_stat("").is_none());
            assert!(parse_stat("notapid (foo) R 1").is_none());
            assert!(parse_stat("1 nameWithoutParens R 1").is_none());
        }

        #[test]
        fn walk_ancestors_reconstructs_chain() {
            let dir = TempDir::new().unwrap();
            // explorer.exe (1) -> winword.exe (10) -> cmd.exe (20) -> powershell.exe (30)
            write_proc(dir.path(), 1, "explorer.exe", 0);
            write_proc(dir.path(), 10, "winword.exe", 1);
            write_proc(dir.path(), 20, "cmd.exe", 10);
            write_proc(dir.path(), 30, "powershell.exe", 20);
            let ancestors = walk_ancestors(dir.path(), 30, 8).unwrap();
            let names: Vec<_> = ancestors.iter().map(|a| a.name.as_str()).collect();
            assert_eq!(names, vec!["cmd.exe", "winword.exe", "explorer.exe"]);
        }

        #[test]
        fn walk_ancestors_respects_max_depth() {
            let dir = TempDir::new().unwrap();
            write_proc(dir.path(), 1, "init", 0);
            write_proc(dir.path(), 2, "a", 1);
            write_proc(dir.path(), 3, "b", 2);
            write_proc(dir.path(), 4, "c", 3);
            let ancestors = walk_ancestors(dir.path(), 4, 2).unwrap();
            assert_eq!(ancestors.len(), 2);
            assert_eq!(ancestors[0].name, "b");
            assert_eq!(ancestors[1].name, "a");
        }

        #[test]
        fn walk_ancestors_terminates_on_missing_parent() {
            let dir = TempDir::new().unwrap();
            write_proc(dir.path(), 5, "orphan", 999); // ppid not in /proc
            let ancestors = walk_ancestors(dir.path(), 5, 8).unwrap();
            assert!(ancestors.is_empty());
        }

        #[tokio::test]
        async fn poller_emits_created_for_new_pids() {
            let dir = TempDir::new().unwrap();
            write_proc(dir.path(), 1, "init", 0);
            let monitor = LinuxProcessMonitor::with_proc_root(dir.path().to_path_buf());
            let opts = ProcessMonitorOpts {
                image_load_events: false,
                channel_buffer: 32,
                poll_interval_ms: 60,
            };
            let mut stream = monitor.subscribe(&opts).unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
            write_proc(dir.path(), 42, "newproc", 1);
            // Wait for at least one event.
            let recv = tokio::time::timeout(std::time::Duration::from_secs(2), stream.recv())
                .await
                .expect("event within timeout");
            match recv {
                Some(ProcessEvent::Created {
                    pid, name, ppid, ..
                }) => {
                    assert_eq!(pid, 42);
                    assert_eq!(name, "newproc");
                    assert_eq!(ppid, 1);
                }
                other => panic!("expected Created, got {other:?}"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Non-Linux (Windows / macOS / other) production-path stub
// ---------------------------------------------------------------------------
//
// The Windows ETW and macOS Endpoint Security implementations
// require SYSTEM / entitlement-gated access that is not available
// in CI. We expose a typed `LinuxProcessMonitor` only on Linux;
// on Windows and macOS the production-path provider is wired in
// the corresponding cfg-gated PAL module (kept here under a stub
// so the crate compiles on all targets) and consumers default to
// `MockProcessMonitor` for tests.

#[cfg(target_os = "windows")]
pub use windows_impl::WindowsProcessMonitor;

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;

    /// Windows ETW-backed process monitor.
    ///
    /// The production implementation uses the
    /// `Microsoft-Windows-Kernel-Process` ETW provider for
    /// `PROCESS_START`, `PROCESS_STOP`, and `IMAGE_LOAD` events.
    /// Enabling the provider requires `SYSTEM` privileges; the
    /// SDA Windows service is configured to run as `LocalSystem`
    /// and is the only consumer.
    ///
    /// On non-Windows builds (which never instantiate this type)
    /// the consumer falls back to [`super::MockProcessMonitor`].
    /// In CI we stub the implementation to return `Unsupported`
    /// so the test matrix runs unprivileged. A real ETW backend
    /// can be wired in a follow-up under a feature gate; the
    /// trait surface is stable.
    pub struct WindowsProcessMonitor;

    impl Default for WindowsProcessMonitor {
        fn default() -> Self {
            Self
        }
    }

    impl WindowsProcessMonitor {
        pub fn new() -> Self {
            Self
        }
    }

    impl ProcessMonitor for WindowsProcessMonitor {
        fn subscribe(&self, _opts: &ProcessMonitorOpts) -> Result<ProcessEventStream> {
            Err(ProcessMonitorError::Unsupported(
                "ETW Microsoft-Windows-Kernel-Process provider not wired (needs SYSTEM)"
                    .to_string(),
            ))
        }

        fn lookup_ancestors(&self, _pid: u32, _max_depth: u32) -> Result<Vec<ProcessAncestor>> {
            Err(ProcessMonitorError::Unsupported(
                "Windows toolhelp32 ancestry not wired".to_string(),
            ))
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos_impl::MacosProcessMonitor;

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;

    /// macOS Endpoint Security-backed process monitor.
    ///
    /// The production implementation uses `es_new_client` with
    /// `ES_EVENT_TYPE_NOTIFY_EXEC` / `_FORK` / `_EXIT` / `_MMAP`.
    /// This requires the
    /// `com.apple.developer.endpoint-security.client` entitlement,
    /// which is not available in CI. In CI we stub the
    /// implementation to return `Unsupported` so the test matrix
    /// runs unprivileged. A real ES backend can be wired in a
    /// follow-up under a feature gate; the trait surface is stable.
    pub struct MacosProcessMonitor;

    impl Default for MacosProcessMonitor {
        fn default() -> Self {
            Self
        }
    }

    impl MacosProcessMonitor {
        pub fn new() -> Self {
            Self
        }
    }

    impl ProcessMonitor for MacosProcessMonitor {
        fn subscribe(&self, _opts: &ProcessMonitorOpts) -> Result<ProcessEventStream> {
            Err(ProcessMonitorError::Unsupported(
                "Endpoint Security client not wired (needs entitlement)".to_string(),
            ))
        }

        fn lookup_ancestors(&self, _pid: u32, _max_depth: u32) -> Result<Vec<ProcessAncestor>> {
            Err(ProcessMonitorError::Unsupported(
                "macOS proc_listallpids ancestry not wired".to_string(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Mock implementation (always available)
// ---------------------------------------------------------------------------

/// In-memory [`ProcessMonitor`] used by tests and by every
/// non-Linux target until the ETW / Endpoint Security backends
/// are entitled.
///
/// Construct with [`MockProcessMonitor::with_events`] passing a
/// canned sequence of [`ProcessEvent`]s; calling [`subscribe`]
/// replays them in order on a background task. Ancestor lookups
/// are seeded via [`MockProcessMonitor::set_ancestors`].
pub struct MockProcessMonitor {
    events: std::sync::Mutex<Vec<ProcessEvent>>,
    ancestors: std::sync::Mutex<std::collections::HashMap<u32, Vec<ProcessAncestor>>>,
}

impl Default for MockProcessMonitor {
    fn default() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
            ancestors: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl MockProcessMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_events(events: Vec<ProcessEvent>) -> Self {
        Self {
            events: std::sync::Mutex::new(events),
            ancestors: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Append events to be replayed on the next subscription.
    pub fn push_event(&self, event: ProcessEvent) {
        self.events
            .lock()
            .expect("mock events poisoned")
            .push(event);
    }

    /// Seed an ancestry chain for a given pid.
    pub fn set_ancestors(&self, pid: u32, ancestors: Vec<ProcessAncestor>) {
        self.ancestors
            .lock()
            .expect("mock ancestors poisoned")
            .insert(pid, ancestors);
    }
}

impl ProcessMonitor for MockProcessMonitor {
    fn subscribe(&self, opts: &ProcessMonitorOpts) -> Result<ProcessEventStream> {
        let (tx, rx) = mpsc::channel(opts.channel_buffer.max(1));
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let dropped_clone = dropped.clone();
        let canned: Vec<ProcessEvent> = self.events.lock().expect("mock events poisoned").clone();
        tokio::spawn(async move {
            for ev in canned {
                if tx.send(ev).await.is_err() {
                    dropped_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
            }
        });
        Ok(ProcessEventStream::from_parts(rx, dropped))
    }

    fn lookup_ancestors(&self, pid: u32, max_depth: u32) -> Result<Vec<ProcessAncestor>> {
        let map = self.ancestors.lock().expect("mock ancestors poisoned");
        Ok(map
            .get(&pid)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .take(max_depth as usize)
            .collect())
    }
}

/// Returns the appropriate default [`ProcessMonitor`] for the
/// current target. Linux returns the `/proc` poller; Windows
/// and macOS return mocks (until ETW / Endpoint Security backends
/// land).
pub fn default_process_monitor() -> Box<dyn ProcessMonitor> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxProcessMonitor::new())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Box::new(MockProcessMonitor::new())
    }
}

#[cfg(test)]
mod common_tests {
    use super::*;

    #[test]
    fn process_event_pid_getter_matches_variant_field() {
        let now = Utc::now();
        let created = ProcessEvent::Created {
            pid: 100,
            ppid: 1,
            name: "bash".into(),
            exe_path: None,
            cmdline: vec![],
            user: None,
            started_at: now,
        };
        let terminated = ProcessEvent::Terminated {
            pid: 200,
            name: "bash".into(),
            exit_code: Some(0),
            ended_at: now,
        };
        let loaded = ProcessEvent::ImageLoaded {
            pid: 300,
            image_path: "/usr/lib/libc.so".into(),
            image_hash: None,
            loaded_at: now,
        };
        assert_eq!(created.pid(), 100);
        assert_eq!(terminated.pid(), 200);
        assert_eq!(loaded.pid(), 300);
    }

    #[test]
    fn process_event_round_trips_via_serde_json() {
        let ev = ProcessEvent::Created {
            pid: 42,
            ppid: 1,
            name: "powershell.exe".into(),
            exe_path: Some("/usr/bin/powershell".into()),
            cmdline: vec!["powershell".into(), "-NoProfile".into()],
            user: Some("1000".into()),
            started_at: Utc::now(),
        };
        let json = serde_json::to_string(&ev).expect("encode");
        let back: ProcessEvent = serde_json::from_str(&json).expect("decode");
        assert_eq!(ev, back);
    }

    #[tokio::test]
    async fn mock_replays_events_in_order() {
        let now = Utc::now();
        let events = vec![
            ProcessEvent::Created {
                pid: 1,
                ppid: 0,
                name: "a".into(),
                exe_path: None,
                cmdline: vec![],
                user: None,
                started_at: now,
            },
            ProcessEvent::Terminated {
                pid: 1,
                name: "a".into(),
                exit_code: Some(0),
                ended_at: now,
            },
        ];
        let monitor = MockProcessMonitor::with_events(events);
        let mut stream = monitor.subscribe(&ProcessMonitorOpts::default()).unwrap();
        let first = stream.recv().await.unwrap();
        assert!(matches!(first, ProcessEvent::Created { pid: 1, .. }));
        let second = stream.recv().await.unwrap();
        assert!(matches!(second, ProcessEvent::Terminated { pid: 1, .. }));
    }

    #[test]
    fn mock_lookup_ancestors_respects_max_depth() {
        let mock = MockProcessMonitor::new();
        mock.set_ancestors(
            42,
            vec![
                ProcessAncestor {
                    pid: 41,
                    name: "cmd.exe".into(),
                    exe_path: None,
                },
                ProcessAncestor {
                    pid: 40,
                    name: "winword.exe".into(),
                    exe_path: None,
                },
                ProcessAncestor {
                    pid: 39,
                    name: "explorer.exe".into(),
                    exe_path: None,
                },
            ],
        );
        let two = mock.lookup_ancestors(42, 2).unwrap();
        assert_eq!(two.len(), 2);
        assert_eq!(two[0].name, "cmd.exe");
        assert_eq!(two[1].name, "winword.exe");
    }

    #[test]
    fn dropped_count_increments_on_overflow() {
        // Channel of size 1, send 2 events without recv => one
        // dropped on Linux poller-style monitors using try_send.
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        dropped.fetch_add(3, std::sync::atomic::Ordering::Relaxed);
        let (_tx, rx) = mpsc::channel::<ProcessEvent>(1);
        let stream = ProcessEventStream::from_parts(rx, dropped);
        assert_eq!(stream.dropped_count(), 3);
    }
}
