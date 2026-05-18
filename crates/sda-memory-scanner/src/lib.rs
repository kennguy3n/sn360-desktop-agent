//! Memory scanning + fileless detection module (Phase E4 of the
//! EDR Parity workstream).
//!
//! Periodically enumerates committed RWX / anonymous / JIT regions
//! of running processes via the platform
//! [`sda_pal::memory_scanner::MemoryScanner`], reads bounded byte
//! slices from each interesting region, and feeds them through an
//! injectable [`MemoryMatcher`] (in production: the YARA matcher in
//! `sda-local-detection`, opt-in AMSI provider on Windows). On a
//! match the module publishes an [`EventKind::MemoryScanAlert`] on
//! the shared event bus.
//!
//! Lifecycle mirrors [`sda_process_monitor::ProcessMonitorModule`]:
//! an [`AtomicU8`] status, a [`ModuleHandle`] returned from
//! `start()`, and a `tokio::select!` loop driven by a
//! [`ShutdownSignal`].
//!
//! ## Safety invariants
//!
//! 1. The agent's own PID is NEVER passed to
//!    [`MemoryScanner::enumerate`] or [`MemoryScanner::read`]
//!    (`docs/architecture.md` § 8.3). Self-pid exclusion is enforced both
//!    at the module level (here) and at the PAL level (in
//!    `sda-pal::memory_scanner`).
//! 2. The bus publish path uses
//!    [`EventBus::publish_to_server`] only — that method already
//!    broadcasts locally before attempting the server-bound queue,
//!    so we deliberately do NOT add a fallback `bus.publish()` call
//!    that would double-fire the LDE pipeline.
//! 3. Scan budgets:
//!    * Bounded per-region reads via
//!      [`MemoryScannerConfig::max_region_bytes`].
//!    * Idle-CPU gating via
//!      [`MemoryScannerConfig::only_when_idle_below_cpu_pct`].
//!    * Battery defer via
//!      [`MemoryScannerConfig::defer_on_battery`] +
//!      [`sda_pal::power::PowerMonitor`].
//!
//!    These together match the `docs/architecture.md` § 5.2 budget
//!    (peak 4 MB RSS / 1% CPU during a scan window).
//!
//! ## AMSI (Windows, optional)
//!
//! With the `amsi` feature enabled on Windows the module additionally
//! registers an [`AmsiProvider`] (mocked behind `#[cfg(test)]`).
//! Off-feature, all AMSI code is excluded at compile time.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use sda_core::config::{AgentConfig, MemoryScannerConfig};
use sda_core::module::{AgentModule, ModuleHandle, ModuleHealth, ModuleStatus};
use sda_core::signal::ShutdownSignal;
use sda_core::time::format_rfc3339_utc_millis;
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use sda_pal::memory_scanner::{default_memory_scanner, MemoryRegion, MemoryScanner};
use sda_pal::power::PowerMonitor;
use sda_pal::types::PowerState;

// AMSI integration is wired up in E4.7. The `amsi` feature toggles
// it on for Windows builds; on other targets the module is absent.
#[cfg(all(feature = "amsi", target_os = "windows"))]
pub mod amsi;
// A test-only mock provider exists on every target so the AMSI
// pipeline is exercised by `cargo test` regardless of OS / feature
// flag (see `amsi_mock::MockAmsiProvider`).
#[cfg(test)]
pub mod amsi_mock;

const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

/// Handle returned by [`MemoryScannerModule::start`].
pub struct MemoryScannerModule {
    status: Arc<AtomicU8>,
}

impl Default for MemoryScannerModule {
    fn default() -> Self {
        Self {
            status: Arc::new(AtomicU8::new(STATUS_INITIALIZED)),
        }
    }
}

impl MemoryScannerModule {
    /// Spawn the run loop using the per-OS default
    /// [`MemoryScanner`] and a process / CPU sampler tuned for the
    /// platform.
    pub fn start(config: &AgentConfig, bus: EventBus, shutdown: ShutdownSignal) -> ModuleHandle {
        let cfg = config.modules.memory_scanner.clone();
        let scanner: Arc<dyn MemoryScanner> = Arc::from(default_memory_scanner());
        let lister: Arc<dyn ProcessLister> = Arc::new(default_process_lister());
        let cpu: Arc<dyn CpuSampler> = Arc::new(default_cpu_sampler());
        let power = Arc::new(PowerMonitor::new());
        let matcher: Arc<dyn MemoryMatcher> = Arc::new(NoopMatcher);
        Self::start_with_deps(cfg, scanner, lister, cpu, power, matcher, bus, shutdown)
    }

    /// Spawn the run loop with fully-injected dependencies. Used by
    /// unit / integration tests to plug in mock scanners, matchers,
    /// and CPU / power sources.
    #[allow(clippy::too_many_arguments)]
    pub fn start_with_deps(
        cfg: MemoryScannerConfig,
        scanner: Arc<dyn MemoryScanner>,
        lister: Arc<dyn ProcessLister>,
        cpu: Arc<dyn CpuSampler>,
        power: Arc<PowerMonitor>,
        matcher: Arc<dyn MemoryMatcher>,
        bus: EventBus,
        shutdown: ShutdownSignal,
    ) -> ModuleHandle {
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);
        let task = tokio::spawn(async move {
            if let Err(e) = run(
                cfg,
                scanner,
                lister,
                cpu,
                power,
                matcher,
                bus,
                shutdown,
                task_status.clone(),
            )
            .await
            {
                error!(error = %e, "memory scanner module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });
        ModuleHandle::new("memory_scanner", task)
    }
}

impl AgentModule for MemoryScannerModule {
    fn name(&self) -> &'static str {
        "memory_scanner"
    }

    fn status(&self) -> ModuleStatus {
        match self.status.load(Ordering::Relaxed) {
            STATUS_RUNNING => ModuleStatus::Running,
            STATUS_STOPPED => ModuleStatus::Stopped,
            STATUS_FAILED => ModuleStatus::Failed,
            _ => ModuleStatus::Initialized,
        }
    }

    fn health(&self) -> ModuleHealth {
        match self.status.load(Ordering::Relaxed) {
            STATUS_FAILED => ModuleHealth::Unhealthy,
            _ => ModuleHealth::Healthy,
        }
    }
}

// ---------------------------------------------------------------------------
// Wire shape
// ---------------------------------------------------------------------------

/// Kind of memory-scan alert. Surfaced on the wire as a string so
/// downstream consumers (LDE, comms) don't have to keep in sync with
/// the Rust enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAlertKind {
    /// A YARA rule matched a slice of process memory.
    YaraMatch,
    /// Windows AMSI returned `AMSI_RESULT_DETECTED` for a buffer
    /// submitted via [`amsi::AmsiProvider`].
    AmsiMatch,
    /// An RWX or otherwise-suspicious region was enumerated. Used
    /// when telemetry-only emission is desired without a content
    /// hit (e.g. for tuning a baseline before enabling YARA rules).
    RwxRegionEnumerated,
}

impl MemoryAlertKind {
    /// Canonical wire string used in JSON payloads.
    pub fn as_wire(&self) -> &'static str {
        match self {
            MemoryAlertKind::YaraMatch => "yara_match",
            MemoryAlertKind::AmsiMatch => "amsi_match",
            MemoryAlertKind::RwxRegionEnumerated => "rwx_region_enumerated",
        }
    }
}

/// Wire shape of a `MemoryScanAlert` payload
/// (`docs/edr.md` § 4 — Memory scanning and fileless detection).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MemoryScanAlertPayload {
    /// PID of the scanned process. NEVER equal to the agent's own
    /// PID — the agent process is unconditionally excluded.
    pub pid: u32,
    /// Best-effort process name (may be empty if the PAL couldn't
    /// resolve it before the alert fired).
    pub process_name: String,
    /// Base address of the matching region.
    pub region_base: u64,
    /// Size in bytes of the matching region.
    pub region_size: u64,
    /// The alert subtype (YARA / AMSI / RWX-enumeration).
    pub alert_type: MemoryAlertKind,
    /// Human-readable description (matched rule id, error string,
    /// etc.). Per `docs/architecture.md` § 8.2 this MUST NOT contain
    /// raw matched bytes from the scanned region.
    pub description: String,
    /// RFC3339 timestamp when the alert was generated.
    pub detected_at: String,
}

// ---------------------------------------------------------------------------
// Matcher trait
// ---------------------------------------------------------------------------

/// Pluggable in-memory content matcher. The production path is
/// implemented in `sda-local-detection` (E4.5) wrapping the existing
/// YARA scanner. Tests inject a deterministic mock.
pub trait MemoryMatcher: Send + Sync {
    /// Match a slice of process memory. Implementations MUST NOT
    /// store the slice beyond the call, and MUST NOT include raw
    /// bytes from the slice in their returned descriptions.
    fn match_bytes(&self, pid: u32, region: &MemoryRegion, bytes: &[u8]) -> Vec<MemoryMatch>;
}

/// A single matcher hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryMatch {
    pub alert_type: MemoryAlertKind,
    /// Human-readable description (matched rule id, etc.). MUST
    /// NOT contain raw matched bytes (`docs/architecture.md` § 8.2).
    pub description: String,
}

/// Matcher that never reports a hit. Used as the default when the
/// memory scanner is wired up before YARA is.
pub struct NoopMatcher;

impl MemoryMatcher for NoopMatcher {
    fn match_bytes(&self, _pid: u32, _region: &MemoryRegion, _bytes: &[u8]) -> Vec<MemoryMatch> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Process lister
// ---------------------------------------------------------------------------

/// One process candidate the scanner may inspect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessHandle {
    pub pid: u32,
    pub name: String,
}

/// Enumerates the PIDs (and best-effort names) of processes
/// currently running on the host. Implementations are platform-
/// specific and may be replaced in tests by [`MockProcessLister`].
pub trait ProcessLister: Send + Sync {
    fn list(&self) -> std::io::Result<Vec<ProcessHandle>>;
}

/// Linux process lister backed by `/proc/<pid>/comm`. Returns the
/// pid plus the truncated comm value (typically 15 chars per the
/// kernel's `TASK_COMM_LEN`).
#[cfg(target_os = "linux")]
pub struct LinuxProcessLister;

#[cfg(target_os = "linux")]
impl ProcessLister for LinuxProcessLister {
    fn list(&self) -> std::io::Result<Vec<ProcessHandle>> {
        let mut handles = Vec::new();
        for entry in std::fs::read_dir("/proc")? {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let file_name = entry.file_name();
            let pid: u32 = match file_name.to_str().and_then(|s| s.parse().ok()) {
                Some(p) => p,
                None => continue,
            };
            let comm_path = entry.path().join("comm");
            let name = std::fs::read_to_string(&comm_path)
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            handles.push(ProcessHandle { pid, name });
        }
        Ok(handles)
    }
}

/// Fallback process lister returning an empty list when the
/// platform doesn't have a native impl yet (production macOS /
/// Windows are wired up via the kernel-mode crates in E6; the
/// user-mode fallback returns nothing rather than crashing).
pub struct UnsupportedProcessLister;

impl ProcessLister for UnsupportedProcessLister {
    fn list(&self) -> std::io::Result<Vec<ProcessHandle>> {
        Ok(Vec::new())
    }
}

#[cfg(target_os = "linux")]
fn default_process_lister() -> impl ProcessLister + 'static {
    LinuxProcessLister
}

#[cfg(not(target_os = "linux"))]
fn default_process_lister() -> impl ProcessLister + 'static {
    UnsupportedProcessLister
}

// ---------------------------------------------------------------------------
// CPU sampler
// ---------------------------------------------------------------------------

/// Samples the system-wide CPU usage as an integer percentage
/// (0-100). Implementations may cache and / or smooth their samples.
pub trait CpuSampler: Send + Sync {
    /// Return the most recent system-wide CPU usage as a percentage.
    /// Implementations that cannot sample (no /proc, no perf
    /// counters, etc.) should return `0` so the gate is permissive
    /// rather than degenerate.
    fn sample_percent(&self) -> u32;
}

/// Sampler that always returns `0`. Used as a fallback so the
/// idle-CPU gate doesn't accidentally block scans on platforms
/// without a native sampler yet.
pub struct ZeroCpuSampler;

impl CpuSampler for ZeroCpuSampler {
    fn sample_percent(&self) -> u32 {
        0
    }
}

/// Linux CPU sampler. Reads two snapshots of `/proc/stat` 100 ms
/// apart and computes the busy / total ratio for the aggregate
/// `cpu` line.
#[cfg(target_os = "linux")]
pub struct ProcStatCpuSampler {
    sample_window_ms: u64,
}

#[cfg(target_os = "linux")]
impl ProcStatCpuSampler {
    pub fn new() -> Self {
        Self {
            sample_window_ms: 100,
        }
    }

    fn read_totals() -> std::io::Result<(u64, u64)> {
        let contents = std::fs::read_to_string("/proc/stat")?;
        let line = contents
            .lines()
            .next()
            .ok_or_else(|| std::io::Error::other("empty /proc/stat"))?;
        if !line.starts_with("cpu ") && !line.starts_with("cpu\t") {
            return Err(std::io::Error::other("first line is not aggregate cpu"));
        }
        // Layout: "cpu  user nice system idle iowait irq softirq ..."
        let mut totals: u64 = 0;
        let mut idle: u64 = 0;
        for (i, token) in line.split_whitespace().skip(1).enumerate() {
            let v: u64 = token.parse().unwrap_or(0);
            totals = totals.saturating_add(v);
            // idle == column 3, iowait == column 4. Treat both as
            // "not busy" so a host blocked on I/O isn't misreported
            // as 100% utilised.
            if i == 3 || i == 4 {
                idle = idle.saturating_add(v);
            }
        }
        Ok((totals, idle))
    }
}

#[cfg(target_os = "linux")]
impl Default for ProcStatCpuSampler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl CpuSampler for ProcStatCpuSampler {
    fn sample_percent(&self) -> u32 {
        let Ok((t1, i1)) = Self::read_totals() else {
            return 0;
        };
        std::thread::sleep(Duration::from_millis(self.sample_window_ms));
        let Ok((t2, i2)) = Self::read_totals() else {
            return 0;
        };
        let dt = t2.saturating_sub(t1);
        let di = i2.saturating_sub(i1);
        if dt == 0 {
            return 0;
        }
        let busy = dt.saturating_sub(di);
        ((busy * 100) / dt).min(100) as u32
    }
}

#[cfg(target_os = "linux")]
fn default_cpu_sampler() -> impl CpuSampler + 'static {
    ProcStatCpuSampler::new()
}

#[cfg(not(target_os = "linux"))]
fn default_cpu_sampler() -> impl CpuSampler + 'static {
    ZeroCpuSampler
}

// ---------------------------------------------------------------------------
// Vitals
// ---------------------------------------------------------------------------

/// Counters surfaced via the agent vitals stream.
#[derive(Debug, Default)]
pub struct MemoryScannerVitals {
    pub scans_started: AtomicU64,
    pub scans_skipped_cpu: AtomicU64,
    pub scans_skipped_battery: AtomicU64,
    pub regions_enumerated: AtomicU64,
    pub regions_scanned: AtomicU64,
    pub matches_emitted: AtomicU64,
    pub publish_failures: AtomicU64,
}

// ---------------------------------------------------------------------------
// Run loop
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run(
    cfg: MemoryScannerConfig,
    scanner: Arc<dyn MemoryScanner>,
    lister: Arc<dyn ProcessLister>,
    cpu: Arc<dyn CpuSampler>,
    power: Arc<PowerMonitor>,
    matcher: Arc<dyn MemoryMatcher>,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    if !cfg.enabled {
        info!("memory scanner disabled; module is a no-op");
        status.store(STATUS_RUNNING, Ordering::Relaxed);
        shutdown.wait().await;
        status.store(STATUS_STOPPED, Ordering::Relaxed);
        return Ok(());
    }

    info!(
        scan_interval_secs = cfg.scan_interval_secs,
        only_when_idle_below_cpu_pct = cfg.only_when_idle_below_cpu_pct,
        defer_on_battery = cfg.defer_on_battery,
        max_region_bytes = cfg.max_region_bytes,
        "memory scanner module starting"
    );

    let vitals = Arc::new(MemoryScannerVitals::default());
    let allow_list = build_allow_list(&cfg);
    let self_pid = scanner.self_pid();
    status.store(STATUS_RUNNING, Ordering::Relaxed);

    // Use a tokio interval so the loop is reactive to shutdown
    // signals without spinning on a wall clock. The first tick fires
    // immediately so an operator who just toggled the module on can
    // see telemetry without waiting for `scan_interval_secs`.
    let interval = Duration::from_secs(cfg.scan_interval_secs.max(1));
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;

            _ = shutdown.wait() => {
                info!("memory scanner received shutdown signal");
                break;
            }

            _ = tick.tick() => {
                // Sample CPU off the tokio runtime: the Linux
                // sampler does a ~100ms `std::thread::sleep` between
                // two `/proc/stat` reads, which would block the
                // single-threaded test runtime and (on the multi-
                // threaded production runtime) stall whichever
                // worker is unlucky enough to poll us at that
                // moment. `spawn_blocking` hands the sleep to the
                // blocking pool. Flagged by the Devin Review bot on
                // PR #25.
                let cpu_for_sample = cpu.clone();
                let busy = tokio::task::spawn_blocking(move || cpu_for_sample.sample_percent())
                    .await
                    .unwrap_or(0);
                scan_once(
                    &cfg,
                    scanner.as_ref(),
                    lister.as_ref(),
                    busy,
                    power.as_ref(),
                    matcher.as_ref(),
                    &bus,
                    self_pid,
                    &allow_list,
                    &vitals,
                ).await;
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!(
        scans_started = vitals.scans_started.load(Ordering::Relaxed),
        scans_skipped_cpu = vitals.scans_skipped_cpu.load(Ordering::Relaxed),
        scans_skipped_battery = vitals.scans_skipped_battery.load(Ordering::Relaxed),
        regions_enumerated = vitals.regions_enumerated.load(Ordering::Relaxed),
        regions_scanned = vitals.regions_scanned.load(Ordering::Relaxed),
        matches_emitted = vitals.matches_emitted.load(Ordering::Relaxed),
        publish_failures = vitals.publish_failures.load(Ordering::Relaxed),
        "memory scanner module stopped"
    );
    Ok(())
}

fn build_allow_list(cfg: &MemoryScannerConfig) -> HashSet<String> {
    let mut set: HashSet<String> = cfg.allow_list_processes.iter().cloned().collect();
    // The agent process is ALWAYS in the allow-list (compile-time
    // invariant per docs/architecture.md § 8.3). We add it both as the
    // canonical binary name (`sn360-desktop-agent`) and as the comm
    // truncation that Linux exposes via `/proc/<pid>/comm`.
    set.insert("sn360-desktop-agent".to_string());
    set.insert("sda-agent".to_string());
    set
}

#[allow(clippy::too_many_arguments)]
async fn scan_once(
    cfg: &MemoryScannerConfig,
    scanner: &dyn MemoryScanner,
    lister: &dyn ProcessLister,
    busy: u32,
    power: &PowerMonitor,
    matcher: &dyn MemoryMatcher,
    bus: &EventBus,
    self_pid: u32,
    allow_list: &HashSet<String>,
    vitals: &Arc<MemoryScannerVitals>,
) {
    vitals.scans_started.fetch_add(1, Ordering::Relaxed);

    // --- CPU gate ---
    // `busy` is the already-sampled host CPU percentage, computed
    // on the blocking pool in `run()` so the ~100ms /proc/stat
    // delta does not stall the async runtime.
    if cfg.only_when_idle_below_cpu_pct < 100 && busy >= cfg.only_when_idle_below_cpu_pct {
        debug!(
            cpu_pct = busy,
            threshold = cfg.only_when_idle_below_cpu_pct,
            "memory scanner deferring scan: cpu above idle threshold"
        );
        vitals.scans_skipped_cpu.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // --- Battery gate ---
    if cfg.defer_on_battery && matches!(power.power_state(), PowerState::Battery) {
        debug!("memory scanner deferring scan: host is on battery");
        vitals.scans_skipped_battery.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // --- Enumerate processes ---
    let processes = match lister.list() {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "memory scanner process enumeration failed");
            return;
        }
    };

    for handle in processes {
        if should_skip_pid(&handle, self_pid, allow_list) {
            continue;
        }
        scan_process(cfg, scanner, matcher, bus, &handle, vitals).await;
    }
}

fn should_skip_pid(handle: &ProcessHandle, self_pid: u32, allow_list: &HashSet<String>) -> bool {
    if handle.pid == 0 {
        // kernel pseudo-process
        return true;
    }
    if handle.pid == self_pid {
        return true;
    }
    if allow_list.contains(&handle.name) {
        return true;
    }
    false
}

async fn scan_process(
    cfg: &MemoryScannerConfig,
    scanner: &dyn MemoryScanner,
    matcher: &dyn MemoryMatcher,
    bus: &EventBus,
    handle: &ProcessHandle,
    vitals: &Arc<MemoryScannerVitals>,
) {
    let regions = match scanner.enumerate(handle.pid) {
        Ok(r) => r,
        Err(e) => {
            debug!(pid = handle.pid, error = %e, "memory scanner enumerate failed");
            return;
        }
    };

    for region in regions {
        if !is_interesting_region(&region) {
            continue;
        }
        vitals.regions_enumerated.fetch_add(1, Ordering::Relaxed);

        let read_len = bounded_read_len(region.size as usize, cfg.max_region_bytes);
        if read_len == 0 {
            continue;
        }
        let mut buf = vec![0u8; read_len];
        let n = match scanner.read(handle.pid, region.base, read_len, &mut buf) {
            Ok(n) => n,
            Err(e) => {
                debug!(
                    pid = handle.pid,
                    base = region.base,
                    error = %e,
                    "memory scanner read failed"
                );
                continue;
            }
        };
        buf.truncate(n);
        vitals.regions_scanned.fetch_add(1, Ordering::Relaxed);

        let matches = matcher.match_bytes(handle.pid, &region, &buf);
        for m in matches {
            emit_alert(bus, handle, &region, &m, vitals).await;
        }
    }
}

fn is_interesting_region(region: &MemoryRegion) -> bool {
    // Defer to the PAL definition (`MemoryRegion::is_interesting`):
    // RWX always wins; anonymous + JIT mappings are scanned even
    // if they aren't currently executable because attackers stage
    // shellcode in RW pages before flipping them to RX. See
    // docs/architecture.md § 3.
    region.is_interesting()
}

fn bounded_read_len(region_size: usize, cap: usize) -> usize {
    if cap == 0 {
        region_size
    } else {
        region_size.min(cap)
    }
}

// Timestamps surfaced into MemoryScanAlert payloads are produced via
// `sda_core::time::format_rfc3339_utc_millis`. There used to be a
// private `civil_from_unix_secs` here; that duplicated logic with
// `sda-identity-monitor`, which the Devin Review bot flagged as a
// maintenance risk. Both crates now share the single
// `sda_core::time` implementation.

async fn emit_alert(
    bus: &EventBus,
    handle: &ProcessHandle,
    region: &MemoryRegion,
    m: &MemoryMatch,
    vitals: &Arc<MemoryScannerVitals>,
) {
    let payload = MemoryScanAlertPayload {
        pid: handle.pid,
        process_name: handle.name.clone(),
        region_base: region.base,
        region_size: region.size,
        alert_type: m.alert_type,
        description: m.description.clone(),
        detected_at: format_rfc3339_utc_millis(std::time::SystemTime::now()),
    };
    let Ok(payload_str) = serde_json::to_string(&payload) else {
        vitals.publish_failures.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let event = Event::new(
        "memory_scanner",
        Priority::High,
        EventKind::MemoryScanAlert {
            payload: payload_str,
        },
    );
    // `publish_to_server` already broadcasts locally before
    // attempting the server queue. Adding a fallback `bus.publish()`
    // here would double-fire the LDE pipeline; see the comment block
    // at the top of this file.
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, "memory scanner server-bound publish failed");
        vitals.publish_failures.fetch_add(1, Ordering::Relaxed);
    } else {
        vitals.matches_emitted.fetch_add(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "test-support"))]
pub use mock::{MockCpuSampler, MockMatcher, MockProcessLister};

#[cfg(any(test, feature = "test-support"))]
pub mod mock {
    //! In-process mock implementations of the dependency traits.
    //!
    //! Exposed under the `test-support` feature so cross-crate E2E
    //! tests in `sda-agent` can construct them without enabling
    //! `cfg(test)`.

    use super::*;
    use std::sync::Mutex;

    /// Mock [`ProcessLister`] returning a canned set of handles.
    pub struct MockProcessLister {
        handles: Mutex<Vec<ProcessHandle>>,
        fail: Mutex<bool>,
    }

    impl MockProcessLister {
        /// Build a new mock lister with the given canned process
        /// handles.
        pub fn new(handles: Vec<ProcessHandle>) -> Self {
            Self {
                handles: Mutex::new(handles),
                fail: Mutex::new(false),
            }
        }

        /// Toggle the "fail next list call" flag. When `true`,
        /// [`ProcessLister::list`] returns a synthetic
        /// `io::Error::other("forced failure")`.
        pub fn set_fail(&self, fail: bool) {
            *self.fail.lock().unwrap() = fail;
        }
    }

    impl ProcessLister for MockProcessLister {
        fn list(&self) -> std::io::Result<Vec<ProcessHandle>> {
            if *self.fail.lock().unwrap() {
                return Err(std::io::Error::other("forced failure"));
            }
            Ok(self.handles.lock().unwrap().clone())
        }
    }

    /// Mock [`CpuSampler`] that returns a configurable fixed value.
    pub struct MockCpuSampler {
        pct: Mutex<u32>,
    }

    impl MockCpuSampler {
        /// Build a new mock sampler pinned to `pct` percent.
        pub fn new(pct: u32) -> Self {
            Self {
                pct: Mutex::new(pct),
            }
        }

        /// Update the pinned percentage at runtime.
        pub fn set(&self, pct: u32) {
            *self.pct.lock().unwrap() = pct;
        }
    }

    impl CpuSampler for MockCpuSampler {
        fn sample_percent(&self) -> u32 {
            *self.pct.lock().unwrap()
        }
    }

    /// Mock [`MemoryMatcher`] that returns a canned set of hits
    /// for every call.
    pub struct MockMatcher {
        hits: Mutex<Vec<MemoryMatch>>,
        call_count: AtomicU64,
    }

    impl MockMatcher {
        /// Build a new mock matcher whose every call yields `hits`.
        pub fn new(hits: Vec<MemoryMatch>) -> Self {
            Self {
                hits: Mutex::new(hits),
                call_count: AtomicU64::new(0),
            }
        }

        /// Number of times [`MemoryMatcher::match_bytes`] has been
        /// invoked.
        pub fn calls(&self) -> u64 {
            self.call_count.load(Ordering::Relaxed)
        }
    }

    impl MemoryMatcher for MockMatcher {
        fn match_bytes(&self, _pid: u32, _r: &MemoryRegion, _b: &[u8]) -> Vec<MemoryMatch> {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            self.hits.lock().unwrap().clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::config::AgentConfig;
    use sda_core::signal::ShutdownController;
    use sda_pal::memory_scanner::{MappingKind, MemoryPermissions, MockMemoryScanner};

    fn rwx() -> MemoryPermissions {
        MemoryPermissions {
            readable: true,
            writable: true,
            executable: true,
        }
    }

    fn rw() -> MemoryPermissions {
        MemoryPermissions {
            readable: true,
            writable: true,
            executable: false,
        }
    }

    fn rx() -> MemoryPermissions {
        MemoryPermissions {
            readable: true,
            writable: false,
            executable: true,
        }
    }

    fn region(base: u64, size: u64, perms: MemoryPermissions, kind: MappingKind) -> MemoryRegion {
        MemoryRegion {
            base,
            size,
            permissions: perms,
            mapping: kind,
        }
    }

    fn yara_hit(rule: &str) -> MemoryMatch {
        MemoryMatch {
            alert_type: MemoryAlertKind::YaraMatch,
            description: format!("yara rule {rule} matched"),
        }
    }

    fn enabled_cfg() -> MemoryScannerConfig {
        MemoryScannerConfig {
            enabled: true,
            scan_interval_secs: 1,
            only_when_idle_below_cpu_pct: 80,
            allow_list_processes: vec!["sn360-desktop-agent".to_string()],
            yara_rule_source: "trds".to_string(),
            defer_on_battery: false,
            max_region_bytes: 4096,
        }
    }

    // ---- pure-function tests ----

    #[test]
    fn defaults_match_phase_e4_spec() {
        let cfg = MemoryScannerConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.scan_interval_secs, 300);
        assert_eq!(cfg.only_when_idle_below_cpu_pct, 20);
        assert_eq!(cfg.allow_list_processes, vec!["sn360-desktop-agent"]);
        assert_eq!(cfg.yara_rule_source, "trds");
        assert!(cfg.defer_on_battery);
        assert_eq!(cfg.max_region_bytes, 4 * 1024 * 1024);
    }

    #[test]
    fn agent_config_round_trip_through_serde() {
        let cfg = AgentConfig::default();
        let s = serde_json::to_string(&cfg.modules.memory_scanner).unwrap();
        let parsed: MemoryScannerConfig = serde_json::from_str(&s).unwrap();
        assert!(!parsed.enabled);
        assert_eq!(parsed.scan_interval_secs, 300);
    }

    #[test]
    fn allow_list_always_contains_agent_binary() {
        let cfg = MemoryScannerConfig {
            allow_list_processes: vec!["something_else".to_string()],
            ..MemoryScannerConfig::default()
        };
        let list = build_allow_list(&cfg);
        assert!(list.contains("sn360-desktop-agent"));
        assert!(list.contains("sda-agent"));
        assert!(list.contains("something_else"));
    }

    #[test]
    fn should_skip_pid_excludes_self_kernel_and_allowlist() {
        let allow: HashSet<String> = ["sn360-desktop-agent".to_string()].into_iter().collect();
        // kernel pseudo-pid
        assert!(should_skip_pid(
            &ProcessHandle {
                pid: 0,
                name: "init".into()
            },
            7777,
            &allow
        ));
        // self
        assert!(should_skip_pid(
            &ProcessHandle {
                pid: 7777,
                name: "any".into()
            },
            7777,
            &allow
        ));
        // allow-list name
        assert!(should_skip_pid(
            &ProcessHandle {
                pid: 99,
                name: "sn360-desktop-agent".into()
            },
            7777,
            &allow
        ));
        // normal process
        assert!(!should_skip_pid(
            &ProcessHandle {
                pid: 99,
                name: "powershell.exe".into()
            },
            7777,
            &allow
        ));
    }

    #[test]
    fn interesting_region_admits_rwx_and_anon_rw_and_jit() {
        assert!(is_interesting_region(&region(
            0x1000,
            4096,
            rwx(),
            MappingKind::Anonymous
        )));
        assert!(is_interesting_region(&region(
            0x2000,
            4096,
            rw(),
            MappingKind::Anonymous
        )));
        assert!(is_interesting_region(&region(
            0x3000,
            4096,
            rwx(),
            MappingKind::Jit
        )));
        // RWX over a file-backed region (e.g. a shared library page
        // that was W^X-violated) is still interesting.
        assert!(is_interesting_region(&region(
            0x4000,
            4096,
            rwx(),
            MappingKind::FileBacked("/usr/lib/libc.so.6".into())
        )));
    }

    #[test]
    fn interesting_region_rejects_rx_file_and_clean_anonymous_ro() {
        // RX over a file-backed library — typical for libc text
        // pages, not interesting.
        assert!(!is_interesting_region(&region(
            0x1000,
            4096,
            rx(),
            MappingKind::FileBacked("/usr/lib/libc.so.6".into())
        )));
        // Read-only anonymous: per the PAL contract, anonymous +
        // JIT mappings ARE considered interesting regardless of
        // their current permission bits (attackers flip perms
        // later). We assert that here so future refactors don't
        // silently weaken the contract.
        assert!(is_interesting_region(&region(
            0x2000,
            4096,
            MemoryPermissions {
                readable: true,
                writable: false,
                executable: false,
            },
            MappingKind::Anonymous
        )));
    }

    #[test]
    fn bounded_read_len_caps_at_max_or_region() {
        // cap < region
        assert_eq!(bounded_read_len(8192, 4096), 4096);
        // region < cap
        assert_eq!(bounded_read_len(2048, 4096), 2048);
        // cap == 0 means read whole region
        assert_eq!(bounded_read_len(8192, 0), 8192);
    }

    // ---- integration-style tests ----

    fn empty_bus() -> (EventBus, sda_event_bus::EventReceiver) {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let rx = bus.subscribe();
        (bus, rx)
    }

    fn with_pid_region(scanner: &Arc<MockMemoryScanner>, pid: u32, r: MemoryRegion, bytes: &[u8]) {
        scanner.set_regions(pid, vec![r.clone()]);
        scanner.set_read(pid, r.base, bytes.to_vec());
    }

    #[tokio::test]
    async fn disabled_module_remains_idle_until_shutdown() {
        let cfg = MemoryScannerConfig {
            enabled: false,
            ..enabled_cfg()
        };
        let scanner: Arc<dyn MemoryScanner> = Arc::new(MockMemoryScanner::with_self_pid(42));
        let lister: Arc<dyn ProcessLister> =
            Arc::new(MockProcessLister::new(vec![ProcessHandle {
                pid: 99,
                name: "victim".into(),
            }]));
        let cpu: Arc<dyn CpuSampler> = Arc::new(MockCpuSampler::new(0));
        let power = Arc::new(PowerMonitor::new());
        let matcher: Arc<dyn MemoryMatcher> =
            Arc::new(MockMatcher::new(vec![yara_hit("memscan_demo")]));
        let (bus, mut rx) = empty_bus();
        let (controller, shutdown) = ShutdownController::new();
        let handle = MemoryScannerModule::start_with_deps(
            cfg, scanner, lister, cpu, power, matcher, bus, shutdown,
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        controller.shutdown();
        handle.task.await.unwrap().unwrap();
        // Drain — should be empty (no MemoryScanAlerts).
        while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(10), rx.recv()).await {
            assert!(
                !matches!(ev.kind, EventKind::MemoryScanAlert { .. }),
                "disabled module emitted an alert: {:?}",
                ev.kind
            );
        }
    }

    #[tokio::test]
    async fn yara_hit_emits_alert_with_canonical_payload() {
        let scanner = Arc::new(MockMemoryScanner::with_self_pid(42));
        with_pid_region(
            &scanner,
            99,
            region(0x1000_0000, 8192, rwx(), MappingKind::Anonymous),
            &b"shellcode_here"[..],
        );
        let lister: Arc<dyn ProcessLister> =
            Arc::new(MockProcessLister::new(vec![ProcessHandle {
                pid: 99,
                name: "victim".into(),
            }]));
        let cpu: Arc<dyn CpuSampler> = Arc::new(MockCpuSampler::new(0));
        let power = Arc::new(PowerMonitor::new());
        let matcher: Arc<dyn MemoryMatcher> =
            Arc::new(MockMatcher::new(vec![yara_hit("memscan_demo")]));
        let (bus, mut rx) = empty_bus();
        let (controller, shutdown) = ShutdownController::new();
        let handle = MemoryScannerModule::start_with_deps(
            enabled_cfg(),
            scanner.clone() as Arc<dyn MemoryScanner>,
            lister,
            cpu,
            power,
            matcher,
            bus,
            shutdown,
        );

        let ev = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("event within timeout")
            .expect("bus open");
        controller.shutdown();
        let _ = handle.task.await;

        let EventKind::MemoryScanAlert { payload } = ev.kind else {
            panic!("expected MemoryScanAlert, got {:?}", ev.kind);
        };
        let parsed: MemoryScanAlertPayload = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed.pid, 99);
        assert_eq!(parsed.process_name, "victim");
        assert_eq!(parsed.region_base, 0x1000_0000);
        assert_eq!(parsed.region_size, 8192);
        assert_eq!(parsed.alert_type, MemoryAlertKind::YaraMatch);
        assert!(
            !parsed.description.contains("shellcode_here"),
            "description leaked raw matched bytes"
        );
        assert!(parsed.description.contains("memscan_demo"));
    }

    #[tokio::test]
    async fn allow_listed_process_is_never_scanned() {
        let scanner = Arc::new(MockMemoryScanner::with_self_pid(42));
        // Pre-populate the agent binary's region so a buggy
        // implementation would emit a hit.
        with_pid_region(
            &scanner,
            7777,
            region(0xA000, 4096, rwx(), MappingKind::Anonymous),
            &b"agent-data"[..],
        );
        let lister: Arc<dyn ProcessLister> =
            Arc::new(MockProcessLister::new(vec![ProcessHandle {
                pid: 7777,
                name: "sn360-desktop-agent".into(),
            }]));
        let matcher = Arc::new(MockMatcher::new(vec![yara_hit("agent_should_not_fire")]));
        let cpu: Arc<dyn CpuSampler> = Arc::new(MockCpuSampler::new(0));
        let power = Arc::new(PowerMonitor::new());
        let (bus, mut rx) = empty_bus();
        let (controller, shutdown) = ShutdownController::new();
        let handle = MemoryScannerModule::start_with_deps(
            enabled_cfg(),
            scanner.clone() as Arc<dyn MemoryScanner>,
            lister,
            cpu,
            power,
            matcher.clone() as Arc<dyn MemoryMatcher>,
            bus,
            shutdown,
        );

        tokio::time::sleep(Duration::from_millis(200)).await;
        controller.shutdown();
        let _ = handle.task.await;

        assert_eq!(
            matcher.calls(),
            0,
            "matcher must not be called on allow-listed pid"
        );
        while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(10), rx.recv()).await {
            assert!(
                !matches!(ev.kind, EventKind::MemoryScanAlert { .. }),
                "alert fired on allow-listed pid"
            );
        }
    }

    #[tokio::test]
    async fn self_pid_is_always_excluded_even_if_not_in_allow_list() {
        let scanner = Arc::new(MockMemoryScanner::with_self_pid(7777));
        // Pretend a separate process happens to share the PID slot
        // we report as "self_pid". The module must still skip it.
        with_pid_region(
            &scanner,
            7777,
            region(0xB000, 4096, rwx(), MappingKind::Anonymous),
            &b"data"[..],
        );
        let lister: Arc<dyn ProcessLister> =
            Arc::new(MockProcessLister::new(vec![ProcessHandle {
                pid: 7777,
                name: "renamed-binary".into(), // NOT in allow-list
            }]));
        let matcher = Arc::new(MockMatcher::new(vec![yara_hit("self_pid_bypass")]));
        let cpu: Arc<dyn CpuSampler> = Arc::new(MockCpuSampler::new(0));
        let power = Arc::new(PowerMonitor::new());
        let (bus, mut rx) = empty_bus();
        let (controller, shutdown) = ShutdownController::new();
        let handle = MemoryScannerModule::start_with_deps(
            enabled_cfg(),
            scanner.clone() as Arc<dyn MemoryScanner>,
            lister,
            cpu,
            power,
            matcher.clone() as Arc<dyn MemoryMatcher>,
            bus,
            shutdown,
        );

        tokio::time::sleep(Duration::from_millis(200)).await;
        controller.shutdown();
        let _ = handle.task.await;

        assert_eq!(matcher.calls(), 0, "self-pid must never reach the matcher");
        while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(10), rx.recv()).await {
            assert!(
                !matches!(ev.kind, EventKind::MemoryScanAlert { .. }),
                "alert fired on self-pid"
            );
        }
    }

    #[tokio::test]
    async fn cpu_above_threshold_skips_scan_window() {
        let scanner = Arc::new(MockMemoryScanner::with_self_pid(42));
        with_pid_region(
            &scanner,
            99,
            region(0xC000, 4096, rwx(), MappingKind::Anonymous),
            &b"data"[..],
        );
        let lister: Arc<dyn ProcessLister> =
            Arc::new(MockProcessLister::new(vec![ProcessHandle {
                pid: 99,
                name: "victim".into(),
            }]));
        let matcher = Arc::new(MockMatcher::new(vec![yara_hit("cpu_gate")]));
        // 90% busy with a 20% idle-threshold -> scans must be skipped.
        let cpu: Arc<dyn CpuSampler> = Arc::new(MockCpuSampler::new(90));
        let power = Arc::new(PowerMonitor::new());
        let cfg = MemoryScannerConfig {
            only_when_idle_below_cpu_pct: 20,
            ..enabled_cfg()
        };
        let (bus, mut rx) = empty_bus();
        let (controller, shutdown) = ShutdownController::new();
        let handle = MemoryScannerModule::start_with_deps(
            cfg,
            scanner.clone() as Arc<dyn MemoryScanner>,
            lister,
            cpu,
            power,
            matcher.clone() as Arc<dyn MemoryMatcher>,
            bus,
            shutdown,
        );

        tokio::time::sleep(Duration::from_millis(200)).await;
        controller.shutdown();
        let _ = handle.task.await;

        assert_eq!(matcher.calls(), 0, "scan ran despite cpu over threshold");
        while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(10), rx.recv()).await {
            assert!(
                !matches!(ev.kind, EventKind::MemoryScanAlert { .. }),
                "alert fired despite cpu gate"
            );
        }
    }

    #[tokio::test]
    async fn idle_threshold_100_disables_the_cpu_gate() {
        let scanner = Arc::new(MockMemoryScanner::with_self_pid(42));
        with_pid_region(
            &scanner,
            99,
            region(0xD000, 4096, rwx(), MappingKind::Anonymous),
            &b"hit"[..],
        );
        let lister: Arc<dyn ProcessLister> =
            Arc::new(MockProcessLister::new(vec![ProcessHandle {
                pid: 99,
                name: "victim".into(),
            }]));
        let matcher = Arc::new(MockMatcher::new(vec![yara_hit("ungated")]));
        // CPU is pegged but threshold is 100 -> gate disabled.
        let cpu: Arc<dyn CpuSampler> = Arc::new(MockCpuSampler::new(99));
        let power = Arc::new(PowerMonitor::new());
        let cfg = MemoryScannerConfig {
            only_when_idle_below_cpu_pct: 100,
            ..enabled_cfg()
        };
        let (bus, mut rx) = empty_bus();
        let (controller, shutdown) = ShutdownController::new();
        let handle = MemoryScannerModule::start_with_deps(
            cfg,
            scanner.clone() as Arc<dyn MemoryScanner>,
            lister,
            cpu,
            power,
            matcher,
            bus,
            shutdown,
        );

        let ev = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("alert within timeout")
            .expect("bus open");
        controller.shutdown();
        let _ = handle.task.await;
        assert!(matches!(ev.kind, EventKind::MemoryScanAlert { .. }));
    }

    #[tokio::test]
    async fn clean_memory_produces_no_alert() {
        let scanner = Arc::new(MockMemoryScanner::with_self_pid(42));
        with_pid_region(
            &scanner,
            99,
            region(0xE000, 4096, rwx(), MappingKind::Anonymous),
            &b"benign data"[..],
        );
        let lister: Arc<dyn ProcessLister> =
            Arc::new(MockProcessLister::new(vec![ProcessHandle {
                pid: 99,
                name: "victim".into(),
            }]));
        // Matcher returns no hits.
        let matcher = Arc::new(MockMatcher::new(vec![]));
        let cpu: Arc<dyn CpuSampler> = Arc::new(MockCpuSampler::new(0));
        let power = Arc::new(PowerMonitor::new());
        let (bus, mut rx) = empty_bus();
        let (controller, shutdown) = ShutdownController::new();
        let handle = MemoryScannerModule::start_with_deps(
            enabled_cfg(),
            scanner.clone() as Arc<dyn MemoryScanner>,
            lister,
            cpu,
            power,
            matcher.clone() as Arc<dyn MemoryMatcher>,
            bus,
            shutdown,
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        controller.shutdown();
        let _ = handle.task.await;
        assert!(matcher.calls() >= 1, "matcher should have been invoked");
        while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(10), rx.recv()).await {
            assert!(
                !matches!(ev.kind, EventKind::MemoryScanAlert { .. }),
                "alert fired on clean memory"
            );
        }
    }

    #[tokio::test]
    async fn non_interesting_regions_are_not_scanned() {
        let scanner = Arc::new(MockMemoryScanner::with_self_pid(42));
        // RX file-backed (e.g. libc text page): not interesting.
        with_pid_region(
            &scanner,
            99,
            region(
                0xF000,
                4096,
                rx(),
                MappingKind::FileBacked("/usr/lib/libc.so.6".into()),
            ),
            &b"libc"[..],
        );
        // RW file-backed (e.g. mmap'd data file): not interesting
        // either. The PAL is_interesting() rule admits only RWX,
        // anonymous, and JIT mappings.
        with_pid_region(
            &scanner,
            99,
            region(
                0xF1000,
                4096,
                rw(),
                MappingKind::FileBacked("/var/log/example.dat".into()),
            ),
            &b"data"[..],
        );
        let lister: Arc<dyn ProcessLister> =
            Arc::new(MockProcessLister::new(vec![ProcessHandle {
                pid: 99,
                name: "victim".into(),
            }]));
        let matcher = Arc::new(MockMatcher::new(vec![yara_hit("should_not_run")]));
        let cpu: Arc<dyn CpuSampler> = Arc::new(MockCpuSampler::new(0));
        let power = Arc::new(PowerMonitor::new());
        let (bus, _rx) = empty_bus();
        let (controller, shutdown) = ShutdownController::new();
        let handle = MemoryScannerModule::start_with_deps(
            enabled_cfg(),
            scanner.clone() as Arc<dyn MemoryScanner>,
            lister,
            cpu,
            power,
            matcher.clone() as Arc<dyn MemoryMatcher>,
            bus,
            shutdown,
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        controller.shutdown();
        let _ = handle.task.await;
        assert_eq!(
            matcher.calls(),
            0,
            "matcher must not be invoked for uninteresting regions"
        );
    }

    #[tokio::test]
    async fn bounded_read_clamps_large_regions() {
        let scanner = Arc::new(MockMemoryScanner::with_self_pid(42));
        // 1 MiB region but the config caps reads at 4 KiB.
        let big = region(0x1_0000, 1024 * 1024, rwx(), MappingKind::Anonymous);
        scanner.set_regions(99, vec![big.clone()]);
        // Mock byte store contains the full 1 MiB so any over-read
        // would succeed at the PAL layer.
        scanner.set_read(99, big.base, vec![0xAA; 1024 * 1024]);

        let lister: Arc<dyn ProcessLister> =
            Arc::new(MockProcessLister::new(vec![ProcessHandle {
                pid: 99,
                name: "victim".into(),
            }]));
        // Matcher records the byte length it sees.
        struct LenCapture(Arc<AtomicU64>);
        impl MemoryMatcher for LenCapture {
            fn match_bytes(&self, _: u32, _: &MemoryRegion, bytes: &[u8]) -> Vec<MemoryMatch> {
                self.0.store(bytes.len() as u64, Ordering::Relaxed);
                Vec::new()
            }
        }
        let observed = Arc::new(AtomicU64::new(0));
        let matcher: Arc<dyn MemoryMatcher> = Arc::new(LenCapture(observed.clone()));
        let cpu: Arc<dyn CpuSampler> = Arc::new(MockCpuSampler::new(0));
        let power = Arc::new(PowerMonitor::new());
        let cfg = MemoryScannerConfig {
            max_region_bytes: 4096,
            ..enabled_cfg()
        };
        let (bus, _rx) = empty_bus();
        let (controller, shutdown) = ShutdownController::new();
        let handle = MemoryScannerModule::start_with_deps(
            cfg,
            scanner.clone() as Arc<dyn MemoryScanner>,
            lister,
            cpu,
            power,
            matcher,
            bus,
            shutdown,
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        controller.shutdown();
        let _ = handle.task.await;
        let n = observed.load(Ordering::Relaxed);
        assert!(n > 0 && n <= 4096, "expected bounded read, got {n}");
    }

    #[tokio::test]
    async fn process_lister_failure_does_not_crash_module() {
        let scanner: Arc<dyn MemoryScanner> = Arc::new(MockMemoryScanner::with_self_pid(42));
        let lister = Arc::new(MockProcessLister::new(vec![]));
        lister.set_fail(true);
        let cpu: Arc<dyn CpuSampler> = Arc::new(MockCpuSampler::new(0));
        let power = Arc::new(PowerMonitor::new());
        let matcher: Arc<dyn MemoryMatcher> = Arc::new(NoopMatcher);
        let (bus, _rx) = empty_bus();
        let (controller, shutdown) = ShutdownController::new();
        let handle = MemoryScannerModule::start_with_deps(
            enabled_cfg(),
            scanner,
            lister.clone() as Arc<dyn ProcessLister>,
            cpu,
            power,
            matcher,
            bus,
            shutdown,
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        controller.shutdown();
        // Task should complete cleanly (Ok), not panic / Err.
        handle.task.await.unwrap().unwrap();
    }

    #[test]
    fn memory_scan_alert_payload_round_trips_via_serde() {
        let p = MemoryScanAlertPayload {
            pid: 1234,
            process_name: "victim".into(),
            region_base: 0x4000,
            region_size: 8192,
            alert_type: MemoryAlertKind::AmsiMatch,
            description: "powershell encoded command".into(),
            detected_at: "2026-05-18T00:00:00Z".into(),
        };
        let s = serde_json::to_string(&p).unwrap();
        let parsed: MemoryScanAlertPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn memory_alert_kind_round_trips_through_wire_string() {
        for kind in [
            MemoryAlertKind::YaraMatch,
            MemoryAlertKind::AmsiMatch,
            MemoryAlertKind::RwxRegionEnumerated,
        ] {
            let s = serde_json::to_string(&kind).unwrap();
            let parsed: MemoryAlertKind = serde_json::from_str(&s).unwrap();
            assert_eq!(parsed, kind);
            // `as_wire()` should match the serde rename_all="snake_case".
            assert!(s.contains(kind.as_wire()));
        }
    }

    #[test]
    fn unsupported_process_lister_returns_empty_list() {
        let lister = UnsupportedProcessLister;
        let list = lister.list().unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn zero_cpu_sampler_returns_zero() {
        assert_eq!(ZeroCpuSampler.sample_percent(), 0);
    }

    #[test]
    fn noop_matcher_never_hits() {
        let r = region(0x1000, 4096, rwx(), MappingKind::Anonymous);
        let hits = NoopMatcher.match_bytes(99, &r, b"anything");
        assert!(hits.is_empty());
    }

    #[test]
    fn agent_module_trait_surfaces_status_and_health() {
        let m = MemoryScannerModule::default();
        assert_eq!(m.name(), "memory_scanner");
        assert_eq!(m.status(), ModuleStatus::Initialized);
        assert_eq!(m.health(), ModuleHealth::Healthy);
        m.status.store(STATUS_FAILED, Ordering::Relaxed);
        assert_eq!(m.status(), ModuleStatus::Failed);
        assert_eq!(m.health(), ModuleHealth::Unhealthy);
    }
}
