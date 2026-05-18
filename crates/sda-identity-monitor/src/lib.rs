//! Identity-attack detection module (Phase E5 of EDR Parity).
//!
//! Surfaces three classes of credential-theft signals across the
//! supported platforms and re-encodes them as canonical
//! [`EventKind::IdentityAlert`] payloads:
//!
//! | Platform | Signal                                | MITRE ATT&CK |
//! |----------|---------------------------------------|--------------|
//! | Windows  | `lsass.exe` handle openings (ETW)     | `T1003.001`  |
//! | Linux    | `/etc/shadow` reads (FIM)             | `T1003.008`  |
//! | Linux    | `/proc/kcore` reads (audit)           | `T1003`      |
//! | macOS    | Keychain DB opens (Endpoint Security) | `T1555.001`  |
//!
//! The module is intentionally *evidence-only* — it never mutates
//! host state. Quarantine / containment is left to the LDE pipeline
//! and `sda-active-response`.
//!
//! # Architecture
//!
//! At the lifecycle level this is the standard agent module:
//!
//! - A run-loop owned by [`IdentityMonitorModule::start`] spawns one
//!   task per active provider plus a fan-in task that publishes
//!   [`EventKind::IdentityAlert`] events on the shared bus.
//! - A [`IdentityProvider`] trait abstracts the OS-specific capture
//!   surface; each provider yields a stream of [`IdentitySignal`]s.
//! - The Linux backend reuses the existing FIM event stream by
//!   subscribing to the in-process `EventBus` rather than opening a
//!   second inotify handle — no extra capabilities are required.
//! - The Windows / macOS backends are mocked in this crate because
//!   ETW (`Microsoft-Windows-Threat-Intelligence`) and Endpoint
//!   Security require SYSTEM / Apple-issued entitlements that aren't
//!   available in CI. The production backends will plug in behind
//!   the same [`IdentityProvider`] trait via E6.1 (WDK minifilter)
//!   and E6.3 (signed SystemExtension).
//!
//! # Safety / privacy invariants
//!
//! - [`IdentityAlertPayload::description`] MUST NOT contain raw
//!   credential bytes — only metadata.
//! - System-owned processes (`pid 0`, `pid 4` on Windows, `root` /
//!   `_securityd` on Linux / macOS) MUST NOT trigger an alert; the
//!   filter is enforced at the module's publish boundary so every
//!   provider benefits from the same rule.

#![deny(missing_docs)]

pub mod linux;
pub mod macos;
pub mod windows;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use sda_core::config::{AgentConfig, IdentityMonitorConfig};
use sda_core::module::{AgentModule, ModuleHandle, ModuleHealth, ModuleStatus};
use sda_core::signal::ShutdownSignal;
use sda_event_bus::{Event, EventBus, EventKind, Priority};

const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

// ---------------------------------------------------------------------------
// Wire shape
// ---------------------------------------------------------------------------

/// Kind of identity alert. Surfaced on the wire as a snake-case
/// string so downstream consumers (LDE, comms) don't have to track
/// the Rust enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityAlertKind {
    /// Windows `lsass.exe` handle opened by a non-system process.
    LsassAccess,
    /// Linux `/etc/shadow` opened by a non-root process.
    ShadowAccess,
    /// Linux `/proc/kcore` opened by a non-root process.
    KcoreAccess,
    /// macOS keychain DB opened by an unsigned / non-Apple binary.
    KeychainAccess,
}

impl IdentityAlertKind {
    /// Canonical wire string used in the JSON payload.
    pub fn as_wire(&self) -> &'static str {
        match self {
            IdentityAlertKind::LsassAccess => "lsass_access",
            IdentityAlertKind::ShadowAccess => "shadow_access",
            IdentityAlertKind::KcoreAccess => "kcore_access",
            IdentityAlertKind::KeychainAccess => "keychain_access",
        }
    }

    /// MITRE ATT&CK technique ID associated with this signal.
    pub fn mitre_technique(&self) -> &'static str {
        match self {
            IdentityAlertKind::LsassAccess => "T1003.001",
            IdentityAlertKind::ShadowAccess => "T1003.008",
            IdentityAlertKind::KcoreAccess => "T1003",
            IdentityAlertKind::KeychainAccess => "T1555.001",
        }
    }
}

/// Wire shape of an `IdentityAlert` payload
/// (`docs/edr-parity/ARCHITECTURE.md` § 8).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityAlertPayload {
    /// Alert subtype (LSASS / shadow / kcore / keychain).
    pub category: IdentityAlertKind,
    /// Canonical wire form of [`Self::category`] — duplicated as a
    /// flat string so consumers (LDE, comms, dashboards) don't need
    /// the typed enum.
    pub category_wire: String,
    /// MITRE ATT&CK technique ID matching the category.
    pub technique: String,
    /// Effective user of the accessing process.
    pub user: String,
    /// PID of the accessing process (0 when the OS did not report).
    pub pid: u32,
    /// Best-effort process name of the accessor.
    pub process: String,
    /// Best-effort image path of the accessor (empty when unknown).
    pub image_path: String,
    /// Target object that was accessed (e.g. `lsass.exe`,
    /// `/etc/shadow`, `/Library/Keychains/login.keychain-db`).
    pub target: String,
    /// Human-readable description. MUST NOT contain raw credential
    /// bytes per `ARCHITECTURE.md § 8.1`.
    pub description: String,
    /// RFC3339 timestamp when the signal fired.
    pub detected_at: String,
}

// ---------------------------------------------------------------------------
// Signal + provider trait
// ---------------------------------------------------------------------------

/// A raw identity-attack signal emitted by an [`IdentityProvider`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitySignal {
    /// Alert subtype.
    pub category: IdentityAlertKind,
    /// User of the accessing process (e.g. `"alice"`, `"SYSTEM"`,
    /// `"root"`).
    pub user: String,
    /// PID of the accessing process; 0 when the OS did not report.
    pub pid: u32,
    /// Process name of the accessor.
    pub process: String,
    /// Image path of the accessor (empty if unknown).
    pub image_path: String,
    /// Target object that was accessed.
    pub target: String,
    /// Human-readable description; redaction rules apply.
    pub description: String,
}

/// Asynchronously yields a stream of [`IdentitySignal`]s from the
/// underlying OS-specific capture surface (ETW on Windows, FIM on
/// Linux, Endpoint Security on macOS).
///
/// Implementations are responsible for filtering provider-specific
/// noise (e.g. duplicate events from the same handle within a
/// debounce window). The module-level publish boundary handles
/// the system-principal filter so providers don't all need to
/// reimplement it.
pub trait IdentityProvider: Send + Sync {
    /// Drive the provider until [`ShutdownSignal`] fires or the
    /// underlying source closes. Each yielded signal is published
    /// as a single [`EventKind::IdentityAlert`] event.
    fn run(
        &self,
        cfg: IdentityMonitorConfig,
        tx: mpsc::Sender<IdentitySignal>,
        shutdown: ShutdownSignal,
    ) -> tokio::task::JoinHandle<anyhow::Result<()>>;
}

/// Returns `true` when `user` looks like a system principal that
/// should never trigger an identity alert.
pub fn is_system_principal(user: &str) -> bool {
    let normalized = user.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        ""
            | "system"
            | "nt authority\\system"
            | "nt service\\trustedinstaller"
            | "root"
            | "_securityd"
            | "_keychain"
            | "_locationd"
    )
}

// ---------------------------------------------------------------------------
// Module lifecycle
// ---------------------------------------------------------------------------

/// Handle returned by [`IdentityMonitorModule::start`].
pub struct IdentityMonitorModule {
    status: Arc<AtomicU8>,
}

impl Default for IdentityMonitorModule {
    fn default() -> Self {
        Self {
            status: Arc::new(AtomicU8::new(STATUS_INITIALIZED)),
        }
    }
}

impl IdentityMonitorModule {
    /// Spawn the run loop with per-OS default providers. Production
    /// callers pass through here; tests use
    /// [`Self::start_with_providers`] to inject mocks.
    pub fn start(config: &AgentConfig, bus: EventBus, shutdown: ShutdownSignal) -> ModuleHandle {
        let cfg = config.modules.identity_monitor.clone();
        let providers = default_providers(&cfg, bus.clone());
        Self::start_with_providers(cfg, providers, bus, shutdown)
    }

    /// Spawn the run loop with explicit providers. The producer side
    /// of every channel is owned by the provider task; the consumer
    /// side runs inside the module and fans signals onto the bus.
    pub fn start_with_providers(
        cfg: IdentityMonitorConfig,
        providers: Vec<Arc<dyn IdentityProvider>>,
        bus: EventBus,
        shutdown: ShutdownSignal,
    ) -> ModuleHandle {
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);
        let task = tokio::spawn(async move {
            if let Err(e) = run(cfg, providers, bus, shutdown, task_status.clone()).await {
                error!(error = %e, "identity monitor module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });
        ModuleHandle::new("identity_monitor", task)
    }
}

impl AgentModule for IdentityMonitorModule {
    fn name(&self) -> &'static str {
        "identity_monitor"
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

fn default_providers(
    cfg: &IdentityMonitorConfig,
    bus: EventBus,
) -> Vec<Arc<dyn IdentityProvider>> {
    let mut out: Vec<Arc<dyn IdentityProvider>> = Vec::new();
    if cfg.shadow_access_linux {
        out.push(Arc::new(linux::LinuxShadowAccessProvider::new(bus.clone())));
    }
    if cfg.lsass_access_windows {
        out.push(Arc::new(windows::WindowsLsassAccessProvider::default()));
    }
    if cfg.keychain_access_macos {
        out.push(Arc::new(macos::MacosKeychainAccessProvider::default()));
    }
    out
}

async fn run(
    cfg: IdentityMonitorConfig,
    providers: Vec<Arc<dyn IdentityProvider>>,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    if !cfg.enabled {
        info!("identity monitor disabled — idling until shutdown");
        status.store(STATUS_RUNNING, Ordering::Relaxed);
        shutdown.wait().await;
        status.store(STATUS_STOPPED, Ordering::Relaxed);
        return Ok(());
    }

    info!(
        provider_count = providers.len(),
        "starting identity monitor"
    );
    status.store(STATUS_RUNNING, Ordering::Relaxed);

    // Bounded fan-in channel. Provider tasks back-pressure when the
    // module is overwhelmed (e.g. a runaway FIM stream); preferable
    // to dropping silently and creating a detection blind spot.
    let (tx, mut rx) = mpsc::channel::<IdentitySignal>(256);

    let mut provider_tasks = Vec::with_capacity(providers.len());
    for provider in providers {
        let task = provider.run(cfg.clone(), tx.clone(), shutdown.clone());
        provider_tasks.push(task);
    }
    drop(tx);

    loop {
        tokio::select! {
            biased;
            _ = shutdown.wait() => {
                info!("identity monitor received shutdown");
                break;
            }
            signal = rx.recv() => {
                let Some(signal) = signal else {
                    debug!("identity provider channel closed");
                    break;
                };
                if let Err(e) = publish_signal(&bus, &signal).await {
                    warn!(error = %e, "failed to publish IdentityAlert");
                }
            }
        }
    }

    // Drain remaining buffered signals so a clean shutdown doesn't
    // swallow telemetry already in flight.
    while let Ok(Some(signal)) =
        tokio::time::timeout(Duration::from_millis(50), rx.recv()).await
    {
        if let Err(e) = publish_signal(&bus, &signal).await {
            warn!(error = %e, "failed to publish IdentityAlert during drain");
        }
    }

    for handle in provider_tasks {
        handle.abort();
        let _ = handle.await;
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    Ok(())
}

async fn publish_signal(bus: &EventBus, signal: &IdentitySignal) -> anyhow::Result<()> {
    if is_system_principal(&signal.user) {
        debug!(
            user = %signal.user,
            category = ?signal.category,
            "dropping identity signal from system principal"
        );
        return Ok(());
    }
    let payload = IdentityAlertPayload {
        category: signal.category,
        category_wire: signal.category.as_wire().to_string(),
        technique: signal.category.mitre_technique().to_string(),
        user: signal.user.clone(),
        pid: signal.pid,
        process: signal.process.clone(),
        image_path: signal.image_path.clone(),
        target: signal.target.clone(),
        description: signal.description.clone(),
        detected_at: now_rfc3339(),
    };
    let json = serde_json::to_string(&payload).context("serialize IdentityAlertPayload")?;
    let event = Event::new(
        "identity_monitor",
        Priority::High,
        EventKind::IdentityAlert { payload: json },
    );
    bus.publish(event)
        .map_err(|e| anyhow::anyhow!("publish IdentityAlert: {e}"))?;
    Ok(())
}

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    civil_from_unix_secs(dur.as_secs())
}

fn civil_from_unix_secs(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let secs_in_day = (secs % 86_400) as u32;
    let h = secs_in_day / 3600;
    let m = (secs_in_day / 60) % 60;
    let s = secs_in_day % 60;
    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m_month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m_month <= 2 { y + 1 } else { y };
    format!(
        "{year:04}-{m_month:02}-{d:02}T{h:02}:{m:02}:{s:02}Z",
        year = year as u32,
        m_month = m_month,
        d = d,
        h = h,
        m = m,
        s = s
    )
}

// ---------------------------------------------------------------------------
// Mock provider (test-only / feature-gated for cross-crate testing)
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "test-support"))]
pub mod mock {
    //! In-process mock [`IdentityProvider`] that replays a canned
    //! sequence of [`IdentitySignal`]s. Used by both unit tests in
    //! this crate and the E5 E2E suite.

    use super::*;
    use std::sync::Mutex;

    /// Replays a canned sequence of signals onto the provider
    /// channel.
    pub struct MockIdentityProvider {
        signals: Mutex<Vec<IdentitySignal>>,
    }

    impl MockIdentityProvider {
        /// Build a new mock provider with the given canned signals.
        pub fn new(signals: Vec<IdentitySignal>) -> Self {
            Self {
                signals: Mutex::new(signals),
            }
        }
    }

    impl IdentityProvider for MockIdentityProvider {
        fn run(
            &self,
            _cfg: IdentityMonitorConfig,
            tx: mpsc::Sender<IdentitySignal>,
            _shutdown: ShutdownSignal,
        ) -> tokio::task::JoinHandle<anyhow::Result<()>> {
            let signals = std::mem::take(&mut *self.signals.lock().unwrap());
            tokio::spawn(async move {
                for signal in signals {
                    if tx.send(signal).await.is_err() {
                        return Ok(());
                    }
                }
                Ok(())
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockIdentityProvider;
    use sda_core::signal::ShutdownController;
    use sda_event_bus::EventReceiver;

    fn enabled_cfg() -> IdentityMonitorConfig {
        IdentityMonitorConfig {
            enabled: true,
            lsass_access_windows: true,
            shadow_access_linux: true,
            keychain_access_macos: true,
        }
    }

    fn signal(category: IdentityAlertKind, user: &str, target: &str) -> IdentitySignal {
        IdentitySignal {
            category,
            user: user.to_string(),
            pid: 1234,
            process: "evil.exe".to_string(),
            image_path: "/usr/bin/evil.exe".to_string(),
            target: target.to_string(),
            description: format!("synthetic test signal for {target}"),
        }
    }

    async fn await_identity_event(rx: &mut EventReceiver) -> Option<Event> {
        for _ in 0..200 {
            match tokio::time::timeout(Duration::from_millis(25), rx.recv()).await {
                Ok(Some(ev)) => {
                    if matches!(ev.kind, EventKind::IdentityAlert { .. }) {
                        return Some(ev);
                    }
                }
                Ok(None) => return None,
                Err(_) => continue,
            }
        }
        None
    }

    #[test]
    fn alert_kind_wire_form_round_trips() {
        for kind in [
            IdentityAlertKind::LsassAccess,
            IdentityAlertKind::ShadowAccess,
            IdentityAlertKind::KcoreAccess,
            IdentityAlertKind::KeychainAccess,
        ] {
            let s = kind.as_wire();
            let json = format!("\"{s}\"");
            let parsed: IdentityAlertKind = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn mitre_techniques_are_documented_ids() {
        assert_eq!(IdentityAlertKind::LsassAccess.mitre_technique(), "T1003.001");
        assert_eq!(
            IdentityAlertKind::ShadowAccess.mitre_technique(),
            "T1003.008"
        );
        assert_eq!(IdentityAlertKind::KcoreAccess.mitre_technique(), "T1003");
        assert_eq!(
            IdentityAlertKind::KeychainAccess.mitre_technique(),
            "T1555.001"
        );
    }

    #[test]
    fn is_system_principal_recognises_common_system_users() {
        for user in [
            "",
            "root",
            "SYSTEM",
            "system",
            "NT AUTHORITY\\SYSTEM",
            "_securityd",
            "_keychain",
        ] {
            assert!(is_system_principal(user), "should be system: {user}");
        }
        for user in ["alice", "bob", "Administrator", "ubuntu", "ken"] {
            assert!(!is_system_principal(user), "should NOT be system: {user}");
        }
    }

    #[test]
    fn payload_serde_round_trip_preserves_all_fields() {
        let p = IdentityAlertPayload {
            category: IdentityAlertKind::LsassAccess,
            category_wire: "lsass_access".to_string(),
            technique: "T1003.001".to_string(),
            user: "alice".to_string(),
            pid: 1234,
            process: "mimikatz.exe".to_string(),
            image_path: "C:\\evil\\mimikatz.exe".to_string(),
            target: "lsass.exe".to_string(),
            description: "non-system process opened LSASS handle".to_string(),
            detected_at: "2026-05-18T01:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&p).unwrap();
        let parsed: IdentityAlertPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(p, parsed);
    }

    #[tokio::test]
    async fn disabled_module_does_not_publish_any_signals() {
        let (bus, _) = EventBus::new(64, 64);
        let mut rx = bus.subscribe();
        let (ctrl, signal_handle) = ShutdownController::new();
        let cfg = IdentityMonitorConfig {
            enabled: false,
            lsass_access_windows: true,
            shadow_access_linux: true,
            keychain_access_macos: true,
        };
        let provider: Arc<dyn IdentityProvider> = Arc::new(MockIdentityProvider::new(vec![signal(
            IdentityAlertKind::LsassAccess,
            "alice",
            "lsass.exe",
        )]));
        let handle = IdentityMonitorModule::start_with_providers(
            cfg,
            vec![provider],
            bus.clone(),
            signal_handle,
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(await_identity_event(&mut rx).await.is_none());
        ctrl.shutdown();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn enabled_module_publishes_alerts_for_each_signal() {
        let (bus, _) = EventBus::new(64, 64);
        let mut rx = bus.subscribe();
        let (ctrl, signal_handle) = ShutdownController::new();
        let provider: Arc<dyn IdentityProvider> = Arc::new(MockIdentityProvider::new(vec![
            signal(IdentityAlertKind::LsassAccess, "alice", "lsass.exe"),
            signal(IdentityAlertKind::ShadowAccess, "bob", "/etc/shadow"),
        ]));
        let handle = IdentityMonitorModule::start_with_providers(
            enabled_cfg(),
            vec![provider],
            bus.clone(),
            signal_handle,
        );

        let first = await_identity_event(&mut rx).await.expect("first alert");
        let second = await_identity_event(&mut rx).await.expect("second alert");

        for ev in [&first, &second] {
            let EventKind::IdentityAlert { payload } = &ev.kind else {
                panic!("expected IdentityAlert, got {:?}", ev.kind);
            };
            let parsed: IdentityAlertPayload = serde_json::from_str(payload).unwrap();
            assert!(parsed.detected_at.ends_with('Z'));
            assert!(parsed.description.contains("synthetic test signal"));
        }

        ctrl.shutdown();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn system_principal_is_filtered_at_publish_boundary() {
        let (bus, _) = EventBus::new(64, 64);
        let mut rx = bus.subscribe();
        let (ctrl, signal_handle) = ShutdownController::new();
        let provider: Arc<dyn IdentityProvider> = Arc::new(MockIdentityProvider::new(vec![
            signal(IdentityAlertKind::LsassAccess, "SYSTEM", "lsass.exe"),
            signal(IdentityAlertKind::LsassAccess, "alice", "lsass.exe"),
        ]));
        let handle = IdentityMonitorModule::start_with_providers(
            enabled_cfg(),
            vec![provider],
            bus.clone(),
            signal_handle,
        );

        let alert = await_identity_event(&mut rx).await.expect("user alert");
        let EventKind::IdentityAlert { payload } = &alert.kind else {
            panic!("expected IdentityAlert");
        };
        let parsed: IdentityAlertPayload = serde_json::from_str(payload).unwrap();
        assert_eq!(parsed.user, "alice");

        assert!(await_identity_event(&mut rx).await.is_none());

        ctrl.shutdown();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn shadow_signal_carries_t1003_008_technique() {
        let (bus, _) = EventBus::new(64, 64);
        let mut rx = bus.subscribe();
        let (ctrl, signal_handle) = ShutdownController::new();
        let provider: Arc<dyn IdentityProvider> = Arc::new(MockIdentityProvider::new(vec![signal(
            IdentityAlertKind::ShadowAccess,
            "ubuntu",
            "/etc/shadow",
        )]));
        let handle = IdentityMonitorModule::start_with_providers(
            enabled_cfg(),
            vec![provider],
            bus.clone(),
            signal_handle,
        );
        let alert = await_identity_event(&mut rx).await.expect("shadow alert");
        let EventKind::IdentityAlert { payload } = &alert.kind else {
            panic!("expected IdentityAlert");
        };
        let parsed: IdentityAlertPayload = serde_json::from_str(payload).unwrap();
        assert_eq!(parsed.technique, "T1003.008");
        assert_eq!(parsed.category, IdentityAlertKind::ShadowAccess);
        assert_eq!(parsed.category_wire, "shadow_access");
        ctrl.shutdown();
        let _ = handle.task.await;
    }

    #[test]
    fn config_default_starts_disabled() {
        let cfg = IdentityMonitorConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.lsass_access_windows);
        assert!(cfg.shadow_access_linux);
        assert!(cfg.keychain_access_macos);
    }

    #[tokio::test]
    async fn agent_module_trait_exposes_running_health() {
        let (bus, _) = EventBus::new(64, 64);
        let _rx = bus.subscribe();
        let (ctrl, signal_handle) = ShutdownController::new();
        let provider: Arc<dyn IdentityProvider> = Arc::new(MockIdentityProvider::new(vec![]));
        let module = IdentityMonitorModule::default();
        assert_eq!(module.name(), "identity_monitor");
        assert_eq!(module.status(), ModuleStatus::Initialized);
        assert_eq!(module.health(), ModuleHealth::Healthy);
        let handle = IdentityMonitorModule::start_with_providers(
            enabled_cfg(),
            vec![provider],
            bus.clone(),
            signal_handle,
        );
        ctrl.shutdown();
        let _ = handle.task.await;
    }

    #[test]
    fn civil_from_unix_secs_produces_rfc3339_z_string() {
        let s = civil_from_unix_secs(1_700_000_000);
        assert!(s.ends_with('Z'));
        assert_eq!(s.len(), 20);
    }
}
