//! Rootkit detection module for the SN360 Desktop Agent.
//!
//! Performs four classes of checks during idle periods:
//!
//! 1. **Signature sweep** — looks for known rootkit file paths
//!    (see [`signatures`]).
//! 2. **Content inspection** — reads `/etc/ld.so.preload`,
//!    `/etc/crontab`, and `/etc/hosts` and flags rootkit / persistence
//!    indicators inside them (see [`content_checks`]).
//! 3. **Hidden-process detection** — compares the OS-native process
//!    enumeration against a per-PID liveness probe on Linux, macOS,
//!    and Windows (see [`hidden_process`]).
//! 4. **Binary integrity** — tracks SHA-256 drift of critical system
//!    binaries against an on-disk baseline (see [`binary_integrity`]).
//!
//! All findings are published on the shared event bus as
//! [`EventKind::RootcheckAlert`](sda_event_bus::EventKind::RootcheckAlert)
//! events tagged with the originating category.

pub mod binary_integrity;
pub mod content_checks;
pub mod hidden_process;
pub mod signatures;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use sda_core::config::{default_rootcheck_binary_paths, AgentConfig, RootcheckConfig};
use sda_core::module::{AgentModule, ModuleHandle, ModuleHealth, ModuleStatus};
use sda_core::signal::ShutdownSignal;
use sda_event_bus::{Event, EventBus, EventKind, Priority};

use crate::binary_integrity::{Baseline, DriftKind};

const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// Rootcheck module handle.
pub struct RootcheckModule {
    status: Arc<AtomicU8>,
}

impl RootcheckModule {
    /// Spawn the rootcheck run loop and return a [`ModuleHandle`].
    pub fn start(config: &AgentConfig, bus: EventBus, shutdown: ShutdownSignal) -> ModuleHandle {
        let rc_config = config.modules.rootcheck.clone();
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);

        let task = tokio::spawn(async move {
            if let Err(e) = run(rc_config, bus, shutdown, task_status.clone()).await {
                error!(error = %e, "rootcheck module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });

        ModuleHandle::new("rootcheck", task)
    }
}

impl Default for RootcheckModule {
    fn default() -> Self {
        Self {
            status: Arc::new(AtomicU8::new(STATUS_INITIALIZED)),
        }
    }
}

impl AgentModule for RootcheckModule {
    fn name(&self) -> &'static str {
        "rootcheck"
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

/// Resolve the effective list of tracked binaries — operator override
/// if provided, otherwise the platform defaults.
fn effective_binary_paths(config: &RootcheckConfig) -> Vec<String> {
    if config.binary_paths.is_empty() {
        default_rootcheck_binary_paths()
    } else {
        config.binary_paths.clone()
    }
}

/// Publish a single alert on the shared bus.
async fn publish_alert(
    bus: &EventBus,
    category: &str,
    title: &str,
    subject: &str,
    description: &str,
) {
    let event = Event::new(
        "rootcheck",
        Priority::Normal,
        EventKind::RootcheckAlert {
            category: category.to_string(),
            title: title.to_string(),
            subject: subject.to_string(),
            description: description.to_string(),
        },
    );
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, category, "failed to publish rootcheck alert");
    }
}

/// Run one full rootcheck sweep (all four check categories:
/// signature, content, hidden-process, binary integrity).
async fn run_sweep(config: &RootcheckConfig, bus: &EventBus) {
    info!("rootcheck sweep starting");

    // --- 1. Signature sweep ---
    let extra_paths = config.signature_paths.clone();
    let signature_hits = tokio::task::spawn_blocking(move || signatures::scan(&extra_paths))
        .await
        .unwrap_or_default();

    for hit in &signature_hits {
        let title = format!("Rootkit signature detected ({})", hit.family);
        let description = format!(
            "path '{}' matches known rootkit signature for family '{}'",
            hit.path, hit.family
        );
        publish_alert(bus, "signature", &title, &hit.path, &description).await;
    }

    // --- 2. Content-based checks (ld.so.preload, crontab, hosts) ---
    let content_hits =
        tokio::task::spawn_blocking(|| content_checks::scan(std::path::Path::new("/")))
            .await
            .unwrap_or_default();

    for hit in &content_hits {
        let title = format!("Suspicious content in {}", hit.path);
        publish_alert(bus, hit.category, &title, &hit.indicator, &hit.reason).await;
    }

    // --- 3. Hidden-process check ---
    if config.hidden_process_check {
        let max_pid = config.max_pid;
        let hidden = tokio::task::spawn_blocking(move || hidden_process::scan(max_pid))
            .await
            .unwrap_or_default();

        for h in &hidden {
            let subject = h.pid.to_string();
            let description = format!(
                "PID {} responds to liveness probe but is absent from the OS process list — possible hidden process",
                h.pid
            );
            publish_alert(
                bus,
                "hidden_process",
                "Hidden process detected",
                &subject,
                &description,
            )
            .await;
        }
    }

    // --- 4. Binary integrity ---
    if config.binary_integrity_check {
        run_binary_integrity(config, bus).await;
    }

    debug!(
        signature_hits = signature_hits.len(),
        "rootcheck sweep finished"
    );
}

async fn run_binary_integrity(config: &RootcheckConfig, bus: &EventBus) {
    let binaries = effective_binary_paths(config);
    if binaries.is_empty() {
        return;
    }

    let baseline_path: PathBuf = config.baseline_path.clone();
    let binaries_for_task = binaries.clone();

    let result = tokio::task::spawn_blocking(move || {
        let baseline = Baseline::load(&baseline_path)?;
        let was_empty = baseline.entries.is_empty();
        let (drift, updated) = binary_integrity::compare(&baseline, &binaries_for_task);

        if updated.entries.len() != baseline.entries.len() {
            if let Err(e) = updated.save(&baseline_path) {
                warn!(
                    error = %e,
                    path = %baseline_path.display(),
                    "failed to persist rootcheck baseline"
                );
            }
        }

        Ok::<_, anyhow::Error>((drift, was_empty))
    })
    .await;

    let (drift, first_run) = match result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            warn!(error = %e, "rootcheck binary-integrity check failed");
            return;
        }
        Err(e) => {
            warn!(error = %e, "rootcheck binary-integrity task panicked");
            return;
        }
    };

    if first_run {
        info!(
            binaries = binaries.len(),
            "rootcheck binary-integrity baseline recorded on first run"
        );
        return;
    }

    for alert in &drift {
        match &alert.kind {
            DriftKind::HashChanged {
                old_sha256,
                new_sha256,
            } => {
                let description = format!(
                    "SHA-256 of '{}' changed from {} to {}",
                    alert.path, old_sha256, new_sha256
                );
                publish_alert(
                    bus,
                    "binary_integrity",
                    "System binary hash changed",
                    &alert.path,
                    &description,
                )
                .await;
            }
            DriftKind::Missing { old_sha256 } => {
                let description = format!(
                    "tracked system binary '{}' is missing on disk (baseline sha256={})",
                    alert.path, old_sha256
                );
                publish_alert(
                    bus,
                    "binary_integrity",
                    "Tracked system binary missing",
                    &alert.path,
                    &description,
                )
                .await;
            }
        }
    }
}

/// Main rootcheck run loop.
async fn run(
    rc_config: RootcheckConfig,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    info!(
        scan_interval_secs = rc_config.scan_interval_secs,
        hidden_process = rc_config.hidden_process_check,
        binary_integrity = rc_config.binary_integrity_check,
        "rootcheck module starting"
    );

    status.store(STATUS_RUNNING, Ordering::Relaxed);

    // Initial sweep on startup.
    run_sweep(&rc_config, &bus).await;

    let interval = Duration::from_secs(rc_config.scan_interval_secs.max(1));
    let mut timer = tokio::time::interval(interval);
    // Consume the immediate first tick — the startup sweep already covered it.
    timer.tick().await;

    loop {
        tokio::select! {
            biased;

            _ = shutdown.wait() => {
                info!("rootcheck module received shutdown signal");
                break;
            }

            _ = timer.tick() => {
                debug!("rootcheck scan timer fired");
                run_sweep(&rc_config, &bus).await;
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!("rootcheck module stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_event_bus::EventBus;

    fn test_config(tmp: &tempfile::TempDir) -> RootcheckConfig {
        RootcheckConfig {
            enabled: true,
            scan_interval_secs: 3600,
            signature_paths: Vec::new(),
            binary_paths: vec![],
            baseline_path: tmp.path().join("baseline.json"),
            hidden_process_check: false,
            binary_integrity_check: false,
            max_pid: 1024,
        }
    }

    #[tokio::test]
    async fn test_sweep_publishes_signature_hit_for_extra_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let marker = tmp.path().join("fake-rootkit-marker");
        std::fs::write(&marker, b"").unwrap();

        let mut cfg = test_config(&tmp);
        cfg.signature_paths = vec![marker.to_string_lossy().to_string()];

        let (bus, mut server_rx) = EventBus::new(16, 16);
        run_sweep(&cfg, &bus).await;

        let event = tokio::time::timeout(Duration::from_millis(200), server_rx.recv())
            .await
            .expect("expected a rootcheck alert to be published")
            .expect("server_rx closed");

        match event.kind {
            EventKind::RootcheckAlert {
                category, subject, ..
            } => {
                assert_eq!(category, "signature");
                assert_eq!(subject, marker.to_string_lossy());
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_sweep_emits_nothing_on_clean_system() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = test_config(&tmp);

        let (bus, mut server_rx) = EventBus::new(16, 16);
        run_sweep(&cfg, &bus).await;

        let maybe = tokio::time::timeout(Duration::from_millis(100), server_rx.recv()).await;
        assert!(
            maybe.is_err(),
            "expected no alerts on clean system, got: {:?}",
            maybe
        );
    }

    #[tokio::test]
    async fn test_binary_integrity_baseline_created_then_detects_tamper() {
        let tmp = tempfile::TempDir::new().unwrap();
        let bin = tmp.path().join("ls");
        std::fs::write(&bin, b"ls-v1").unwrap();

        let mut cfg = test_config(&tmp);
        cfg.binary_paths = vec![bin.to_string_lossy().to_string()];
        cfg.binary_integrity_check = true;

        let (bus, mut server_rx) = EventBus::new(16, 16);

        // First run: baseline is created, no alert expected.
        run_sweep(&cfg, &bus).await;
        let first = tokio::time::timeout(Duration::from_millis(100), server_rx.recv()).await;
        assert!(first.is_err(), "first run must not produce drift alerts");

        // Tamper with the tracked binary.
        std::fs::write(&bin, b"ls-tampered").unwrap();

        // Second run: should surface a HashChanged alert.
        run_sweep(&cfg, &bus).await;
        let alert = tokio::time::timeout(Duration::from_millis(500), server_rx.recv())
            .await
            .expect("expected a binary_integrity alert")
            .expect("server_rx closed");

        match alert.kind {
            EventKind::RootcheckAlert {
                category, subject, ..
            } => {
                assert_eq!(category, "binary_integrity");
                assert_eq!(subject, bin.to_string_lossy());
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_module_lifecycle_starts_and_stops() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = test_config(&tmp);

        let mut agent_config = AgentConfig::default();
        agent_config.modules.rootcheck = cfg;

        let (controller, signal) = sda_core::signal::ShutdownController::new();
        let (bus, _server_rx) = EventBus::new(16, 16);

        let handle = RootcheckModule::start(&agent_config, bus, signal);

        tokio::time::sleep(Duration::from_millis(50)).await;
        controller.shutdown();

        tokio::time::timeout(Duration::from_secs(2), handle.task)
            .await
            .expect("rootcheck task did not stop within 2s")
            .expect("join error")
            .expect("rootcheck run returned Err");
    }

    #[test]
    fn test_effective_binary_paths_falls_back_to_defaults_when_empty() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = test_config(&tmp);
        let paths = effective_binary_paths(&cfg);
        assert_eq!(paths, default_rootcheck_binary_paths());
    }

    #[test]
    fn test_effective_binary_paths_honors_override() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(&tmp);
        cfg.binary_paths = vec!["/custom/bin".to_string(), "/another/bin".to_string()];
        let paths = effective_binary_paths(&cfg);
        assert_eq!(paths, cfg.binary_paths);
    }
}
