//! Data-Loss-Prevention module (Phase E5 of EDR Parity).
//!
//! Inspects file-write events from the FIM stream and matches their
//! bounded content against a regex pattern set (US SSN, UK NI, PCI
//! PAN+Luhn). When a finding survives validation, the module emits
//! a [`EventKind::LocalDetectionAlert`] event with
//! `rule_type == "dlp"`.
//!
//! ## Redaction invariant (docs/architecture.md § 8.2)
//!
//! The matched bytes **MUST NOT** leave the module. Findings carry
//! only:
//!
//! - the category (e.g. `"pii.ssn"`)
//! - the byte offset + length of the match
//! - a Blake3 fingerprint of a 32-byte surrounding window
//!
//! The `description` field of the emitted event is a stable
//! template (`"DLP match category=… file=… offset=… len=…"`) and
//! never embeds the matched bytes.
//!
//! ## Operating modes
//!
//! | Mode      | Behaviour                                              |
//! |-----------|--------------------------------------------------------|
//! | `monitor` | Emit findings, log them; the file is left untouched.   |
//! | `enforce` | Emit findings, log them, AND mark the file as a        |
//! |           | quarantine candidate by raising the event severity.    |
//! |           | The actual quarantine action is performed by           |
//! |           | `sda-active-response` reading the high-severity event. |
//!
//! ## Optional clipboard monitoring
//!
//! The `dlp-clipboard` Cargo feature opts the module into watching
//! a [`mock::MockClipboardSource`] (or, in production, the platform
//! clipboard hook described in the original phase plan § E5.7). Even when the
//! feature is compiled in, `inspect_clipboard: false` keeps it
//! disabled.

#![deny(missing_docs)]

pub mod patterns;
pub mod scanner;

#[cfg(feature = "dlp-clipboard")]
pub mod clipboard;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use anyhow::Context;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info, warn};

use sda_core::config::{AgentConfig, DlpConfig};
use sda_core::module::{AgentModule, ModuleHandle, ModuleHealth, ModuleStatus};
use sda_core::signal::ShutdownSignal;
use sda_event_bus::{Event, EventBus, EventKind, EventReceiver, Priority};

use crate::scanner::{DlpFinding, Scanner};

const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// DLP module operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlpMode {
    /// Monitor only — emit findings, do not quarantine.
    Monitor,
    /// Enforce — emit findings AND raise severity so the active-
    /// response module quarantines the file.
    Enforce,
}

impl DlpMode {
    fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "enforce" => DlpMode::Enforce,
            _ => DlpMode::Monitor,
        }
    }
}

/// Handle returned by [`DlpModule::start`].
pub struct DlpModule {
    status: Arc<AtomicU8>,
}

impl Default for DlpModule {
    fn default() -> Self {
        Self {
            status: Arc::new(AtomicU8::new(STATUS_INITIALIZED)),
        }
    }
}

impl DlpModule {
    /// Spawn the DLP module using the global agent config.
    pub fn start(config: &AgentConfig, bus: EventBus, shutdown: ShutdownSignal) -> ModuleHandle {
        let cfg = config.modules.dlp.clone();
        Self::start_with_config(cfg, bus, shutdown)
    }

    /// Spawn the DLP module with a hand-built config (used by
    /// tests + E2E suites).
    ///
    /// The receiver is acquired on the calling thread BEFORE the
    /// task is spawned so a test that publishes a FIM event
    /// immediately after `start_with_config` cannot lose the
    /// event in the gap between `tokio::spawn` and the task's
    /// first poll. See `tests/e2e_dlp.rs` for the regression.
    pub fn start_with_config(
        cfg: DlpConfig,
        bus: EventBus,
        shutdown: ShutdownSignal,
    ) -> ModuleHandle {
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);
        let rx = bus.subscribe();
        let task = tokio::spawn(async move {
            if let Err(e) = run(cfg, bus, rx, shutdown, task_status.clone()).await {
                error!(error = %e, "DLP module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });
        ModuleHandle::new("dlp", task)
    }
}

impl AgentModule for DlpModule {
    fn name(&self) -> &'static str {
        "dlp"
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

async fn run(
    cfg: DlpConfig,
    bus: EventBus,
    mut rx: EventReceiver,
    mut shutdown: ShutdownSignal,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    if !cfg.enabled {
        info!("DLP module disabled — idling until shutdown");
        status.store(STATUS_RUNNING, Ordering::Relaxed);
        shutdown.wait().await;
        status.store(STATUS_STOPPED, Ordering::Relaxed);
        return Ok(());
    }

    let mode = DlpMode::parse(&cfg.mode);
    let dropped: Vec<String> = cfg
        .patterns
        .iter()
        .filter(|p| !patterns::is_builtin_category(p))
        .cloned()
        .collect();
    if !dropped.is_empty() {
        warn!(
            ?dropped,
            "DLP config references unknown pattern categories; dropping"
        );
    }

    let scanner = Arc::new(Scanner::new(patterns::select(&cfg.patterns)));
    info!(
        mode = ?mode,
        patterns = scanner.pattern_count(),
        inspect_file_writes = cfg.inspect_file_writes,
        inspect_clipboard = cfg.inspect_clipboard,
        "starting DLP module"
    );
    status.store(STATUS_RUNNING, Ordering::Relaxed);

    loop {
        tokio::select! {
            biased;
            _ = shutdown.wait() => {
                info!("DLP module received shutdown");
                break;
            }
            ev = rx.recv() => {
                let Some(event) = ev else {
                    debug!("DLP module: bus closed");
                    break;
                };
                if !cfg.inspect_file_writes {
                    continue;
                }
                if let Some(path) = file_path_for_event(&event) {
                    inspect_file(&scanner, mode, &cfg, &bus, &path).await;
                }
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    Ok(())
}

/// Return the file path embedded in an `EventBus` event when it is
/// a FIM write event we care about. The DLP module ignores
/// `FileDeleted` / `FileMetadataChanged` because a payload-less
/// metadata flip can't contain new PII.
fn file_path_for_event(event: &Event) -> Option<PathBuf> {
    match &event.kind {
        EventKind::FileCreated { path, .. } | EventKind::FileModified { path, .. } => {
            Some(PathBuf::from(path))
        }
        _ => None,
    }
}

async fn inspect_file(
    scanner: &Scanner,
    mode: DlpMode,
    cfg: &DlpConfig,
    bus: &EventBus,
    path: &std::path::Path,
) {
    let Ok(metadata) = fs::metadata(path).await else {
        debug!(?path, "DLP: file metadata unavailable, skipping");
        return;
    };
    if !metadata.is_file() {
        return;
    }
    let limit = cfg.max_bytes_per_file as u64;
    let len = metadata.len().min(limit);
    if len == 0 {
        return;
    }
    match read_bounded(path, len as usize).await {
        Ok(buf) => {
            let findings = scanner.scan_bytes(&buf);
            if findings.is_empty() {
                return;
            }
            for finding in findings {
                publish_finding(bus, mode, path, &finding).await;
            }
        }
        Err(e) => {
            debug!(error = %e, ?path, "DLP: file read failed");
        }
    }
}

/// Read at most `limit` bytes from `path` into a fresh `Vec`.
///
/// A naive `let n = f.read(&mut buf); buf.truncate(n)` is buggy
/// here because `AsyncReadExt::read` is allowed to return any
/// non-zero count up to the buffer length on each call — a single
/// short read would silently truncate the DLP scan window. Wrapping
/// the handle in `take(limit)` and draining with `read_to_end`
/// guarantees we either consume `limit` bytes or hit EOF first.
async fn read_bounded(path: &std::path::Path, limit: usize) -> anyhow::Result<Vec<u8>> {
    let f = fs::File::open(path)
        .await
        .with_context(|| format!("open {}", path.display()))?;
    let mut limited = f.take(limit as u64);
    let mut buf = Vec::with_capacity(limit);
    limited
        .read_to_end(&mut buf)
        .await
        .with_context(|| format!("read {}", path.display()))?;
    Ok(buf)
}

async fn publish_finding(
    bus: &EventBus,
    mode: DlpMode,
    path: &std::path::Path,
    finding: &DlpFinding,
) {
    let path_display = path.display().to_string();
    let severity = match mode {
        DlpMode::Monitor => "medium",
        DlpMode::Enforce => "high",
    };
    let description = format!(
        "DLP match category={} pattern={} file={} offset={} len={} fp={}…",
        finding.category,
        finding.pattern_name,
        path_display,
        finding.offset,
        finding.length,
        // Truncate fingerprint to keep the event small; full
        // fingerprint is in matched_value below.
        &finding.fingerprint[..16.min(finding.fingerprint.len())],
    );
    let event = Event::new(
        "dlp",
        if mode == DlpMode::Enforce {
            Priority::High
        } else {
            Priority::Normal
        },
        EventKind::LocalDetectionAlert {
            rule_id: format!("dlp.{}", finding.category),
            rule_type: "dlp".to_string(),
            severity: severity.to_string(),
            description,
            // matched_value is documented as the wire-safe handle to
            // the source — for DLP this is the file path + finger-
            // print, never the bytes themselves.
            matched_value: format!("{}#{}", path_display, finding.fingerprint),
        },
    );
    // DLP findings must reach the server: SOC visibility is the
    // whole point of the module. `publish_to_server` already
    // broadcasts locally before attempting the server queue, so
    // adding a `bus.publish(ev)` fallback after a failure would
    // double-fire local detection rules on the same event — log
    // and move on instead (matches the memory-scanner pattern).
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, ?path, "DLP: server-bound publish failed");
    }
}

// ---------------------------------------------------------------------------
// Test-support helpers
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "test-support"))]
pub mod mock {
    //! Test-only helpers shared between unit tests and the E5 E2E
    //! suite.

    use super::*;

    /// Synchronous, in-process scanner suitable for direct unit
    /// tests. Returns the findings without consuming any event bus.
    pub fn scan_buf(input: &str) -> Vec<DlpFinding> {
        Scanner::new(patterns::baseline_patterns()).scan(input)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::signal::ShutdownController;
    use sda_event_bus::EventReceiver;
    use std::io::Write;
    use std::time::Duration;
    use tempfile::TempDir;

    fn cfg(mode: &str) -> DlpConfig {
        DlpConfig {
            enabled: true,
            mode: mode.to_string(),
            patterns: vec![],
            inspect_file_writes: true,
            inspect_clipboard: false,
            max_bytes_per_file: 2 * 1024 * 1024,
        }
    }

    async fn write_tempfile(dir: &TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    async fn await_dlp_event(rx: &mut EventReceiver) -> Option<Event> {
        for _ in 0..200 {
            match tokio::time::timeout(Duration::from_millis(25), rx.recv()).await {
                Ok(Some(ev)) => {
                    if let EventKind::LocalDetectionAlert { rule_type, .. } = &ev.kind {
                        if rule_type == "dlp" {
                            return Some(ev);
                        }
                    }
                }
                Ok(None) => return None,
                Err(_) => continue,
            }
        }
        None
    }

    #[test]
    fn mode_parsing_handles_known_strings() {
        assert_eq!(DlpMode::parse("monitor"), DlpMode::Monitor);
        assert_eq!(DlpMode::parse("MONITOR"), DlpMode::Monitor);
        assert_eq!(DlpMode::parse("enforce"), DlpMode::Enforce);
        assert_eq!(DlpMode::parse("unknown"), DlpMode::Monitor);
    }

    #[test]
    fn dlp_config_default_starts_disabled() {
        let c = DlpConfig::default();
        assert!(!c.enabled);
        assert_eq!(c.mode, "monitor");
        assert!(c.inspect_file_writes);
        assert!(!c.inspect_clipboard);
        assert!(c.max_bytes_per_file >= 1024);
    }

    #[tokio::test]
    async fn disabled_module_emits_nothing() {
        let (bus, _) = EventBus::new(64, 64);
        let mut rx = bus.subscribe();
        let (ctrl, signal) = ShutdownController::new();
        let mut c = cfg("monitor");
        c.enabled = false;
        let handle = DlpModule::start_with_config(c, bus.clone(), signal);
        // Drive a synthetic FIM event past the disabled module.
        bus.publish(Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileCreated {
                path: "/dev/null".to_string(),
                syscheck_payload: None,
            },
        ))
        .unwrap();
        assert!(await_dlp_event(&mut rx).await.is_none());
        ctrl.shutdown();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn module_emits_finding_for_ssn_in_file() {
        let tmp = TempDir::new().unwrap();
        let path = write_tempfile(&tmp, "leak.txt", "patient ssn 123-45-6789\n").await;

        let (bus, _) = EventBus::new(64, 64);
        let mut rx = bus.subscribe();
        let (ctrl, signal) = ShutdownController::new();
        let handle = DlpModule::start_with_config(cfg("monitor"), bus.clone(), signal);
        // Give the module a moment to subscribe before publishing.
        tokio::time::sleep(Duration::from_millis(20)).await;
        bus.publish(Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileCreated {
                path: path.display().to_string(),
                syscheck_payload: None,
            },
        ))
        .unwrap();

        let finding = await_dlp_event(&mut rx).await.expect("finding");
        let EventKind::LocalDetectionAlert {
            rule_id,
            rule_type,
            description,
            matched_value,
            severity,
            ..
        } = &finding.kind
        else {
            panic!("expected LocalDetectionAlert");
        };
        assert_eq!(rule_type, "dlp");
        assert_eq!(rule_id, "dlp.pii.ssn");
        assert_eq!(severity, "medium");
        // Redaction invariant: matched bytes MUST NOT appear in the
        // event description or matched_value.
        assert!(!description.contains("123-45-6789"));
        assert!(!matched_value.contains("123-45-6789"));

        ctrl.shutdown();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn enforce_mode_raises_severity() {
        let tmp = TempDir::new().unwrap();
        let path = write_tempfile(&tmp, "enforce.txt", "card 4242424242424242\n").await;
        let (bus, _) = EventBus::new(64, 64);
        let mut rx = bus.subscribe();
        let (ctrl, signal) = ShutdownController::new();
        let handle = DlpModule::start_with_config(cfg("enforce"), bus.clone(), signal);
        tokio::time::sleep(Duration::from_millis(20)).await;
        bus.publish(Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileModified {
                path: path.display().to_string(),
                syscheck_payload: None,
            },
        ))
        .unwrap();
        let finding = await_dlp_event(&mut rx).await.expect("finding");
        let EventKind::LocalDetectionAlert { severity, .. } = &finding.kind else {
            panic!("expected LocalDetectionAlert");
        };
        assert_eq!(severity, "high");
        ctrl.shutdown();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn clean_file_produces_no_finding() {
        let tmp = TempDir::new().unwrap();
        let path = write_tempfile(&tmp, "clean.txt", "this is a clean document\n").await;
        let (bus, _) = EventBus::new(64, 64);
        let mut rx = bus.subscribe();
        let (ctrl, signal) = ShutdownController::new();
        let handle = DlpModule::start_with_config(cfg("monitor"), bus.clone(), signal);
        tokio::time::sleep(Duration::from_millis(20)).await;
        bus.publish(Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileCreated {
                path: path.display().to_string(),
                syscheck_payload: None,
            },
        ))
        .unwrap();
        assert!(await_dlp_event(&mut rx).await.is_none());
        ctrl.shutdown();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn module_skips_when_inspect_file_writes_disabled() {
        let tmp = TempDir::new().unwrap();
        let path = write_tempfile(&tmp, "ssn.txt", "ssn 123-45-6789\n").await;
        let (bus, _) = EventBus::new(64, 64);
        let mut rx = bus.subscribe();
        let (ctrl, signal) = ShutdownController::new();
        let mut c = cfg("monitor");
        c.inspect_file_writes = false;
        let handle = DlpModule::start_with_config(c, bus.clone(), signal);
        tokio::time::sleep(Duration::from_millis(20)).await;
        bus.publish(Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileCreated {
                path: path.display().to_string(),
                syscheck_payload: None,
            },
        ))
        .unwrap();
        assert!(await_dlp_event(&mut rx).await.is_none());
        ctrl.shutdown();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn module_respects_max_bytes_per_file() {
        let tmp = TempDir::new().unwrap();
        // Place the SSN 4 KiB into the file but cap the scan window
        // at 1 KiB; the SSN must NOT be found.
        let mut content = vec![b' '; 4096];
        content.extend_from_slice(b"ssn 123-45-6789\n");
        let path = tmp.path().join("big.txt");
        std::fs::write(&path, &content).unwrap();
        let (bus, _) = EventBus::new(64, 64);
        let mut rx = bus.subscribe();
        let (ctrl, signal) = ShutdownController::new();
        let mut c = cfg("monitor");
        c.max_bytes_per_file = 1024;
        let handle = DlpModule::start_with_config(c, bus.clone(), signal);
        tokio::time::sleep(Duration::from_millis(20)).await;
        bus.publish(Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileCreated {
                path: path.display().to_string(),
                syscheck_payload: None,
            },
        ))
        .unwrap();
        assert!(await_dlp_event(&mut rx).await.is_none());
        ctrl.shutdown();
        let _ = handle.task.await;
    }

    #[test]
    fn agent_module_trait_smoke() {
        let m = DlpModule::default();
        assert_eq!(m.name(), "dlp");
        assert_eq!(m.status(), ModuleStatus::Initialized);
        assert_eq!(m.health(), ModuleHealth::Healthy);
    }

    #[test]
    fn mock_scan_buf_finds_known_patterns() {
        let findings = mock::scan_buf("ssn 123-45-6789, ni AB123456C, card 4242424242424242");
        let cats: Vec<_> = findings.iter().map(|f| f.category.as_str()).collect();
        assert!(cats.contains(&"pii.ssn"));
        assert!(cats.contains(&"pii.uk_ni"));
        assert!(cats.contains(&"pci.pan_luhn"));
    }
}
