//! Phase E4.8 — hermetic end-to-end coverage for the EDR memory
//! scanner (`sda-memory-scanner`).
//!
//! The memory-scanner module periodically enumerates committed
//! memory regions of running processes via the platform
//! [`sda_pal::memory_scanner::MemoryScanner`], reads bounded byte
//! slices from each interesting region, feeds them through an
//! injectable [`sda_memory_scanner::MemoryMatcher`] (in production:
//! the YARA matcher in `sda-local-detection`), and publishes
//! [`EventKind::MemoryScanAlert`] events when a match fires.
//!
//! This E2E suite drives the module against a fully-mocked PAL.
//! Live `/proc/<pid>/mem` reads require `CAP_SYS_PTRACE` not
//! available in CI, so the platform scanner is replaced with
//! [`sda_pal::memory_scanner::MockMemoryScanner`] and the process /
//! cpu / matcher dependencies come from the `test-support` mocks in
//! `sda-memory-scanner::mock`.
//!
//! Coverage (≥ 6 tests for `docs/edr.md` § 4 — Memory scanning and fileless detection):
//!
//! 1. Disabled module never publishes any `MemoryScanAlert` events.
//! 2. Synthetic RWX region with a known byte pattern flows through
//!    the matcher and produces a canonical alert payload (`pid`,
//!    `region_base`, `alert_type`, `description`, `detected_at`).
//! 3. Self-pid is unconditionally excluded — even if a region is
//!    registered for the agent's own pid, no alert fires.
//! 4. Allow-listed process names are skipped.
//! 5. Mock CPU sampler above the configured idle threshold gates
//!    the scan window entirely (no matcher calls).
//! 6. Clean memory (matcher returns nothing) produces no alerts.
//! 7. Non-interesting regions (RX file-backed) are skipped.
//! 8. The published payload contains an RFC3339 `detected_at`
//!    ending in `Z`.
//! 9. The published payload never embeds raw bytes from the scanned
//!    region in `description`.

#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use sda_core::config::MemoryScannerConfig;
use sda_core::signal::ShutdownController;
use sda_event_bus::{Event, EventBus, EventKind, EventReceiver};
use sda_memory_scanner::mock::{MockCpuSampler, MockMatcher, MockProcessLister};
use sda_memory_scanner::{
    MemoryAlertKind, MemoryMatch, MemoryMatcher, MemoryScanAlertPayload, MemoryScannerModule,
    ProcessHandle,
};
use sda_pal::memory_scanner::{MappingKind, MemoryPermissions, MemoryRegion, MockMemoryScanner};
use sda_pal::power::PowerMonitor;

// ------------------------------------------------------------------ helpers

const AGENT_SELF_PID: u32 = 99;

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

fn rwx() -> MemoryPermissions {
    MemoryPermissions {
        readable: true,
        writable: true,
        executable: true,
    }
}

fn rx_file() -> MemoryPermissions {
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

/// Drain `EventKind::MemoryScanAlert` events off the bus for the
/// given window.
async fn drain_memory(rx: &mut EventReceiver, window: Duration) -> Vec<Event> {
    let deadline = tokio::time::Instant::now() + window;
    let mut out = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return out;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(ev)) => {
                if matches!(ev.kind, EventKind::MemoryScanAlert { .. }) {
                    out.push(ev);
                }
            }
            Ok(None) => return out,
            Err(_) => return out,
        }
    }
}

fn parse_alert(ev: &Event) -> MemoryScanAlertPayload {
    let EventKind::MemoryScanAlert { payload } = &ev.kind else {
        panic!("expected MemoryScanAlert, got {:?}", ev.kind)
    };
    serde_json::from_str(payload).expect("MemoryScanAlertPayload parses")
}

/// Pre-populate the mock scanner with a single RWX anonymous region
/// for `pid` and an associated read buffer.
fn with_rwx_region(pid: u32, base: u64, bytes: &[u8]) -> Arc<MockMemoryScanner> {
    let m = Arc::new(MockMemoryScanner::with_self_pid(AGENT_SELF_PID));
    m.set_regions(
        pid,
        vec![region(
            base,
            bytes.len() as u64,
            rwx(),
            MappingKind::Anonymous,
        )],
    );
    m.set_read(pid, base, bytes.to_vec());
    m
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn t01_disabled_module_emits_no_memory_scan_alerts() {
    let mut cfg = enabled_cfg();
    cfg.enabled = false;

    let scanner = with_rwx_region(123, 0x1000, b"trigger-this");
    let lister = Arc::new(MockProcessLister::new(vec![ProcessHandle {
        pid: 123,
        name: "victim".to_string(),
    }]));
    let cpu = Arc::new(MockCpuSampler::new(0));
    let matcher: Arc<dyn MemoryMatcher> = Arc::new(MockMatcher::new(vec![yara_hit("PE_DUMP")]));

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (ctrl, shutdown) = ShutdownController::new();

    let handle = MemoryScannerModule::start_with_deps(
        cfg,
        scanner,
        lister,
        cpu,
        Arc::new(PowerMonitor::new()),
        matcher,
        bus.clone(),
        shutdown,
    );

    let alerts = drain_memory(&mut rx, Duration::from_millis(300)).await;
    assert!(
        alerts.is_empty(),
        "disabled module published {} alerts",
        alerts.len()
    );

    ctrl.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t02_rwx_region_yara_hit_emits_canonical_alert() {
    let scanner = with_rwx_region(123, 0x4000, b"MZ shellcode-marker");
    let lister = Arc::new(MockProcessLister::new(vec![ProcessHandle {
        pid: 123,
        name: "victim".to_string(),
    }]));
    let cpu = Arc::new(MockCpuSampler::new(0));
    let matcher: Arc<dyn MemoryMatcher> = Arc::new(MockMatcher::new(vec![yara_hit("PE_DUMP")]));

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (ctrl, shutdown) = ShutdownController::new();

    let handle = MemoryScannerModule::start_with_deps(
        enabled_cfg(),
        scanner,
        lister,
        cpu,
        Arc::new(PowerMonitor::new()),
        matcher,
        bus.clone(),
        shutdown,
    );

    let alerts = drain_memory(&mut rx, Duration::from_secs(2)).await;
    assert!(!alerts.is_empty(), "expected at least one MemoryScanAlert");
    let payload = parse_alert(&alerts[0]);
    assert_eq!(payload.pid, 123);
    assert_eq!(payload.process_name, "victim");
    assert_eq!(payload.region_base, 0x4000);
    assert_eq!(payload.alert_type, MemoryAlertKind::YaraMatch);
    assert!(payload.description.contains("PE_DUMP"));

    ctrl.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t03_self_pid_is_never_scanned_even_with_regions_set() {
    let scanner = Arc::new(MockMemoryScanner::with_self_pid(AGENT_SELF_PID));
    // Deliberately populate regions + reads for the agent's own pid.
    scanner.set_regions(
        AGENT_SELF_PID,
        vec![region(0x1000, 0x10, rwx(), MappingKind::Anonymous)],
    );
    scanner.set_read(AGENT_SELF_PID, 0x1000, b"self-bytes".to_vec());
    // The lister also advertises a non-self pid so the scanner has
    // something legitimate to consider (otherwise the test could
    // pass trivially).
    let lister = Arc::new(MockProcessLister::new(vec![
        ProcessHandle {
            pid: AGENT_SELF_PID,
            name: "agent".to_string(),
        },
        ProcessHandle {
            pid: 123,
            name: "victim".to_string(),
        },
    ]));
    let cpu = Arc::new(MockCpuSampler::new(0));
    // Match on every call so any leakage is loud.
    let mock_matcher = Arc::new(MockMatcher::new(vec![yara_hit("LEAK")]));
    let matcher: Arc<dyn MemoryMatcher> = mock_matcher.clone();

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (ctrl, shutdown) = ShutdownController::new();

    let handle = MemoryScannerModule::start_with_deps(
        enabled_cfg(),
        scanner,
        lister,
        cpu,
        Arc::new(PowerMonitor::new()),
        matcher,
        bus.clone(),
        shutdown,
    );

    let alerts = drain_memory(&mut rx, Duration::from_millis(800)).await;
    // No alert for the agent's own pid.
    for ev in &alerts {
        let p = parse_alert(ev);
        assert_ne!(
            p.pid, AGENT_SELF_PID,
            "self-pid leaked into MemoryScanAlert: {ev:?}"
        );
    }

    ctrl.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t04_allow_list_process_is_skipped() {
    let scanner = with_rwx_region(123, 0x1000, b"data");
    // Both processes are scannable PIDs, but `chrome` is in the
    // allow-list so should never be scanned.
    let lister = Arc::new(MockProcessLister::new(vec![ProcessHandle {
        pid: 123,
        name: "chrome".to_string(),
    }]));
    let cpu = Arc::new(MockCpuSampler::new(0));
    let mock_matcher = Arc::new(MockMatcher::new(vec![yara_hit("WOULD_TRIGGER")]));
    let matcher: Arc<dyn MemoryMatcher> = mock_matcher.clone();

    let mut cfg = enabled_cfg();
    cfg.allow_list_processes = vec!["sn360-desktop-agent".to_string(), "chrome".to_string()];

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (ctrl, shutdown) = ShutdownController::new();

    let handle = MemoryScannerModule::start_with_deps(
        cfg,
        scanner,
        lister,
        cpu,
        Arc::new(PowerMonitor::new()),
        matcher,
        bus.clone(),
        shutdown,
    );

    let alerts = drain_memory(&mut rx, Duration::from_millis(800)).await;
    assert!(
        alerts.is_empty(),
        "allow-listed process produced {} alerts",
        alerts.len()
    );
    // Matcher should never have been called for the allow-listed pid.
    assert_eq!(
        mock_matcher.calls(),
        0,
        "matcher called {} times for allow-listed process",
        mock_matcher.calls()
    );

    ctrl.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t05_high_cpu_skips_scan_window() {
    let scanner = with_rwx_region(123, 0x1000, b"data");
    let lister = Arc::new(MockProcessLister::new(vec![ProcessHandle {
        pid: 123,
        name: "victim".to_string(),
    }]));
    // Mock the system at 95% busy. With `only_when_idle_below_cpu_pct
    // = 50`, every scan window should be skipped.
    let cpu = Arc::new(MockCpuSampler::new(95));
    let mock_matcher = Arc::new(MockMatcher::new(vec![yara_hit("LATENT")]));
    let matcher: Arc<dyn MemoryMatcher> = mock_matcher.clone();

    let mut cfg = enabled_cfg();
    cfg.only_when_idle_below_cpu_pct = 50;

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (ctrl, shutdown) = ShutdownController::new();

    let handle = MemoryScannerModule::start_with_deps(
        cfg,
        scanner,
        lister,
        cpu,
        Arc::new(PowerMonitor::new()),
        matcher,
        bus.clone(),
        shutdown,
    );

    let alerts = drain_memory(&mut rx, Duration::from_millis(800)).await;
    assert!(
        alerts.is_empty(),
        "scan ran despite high CPU: {} alerts",
        alerts.len()
    );
    assert_eq!(
        mock_matcher.calls(),
        0,
        "matcher was invoked despite cpu gate"
    );

    ctrl.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t06_clean_memory_produces_no_alerts() {
    let scanner = with_rwx_region(123, 0x1000, b"clean innocuous bytes");
    let lister = Arc::new(MockProcessLister::new(vec![ProcessHandle {
        pid: 123,
        name: "victim".to_string(),
    }]));
    let cpu = Arc::new(MockCpuSampler::new(0));
    // Matcher returns zero hits → no alert should fire.
    let mock_matcher = Arc::new(MockMatcher::new(vec![]));
    let matcher: Arc<dyn MemoryMatcher> = mock_matcher.clone();

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (ctrl, shutdown) = ShutdownController::new();

    let handle = MemoryScannerModule::start_with_deps(
        enabled_cfg(),
        scanner,
        lister,
        cpu,
        Arc::new(PowerMonitor::new()),
        matcher,
        bus.clone(),
        shutdown,
    );

    let alerts = drain_memory(&mut rx, Duration::from_millis(800)).await;
    assert!(
        alerts.is_empty(),
        "clean memory produced {} alerts",
        alerts.len()
    );
    // The matcher SHOULD have been called at least once (the region
    // is RWX-anonymous and therefore interesting).
    assert!(
        mock_matcher.calls() >= 1,
        "matcher was never called on RWX region"
    );

    ctrl.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t07_non_interesting_region_is_skipped() {
    // RX file-backed regions are deliberately excluded — already
    // covered by FIM + on-disk YARA.
    let scanner = Arc::new(MockMemoryScanner::with_self_pid(AGENT_SELF_PID));
    scanner.set_regions(
        123,
        vec![region(
            0x2000,
            0x100,
            rx_file(),
            MappingKind::FileBacked("/lib/libc.so.6".to_string()),
        )],
    );
    scanner.set_read(123, 0x2000, b"libc-bytes".to_vec());
    let lister = Arc::new(MockProcessLister::new(vec![ProcessHandle {
        pid: 123,
        name: "victim".to_string(),
    }]));
    let cpu = Arc::new(MockCpuSampler::new(0));
    let mock_matcher = Arc::new(MockMatcher::new(vec![yara_hit("WOULD_TRIGGER")]));
    let matcher: Arc<dyn MemoryMatcher> = mock_matcher.clone();

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (ctrl, shutdown) = ShutdownController::new();

    let handle = MemoryScannerModule::start_with_deps(
        enabled_cfg(),
        scanner,
        lister,
        cpu,
        Arc::new(PowerMonitor::new()),
        matcher,
        bus.clone(),
        shutdown,
    );

    let alerts = drain_memory(&mut rx, Duration::from_millis(800)).await;
    assert!(
        alerts.is_empty(),
        "RX file-backed region triggered {} alerts",
        alerts.len()
    );
    assert_eq!(
        mock_matcher.calls(),
        0,
        "matcher was called for non-interesting region"
    );

    ctrl.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t08_alert_carries_rfc3339_detected_at_timestamp() {
    let scanner = with_rwx_region(123, 0x1000, b"trigger");
    let lister = Arc::new(MockProcessLister::new(vec![ProcessHandle {
        pid: 123,
        name: "victim".to_string(),
    }]));
    let cpu = Arc::new(MockCpuSampler::new(0));
    let matcher: Arc<dyn MemoryMatcher> = Arc::new(MockMatcher::new(vec![yara_hit("R1")]));

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (ctrl, shutdown) = ShutdownController::new();

    let handle = MemoryScannerModule::start_with_deps(
        enabled_cfg(),
        scanner,
        lister,
        cpu,
        Arc::new(PowerMonitor::new()),
        matcher,
        bus.clone(),
        shutdown,
    );

    let alerts = drain_memory(&mut rx, Duration::from_secs(2)).await;
    assert!(!alerts.is_empty());
    let payload = parse_alert(&alerts[0]);
    assert!(
        payload.detected_at.ends_with('Z'),
        "detected_at not RFC3339-Z: {}",
        payload.detected_at
    );
    // Coarse shape check: "YYYY-MM-DDTHH:MM:SS"
    assert!(
        payload.detected_at.len() >= 20,
        "detected_at too short: {}",
        payload.detected_at
    );

    ctrl.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t09_description_never_contains_raw_region_bytes() {
    // The scanned region contains a secret-like sequence. The
    // matcher MUST NOT echo bytes from the slice into its
    // `description`; the module re-serialises that description into
    // the wire payload, so the redaction invariant ends up
    // exercised end-to-end.
    const SECRET: &str = "TOPSECRET-AAAA-BBBB-CCCC";
    let mut body = b"prefix:".to_vec();
    body.extend_from_slice(SECRET.as_bytes());

    let scanner = Arc::new(MockMemoryScanner::with_self_pid(AGENT_SELF_PID));
    scanner.set_regions(
        123,
        vec![region(
            0x9000,
            body.len() as u64,
            rwx(),
            MappingKind::Anonymous,
        )],
    );
    scanner.set_read(123, 0x9000, body.clone());

    let lister = Arc::new(MockProcessLister::new(vec![ProcessHandle {
        pid: 123,
        name: "victim".to_string(),
    }]));
    let cpu = Arc::new(MockCpuSampler::new(0));
    // The matcher returns a description that intentionally does
    // NOT include the secret — mirroring the production YARA
    // wrapper in `sda-local-detection`.
    let matcher: Arc<dyn MemoryMatcher> = Arc::new(MockMatcher::new(vec![MemoryMatch {
        alert_type: MemoryAlertKind::YaraMatch,
        description: "rule:HighEntropyBlob region=anon".to_string(),
    }]));

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (ctrl, shutdown) = ShutdownController::new();

    let handle = MemoryScannerModule::start_with_deps(
        enabled_cfg(),
        scanner,
        lister,
        cpu,
        Arc::new(PowerMonitor::new()),
        matcher,
        bus.clone(),
        shutdown,
    );

    let alerts = drain_memory(&mut rx, Duration::from_secs(2)).await;
    assert!(!alerts.is_empty());
    for ev in &alerts {
        let EventKind::MemoryScanAlert { payload } = &ev.kind else {
            unreachable!();
        };
        assert!(
            !payload.contains(SECRET),
            "MemoryScanAlert payload leaked region bytes: {payload}"
        );
    }

    ctrl.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t10_unknown_pid_in_lister_does_not_crash_module() {
    // Lister advertises a pid that the scanner doesn't know about.
    // The module must handle the empty-regions return gracefully
    // (no panic, no alerts).
    let scanner = Arc::new(MockMemoryScanner::with_self_pid(AGENT_SELF_PID));
    let lister = Arc::new(MockProcessLister::new(vec![ProcessHandle {
        pid: 9999,
        name: "ghost".to_string(),
    }]));
    let cpu = Arc::new(MockCpuSampler::new(0));
    let matcher: Arc<dyn MemoryMatcher> = Arc::new(MockMatcher::new(vec![yara_hit("LATENT")]));

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (ctrl, shutdown) = ShutdownController::new();

    let handle = MemoryScannerModule::start_with_deps(
        enabled_cfg(),
        scanner,
        lister,
        cpu,
        Arc::new(PowerMonitor::new()),
        matcher,
        bus.clone(),
        shutdown,
    );

    let alerts = drain_memory(&mut rx, Duration::from_millis(800)).await;
    assert!(alerts.is_empty());

    ctrl.shutdown();
    let _ = handle.task.await;
}
