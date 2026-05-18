//! Phase E1.8 — hermetic end-to-end coverage for the EDR process
//! telemetry pipeline.
//!
//! This suite stitches together:
//!
//! - `sda-pal::MockProcessMonitor` (replays a canned sequence of
//!   `ProcessEvent`s and serves ancestor lookups),
//! - `sda-process-monitor::ProcessMonitorModule` (the agent module
//!   under test — performs enrichment, dedup, backpressure handling,
//!   and publishes canonical-JSON wire payloads on the bus), and
//! - `sda-local-detection::LocalDetectionModule` (the LDE, which
//!   consumes the new `ProcessCreated` / `ProcessTerminated` /
//!   `ImageLoaded` arms in `handle_event` and surfaces
//!   `LocalDetectionAlert` events when behavioural rules fire).
//!
//! All scenarios run on the in-process `EventBus`, walk the same
//! wire shape `sda-process-monitor` publishes in production, and
//! finish in tens of milliseconds — `make e2e-process-telemetry`
//! is safe to run on every CI host without privileges.
//!
//! Coverage (≥ 12 tests for `docs/edr.md` § 2.1 — Process telemetry):
//!
//! 1. Process monitor disabled → no events leak on the bus.
//! 2. `Created` event surfaces as `EventKind::ProcessCreated`
//!    with the canonical `ProcessCreatedPayload` JSON shape.
//! 3. Parent chain enrichment populates `parent_chain` from the
//!    PAL `lookup_ancestors` result, ordered closest-ancestor-first.
//! 4. `parent_chain_depth = 0` skips ancestor enrichment entirely.
//! 5. `Terminated` event surfaces as `EventKind::ProcessTerminated`
//!    with the lightweight payload (pid + name + exit_code).
//! 6. `ImageLoaded` event surfaces as `EventKind::ImageLoaded` when
//!    `image_load_events = true`.
//! 7. `ImageLoaded` event is suppressed when
//!    `image_load_events = false`.
//! 8. Three identical `Created` events for the same pid collapse to
//!    a single bus event via the LDE-side dedup ring.
//! 9. When the PAL `subscribe()` errors the module idles cleanly
//!    without crashing the agent.
//! 10. LDE behavioural rule "Office → PowerShell" fires when a
//!     `Created` event carries a `winword.exe` ancestor.
//! 11. LDE does NOT fire the Office-→-PowerShell rule on a benign
//!     parent chain (`explorer.exe > cmd.exe > powershell.exe`).
//! 12. LDE behavioural rule "wmiprvse → rundll32" fires on the
//!     corresponding ancestry.
//! 13. `Created` payload pid + ppid + cmdline survive a JSON
//!     round-trip without loss (regression for serde wire shape).

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use sda_core::config::{LocalDetectionConfig, ProcessMonitorConfig};
use sda_core::signal::ShutdownController;
use sda_event_bus::{Event, EventBus, EventKind, EventReceiver, Priority};
use sda_local_detection::rule_store::{BehavioralRule, BehavioralRuleKind, RuleBundle, SEV_HIGH};
use sda_pal::process_monitor::{
    MockProcessMonitor, ProcessAncestor, ProcessEvent, ProcessEventStream, ProcessMonitor,
    ProcessMonitorError, ProcessMonitorOpts, Result as PmResult,
};
use sda_process_monitor::{
    ImageLoadedPayload, ProcessCreatedPayload, ProcessMonitorModule, ProcessTerminatedPayload,
};
use serde_json::Value;
use tempfile::TempDir;

// ------------------------------------------------------------------ helpers

/// Wait up to `budget` for an event matching `predicate` to appear on the
/// bus. Returns `None` on timeout. Drains every event in the meantime so
/// the caller can assert on the FIRST matching event.
async fn await_kind<F>(rx: &mut EventReceiver, budget: Duration, predicate: F) -> Option<Event>
where
    F: Fn(&EventKind) -> bool,
{
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(ev)) if predicate(&ev.kind) => return Some(ev),
            Ok(Some(_)) => continue,
            Ok(None) => return None,
            Err(_) => return None,
        }
    }
}

/// Count bus events matching `predicate` over `window`. Useful for
/// dedup assertions where the contract is "≤ 1 published, not 3".
async fn count_kinds<F>(rx: &mut EventReceiver, window: Duration, predicate: F) -> usize
where
    F: Fn(&EventKind) -> bool,
{
    let deadline = tokio::time::Instant::now() + window;
    let mut count = 0;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return count;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(ev)) if predicate(&ev.kind) => count += 1,
            Ok(Some(_)) => continue,
            Ok(None) => return count,
            Err(_) => return count,
        }
    }
}

fn pm_cfg(enabled: bool, parent_depth: u32, image_loads: bool) -> ProcessMonitorConfig {
    ProcessMonitorConfig {
        enabled,
        parent_chain_depth: parent_depth,
        image_load_events: image_loads,
        event_buffer_size: 64,
        poll_interval_ms: 25,
    }
}

fn lde_cfg(tmp: &TempDir) -> LocalDetectionConfig {
    LocalDetectionConfig {
        enabled: true,
        rule_pull_interval: 3600,
        offline_queue_max: 1024,
        yara_scan_rate_limit: 0,
        yara_max_file_size_mb: 16,
        bloom_filter_fpr: 0.01,
        behavioral_max_window_sec: 600,
        behavioral_max_tracked_entities: 256,
        block_ip: false,
        kill_process: false,
        quarantine: false,
        rule_bundle_path: tmp.path().join("bundle.msgpack"),
        offline_queue_path: tmp.path().join("queue.sqlite"),
        quarantine_dir: tmp.path().join("quarantine"),
        offline_drain_interval: 3600,
        offline_drain_batch: 32,
        trds_endpoint: None,
        rule_bundle_signing_keys: Vec::new(),
        trds_pull_timeout_secs: 10,
    }
}

fn agent_config_with(lde: LocalDetectionConfig) -> sda_core::config::AgentConfig {
    let mut cfg = sda_core::config::AgentConfig::default();
    cfg.modules.local_detection = lde;
    cfg
}

fn ancestor(pid: u32, name: &str) -> ProcessAncestor {
    ProcessAncestor {
        pid,
        name: name.into(),
        exe_path: Some(PathBuf::from(format!("/usr/bin/{name}"))),
    }
}

fn created(pid: u32, ppid: u32, name: &str, args: &[&str]) -> ProcessEvent {
    ProcessEvent::Created {
        pid,
        ppid,
        name: name.into(),
        exe_path: Some(PathBuf::from(format!("/usr/bin/{name}"))),
        cmdline: args.iter().map(|s| (*s).into()).collect(),
        user: Some("1000".into()),
        started_at: Utc::now(),
    }
}

fn save_bundle(tmp: &TempDir, rules: Vec<BehavioralRule>) -> PathBuf {
    let bundle = RuleBundle {
        version: 1,
        generated_at: "2026-05-17T00:00:00Z".into(),
        iocs: Default::default(),
        behavioral: rules,
        yara_paths: Vec::new(),
    };
    let path = tmp.path().join("bundle.msgpack");
    bundle.save(&path).expect("write bundle");
    path
}

fn office_chain_rule() -> BehavioralRule {
    BehavioralRule {
        id: "edr-chain-office-powershell".into(),
        severity: SEV_HIGH.into(),
        description: "Office process spawned PowerShell".into(),
        // Phase E review: pin ProcessChain rules to the
        // `process_created` source tag so they cannot fire on
        // ProcessTerminated / ImageLoaded events that share the
        // same underlying domain.
        event_source: "process_created".into(),
        kind: BehavioralRuleKind::ProcessChain {
            name_regex: r"^powershell(\.exe)?$".into(),
            parent_chain_regex: r".*(winword|excel|outlook)(\.exe)?.*".into(),
        },
    }
}

fn wmi_rundll_rule() -> BehavioralRule {
    BehavioralRule {
        id: "edr-chain-wmiprvse-rundll32".into(),
        severity: SEV_HIGH.into(),
        description: "WMI Provider Host spawned rundll32".into(),
        event_source: "process_created".into(),
        kind: BehavioralRuleKind::ProcessChain {
            name_regex: r"^rundll32(\.exe)?$".into(),
            parent_chain_regex: r".*wmiprvse(\.exe)?.*".into(),
        },
    }
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn t01_disabled_module_emits_no_process_events() {
    let monitor = Arc::new(MockProcessMonitor::new());
    monitor.push_event(created(99, 1, "leaked", &[]));
    let (bus, _server_rx) = EventBus::new(16, 16);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = ProcessMonitorModule::start_with_monitor(
        pm_cfg(false, 4, true),
        monitor as Arc<dyn ProcessMonitor>,
        bus,
        shutdown,
    );

    let leaked = count_kinds(&mut rx, Duration::from_millis(150), |k| {
        matches!(
            k,
            EventKind::ProcessCreated { .. }
                | EventKind::ProcessTerminated { .. }
                | EventKind::ImageLoaded { .. }
        )
    })
    .await;
    assert_eq!(leaked, 0, "disabled module leaked {leaked} events");

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t02_created_event_surfaces_as_process_created_kind() {
    let monitor = Arc::new(MockProcessMonitor::new());
    monitor.push_event(created(101, 1, "bash", &["bash", "-c", "ls"]));
    let (bus, _server_rx) = EventBus::new(16, 16);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = ProcessMonitorModule::start_with_monitor(
        pm_cfg(true, 4, true),
        monitor as Arc<dyn ProcessMonitor>,
        bus,
        shutdown,
    );

    let ev = await_kind(&mut rx, Duration::from_secs(2), |k| {
        matches!(k, EventKind::ProcessCreated { .. })
    })
    .await
    .expect("ProcessCreated within 2s");
    let EventKind::ProcessCreated { payload } = ev.kind else {
        unreachable!()
    };
    let parsed: ProcessCreatedPayload = serde_json::from_str(&payload).unwrap();
    assert_eq!(parsed.pid, 101);
    assert_eq!(parsed.ppid, 1);
    assert_eq!(parsed.name, "bash");
    assert_eq!(parsed.cmdline, vec!["bash", "-c", "ls"]);
    assert_eq!(ev.priority, Priority::Normal);

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t03_parent_chain_enrichment_includes_pal_ancestors() {
    let monitor = Arc::new(MockProcessMonitor::new());
    monitor.set_ancestors(
        500,
        vec![
            ancestor(400, "cmd.exe"),
            ancestor(300, "winword.exe"),
            ancestor(200, "explorer.exe"),
        ],
    );
    monitor.push_event(created(500, 400, "powershell.exe", &["powershell.exe"]));

    let (bus, _server_rx) = EventBus::new(16, 16);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = ProcessMonitorModule::start_with_monitor(
        pm_cfg(true, 4, true),
        monitor as Arc<dyn ProcessMonitor>,
        bus,
        shutdown,
    );

    let ev = await_kind(&mut rx, Duration::from_secs(2), |k| {
        matches!(k, EventKind::ProcessCreated { .. })
    })
    .await
    .expect("created within 2s");
    let EventKind::ProcessCreated { payload } = ev.kind else {
        unreachable!()
    };
    let parsed: ProcessCreatedPayload = serde_json::from_str(&payload).unwrap();
    let names: Vec<&str> = parsed
        .parent_chain
        .iter()
        .map(|a| a.name.as_str())
        .collect();
    assert_eq!(names, vec!["cmd.exe", "winword.exe", "explorer.exe"]);

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t04_parent_chain_depth_zero_skips_enrichment() {
    let monitor = Arc::new(MockProcessMonitor::new());
    monitor.set_ancestors(7, vec![ancestor(1, "init")]);
    monitor.push_event(created(7, 1, "sshd", &[]));

    let (bus, _server_rx) = EventBus::new(16, 16);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = ProcessMonitorModule::start_with_monitor(
        pm_cfg(true, 0, true),
        monitor as Arc<dyn ProcessMonitor>,
        bus,
        shutdown,
    );

    let ev = await_kind(&mut rx, Duration::from_secs(2), |k| {
        matches!(k, EventKind::ProcessCreated { .. })
    })
    .await
    .expect("created within 2s");
    let EventKind::ProcessCreated { payload } = ev.kind else {
        unreachable!()
    };
    let parsed: ProcessCreatedPayload = serde_json::from_str(&payload).unwrap();
    assert!(
        parsed.parent_chain.is_empty(),
        "depth=0 should not enrich, got {:?}",
        parsed.parent_chain
    );

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t05_terminated_event_emits_lightweight_payload() {
    let monitor = Arc::new(MockProcessMonitor::new());
    monitor.push_event(ProcessEvent::Terminated {
        pid: 4242,
        name: "evil.exe".into(),
        exit_code: Some(-9),
        ended_at: Utc::now(),
    });
    let (bus, _server_rx) = EventBus::new(16, 16);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = ProcessMonitorModule::start_with_monitor(
        pm_cfg(true, 4, true),
        monitor as Arc<dyn ProcessMonitor>,
        bus,
        shutdown,
    );

    let ev = await_kind(&mut rx, Duration::from_secs(2), |k| {
        matches!(k, EventKind::ProcessTerminated { .. })
    })
    .await
    .expect("terminated within 2s");
    let EventKind::ProcessTerminated { payload } = ev.kind else {
        unreachable!()
    };
    let parsed: ProcessTerminatedPayload = serde_json::from_str(&payload).unwrap();
    assert_eq!(parsed.pid, 4242);
    assert_eq!(parsed.exit_code, Some(-9));
    assert_eq!(parsed.name, "evil.exe");

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t06_image_loaded_event_surfaces_when_enabled() {
    let monitor = Arc::new(MockProcessMonitor::new());
    monitor.push_event(ProcessEvent::ImageLoaded {
        pid: 9000,
        image_path: "/usr/lib/libsuspicious.so".into(),
        image_hash: Some("a".repeat(64)),
        loaded_at: Utc::now(),
    });
    let (bus, _server_rx) = EventBus::new(16, 16);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = ProcessMonitorModule::start_with_monitor(
        pm_cfg(true, 4, true),
        monitor as Arc<dyn ProcessMonitor>,
        bus,
        shutdown,
    );

    let ev = await_kind(&mut rx, Duration::from_secs(2), |k| {
        matches!(k, EventKind::ImageLoaded { .. })
    })
    .await
    .expect("image_loaded within 2s");
    let EventKind::ImageLoaded { payload } = ev.kind else {
        unreachable!()
    };
    let parsed: ImageLoadedPayload = serde_json::from_str(&payload).unwrap();
    assert_eq!(parsed.pid, 9000);
    assert_eq!(parsed.image_path, "/usr/lib/libsuspicious.so");
    assert_eq!(parsed.image_hash.as_deref(), Some("a".repeat(64).as_str()));

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t07_image_loaded_event_suppressed_when_disabled() {
    let monitor = Arc::new(MockProcessMonitor::new());
    monitor.push_event(ProcessEvent::ImageLoaded {
        pid: 1,
        image_path: "/usr/lib/libignored.so".into(),
        image_hash: None,
        loaded_at: Utc::now(),
    });
    let (bus, _server_rx) = EventBus::new(16, 16);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = ProcessMonitorModule::start_with_monitor(
        pm_cfg(true, 4, false),
        monitor as Arc<dyn ProcessMonitor>,
        bus,
        shutdown,
    );

    let leaked = count_kinds(&mut rx, Duration::from_millis(200), |k| {
        matches!(k, EventKind::ImageLoaded { .. })
    })
    .await;
    assert_eq!(leaked, 0, "ImageLoaded leaked while disabled");

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t08_duplicate_created_events_collapse_to_single_bus_event() {
    let monitor = Arc::new(MockProcessMonitor::new());
    let ts = Utc::now();
    for _ in 0..3 {
        monitor.push_event(ProcessEvent::Created {
            pid: 77,
            ppid: 1,
            name: "dup".into(),
            exe_path: None,
            cmdline: vec![],
            user: None,
            started_at: ts,
        });
    }
    let (bus, _server_rx) = EventBus::new(16, 16);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = ProcessMonitorModule::start_with_monitor(
        pm_cfg(true, 0, true),
        monitor as Arc<dyn ProcessMonitor>,
        bus,
        shutdown,
    );

    let n = count_kinds(&mut rx, Duration::from_millis(250), |k| {
        matches!(k, EventKind::ProcessCreated { .. })
    })
    .await;
    assert_eq!(n, 1, "expected dedup to collapse 3 identical events to 1");

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

/// Mock PAL that returns an error from `subscribe`. The module must
/// idle cleanly until shutdown rather than panic the agent.
struct AlwaysErrSubscribe;

impl ProcessMonitor for AlwaysErrSubscribe {
    fn subscribe(&self, _opts: &ProcessMonitorOpts) -> PmResult<ProcessEventStream> {
        Err(ProcessMonitorError::Unsupported("test".into()))
    }
    fn lookup_ancestors(&self, _pid: u32, _max: u32) -> PmResult<Vec<ProcessAncestor>> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn t09_subscribe_failure_does_not_crash_agent() {
    let monitor: Arc<dyn ProcessMonitor> = Arc::new(AlwaysErrSubscribe);
    let (bus, _server_rx) = EventBus::new(16, 16);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle =
        ProcessMonitorModule::start_with_monitor(pm_cfg(true, 4, true), monitor, bus, shutdown);
    let leaked = count_kinds(&mut rx, Duration::from_millis(100), |_| true).await;
    assert_eq!(leaked, 0);
    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t10_lde_office_powershell_chain_rule_fires() {
    let tmp = tempfile::tempdir().unwrap();
    let _ = save_bundle(&tmp, vec![office_chain_rule()]);

    let monitor = Arc::new(MockProcessMonitor::new());
    monitor.set_ancestors(
        500,
        vec![
            ancestor(400, "cmd.exe"),
            ancestor(300, "winword.exe"),
            ancestor(200, "explorer.exe"),
        ],
    );
    monitor.push_event(created(
        500,
        400,
        "powershell.exe",
        &["-NoProfile", "-enc", "..."],
    ));

    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown_pm) = ShutdownController::new();
    let (lde_controller, shutdown_lde) = ShutdownController::new();

    let agent_cfg = agent_config_with(lde_cfg(&tmp));
    let _lde =
        sda_local_detection::LocalDetectionModule::start(&agent_cfg, bus.clone(), shutdown_lde);
    // Give the LDE a beat to load the bundle from disk.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let pm_handle = ProcessMonitorModule::start_with_monitor(
        pm_cfg(true, 4, true),
        monitor as Arc<dyn ProcessMonitor>,
        bus,
        shutdown_pm,
    );

    let alert = await_kind(&mut rx, Duration::from_secs(3), |k| {
        matches!(k, EventKind::LocalDetectionAlert { rule_id, .. }
                 if rule_id == "edr-chain-office-powershell")
    })
    .await;
    controller.shutdown();
    lde_controller.shutdown();
    pm_handle.task.await.unwrap().unwrap();
    assert!(alert.is_some(), "Office→PowerShell rule did not fire");
}

#[tokio::test]
async fn t11_lde_does_not_fire_chain_rule_on_benign_parents() {
    let tmp = tempfile::tempdir().unwrap();
    let _ = save_bundle(&tmp, vec![office_chain_rule()]);

    let monitor = Arc::new(MockProcessMonitor::new());
    monitor.set_ancestors(
        500,
        vec![ancestor(400, "cmd.exe"), ancestor(300, "explorer.exe")],
    );
    monitor.push_event(created(500, 400, "powershell.exe", &["-NoProfile"]));

    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown_pm) = ShutdownController::new();
    let (lde_controller, shutdown_lde) = ShutdownController::new();

    let agent_cfg = agent_config_with(lde_cfg(&tmp));
    let _lde =
        sda_local_detection::LocalDetectionModule::start(&agent_cfg, bus.clone(), shutdown_lde);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let pm_handle = ProcessMonitorModule::start_with_monitor(
        pm_cfg(true, 4, true),
        monitor as Arc<dyn ProcessMonitor>,
        bus,
        shutdown_pm,
    );

    let leaked = count_kinds(&mut rx, Duration::from_millis(400), |k| {
        matches!(k, EventKind::LocalDetectionAlert { rule_id, .. }
                 if rule_id == "edr-chain-office-powershell")
    })
    .await;
    controller.shutdown();
    lde_controller.shutdown();
    pm_handle.task.await.unwrap().unwrap();
    assert_eq!(leaked, 0, "benign chain triggered false positive");
}

#[tokio::test]
async fn t12_lde_wmiprvse_rundll32_chain_rule_fires() {
    let tmp = tempfile::tempdir().unwrap();
    let _ = save_bundle(&tmp, vec![wmi_rundll_rule()]);

    let monitor = Arc::new(MockProcessMonitor::new());
    monitor.set_ancestors(
        910,
        vec![ancestor(910, "wmiprvse.exe"), ancestor(8, "svchost.exe")],
    );
    monitor.push_event(created(
        910,
        4,
        "rundll32.exe",
        &["rundll32.exe", "shell32,Control_RunDLL"],
    ));

    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown_pm) = ShutdownController::new();
    let (lde_controller, shutdown_lde) = ShutdownController::new();
    let agent_cfg = agent_config_with(lde_cfg(&tmp));
    let _lde =
        sda_local_detection::LocalDetectionModule::start(&agent_cfg, bus.clone(), shutdown_lde);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let pm_handle = ProcessMonitorModule::start_with_monitor(
        pm_cfg(true, 4, true),
        monitor as Arc<dyn ProcessMonitor>,
        bus,
        shutdown_pm,
    );

    let alert = await_kind(&mut rx, Duration::from_secs(3), |k| {
        matches!(k, EventKind::LocalDetectionAlert { rule_id, .. }
                 if rule_id == "edr-chain-wmiprvse-rundll32")
    })
    .await;
    controller.shutdown();
    lde_controller.shutdown();
    pm_handle.task.await.unwrap().unwrap();
    assert!(alert.is_some(), "wmiprvse→rundll32 rule did not fire");
}

#[tokio::test]
async fn t13_process_created_payload_survives_json_round_trip() {
    let monitor = Arc::new(MockProcessMonitor::new());
    monitor.push_event(created(
        333,
        1,
        "complex.exe",
        &["complex.exe", "--with", "\"quoted args\"", "--flag"],
    ));
    let (bus, _server_rx) = EventBus::new(16, 16);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = ProcessMonitorModule::start_with_monitor(
        pm_cfg(true, 0, true),
        monitor as Arc<dyn ProcessMonitor>,
        bus,
        shutdown,
    );

    let ev = await_kind(&mut rx, Duration::from_secs(2), |k| {
        matches!(k, EventKind::ProcessCreated { .. })
    })
    .await
    .expect("created within 2s");
    let EventKind::ProcessCreated { payload } = ev.kind else {
        unreachable!()
    };
    let v: Value = serde_json::from_str(&payload).expect("payload is valid JSON");
    assert_eq!(v["pid"].as_u64(), Some(333));
    assert_eq!(v["ppid"].as_u64(), Some(1));
    assert_eq!(v["name"].as_str(), Some("complex.exe"));
    let cmdline: Vec<&str> = v["cmdline"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect();
    assert_eq!(
        cmdline,
        vec!["complex.exe", "--with", "\"quoted args\"", "--flag"]
    );

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}
