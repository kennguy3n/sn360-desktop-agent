//! Process telemetry module (Phase E1 of the EDR Parity workstream).
//!
//! Subscribes to the platform [`sda_pal::process_monitor::ProcessMonitor`]
//! feed, enriches each `Created` event with a parent chain, and
//! publishes [`EventKind::ProcessCreated`], [`EventKind::ProcessTerminated`]
//! and [`EventKind::ImageLoaded`] on the shared event bus.
//!
//! Lifecycle mirrors `sda_local_detection::LocalDetectionModule`:
//! an `AtomicU8` status, a [`ModuleHandle`] returned from `start()`,
//! and a `tokio::select!` loop driven by a [`ShutdownSignal`].

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use sda_core::config::{AgentConfig, ProcessMonitorConfig};
use sda_core::module::{AgentModule, ModuleHandle, ModuleHealth, ModuleStatus};
use sda_core::signal::ShutdownSignal;
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use sda_pal::process_monitor::{
    default_process_monitor, ProcessAncestor, ProcessEvent, ProcessMonitor, ProcessMonitorOpts,
};

const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// Module handle returned by [`ProcessMonitorModule::start`].
pub struct ProcessMonitorModule {
    status: Arc<AtomicU8>,
}

impl Default for ProcessMonitorModule {
    fn default() -> Self {
        Self {
            status: Arc::new(AtomicU8::new(STATUS_INITIALIZED)),
        }
    }
}

impl ProcessMonitorModule {
    /// Spawn the run loop and return a [`ModuleHandle`]. Uses the
    /// per-OS default [`ProcessMonitor`] from
    /// [`sda_pal::process_monitor::default_process_monitor`].
    pub fn start(config: &AgentConfig, bus: EventBus, shutdown: ShutdownSignal) -> ModuleHandle {
        let cfg = config.modules.process_monitor.clone();
        let monitor: Arc<dyn ProcessMonitor> = Arc::from(default_process_monitor());
        Self::start_with_monitor(cfg, monitor, bus, shutdown)
    }

    /// Spawn the run loop with an injected monitor. Used by E2E
    /// tests to plug in [`sda_pal::process_monitor::MockProcessMonitor`].
    pub fn start_with_monitor(
        cfg: ProcessMonitorConfig,
        monitor: Arc<dyn ProcessMonitor>,
        bus: EventBus,
        shutdown: ShutdownSignal,
    ) -> ModuleHandle {
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);
        let task = tokio::spawn(async move {
            if let Err(e) = run(cfg, monitor, bus, shutdown, task_status.clone()).await {
                error!(error = %e, "process monitor module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });
        ModuleHandle::new("process_monitor", task)
    }
}

impl AgentModule for ProcessMonitorModule {
    fn name(&self) -> &'static str {
        "process_monitor"
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

/// Wire-shape of an ancestor entry inside a process telemetry payload.
///
/// Mirrored verbatim from [`ProcessAncestor`] so the wire layer
/// doesn't pull the PAL into its serde graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WireAncestor {
    pub pid: u32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe_path: Option<String>,
}

impl From<ProcessAncestor> for WireAncestor {
    fn from(a: ProcessAncestor) -> Self {
        Self {
            pid: a.pid,
            name: a.name,
            exe_path: a.exe_path.map(|p| p.to_string_lossy().into_owned()),
        }
    }
}

/// Wire-shape of a `ProcessCreated` payload (see
/// `docs/edr-parity/ARCHITECTURE.md` § 8).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessCreatedPayload {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe_path: Option<String>,
    #[serde(default)]
    pub cmdline: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default)]
    pub parent_chain: Vec<WireAncestor>,
    pub started_at: String,
}

/// Wire-shape of a `ProcessTerminated` payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessTerminatedPayload {
    pub pid: u32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub ended_at: String,
}

/// Wire-shape of an `ImageLoaded` payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ImageLoadedPayload {
    pub pid: u32,
    pub image_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_hash: Option<String>,
    pub loaded_at: String,
}

/// Bounded LRU-ish dedup window keyed on `(kind, pid, secondary)`
/// so a poller that emits the same Created twice within the
/// debounce window doesn't double-publish.
#[derive(Debug)]
struct DedupRing {
    seen: VecDeque<u64>,
    capacity: usize,
}

impl DedupRing {
    fn new(capacity: usize) -> Self {
        Self {
            seen: VecDeque::with_capacity(capacity.max(1)),
            capacity: capacity.max(1),
        }
    }

    fn insert(&mut self, key: u64) -> bool {
        if self.seen.iter().any(|k| *k == key) {
            return false;
        }
        if self.seen.len() == self.capacity {
            self.seen.pop_front();
        }
        self.seen.push_back(key);
        true
    }
}

fn event_dedup_key(ev: &ProcessEvent) -> u64 {
    // Cheap rolling hash — `(kind tag, pid, ts micros / 100ms bucket)`.
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    match ev {
        ProcessEvent::Created {
            pid, started_at, ..
        } => {
            0u8.hash(&mut hasher);
            pid.hash(&mut hasher);
            (started_at.timestamp_millis() / 100).hash(&mut hasher);
        }
        ProcessEvent::Terminated { pid, ended_at, .. } => {
            1u8.hash(&mut hasher);
            pid.hash(&mut hasher);
            (ended_at.timestamp_millis() / 100).hash(&mut hasher);
        }
        ProcessEvent::ImageLoaded {
            pid,
            image_path,
            loaded_at,
            ..
        } => {
            2u8.hash(&mut hasher);
            pid.hash(&mut hasher);
            image_path.hash(&mut hasher);
            (loaded_at.timestamp_millis() / 100).hash(&mut hasher);
        }
    }
    hasher.finish()
}

/// Counters exposed via the agent vitals stream.
#[derive(Debug, Default)]
pub struct ProcessMonitorVitals {
    pub events_emitted: AtomicU64,
    pub duplicates_dropped: AtomicU64,
    pub publish_failures: AtomicU64,
}

async fn run(
    cfg: ProcessMonitorConfig,
    monitor: Arc<dyn ProcessMonitor>,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    if !cfg.enabled {
        info!("process monitor disabled; module is a no-op");
        status.store(STATUS_RUNNING, Ordering::Relaxed);
        shutdown.wait().await;
        status.store(STATUS_STOPPED, Ordering::Relaxed);
        return Ok(());
    }

    info!(
        parent_chain_depth = cfg.parent_chain_depth,
        image_load_events = cfg.image_load_events,
        event_buffer_size = cfg.event_buffer_size,
        "process monitor module starting"
    );

    let opts = ProcessMonitorOpts {
        image_load_events: cfg.image_load_events,
        channel_buffer: cfg.event_buffer_size,
        poll_interval_ms: cfg.poll_interval_ms,
    };

    let mut stream = match monitor.subscribe(&opts) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "process monitor subscribe failed; module will remain idle");
            status.store(STATUS_FAILED, Ordering::Relaxed);
            // Wait for shutdown instead of returning — keeps the
            // agent supervisor happy and matches the LDE behaviour
            // when a PAL backend is unavailable.
            shutdown.wait().await;
            return Ok(());
        }
    };

    let vitals = Arc::new(ProcessMonitorVitals::default());
    let mut dedup = DedupRing::new(1024);
    status.store(STATUS_RUNNING, Ordering::Relaxed);

    loop {
        tokio::select! {
            biased;

            _ = shutdown.wait() => {
                info!("process monitor received shutdown signal");
                break;
            }

            ev = stream.recv() => {
                let Some(ev) = ev else {
                    // PAL stream closed (mock backend exhausted, or
                    // production producer died). Keep the module alive
                    // and wait for an explicit shutdown signal so the
                    // event bus stays connected for any in-flight
                    // subscribers.
                    debug!("process monitor stream closed; idling until shutdown");
                    shutdown.wait().await;
                    break;
                };
                let key = event_dedup_key(&ev);
                if !dedup.insert(key) {
                    vitals.duplicates_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                emit_event(ev, &cfg, monitor.as_ref(), &bus, &vitals).await;
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!(
        emitted = vitals.events_emitted.load(Ordering::Relaxed),
        duplicates = vitals.duplicates_dropped.load(Ordering::Relaxed),
        publish_failures = vitals.publish_failures.load(Ordering::Relaxed),
        "process monitor module stopped"
    );
    Ok(())
}

async fn emit_event(
    ev: ProcessEvent,
    cfg: &ProcessMonitorConfig,
    monitor: &dyn ProcessMonitor,
    bus: &EventBus,
    vitals: &Arc<ProcessMonitorVitals>,
) {
    let kind = match ev {
        ProcessEvent::Created {
            pid,
            ppid,
            name,
            exe_path,
            cmdline,
            user,
            started_at,
        } => {
            // Walk the parent chain only when configured.
            let parent_chain: Vec<WireAncestor> = if cfg.parent_chain_depth > 0 {
                match monitor.lookup_ancestors(pid, cfg.parent_chain_depth) {
                    Ok(v) => v.into_iter().map(WireAncestor::from).collect(),
                    Err(e) => {
                        debug!(pid, error = %e, "ancestor lookup failed; emitting without chain");
                        Vec::new()
                    }
                }
            } else {
                Vec::new()
            };
            let payload = ProcessCreatedPayload {
                pid,
                ppid,
                name,
                exe_path: exe_path.map(|p| p.to_string_lossy().into_owned()),
                cmdline,
                user,
                parent_chain,
                started_at: started_at.to_rfc3339(),
            };
            let Ok(payload_str) = serde_json::to_string(&payload) else {
                vitals.publish_failures.fetch_add(1, Ordering::Relaxed);
                return;
            };
            EventKind::ProcessCreated {
                payload: payload_str,
            }
        }
        ProcessEvent::Terminated {
            pid,
            name,
            exit_code,
            ended_at,
        } => {
            let payload = ProcessTerminatedPayload {
                pid,
                name,
                exit_code,
                ended_at: ended_at.to_rfc3339(),
            };
            let Ok(payload_str) = serde_json::to_string(&payload) else {
                vitals.publish_failures.fetch_add(1, Ordering::Relaxed);
                return;
            };
            EventKind::ProcessTerminated {
                payload: payload_str,
            }
        }
        ProcessEvent::ImageLoaded {
            pid,
            image_path,
            image_hash,
            loaded_at,
        } => {
            if !cfg.image_load_events {
                return;
            }
            let payload = ImageLoadedPayload {
                pid,
                image_path: image_path.to_string_lossy().into_owned(),
                image_hash,
                loaded_at: loaded_at.to_rfc3339(),
            };
            let Ok(payload_str) = serde_json::to_string(&payload) else {
                vitals.publish_failures.fetch_add(1, Ordering::Relaxed);
                return;
            };
            EventKind::ImageLoaded {
                payload: payload_str,
            }
        }
    };

    let event = Event::new("process_monitor", Priority::Normal, kind);
    // Mirror the local-detection / FIM convention: publish_to_server
    // already broadcasts locally before attempting the server queue,
    // so we deliberately do NOT add a fallback `bus.publish()` call
    // that would double-fire the LDE pipeline.
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, "process monitor server-bound publish failed");
        vitals.publish_failures.fetch_add(1, Ordering::Relaxed);
    } else {
        vitals.events_emitted.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sda_core::signal::ShutdownController;
    use sda_pal::process_monitor::{MockProcessMonitor, ProcessAncestor, ProcessEvent};

    fn enabled_cfg() -> ProcessMonitorConfig {
        ProcessMonitorConfig {
            enabled: true,
            parent_chain_depth: 4,
            image_load_events: true,
            event_buffer_size: 64,
            poll_interval_ms: 50,
        }
    }

    fn created(pid: u32, ppid: u32, name: &str) -> ProcessEvent {
        ProcessEvent::Created {
            pid,
            ppid,
            name: name.to_string(),
            exe_path: Some(std::path::PathBuf::from(format!("/usr/bin/{name}"))),
            cmdline: vec![name.to_string()],
            user: Some("1000".to_string()),
            started_at: Utc::now(),
        }
    }

    #[test]
    fn dedup_ring_drops_duplicates_within_window() {
        let mut ring = DedupRing::new(4);
        assert!(ring.insert(1));
        assert!(!ring.insert(1));
        assert!(ring.insert(2));
        assert!(ring.insert(3));
        assert!(ring.insert(4));
        // Capacity reached — inserting 5 evicts 1.
        assert!(ring.insert(5));
        // 1 has been evicted so it's accepted again.
        assert!(ring.insert(1));
    }

    #[test]
    fn process_monitor_config_defaults_match_phase_e1_spec() {
        let cfg = ProcessMonitorConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.parent_chain_depth, 8);
        assert!(cfg.image_load_events);
        assert_eq!(cfg.event_buffer_size, 4096);
        assert_eq!(cfg.poll_interval_ms, 500);
    }

    #[tokio::test]
    async fn disabled_module_remains_idle_until_shutdown() {
        let mut cfg = enabled_cfg();
        cfg.enabled = false;
        let monitor = Arc::new(MockProcessMonitor::new());
        let (bus, _server_rx) = EventBus::new(16, 16);
        let (controller, shutdown) = ShutdownController::new();
        let mut rx = bus.subscribe();
        let handle = ProcessMonitorModule::start_with_monitor(
            cfg,
            monitor as Arc<dyn ProcessMonitor>,
            bus,
            shutdown,
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        controller.shutdown();
        handle.task.await.unwrap().unwrap();
        // Drain — should be empty.
        while let Ok(Some(ev)) = tokio::time::timeout(
            std::time::Duration::from_millis(10),
            rx.recv(),
        )
        .await
        {
            assert!(
                !matches!(
                    ev.kind,
                    EventKind::ProcessCreated { .. }
                        | EventKind::ProcessTerminated { .. }
                        | EventKind::ImageLoaded { .. }
                ),
                "disabled module emitted a process event"
            );
        }
    }

    #[tokio::test]
    async fn created_event_includes_parent_chain_from_pal() {
        let monitor = Arc::new(MockProcessMonitor::new());
        monitor.set_ancestors(
            42,
            vec![
                ProcessAncestor {
                    pid: 10,
                    name: "cmd.exe".into(),
                    exe_path: None,
                },
                ProcessAncestor {
                    pid: 5,
                    name: "winword.exe".into(),
                    exe_path: None,
                },
            ],
        );
        monitor.push_event(created(42, 10, "powershell.exe"));

        let (bus, _server_rx) = EventBus::new(16, 16);
        let mut rx = bus.subscribe();
        let (controller, shutdown) = ShutdownController::new();
        let handle = ProcessMonitorModule::start_with_monitor(
            enabled_cfg(),
            monitor as Arc<dyn ProcessMonitor>,
            bus,
            shutdown,
        );

        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("event within timeout")
            .expect("bus open");
        let EventKind::ProcessCreated { payload } = ev.kind else {
            panic!("expected ProcessCreated, got {:?}", ev.kind);
        };
        let parsed: ProcessCreatedPayload = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed.pid, 42);
        assert_eq!(parsed.ppid, 10);
        assert_eq!(parsed.name, "powershell.exe");
        let names: Vec<_> = parsed.parent_chain.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["cmd.exe", "winword.exe"]);

        controller.shutdown();
        handle.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn terminated_event_publishes_clean_payload() {
        let monitor = Arc::new(MockProcessMonitor::new());
        monitor.push_event(ProcessEvent::Terminated {
            pid: 99,
            name: "evil.exe".into(),
            exit_code: Some(137),
            ended_at: Utc::now(),
        });

        let (bus, _server_rx) = EventBus::new(8, 8);
        let mut rx = bus.subscribe();
        let (controller, shutdown) = ShutdownController::new();
        let handle = ProcessMonitorModule::start_with_monitor(
            enabled_cfg(),
            monitor as Arc<dyn ProcessMonitor>,
            bus,
            shutdown,
        );

        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let EventKind::ProcessTerminated { payload } = ev.kind else {
            panic!("expected ProcessTerminated");
        };
        let parsed: ProcessTerminatedPayload = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed.pid, 99);
        assert_eq!(parsed.exit_code, Some(137));

        controller.shutdown();
        handle.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn image_loaded_event_respects_disabled_flag() {
        let monitor = Arc::new(MockProcessMonitor::new());
        monitor.push_event(ProcessEvent::ImageLoaded {
            pid: 7,
            image_path: "/usr/lib/libevil.so".into(),
            image_hash: Some("deadbeef".into()),
            loaded_at: Utc::now(),
        });

        let mut cfg = enabled_cfg();
        cfg.image_load_events = false;

        let (bus, _server_rx) = EventBus::new(8, 8);
        let mut rx = bus.subscribe();
        let (controller, shutdown) = ShutdownController::new();
        let handle = ProcessMonitorModule::start_with_monitor(
            cfg,
            monitor as Arc<dyn ProcessMonitor>,
            bus,
            shutdown,
        );
        // Give the loop time to consume + drop the event.
        let res =
            tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
        let leaked = matches!(res, Ok(Some(_)));
        assert!(!leaked, "ImageLoaded event leaked while disabled: {res:?}");

        controller.shutdown();
        handle.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn duplicate_created_events_are_collapsed_by_dedup_ring() {
        let monitor = Arc::new(MockProcessMonitor::new());
        let ts = Utc::now();
        for _ in 0..3 {
            monitor.push_event(ProcessEvent::Created {
                pid: 12,
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
            enabled_cfg(),
            monitor as Arc<dyn ProcessMonitor>,
            bus,
            shutdown,
        );

        // First Created should arrive.
        let first = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(first.kind, EventKind::ProcessCreated { .. }));

        // Subsequent identical events should be deduped.
        let second =
            tokio::time::timeout(std::time::Duration::from_millis(150), rx.recv()).await;
        let duplicate_fired = matches!(
            second,
            Ok(Some(ref ev)) if matches!(
                ev.kind,
                EventKind::ProcessCreated { .. }
                    | EventKind::ProcessTerminated { .. }
                    | EventKind::ImageLoaded { .. }
            )
        );
        assert!(
            !duplicate_fired,
            "dedup ring did not collapse duplicates: {second:?}"
        );

        controller.shutdown();
        handle.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn module_uses_default_pal_on_start() {
        // Smoke: start() must not panic when the default PAL is
        // selected. We feed a disabled config so we don't actually
        // touch /proc on the CI host.
        use sda_core::config::AgentConfig;
        let mut config = AgentConfig::default();
        config.modules.process_monitor.enabled = false;
        let (bus, _server_rx) = EventBus::new(8, 8);
        let (controller, shutdown) = ShutdownController::new();
        let handle = ProcessMonitorModule::start(&config, bus, shutdown);
        controller.shutdown();
        handle.task.await.unwrap().unwrap();
    }

    #[test]
    fn process_created_payload_round_trips_via_serde() {
        let p = ProcessCreatedPayload {
            pid: 1,
            ppid: 0,
            name: "init".into(),
            exe_path: Some("/sbin/init".into()),
            cmdline: vec!["/sbin/init".into()],
            user: Some("0".into()),
            parent_chain: vec![WireAncestor {
                pid: 0,
                name: "kthreadd".into(),
                exe_path: None,
            }],
            started_at: Utc::now().to_rfc3339(),
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: ProcessCreatedPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn wire_ancestor_drops_exe_path_when_absent() {
        let a = WireAncestor {
            pid: 1,
            name: "init".into(),
            exe_path: None,
        };
        let s = serde_json::to_string(&a).unwrap();
        // serde(skip_serializing_if) must omit the missing field.
        assert!(!s.contains("exe_path"));
    }

    #[test]
    fn event_dedup_key_stable_for_same_event_in_same_bucket() {
        let ts = Utc::now();
        let a = ProcessEvent::Created {
            pid: 1,
            ppid: 0,
            name: "a".into(),
            exe_path: None,
            cmdline: vec![],
            user: None,
            started_at: ts,
        };
        let b = a.clone();
        assert_eq!(event_dedup_key(&a), event_dedup_key(&b));
    }

    #[tokio::test]
    async fn subscribe_failure_does_not_crash_module() {
        use sda_pal::process_monitor::ProcessMonitorOpts;
        struct FailingMonitor;
        impl ProcessMonitor for FailingMonitor {
            fn subscribe(
                &self,
                _opts: &ProcessMonitorOpts,
            ) -> std::result::Result<
                sda_pal::process_monitor::ProcessEventStream,
                sda_pal::process_monitor::ProcessMonitorError,
            > {
                Err(sda_pal::process_monitor::ProcessMonitorError::Unsupported(
                    "test-forced".into(),
                ))
            }
            fn lookup_ancestors(
                &self,
                _pid: u32,
                _max_depth: u32,
            ) -> std::result::Result<Vec<ProcessAncestor>, sda_pal::process_monitor::ProcessMonitorError>
            {
                Ok(Vec::new())
            }
        }

        let (bus, _server_rx) = EventBus::new(4, 4);
        let (controller, shutdown) = ShutdownController::new();
        let monitor: Arc<dyn ProcessMonitor> = Arc::new(FailingMonitor);
        let handle = ProcessMonitorModule::start_with_monitor(
            enabled_cfg(),
            monitor,
            bus,
            shutdown,
        );
        controller.shutdown();
        handle.task.await.unwrap().unwrap();
    }
}
