//! Enhanced Software Inventory module for the SN360 Desktop Agent.
//!
//! Extends the base inventory ([`sda-inventory`]) with:
//!
//! * **Running software monitor** (task 4.7) — periodically snapshots
//!   the process list on Linux, macOS and Windows and emits deltas on
//!   the event bus (see [`running_software`]).
//! * **Browser extensions** (task 4.8) — enumerates installed Chrome,
//!   Firefox, Edge, and Safari extensions per user profile (see
//!   [`browser_extensions`]).
//! * **CycloneDX SBOM** (task 4.9) — generates a full Software Bill
//!   of Materials (CycloneDX 1.5 JSON) combining OS packages, running
//!   processes, and browser extensions (see [`sbom`]). Publishes on
//!   its own timer and on explicit server-pushed requests.
//!
//! The module publishes
//! [`EventKind::EnhancedInventoryUpdate`](sda_event_bus::EventKind::EnhancedInventoryUpdate)
//! events, which the agent maps to a `MessageType::Syscollector`
//! queue on the Wazuh manager so the new categories land alongside
//! the existing inventory indices.

pub mod browser_extensions;
pub mod running_software;
pub mod sbom;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tracing::{debug, error, info, warn};

use sda_core::config::{AgentConfig, EnhancedInventoryConfig};
use sda_core::module::{AgentModule, ModuleHandle, ModuleHealth, ModuleStatus};
use sda_core::signal::ShutdownSignal;
use sda_core::{PowerProfile, PowerProfileReceiver};
use sda_device_control::canonicalize::canonicalize;
use sda_event_bus::{Event, EventBus, EventKind, EventReceiver, Priority};

use crate::browser_extensions::{enumerate_browser_extensions, BrowserExtension};
use crate::running_software::{enumerate_processes, ProcessEntry};

const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// Enhanced inventory module handle.
pub struct EnhancedInventoryModule {
    status: Arc<AtomicU8>,
}

impl EnhancedInventoryModule {
    /// Spawn the enhanced-inventory run loop and return a [`ModuleHandle`].
    ///
    /// `power_rx` lets the module adapt to the active [`PowerProfile`]:
    /// the running-software, browser-extensions, and SBOM timers are
    /// all rebuilt against [`PowerProfile::inventory_interval`] when
    /// the profile changes, and on
    /// [`PowerProfile::CriticalBattery`] all enhanced-inventory scans
    /// are skipped until the host recovers.
    pub fn start(
        config: &AgentConfig,
        bus: EventBus,
        shutdown: ShutdownSignal,
        power_rx: PowerProfileReceiver,
    ) -> ModuleHandle {
        let ei_config = config.modules.enhanced_inventory.clone();
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);

        let task = tokio::spawn(async move {
            if let Err(e) = run(ei_config, bus, shutdown, power_rx, task_status.clone()).await {
                error!(error = %e, "enhanced inventory module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });

        ModuleHandle::new("enhanced_inventory", task)
    }
}

impl Default for EnhancedInventoryModule {
    fn default() -> Self {
        Self {
            status: Arc::new(AtomicU8::new(STATUS_INITIALIZED)),
        }
    }
}

impl AgentModule for EnhancedInventoryModule {
    fn name(&self) -> &'static str {
        "enhanced_inventory"
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

/// Tracks the previous running-software snapshot so the module can
/// emit deltas instead of a full process list on every tick.
#[derive(Default)]
struct RunningSoftwareState {
    /// Whether we've emitted the baseline (full) snapshot yet.
    baseline_sent: bool,
    /// Last observed processes keyed by PID.
    previous: HashMap<u32, ProcessEntry>,
}

/// Two [`ProcessEntry`] values refer to the same running process when
/// they agree on the fields the OS would actually preserve across PID
/// reuse — i.e. the resolved image name and, when known, the absolute
/// executable path. `started_at` is deliberately ignored because Linux
/// derives it from `clock_ticks_per_sec()` and short-lived processes
/// can round-trip to the same tick boundary; PID reuse is always
/// detectable via a different image name or binary path.
fn same_process(a: &ProcessEntry, b: &ProcessEntry) -> bool {
    a.name == b.name && a.path == b.path
}

/// Publish a single enhanced-inventory event on the shared bus.
///
/// Returns `true` on success; logs a warning and returns `false` if the
/// event bus rejected the event (e.g. the server queue is at capacity).
/// Callers that track delivery (such as the running-software baseline)
/// should only advance their state when this returns `true`.
async fn publish_update(bus: &EventBus, category: &str, data: serde_json::Value) -> bool {
    let event = Event::new(
        "enhanced_inventory",
        // Match `sda-inventory::publish_inventory_event` — inventory
        // snapshots are background telemetry and should queue behind
        // latency-sensitive events once the bus starts scheduling by
        // priority.
        Priority::Low,
        EventKind::EnhancedInventoryUpdate {
            category: category.to_string(),
            data,
        },
    );
    match bus.publish_to_server(event).await {
        Ok(()) => true,
        Err(e) => {
            warn!(error = %e, category, "failed to publish enhanced inventory event");
            false
        }
    }
}

/// Build the canonical-JSON payload for a `SoftwareInventoryDelta`
/// event from a running-software baseline or delta.
///
/// `kind` is `"baseline"` or `"delta"`. `processes` is the full process
/// list for baselines; `added` / `removed` are the per-PID diffs for
/// deltas. The output is RFC 8785 canonical JSON so the control plane
/// can dedupe and chain-hash on it without re-parsing.
fn build_software_inventory_delta_payload(
    kind: &str,
    processes: &[&ProcessEntry],
    added: &[&ProcessEntry],
    removed: &[&ProcessEntry],
) -> Option<String> {
    let body = match kind {
        "baseline" => json!({
            "type": "baseline",
            "count": processes.len(),
            "processes": processes,
        }),
        "delta" => json!({
            "type": "delta",
            "added": added,
            "removed": removed,
        }),
        _ => return None,
    };
    match canonicalize(&body) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => Some(s),
            Err(e) => {
                warn!(error = %e, "SoftwareInventoryDelta canonical JSON was not UTF-8");
                None
            }
        },
        Err(e) => {
            warn!(error = %e, "failed to canonicalise SoftwareInventoryDelta payload");
            None
        }
    }
}

/// Publish a `SoftwareInventoryDelta` event for Device Control
/// consumers. Bridges the existing running-software snapshot/delta
/// stream into the Device Control event surface (PHASES.md task 1.10).
async fn publish_software_inventory_delta(bus: &EventBus, payload: String) {
    let event = Event::new(
        "enhanced_inventory",
        // Device Control inventory bridge events are background
        // telemetry — keep them at `Low` like the underlying
        // EnhancedInventoryUpdate so they yield to active-response /
        // signed-job traffic.
        Priority::Low,
        EventKind::SoftwareInventoryDelta { payload },
    );
    if let Err(e) = bus.publish_to_server(event).await {
        // EventBus::publish_to_server already broadcasts locally before
        // attempting the server-bound enqueue, so a failure here just
        // means the server queue was saturated. Log and move on — do
        // NOT add a fallback `bus.publish(...)` (that would double-fire
        // local subscribers).
        warn!(error = %e, "failed to publish SoftwareInventoryDelta event");
    }
}

/// Take one running-software snapshot, diff it against the previous
/// state, and emit any changes on the bus.
///
/// When `device_control_enabled` is true, the running-software
/// snapshot/delta is mirrored as an [`EventKind::SoftwareInventoryDelta`]
/// event with a canonical-JSON payload, in addition to the existing
/// [`EventKind::EnhancedInventoryUpdate`]. This bridges the existing
/// inventory pipeline into the Device Control event surface
/// (`docs/device-control/ARCHITECTURE.md` § 2,
/// `docs/device-control/PHASES.md` task 1.10).
async fn run_running_software_tick(
    bus: &EventBus,
    state: &mut RunningSoftwareState,
    device_control_enabled: bool,
) {
    let processes = match tokio::task::spawn_blocking(enumerate_processes).await {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "running-software enumeration task panicked");
            return;
        }
    };

    let current: HashMap<u32, ProcessEntry> = processes.into_iter().map(|p| (p.pid, p)).collect();

    if !state.baseline_sent {
        let entries: Vec<&ProcessEntry> = current.values().collect();
        let published = publish_update(
            bus,
            "running_software",
            json!({
                "type": "baseline",
                "count": entries.len(),
                "processes": entries,
            }),
        )
        .await;
        if published {
            // Mirror the baseline into the Device Control event surface
            // ONLY after the underlying EnhancedInventoryUpdate has
            // landed — keeping the two streams in lockstep for any
            // consumer correlating them.
            if device_control_enabled {
                if let Some(payload) =
                    build_software_inventory_delta_payload("baseline", &entries, &[], &[])
                {
                    publish_software_inventory_delta(bus, payload).await;
                }
            }
            state.baseline_sent = true;
            state.previous = current;
        } else {
            // Leave `baseline_sent` false so the next tick retries the
            // full baseline instead of jumping straight to deltas that
            // the manager cannot reconcile.
            debug!("baseline publish failed; will retry on next tick");
        }
        return;
    }

    let mut added: Vec<&ProcessEntry> = Vec::new();
    let mut removed: Vec<&ProcessEntry> = Vec::new();

    for (pid, entry) in &current {
        match state.previous.get(pid) {
            None => added.push(entry),
            Some(prev) if !same_process(prev, entry) => {
                // PID reuse — the kernel handed the same pid to a new
                // process between ticks. Report it as a remove + add so
                // the manager updates its view of that slot instead of
                // silently keeping stale process metadata.
                removed.push(prev);
                added.push(entry);
            }
            Some(_) => {}
        }
    }
    for (pid, entry) in &state.previous {
        if !current.contains_key(pid) {
            removed.push(entry);
        }
    }

    if !added.is_empty() || !removed.is_empty() {
        debug!(
            added = added.len(),
            removed = removed.len(),
            "running-software delta"
        );
        let published = publish_update(
            bus,
            "running_software",
            json!({
                "type": "delta",
                "added": added,
                "removed": removed,
            }),
        )
        .await;
        if !published {
            // Keep the previous snapshot so the next tick re-computes
            // the same delta (plus anything new) instead of silently
            // dropping these process changes.
            debug!("delta publish failed; keeping previous snapshot for retry");
            return;
        }
        if device_control_enabled {
            if let Some(payload) =
                build_software_inventory_delta_payload("delta", &[], &added, &removed)
            {
                publish_software_inventory_delta(bus, payload).await;
            }
        }
    }

    state.previous = current;
}

/// Take one SBOM snapshot and emit it as a full CycloneDX document
/// on the bus. The document is always a full snapshot — SBOMs are
/// generated infrequently (default: once per day) and the cost of a
/// delta encoding is not worth the bookkeeping.
async fn run_sbom_tick(bus: &EventBus) {
    let bom = match tokio::task::spawn_blocking(sbom::generate_sbom).await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "sbom generation task panicked");
            return;
        }
    };

    let component_count = bom
        .get("components")
        .and_then(|c| c.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    debug!(components = component_count, "sbom snapshot");
    publish_update(
        bus,
        "sbom",
        json!({
            "type": "snapshot",
            "components": component_count,
            "bom": bom,
        }),
    )
    .await;
}

/// Detect a server-pushed command that should trigger an out-of-band
/// SBOM generation. Kept intentionally lenient — the Wazuh manager
/// has historically sent command names in a few different shapes
/// (raw `"sbom"`, `#!-sbom`, `execd`-wrapped JSON, …) — so we accept
/// any payload that mentions `"sbom"` case-insensitively.
fn is_sbom_request(command: &str, payload: &str) -> bool {
    let needle = "sbom";
    command.to_ascii_lowercase().contains(needle) || payload.to_ascii_lowercase().contains(needle)
}

/// Take one browser-extensions snapshot and emit it as a full list
/// on the bus. Unlike running-software, extensions churn slowly
/// enough that a flat snapshot is both cheap and easier to reconcile
/// than a delta stream.
async fn run_browser_extensions_tick(bus: &EventBus) {
    let extensions: Vec<BrowserExtension> =
        match tokio::task::spawn_blocking(enumerate_browser_extensions).await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "browser-extensions enumeration task panicked");
                return;
            }
        };

    debug!(count = extensions.len(), "browser-extensions snapshot");
    publish_update(
        bus,
        "browser_extensions",
        json!({
            "type": "snapshot",
            "count": extensions.len(),
            "extensions": extensions,
        }),
    )
    .await;
}

/// Compute the effective scan interval for an enhanced-inventory
/// timer under the active [`PowerProfile`].
///
/// Returns `None` for [`PowerProfile::CriticalBattery`] so the caller
/// can pause the timer entirely until the host recovers.
fn effective_ei_interval(configured: Duration, profile: PowerProfile) -> Option<Duration> {
    if matches!(profile, PowerProfile::CriticalBattery) {
        return None;
    }
    Some(configured.max(profile.inventory_interval()))
}

fn rebuild_ei_timer(
    configured: Duration,
    profile: PowerProfile,
    enabled: bool,
) -> Option<tokio::time::Interval> {
    if !enabled {
        return None;
    }
    let interval = effective_ei_interval(configured, profile)?;
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    Some(timer)
}

async fn tick_ei_timer(timer: Option<&mut tokio::time::Interval>) {
    match timer {
        Some(t) => {
            t.tick().await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// Main enhanced-inventory run loop.
async fn run(
    ei_config: EnhancedInventoryConfig,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    mut power_rx: PowerProfileReceiver,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    info!(
        running_software_enabled = ei_config.running_software.enabled,
        running_software_interval = ei_config.running_software.interval,
        browser_extensions_enabled = ei_config.browser_extensions.enabled,
        browser_extensions_interval = ei_config.browser_extensions.interval,
        sbom_enabled = ei_config.sbom.enabled,
        sbom_interval = ei_config.sbom.interval,
        sbom_on_demand = ei_config.sbom.on_demand,
        "enhanced inventory module starting"
    );

    status.store(STATUS_RUNNING, Ordering::Relaxed);

    let mut rs_state = RunningSoftwareState::default();
    let rs_enabled = ei_config.running_software.enabled;
    let rs_configured = Duration::from_secs(ei_config.running_software.interval.max(1));
    let device_control_enabled = ei_config.device_control_bridge_enabled;

    let be_enabled = ei_config.browser_extensions.enabled;
    let be_configured = Duration::from_secs(ei_config.browser_extensions.interval.max(1));

    let sbom_enabled = ei_config.sbom.enabled;
    let sbom_configured = Duration::from_secs(ei_config.sbom.interval.max(1));
    let sbom_on_demand = ei_config.sbom.on_demand;

    // Subscribe to the event bus so we can pick up server-pushed
    // commands that request an out-of-band SBOM. The subscription is
    // taken unconditionally (it's cheap) but messages are only acted
    // on when `sbom_on_demand` is true.
    let mut bus_rx: EventReceiver = bus.subscribe();

    let mut current_profile = *power_rx.borrow();
    let on_critical = matches!(current_profile, PowerProfile::CriticalBattery);

    if rs_enabled && !on_critical {
        // Emit the baseline snapshot immediately on startup so the
        // manager has a fresh inventory without waiting a full cycle.
        run_running_software_tick(&bus, &mut rs_state, device_control_enabled).await;
    }
    if be_enabled && !on_critical {
        run_browser_extensions_tick(&bus).await;
    }
    if sbom_enabled && !on_critical {
        run_sbom_tick(&bus).await;
    }

    let mut rs_timer = rebuild_ei_timer(rs_configured, current_profile, rs_enabled);
    let mut be_timer = rebuild_ei_timer(be_configured, current_profile, be_enabled);
    let mut sbom_timer = rebuild_ei_timer(sbom_configured, current_profile, sbom_enabled);
    // Consume the immediate first tick on each timer — the baselines
    // above already handled the initial snapshot.
    if let Some(ref mut t) = rs_timer {
        t.tick().await;
    }
    if let Some(ref mut t) = be_timer {
        t.tick().await;
    }
    if let Some(ref mut t) = sbom_timer {
        t.tick().await;
    }

    loop {
        tokio::select! {
            biased;

            _ = shutdown.wait() => {
                info!("enhanced inventory module received shutdown signal");
                break;
            }

            change = power_rx.changed() => {
                if change.is_err() {
                    debug!(
                        "power-profile sender dropped; enhanced inventory holding last profile"
                    );
                    continue;
                }
                let new_profile = *power_rx.borrow();
                if new_profile == current_profile {
                    continue;
                }
                info!(
                    previous = ?current_profile,
                    current = ?new_profile,
                    "enhanced inventory retuning for new power profile"
                );
                current_profile = new_profile;
                rs_timer = rebuild_ei_timer(rs_configured, current_profile, rs_enabled);
                be_timer = rebuild_ei_timer(be_configured, current_profile, be_enabled);
                sbom_timer = rebuild_ei_timer(sbom_configured, current_profile, sbom_enabled);
                if let Some(ref mut t) = rs_timer {
                    t.tick().await;
                }
                if let Some(ref mut t) = be_timer {
                    t.tick().await;
                }
                if let Some(ref mut t) = sbom_timer {
                    t.tick().await;
                }
            }

            _ = tick_ei_timer(rs_timer.as_mut()), if rs_timer.is_some() => {
                debug!(profile = ?current_profile, "running-software scan timer fired");
                run_running_software_tick(&bus, &mut rs_state, device_control_enabled).await;
            }

            _ = tick_ei_timer(be_timer.as_mut()), if be_timer.is_some() => {
                debug!(profile = ?current_profile, "browser-extensions scan timer fired");
                run_browser_extensions_tick(&bus).await;
            }

            _ = tick_ei_timer(sbom_timer.as_mut()), if sbom_timer.is_some() => {
                debug!(profile = ?current_profile, "sbom scan timer fired");
                run_sbom_tick(&bus).await;
            }

            result = bus_rx.recv(), if sbom_enabled && sbom_on_demand => {
                match result {
                    Some(event) => {
                        if let EventKind::ServerCommand { command, payload } = &event.kind {
                            if is_sbom_request(command, payload) {
                                if matches!(current_profile, PowerProfile::CriticalBattery) {
                                    debug!(
                                        command = %command,
                                        profile = ?current_profile,
                                        "deferring on-demand SBOM: critical battery"
                                    );
                                } else {
                                    info!(
                                        command = %command,
                                        "on-demand SBOM generation requested"
                                    );
                                    run_sbom_tick(&bus).await;
                                }
                            }
                        }
                    }
                    None => {
                        warn!("event bus closed, stopping enhanced inventory module");
                        break;
                    }
                }
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!("enhanced inventory module stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::config::{BrowserExtensionsConfig, RunningSoftwareConfig, SbomConfig};
    use sda_event_bus::EventBus;

    fn test_agent_config() -> AgentConfig {
        let mut cfg = AgentConfig::default();
        cfg.modules.enhanced_inventory = EnhancedInventoryConfig {
            enabled: true,
            running_software: RunningSoftwareConfig {
                enabled: true,
                interval: 3600,
            },
            browser_extensions: BrowserExtensionsConfig {
                // Disabled by default in tests so the RunningSoftware
                // assertions don't race a browser-extensions snapshot
                // for the single event slot on the bus.
                enabled: false,
                interval: 3600,
            },
            sbom: SbomConfig {
                // Disabled by default for the same reason as
                // browser_extensions — these unit tests focus on the
                // running-software state machine.
                enabled: false,
                interval: 86_400,
                on_demand: false,
            },
            device_control_bridge_enabled: false,
        };
        cfg
    }

    #[tokio::test]
    async fn test_publishes_inventory_event() {
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let mut state = RunningSoftwareState::default();
        run_running_software_tick(&bus, &mut state, false).await;

        let event = tokio::time::timeout(Duration::from_millis(500), server_rx.recv())
            .await
            .expect("expected a running-software baseline event")
            .expect("server_rx closed");

        match event.kind {
            EventKind::EnhancedInventoryUpdate { category, data } => {
                assert_eq!(category, "running_software");
                assert_eq!(data["type"], "baseline");
                assert!(
                    data["count"].as_u64().unwrap() > 0,
                    "baseline must include at least one process, got: {:?}",
                    data
                );
            }
            other => panic!("unexpected event: {:?}", other),
        }
        assert!(state.baseline_sent);
        assert!(!state.previous.is_empty());
    }

    #[tokio::test]
    async fn test_delta_emits_only_on_change() {
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let mut state = RunningSoftwareState::default();

        run_running_software_tick(&bus, &mut state, false).await;
        let _ = tokio::time::timeout(Duration::from_millis(200), server_rx.recv()).await;

        // Force a synthetic entry into the previous snapshot so the
        // next tick sees it as terminated.
        let phantom_pid = u32::MAX;
        state.previous.insert(
            phantom_pid,
            ProcessEntry {
                pid: phantom_pid,
                name: "phantom".into(),
                path: None,
                started_at: None,
                publisher: None,
            },
        );

        run_running_software_tick(&bus, &mut state, false).await;
        let event = tokio::time::timeout(Duration::from_millis(500), server_rx.recv())
            .await
            .expect("expected a delta event")
            .expect("server_rx closed");

        match event.kind {
            EventKind::EnhancedInventoryUpdate { category, data } => {
                assert_eq!(category, "running_software");
                assert_eq!(data["type"], "delta");
                let removed = data["removed"].as_array().expect("removed must be array");
                assert!(
                    removed.iter().any(|p| p["pid"] == phantom_pid),
                    "phantom pid must appear in the removed list: {:?}",
                    removed
                );
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_delta_detects_pid_reuse() {
        // Seed `previous` with an entry that claims to be a different
        // process at a PID we KNOW the current snapshot will also hold
        // (our own test process). The next tick must see the same PID
        // in both maps but detect that the name/path differ and emit
        // both a remove (of the synthetic entry) and an add (of the
        // real entry) for that slot.
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let mut state = RunningSoftwareState::default();

        let me = std::process::id();
        state.baseline_sent = true;
        state.previous.insert(
            me,
            ProcessEntry {
                pid: me,
                name: "impostor".into(),
                path: Some("/definitely/not/this/binary".into()),
                started_at: None,
                publisher: None,
            },
        );

        run_running_software_tick(&bus, &mut state, false).await;
        let event = tokio::time::timeout(Duration::from_millis(500), server_rx.recv())
            .await
            .expect("expected a delta event")
            .expect("server_rx closed");

        match event.kind {
            EventKind::EnhancedInventoryUpdate { category, data } => {
                assert_eq!(category, "running_software");
                assert_eq!(data["type"], "delta");
                let removed = data["removed"].as_array().expect("removed must be array");
                let added = data["added"].as_array().expect("added must be array");
                assert!(
                    removed
                        .iter()
                        .any(|p| p["pid"] == me && p["name"] == "impostor"),
                    "PID-reused slot must appear in the removed list: {:?}",
                    removed
                );
                assert!(
                    added
                        .iter()
                        .any(|p| p["pid"] == me && p["name"] != "impostor"),
                    "new process at the reused PID must appear in the added list: {:?}",
                    added
                );
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[test]
    fn test_same_process_treats_matching_name_and_path_as_equal() {
        let a = ProcessEntry {
            pid: 1,
            name: "foo".into(),
            path: Some("/usr/bin/foo".into()),
            started_at: Some("2026-04-20T06:30:00Z".into()),
            publisher: None,
        };
        let b = ProcessEntry {
            pid: 1,
            name: "foo".into(),
            path: Some("/usr/bin/foo".into()),
            // Intentionally different started_at — we ignore it.
            started_at: Some("2026-04-20T07:00:00Z".into()),
            publisher: None,
        };
        assert!(same_process(&a, &b));
    }

    #[test]
    fn test_same_process_rejects_differing_name() {
        let a = ProcessEntry {
            pid: 1,
            name: "foo".into(),
            path: None,
            started_at: None,
            publisher: None,
        };
        let b = ProcessEntry {
            pid: 1,
            name: "bar".into(),
            path: None,
            started_at: None,
            publisher: None,
        };
        assert!(!same_process(&a, &b));
    }

    #[test]
    fn test_same_process_rejects_differing_path() {
        let a = ProcessEntry {
            pid: 1,
            name: "foo".into(),
            path: Some("/usr/bin/foo".into()),
            started_at: None,
            publisher: None,
        };
        let b = ProcessEntry {
            pid: 1,
            name: "foo".into(),
            path: Some("/tmp/foo".into()),
            started_at: None,
            publisher: None,
        };
        assert!(!same_process(&a, &b));
    }

    #[test]
    fn effective_ei_interval_pauses_on_critical_battery() {
        let cfg = Duration::from_secs(1800);
        assert!(effective_ei_interval(cfg, PowerProfile::CriticalBattery).is_none());
        let normal = effective_ei_interval(cfg, PowerProfile::Normal).unwrap();
        let battery = effective_ei_interval(cfg, PowerProfile::BatteryActive).unwrap();
        assert!(
            battery >= normal,
            "battery interval {battery:?} must be >= normal interval {normal:?}"
        );
    }

    #[tokio::test]
    async fn rebuild_ei_timer_respects_disabled_flag() {
        assert!(
            rebuild_ei_timer(Duration::from_secs(60), PowerProfile::Normal, false).is_none(),
            "disabled module must not build a timer"
        );
        assert!(
            rebuild_ei_timer(Duration::from_secs(60), PowerProfile::CriticalBattery, true)
                .is_none(),
            "critical battery must pause the timer"
        );
        assert!(rebuild_ei_timer(Duration::from_secs(60), PowerProfile::Normal, true).is_some());
    }

    #[tokio::test]
    async fn test_module_lifecycle_starts_and_stops() {
        let agent_config = test_agent_config();
        let (controller, signal) = sda_core::signal::ShutdownController::new();
        let (bus, _server_rx) = EventBus::new(16, 16);
        let (_power_tx, power_rx) = sda_core::power::channel(PowerProfile::Normal);

        let handle = EnhancedInventoryModule::start(&agent_config, bus, signal, power_rx);

        tokio::time::sleep(Duration::from_millis(50)).await;
        controller.shutdown();

        tokio::time::timeout(Duration::from_secs(2), handle.task)
            .await
            .expect("enhanced inventory task did not stop within 2s")
            .expect("join error")
            .expect("enhanced inventory run returned Err");
    }

    #[tokio::test]
    async fn test_baseline_retries_when_publish_fails() {
        // Saturate the server queue BEFORE the first tick so the baseline
        // publish fails. The `baseline_sent` flag and `previous` snapshot
        // must stay empty, and the next tick (after draining the queue)
        // must re-emit the baseline.
        let (bus, mut server_rx) = EventBus::new(16, 2);
        let mut state = RunningSoftwareState::default();

        // Fill the server queue so publish_to_server returns Err(ChannelFull).
        bus.publish_to_server(Event::new("x", Priority::Normal, EventKind::Keepalive))
            .await
            .expect("seed 1/2");
        bus.publish_to_server(Event::new("y", Priority::Normal, EventKind::Keepalive))
            .await
            .expect("seed 2/2");

        run_running_software_tick(&bus, &mut state, false).await;
        assert!(
            !state.baseline_sent,
            "baseline_sent must stay false when publish fails"
        );
        assert!(
            state.previous.is_empty(),
            "previous snapshot must stay empty so the baseline can be retried"
        );

        // Drain the saturating keepalives and re-run the tick; the
        // baseline should now go through and flip the flag.
        let _ = server_rx.recv().await.expect("seeded event 1");
        let _ = server_rx.recv().await.expect("seeded event 2");
        run_running_software_tick(&bus, &mut state, false).await;
        let event = tokio::time::timeout(Duration::from_millis(500), server_rx.recv())
            .await
            .expect("expected a baseline event on retry")
            .expect("server_rx closed");
        match event.kind {
            EventKind::EnhancedInventoryUpdate { category, data } => {
                assert_eq!(category, "running_software");
                assert_eq!(data["type"], "baseline");
            }
            other => panic!("unexpected event: {:?}", other),
        }
        assert!(state.baseline_sent);
        assert!(!state.previous.is_empty());
    }

    #[tokio::test]
    async fn test_delta_retries_when_publish_fails() {
        // Saturate the server queue AFTER the baseline has gone through,
        // so the next tick's delta publish will fail. The `previous`
        // snapshot must be retained so the phantom PID reappears in the
        // delta on the next successful tick.
        let (bus, mut server_rx) = EventBus::new(16, 2);
        let mut state = RunningSoftwareState::default();

        // Send the baseline.
        run_running_software_tick(&bus, &mut state, false).await;
        let _baseline = server_rx
            .recv()
            .await
            .expect("expected baseline on server queue");
        assert!(state.baseline_sent);

        // Inject a phantom entry so the next tick wants to emit a delta.
        let phantom_pid = u32::MAX;
        state.previous.insert(
            phantom_pid,
            ProcessEntry {
                pid: phantom_pid,
                name: "phantom".into(),
                path: None,
                started_at: None,
                publisher: None,
            },
        );

        // Fill the server queue so the delta publish fails.
        bus.publish_to_server(Event::new("x", Priority::Normal, EventKind::Keepalive))
            .await
            .expect("seed 1/2");
        bus.publish_to_server(Event::new("y", Priority::Normal, EventKind::Keepalive))
            .await
            .expect("seed 2/2");

        run_running_software_tick(&bus, &mut state, false).await;
        assert!(
            state.previous.contains_key(&phantom_pid),
            "previous snapshot must still contain the phantom pid so the delta can be re-emitted; got {:?}",
            state.previous.keys().collect::<Vec<_>>()
        );

        // Drain the seeded events and retry. The phantom must appear in
        // the removed list on this tick.
        let _ = server_rx.recv().await;
        let _ = server_rx.recv().await;
        run_running_software_tick(&bus, &mut state, false).await;
        let event = tokio::time::timeout(Duration::from_millis(500), server_rx.recv())
            .await
            .expect("expected a delta event on retry")
            .expect("server_rx closed");
        match event.kind {
            EventKind::EnhancedInventoryUpdate { category, data } => {
                assert_eq!(category, "running_software");
                assert_eq!(data["type"], "delta");
                let removed = data["removed"].as_array().expect("removed must be array");
                assert!(
                    removed.iter().any(|p| p["pid"] == phantom_pid),
                    "phantom pid must reappear in the retried delta: {:?}",
                    removed
                );
            }
            other => panic!("unexpected event: {:?}", other),
        }
        assert!(!state.previous.contains_key(&phantom_pid));
    }

    #[tokio::test]
    async fn test_module_lifecycle_with_running_software_disabled() {
        let mut agent_config = test_agent_config();
        agent_config
            .modules
            .enhanced_inventory
            .running_software
            .enabled = false;

        let (controller, signal) = sda_core::signal::ShutdownController::new();
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let (_power_tx, power_rx) = sda_core::power::channel(PowerProfile::Normal);

        let handle = EnhancedInventoryModule::start(&agent_config, bus, signal, power_rx);

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            server_rx.try_recv().is_err(),
            "no events should be published when running_software is disabled"
        );

        controller.shutdown();
        tokio::time::timeout(Duration::from_secs(2), handle.task)
            .await
            .expect("task did not stop within 2s")
            .expect("join error")
            .expect("run returned Err");
    }

    // ---------------------------------------------------------------
    // Task 1.10 — Software Inventory Bridge
    //
    // The running-software monitor must mirror its baseline / delta
    // events as `EventKind::SoftwareInventoryDelta` for Device Control
    // consumers (only) when `device_control_bridge_enabled = true`.
    // The mirror payload is RFC 8785 canonical JSON.
    // ---------------------------------------------------------------

    /// Drain the server-bound queue until either an event matching
    /// `pred` arrives or the timeout elapses. Any non-matching events
    /// are discarded — used by the bridge tests below to skip past
    /// `EnhancedInventoryUpdate` envelopes when we only care about
    /// the `SoftwareInventoryDelta` mirror.
    async fn recv_matching<F>(
        rx: &mut tokio::sync::mpsc::Receiver<Event>,
        timeout: Duration,
        mut pred: F,
    ) -> Option<Event>
    where
        F: FnMut(&Event) -> bool,
    {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return None;
            }
            let remaining = deadline - now;
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some(ev)) => {
                    if pred(&ev) {
                        return Some(ev);
                    }
                }
                Ok(None) => return None,
                Err(_) => return None,
            }
        }
    }

    #[test]
    fn build_software_inventory_delta_payload_baseline_is_canonical_json() {
        let p = ProcessEntry {
            pid: 7,
            name: "alpha".into(),
            path: Some("/usr/bin/alpha".into()),
            started_at: None,
            publisher: None,
        };
        let q = ProcessEntry {
            pid: 1,
            name: "beta".into(),
            path: None,
            started_at: None,
            publisher: None,
        };
        let processes: Vec<&ProcessEntry> = vec![&p, &q];
        let payload = build_software_inventory_delta_payload("baseline", &processes, &[], &[])
            .expect("baseline payload");

        // Canonical encoding sorts object keys lexicographically. The
        // top-level keys are `count`, `processes`, `type` so they must
        // appear in that order. Any drift is a wire-schema break.
        let count_idx = payload.find("\"count\":").expect("count key present");
        let processes_idx = payload
            .find("\"processes\":")
            .expect("processes key present");
        let type_idx = payload.find("\"type\":").expect("type key present");
        assert!(count_idx < processes_idx, "count must precede processes");
        assert!(processes_idx < type_idx, "processes must precede type");

        // The baseline must report the right count and type tag.
        assert!(
            payload.contains("\"count\":2"),
            "expected count=2 in canonical baseline payload, got {payload}"
        );
        assert!(
            payload.contains("\"type\":\"baseline\""),
            "expected type=baseline in canonical baseline payload, got {payload}"
        );

        // Round-trip through serde_json to confirm it parses.
        let value: serde_json::Value =
            serde_json::from_str(&payload).expect("payload must parse as JSON");
        assert_eq!(value["type"], "baseline");
        assert_eq!(value["count"], 2);
        assert_eq!(value["processes"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn build_software_inventory_delta_payload_delta_is_canonical_json() {
        let added = ProcessEntry {
            pid: 9,
            name: "new".into(),
            path: Some("/usr/bin/new".into()),
            started_at: None,
            publisher: None,
        };
        let removed = ProcessEntry {
            pid: 3,
            name: "gone".into(),
            path: None,
            started_at: None,
            publisher: None,
        };
        let added_refs = [&added];
        let removed_refs = [&removed];
        let payload =
            build_software_inventory_delta_payload("delta", &[], &added_refs, &removed_refs)
                .expect("delta payload");

        let value: serde_json::Value =
            serde_json::from_str(&payload).expect("payload must parse as JSON");
        assert_eq!(value["type"], "delta");
        assert_eq!(value["added"].as_array().unwrap().len(), 1);
        assert_eq!(value["removed"].as_array().unwrap().len(), 1);

        // The delta payload must be free of `processes`/`count` since
        // those are baseline-only fields.
        assert!(!payload.contains("\"processes\""));
        assert!(!payload.contains("\"count\""));
    }

    #[test]
    fn build_software_inventory_delta_payload_rejects_unknown_kind() {
        assert!(build_software_inventory_delta_payload("snapshot", &[], &[], &[]).is_none());
    }

    #[tokio::test]
    async fn baseline_emits_software_inventory_delta_when_bridge_enabled() {
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let mut state = RunningSoftwareState::default();

        run_running_software_tick(&bus, &mut state, true).await;

        // The first event must be the existing EnhancedInventoryUpdate
        // baseline; the second must be the new SoftwareInventoryDelta
        // mirror. We check both events are emitted (in the right order).
        let ei_event = tokio::time::timeout(Duration::from_millis(500), server_rx.recv())
            .await
            .expect("expected EnhancedInventoryUpdate baseline")
            .expect("server_rx closed");
        match &ei_event.kind {
            EventKind::EnhancedInventoryUpdate { category, data } => {
                assert_eq!(category, "running_software");
                assert_eq!(data["type"], "baseline");
            }
            other => panic!("expected EnhancedInventoryUpdate, got {:?}", other),
        }

        let mirror = recv_matching(&mut server_rx, Duration::from_millis(500), |ev| {
            matches!(ev.kind, EventKind::SoftwareInventoryDelta { .. })
        })
        .await
        .expect("expected SoftwareInventoryDelta mirror after baseline");
        match mirror.kind {
            EventKind::SoftwareInventoryDelta { payload } => {
                let value: serde_json::Value = serde_json::from_str(&payload)
                    .expect("SoftwareInventoryDelta payload must be valid JSON");
                assert_eq!(value["type"], "baseline");
                assert!(
                    value["count"].as_u64().unwrap() > 0,
                    "baseline mirror must include at least one process"
                );
            }
            other => panic!("expected SoftwareInventoryDelta, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn delta_emits_software_inventory_delta_when_bridge_enabled() {
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let mut state = RunningSoftwareState::default();

        // Send the baseline first so the next tick produces a delta.
        run_running_software_tick(&bus, &mut state, true).await;
        // Drain any baseline-related events (EnhancedInventoryUpdate +
        // SoftwareInventoryDelta) so they don't pollute the delta
        // assertions below.
        loop {
            if tokio::time::timeout(Duration::from_millis(50), server_rx.recv())
                .await
                .is_err()
            {
                break;
            }
        }

        // Force a synthetic entry into the previous snapshot so the
        // next tick observes a removed process.
        let phantom_pid = u32::MAX;
        state.previous.insert(
            phantom_pid,
            ProcessEntry {
                pid: phantom_pid,
                name: "phantom".into(),
                path: None,
                started_at: None,
                publisher: None,
            },
        );

        run_running_software_tick(&bus, &mut state, true).await;

        // The first event after a delta tick must be the existing
        // EnhancedInventoryUpdate.
        let ei_event = tokio::time::timeout(Duration::from_millis(500), server_rx.recv())
            .await
            .expect("expected EnhancedInventoryUpdate delta")
            .expect("server_rx closed");
        match &ei_event.kind {
            EventKind::EnhancedInventoryUpdate { category, data } => {
                assert_eq!(category, "running_software");
                assert_eq!(data["type"], "delta");
            }
            other => panic!("expected EnhancedInventoryUpdate, got {:?}", other),
        }

        let mirror = recv_matching(&mut server_rx, Duration::from_millis(500), |ev| {
            matches!(ev.kind, EventKind::SoftwareInventoryDelta { .. })
        })
        .await
        .expect("expected SoftwareInventoryDelta mirror after delta");
        match mirror.kind {
            EventKind::SoftwareInventoryDelta { payload } => {
                let value: serde_json::Value = serde_json::from_str(&payload)
                    .expect("SoftwareInventoryDelta payload must be valid JSON");
                assert_eq!(value["type"], "delta");
                let removed = value["removed"].as_array().expect("removed must be array");
                assert!(
                    removed.iter().any(|p| p["pid"] == phantom_pid),
                    "phantom pid must appear in the SoftwareInventoryDelta mirror, got {:?}",
                    removed
                );
            }
            other => panic!("expected SoftwareInventoryDelta, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn no_software_inventory_delta_when_bridge_disabled() {
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let mut state = RunningSoftwareState::default();

        run_running_software_tick(&bus, &mut state, false).await;

        // The baseline EnhancedInventoryUpdate must still fire.
        let ei_event = tokio::time::timeout(Duration::from_millis(500), server_rx.recv())
            .await
            .expect("expected EnhancedInventoryUpdate baseline")
            .expect("server_rx closed");
        assert!(
            matches!(ei_event.kind, EventKind::EnhancedInventoryUpdate { .. }),
            "expected EnhancedInventoryUpdate, got {:?}",
            ei_event.kind
        );

        // Drain the channel for a short window and assert no
        // SoftwareInventoryDelta event ever appears. Using a small
        // budget is fine — the mirror is enqueued synchronously
        // inside `run_running_software_tick`, so if it were going to
        // appear at all it would already be in the queue by now.
        let mirror = recv_matching(&mut server_rx, Duration::from_millis(150), |ev| {
            matches!(ev.kind, EventKind::SoftwareInventoryDelta { .. })
        })
        .await;
        assert!(
            mirror.is_none(),
            "no SoftwareInventoryDelta should be emitted when the bridge is disabled, got {:?}",
            mirror
        );
    }
}
