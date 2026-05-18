//! Supervisor task for the agent-vitals heartbeat.
//!
//! Wires the [`Collector`] and the heartbeat tick from
//! [`crate::heartbeat::run_tick`] onto a power-aware timer that the
//! agent supervisor can spawn alongside `QueryModule` and
//! `PostureModule`.
//!
//! The Phase 1 module:
//!
//! 1. Spawns a [`tokio::time::Interval`] at the configured cadence
//!    (default 60s — `Priority::Low` per `docs/architecture.md` § 3.1).
//! 2. Subscribes to the [`PowerProfileReceiver`] so the cadence is
//!    paused entirely on [`PowerProfile::CriticalBattery`].
//! 3. Calls [`run_tick`] on every fire.
//! 4. Exits cleanly when [`ShutdownSignal`] fires.
//!
//! When `device_control.enabled = false` the agent never spawns this
//! task, which keeps idle CPU at zero (the lazy-module-loading
//! invariant from `docs/architecture.md` § 3).

use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::Arc;
use std::time::Duration;

use sda_core::location::LastKnownLocationStore;
use sda_core::module::ModuleHandle;
use sda_core::signal::ShutdownSignal;
use sda_core::{PowerProfile, PowerProfileReceiver};
use sda_event_bus::EventBus;
use tracing::{debug, info, warn};

use crate::collector::DefaultCollector;
use crate::heartbeat::{effective_interval, run_tick};

/// Default cadence for the heartbeat (`docs/architecture.md` § 3.1).
pub const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 60;

/// Counters that the supervisor and the collector share. The
/// supervisor (or other modules) advance these atomics as they
/// observe queue depth and watchdog faults; every heartbeat tick
/// snapshots them.
#[derive(Debug, Clone, Default)]
pub struct VitalsCounters {
    pub queue_depth: Arc<AtomicUsize>,
    pub watchdog_faults: Arc<AtomicU64>,
}

impl VitalsCounters {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Phase 1 supervisor handle for the agent-vitals module.
pub struct VitalsModule;

impl VitalsModule {
    /// Spawn the agent-vitals heartbeat task.
    ///
    /// `interval_secs` is the heartbeat cadence in seconds; pass
    /// [`DEFAULT_HEARTBEAT_INTERVAL_SECS`] if the operator did not
    /// override it. `counters` carries the live queue-depth and
    /// watchdog-fault atomics; the agent supervisor keeps the same
    /// atomics on its side and updates them as it observes the bus.
    ///
    /// `location_store` is the shared
    /// [`LastKnownLocationStore`] the Desktop MDM lost-mode reporter
    /// writes into. Pass the same instance you handed to
    /// [`sda_mdm::MdmModule::with_geolocator`] so the heartbeat can
    /// attach the latest IP-geolocation reading to its
    /// `AgentVitals` payload. Pass `None` if the MDM module is not
    /// running (the heartbeat then publishes
    /// `last_known_location = None`).
    pub fn start(
        interval_secs: u64,
        counters: VitalsCounters,
        bus: EventBus,
        mut shutdown: ShutdownSignal,
        mut power_rx: PowerProfileReceiver,
        location_store: Option<LastKnownLocationStore>,
    ) -> ModuleHandle {
        let configured = Duration::from_secs(interval_secs.max(1));
        let mut collector = DefaultCollector::new(counters.queue_depth, counters.watchdog_faults);
        if let Some(store) = location_store {
            collector = collector.with_location_store(store);
        }

        info!(
            interval_secs = configured.as_secs(),
            "agent vitals heartbeat starting"
        );

        let task = tokio::spawn(async move {
            let mut current_profile = *power_rx.borrow();
            let mut timer = build_timer(configured, current_profile);
            // Consume the immediate first tick so we don't fire a
            // heartbeat at startup before any modules have warmed
            // up.
            if let Some(t) = timer.as_mut() {
                t.tick().await;
            }
            loop {
                tokio::select! {
                    biased;

                    _ = shutdown.wait() => {
                        info!("agent vitals heartbeat shutting down");
                        break;
                    }

                    change = power_rx.changed() => {
                        if change.is_err() {
                            debug!(
                                "power-profile sender dropped; vitals holding last profile"
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
                            "vitals retuning for new power profile"
                        );
                        current_profile = new_profile;
                        timer = build_timer(configured, current_profile);
                        if let Some(t) = timer.as_mut() {
                            t.tick().await;
                        }
                    }

                    _ = tick_timer(timer.as_mut()), if timer.is_some() => {
                        let outcome = run_tick(&bus, &collector, current_profile).await;
                        if let crate::heartbeat::TickOutcome::PublishFailed(_) = outcome {
                            warn!("agent vitals tick: publish failed");
                        }
                    }
                }
            }
            Ok(())
        });

        ModuleHandle::new("agent_vitals", task)
    }
}

fn build_timer(configured: Duration, profile: PowerProfile) -> Option<tokio::time::Interval> {
    let interval = effective_interval(configured, profile)?;
    let mut t = tokio::time::interval(interval);
    t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    Some(t)
}

async fn tick_timer(timer: Option<&mut tokio::time::Interval>) {
    match timer {
        Some(t) => {
            t.tick().await;
        }
        None => std::future::pending::<()>().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::power::channel as power_profile_channel;
    use sda_core::signal::ShutdownController;

    #[tokio::test(flavor = "current_thread")]
    async fn module_starts_and_exits_cleanly_on_shutdown() {
        let (bus, _server_rx) = EventBus::new(8, 8);
        let (controller, signal) = ShutdownController::new();
        let (_pwr_tx, pwr_rx) = power_profile_channel(PowerProfile::Normal);
        let counters = VitalsCounters::new();
        let handle = VitalsModule::start(
            DEFAULT_HEARTBEAT_INTERVAL_SECS,
            counters,
            bus,
            signal,
            pwr_rx,
            None,
        );
        assert_eq!(handle.name, "agent_vitals");
        controller.shutdown();
        handle.task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn module_idles_on_critical_battery_and_exits() {
        let (bus, _server_rx) = EventBus::new(8, 8);
        let (controller, signal) = ShutdownController::new();
        let (_pwr_tx, pwr_rx) = power_profile_channel(PowerProfile::CriticalBattery);
        let counters = VitalsCounters::new();
        let handle = VitalsModule::start(1, counters, bus, signal, pwr_rx, None);
        // No timer running, but shutdown still wakes the loop.
        controller.shutdown();
        handle.task.await.unwrap().unwrap();
    }

    #[test]
    fn build_timer_returns_none_on_critical_battery() {
        // `build_timer` does not create a tokio interval on
        // `CriticalBattery`, so this test does not need a runtime.
        assert!(build_timer(Duration::from_secs(60), PowerProfile::CriticalBattery).is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn build_timer_returns_some_on_other_profiles() {
        // `tokio::time::interval` requires a tokio runtime, so this
        // test runs inside one.
        assert!(build_timer(Duration::from_secs(60), PowerProfile::Normal).is_some());
        assert!(build_timer(Duration::from_secs(60), PowerProfile::BatteryActive).is_some());
    }

    #[test]
    fn vitals_counters_are_arc_shared() {
        let c = VitalsCounters::new();
        let c2 = c.clone();
        c.queue_depth.store(7, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(c2.queue_depth.load(std::sync::atomic::Ordering::Relaxed), 7);
    }

    #[test]
    fn default_heartbeat_interval_matches_arch_md() {
        // `docs/architecture.md` § 3.1 lists AgentVitals as Priority::Low
        // with a default 60-second cadence. Lock that in so a future
        // refactor cannot silently change it.
        assert_eq!(DEFAULT_HEARTBEAT_INTERVAL_SECS, 60);
    }
}
