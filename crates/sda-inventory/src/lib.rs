//! System inventory collection module for the SN360 Desktop Agent.
//!
//! Collects hardware, OS, package, network information and publishes
//! `EventKind::InventoryUpdate` events to the event bus for each category.
//! Data is collected on startup and then periodically at a configurable interval.

pub mod hardware;
pub mod network;
pub mod os_info;
pub mod packages;
pub mod syscollector_format;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use sda_core::config::AgentConfig;
use sda_core::module::ModuleHandle;
use sda_core::signal::ShutdownSignal;
use sda_core::{PowerProfile, PowerProfileReceiver};
use sda_event_bus::{Event, EventBus, EventKind, Priority};

use crate::syscollector_format::wrap_syscollector;

const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// System inventory collection module.
pub struct InventoryModule;

impl InventoryModule {
    /// Start the inventory module, returning a `ModuleHandle` that owns the spawned task.
    ///
    /// `power_rx` drives adaptive scan scheduling: when the active
    /// [`PowerProfile`] transitions to battery the scan interval is
    /// extended to match [`PowerProfile::inventory_interval`]; on
    /// [`PowerProfile::CriticalBattery`] scans are skipped entirely so
    /// the CPU and radio can stay asleep.
    pub fn start(
        config: &AgentConfig,
        bus: EventBus,
        shutdown: ShutdownSignal,
        power_rx: PowerProfileReceiver,
    ) -> ModuleHandle {
        let inv_config = config.modules.inventory.clone();
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);

        let task = tokio::spawn(async move {
            if let Err(e) = run(inv_config, bus, shutdown, power_rx, task_status.clone()).await {
                error!(error = %e, "inventory module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });

        ModuleHandle::new("inventory", task)
    }
}

impl sda_core::module::AgentModule for InventoryModule {
    fn name(&self) -> &'static str {
        "inventory"
    }

    fn status(&self) -> sda_core::module::ModuleStatus {
        sda_core::module::ModuleStatus::Initialized
    }

    fn health(&self) -> sda_core::module::ModuleHealth {
        sda_core::module::ModuleHealth::Healthy
    }
}

/// Compute the effective inventory scan interval for the active
/// [`PowerProfile`].
///
/// Returns the larger of the statically configured interval and the
/// profile's preferred interval so that a config value like "scan
/// every 30 s" still backs off appropriately on battery. Returns
/// `None` for [`PowerProfile::CriticalBattery`], signalling that the
/// module should pause scans entirely until conditions improve.
fn effective_inventory_interval(configured: Duration, profile: PowerProfile) -> Option<Duration> {
    if matches!(profile, PowerProfile::CriticalBattery) {
        return None;
    }
    Some(configured.max(profile.inventory_interval()))
}

fn rebuild_inventory_timer(
    configured: Duration,
    profile: PowerProfile,
) -> Option<tokio::time::Interval> {
    let interval = effective_inventory_interval(configured, profile)?;
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Consume the immediate first tick — the caller has already
    // handled the initial collection.
    Some(timer)
}

async fn tick_inventory_timer(timer: Option<&mut tokio::time::Interval>) {
    match timer {
        Some(t) => {
            t.tick().await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// The main inventory run loop.
async fn run(
    inv_config: sda_core::config::InventoryConfig,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    mut power_rx: PowerProfileReceiver,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    info!("inventory module starting");

    let configured_interval = Duration::from_secs(inv_config.interval);
    let categories = inv_config.collect.clone();

    status.store(STATUS_RUNNING, Ordering::Relaxed);
    info!(
        interval_secs = inv_config.interval,
        "inventory module running"
    );

    let mut current_profile = *power_rx.borrow();

    // Collect immediately on startup unless we already know the host
    // is on critical battery, in which case we honor the pause.
    if !matches!(current_profile, PowerProfile::CriticalBattery) {
        collect_and_publish(&categories, &bus).await;
    } else {
        info!(
            profile = ?current_profile,
            "skipping initial inventory scan: critical battery"
        );
    }

    // Build the periodic timer scoped to the active profile. The
    // interval will be rebuilt on every profile transition.
    let mut timer = rebuild_inventory_timer(configured_interval, current_profile);
    if let Some(ref mut t) = timer {
        // First tick fires immediately; we already collected above,
        // so consume it to align future ticks to `interval`.
        t.tick().await;
    }

    loop {
        tokio::select! {
            biased;

            _ = shutdown.wait() => {
                info!("inventory module received shutdown signal");
                break;
            }

            change = power_rx.changed() => {
                if change.is_err() {
                    debug!("power-profile sender dropped; inventory holding last profile");
                    continue;
                }
                let new_profile = *power_rx.borrow();
                if new_profile == current_profile {
                    continue;
                }
                info!(
                    previous = ?current_profile,
                    current = ?new_profile,
                    "inventory retuning for new power profile"
                );
                current_profile = new_profile;
                timer = rebuild_inventory_timer(configured_interval, current_profile);
                if let Some(ref mut t) = timer {
                    t.tick().await;
                }
            }

            _ = tick_inventory_timer(timer.as_mut()), if timer.is_some() => {
                debug!(profile = ?current_profile, "inventory collection timer fired");
                collect_and_publish(&categories, &bus).await;
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!("inventory module stopped");
    Ok(())
}

/// Collect all enabled inventory categories and publish events to the bus.
async fn collect_and_publish(categories: &[String], bus: &EventBus) {
    info!("starting inventory collection");

    for category in categories {
        match category.as_str() {
            "os" => {
                let payload = tokio::task::spawn_blocking(os_info::collect_os_info)
                    .await
                    .unwrap_or_else(|e| {
                        warn!(error = %e, "os info collection task panicked");
                        serde_json::json!({})
                    });

                let wire = wrap_syscollector(&payload);
                publish_inventory_event(bus, "os", &wire).await;
            }
            "hardware" => {
                let payload = tokio::task::spawn_blocking(hardware::collect_hardware_info)
                    .await
                    .unwrap_or_else(|e| {
                        warn!(error = %e, "hardware info collection task panicked");
                        serde_json::json!({})
                    });

                let wire = wrap_syscollector(&payload);
                publish_inventory_event(bus, "hardware", &wire).await;
            }
            "network" => {
                let payloads = tokio::task::spawn_blocking(network::collect_network_info)
                    .await
                    .unwrap_or_else(|e| {
                        warn!(error = %e, "network info collection task panicked");
                        Vec::new()
                    });

                for payload in &payloads {
                    let wire = wrap_syscollector(payload);
                    publish_inventory_event(bus, "network", &wire).await;
                    tokio::task::yield_now().await;
                }
            }
            "packages" => {
                let payloads = packages::collect_packages().await;

                for (i, payload) in payloads.iter().enumerate() {
                    let wire = wrap_syscollector(payload);
                    publish_inventory_event(bus, "packages", &wire).await;
                    // Yield every event and sleep every 50 to let the
                    // forwarding loop drain the event bus.
                    if (i + 1) % 50 == 0 {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    } else {
                        tokio::task::yield_now().await;
                    }
                }
            }
            other => {
                warn!(category = %other, "unknown inventory category, skipping");
            }
        }
    }

    info!("inventory collection complete");
}

/// Publish a single inventory event to the event bus.
async fn publish_inventory_event(bus: &EventBus, category: &str, wire_payload: &str) {
    let event = Event::new(
        "inventory",
        Priority::Low,
        EventKind::InventoryUpdate {
            category: category.to_string(),
            data: serde_json::Value::String(wire_payload.to_string()),
        },
    );
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, category = %category, "failed to publish inventory event");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::config::{InventoryConfig, ModulesConfig};
    use sda_core::signal::ShutdownController;

    fn test_config() -> AgentConfig {
        AgentConfig {
            modules: ModulesConfig {
                inventory: InventoryConfig {
                    enabled: true,
                    interval: 5,
                    collect: vec![
                        "os".to_string(),
                        "hardware".to_string(),
                        "network".to_string(),
                    ],
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_inventory_module_lifecycle() {
        let config = test_config();
        let (bus, mut server_rx) = EventBus::new(256, 256);
        let (controller, signal) = ShutdownController::new();

        let (_power_tx, power_rx) = sda_core::power_profile_channel(PowerProfile::Normal);
        let _handle = InventoryModule::start(&config, bus, signal, power_rx);

        // Wait for the initial collection to publish events.
        let event = tokio::time::timeout(Duration::from_secs(10), server_rx.recv())
            .await
            .expect("timed out waiting for inventory event")
            .expect("server_rx closed");

        match &event.kind {
            EventKind::InventoryUpdate { category, data } => {
                assert!(
                    ["os", "hardware", "network", "packages"].contains(&category.as_str()),
                    "unexpected category: {category}"
                );
                assert!(data.is_string(), "data should be a wire-format string");
                let wire = data.as_str().unwrap();
                assert!(
                    wire.starts_with("syscollector:"),
                    "payload should start with syscollector:"
                );
            }
            other => panic!("expected InventoryUpdate, got: {other:?}"),
        }

        controller.shutdown();
    }

    #[test]
    fn effective_inventory_interval_honors_profile() {
        let cfg = Duration::from_secs(60);

        // Normal keeps the configured interval because the profile's
        // preferred floor (30 min) is above 60 s.
        let normal = effective_inventory_interval(cfg, PowerProfile::Normal).unwrap();
        assert!(normal >= PowerProfile::Normal.inventory_interval());

        // BatteryActive stretches further than Normal.
        let battery = effective_inventory_interval(cfg, PowerProfile::BatteryActive).unwrap();
        assert!(
            battery >= normal,
            "battery interval {battery:?} should be >= normal interval {normal:?}"
        );

        // CriticalBattery pauses entirely.
        assert!(effective_inventory_interval(cfg, PowerProfile::CriticalBattery).is_none());
    }

    #[tokio::test]
    async fn rebuild_inventory_timer_returns_none_on_critical_battery() {
        assert!(
            rebuild_inventory_timer(Duration::from_secs(60), PowerProfile::CriticalBattery)
                .is_none()
        );
        assert!(rebuild_inventory_timer(Duration::from_secs(60), PowerProfile::Normal).is_some());
    }

    #[tokio::test]
    async fn test_collect_and_publish_os_only() {
        let (bus, mut server_rx) = EventBus::new(256, 256);
        let categories = vec!["os".to_string()];

        collect_and_publish(&categories, &bus).await;

        let event = tokio::time::timeout(Duration::from_secs(5), server_rx.recv())
            .await
            .expect("timed out waiting for OS inventory event")
            .expect("server_rx closed");

        match &event.kind {
            EventKind::InventoryUpdate { category, .. } => {
                assert_eq!(category, "os");
            }
            other => panic!("expected InventoryUpdate, got: {other:?}"),
        }
    }
}
