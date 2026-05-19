//! `sda-posture` — periodic device-posture snapshot module for the
//! SN360 Desktop Agent (Phase 1).
//!
//! This crate is the SDA-side counterpart to
//! [`sda_pal::posture::DevicePostureProvider`]. It owns the timer
//! that asks the PAL for a fresh [`PostureSnapshot`] every
//! `modules.posture.interval_secs` seconds, the [`DeltaTracker`]
//! that decides whether the snapshot is worth publishing, and the
//! power-aware deferral logic that pauses the loop on battery.
//!
//! The Phase 1 supervisor is intentionally minimal — it parks on
//! the shutdown signal so that flipping `modules.posture.enabled`
//! to `false` (the default) keeps idle CPU at zero. The full
//! snapshot loop ships in Phase 2 alongside the bus subscription
//! infrastructure.

pub mod snapshot;

pub use snapshot::{should_snapshot, DeltaDecision, DeltaTracker, PosturePayload};

use sda_core::config::AgentConfig;
use sda_core::module::ModuleHandle;
use sda_core::power::PowerProfileReceiver;
use sda_core::signal::ShutdownSignal;
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use tracing::{info, warn};

/// Posture snapshot module.
///
/// Periodically collects device-posture data (disk encryption,
/// firewall, screen lock, OS patch level) via the PAL
/// [`DevicePostureProvider`] and publishes `DevicePostureState`
/// events on the bus when the snapshot changes. The delta filter
/// avoids bus traffic for unchanged state. Power-aware scheduling
/// defers snapshots while on battery.
pub struct PostureModule;

impl PostureModule {
    pub fn start(
        config: &AgentConfig,
        bus: EventBus,
        mut shutdown: ShutdownSignal,
        power_rx: PowerProfileReceiver,
    ) -> ModuleHandle {
        let interval_secs = config.modules.posture.interval_secs;
        let defer_on_battery = config.modules.posture.defer_on_battery;

        info!(interval_secs, defer_on_battery, "posture module starting");

        let task = tokio::spawn(async move {
            let provider = match sda_pal::posture::default_posture_provider() {
                Some(p) => p,
                None => {
                    warn!("posture: no platform provider available; parking");
                    shutdown.wait().await;
                    return Ok(());
                }
            };
            let mut tracker = DeltaTracker::new();
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(interval_secs.max(10)));

            // Take the first snapshot immediately.
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = shutdown.wait() => {
                        warn!("posture module shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        // Power-aware deferral.
                        if defer_on_battery {
                            let profile = *power_rx.borrow();
                            if !should_snapshot(profile) {
                                continue;
                            }
                        }

                        match provider.snapshot() {
                            Ok(snap) => {
                                let decision = tracker.observe(snap.clone());
                                if decision == DeltaDecision::Emit {
                                    let payload = PosturePayload {
                                        captured_at: chrono::Utc::now(),
                                        snapshot: snap,
                                    };
                                    match serde_json::to_string(&payload) {
                                        Ok(json) => {
                                            let event = Event::new(
                                                "posture",
                                                Priority::Low,
                                                EventKind::DevicePostureState {
                                                    payload: json,
                                                },
                                            );
                                            if let Err(e) = bus.publish(event) {
                                                warn!("posture: bus publish failed: {e}");
                                            }
                                        }
                                        Err(e) => {
                                            warn!("posture: JSON serialize failed: {e}");
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("posture: snapshot failed: {e}");
                            }
                        }
                    }
                }
            }
            Ok(())
        });
        ModuleHandle::new("posture", task)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::PowerProfile;

    #[test]
    fn re_exports_compile() {
        let _ = DeltaTracker::new();
        let _ = should_snapshot(PowerProfile::Normal);
    }

    #[test]
    fn integration_payload_is_valid_json() {
        // Mirrors task 1.6's "snapshot produces valid PostureSnapshot
        // JSON" requirement. We construct the snapshot directly
        // (rather than through `default_posture_provider()`) so the
        // test is hermetic on every CI host regardless of which
        // platform implementation is compiled in.
        use sda_pal::posture::{PostureSnapshot, PostureToggle};
        let snap = PostureSnapshot {
            disk_encryption: PostureToggle::On,
            firewall_enabled: PostureToggle::On,
            screen_lock_enabled: PostureToggle::Unknown,
            os_patch_level: Some("2026-04".into()),
            os_version: Some("24.04".into()),
        };
        let payload = PosturePayload {
            captured_at: chrono::Utc::now(),
            snapshot: snap,
        };
        let s = serde_json::to_string(&payload).unwrap();
        // Round-trips cleanly back into a PosturePayload.
        let _: PosturePayload = serde_json::from_str(&s).unwrap();
    }
}
