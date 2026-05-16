//! Periodic heartbeat that emits [`EventKind::AgentVitals`] events
//! on the shared event bus.
//!
//! The heartbeat runs at `interval_secs` (default 60s, taken from
//! `ARCHITECTURE.md § 7.3` where `AgentVitals` is `Priority::Low`).
//! It honours power-aware deferral: on
//! [`PowerProfile::CriticalBattery`] the cadence is paused entirely
//! so the radios stay quiet on a dying laptop. On any other profile
//! the configured cadence is used verbatim — `Priority::Low` already
//! lets the bus scheduler defer the event behind operational
//! traffic, so we do not stretch the cadence here.
//!
//! The emitted payload is the canonical JSON of [`VitalsSnapshot`];
//! it is wrapped in [`EventKind::AgentVitals`] (which carries an
//! already-serialised payload string per the wire schema in
//! `SCHEMAS.md § 12`).

use std::time::Duration;

use sda_core::PowerProfile;
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use serde_json::json;
use tracing::{debug, warn};

use crate::collector::{Collector, VitalsSnapshot};

/// Result of a single heartbeat tick. Returned so unit tests can
/// drive ticks deterministically without relying on real wall time.
#[derive(Debug, Clone, PartialEq)]
pub enum TickOutcome {
    /// A vitals event was published successfully.
    Published(VitalsSnapshot),
    /// Tick deferred because the host is on critical battery.
    DeferredCriticalBattery,
    /// `publish_to_server` failed (queue full, server-bus closed,
    /// etc.). The snapshot is still attached so the caller can log /
    /// retry as it sees fit.
    PublishFailed(VitalsSnapshot),
}

/// Wrap a snapshot into an [`EventKind::AgentVitals`] payload.
///
/// The wire schema is canonical JSON; we use `serde_json::to_string`
/// here because the manifest schema (SCHEMAS.md § 12) does not
/// require RFC 8785 byte-equality for vitals events — the control
/// plane parses the payload as-is. Keeping this on a deterministic
/// path (no maps with arbitrary keys; struct fields are
/// lexicographically named) makes the encoded form stable on every
/// tick.
pub fn snapshot_to_event_kind(snap: &VitalsSnapshot) -> EventKind {
    let mut body = json!({
        "schema_version": 1,
        "rss_kb": snap.rss_kb,
        "cpu_percent": snap.cpu_percent,
        "queue_depth": snap.queue_depth,
        "watchdog_faults": snap.watchdog_faults,
        "agent_version": snap.agent_version,
        "uptime_secs": snap.uptime_secs,
        "last_seen": snap.last_seen.to_rfc3339(),
    });
    if let Some(loc) = snap.last_known_location {
        // Additive field — see `docs/desktop-mdm/ARCHITECTURE.md` § 3.7.
        // Devices that never entered lost mode omit the field
        // entirely so the existing wire schema is unchanged.
        body["last_known_location"] = json!({
            "lat": loc.lat,
            "lon": loc.lon,
            "accuracy_m": loc.accuracy_m,
            "reported_at": loc.reported_at.to_rfc3339(),
        });
    }
    let payload =
        serde_json::to_string(&body).expect("serializing AgentVitals payload must not fail");
    EventKind::AgentVitals { payload }
}

/// Drive one heartbeat tick. Public so the unit tests can call it
/// directly without spawning a timer.
pub async fn run_tick<C: Collector>(
    bus: &EventBus,
    collector: &C,
    profile: PowerProfile,
) -> TickOutcome {
    if matches!(profile, PowerProfile::CriticalBattery) {
        debug!("agent vitals heartbeat deferred: critical battery");
        return TickOutcome::DeferredCriticalBattery;
    }
    let snap = collector.collect();
    let kind = snapshot_to_event_kind(&snap);
    let event = Event::new("agent_vitals", Priority::Low, kind);
    match bus.publish_to_server(event).await {
        Ok(()) => TickOutcome::Published(snap),
        Err(e) => {
            // Per the SDA event-bus contract, `publish_to_server`
            // already broadcasts locally before attempting the mpsc
            // send, so we must NOT retry via `bus.publish` here —
            // doing so would double-fire local subscribers. Just log
            // and return.
            warn!(error = %e, "agent vitals publish_to_server failed");
            TickOutcome::PublishFailed(snap)
        }
    }
}

/// Compute the effective heartbeat cadence under the active power
/// profile. Returns `None` when the profile is
/// [`PowerProfile::CriticalBattery`] so the supervisor can pause
/// the timer entirely until the host recovers.
pub fn effective_interval(configured: Duration, profile: PowerProfile) -> Option<Duration> {
    if matches!(profile, PowerProfile::CriticalBattery) {
        None
    } else {
        Some(configured)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::MockCollector;
    use chrono::Utc;
    use sda_event_bus::EventBus;

    fn fixed_snapshot() -> VitalsSnapshot {
        VitalsSnapshot {
            rss_kb: 1024,
            cpu_percent: 1.5,
            queue_depth: 2,
            watchdog_faults: 0,
            agent_version: "0.1.0".into(),
            uptime_secs: 42,
            last_seen: Utc::now(),
            last_known_location: None,
        }
    }

    #[test]
    fn snapshot_to_event_kind_emits_canonical_payload() {
        let snap = fixed_snapshot();
        match snapshot_to_event_kind(&snap) {
            EventKind::AgentVitals { payload } => {
                let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
                assert_eq!(parsed["schema_version"], 1);
                assert_eq!(parsed["rss_kb"], 1024);
                assert_eq!(parsed["queue_depth"], 2);
                assert_eq!(parsed["uptime_secs"], 42);
                assert_eq!(parsed["agent_version"], "0.1.0");
                assert!(
                    parsed.get("last_known_location").is_none(),
                    "last_known_location must be omitted when None"
                );
            }
            other => panic!("expected AgentVitals, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_to_event_kind_includes_location_when_present() {
        use sda_core::location::LastKnownLocation;
        let mut snap = fixed_snapshot();
        snap.last_known_location = Some(LastKnownLocation {
            lat: 37.7749,
            lon: -122.4194,
            accuracy_m: 25.0,
            reported_at: Utc::now(),
        });
        match snapshot_to_event_kind(&snap) {
            EventKind::AgentVitals { payload } => {
                let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
                let loc = parsed.get("last_known_location").expect("loc field present");
                assert_eq!(loc["lat"], 37.7749);
                assert_eq!(loc["lon"], -122.4194);
                assert_eq!(loc["accuracy_m"], 25.0);
                assert!(loc.get("reported_at").is_some());
            }
            other => panic!("expected AgentVitals, got {other:?}"),
        }
    }

    #[test]
    fn effective_interval_pauses_on_critical_battery() {
        assert_eq!(
            effective_interval(Duration::from_secs(60), PowerProfile::CriticalBattery),
            None
        );
        assert_eq!(
            effective_interval(Duration::from_secs(60), PowerProfile::Normal),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            effective_interval(Duration::from_secs(60), PowerProfile::BatteryActive),
            Some(Duration::from_secs(60))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_tick_publishes_on_normal_profile() {
        let (bus, mut server_rx) = EventBus::new(8, 8);
        let collector = MockCollector {
            fixed: fixed_snapshot(),
        };
        let outcome = run_tick(&bus, &collector, PowerProfile::Normal).await;
        match outcome {
            TickOutcome::Published(s) => assert_eq!(s.rss_kb, 1024),
            other => panic!("expected Published, got {other:?}"),
        }
        // Drain the server-bound queue and assert we got an
        // AgentVitals event.
        let event = server_rx
            .recv()
            .await
            .expect("server queue should have event");
        match event.kind {
            EventKind::AgentVitals { .. } => {}
            other => panic!("expected AgentVitals, got {other:?}"),
        }
        assert_eq!(event.priority, Priority::Low);
        assert_eq!(event.source, "agent_vitals");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_tick_defers_on_critical_battery() {
        let (bus, mut server_rx) = EventBus::new(8, 8);
        let collector = MockCollector {
            fixed: fixed_snapshot(),
        };
        let outcome = run_tick(&bus, &collector, PowerProfile::CriticalBattery).await;
        assert!(matches!(outcome, TickOutcome::DeferredCriticalBattery));
        // No event was published.
        assert!(server_rx.try_recv().is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_tick_publishes_on_battery_active() {
        let (bus, mut server_rx) = EventBus::new(8, 8);
        let collector = MockCollector {
            fixed: fixed_snapshot(),
        };
        let outcome = run_tick(&bus, &collector, PowerProfile::BatteryActive).await;
        assert!(matches!(outcome, TickOutcome::Published(_)));
        let event = server_rx.recv().await.unwrap();
        assert!(matches!(event.kind, EventKind::AgentVitals { .. }));
    }
}
