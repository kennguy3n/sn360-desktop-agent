//! System-stats collector for the agent-vitals heartbeat.
//!
//! Phase 1 ships a deliberately minimal collector that captures the
//! fields named in `docs/architecture.md` § 3.1 and `docs/architecture.md` § 6:
//!
//! * `rss_kb` — resident set size of the agent process
//! * `cpu_percent` — process CPU averaged since the last sample
//! * `queue_depth` — current event-bus queue depth (mpsc capacity used)
//! * `watchdog_faults` — running count of watchdog-detected faults
//! * `agent_version` — `CARGO_PKG_VERSION` of the agent build
//! * `uptime_secs` — seconds since the process started
//! * `last_seen` — UTC timestamp of the snapshot (`chrono::DateTime<Utc>`)
//!
//! The collector deliberately reads a small subset of the platform
//! APIs so the snapshot is cheap on every OS:
//!
//! | Field         | Linux                      | macOS                | Windows           |
//! |---------------|----------------------------|----------------------|-------------------|
//! | `rss_kb`      | `/proc/self/status`        | `task_info`-style    | `GetProcessMemoryInfo` |
//! | `cpu_percent` | `/proc/self/stat` deltas   | `task_info` deltas   | `GetProcessTimes` |
//!
//! The Phase 1 PR keeps the platform readers as best-effort stubs:
//! when the OS-specific helpers are not yet implemented the
//! collector returns `0` so the heartbeat still flows. The full PAL
//! implementation lands in Phase 1.7 alongside `ResourceLimits`.
//!
//! `Collector` is implemented as a trait so unit tests can drive a
//! deterministic `MockCollector` without poking real syscalls.

use chrono::{DateTime, Utc};
use sda_core::location::{LastKnownLocation, LastKnownLocationStore};
use serde::{Deserialize, Serialize};

/// Snapshot of the agent's vitals at a single instant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VitalsSnapshot {
    /// Resident-set size of the agent process, in kilobytes.
    pub rss_kb: u64,
    /// Process CPU usage since the last sample, in [0, 100].
    pub cpu_percent: f32,
    /// Current event-bus queue depth (count of buffered events).
    pub queue_depth: usize,
    /// Number of watchdog-detected faults observed since startup.
    pub watchdog_faults: u64,
    /// Agent version string (`CARGO_PKG_VERSION`).
    pub agent_version: String,
    /// Process uptime in seconds.
    pub uptime_secs: u64,
    /// UTC timestamp the snapshot was taken at.
    pub last_seen: DateTime<Utc>,
    /// Best-effort IP-geolocation set by the Desktop MDM
    /// `lost_mode` reporter (Phase M2.3). `None` on devices that have
    /// never entered lost mode. Serialised onto the
    /// [`sda_event_bus::EventKind::AgentVitals`] payload only when
    /// present so the existing wire schema is unchanged for devices
    /// that never went lost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_known_location: Option<LastKnownLocation>,
}

/// Trait describing how the heartbeat task collects a fresh
/// [`VitalsSnapshot`]. Implementing this as a trait lets the unit
/// tests drive a deterministic mock without poking real OS APIs.
pub trait Collector: Send + Sync + 'static {
    fn collect(&self) -> VitalsSnapshot;
}

/// Best-effort production collector. On platforms whose readers have
/// not landed yet (Phase 1.7) the integer fields fall back to `0`,
/// which is faithfully emitted on the bus so the control plane can
/// alert that the field is unobservable on this build.
pub struct DefaultCollector {
    started_at: std::time::Instant,
    queue_depth: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    watchdog_faults: std::sync::Arc<std::sync::atomic::AtomicU64>,
    agent_version: String,
    /// Optional cross-module last-known-location store. The Desktop
    /// MDM `lost_mode` reporter writes into this; we read from it
    /// when assembling each snapshot so the next AgentVitals payload
    /// carries the freshest position (Phase M2.3).
    location_store: Option<LastKnownLocationStore>,
}

impl DefaultCollector {
    /// Construct a collector tied to the supplied counters. The
    /// caller (typically the agent supervisor) keeps clones of the
    /// atomics so it can advance them as it observes queue depth and
    /// watchdog faults.
    pub fn new(
        queue_depth: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        watchdog_faults: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        Self {
            started_at: std::time::Instant::now(),
            queue_depth,
            watchdog_faults,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            location_store: None,
        }
    }

    /// Attach the shared [`LastKnownLocationStore`] used by the
    /// Desktop MDM `lost_mode` reporter. After this is called every
    /// snapshot is populated with the current value from the store
    /// (or `None` if no location has been reported yet).
    pub fn with_location_store(mut self, store: LastKnownLocationStore) -> Self {
        self.location_store = Some(store);
        self
    }
}

impl Collector for DefaultCollector {
    fn collect(&self) -> VitalsSnapshot {
        let last_known_location = self.location_store.as_ref().and_then(|s| s.get());
        VitalsSnapshot {
            rss_kb: read_rss_kb(),
            cpu_percent: read_cpu_percent(),
            queue_depth: self.queue_depth.load(std::sync::atomic::Ordering::Relaxed),
            watchdog_faults: self
                .watchdog_faults
                .load(std::sync::atomic::Ordering::Relaxed),
            agent_version: self.agent_version.clone(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            last_seen: Utc::now(),
            last_known_location,
        }
    }
}

/// Read `rss_kb` from `/proc/self/status` on Linux, or fall back to
/// `0` on platforms whose readers have not landed yet. Returning `0`
/// (rather than panicking or returning an error) keeps the heartbeat
/// flowing on every OS so the control plane can alert that the field
/// is unobservable.
#[cfg(target_os = "linux")]
fn read_rss_kb() -> u64 {
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb_str = rest.split_whitespace().next().unwrap_or("0");
                return kb_str.parse::<u64>().unwrap_or(0);
            }
        }
    }
    0
}

#[cfg(not(target_os = "linux"))]
fn read_rss_kb() -> u64 {
    0
}

#[cfg(target_os = "linux")]
fn read_cpu_percent() -> f32 {
    // Phase 1 stub: a single-shot read of /proc/self/stat would
    // require persistent state to compute deltas. The full deltas
    // implementation lands in Phase 1.7 alongside the macOS and
    // Windows readers; until then we emit 0 so the heartbeat flows
    // and the control plane can alert that the field is unobservable.
    0.0
}

#[cfg(not(target_os = "linux"))]
fn read_cpu_percent() -> f32 {
    0.0
}

/// Deterministic mock collector used by the heartbeat unit tests
/// (and re-exported via [`crate::collector::MockCollector`] for the
/// `module.rs` integration tests).
#[cfg(test)]
pub struct MockCollector {
    pub fixed: VitalsSnapshot,
}

#[cfg(test)]
impl Collector for MockCollector {
    fn collect(&self) -> VitalsSnapshot {
        self.fixed.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn default_collector_reports_supplied_counters() {
        let queue_depth = Arc::new(AtomicUsize::new(0));
        let watchdog_faults = Arc::new(AtomicU64::new(0));
        let c = DefaultCollector::new(queue_depth.clone(), watchdog_faults.clone());

        queue_depth.store(7, Ordering::Relaxed);
        watchdog_faults.store(3, Ordering::Relaxed);

        let snap = c.collect();
        assert_eq!(snap.queue_depth, 7);
        assert_eq!(snap.watchdog_faults, 3);
        assert_eq!(snap.agent_version, env!("CARGO_PKG_VERSION"));
        // last_seen should be very recent.
        let lag = (Utc::now() - snap.last_seen).num_seconds().abs();
        assert!(lag < 5, "last_seen was not recent: lag={lag}s");
    }

    #[test]
    fn default_collector_uptime_is_monotonic() {
        let queue_depth = Arc::new(AtomicUsize::new(0));
        let watchdog_faults = Arc::new(AtomicU64::new(0));
        let c = DefaultCollector::new(queue_depth, watchdog_faults);
        let s1 = c.collect();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let s2 = c.collect();
        assert!(s2.uptime_secs >= s1.uptime_secs);
    }

    #[test]
    fn snapshot_round_trips_via_serde_json() {
        let snap = VitalsSnapshot {
            rss_kb: 12_345,
            cpu_percent: 4.25,
            queue_depth: 9,
            watchdog_faults: 1,
            agent_version: "0.1.0".into(),
            uptime_secs: 99,
            last_seen: Utc::now(),
            last_known_location: None,
        };
        let s = serde_json::to_string(&snap).unwrap();
        let back: VitalsSnapshot = serde_json::from_str(&s).unwrap();
        assert_eq!(back, snap);
    }

    #[test]
    fn snapshot_round_trips_with_location() {
        let loc = LastKnownLocation {
            lat: 37.7749,
            lon: -122.4194,
            accuracy_m: 25.0,
            reported_at: Utc::now(),
        };
        let snap = VitalsSnapshot {
            rss_kb: 1,
            cpu_percent: 0.0,
            queue_depth: 0,
            watchdog_faults: 0,
            agent_version: "test".into(),
            uptime_secs: 0,
            last_seen: Utc::now(),
            last_known_location: Some(loc),
        };
        let s = serde_json::to_string(&snap).unwrap();
        let back: VitalsSnapshot = serde_json::from_str(&s).unwrap();
        assert_eq!(back, snap);
    }

    #[test]
    fn default_collector_reads_location_store() {
        let queue_depth = Arc::new(AtomicUsize::new(0));
        let watchdog_faults = Arc::new(AtomicU64::new(0));
        let store = LastKnownLocationStore::new();
        let loc = LastKnownLocation {
            lat: 1.0,
            lon: 2.0,
            accuracy_m: 50.0,
            reported_at: Utc::now(),
        };
        store.set(loc);

        let c = DefaultCollector::new(queue_depth, watchdog_faults).with_location_store(store);
        let snap = c.collect();
        let got = snap.last_known_location.expect("location should be set");
        assert_eq!(got.lat, 1.0);
        assert_eq!(got.lon, 2.0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_rss_kb_returns_nonzero_on_linux() {
        // The Linux test runner's process always has a non-zero
        // VmRSS, so this is a useful smoke test that the parser
        // actually picks the value up.
        let rss = read_rss_kb();
        assert!(rss > 0, "VmRSS parsed as 0 on Linux test runner");
    }

    #[test]
    fn mock_collector_returns_fixed_snapshot() {
        let snap = VitalsSnapshot {
            rss_kb: 1,
            cpu_percent: 2.0,
            queue_depth: 3,
            watchdog_faults: 4,
            agent_version: "test".into(),
            uptime_secs: 5,
            last_seen: Utc::now(),
            last_known_location: None,
        };
        let c = MockCollector {
            fixed: snap.clone(),
        };
        assert_eq!(c.collect(), snap);
    }
}
