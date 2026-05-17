//! Cross-module last-known-location surface.
//!
//! The Desktop MDM module ([`sda_mdm::lost_mode`]) writes the most
//! recent IP-geolocation reading into a [`LastKnownLocationStore`]
//! while the device is in lost mode. The agent-vitals heartbeat
//! ([`sda_agent_vitals::heartbeat`]) reads from the same store and
//! attaches the location to its outbound `AgentVitals` payload as an
//! additive field, so the control plane can render the device's
//! approximate position alongside its health metrics.
//!
//! The type lives in `sda-core` so neither sub-crate has to depend on
//! the other.

use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Best-effort IP-geolocation report attached to `AgentVitals`.
///
/// Wire schema: `(lat, lon, accuracy_m, reported_at)` — see
/// `docs/desktop-mdm/ARCHITECTURE.md` § 3.7.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LastKnownLocation {
    pub lat: f64,
    pub lon: f64,
    /// Estimated accuracy radius in metres.
    pub accuracy_m: f64,
    pub reported_at: DateTime<Utc>,
}

/// Cheaply-cloneable shared store for the most recent
/// [`LastKnownLocation`]. The writer is the Desktop MDM `lost_mode`
/// reporter; the reader is the agent-vitals heartbeat collector.
#[derive(Clone, Default)]
pub struct LastKnownLocationStore {
    inner: Arc<RwLock<Option<LastKnownLocation>>>,
}

impl LastKnownLocationStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the current location (returns `None` when nothing has
    /// been reported yet or the lock is poisoned).
    ///
    /// A poisoned lock means a previous holder of the write lock
    /// panicked — we log a `warn!` so the failure mode is at least
    /// observable in agent logs, then return `None` and keep the
    /// heartbeat path going. The poisoned-lock branch is silent in
    /// the previous implementation and would suppress all future
    /// location reports without any signal.
    pub fn get(&self) -> Option<LastKnownLocation> {
        match self.inner.read() {
            Ok(g) => *g,
            Err(e) => {
                warn!(
                    target: "sda_core::location",
                    error = %e,
                    "LastKnownLocationStore read lock poisoned — returning None"
                );
                None
            }
        }
    }

    /// Overwrite the stored location.
    ///
    /// A poisoned lock is logged at `warn!` and the write is
    /// dropped — the previous implementation silently dropped the
    /// write with no signal.
    pub fn set(&self, loc: LastKnownLocation) {
        match self.inner.write() {
            Ok(mut g) => *g = Some(loc),
            Err(e) => warn!(
                target: "sda_core::location",
                error = %e,
                "LastKnownLocationStore write lock poisoned — dropping update"
            ),
        }
    }

    /// Drop the stored location (used when exiting lost mode if the
    /// caller wants to stop reporting). Most callers leave the last
    /// reading in place so a stale-but-useful position can still be
    /// surfaced after exit.
    ///
    /// A poisoned lock is logged at `warn!` and the clear is
    /// dropped.
    pub fn clear(&self) {
        match self.inner.write() {
            Ok(mut g) => *g = None,
            Err(e) => warn!(
                target: "sda_core::location",
                error = %e,
                "LastKnownLocationStore write lock poisoned — dropping clear"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_round_trip() {
        let s = LastKnownLocationStore::new();
        assert!(s.get().is_none());
        let loc = LastKnownLocation {
            lat: 37.7749,
            lon: -122.4194,
            accuracy_m: 25.0,
            reported_at: Utc::now(),
        };
        s.set(loc);
        let got = s.get().unwrap();
        assert_eq!(got.lat, 37.7749);
        assert_eq!(got.lon, -122.4194);
        s.clear();
        assert!(s.get().is_none());
    }

    #[test]
    fn store_logs_and_falls_back_on_poisoned_lock() {
        // Regression test for the bug Devin Review flagged: every
        // `RwLock` access in this store silently swallowed
        // `PoisonError` via `.ok()`. A panic in the lost-mode
        // reporter holding the write lock would then suppress all
        // future heartbeat reads with no log output. The new
        // implementation logs `warn!` on poison and keeps the
        // best-effort fallback (`get` returns `None`, `set` /
        // `clear` drop the update).
        //
        // We can't easily assert the `warn!` event was emitted
        // here without pulling in `tracing-test`, but we can
        // assert the more important contract: the poison branch
        // does NOT panic and falls back to the safe value. A
        // future regression that replaced `match` with `.unwrap()`
        // would trip this test by panicking inside `get` / `set` /
        // `clear`.
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(LastKnownLocationStore::new());
        let seed = LastKnownLocation {
            lat: 1.0,
            lon: 2.0,
            accuracy_m: 3.0,
            reported_at: Utc::now(),
        };
        store.set(seed);

        // Poison the underlying RwLock by panicking inside a
        // write-locked thread. After `.join()` returns Err, the
        // lock is in the `PoisonError` state for every subsequent
        // read/write.
        let poison_handle = {
            let s = store.clone();
            thread::spawn(move || {
                let _w = s.inner.write().expect("acquire write");
                panic!("intentional poison for test");
            })
        };
        let join_result = poison_handle.join();
        assert!(
            join_result.is_err(),
            "panicking thread must propagate the panic to `join`"
        );

        // `get` must fall back to `None` without panicking. Note
        // that the previous (Some/seed) reading is NOT recovered —
        // poisoning is a one-way state and the safe fallback is
        // the empty value.
        assert!(
            store.get().is_none(),
            "get() on a poisoned lock must fall back to None"
        );

        // `set` and `clear` must not panic either; both drop the
        // update.
        store.set(LastKnownLocation {
            lat: 9.0,
            lon: 9.0,
            accuracy_m: 9.0,
            reported_at: Utc::now(),
        });
        store.clear();
    }

    #[test]
    fn last_known_location_round_trips_serde() {
        let loc = LastKnownLocation {
            lat: -33.8688,
            lon: 151.2093,
            accuracy_m: 100.0,
            reported_at: Utc::now(),
        };
        let s = serde_json::to_string(&loc).unwrap();
        let back: LastKnownLocation = serde_json::from_str(&s).unwrap();
        assert_eq!(back.lat, loc.lat);
        assert_eq!(back.lon, loc.lon);
        assert_eq!(back.accuracy_m, loc.accuracy_m);
    }
}
