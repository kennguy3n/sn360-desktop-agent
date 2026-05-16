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
    pub fn get(&self) -> Option<LastKnownLocation> {
        self.inner.read().ok().and_then(|g| *g)
    }

    /// Overwrite the stored location.
    pub fn set(&self, loc: LastKnownLocation) {
        if let Ok(mut g) = self.inner.write() {
            *g = Some(loc);
        }
    }

    /// Drop the stored location (used when exiting lost mode if the
    /// caller wants to stop reporting). Most callers leave the last
    /// reading in place so a stale-but-useful position can still be
    /// surfaced after exit.
    pub fn clear(&self) {
        if let Ok(mut g) = self.inner.write() {
            *g = None;
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
