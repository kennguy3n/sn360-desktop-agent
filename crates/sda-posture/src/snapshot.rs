//! Periodic device-posture snapshot loop.
//!
//! The Posture module asks the [`DevicePostureProvider`] PAL trait
//! for a [`PostureSnapshot`] every `modules.posture.interval_secs`
//! seconds and emits an `EventKind::DevicePostureState` *only when
//! the snapshot has changed*. That delta filter keeps idle traffic
//! at zero between actual host changes — the bus carries one event
//! per real disk-encryption / firewall / screen-lock change and
//! nothing else.
//!
//! On battery (or any [`PowerProfile`] whose `posture_enabled()`
//! returns `false`) the supervisor defers the next snapshot to the
//! next AC tick. This is the same pattern the FIM and rootcheck
//! modules use for power-aware scheduling.

use chrono::{DateTime, Utc};
use sda_core::PowerProfile;
use sda_pal::posture::PostureSnapshot;
use serde::{Deserialize, Serialize};

/// JSON payload emitted on `EventKind::DevicePostureState`.
///
/// We wrap the `PostureSnapshot` in a small envelope so consumers
/// can tell *when* the snapshot was taken without rummaging through
/// the event metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PosturePayload {
    pub captured_at: DateTime<Utc>,
    pub snapshot: PostureSnapshot,
}

/// Decision returned by [`DeltaTracker::observe`].
///
/// `Emit` means the supervisor should publish the snapshot on the
/// bus; `Skip` means the snapshot is identical to the last one
/// observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaDecision {
    /// First snapshot ever, or the snapshot has changed since the
    /// previous one.
    Emit,
    /// Snapshot is bit-for-bit identical to the previously-observed
    /// snapshot — nothing to publish.
    Skip,
}

/// Holds the most-recently-seen [`PostureSnapshot`] so the
/// supervisor can decide whether the *next* snapshot is a delta.
#[derive(Debug, Default, Clone)]
pub struct DeltaTracker {
    last: Option<PostureSnapshot>,
}

impl DeltaTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the previous snapshot (without consuming the
    /// tracker). Useful in tests.
    pub fn last(&self) -> Option<&PostureSnapshot> {
        self.last.as_ref()
    }

    /// Compare `next` to the stored snapshot. If it differs (or no
    /// snapshot has been observed yet), record `next` as the new
    /// baseline and return `DeltaDecision::Emit`. Otherwise return
    /// `DeltaDecision::Skip`.
    pub fn observe(&mut self, next: PostureSnapshot) -> DeltaDecision {
        match &self.last {
            Some(prev) if prev == &next => DeltaDecision::Skip,
            _ => {
                self.last = Some(next);
                DeltaDecision::Emit
            }
        }
    }
}

/// Power-aware deferral: returns `true` iff the supervisor should
/// take a snapshot at the next tick under `profile`.
///
/// We only ever skip on `BatteryActive`, `BatteryIdle`, and
/// `CriticalBattery`. AC and `IdleAC` always run snapshots.
pub fn should_snapshot(profile: PowerProfile) -> bool {
    matches!(profile, PowerProfile::Normal | PowerProfile::IdleAC)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(disk: bool, fw: bool, lock: bool) -> PostureSnapshot {
        use sda_pal::posture::{PostureSnapshot, PostureToggle};
        PostureSnapshot {
            disk_encryption: if disk {
                PostureToggle::On
            } else {
                PostureToggle::Off
            },
            firewall_enabled: if fw {
                PostureToggle::On
            } else {
                PostureToggle::Off
            },
            screen_lock_enabled: if lock {
                PostureToggle::On
            } else {
                PostureToggle::Off
            },
            os_patch_level: Some("2026-04".into()),
            os_version: Some("24.04".into()),
        }
    }

    #[test]
    fn delta_tracker_first_snapshot_emits() {
        let mut t = DeltaTracker::new();
        assert_eq!(t.observe(snap(true, true, true)), DeltaDecision::Emit);
        assert!(t.last().is_some());
    }

    #[test]
    fn delta_tracker_identical_snapshot_skips() {
        let mut t = DeltaTracker::new();
        let s = snap(true, true, true);
        assert_eq!(t.observe(s.clone()), DeltaDecision::Emit);
        assert_eq!(t.observe(s), DeltaDecision::Skip);
    }

    #[test]
    fn delta_tracker_changed_snapshot_emits() {
        let mut t = DeltaTracker::new();
        assert_eq!(t.observe(snap(true, true, true)), DeltaDecision::Emit);
        // Disk encryption flipped off — must emit a new event.
        assert_eq!(t.observe(snap(false, true, true)), DeltaDecision::Emit);
        // …and emit again when it flips back on.
        assert_eq!(t.observe(snap(true, true, true)), DeltaDecision::Emit);
    }

    #[test]
    fn delta_tracker_handles_partial_change() {
        let mut t = DeltaTracker::new();
        let mut s = snap(true, true, true);
        s.os_patch_level = Some("2026-04".into());
        assert_eq!(t.observe(s.clone()), DeltaDecision::Emit);
        s.os_patch_level = Some("2026-05".into());
        assert_eq!(t.observe(s), DeltaDecision::Emit);
    }

    #[test]
    fn payload_round_trips_through_serde() {
        let p = PosturePayload {
            captured_at: chrono::Utc::now(),
            snapshot: snap(true, true, true),
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: PosturePayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn payload_rejects_unknown_field() {
        let raw = r#"{
            "captured_at": "2026-05-07T08:30:00Z",
            "snapshot": {
                "disk_encryption": "on",
                "firewall_enabled": "on",
                "screen_lock_enabled": "on",
                "os_patch_level": null,
                "os_version": "24.04"
            },
            "extra": 1
        }"#;
        // Note: PostureSnapshot itself is defined in sda-pal
        // without #[serde(deny_unknown_fields)], so unknown
        // fields *inside* `snapshot` would be silently ignored.
        // The deny applies only to the envelope's top-level keys,
        // which is what this test exercises.
        assert!(serde_json::from_str::<PosturePayload>(raw).is_err());
    }

    #[test]
    fn power_aware_should_snapshot_on_ac() {
        assert!(should_snapshot(PowerProfile::Normal));
        assert!(should_snapshot(PowerProfile::IdleAC));
    }

    #[test]
    fn power_aware_skips_on_battery() {
        assert!(!should_snapshot(PowerProfile::BatteryActive));
        assert!(!should_snapshot(PowerProfile::BatteryIdle));
        assert!(!should_snapshot(PowerProfile::CriticalBattery));
    }
}
