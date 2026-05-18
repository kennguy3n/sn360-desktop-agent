//! `GrantRecord` and friends — the persistent representation of a
//! JIT-admin grant on the agent.
//!
//! See `docs/device-control.md` § 7 (Just-in-Time admin — state
//! machine) and `docs/wire-protocols/device-control.md` § 8
//! (wire payload).

use chrono::{DateTime, Utc};
use sda_pal::admin_manager::{GrantHandle, UserRef};
use serde::{Deserialize, Serialize};

/// Lifecycle state of a [`GrantRecord`].
///
/// State transitions are owned by [`crate::StateMachine`]. Terminal
/// states ([`GrantState::Revoked`], [`GrantState::Expired`],
/// [`GrantState::Denied`], [`GrantState::DriftDetected`]) are
/// retained in the ledger so the audit trail can prove an outcome,
/// but they accept no further transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    /// Server received the request but has not yet decided.
    Requested,
    /// Server approved; agent has not yet called `grant_admin`.
    Approved,
    /// Agent successfully called `grant_admin`; the privilege is
    /// active on the device.
    Granted,
    /// Server denied the request — terminal.
    Denied,
    /// Privilege was successfully revoked — terminal.
    Revoked,
    /// `grant.until` passed without the watchdog firing in time —
    /// terminal. Distinguished from `Revoked` so the audit chain can
    /// show that the revocation happened *after* the formal expiry.
    Expired,
    /// Agent observed an admin-account that is not in the local
    /// ledger (drift). Terminal — the grant is force-revoked and the
    /// device is flagged.
    DriftDetected,
}

impl GrantState {
    /// `true` iff this state is terminal — no further transitions
    /// are permitted.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Denied | Self::Revoked | Self::Expired | Self::DriftDetected
        )
    }

    /// `true` iff the OS-level privilege is currently active.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Granted)
    }

    /// Lower-snake-case label suitable for evidence payloads.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Approved => "approved",
            Self::Granted => "granted",
            Self::Denied => "denied",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::DriftDetected => "drift_detected",
        }
    }
}

/// A single tracked JIT-admin lifecycle from request to terminal
/// state.
///
/// Records are stored on disk by [`crate::store::GrantStore`] so
/// they survive agent restarts. The struct is split deliberately
/// from [`sda_pal::admin_manager::GrantHandle`] — `GrantHandle` is
/// the OS-level handle (filename, ledger id) and `GrantRecord` is
/// the auditable lifecycle record (state, transitions, evidence
/// references).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRecord {
    /// Server-issued grant id (unique per request, used to correlate
    /// with the control plane's grant ledger).
    pub id: String,
    /// Operator/server actor who initiated the request, used by the
    /// audit trail.
    pub requested_by: String,
    /// Target user account.
    pub user: UserRef,
    /// Wall-clock UTC time after which the grant must be revoked.
    pub until: DateTime<Utc>,
    /// Current lifecycle state.
    pub state: GrantState,
    /// When the request first reached the agent.
    pub requested_at: DateTime<Utc>,
    /// When the agent last transitioned this record. Equal to
    /// `requested_at` for fresh requests.
    pub last_transition_at: DateTime<Utc>,
    /// Set once the underlying `AdminManager` returns a
    /// [`GrantHandle`]. Stays `None` for [`GrantState::Requested`],
    /// [`GrantState::Approved`], and [`GrantState::Denied`].
    #[serde(default)]
    pub handle: Option<GrantHandle>,
    /// Human-readable reason for the most recent transition. The
    /// state machine populates this on every move so the operator
    /// can read the audit trail without cross-referencing event
    /// payloads. Free-form, capped at 256 chars by the state
    /// machine.
    #[serde(default)]
    pub last_reason: Option<String>,
    /// Evidence record IDs emitted during this grant's lifecycle, in
    /// emission order. The state machine appends to this list on
    /// every transition so the audit chain is reconstructible from
    /// the persisted ledger alone.
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

impl GrantRecord {
    /// Construct a fresh `Requested` record.
    pub fn new_requested(
        id: impl Into<String>,
        requested_by: impl Into<String>,
        user: UserRef,
        until: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            id: id.into(),
            requested_by: requested_by.into(),
            user,
            until,
            state: GrantState::Requested,
            requested_at: now,
            last_transition_at: now,
            handle: None,
            last_reason: Some("requested".into()),
            evidence_ids: Vec::new(),
        }
    }

    /// `true` iff `now >= self.until` and the privilege is still
    /// active on the device.
    pub fn is_overdue(&self, now: DateTime<Utc>) -> bool {
        self.state.is_active() && now >= self.until
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str) -> UserRef {
        UserRef {
            username: name.into(),
            domain: None,
        }
    }

    #[test]
    fn terminal_states_are_terminal() {
        assert!(GrantState::Denied.is_terminal());
        assert!(GrantState::Revoked.is_terminal());
        assert!(GrantState::Expired.is_terminal());
        assert!(GrantState::DriftDetected.is_terminal());
        assert!(!GrantState::Requested.is_terminal());
        assert!(!GrantState::Approved.is_terminal());
        assert!(!GrantState::Granted.is_terminal());
    }

    #[test]
    fn only_granted_is_active() {
        assert!(GrantState::Granted.is_active());
        for s in [
            GrantState::Requested,
            GrantState::Approved,
            GrantState::Denied,
            GrantState::Revoked,
            GrantState::Expired,
            GrantState::DriftDetected,
        ] {
            assert!(!s.is_active(), "{s:?} should not be active");
        }
    }

    #[test]
    fn new_requested_initialises_audit_fields() {
        let now = Utc::now();
        let until = now + chrono::Duration::hours(1);
        let r = GrantRecord::new_requested("g-1", "alice@server", user("bob"), until, now);
        assert_eq!(r.state, GrantState::Requested);
        assert_eq!(r.requested_at, now);
        assert_eq!(r.last_transition_at, now);
        assert!(r.handle.is_none());
        assert_eq!(r.evidence_ids, Vec::<String>::new());
        assert_eq!(r.last_reason.as_deref(), Some("requested"));
    }

    #[test]
    fn is_overdue_only_when_granted_and_past_expiry() {
        let now = Utc::now();
        let mut r = GrantRecord::new_requested(
            "g-2",
            "ops",
            user("bob"),
            now + chrono::Duration::seconds(30),
            now,
        );
        // Requested + before expiry → not overdue.
        assert!(!r.is_overdue(now));
        // Granted + past expiry → overdue.
        r.state = GrantState::Granted;
        assert!(r.is_overdue(now + chrono::Duration::seconds(60)));
        // Already revoked → not overdue (terminal).
        r.state = GrantState::Revoked;
        assert!(!r.is_overdue(now + chrono::Duration::seconds(60)));
    }

    #[test]
    fn grant_state_round_trips_through_json() {
        for s in [
            GrantState::Requested,
            GrantState::Approved,
            GrantState::Granted,
            GrantState::Denied,
            GrantState::Revoked,
            GrantState::Expired,
            GrantState::DriftDetected,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: GrantState = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back, "{s:?} did not round-trip");
            assert!(json.contains(s.as_str()), "{json} missing {s:?} label");
        }
    }
}
