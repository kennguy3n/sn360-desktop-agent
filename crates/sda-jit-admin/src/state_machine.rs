//! Pure-logic state machine for [`GrantRecord`] lifecycles.
//!
//! The machine is intentionally split out from the supervisor task
//! and the disk store so it can be unit-tested without spinning up
//! Tokio. All transitions go through [`StateMachine::apply`] which
//! validates the source/target pair against the matrix below.
//!
//! ```text
//!     Requested ──approve───▶ Approved ──grant───▶ Granted ──revoke───▶ Revoked
//!         │                                            │
//!         └──deny──▶ Denied                            ├──expire──▶ Expired
//!                                                      └──drift───▶ DriftDetected
//! ```
//!
//! See `docs/device-control/PROPOSAL.md` § 9.3 for the canonical
//! diagram.

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::grant::{GrantRecord, GrantState};

/// One concrete transition the supervisor wants to apply.
#[derive(Debug, Clone)]
pub enum StateTransition {
    /// Server approved the request.
    Approve { reason: Option<String> },
    /// Server denied the request — terminal.
    Deny { reason: Option<String> },
    /// Agent successfully granted the OS-level privilege.
    Grant {
        handle: sda_pal::admin_manager::GrantHandle,
        reason: Option<String>,
    },
    /// Watchdog or operator decided to revoke the grant.
    Revoke {
        reason: crate::watchdog::RevocationReason,
    },
    /// `grant.until` passed — record terminal expiry.
    Expire,
    /// Agent observed an unauthorized admin account; force-revoke.
    DriftDetected { detail: Option<String> },
}

impl StateTransition {
    /// Compact tag suitable for evidence payloads / logs.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Approve { .. } => "approve",
            Self::Deny { .. } => "deny",
            Self::Grant { .. } => "grant",
            Self::Revoke { .. } => "revoke",
            Self::Expire => "expire",
            Self::DriftDetected { .. } => "drift_detected",
        }
    }
}

/// Rejection reasons the state machine reports.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransitionError {
    /// The target state is not reachable from the current one.
    #[error("invalid transition {from:?} → {to:?}")]
    Invalid { from: GrantState, to: GrantState },
    /// The record is already in a terminal state.
    #[error("record is in terminal state {0:?}")]
    Terminal(GrantState),
}

/// The state machine itself. Stateless — every call takes the
/// current record and returns the new one.
#[derive(Debug, Clone, Default)]
pub struct StateMachine;

impl StateMachine {
    /// Validate `transition` against `record` and return the new
    /// record on success.
    ///
    /// Mutations are non-destructive — the returned record is a
    /// fresh `GrantRecord` so callers can keep the previous one for
    /// audit / rollback purposes.
    pub fn apply(
        &self,
        record: &GrantRecord,
        transition: StateTransition,
        now: DateTime<Utc>,
    ) -> Result<GrantRecord, TransitionError> {
        if record.state.is_terminal() {
            return Err(TransitionError::Terminal(record.state));
        }

        let target = match (record.state, &transition) {
            (GrantState::Requested, StateTransition::Approve { .. }) => GrantState::Approved,
            (GrantState::Requested, StateTransition::Deny { .. }) => GrantState::Denied,
            (GrantState::Approved, StateTransition::Grant { .. }) => GrantState::Granted,
            (GrantState::Granted, StateTransition::Revoke { .. }) => GrantState::Revoked,
            (GrantState::Granted, StateTransition::Expire) => GrantState::Expired,
            (GrantState::Granted, StateTransition::DriftDetected { .. }) => {
                GrantState::DriftDetected
            }
            // Drift on a request that was approved but never made it
            // to grant is also fatal — the device's admin set has
            // diverged from the agent's view.
            (GrantState::Approved, StateTransition::DriftDetected { .. }) => {
                GrantState::DriftDetected
            }
            // Boot-time and supervisory expiry — when a request or
            // approval has aged past its `until` boundary without
            // ever being grant-finalised, finalise it as `Expired`.
            // No OS-level privilege was ever active, so `Revoke` is
            // semantically wrong here.
            (GrantState::Requested, StateTransition::Expire)
            | (GrantState::Approved, StateTransition::Expire) => GrantState::Expired,
            (from, _) => {
                return Err(TransitionError::Invalid {
                    from,
                    to: target_for(&transition),
                });
            }
        };

        let mut next = record.clone();
        next.state = target;
        next.last_transition_at = now;
        next.last_reason = transition_reason(&transition);
        if let StateTransition::Grant { handle, .. } = &transition {
            next.handle = Some(handle.clone());
        }
        Ok(next)
    }
}

fn target_for(t: &StateTransition) -> GrantState {
    match t {
        StateTransition::Approve { .. } => GrantState::Approved,
        StateTransition::Deny { .. } => GrantState::Denied,
        StateTransition::Grant { .. } => GrantState::Granted,
        StateTransition::Revoke { .. } => GrantState::Revoked,
        StateTransition::Expire => GrantState::Expired,
        StateTransition::DriftDetected { .. } => GrantState::DriftDetected,
    }
}

fn transition_reason(t: &StateTransition) -> Option<String> {
    /// Hard cap on stored reason length so a misbehaving server
    /// cannot pump the on-disk ledger full of garbage.
    ///
    /// The cap is measured in Unicode scalar values (chars), not
    /// bytes. Slicing a `String` at an arbitrary byte offset would
    /// panic when the cut falls inside a multi-byte UTF-8 sequence
    /// (CJK, emoji, accented Latin, …); the control-plane reason
    /// strings are not sanitised before they reach this layer.
    const MAX_REASON_CHARS: usize = 256;

    let raw = match t {
        StateTransition::Approve { reason } | StateTransition::Deny { reason } => reason.clone(),
        StateTransition::Grant { reason, .. } => reason.clone(),
        StateTransition::Revoke { reason } => Some(reason.as_str().to_string()),
        StateTransition::Expire => Some("expire".to_string()),
        StateTransition::DriftDetected { detail } => Some(
            detail
                .clone()
                .unwrap_or_else(|| "drift_detected".to_string()),
        ),
    };
    raw.map(|s| {
        if s.chars().count() > MAX_REASON_CHARS {
            let truncated: String = s.chars().take(MAX_REASON_CHARS).collect();
            format!("{truncated}…")
        } else {
            s
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watchdog::RevocationReason;
    use sda_pal::admin_manager::{GrantHandle, UserRef};

    fn user() -> UserRef {
        UserRef {
            username: "alice".into(),
            domain: None,
        }
    }

    fn handle(id: &str) -> GrantHandle {
        GrantHandle {
            id: id.into(),
            user: user(),
            until: Utc::now(),
        }
    }

    fn fresh() -> GrantRecord {
        let now = Utc::now();
        GrantRecord::new_requested("g-1", "ops", user(), now + chrono::Duration::hours(1), now)
    }

    #[test]
    fn happy_path_request_to_revoke() {
        let sm = StateMachine;
        let r0 = fresh();
        let now = Utc::now();

        let r1 = sm
            .apply(&r0, StateTransition::Approve { reason: None }, now)
            .unwrap();
        assert_eq!(r1.state, GrantState::Approved);

        let r2 = sm
            .apply(
                &r1,
                StateTransition::Grant {
                    handle: handle("h-1"),
                    reason: None,
                },
                now,
            )
            .unwrap();
        assert_eq!(r2.state, GrantState::Granted);
        assert_eq!(r2.handle.as_ref().unwrap().id, "h-1");

        let r3 = sm
            .apply(
                &r2,
                StateTransition::Revoke {
                    reason: RevocationReason::Timer,
                },
                now,
            )
            .unwrap();
        assert_eq!(r3.state, GrantState::Revoked);
        assert!(r3.state.is_terminal());
    }

    #[test]
    fn deny_from_requested() {
        let sm = StateMachine;
        let r0 = fresh();
        let r1 = sm
            .apply(
                &r0,
                StateTransition::Deny {
                    reason: Some("policy violation".into()),
                },
                Utc::now(),
            )
            .unwrap();
        assert_eq!(r1.state, GrantState::Denied);
        assert!(r1.state.is_terminal());
        assert_eq!(r1.last_reason.as_deref(), Some("policy violation"));
    }

    #[test]
    fn cannot_grant_directly_from_requested() {
        let sm = StateMachine;
        let r0 = fresh();
        let err = sm
            .apply(
                &r0,
                StateTransition::Grant {
                    handle: handle("h-1"),
                    reason: None,
                },
                Utc::now(),
            )
            .expect_err("must be rejected");
        assert!(matches!(err, TransitionError::Invalid { .. }), "{err:?}");
    }

    #[test]
    fn terminal_record_rejects_further_transitions() {
        let sm = StateMachine;
        let r0 = fresh();
        let r1 = sm
            .apply(&r0, StateTransition::Deny { reason: None }, Utc::now())
            .unwrap();
        let err = sm
            .apply(&r1, StateTransition::Approve { reason: None }, Utc::now())
            .expect_err("denied → approved must fail");
        assert!(matches!(err, TransitionError::Terminal(_)), "{err:?}");
    }

    #[test]
    fn drift_from_granted_is_terminal() {
        let sm = StateMachine;
        let mut r = fresh();
        r.state = GrantState::Granted;
        let r2 = sm
            .apply(
                &r,
                StateTransition::DriftDetected {
                    detail: Some("unauthorized account: bob".into()),
                },
                Utc::now(),
            )
            .unwrap();
        assert_eq!(r2.state, GrantState::DriftDetected);
        assert_eq!(r2.last_reason.as_deref(), Some("unauthorized account: bob"));
    }

    #[test]
    fn long_reason_strings_are_truncated() {
        let sm = StateMachine;
        let r = fresh();
        let big = "x".repeat(1024);
        let r2 = sm
            .apply(
                &r,
                StateTransition::Deny {
                    reason: Some(big.clone()),
                },
                Utc::now(),
            )
            .unwrap();
        let stored = r2.last_reason.as_deref().unwrap();
        assert!(stored.len() < big.len(), "must be truncated");
        assert!(stored.ends_with('…'));
        assert_eq!(stored.chars().count(), 257, "256 chars + ellipsis");
    }

    /// Regression — `transition_reason` used to slice the reason
    /// `String` at byte offset 256, which panics whenever the cut
    /// falls inside a multi-byte UTF-8 sequence. The control plane
    /// is allowed to send arbitrary text, so this must never panic.
    #[test]
    fn multibyte_reason_strings_truncate_without_panicking() {
        let sm = StateMachine;
        let r = fresh();
        // Each "汉" is three bytes — 1024 chars = 3072 bytes, so
        // the byte cut at 256 lands inside a code point.
        let big = "汉".repeat(1024);
        let r2 = sm
            .apply(
                &r,
                StateTransition::Deny {
                    reason: Some(big.clone()),
                },
                Utc::now(),
            )
            .expect("must not panic on multi-byte truncation");
        let stored = r2.last_reason.as_deref().unwrap();
        assert!(stored.ends_with('…'));
        assert_eq!(stored.chars().count(), 257, "256 chars + ellipsis");
    }

    /// Boot-sweep finalisation paths. The supervisor's boot sweep
    /// hits records that are still in `Requested` or `Approved`
    /// when their `until` has passed. The state machine must accept
    /// `Expire` from those states so the ledger can move them to
    /// `Expired` instead of leaving them as permanent non-terminal
    /// stragglers.
    #[test]
    fn expire_finalises_requested_records() {
        let sm = StateMachine;
        let r = fresh();
        assert_eq!(r.state, GrantState::Requested);
        let r2 = sm
            .apply(&r, StateTransition::Expire, Utc::now())
            .expect("Requested → Expired must be accepted");
        assert_eq!(r2.state, GrantState::Expired);
        assert!(r2.state.is_terminal());
        assert_eq!(r2.last_reason.as_deref(), Some("expire"));
    }

    #[test]
    fn expire_finalises_approved_records() {
        let sm = StateMachine;
        let mut r = fresh();
        r.state = GrantState::Approved;
        let r2 = sm
            .apply(&r, StateTransition::Expire, Utc::now())
            .expect("Approved → Expired must be accepted");
        assert_eq!(r2.state, GrantState::Expired);
        assert!(r2.state.is_terminal());
    }

    #[test]
    fn revoke_still_rejected_from_non_granted_states() {
        // The matrix extension intentionally only adds Expire from
        // Requested/Approved — Revoke remains restricted to
        // Granted, since "revoke" implies an active OS-level
        // privilege we need to drop.
        use crate::watchdog::RevocationReason;
        let sm = StateMachine;
        let r0 = fresh();
        let err = sm
            .apply(
                &r0,
                StateTransition::Revoke {
                    reason: RevocationReason::BootSweep,
                },
                Utc::now(),
            )
            .expect_err("Requested → Revoked must still be rejected");
        assert!(matches!(err, TransitionError::Invalid { .. }));

        let mut r1 = fresh();
        r1.state = GrantState::Approved;
        let err = sm
            .apply(
                &r1,
                StateTransition::Revoke {
                    reason: RevocationReason::BootSweep,
                },
                Utc::now(),
            )
            .expect_err("Approved → Revoked must still be rejected");
        assert!(matches!(err, TransitionError::Invalid { .. }));
    }
}
