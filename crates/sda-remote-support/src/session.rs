//! Remote-support session state machine.
//!
//! ```text
//! Pending ──▸ ConsentRequested ──▸ Active ──▸ Ended
//!                │                            ▲
//!                └─── (denied) ───────────────┘
//! ```

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// States a remote-support session can be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Session created but consent has not been requested yet.
    Pending,
    /// A consent banner has been shown to the end-user and we are
    /// waiting for their decision.
    ConsentRequested,
    /// The user accepted and the session is running.
    Active,
    /// The session has ended — either the user denied consent, the
    /// operator disconnected, the wall-clock cap expired, or an
    /// error occurred.
    Ended,
}

/// Reason why a session transitioned to [`SessionState::Ended`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    /// The end-user denied the consent prompt.
    ConsentDenied,
    /// The operator gracefully disconnected.
    OperatorDisconnect,
    /// The wall-clock cap expired.
    Timeout,
    /// An internal error terminated the session.
    Error(String),
}

/// In-memory representation of a single remote-support session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Agent-issued UUIDv4 session identifier.
    pub session_id: String,
    /// Opaque operator identifier (helpdesk agent, automation tag).
    pub operator_id: String,
    /// Current state of the session.
    pub state: SessionState,
    /// When the session record was first created.
    pub created_at: DateTime<Utc>,
    /// When the session transitioned to [`SessionState::Active`].
    /// `None` if the session never became active.
    pub started_at: Option<DateTime<Utc>>,
    /// When the session transitioned to [`SessionState::Ended`].
    /// `None` if the session is still ongoing.
    pub ended_at: Option<DateTime<Utc>>,
    /// Hard wall-clock cap on the session.
    pub max_duration: Duration,
    /// Why the session ended, if it has ended.
    pub end_reason: Option<EndReason>,
}

impl Session {
    /// Create a new session in [`SessionState::Pending`].
    pub fn new(session_id: String, operator_id: String, max_duration: Duration) -> Self {
        Self {
            session_id,
            operator_id,
            state: SessionState::Pending,
            created_at: Utc::now(),
            started_at: None,
            ended_at: None,
            max_duration,
            end_reason: None,
        }
    }

    /// Transition from `Pending` to `ConsentRequested`.
    pub fn request_consent(&mut self) -> Result<(), InvalidTransition> {
        if self.state != SessionState::Pending {
            return Err(InvalidTransition {
                from: self.state,
                to: SessionState::ConsentRequested,
            });
        }
        self.state = SessionState::ConsentRequested;
        Ok(())
    }

    /// Transition from `ConsentRequested` to `Active`.
    pub fn activate(&mut self) -> Result<(), InvalidTransition> {
        if self.state != SessionState::ConsentRequested {
            return Err(InvalidTransition {
                from: self.state,
                to: SessionState::Active,
            });
        }
        self.state = SessionState::Active;
        self.started_at = Some(Utc::now());
        Ok(())
    }

    /// Transition to `Ended` from any non-terminal state.
    pub fn end(&mut self, reason: EndReason) -> Result<(), InvalidTransition> {
        if self.state == SessionState::Ended {
            return Err(InvalidTransition {
                from: self.state,
                to: SessionState::Ended,
            });
        }
        self.state = SessionState::Ended;
        self.ended_at = Some(Utc::now());
        self.end_reason = Some(reason);
        Ok(())
    }

    /// Returns `true` when the session has been active for longer
    /// than `max_duration`.
    pub fn is_expired(&self) -> bool {
        if let Some(start) = self.started_at {
            Utc::now() - start >= self.max_duration
        } else {
            false
        }
    }

    /// Duration the session has been in the `Active` state (or
    /// total active duration if already ended).
    pub fn active_duration(&self) -> Option<Duration> {
        let start = self.started_at?;
        let end = self.ended_at.unwrap_or_else(Utc::now);
        Some(end - start)
    }
}

/// Error returned when a state-machine transition is illegal.
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid session transition: {from:?} → {to:?}")]
pub struct InvalidTransition {
    pub from: SessionState,
    pub to: SessionState,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session() -> Session {
        Session::new(
            "sess-1".into(),
            "ops@example.com".into(),
            Duration::minutes(30),
        )
    }

    #[test]
    fn happy_path_pending_to_consent_to_active_to_ended() {
        let mut s = make_session();
        assert_eq!(s.state, SessionState::Pending);
        s.request_consent().unwrap();
        assert_eq!(s.state, SessionState::ConsentRequested);
        s.activate().unwrap();
        assert_eq!(s.state, SessionState::Active);
        assert!(s.started_at.is_some());
        s.end(EndReason::OperatorDisconnect).unwrap();
        assert_eq!(s.state, SessionState::Ended);
        assert!(s.ended_at.is_some());
        assert!(s.active_duration().is_some());
    }

    #[test]
    fn consent_denied_ends_session_directly() {
        let mut s = make_session();
        s.request_consent().unwrap();
        s.end(EndReason::ConsentDenied).unwrap();
        assert_eq!(s.state, SessionState::Ended);
        assert!(s.started_at.is_none());
    }

    #[test]
    fn double_end_is_illegal() {
        let mut s = make_session();
        s.request_consent().unwrap();
        s.end(EndReason::ConsentDenied).unwrap();
        assert!(s.end(EndReason::Timeout).is_err());
    }

    #[test]
    fn activate_from_pending_is_illegal() {
        let mut s = make_session();
        assert!(s.activate().is_err());
    }

    #[test]
    fn request_consent_from_active_is_illegal() {
        let mut s = make_session();
        s.request_consent().unwrap();
        s.activate().unwrap();
        assert!(s.request_consent().is_err());
    }

    #[test]
    fn is_expired_false_for_pending_session() {
        let s = make_session();
        assert!(!s.is_expired());
    }

    #[test]
    fn session_round_trips_through_json() {
        let s = make_session();
        let json = serde_json::to_string(&s).expect("encode");
        let back: Session = serde_json::from_str(&json).expect("decode");
        assert_eq!(s.session_id, back.session_id);
        assert_eq!(s.state, back.state);
    }

    #[test]
    fn state_round_trips_through_json() {
        for state in [
            SessionState::Pending,
            SessionState::ConsentRequested,
            SessionState::Active,
            SessionState::Ended,
        ] {
            let json = serde_json::to_string(&state).expect("encode");
            let back: SessionState = serde_json::from_str(&json).expect("decode");
            assert_eq!(state, back);
        }
    }

    #[test]
    fn end_reason_round_trips_through_json() {
        for reason in [
            EndReason::ConsentDenied,
            EndReason::OperatorDisconnect,
            EndReason::Timeout,
            EndReason::Error("boom".into()),
        ] {
            let json = serde_json::to_string(&reason).expect("encode");
            let back: EndReason = serde_json::from_str(&json).expect("decode");
            assert_eq!(reason, back);
        }
    }
}
