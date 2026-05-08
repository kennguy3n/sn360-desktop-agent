//! User-consent gate for remote-support sessions.
//!
//! PROPOSAL.md § 9.7 mandates that **every** remote-support session
//! show a consent banner and block until the end-user accepts. This
//! module owns that gate. Phase 4 ships:
//!
//! * [`ConsentManager`] — the orchestration surface; takes a
//!   pluggable [`ConsentPrompt`] so production code can wire it to a
//!   real desktop UI while tests use [`AutoApproveConsentPrompt`] /
//!   [`AutoDenyConsentPrompt`].
//! * [`ConsentDecision`] — the outcome of a single prompt. Captured
//!   verbatim in evidence / audit records.
//!
//! The Phase-4 default prompt — [`StubConsentPrompt`] — denies every
//! request, matching the agent's fail-closed posture: if the
//! operator wires a `RemoteSupportModule` without supplying a real
//! prompt, no remote-support session ever activates.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Outcome of a single consent prompt.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentDecision {
    /// User accepted the prompt; the session may proceed.
    Approved,
    /// User actively dismissed / refused the prompt.
    Denied,
    /// The prompt timed out before the user responded.
    TimedOut,
}

/// Pluggable surface for asking the user whether a session may
/// proceed.
///
/// Implementations MUST be `Send + Sync` because the supervisor
/// holds them in a `Box<dyn ConsentPrompt>`. The Phase-4 default
/// is [`StubConsentPrompt`]; real implementations will land in
/// later phases (one per OS, wired into the desktop notification
/// surface).
pub trait ConsentPrompt: Send + Sync {
    /// Show a prompt for `operator_id` and `session_id` and block
    /// until the user responds (or the implementation's internal
    /// timeout elapses).
    fn ask(&self, session_id: &str, operator_id: &str) -> ConsentDecision;
}

/// Phase-4 default prompt: deny every request.
///
/// Used when the operator has wired a `RemoteSupportModule` but
/// has not yet supplied a real desktop UI surface. Failing closed
/// here matches the agent's privacy-first posture.
#[derive(Debug, Default)]
pub struct StubConsentPrompt;

impl ConsentPrompt for StubConsentPrompt {
    fn ask(&self, _session_id: &str, _operator_id: &str) -> ConsentDecision {
        ConsentDecision::Denied
    }
}

/// Test helper: always approve. Not exposed in production builds.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct AutoApproveConsentPrompt;

#[cfg(test)]
impl ConsentPrompt for AutoApproveConsentPrompt {
    fn ask(&self, _session_id: &str, _operator_id: &str) -> ConsentDecision {
        ConsentDecision::Approved
    }
}

/// Test helper: always deny. Not exposed in production builds.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct AutoDenyConsentPrompt;

#[cfg(test)]
impl ConsentPrompt for AutoDenyConsentPrompt {
    fn ask(&self, _session_id: &str, _operator_id: &str) -> ConsentDecision {
        ConsentDecision::Denied
    }
}

/// Audit record for a single consent prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub session_id: String,
    pub operator_id: String,
    pub decision: ConsentDecision,
    pub asked_at: DateTime<Utc>,
}

/// Stateful consent orchestrator.
///
/// Wraps a [`ConsentPrompt`] and records every decision in an
/// in-memory audit list so the supervisor can include the full
/// chain of prompts in evidence records.
pub struct ConsentManager {
    prompt: Box<dyn ConsentPrompt>,
    history: Vec<ConsentRecord>,
}

impl std::fmt::Debug for ConsentManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentManager")
            .field("history_len", &self.history.len())
            .finish()
    }
}

impl ConsentManager {
    /// Build a manager backed by `prompt`.
    pub fn new(prompt: Box<dyn ConsentPrompt>) -> Self {
        Self {
            prompt,
            history: Vec::new(),
        }
    }

    /// Build a manager backed by [`StubConsentPrompt`] (deny-all).
    pub fn deny_all() -> Self {
        Self::new(Box::new(StubConsentPrompt))
    }

    /// Show a prompt and record the decision.
    pub fn ask(&mut self, session_id: &str, operator_id: &str) -> ConsentDecision {
        let decision = self.prompt.ask(session_id, operator_id);
        self.history.push(ConsentRecord {
            session_id: session_id.into(),
            operator_id: operator_id.into(),
            decision: decision.clone(),
            asked_at: Utc::now(),
        });
        decision
    }

    /// Read-only view of all decisions recorded so far. Useful for
    /// evidence emission.
    pub fn history(&self) -> &[ConsentRecord] {
        &self.history
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_prompt_always_denies() {
        let p = StubConsentPrompt;
        assert_eq!(p.ask("s", "o"), ConsentDecision::Denied);
    }

    #[test]
    fn auto_approve_helper_approves() {
        let p = AutoApproveConsentPrompt;
        assert_eq!(p.ask("s", "o"), ConsentDecision::Approved);
    }

    #[test]
    fn auto_deny_helper_denies() {
        let p = AutoDenyConsentPrompt;
        assert_eq!(p.ask("s", "o"), ConsentDecision::Denied);
    }

    #[test]
    fn manager_records_each_decision() {
        let mut m = ConsentManager::new(Box::new(AutoApproveConsentPrompt));
        let d1 = m.ask("s1", "op@example.com");
        let d2 = m.ask("s2", "op@example.com");
        assert_eq!(d1, ConsentDecision::Approved);
        assert_eq!(d2, ConsentDecision::Approved);
        assert_eq!(m.history().len(), 2);
        assert_eq!(m.history()[0].session_id, "s1");
        assert_eq!(m.history()[1].session_id, "s2");
    }

    #[test]
    fn deny_all_factory_uses_stub_prompt() {
        let mut m = ConsentManager::deny_all();
        assert_eq!(m.ask("s", "o"), ConsentDecision::Denied);
    }

    #[test]
    fn decision_round_trips_through_json() {
        for d in [
            ConsentDecision::Approved,
            ConsentDecision::Denied,
            ConsentDecision::TimedOut,
        ] {
            let json = serde_json::to_string(&d).expect("encode");
            let back: ConsentDecision = serde_json::from_str(&json).expect("decode");
            assert_eq!(d, back);
        }
    }

    #[test]
    fn record_round_trips_through_json() {
        let r = ConsentRecord {
            session_id: "s".into(),
            operator_id: "o".into(),
            decision: ConsentDecision::Approved,
            asked_at: Utc::now(),
        };
        let json = serde_json::to_string(&r).expect("encode");
        let back: ConsentRecord = serde_json::from_str(&json).expect("decode");
        assert_eq!(r, back);
    }
}
