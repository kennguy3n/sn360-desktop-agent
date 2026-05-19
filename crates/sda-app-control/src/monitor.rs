//! Monitor mode: log-only allow / deny decisions.
//!
//! In monitor mode the agent never blocks a binary. It records a
//! [`Decision`] for every observation so the operator can review
//! what *would* have happened in enforce mode. This is the
//! Default per `docs/device-control.md` § 8.

use chrono::{DateTime, Utc};
use sda_pal::app_control::AppControlRule;
use serde::{Deserialize, Serialize};

use crate::policy::{canonical_rule_hash, VerifiedPolicy};

/// One observation recorded by [`MonitorController::observe`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// Subject of the binary observed (sha256, team_id, path, …).
    pub subject: String,
    /// `true` if a matching rule allows the binary, `false` if a
    /// matching rule denies it. `None` if no rule matched (the
    /// binary was unknown).
    pub matched_allow: Option<bool>,
    /// The rule hash that matched, if any.
    pub matched_rule_hash: Option<String>,
    /// Wall-clock time of the observation.
    pub observed_at: DateTime<Utc>,
}

/// Stateful monitor-mode controller.
///
/// Holds the currently-applied [`VerifiedPolicy`] and records every
/// observation. The supervisor reads `decisions()` to emit
/// `EventKind::AppControlDecision` events on the bus.
#[derive(Debug, Default)]
pub struct MonitorController {
    policy: Option<VerifiedPolicy>,
    decisions: Vec<Decision>,
}

impl MonitorController {
    /// Build a controller with no active policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the active policy. The previous policy and its
    /// decisions are dropped.
    pub fn install_policy(&mut self, policy: VerifiedPolicy) {
        self.policy = Some(policy);
        self.decisions.clear();
    }

    /// Whether a policy is currently installed.
    pub fn has_policy(&self) -> bool {
        self.policy.is_some()
    }

    /// Read-only access to the active policy.
    pub fn policy(&self) -> Option<&VerifiedPolicy> {
        self.policy.as_ref()
    }

    /// Observe a binary against the active policy. Returns the
    /// recorded [`Decision`] (also appended to the internal log).
    pub fn observe(&mut self, subject: impl Into<String>) -> Decision {
        let subject = subject.into();
        let mut decision = Decision {
            subject: subject.clone(),
            matched_allow: None,
            matched_rule_hash: None,
            observed_at: Utc::now(),
        };
        if let Some(policy) = &self.policy {
            for (idx, rule) in policy.payload.rules.iter().enumerate() {
                if matches_subject(rule, &subject) {
                    decision.matched_allow = Some(rule.allow);
                    decision.matched_rule_hash = policy.rule_hashes.get(idx).cloned();
                    break;
                }
            }
        }
        self.decisions.push(decision.clone());
        decision
    }

    /// Read-only view of every observation recorded so far.
    pub fn decisions(&self) -> &[Decision] {
        &self.decisions
    }

    /// Drop all recorded decisions. Useful for tests and after a
    /// successful flush to the bus.
    pub fn clear_decisions(&mut self) {
        self.decisions.clear();
    }
}

/// Whether a single rule's `subject` field matches an observed
/// subject.  Literal string matching only — wildcards /
/// glob expansion will land when the real PAL
/// backends.
fn matches_subject(rule: &AppControlRule, subject: &str) -> bool {
    rule.subject == subject
}

/// Convenience: hash a rule the same way the verifier does. Useful
/// for callers that want to label observations without holding a
/// [`VerifiedPolicy`].
pub fn rule_hash(rule: &AppControlRule) -> String {
    canonical_rule_hash(rule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sda_pal::app_control::{AppControlMode, AppControlPolicyPayload};

    fn vp(rules: Vec<AppControlRule>) -> VerifiedPolicy {
        let rule_hashes = rules.iter().map(canonical_rule_hash).collect();
        VerifiedPolicy {
            payload: AppControlPolicyPayload {
                version: 1,
                issued_at: Utc::now(),
                target_mode: AppControlMode::Monitor,
                rules,
            },
            rule_hashes,
        }
    }

    fn rule(subject: &str, allow: bool) -> AppControlRule {
        AppControlRule {
            subject: subject.into(),
            allow,
            reason: "test".into(),
        }
    }

    #[test]
    fn observation_records_no_match_when_policy_empty() {
        let mut m = MonitorController::new();
        let d = m.observe("sha256:abc");
        assert!(d.matched_allow.is_none());
        assert!(d.matched_rule_hash.is_none());
    }

    #[test]
    fn observation_records_allow_when_rule_matches() {
        let mut m = MonitorController::new();
        m.install_policy(vp(vec![rule("sha256:abc", true)]));
        let d = m.observe("sha256:abc");
        assert_eq!(d.matched_allow, Some(true));
        assert!(d.matched_rule_hash.is_some());
    }

    #[test]
    fn observation_records_deny_when_rule_matches() {
        let mut m = MonitorController::new();
        m.install_policy(vp(vec![rule("sha256:bad", false)]));
        let d = m.observe("sha256:bad");
        assert_eq!(d.matched_allow, Some(false));
    }

    #[test]
    fn observation_does_not_block_anything() {
        // Monitor mode never reports back-pressure. The contract is
        // that `observe` always succeeds and returns immediately.
        let mut m = MonitorController::new();
        m.install_policy(vp(vec![rule("sha256:bad", false)]));
        for _ in 0..10 {
            m.observe("sha256:bad");
        }
        assert_eq!(m.decisions().len(), 10);
    }

    #[test]
    fn install_policy_clears_prior_decisions() {
        let mut m = MonitorController::new();
        m.install_policy(vp(vec![rule("sha256:abc", true)]));
        m.observe("sha256:abc");
        assert_eq!(m.decisions().len(), 1);
        m.install_policy(vp(vec![rule("sha256:def", true)]));
        assert!(m.decisions().is_empty());
    }

    #[test]
    fn first_matching_rule_wins() {
        let mut m = MonitorController::new();
        m.install_policy(vp(vec![rule("sha256:aa", true), rule("sha256:aa", false)]));
        let d = m.observe("sha256:aa");
        assert_eq!(d.matched_allow, Some(true));
    }

    #[test]
    fn decision_round_trips_through_json() {
        let d = Decision {
            subject: "sha256:abc".into(),
            matched_allow: Some(false),
            matched_rule_hash: Some("hash".into()),
            observed_at: Utc::now(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}
