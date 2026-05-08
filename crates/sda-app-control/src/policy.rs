//! Signed app-control policy verification.
//!
//! Wraps [`sda_pal::app_control::verify_policy`] with extra guards
//! relevant to the orchestration layer:
//!
//! * Trusted-key pinning. The orchestrator is configured with a
//!   single trusted Ed25519 verifying key (lowercase-hex). We
//!   reject any policy whose [`SignedAppControlPolicy::signing_key`]
//!   does not match — even if the signature is otherwise valid.
//! * Per-rule canonical-hash collision detection. The hash of each
//!   `AppControlRule` must be unique within a single policy. Two
//!   identical rules suggests a malformed bundle and is rejected.
//! * Anti-regression checks. The applied policy version must be
//!   strictly greater than the previously-applied version (Phase
//!   4 does not allow rolling back via apply — rollback goes
//!   through [`crate::enforce::DualControlRollback`]).

use sda_pal::app_control::{
    verify_policy, AppControlError, AppControlPolicyPayload, SignedAppControlPolicy,
};
use sha2::{Digest, Sha256};

/// Errors produced by the orchestration-layer policy verifier.
#[derive(Debug, thiserror::Error)]
pub enum PolicyVerificationError {
    /// The PAL-layer signature check failed. The wrapped error
    /// preserves the original cause.
    #[error("signature verification failed: {0}")]
    Signature(#[from] AppControlError),
    /// The policy's signing key does not match the trusted key.
    #[error("untrusted signing key: expected {expected}, got {got}")]
    UntrustedKey { expected: String, got: String },
    /// Two rules in the same policy produce the same canonical hash.
    #[error("duplicate rule hash {0} in policy")]
    DuplicateRule(String),
    /// The policy version did not advance.
    #[error("policy regressed: previous version {previous}, got {current}")]
    PolicyRegressed { previous: u64, current: u64 },
}

/// Result of verifying a [`SignedAppControlPolicy`].
#[derive(Debug, Clone)]
pub struct VerifiedPolicy {
    /// Decoded canonical payload.
    pub payload: AppControlPolicyPayload,
    /// Per-rule canonical SHA-256 hashes (lowercase hex), in the
    /// same order as `payload.rules`. Used by the monitor and
    /// enforce controllers to deduplicate alerts and to anchor
    /// audit records.
    pub rule_hashes: Vec<String>,
}

/// Compute the lowercase-hex SHA-256 hash of a single rule using
/// canonical JSON encoding.
pub fn canonical_rule_hash(rule: &sda_pal::app_control::AppControlRule) -> String {
    let bytes = serde_json::to_vec(rule).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(b"sda-app-control/rule-hash/v1");
    h.update(&bytes);
    hex::encode(h.finalize())
}

/// Verify a signed policy against `trusted_signing_key`, optionally
/// enforcing a strict `previous_version` check.
pub fn verify_signed_policy(
    policy: &SignedAppControlPolicy,
    trusted_signing_key: &str,
    previous_version: Option<u64>,
) -> Result<VerifiedPolicy, PolicyVerificationError> {
    if !policy.signing_key.eq_ignore_ascii_case(trusted_signing_key) {
        return Err(PolicyVerificationError::UntrustedKey {
            expected: trusted_signing_key.to_string(),
            got: policy.signing_key.clone(),
        });
    }
    let payload = verify_policy(policy)?;
    if let Some(prev) = previous_version {
        if payload.version <= prev {
            return Err(PolicyVerificationError::PolicyRegressed {
                previous: prev,
                current: payload.version,
            });
        }
    }
    let mut rule_hashes = Vec::with_capacity(payload.rules.len());
    let mut seen = std::collections::HashSet::new();
    for rule in &payload.rules {
        let h = canonical_rule_hash(rule);
        if !seen.insert(h.clone()) {
            return Err(PolicyVerificationError::DuplicateRule(h));
        }
        rule_hashes.push(h);
    }
    Ok(VerifiedPolicy {
        payload,
        rule_hashes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ed25519_dalek::{Signer, SigningKey};
    use sda_pal::app_control::{
        AppControlMode, AppControlPolicyPayload, AppControlRule, SignedAppControlPolicy,
    };

    fn sign(payload: &AppControlPolicyPayload) -> (SignedAppControlPolicy, String) {
        // Deterministic key for tests.
        let sk_bytes = [7u8; 32];
        let signing = SigningKey::from_bytes(&sk_bytes);
        let verifying = signing.verifying_key();
        let canonical = serde_json::to_vec(payload).unwrap();
        let sig = signing.sign(&canonical);
        let signed = SignedAppControlPolicy {
            canonical_payload_hex: hex::encode(&canonical),
            signature: hex::encode(sig.to_bytes()),
            signing_key: hex::encode(verifying.to_bytes()),
        };
        let trusted = signed.signing_key.clone();
        (signed, trusted)
    }

    fn rule(subject: &str, allow: bool) -> AppControlRule {
        AppControlRule {
            subject: subject.into(),
            allow,
            reason: "test".into(),
        }
    }

    fn payload(version: u64, rules: Vec<AppControlRule>) -> AppControlPolicyPayload {
        AppControlPolicyPayload {
            version,
            issued_at: Utc::now(),
            target_mode: AppControlMode::Monitor,
            rules,
        }
    }

    #[test]
    fn happy_path_verifies_and_returns_rule_hashes() {
        let p = payload(1, vec![rule("sha256:aa", true), rule("sha256:bb", false)]);
        let (signed, trusted) = sign(&p);
        let v = verify_signed_policy(&signed, &trusted, None).expect("verify");
        assert_eq!(v.payload.version, 1);
        assert_eq!(v.rule_hashes.len(), 2);
        assert_ne!(v.rule_hashes[0], v.rule_hashes[1]);
    }

    #[test]
    fn untrusted_key_is_rejected() {
        let p = payload(1, vec![rule("sha256:aa", true)]);
        let (signed, _trusted) = sign(&p);
        let bogus_key = hex::encode([0u8; 32]);
        let err = verify_signed_policy(&signed, &bogus_key, None)
            .err()
            .unwrap();
        assert!(matches!(err, PolicyVerificationError::UntrustedKey { .. }));
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let p = payload(1, vec![rule("sha256:aa", true)]);
        let (mut signed, trusted) = sign(&p);
        // Mutate one nibble of the payload — signature must fail.
        let mut bytes = hex::decode(&signed.canonical_payload_hex).unwrap();
        bytes[0] ^= 0x01;
        signed.canonical_payload_hex = hex::encode(bytes);
        let err = verify_signed_policy(&signed, &trusted, None).err().unwrap();
        assert!(matches!(err, PolicyVerificationError::Signature(_)));
    }

    #[test]
    fn duplicate_rule_is_rejected() {
        let dup = rule("sha256:aa", true);
        let p = payload(1, vec![dup.clone(), dup]);
        let (signed, trusted) = sign(&p);
        let err = verify_signed_policy(&signed, &trusted, None).err().unwrap();
        assert!(matches!(err, PolicyVerificationError::DuplicateRule(_)));
    }

    #[test]
    fn version_regression_is_rejected() {
        let p = payload(2, vec![rule("sha256:aa", true)]);
        let (signed, trusted) = sign(&p);
        let err = verify_signed_policy(&signed, &trusted, Some(5))
            .err()
            .unwrap();
        assert!(matches!(
            err,
            PolicyVerificationError::PolicyRegressed { .. }
        ));
    }

    #[test]
    fn version_advance_is_accepted() {
        let p = payload(6, vec![rule("sha256:aa", true)]);
        let (signed, trusted) = sign(&p);
        verify_signed_policy(&signed, &trusted, Some(5)).expect("advance");
    }

    #[test]
    fn rule_hash_is_deterministic() {
        let r = rule("sha256:aa", true);
        let h1 = canonical_rule_hash(&r);
        let h2 = canonical_rule_hash(&r);
        assert_eq!(h1, h2);
    }

    #[test]
    fn rule_hash_distinguishes_distinct_rules() {
        let a = rule("sha256:aa", true);
        let b = rule("sha256:aa", false);
        assert_ne!(canonical_rule_hash(&a), canonical_rule_hash(&b));
    }
}
