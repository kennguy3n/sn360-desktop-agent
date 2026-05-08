//! Enforce mode: push verified policy to the OS-level backend with
//! dual-control rollback (PROPOSAL.md § 9.6).
//!
//! Enforce mode requires explicit tenant opt-in. Every apply
//! captures the previously-active policy in a
//! [`DualControlRollback`] handle so a misbehaving rule can be
//! reverted automatically — either on a watchdog tick or through an
//! operator command — without the operator having to push a new
//! policy.

use sda_pal::app_control::{
    AppControlError, AppControlMode, AppControlProvider, SignedAppControlPolicy,
};

use crate::policy::VerifiedPolicy;

/// Errors produced by the enforce controller.
#[derive(Debug, thiserror::Error)]
pub enum RollbackError {
    /// The enforce controller was asked to roll back without a
    /// previous policy to roll back to.
    #[error("no previous policy to roll back to")]
    NoPrevious,
    /// The PAL provider returned an error while applying the
    /// rollback policy.
    #[error("pal error: {0}")]
    Pal(#[from] AppControlError),
}

/// Snapshot held by the enforce controller so a misbehaving policy
/// can be rolled back. Phase-4 keeps a single-step history; the
/// snapshot is consumed by the rollback and reset to empty so a
/// second rollback fails cleanly rather than ping-ponging.
#[derive(Debug, Clone, Default)]
pub struct DualControlRollback {
    /// The signed bundle that was active before the latest apply.
    /// `None` after a fresh boot — there is nothing to roll back
    /// to.
    pub previous_signed: Option<SignedAppControlPolicy>,
    /// Verified version of `previous_signed` for the audit trail.
    pub previous_verified: Option<VerifiedPolicy>,
}

impl DualControlRollback {
    /// A fresh rollback handle with no recorded previous policy.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Whether a rollback target is available.
    pub fn has_previous(&self) -> bool {
        self.previous_signed.is_some()
    }
}

/// Stateful enforce-mode controller.
///
/// Owns:
/// * The PAL provider (Box<dyn …> so tests can swap in a stub).
/// * The currently-applied (signed, verified) bundle.
/// * The single-step rollback snapshot.
pub struct EnforceController {
    provider: Box<dyn AppControlProvider>,
    /// Currently-applied signed bundle. We keep both the signed and
    /// the verified form because rollback must re-push the signed
    /// bundle through the PAL.
    current_signed: Option<SignedAppControlPolicy>,
    current_verified: Option<VerifiedPolicy>,
    rollback: DualControlRollback,
}

impl std::fmt::Debug for EnforceController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnforceController")
            .field("has_current", &self.current_signed.is_some())
            .field("can_rollback", &self.rollback.has_previous())
            .finish()
    }
}

impl EnforceController {
    /// Build a controller backed by `provider`. The controller
    /// starts with no policy applied.
    pub fn new(provider: Box<dyn AppControlProvider>) -> Self {
        Self {
            provider,
            current_signed: None,
            current_verified: None,
            rollback: DualControlRollback::empty(),
        }
    }

    /// Read-only access to the currently-applied policy.
    pub fn current(&self) -> Option<&VerifiedPolicy> {
        self.current_verified.as_ref()
    }

    /// Read-only access to the dual-control rollback snapshot.
    pub fn rollback_snapshot(&self) -> &DualControlRollback {
        &self.rollback
    }

    /// Read-only view of the underlying provider's mode.
    pub fn current_mode(&self) -> Result<AppControlMode, AppControlError> {
        self.provider.current_mode()
    }

    /// Push a verified policy to the OS-level backend.
    ///
    /// On success the previously-active policy (if any) is captured
    /// in the rollback handle so [`EnforceController::rollback`]
    /// can revert to it without needing the operator to push
    /// another bundle.
    ///
    /// On PAL failure the controller is left untouched: `current`
    /// still points at the prior bundle and the rollback snapshot
    /// is unchanged.
    pub fn apply(
        &mut self,
        signed: SignedAppControlPolicy,
        verified: VerifiedPolicy,
    ) -> Result<(), AppControlError> {
        // Push to the PAL FIRST. If this fails, we leave the
        // controller's state untouched.
        self.provider.apply_policy(&signed)?;
        // Move the now-displaced bundle into the rollback handle.
        // Phase 4 keeps a single-step rollback history.
        if let (Some(prev_signed), Some(prev_verified)) =
            (self.current_signed.take(), self.current_verified.take())
        {
            self.rollback = DualControlRollback {
                previous_signed: Some(prev_signed),
                previous_verified: Some(prev_verified),
            };
        }
        self.current_signed = Some(signed);
        self.current_verified = Some(verified);
        Ok(())
    }

    /// Roll back to the previously-applied policy by re-pushing the
    /// recorded signed bundle to the OS backend. Phase-4 keeps a
    /// single-step history: the rollback snapshot is consumed and
    /// a second [`EnforceController::rollback`] returns
    /// [`RollbackError::NoPrevious`].
    pub fn rollback(&mut self) -> Result<VerifiedPolicy, RollbackError> {
        let signed = self
            .rollback
            .previous_signed
            .clone()
            .ok_or(RollbackError::NoPrevious)?;
        let verified = self
            .rollback
            .previous_verified
            .clone()
            .ok_or(RollbackError::NoPrevious)?;
        self.provider.apply_policy(&signed)?;
        self.current_signed = Some(signed);
        self.current_verified = Some(verified.clone());
        self.rollback = DualControlRollback::empty();
        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ed25519_dalek::{Signer, SigningKey};
    use sda_pal::app_control::{AppControlPolicyPayload, AppControlRule, SignedAppControlPolicy};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn signed_bundle(
        version: u64,
        rules: Vec<AppControlRule>,
    ) -> (SignedAppControlPolicy, VerifiedPolicy) {
        let payload = AppControlPolicyPayload {
            version,
            issued_at: Utc::now(),
            target_mode: AppControlMode::Enforce,
            rules: rules.clone(),
        };
        let canonical = serde_json::to_vec(&payload).unwrap();
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let sig = signing.sign(&canonical);
        let signed = SignedAppControlPolicy {
            canonical_payload_hex: hex::encode(&canonical),
            signature: hex::encode(sig.to_bytes()),
            signing_key: hex::encode(signing.verifying_key().to_bytes()),
        };
        let rule_hashes = rules
            .iter()
            .map(crate::policy::canonical_rule_hash)
            .collect();
        let verified = VerifiedPolicy {
            payload,
            rule_hashes,
        };
        (signed, verified)
    }

    fn rule(subject: &str, allow: bool) -> AppControlRule {
        AppControlRule {
            subject: subject.into(),
            allow,
            reason: "test".into(),
        }
    }

    /// Stub provider: always accepts apply, records call counts.
    #[derive(Default)]
    struct OkProvider {
        applies: AtomicUsize,
    }

    impl AppControlProvider for OkProvider {
        fn current_mode(&self) -> Result<AppControlMode, AppControlError> {
            Ok(AppControlMode::Enforce)
        }
        fn apply_verified_policy(
            &self,
            _payload: &AppControlPolicyPayload,
        ) -> Result<(), AppControlError> {
            self.applies.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Stub provider: rejects every apply.
    struct FailProvider;
    impl AppControlProvider for FailProvider {
        fn current_mode(&self) -> Result<AppControlMode, AppControlError> {
            Ok(AppControlMode::Enforce)
        }
        fn apply_verified_policy(
            &self,
            _payload: &AppControlPolicyPayload,
        ) -> Result<(), AppControlError> {
            Err(AppControlError::Backend("nope".into()))
        }
    }

    #[test]
    fn fresh_controller_has_no_current_or_rollback() {
        let c = EnforceController::new(Box::<OkProvider>::default());
        assert!(c.current().is_none());
        assert!(!c.rollback_snapshot().has_previous());
    }

    #[test]
    fn first_apply_sets_current_with_no_rollback_target() {
        let mut c = EnforceController::new(Box::<OkProvider>::default());
        let (signed, verified) = signed_bundle(1, vec![rule("sha256:aa", true)]);
        c.apply(signed, verified).unwrap();
        assert_eq!(c.current().unwrap().payload.version, 1);
        // First apply: no rollback target.
        assert!(!c.rollback_snapshot().has_previous());
    }

    #[test]
    fn second_apply_captures_rollback_snapshot() {
        let mut c = EnforceController::new(Box::<OkProvider>::default());
        let (s1, v1) = signed_bundle(1, vec![rule("sha256:aa", true)]);
        c.apply(s1, v1).unwrap();
        let (s2, v2) = signed_bundle(2, vec![rule("sha256:bb", false)]);
        c.apply(s2, v2).unwrap();
        assert!(c.rollback_snapshot().has_previous());
        assert_eq!(c.current().unwrap().payload.version, 2);
        // The rollback snapshot points at v1.
        assert_eq!(
            c.rollback_snapshot()
                .previous_verified
                .as_ref()
                .unwrap()
                .payload
                .version,
            1
        );
    }

    #[test]
    fn rollback_reverts_to_previous_policy() {
        let mut c = EnforceController::new(Box::<OkProvider>::default());
        let (s1, v1) = signed_bundle(1, vec![rule("sha256:aa", true)]);
        c.apply(s1, v1).unwrap();
        let (s2, v2) = signed_bundle(2, vec![rule("sha256:bb", false)]);
        c.apply(s2, v2).unwrap();
        let restored = c.rollback().unwrap();
        // After rollback, current should be v1.
        assert_eq!(restored.payload.version, 1);
        assert_eq!(c.current().unwrap().payload.version, 1);
        // And the snapshot is consumed: a second rollback fails.
        assert!(matches!(c.rollback(), Err(RollbackError::NoPrevious)));
    }

    #[test]
    fn rollback_without_history_is_an_error() {
        let mut c = EnforceController::new(Box::<OkProvider>::default());
        assert!(matches!(c.rollback(), Err(RollbackError::NoPrevious)));
    }

    #[test]
    fn rollback_after_only_first_apply_is_an_error() {
        let mut c = EnforceController::new(Box::<OkProvider>::default());
        let (signed, verified) = signed_bundle(1, vec![rule("sha256:aa", true)]);
        c.apply(signed, verified).unwrap();
        assert!(matches!(c.rollback(), Err(RollbackError::NoPrevious)));
    }

    #[test]
    fn pal_failure_does_not_displace_current() {
        // Apply v1 with the OK provider, then swap in the failing
        // provider and try to apply v2.
        let mut c = EnforceController::new(Box::<OkProvider>::default());
        let (s1, v1) = signed_bundle(1, vec![rule("sha256:aa", true)]);
        c.apply(s1, v1).unwrap();
        // Swap providers preserving state.
        let mut c = EnforceController {
            provider: Box::new(FailProvider),
            current_signed: c.current_signed.take(),
            current_verified: c.current_verified.take(),
            rollback: c.rollback,
        };
        let (s2, v2) = signed_bundle(2, vec![rule("sha256:bb", false)]);
        let err = c.apply(s2, v2).err().unwrap();
        assert!(matches!(err, AppControlError::Backend(_)));
        // Current must still point at v1 and rollback unchanged.
        assert_eq!(c.current().unwrap().payload.version, 1);
        assert!(!c.rollback_snapshot().has_previous());
    }

    #[test]
    fn current_mode_is_proxied_to_provider() {
        let c = EnforceController::new(Box::<OkProvider>::default());
        assert_eq!(c.current_mode().unwrap(), AppControlMode::Enforce);
    }
}
