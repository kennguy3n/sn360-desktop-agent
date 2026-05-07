//! 10-step signed-job validation pipeline.
//!
//! Mirrors `docs/device-control/ARCHITECTURE.md` § 4.3 and
//! `docs/device-control/SCHEMAS.md` § 7.4.
//!
//! Phase 1 scope: this module implements the *deterministic* steps
//! of the pipeline (parse, schema version, window check, tenant /
//! device match, action allow-list, args parse). The
//! infrastructure-dependent steps — Ed25519 signature verification
//! against a rotation set, pricing-tier lookup, and maintenance /
//! quiet-hours window evaluation — are surfaced as trait hooks so
//! Phase 2/3 can plug in real implementations without changing the
//! pipeline layout.
//!
//! The pipeline returns `Result<(), JobRefused>`; on `Err(reason)`
//! the caller MUST emit an `ActionResult` with `status = Refused`
//! and `refused_reason = Some(reason)` per SCHEMAS.md § 8.3.

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::signed_job::{JobArgs, SignedActionJob, SignedJobError};
use crate::types::{ActionKind, JobRefused};

/// Tolerance window for `not_before` / `not_after` (SCHEMAS.md
/// § 7.4 step 5).
pub const CLOCK_SKEW_TOLERANCE: Duration = Duration::seconds(60);

/// Hooks the router calls to delegate decisions that depend on
/// infrastructure not built in Phase 1.
///
/// Phase 1 callers wire up [`Phase1Stub`], which:
/// - rejects every signature with [`JobRefused::UnknownKeyId`]
///   unless the test stub overrides it;
/// - permits the maintenance window for *all* actions (so unit
///   tests for steps 1–8 and 10 can fire);
/// - allows every `ActionKind` (the action-orchestration tier check
///   lives in `sn360-security-platform`).
///
/// Phase 2 will replace `Phase1Stub` with a real `KeyStore`
/// implementation; Phase 3 will plug the maintenance / quiet-hours
/// evaluator from `crates/sda-core`.
pub trait JobValidationHooks {
    /// Step 3 + 4: look up `key_id` in the local rotation set and
    /// verify the Ed25519 signature over the canonical pre-image.
    fn verify_signature(&self, job: &SignedActionJob) -> Result<(), JobRefused>;
    /// Step 8: confirm the action is allow-listed for the agent's
    /// current pricing tier.
    fn action_permitted(&self, action: ActionKind) -> bool;
    /// Step 9: confirm we are inside the configured maintenance
    /// window (and not in a quiet-hours block).
    fn in_window(&self, now: DateTime<Utc>) -> bool;
}

/// Phase 1 placeholder hooks — see module docs.
#[derive(Debug, Default)]
pub struct Phase1Stub;

impl JobValidationHooks for Phase1Stub {
    fn verify_signature(&self, _job: &SignedActionJob) -> Result<(), JobRefused> {
        // No real key store yet; conservatively reject every
        // signature so Phase 1 deployments cannot accidentally
        // execute a forged job. Tests should use [`AcceptingHooks`]
        // (test-only) to exercise the rest of the pipeline.
        Err(JobRefused::UnknownKeyId)
    }
    fn action_permitted(&self, _action: ActionKind) -> bool {
        true
    }
    fn in_window(&self, _now: DateTime<Utc>) -> bool {
        true
    }
}

/// Identity of *this* agent — what steps 6 and 7 compare against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentIdentity {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
}

/// Successful pipeline output — the parsed `JobArgs` is handed to
/// the per-action executor.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedJob {
    pub args: JobArgs,
}

/// Run the 10-step validation pipeline.
///
/// `now` is passed in (rather than read from the system clock) so
/// tests can pin time deterministically and so the higher-level
/// router can enforce a single `now` across all steps.
pub fn validate<H: JobValidationHooks>(
    job: &SignedActionJob,
    self_identity: &AgentIdentity,
    now: DateTime<Utc>,
    hooks: &H,
) -> Result<ValidatedJob, JobRefused> {
    // Steps 1 & 2 — frame decode + schema parse — are upstream of
    // the router. They live in `sda-comms` (TLS / HTTP/2 frame
    // decode) and in `serde_json::from_slice::<SignedActionJob>`
    // respectively. By the time we have a `&SignedActionJob`, both
    // have succeeded. We still re-validate the structural
    // invariants here as a defensive in-process check, mapping
    // `SchemaVersionUnsupported` and `ArgsTooLarge` onto
    // `SchemaParseError` (the wire reason for "step 2 failed").
    if let Err(err) = job.validate_structure() {
        return Err(structural_to_refused(err));
    }

    // Step 3 + 4 — key_id lookup + Ed25519 signature verification.
    hooks.verify_signature(job)?;

    // Step 5 — clock window with ±60 s tolerance.
    if now < job.not_before - CLOCK_SKEW_TOLERANCE {
        return Err(JobRefused::Expired);
    }
    if now > job.not_after + CLOCK_SKEW_TOLERANCE {
        return Err(JobRefused::Expired);
    }

    // Step 6 — tenant_id match.
    if job.tenant_id != self_identity.tenant_id {
        return Err(JobRefused::TenantMismatch);
    }

    // Step 7 — device_id match.
    if job.device_id != self_identity.device_id {
        return Err(JobRefused::DeviceMismatch);
    }

    // Step 8 — pricing-tier allow-list.
    if !hooks.action_permitted(job.action) {
        return Err(JobRefused::ActionNotPermitted);
    }

    // Step 9 — maintenance / quiet-hours window.
    if !hooks.in_window(now) {
        return Err(JobRefused::OutsideWindow);
    }

    // Step 10 — per-ActionKind args parse.
    let args = job.parse_args().map_err(|e| match e {
        SignedJobError::ArgsParseError { .. } => JobRefused::ArgsParseError,
        SignedJobError::ArgsTooLarge { .. } => JobRefused::SchemaParseError,
        SignedJobError::SchemaVersionUnsupported(_) => JobRefused::SchemaParseError,
        SignedJobError::InvalidWindow => JobRefused::SchemaParseError,
    })?;

    Ok(ValidatedJob { args })
}

fn structural_to_refused(err: SignedJobError) -> JobRefused {
    match err {
        SignedJobError::SchemaVersionUnsupported(_) => JobRefused::SchemaParseError,
        SignedJobError::ArgsTooLarge { .. } => JobRefused::SchemaParseError,
        SignedJobError::InvalidWindow => JobRefused::SchemaParseError,
        SignedJobError::ArgsParseError { .. } => JobRefused::ArgsParseError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    /// Test hook that accepts every signature (so tests can exercise
    /// step 5 onward).
    struct AcceptingHooks {
        permitted: bool,
        in_window: bool,
    }

    impl AcceptingHooks {
        fn ok() -> Self {
            Self {
                permitted: true,
                in_window: true,
            }
        }
    }

    impl JobValidationHooks for AcceptingHooks {
        fn verify_signature(&self, _job: &SignedActionJob) -> Result<(), JobRefused> {
            Ok(())
        }
        fn action_permitted(&self, _action: ActionKind) -> bool {
            self.permitted
        }
        fn in_window(&self, _now: DateTime<Utc>) -> bool {
            self.in_window
        }
    }

    fn identity() -> AgentIdentity {
        AgentIdentity {
            tenant_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
        }
    }

    fn job_for(action: ActionKind, args: serde_json::Value) -> SignedActionJob {
        SignedActionJob {
            job_id: Uuid::from_u128(99),
            tenant_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            schema_version: crate::version::SIGNED_ACTION_JOB_SCHEMA_VERSION,
            recommendation_id: None,
            action,
            args,
            not_before: Utc.with_ymd_and_hms(2026, 5, 7, 8, 0, 0).unwrap(),
            not_after: Utc.with_ymd_and_hms(2026, 5, 7, 9, 0, 0).unwrap(),
            signature: vec![0; 64],
            key_id: "sn360-control-2026-05".into(),
            correlation_id: None,
        }
    }

    fn happy_job() -> SignedActionJob {
        job_for(
            ActionKind::UpdatePackage,
            json!({"package_id": "p", "to_version": "1", "channel": "stable"}),
        )
    }

    fn now_in_window() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 7, 8, 30, 0).unwrap()
    }

    #[test]
    fn happy_path_passes_all_steps() {
        let r = validate(
            &happy_job(),
            &identity(),
            now_in_window(),
            &AcceptingHooks::ok(),
        );
        let v = r.expect("should validate");
        match v.args {
            JobArgs::UpdatePackage(_) => {}
            _ => panic!("wrong args variant"),
        }
    }

    #[test]
    fn step_3_unknown_key_id_returns_unknown_key_id() {
        // Default Phase1Stub rejects everything with UnknownKeyId.
        let r = validate(&happy_job(), &identity(), now_in_window(), &Phase1Stub);
        assert_eq!(r.unwrap_err(), JobRefused::UnknownKeyId);
    }

    #[test]
    fn step_2_unsupported_schema_version_maps_to_schema_parse_error() {
        let mut j = happy_job();
        j.schema_version = 999;
        let r = validate(&j, &identity(), now_in_window(), &AcceptingHooks::ok());
        assert_eq!(r.unwrap_err(), JobRefused::SchemaParseError);
    }

    #[test]
    fn step_2_invalid_window_maps_to_schema_parse_error() {
        let mut j = happy_job();
        std::mem::swap(&mut j.not_before, &mut j.not_after);
        let r = validate(&j, &identity(), now_in_window(), &AcceptingHooks::ok());
        assert_eq!(r.unwrap_err(), JobRefused::SchemaParseError);
    }

    #[test]
    fn step_5_before_not_before_minus_skew_is_expired() {
        let j = happy_job();
        let too_early = j.not_before - CLOCK_SKEW_TOLERANCE - Duration::seconds(1);
        let r = validate(&j, &identity(), too_early, &AcceptingHooks::ok());
        assert_eq!(r.unwrap_err(), JobRefused::Expired);
    }

    #[test]
    fn step_5_within_skew_window_is_accepted() {
        let j = happy_job();
        // 30 seconds before not_before — inside the ±60 s tolerance.
        let inside = j.not_before - Duration::seconds(30);
        let r = validate(&j, &identity(), inside, &AcceptingHooks::ok());
        assert!(r.is_ok());
    }

    #[test]
    fn step_5_after_not_after_plus_skew_is_expired() {
        let j = happy_job();
        let too_late = j.not_after + CLOCK_SKEW_TOLERANCE + Duration::seconds(1);
        let r = validate(&j, &identity(), too_late, &AcceptingHooks::ok());
        assert_eq!(r.unwrap_err(), JobRefused::Expired);
    }

    #[test]
    fn step_6_tenant_mismatch() {
        let mut j = happy_job();
        j.tenant_id = Uuid::from_u128(7777);
        let r = validate(&j, &identity(), now_in_window(), &AcceptingHooks::ok());
        assert_eq!(r.unwrap_err(), JobRefused::TenantMismatch);
    }

    #[test]
    fn step_7_device_mismatch() {
        let mut j = happy_job();
        j.device_id = Uuid::from_u128(8888);
        let r = validate(&j, &identity(), now_in_window(), &AcceptingHooks::ok());
        assert_eq!(r.unwrap_err(), JobRefused::DeviceMismatch);
    }

    #[test]
    fn step_8_action_not_permitted() {
        let h = AcceptingHooks {
            permitted: false,
            in_window: true,
        };
        let r = validate(&happy_job(), &identity(), now_in_window(), &h);
        assert_eq!(r.unwrap_err(), JobRefused::ActionNotPermitted);
    }

    #[test]
    fn step_9_outside_window() {
        let h = AcceptingHooks {
            permitted: true,
            in_window: false,
        };
        let r = validate(&happy_job(), &identity(), now_in_window(), &h);
        assert_eq!(r.unwrap_err(), JobRefused::OutsideWindow);
    }

    #[test]
    fn step_10_args_parse_error_on_extra_field() {
        let j = job_for(
            ActionKind::UpdatePackage,
            json!({"package_id": "p", "to_version": "1", "channel": "stable", "x": true}),
        );
        let r = validate(&j, &identity(), now_in_window(), &AcceptingHooks::ok());
        assert_eq!(r.unwrap_err(), JobRefused::ArgsParseError);
    }

    #[test]
    fn step_10_args_parse_error_on_missing_field() {
        let j = job_for(ActionKind::UpdatePackage, json!({}));
        let r = validate(&j, &identity(), now_in_window(), &AcceptingHooks::ok());
        assert_eq!(r.unwrap_err(), JobRefused::ArgsParseError);
    }

    #[test]
    fn step_10_args_parse_error_on_cap_violation() {
        let j = job_for(
            ActionKind::GrantJitAdmin,
            json!({
                "user": "alice",
                "duration_minutes": 999_999,
                "reason": "test",
                "approver_id": "00000000-0000-0000-0000-000000000000"
            }),
        );
        let r = validate(&j, &identity(), now_in_window(), &AcceptingHooks::ok());
        assert_eq!(r.unwrap_err(), JobRefused::ArgsParseError);
    }

    #[test]
    fn args_too_large_maps_to_schema_parse_error() {
        let j = job_for(
            ActionKind::UpdatePackage,
            json!({"x": "y".repeat(70 * 1024)}),
        );
        let r = validate(&j, &identity(), now_in_window(), &AcceptingHooks::ok());
        // ArgsTooLarge surfaces from validate_structure, which the
        // router maps onto SchemaParseError per the docstring above.
        assert_eq!(r.unwrap_err(), JobRefused::SchemaParseError);
    }
}
