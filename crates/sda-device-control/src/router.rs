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
//!
//! This module also exposes [`process_job`], the higher-level entry
//! point that the agent's job dispatcher calls. `process_job` runs
//! the validation pipeline, builds an [`ActionResult`] (refused or
//! Phase-1 no-op ack), then chains an [`EvidenceRecord`] off the
//! supplied [`EvidenceChain`] and publishes both onto the event
//! bus. Phase 1 has no per-`ActionKind` executor — accepted jobs
//! ack with `status = Skipped` and `exit_code = None` so the audit
//! chain stays continuous even before the install / JIT / script
//! orchestrators land in Phase 2/3 (see PHASES.md task 1.13).

use chrono::{DateTime, Duration, Utc};
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use tracing::warn;
use uuid::Uuid;

use crate::action_result::{bound_output, ActionResult};
use crate::canonicalize::canonicalize;
use crate::evidence::{
    build_signed_evidence_record, EvidenceChain, EvidenceContext, EvidenceRecord,
};
use crate::signed_job::{AdditionalSignature, JobArgs, SignedActionJob, SignedJobError};
use crate::types::{ActionKind, ActionStatus, AgentVersion, JobRefused, Platform};
use crate::windows::{MaintenanceWindowPolicy, WindowDecision};

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

    /// Step 11 (dual-control): verify *one* additional approver
    /// signature against the same canonical pre-image as the
    /// primary signature. Default impl returns
    /// `Err(JobRefused::BadSignature)` so hooks that have not
    /// opted-in cannot accidentally accept multi-signature jobs.
    /// See ARCHITECTURE.md § 4.4 of `docs/desktop-mdm/`.
    fn verify_additional_signature(
        &self,
        _job: &SignedActionJob,
        _sig: &AdditionalSignature,
    ) -> Result<(), JobRefused> {
        Err(JobRefused::BadSignature)
    }

    /// Step 11 (dual-control): map a signing `key_id` onto the
    /// **approver identity** the key represents. The router uses
    /// this to enforce "all signatures on a dual-control job must
    /// come from distinct approvers". Returns `None` when the
    /// `key_id` is unknown or carries no approver mapping (e.g.
    /// the agent-local ephemeral key).
    fn approver_user_id(&self, _key_id: &str) -> Option<Uuid> {
        None
    }

    /// Step 12 (local ephemeral key): true iff `key_id` is the
    /// agent-local ephemeral signing key generated at startup by
    /// the auto-remediation supervisor. Such a key is allowed to
    /// sign **only** a narrow allow-list of self-remediation
    /// actions; everything else is refused with
    /// `LocalKeyNotAuthorisedForAction`.
    fn is_local_ephemeral_key(&self, _key_id: &str) -> bool {
        false
    }
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

    // Step 11 — dual-control gate for `RemoteWipe`
    // (ARCHITECTURE.md § 4.4 of `docs/desktop-mdm/`).
    //
    // The agent MUST refuse a wipe unless the inbound job carries
    // at least *two distinct approver signatures*. The primary
    // signature lives inline on `SignedActionJob.signature` /
    // `key_id`; additional approvers ride on
    // `SignedActionJob.additional_signatures`. We:
    //
    //   * require `additional_signatures.len() >= 1` (one primary
    //     + one additional = two total),
    //   * verify each additional signature against the same
    //     canonical pre-image,
    //   * resolve every `key_id` (primary + additional) to an
    //     approver identity and require all of them to be distinct.
    //
    // Any failure on this path collapses onto a single refusal
    // reason — `WipeRequiresDualControl` — so the operator UI
    // surfaces one clean message no matter which sub-check tripped.
    if job.action == ActionKind::RemoteWipe {
        if job.additional_signatures.is_empty() {
            return Err(JobRefused::WipeRequiresDualControl);
        }
        let primary_approver = hooks
            .approver_user_id(&job.key_id)
            .ok_or(JobRefused::WipeRequiresDualControl)?;
        let mut approvers: Vec<Uuid> = Vec::with_capacity(1 + job.additional_signatures.len());
        approvers.push(primary_approver);
        for sig in &job.additional_signatures {
            hooks
                .verify_additional_signature(job, sig)
                .map_err(|_| JobRefused::WipeRequiresDualControl)?;
            let id = hooks
                .approver_user_id(&sig.key_id)
                .ok_or(JobRefused::WipeRequiresDualControl)?;
            approvers.push(id);
        }
        let total = approvers.len();
        approvers.sort_unstable();
        approvers.dedup();
        if approvers.len() != total {
            return Err(JobRefused::WipeRequiresDualControl);
        }
    }

    // Step 12 — agent-local ephemeral key allow-list.
    //
    // The auto-remediation supervisor (see
    // `crates/sda-mdm/src/auto_remediate.rs`) signs self-issued
    // jobs with an in-memory ephemeral Ed25519 key. Such jobs are
    // legitimate — the agent is fixing its own posture — but the
    // ephemeral key MUST NOT be able to authorise anything beyond
    // the three posture-fix actions, and it must never carry a
    // `recommendation_id` (that field is reserved for control-plane
    // recommendations, which never originate locally).
    if hooks.is_local_ephemeral_key(&job.key_id) {
        let allowed = matches!(
            job.action,
            ActionKind::EnableDiskEncryption
                | ActionKind::EnableFirewall
                | ActionKind::SetScreenLock
        );
        if !allowed || job.recommendation_id.is_some() {
            return Err(JobRefused::LocalKeyNotAuthorisedForAction);
        }
    }

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

/// Output of [`process_job`]: an [`ActionResult`] paired with the
/// chained [`EvidenceRecord`] that was appended to the device's
/// audit chain.
///
/// Both projections share the same `evidence_id` so consumers can
/// correlate them downstream without reaching into the bus payload.
#[derive(Debug, Clone)]
pub struct ProcessedJob {
    pub action_result: ActionResult,
    pub evidence: EvidenceRecord,
}

/// Run a `SignedActionJob` through the Phase 1 pipeline.
///
/// Steps:
/// 1. [`validate`] the job against the 10-step pipeline.
/// 2. Produce an [`ActionResult`] — either the refusal projection
///    (when validation rejected the job) or a Phase 1 *no-op ack*
///    (`status = Skipped`, no executor wired in this build) when
///    validation accepted it.
/// 3. Build a chained [`EvidenceRecord`] using `chain.next_prev_hash()`
///    and append it to `chain` so subsequent jobs link onto this
///    record.
/// 4. Return the [`ProcessedJob`] for the caller to publish.
///
/// Both refused and accepted-but-not-implemented jobs produce
/// evidence records — the audit chain is **continuous** even before
/// Phase 2/3 executors land, so any tampering with the in-flight
/// chain is detectable from day one (PHASES.md task 1.13).
pub fn process_job<H: JobValidationHooks>(
    job: &SignedActionJob,
    self_identity: &AgentIdentity,
    now: DateTime<Utc>,
    hooks: &H,
    chain: &mut EvidenceChain,
    platform: &Platform,
    agent: &AgentVersion,
) -> ProcessedJob {
    let validation = validate(job, self_identity, now, hooks);
    let action_result = match validation {
        Ok(_) => phase1_skipped_ack(job, now),
        Err(reason) => phase1_refused(job, reason, now),
    };

    let args_canonical = canonicalize(&job.args)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| job.args.to_string());

    let output_full = action_result.output.as_bytes();
    let evidence = build_signed_evidence_record(
        job,
        &action_result,
        chain,
        EvidenceContext {
            args_canonical,
            output_full,
            platform: platform.clone(),
            agent: agent.clone(),
        },
    )
    .expect("Phase 1 evidence build/validate must not fail for synthesised records");

    chain
        .append(&evidence)
        .expect("Phase 1 chain append must not fail for canonical records");

    ProcessedJob {
        action_result,
        evidence,
    }
}

/// Wrapper around [`process_job`] that consults a
/// [`MaintenanceWindowPolicy`] *before* invoking the rest of the
/// pipeline.
///
/// This is the production entry point used by the agent. The
/// underlying [`process_job`] is preserved so existing call sites
/// and unit tests that pre-date Phase 2.8 continue to work.
///
/// Three outcomes are possible:
///
/// * [`WindowDecision::Execute`] — the policy permits execution
///   right now; we forward to [`process_job`] which runs the full
///   10-step pipeline.
/// * [`WindowDecision::Defer`] — the job arrived outside the
///   maintenance window or inside quiet hours; we synthesise an
///   `ActionResult` with `status = Skipped` and the human-readable
///   marker `outside_maintenance_window` in `output`. The job is
///   not refused — the upstream queue is expected to retry it the
///   next time the window opens.
/// * [`WindowDecision::Refuse`] — the policy is mis-configured (a
///   maintenance window with zero permissible days); we permanently
///   refuse with [`JobRefused::OutsideWindow`].
///
/// Both `Defer` and `Refuse` paths still emit a chained
/// [`EvidenceRecord`] so the audit trail captures the decision.
#[allow(clippy::too_many_arguments)]
pub fn process_job_with_window_policy<H: JobValidationHooks>(
    job: &SignedActionJob,
    self_identity: &AgentIdentity,
    now: DateTime<Utc>,
    hooks: &H,
    window_policy: &MaintenanceWindowPolicy,
    chain: &mut EvidenceChain,
    platform: &Platform,
    agent: &AgentVersion,
) -> ProcessedJob {
    let action_result = match window_policy.should_execute(now) {
        WindowDecision::Execute => {
            return process_job(job, self_identity, now, hooks, chain, platform, agent);
        }
        WindowDecision::Defer => phase2_window_deferred_ack(job, now),
        WindowDecision::Refuse => phase1_refused(job, JobRefused::OutsideWindow, now),
    };

    let args_canonical = canonicalize(&job.args)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| job.args.to_string());

    let output_full = action_result.output.as_bytes();
    let evidence = build_signed_evidence_record(
        job,
        &action_result,
        chain,
        EvidenceContext {
            args_canonical,
            output_full,
            platform: platform.clone(),
            agent: agent.clone(),
        },
    )
    .expect("Phase 2.8 evidence build/validate must not fail for synthesised records");

    chain
        .append(&evidence)
        .expect("Phase 2.8 chain append must not fail for canonical records");

    ProcessedJob {
        action_result,
        evidence,
    }
}

/// `ActionStatus::Skipped` projection used when a job arrives
/// outside the maintenance window. `output` carries the canonical
/// marker `"outside_maintenance_window"` so dashboards and operator
/// queries can filter on it.
fn phase2_window_deferred_ack(job: &SignedActionJob, now: DateTime<Utc>) -> ActionResult {
    let (output, output_truncated) = bound_output(String::from(
        "outside_maintenance_window: deferred — job will retry on the next open window",
    ));
    ActionResult {
        job_id: job.job_id,
        tenant_id: job.tenant_id,
        device_id: job.device_id,
        schema_version: crate::version::ACTION_RESULT_SCHEMA_VERSION,
        action: job.action,
        status: ActionStatus::Skipped,
        refused_reason: None,
        started_at: now,
        finished_at: now,
        exit_code: None,
        output,
        output_truncated,
        evidence_id: Uuid::new_v4(),
    }
}

/// Publish the `DeviceControlActionResult` and `EvidenceRecord`
/// payloads for a [`ProcessedJob`] onto the event bus.
///
/// Both events use [`Priority::High`] per the Phase 0 sign-off
/// (ARCHITECTURE.md § 7.2 — Device Control results sit just below
/// `Critical`). Failures to enqueue onto the server-bound queue are
/// logged at WARN; we deliberately do **not** call `bus.publish`
/// again afterwards because `EventBus::publish_to_server` already
/// performed the local broadcast before attempting the server send
/// (see internal note "double local broadcast on
/// publish_to_server").
pub async fn emit_processed_job(bus: &EventBus, processed: &ProcessedJob) {
    match canonical_action_result_payload(&processed.action_result) {
        Ok(payload) => {
            let event = Event::new(
                "device-control",
                Priority::High,
                EventKind::DeviceControlActionResult { payload },
            );
            if let Err(err) = bus.publish_to_server(event).await {
                warn!(error = %err, "failed to publish DeviceControlActionResult");
            }
        }
        Err(err) => {
            warn!(error = %err, "failed to canonicalise ActionResult — skipping bus emit");
        }
    }

    match canonical_evidence_record_payload(&processed.evidence) {
        Ok(payload) => {
            let event = Event::new(
                "device-control",
                Priority::High,
                EventKind::EvidenceRecord { payload },
            );
            if let Err(err) = bus.publish_to_server(event).await {
                warn!(error = %err, "failed to publish EvidenceRecord");
            }
        }
        Err(err) => {
            warn!(error = %err, "failed to canonicalise EvidenceRecord — skipping bus emit");
        }
    }
}

/// Phase 1 acceptance projection: `status = Skipped`, no exit code,
/// `started_at == finished_at` so the record reads "router accepted
/// the job but no executor exists in this build". Phase 2 swaps
/// this for the per-`ActionKind` executor's actual outcome.
fn phase1_skipped_ack(job: &SignedActionJob, now: DateTime<Utc>) -> ActionResult {
    let (output, output_truncated) = bound_output(format!(
        "phase1_no_op_ack: action {:?} accepted but no executor wired in this build",
        job.action
    ));
    ActionResult {
        job_id: job.job_id,
        tenant_id: job.tenant_id,
        device_id: job.device_id,
        schema_version: crate::version::ACTION_RESULT_SCHEMA_VERSION,
        action: job.action,
        status: ActionStatus::Skipped,
        refused_reason: None,
        started_at: now,
        finished_at: now,
        exit_code: None,
        output,
        output_truncated,
        evidence_id: Uuid::new_v4(),
    }
}

/// Refusal projection — `started_at == finished_at` (no side
/// effect), `status = Refused`, `refused_reason = Some(reason)`.
fn phase1_refused(job: &SignedActionJob, reason: JobRefused, now: DateTime<Utc>) -> ActionResult {
    let (output, output_truncated) =
        bound_output(format!("refused: {}", refusal_human_readable(reason)));
    ActionResult {
        job_id: job.job_id,
        tenant_id: job.tenant_id,
        device_id: job.device_id,
        schema_version: crate::version::ACTION_RESULT_SCHEMA_VERSION,
        action: job.action,
        status: ActionStatus::Refused,
        refused_reason: Some(reason),
        started_at: now,
        finished_at: now,
        exit_code: None,
        output,
        output_truncated,
        evidence_id: Uuid::new_v4(),
    }
}

/// Stable, human-readable spelling of a refusal reason for use in
/// the bounded `output` field. The wire-level `refused_reason` is
/// the structured enum on `ActionResult`; this string is purely
/// descriptive log surface.
fn refusal_human_readable(reason: JobRefused) -> &'static str {
    match reason {
        JobRefused::SchemaParseError => "schema_parse_error",
        JobRefused::UnknownKeyId => "unknown_key_id",
        JobRefused::BadSignature => "bad_signature",
        JobRefused::Expired => "expired",
        JobRefused::TenantMismatch => "tenant_mismatch",
        JobRefused::DeviceMismatch => "device_mismatch",
        JobRefused::ActionNotPermitted => "action_not_permitted",
        JobRefused::OutsideWindow => "outside_window",
        JobRefused::ArgsParseError => "args_parse_error",
        JobRefused::PreconditionFailed => "precondition_failed",
        JobRefused::NotImplemented => "not_implemented",
        // Desktop MDM (Phase M1–M3) — dual-control + local-key
        // refusals. See `crates/sda-device-control/src/types.rs`.
        JobRefused::WipeRequiresDualControl => "wipe_requires_dual_control",
        JobRefused::LocalKeyNotAuthorisedForAction => "local_key_not_authorised_for_action",
    }
}

fn canonical_action_result_payload(r: &ActionResult) -> Result<String, String> {
    let value = serde_json::to_value(r).map_err(|e| format!("serde_json: {e}"))?;
    let bytes = canonicalize(&value).map_err(|e| format!("canonicalize: {e}"))?;
    String::from_utf8(bytes).map_err(|e| format!("utf-8: {e}"))
}

fn canonical_evidence_record_payload(r: &EvidenceRecord) -> Result<String, String> {
    let value = serde_json::to_value(r).map_err(|e| format!("serde_json: {e}"))?;
    let bytes = canonicalize(&value).map_err(|e| format!("canonicalize: {e}"))?;
    String::from_utf8(bytes).map_err(|e| format!("utf-8: {e}"))
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
            additional_signatures: Vec::new(),
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

    // -- step 11 (dual-control) + step 12 (local-ephemeral-key) ---

    /// Approver-aware hooks for Phase M2 router tests. Three knobs:
    ///   * `approvers` maps `key_id` to an approver `Uuid`. Unknown
    ///     `key_id` resolves to `None` (so step 11 refuses with
    ///     `WipeRequiresDualControl`).
    ///   * `local_keys` is the set of `key_id`s the router should
    ///     treat as agent-local ephemeral keys (step 12).
    ///   * `additional_ok` controls whether `verify_additional_signature`
    ///     succeeds (true) or fails with `BadSignature` (false). Tests
    ///     use this to exercise the "additional signature did not
    ///     verify" branch independently of the distinct-approver
    ///     branch.
    struct DualControlHooks {
        approvers: std::collections::HashMap<String, Uuid>,
        local_keys: std::collections::HashSet<String>,
        additional_ok: bool,
    }

    impl DualControlHooks {
        fn new() -> Self {
            Self {
                approvers: std::collections::HashMap::new(),
                local_keys: std::collections::HashSet::new(),
                additional_ok: true,
            }
        }
        fn with_approver(mut self, key_id: &str, approver: Uuid) -> Self {
            self.approvers.insert(key_id.into(), approver);
            self
        }
        fn with_local_key(mut self, key_id: &str) -> Self {
            self.local_keys.insert(key_id.into());
            self
        }
        fn additional_invalid(mut self) -> Self {
            self.additional_ok = false;
            self
        }
    }

    impl JobValidationHooks for DualControlHooks {
        fn verify_signature(&self, _job: &SignedActionJob) -> Result<(), JobRefused> {
            Ok(())
        }
        fn action_permitted(&self, _action: ActionKind) -> bool {
            true
        }
        fn in_window(&self, _now: DateTime<Utc>) -> bool {
            true
        }
        fn verify_additional_signature(
            &self,
            _job: &SignedActionJob,
            _sig: &AdditionalSignature,
        ) -> Result<(), JobRefused> {
            if self.additional_ok {
                Ok(())
            } else {
                Err(JobRefused::BadSignature)
            }
        }
        fn approver_user_id(&self, key_id: &str) -> Option<Uuid> {
            self.approvers.get(key_id).copied()
        }
        fn is_local_ephemeral_key(&self, key_id: &str) -> bool {
            self.local_keys.contains(key_id)
        }
    }

    fn wipe_job() -> SignedActionJob {
        job_for(
            ActionKind::RemoteWipe,
            json!({
                "reason": "lost device",
                "crypto_shred_only": false,
                "wait_for_ac": false
            }),
        )
    }

    #[test]
    fn step_11_remote_wipe_single_signature_is_refused() {
        // Only the primary signature is present — dual-control
        // demands at least one *additional* approver signature.
        let alice = Uuid::from_u128(0x_a11ce);
        let hooks = DualControlHooks::new().with_approver("sn360-control-2026-05", alice);
        let r = validate(&wipe_job(), &identity(), now_in_window(), &hooks);
        assert_eq!(r.unwrap_err(), JobRefused::WipeRequiresDualControl);
    }

    #[test]
    fn step_11_remote_wipe_two_distinct_approvers_accepted() {
        let alice = Uuid::from_u128(0x_a11ce);
        let bob = Uuid::from_u128(0x_b0b);
        let mut j = wipe_job();
        j.additional_signatures.push(AdditionalSignature {
            signature: vec![1; 64],
            key_id: "sn360-control-2026-05-bob".into(),
        });
        let hooks = DualControlHooks::new()
            .with_approver("sn360-control-2026-05", alice)
            .with_approver("sn360-control-2026-05-bob", bob);
        let v = validate(&j, &identity(), now_in_window(), &hooks).expect("dual-control wipe");
        match v.args {
            JobArgs::RemoteWipe(_) => {}
            _ => panic!("wrong args variant"),
        }
    }

    #[test]
    fn step_11_remote_wipe_same_approver_twice_refused() {
        // Both signing keys belong to the same approver — distinct-
        // approver gate must reject.
        let alice = Uuid::from_u128(0x_a11ce);
        let mut j = wipe_job();
        j.additional_signatures.push(AdditionalSignature {
            signature: vec![1; 64],
            key_id: "sn360-control-2026-05-alice-2".into(),
        });
        let hooks = DualControlHooks::new()
            .with_approver("sn360-control-2026-05", alice)
            .with_approver("sn360-control-2026-05-alice-2", alice);
        let r = validate(&j, &identity(), now_in_window(), &hooks);
        assert_eq!(r.unwrap_err(), JobRefused::WipeRequiresDualControl);
    }

    #[test]
    fn step_11_remote_wipe_additional_signature_invalid_refused() {
        let alice = Uuid::from_u128(0x_a11ce);
        let bob = Uuid::from_u128(0x_b0b);
        let mut j = wipe_job();
        j.additional_signatures.push(AdditionalSignature {
            signature: vec![1; 64],
            key_id: "sn360-control-2026-05-bob".into(),
        });
        let hooks = DualControlHooks::new()
            .additional_invalid()
            .with_approver("sn360-control-2026-05", alice)
            .with_approver("sn360-control-2026-05-bob", bob);
        let r = validate(&j, &identity(), now_in_window(), &hooks);
        // BadSignature on an additional signature must surface as
        // WipeRequiresDualControl, not the bare BadSignature reason.
        assert_eq!(r.unwrap_err(), JobRefused::WipeRequiresDualControl);
    }

    #[test]
    fn step_11_remote_wipe_unknown_approver_refused() {
        // The router knows the primary signature is valid (step 4),
        // but it cannot resolve the additional signer's key_id to
        // an approver — so it must refuse rather than silently
        // accept a one-approver dual-control job.
        let alice = Uuid::from_u128(0x_a11ce);
        let mut j = wipe_job();
        j.additional_signatures.push(AdditionalSignature {
            signature: vec![1; 64],
            key_id: "rogue-key".into(),
        });
        let hooks = DualControlHooks::new().with_approver("sn360-control-2026-05", alice);
        let r = validate(&j, &identity(), now_in_window(), &hooks);
        assert_eq!(r.unwrap_err(), JobRefused::WipeRequiresDualControl);
    }

    #[test]
    fn step_12_local_ephemeral_key_allowed_actions_accepted() {
        // The auto-remediation supervisor signs three posture-fix
        // actions with the local ephemeral key. All three must pass
        // step 12.
        let hooks = DualControlHooks::new().with_local_key("sn360-local-ephemeral");
        for action in [
            ActionKind::EnableDiskEncryption,
            ActionKind::EnableFirewall,
            ActionKind::SetScreenLock,
        ] {
            let args = match action {
                ActionKind::SetScreenLock => json!({"timeout_secs": 300}),
                _ => json!({}),
            };
            let mut j = job_for(action, args);
            j.key_id = "sn360-local-ephemeral".into();
            let v = validate(&j, &identity(), now_in_window(), &hooks)
                .unwrap_or_else(|e| panic!("{action:?}: {e:?}"));
            // sanity-check the parsed args variant
            match (&v.args, action) {
                (JobArgs::EnableDiskEncryption(_), ActionKind::EnableDiskEncryption) => {}
                (JobArgs::EnableFirewall(_), ActionKind::EnableFirewall) => {}
                (JobArgs::SetScreenLock(_), ActionKind::SetScreenLock) => {}
                _ => panic!("wrong args variant for {action:?}"),
            }
        }
    }

    #[test]
    fn step_12_local_ephemeral_key_disallowed_action_refused() {
        // A local-ephemeral-key-signed `RemoteLock` is *not* in the
        // allow-list — even though step 4 (signature) would pass.
        let hooks = DualControlHooks::new().with_local_key("sn360-local-ephemeral");
        let mut j = job_for(
            ActionKind::RemoteLock,
            json!({"message": "lock it"}),
        );
        j.key_id = "sn360-local-ephemeral".into();
        let r = validate(&j, &identity(), now_in_window(), &hooks);
        assert_eq!(r.unwrap_err(), JobRefused::LocalKeyNotAuthorisedForAction);
    }

    #[test]
    fn step_12_local_ephemeral_key_with_recommendation_id_refused() {
        // The local ephemeral key never carries a recommendation_id
        // — that field is reserved for control-plane jobs. Setting
        // one alongside a local-key signature must refuse.
        let hooks = DualControlHooks::new().with_local_key("sn360-local-ephemeral");
        let mut j = job_for(ActionKind::EnableFirewall, json!({}));
        j.key_id = "sn360-local-ephemeral".into();
        j.recommendation_id = Some(Uuid::from_u128(42));
        let r = validate(&j, &identity(), now_in_window(), &hooks);
        assert_eq!(r.unwrap_err(), JobRefused::LocalKeyNotAuthorisedForAction);
    }

    #[test]
    fn default_hooks_reject_additional_signatures_with_bad_signature() {
        // The trait's default `verify_additional_signature` impl
        // returns `BadSignature`. Routers that have not opted in to
        // dual-control must therefore refuse multi-signature jobs
        // by default — the router maps that onto
        // `WipeRequiresDualControl`.
        struct OnlyPrimary;
        impl JobValidationHooks for OnlyPrimary {
            fn verify_signature(&self, _job: &SignedActionJob) -> Result<(), JobRefused> {
                Ok(())
            }
            fn action_permitted(&self, _action: ActionKind) -> bool {
                true
            }
            fn in_window(&self, _now: DateTime<Utc>) -> bool {
                true
            }
            fn approver_user_id(&self, _key_id: &str) -> Option<Uuid> {
                Some(Uuid::from_u128(7))
            }
        }
        let mut j = wipe_job();
        j.additional_signatures.push(AdditionalSignature {
            signature: vec![1; 64],
            key_id: "second".into(),
        });
        let r = validate(&j, &identity(), now_in_window(), &OnlyPrimary);
        assert_eq!(r.unwrap_err(), JobRefused::WipeRequiresDualControl);
    }

    // -- process_job / evidence-chain emission tests (task 1.13) ---

    use crate::evidence::{phase1_stub_signature, EvidenceChain, FIRST_RECORD_PREV_HASH};
    use crate::types::{ActionStatus, AgentVersion, Platform, PlatformArch, PlatformOs};

    fn platform() -> Platform {
        Platform {
            os: PlatformOs::Linux,
            version: "24.04".into(),
            arch: PlatformArch::X86_64,
            distro: Some("ubuntu".into()),
        }
    }

    fn agent_version() -> AgentVersion {
        AgentVersion {
            version: "0.10.0".into(),
            build_sha: "0123456789abcdef0123456789abcdef01234567".into(),
            channel: "stable".into(),
        }
    }

    #[test]
    fn process_job_first_record_uses_zero_sentinel_prev_hash() {
        // SCHEMAS.md § 9.1 — the very first evidence record on a
        // device's chain MUST link to FIRST_RECORD_PREV_HASH (32
        // bytes of zero).
        let mut chain = EvidenceChain::new();
        let processed = process_job(
            &happy_job(),
            &identity(),
            now_in_window(),
            &AcceptingHooks::ok(),
            &mut chain,
            &platform(),
            &agent_version(),
        );
        assert_eq!(processed.evidence.prev_record_hash, FIRST_RECORD_PREV_HASH);
        assert!(!chain.is_empty(), "chain head must advance after append");
    }

    #[test]
    fn process_job_chain_links_consecutive_records() {
        let mut chain = EvidenceChain::new();
        let a = process_job(
            &happy_job(),
            &identity(),
            now_in_window(),
            &AcceptingHooks::ok(),
            &mut chain,
            &platform(),
            &agent_version(),
        );
        let b = process_job(
            &happy_job(),
            &identity(),
            now_in_window(),
            &AcceptingHooks::ok(),
            &mut chain,
            &platform(),
            &agent_version(),
        );
        let c = process_job(
            &happy_job(),
            &identity(),
            now_in_window(),
            &AcceptingHooks::ok(),
            &mut chain,
            &platform(),
            &agent_version(),
        );
        // Each record's prev_record_hash must equal the chain_hash
        // of the immediately preceding record.
        assert_eq!(
            b.evidence.prev_record_hash,
            a.evidence.chain_hash().unwrap()
        );
        assert_eq!(
            c.evidence.prev_record_hash,
            b.evidence.chain_hash().unwrap()
        );
        // First record still pinned to the zero sentinel.
        assert_eq!(a.evidence.prev_record_hash, FIRST_RECORD_PREV_HASH);
    }

    #[test]
    fn process_job_emits_skipped_ack_for_accepted_jobs() {
        let mut chain = EvidenceChain::new();
        let processed = process_job(
            &happy_job(),
            &identity(),
            now_in_window(),
            &AcceptingHooks::ok(),
            &mut chain,
            &platform(),
            &agent_version(),
        );
        assert_eq!(processed.action_result.status, ActionStatus::Skipped);
        assert!(processed.action_result.refused_reason.is_none());
        // Refused/Skipped both have started_at == finished_at on
        // Phase 1: no executor side effect ran.
        assert_eq!(
            processed.action_result.started_at,
            processed.action_result.finished_at
        );
        // The evidence record mirrors the ActionResult's status.
        assert_eq!(processed.evidence.status, ActionStatus::Skipped);
        assert!(processed.evidence.refused_reason.is_none());
    }

    #[test]
    fn process_job_emits_refused_evidence_for_validation_failures() {
        // Phase1Stub rejects all signatures with UnknownKeyId — a
        // typical refused-job path. The router still must produce
        // an evidence record so the audit chain stays continuous.
        let mut chain = EvidenceChain::new();
        let processed = process_job(
            &happy_job(),
            &identity(),
            now_in_window(),
            &Phase1Stub,
            &mut chain,
            &platform(),
            &agent_version(),
        );
        assert_eq!(processed.action_result.status, ActionStatus::Refused);
        assert_eq!(
            processed.action_result.refused_reason,
            Some(JobRefused::UnknownKeyId)
        );
        assert_eq!(processed.evidence.status, ActionStatus::Refused);
        assert_eq!(
            processed.evidence.refused_reason,
            Some(JobRefused::UnknownKeyId)
        );
        // First refused record still uses the zero sentinel.
        assert_eq!(processed.evidence.prev_record_hash, FIRST_RECORD_PREV_HASH);
    }

    #[test]
    fn process_job_chains_refused_records_alongside_accepted_records() {
        // Mixed sequence: refused → accepted → refused. Each step
        // must link onto the previous one regardless of status.
        let mut chain = EvidenceChain::new();
        let r1 = process_job(
            &happy_job(),
            &identity(),
            now_in_window(),
            &Phase1Stub, // rejects
            &mut chain,
            &platform(),
            &agent_version(),
        );
        let r2 = process_job(
            &happy_job(),
            &identity(),
            now_in_window(),
            &AcceptingHooks::ok(), // accepts
            &mut chain,
            &platform(),
            &agent_version(),
        );
        let r3 = process_job(
            &happy_job(),
            &identity(),
            now_in_window(),
            &Phase1Stub, // rejects
            &mut chain,
            &platform(),
            &agent_version(),
        );
        assert_eq!(r1.action_result.status, ActionStatus::Refused);
        assert_eq!(r2.action_result.status, ActionStatus::Skipped);
        assert_eq!(r3.action_result.status, ActionStatus::Refused);
        // Chain links survive the status transitions.
        assert_eq!(
            r2.evidence.prev_record_hash,
            r1.evidence.chain_hash().unwrap()
        );
        assert_eq!(
            r3.evidence.prev_record_hash,
            r2.evidence.chain_hash().unwrap()
        );
    }

    #[test]
    fn process_job_evidence_pairs_with_action_result_via_evidence_id() {
        // The router must emit `(ActionResult, EvidenceRecord)`
        // pairs that share the same evidence_id so consumers can
        // correlate them downstream without parsing payload bodies.
        let mut chain = EvidenceChain::new();
        let processed = process_job(
            &happy_job(),
            &identity(),
            now_in_window(),
            &AcceptingHooks::ok(),
            &mut chain,
            &platform(),
            &agent_version(),
        );
        assert_eq!(
            processed.action_result.evidence_id,
            processed.evidence.evidence_id
        );
        assert_eq!(processed.action_result.job_id, processed.evidence.job_id);
        assert_eq!(processed.action_result.action, processed.evidence.action);
    }

    #[test]
    fn process_job_evidence_output_sha256_hashes_full_output() {
        use sha2::{Digest, Sha256};
        let mut chain = EvidenceChain::new();
        let processed = process_job(
            &happy_job(),
            &identity(),
            now_in_window(),
            &AcceptingHooks::ok(),
            &mut chain,
            &platform(),
            &agent_version(),
        );
        // The ActionResult's `output` field is bounded to 64 KiB,
        // but the evidence's `output_sha256` must hash the full
        // output bytes. In Phase 1 the no-op ack output is short
        // enough to fit, so the hashed bytes equal the bytes on
        // the ActionResult itself.
        let mut h = Sha256::new();
        h.update(processed.action_result.output.as_bytes());
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(processed.evidence.output_sha256, want);
    }

    #[test]
    fn process_job_evidence_signature_is_phase1_stub() {
        // Phase 1 places a deterministic stub signature on every
        // evidence record. Verifiers that see PHASE1_STUB_KEY_ID
        // must treat the record as untrusted, but the bytes must
        // round-trip through the canonical pre-image.
        let mut chain = EvidenceChain::new();
        let processed = process_job(
            &happy_job(),
            &identity(),
            now_in_window(),
            &AcceptingHooks::ok(),
            &mut chain,
            &platform(),
            &agent_version(),
        );
        assert_eq!(
            processed.evidence.key_id,
            crate::evidence::PHASE1_STUB_KEY_ID
        );
        assert_eq!(processed.evidence.signature.len(), 64);
        // The signature is reproducible from the canonical pre-image.
        let pre = processed.evidence.canonical_pre_image().unwrap();
        let want = phase1_stub_signature(&pre);
        assert_eq!(processed.evidence.signature, want);
    }

    #[test]
    fn process_job_evidence_args_canonical_is_rfc8785_canonical_json() {
        // The `args_canonical` field on the evidence record must be
        // the RFC 8785 canonical JSON of the originating job's
        // `args`, NOT the wire form that may have whitespace or
        // out-of-order keys.
        let job = job_for(
            ActionKind::UpdatePackage,
            // Keys are deliberately out of order to force the
            // canonical encoder to re-sort them.
            json!({"to_version": "1", "package_id": "p", "channel": "stable"}),
        );
        let mut chain = EvidenceChain::new();
        let processed = process_job(
            &job,
            &identity(),
            now_in_window(),
            &AcceptingHooks::ok(),
            &mut chain,
            &platform(),
            &agent_version(),
        );
        // Canonical JSON has keys in lexicographic order with no
        // whitespace.
        assert_eq!(
            processed.evidence.args_canonical,
            "{\"channel\":\"stable\",\"package_id\":\"p\",\"to_version\":\"1\"}"
        );
    }

    #[test]
    fn process_job_chain_resumes_from_persisted_head_on_restart() {
        // A fresh chain seeded with `with_last(prev)` (e.g. recovered
        // from disk) must produce its first new record linked to
        // `prev`, not to the zero sentinel.
        let pre_existing: [u8; 32] = [0x42; 32];
        let mut chain = EvidenceChain::with_last(pre_existing);
        let processed = process_job(
            &happy_job(),
            &identity(),
            now_in_window(),
            &AcceptingHooks::ok(),
            &mut chain,
            &platform(),
            &agent_version(),
        );
        assert_eq!(processed.evidence.prev_record_hash, pre_existing);
    }

    #[test]
    fn process_job_evidence_record_validates() {
        // Smoke test: every record produced by `process_job` must
        // pass `EvidenceRecord::validate` so it can be safely
        // appended onto the audit chain by downstream consumers.
        let mut chain = EvidenceChain::new();
        for hooks_pick in 0..2 {
            let r = if hooks_pick == 0 {
                process_job(
                    &happy_job(),
                    &identity(),
                    now_in_window(),
                    &AcceptingHooks::ok(),
                    &mut chain,
                    &platform(),
                    &agent_version(),
                )
            } else {
                process_job(
                    &happy_job(),
                    &identity(),
                    now_in_window(),
                    &Phase1Stub,
                    &mut chain,
                    &platform(),
                    &agent_version(),
                )
            };
            r.evidence.validate().expect("evidence must validate");
            r.action_result
                .validate()
                .expect("action result must validate");
        }
    }

    /// Phase 2.8 — `process_job_with_window_policy` happy path: an
    /// always-open policy delegates straight through to the regular
    /// pipeline and produces the Phase 1 skipped-ack projection.
    #[test]
    fn window_policy_always_open_passes_through_to_phase1_ack() {
        let mut chain = EvidenceChain::new();
        let processed = process_job_with_window_policy(
            &happy_job(),
            &identity(),
            now_in_window(),
            &AcceptingHooks::ok(),
            &MaintenanceWindowPolicy::always_open(),
            &mut chain,
            &platform(),
            &agent_version(),
        );
        assert_eq!(processed.action_result.status, ActionStatus::Skipped);
        assert_eq!(processed.action_result.refused_reason, None);
        assert!(
            processed.action_result.output.contains("phase1_no_op_ack"),
            "output should be the phase1 ack marker, got `{}`",
            processed.action_result.output
        );
        processed.evidence.validate().expect("evidence valid");
    }

    /// Phase 2.8 — outside the maintenance window: the wrapper
    /// produces an `ActionStatus::Skipped` ack carrying the
    /// `outside_maintenance_window` marker; the job is *not*
    /// refused, so retry semantics are preserved.
    #[test]
    fn window_policy_outside_window_returns_skipped_with_marker() {
        use sda_core::config::{MaintenanceWindow, QuietHours};
        // Window: Mon-Fri 02:00–05:00. `now_in_window` is a Thursday
        // at 08:30 — outside.
        let policy = MaintenanceWindowPolicy::from_config(
            &MaintenanceWindow {
                enabled: true,
                start: "02:00".into(),
                end: "05:00".into(),
                days: vec!["mon-fri".into()],
            },
            &QuietHours::default(),
            "UTC",
        )
        .unwrap();
        let mut chain = EvidenceChain::new();
        let processed = process_job_with_window_policy(
            &happy_job(),
            &identity(),
            now_in_window(),
            &AcceptingHooks::ok(),
            &policy,
            &mut chain,
            &platform(),
            &agent_version(),
        );
        assert_eq!(processed.action_result.status, ActionStatus::Skipped);
        assert_eq!(processed.action_result.refused_reason, None);
        assert!(
            processed
                .action_result
                .output
                .contains("outside_maintenance_window"),
            "output should carry the canonical marker, got `{}`",
            processed.action_result.output
        );
        processed.evidence.validate().expect("evidence valid");
    }

    /// Phase 2.8 — quiet hours block execution even when the
    /// maintenance window itself permits it.
    #[test]
    fn window_policy_quiet_hours_defers() {
        use sda_core::config::{MaintenanceWindow, QuietHours};
        // Maintenance: any day 00:00–23:59 (always permitted).
        // Quiet hours: 08:00–09:00. `now_in_window` is 08:30 — inside
        // quiet hours, so we expect a Defer.
        let policy = MaintenanceWindowPolicy::from_config(
            &MaintenanceWindow {
                enabled: true,
                start: "00:00".into(),
                end: "23:59".into(),
                days: vec!["mon-sun".into()],
            },
            &QuietHours {
                enabled: true,
                start: "08:00".into(),
                end: "09:00".into(),
            },
            "UTC",
        )
        .unwrap();
        let mut chain = EvidenceChain::new();
        let processed = process_job_with_window_policy(
            &happy_job(),
            &identity(),
            now_in_window(),
            &AcceptingHooks::ok(),
            &policy,
            &mut chain,
            &platform(),
            &agent_version(),
        );
        assert_eq!(processed.action_result.status, ActionStatus::Skipped);
        assert!(processed
            .action_result
            .output
            .contains("outside_maintenance_window"));
    }

    /// Phase 2.8 — a maintenance window with zero allowed days is
    /// permanently un-runnable. The wrapper should refuse rather
    /// than queue forever.
    #[test]
    fn window_policy_zero_days_refuses_with_outside_window() {
        use sda_core::config::{MaintenanceWindow, QuietHours};
        let policy = MaintenanceWindowPolicy::from_config(
            &MaintenanceWindow {
                enabled: true,
                start: "02:00".into(),
                end: "05:00".into(),
                days: vec![],
            },
            &QuietHours::default(),
            "UTC",
        )
        .unwrap();
        let mut chain = EvidenceChain::new();
        let processed = process_job_with_window_policy(
            &happy_job(),
            &identity(),
            now_in_window(),
            &AcceptingHooks::ok(),
            &policy,
            &mut chain,
            &platform(),
            &agent_version(),
        );
        assert_eq!(processed.action_result.status, ActionStatus::Refused);
        assert_eq!(
            processed.action_result.refused_reason,
            Some(JobRefused::OutsideWindow)
        );
    }
}
