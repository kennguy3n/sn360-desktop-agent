//! Evidence emission for software install / update / uninstall /
//! rollback actions (Task 2.11).
//!
//! Per `docs/device-control/SCHEMAS.md` § 9 every software action
//! the agent executes — successful or otherwise — produces an
//! [`EvidenceRecord`] hash-linked into the device's evidence chain.
//! This module is the software-side wrapper around the canonical
//! [`build_signed_evidence_record`] helper from `sda-device-control`:
//! it bookkeeps the chain head, hashes the *full* (un-truncated)
//! command output, and exposes a small adapter type
//! ([`SoftwareActionOutcome`]) that the orchestrator uses regardless
//! of whether the action came from `PackageManager::install`,
//! `update`, `uninstall`, or a [`crate::rollback`] re-install.
//!
//! ## Chain semantics
//!
//! [`SoftwareEvidenceEmitter`] holds an [`EvidenceChain`] and produces
//! a sequence of records whose `prev_record_hash` chains forward:
//!
//! ```text
//! record_0.prev_record_hash = ZERO_SENTINEL
//! record_1.prev_record_hash = record_0.chain_hash
//! record_2.prev_record_hash = record_1.chain_hash
//! ```
//!
//! The chain head can be persisted across agent restarts via
//! [`SoftwareEvidenceEmitter::chain_head`] and re-hydrated with
//! [`SoftwareEvidenceEmitter::resume_with_head`].
//!
//! ## Rollback evidence
//!
//! When an `UpdatePackage` action fails the orchestrator records two
//! evidence rows:
//!
//! 1. The failed `UpdatePackage` itself (status = `Failure`,
//!    `exit_code = Some(non-zero)`).
//! 2. A follow-up record whose `action` is `UpdatePackage` and whose
//!    output references the [`crate::rollback::RollbackOutcome`] —
//!    so the chain captures *both* the breakage and the recovery
//!    attempt without inventing a new wire-level action kind.
//!
//! The two records share the same `job_id` but have distinct
//! `evidence_id`s, which keeps existing chain-validation logic
//! happy.

use chrono::{DateTime, Utc};
use sda_device_control::action_result::ActionResult;
use sda_device_control::evidence::{
    build_signed_evidence_record, sha256, EvidenceChain, EvidenceContext, EvidenceError,
    EvidenceRecord,
};
use sda_device_control::signed_job::SignedActionJob;
use sda_device_control::types::{ActionKind, ActionStatus, AgentVersion, Platform};

use crate::rollback::RollbackOutcome;

/// Outcome the action orchestrator hands the emitter for each
/// `PackageManager` invocation. Mirrors what would otherwise be a
/// raw `Result<(), PackageError>` plus the bookkeeping fields
/// required by [`EvidenceRecord`].
#[derive(Debug, Clone)]
pub struct SoftwareActionOutcome {
    /// Which install / update / uninstall flavour this is.
    pub action: ActionKind,
    /// Stable PAL package id the action targeted.
    pub package_id: String,
    /// Optional version string. `None` means "manager's default".
    pub version: Option<String>,
    /// `Some(0)` on success, `Some(n)` for a wrapped CLI exit code,
    /// or `None` when the underlying error was infrastructural and
    /// did not surface a numeric exit code.
    pub exit_code: Option<i32>,
    /// Combined stdout + stderr bytes captured from the package
    /// manager. The emitter hashes the *full* slice into
    /// `output_sha256`; the action orchestrator is responsible for
    /// truncating into `ActionResult.output` before this point.
    pub output_full: Vec<u8>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
}

impl SoftwareActionOutcome {
    /// Convenience: did the underlying package manager succeed?
    pub fn succeeded(&self) -> bool {
        matches!(self.exit_code, Some(0))
    }

    /// Map the outcome to the [`ActionStatus`] the
    /// [`EvidenceRecord::status`] field requires.
    pub fn action_status(&self) -> ActionStatus {
        if self.succeeded() {
            ActionStatus::Success
        } else {
            ActionStatus::Failure
        }
    }
}

/// Stateful emitter holding the per-device evidence chain and
/// producing one record per software action.
///
/// Construct with [`Self::new`] for a fresh agent or
/// [`Self::resume_with_head`] when restoring chain state from disk.
#[derive(Debug, Clone, Default)]
pub struct SoftwareEvidenceEmitter {
    chain: EvidenceChain,
}

impl SoftwareEvidenceEmitter {
    /// Fresh emitter — first record will link to the zero sentinel.
    pub fn new() -> Self {
        Self {
            chain: EvidenceChain::new(),
        }
    }

    /// Resume from a persisted chain head.
    pub fn resume_with_head(last_chain_hash: [u8; 32]) -> Self {
        Self {
            chain: EvidenceChain::with_last(last_chain_hash),
        }
    }

    /// SHA-256 of the most-recently-appended record. `None` until
    /// at least one record has been emitted.
    pub fn chain_head(&self) -> Option<[u8; 32]> {
        if self.chain.is_empty() {
            None
        } else {
            Some(self.chain.next_prev_hash())
        }
    }

    /// True iff no records have been emitted yet.
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Build, sign (Phase 1 stub), and append a single evidence
    /// record covering one install / update / uninstall action.
    pub fn record_action(
        &mut self,
        job: &SignedActionJob,
        result: &ActionResult,
        outcome: &SoftwareActionOutcome,
        platform: Platform,
        agent: AgentVersion,
    ) -> Result<EvidenceRecord, EvidenceError> {
        let args_canonical = canonical_args_string(job)?;
        let ctx = EvidenceContext {
            args_canonical,
            output_full: &outcome.output_full,
            platform,
            agent,
        };
        let record = build_signed_evidence_record(job, result, &self.chain, ctx)?;
        self.chain.append(&record)?;
        Ok(record)
    }

    /// Append the *follow-up* evidence for a failed update that
    /// triggered a rollback attempt. The returned record references
    /// the same `job_id` but a fresh `evidence_id` (taken from the
    /// caller-supplied `result`) so chain validation still treats it
    /// as a distinct row.
    pub fn record_rollback(
        &mut self,
        job: &SignedActionJob,
        result: &ActionResult,
        rollback: &RollbackOutcome,
        platform: Platform,
        agent: AgentVersion,
    ) -> Result<EvidenceRecord, EvidenceError> {
        let args_canonical = canonical_args_string(job)?;
        let payload = serde_json::to_vec(rollback)?;
        let ctx = EvidenceContext {
            args_canonical,
            output_full: &payload,
            platform,
            agent,
        };
        let record = build_signed_evidence_record(job, result, &self.chain, ctx)?;
        self.chain.append(&record)?;
        Ok(record)
    }
}

/// Compute the RFC 8785 canonical-JSON encoding of a job's `args`,
/// returning it as a UTF-8 string for inclusion in
/// [`EvidenceRecord::args_canonical`].
fn canonical_args_string(job: &SignedActionJob) -> Result<String, EvidenceError> {
    let value = serde_json::to_value(&job.args)?;
    let bytes = sda_device_control::canonicalize_json(&value)?;
    Ok(String::from_utf8(bytes).expect("canonicalize_json emits ASCII-only bytes"))
}

/// SHA-256 helper re-exported for parity with
/// [`sda_device_control::evidence::sha256`]. Useful for tests that
/// want to assert on the `output_sha256` field without re-importing.
pub fn output_sha256(bytes: &[u8]) -> [u8; 32] {
    sha256(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_device_control::action_result::ActionResult;
    use sda_device_control::types::{PlatformArch, PlatformOs};
    use uuid::Uuid;

    fn fixed_now() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 5, 7, 12, 0, 0).unwrap()
    }

    fn platform() -> Platform {
        Platform {
            os: PlatformOs::Linux,
            version: "24.04".into(),
            arch: PlatformArch::X86_64,
            distro: Some("ubuntu".into()),
        }
    }

    fn agent() -> AgentVersion {
        AgentVersion {
            version: "0.10.0".into(),
            build_sha: "abc123".into(),
            channel: "stable".into(),
        }
    }

    fn job(action: ActionKind, package_id: &str) -> SignedActionJob {
        let args = serde_json::json!({
            "package_id": package_id,
            "version": "1.0",
            "channel": "stable",
            "source_url": "https://example.test/p-1.0.pkg",
            "sha256": "0".repeat(64),
        });
        SignedActionJob {
            job_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
            schema_version: sda_device_control::SIGNED_ACTION_JOB_SCHEMA_VERSION,
            recommendation_id: None,
            action,
            args,
            not_before: fixed_now(),
            not_after: fixed_now() + chrono::Duration::hours(1),
            signature: vec![0u8; 64],
            key_id: "test-key".into(),
            correlation_id: None,
            additional_signatures: Vec::new(),
        }
    }

    fn ok_result(action: ActionKind, job: &SignedActionJob) -> ActionResult {
        ActionResult {
            evidence_id: Uuid::new_v4(),
            tenant_id: job.tenant_id,
            device_id: job.device_id,
            schema_version: sda_device_control::ACTION_RESULT_SCHEMA_VERSION,
            job_id: job.job_id,
            action,
            started_at: fixed_now(),
            finished_at: fixed_now() + chrono::Duration::seconds(2),
            status: ActionStatus::Success,
            refused_reason: None,
            exit_code: Some(0),
            output: "ok".into(),
            output_truncated: false,
        }
    }

    fn fail_result(action: ActionKind, job: &SignedActionJob) -> ActionResult {
        ActionResult {
            evidence_id: Uuid::new_v4(),
            tenant_id: job.tenant_id,
            device_id: job.device_id,
            schema_version: sda_device_control::ACTION_RESULT_SCHEMA_VERSION,
            job_id: job.job_id,
            action,
            started_at: fixed_now(),
            finished_at: fixed_now() + chrono::Duration::seconds(2),
            status: ActionStatus::Failure,
            refused_reason: None,
            exit_code: Some(1),
            output: "boom".into(),
            output_truncated: false,
        }
    }

    fn outcome(action: ActionKind, exit: Option<i32>, body: &[u8]) -> SoftwareActionOutcome {
        SoftwareActionOutcome {
            action,
            package_id: "p".into(),
            version: Some("1.0".into()),
            exit_code: exit,
            output_full: body.to_vec(),
            started_at: fixed_now(),
            finished_at: fixed_now() + chrono::Duration::seconds(2),
        }
    }

    #[test]
    fn records_install_evidence_with_correct_action_and_hash() {
        let mut emitter = SoftwareEvidenceEmitter::new();
        let job = job(ActionKind::InstallPackage, "p");
        let result = ok_result(ActionKind::InstallPackage, &job);
        let outcome = outcome(ActionKind::InstallPackage, Some(0), b"install ok");
        let rec = emitter
            .record_action(&job, &result, &outcome, platform(), agent())
            .unwrap();
        assert_eq!(rec.action, ActionKind::InstallPackage);
        assert_eq!(rec.exit_code, Some(0));
        assert_eq!(rec.output_sha256, output_sha256(b"install ok"));
        assert_eq!(rec.platform.os, PlatformOs::Linux);
        rec.validate().expect("schema-valid");
        assert!(emitter.chain_head().is_some());
    }

    #[test]
    fn chain_links_two_consecutive_actions() {
        let mut emitter = SoftwareEvidenceEmitter::new();
        let job_a = job(ActionKind::InstallPackage, "a");
        let result_a = ok_result(ActionKind::InstallPackage, &job_a);
        let outcome_a = outcome(ActionKind::InstallPackage, Some(0), b"a");
        let rec_a = emitter
            .record_action(&job_a, &result_a, &outcome_a, platform(), agent())
            .unwrap();
        let head_after_a = emitter.chain_head().unwrap();

        let job_b = job(ActionKind::UninstallPackage, "b");
        let result_b = ok_result(ActionKind::UninstallPackage, &job_b);
        let outcome_b = outcome(ActionKind::UninstallPackage, Some(0), b"b");
        let rec_b = emitter
            .record_action(&job_b, &result_b, &outcome_b, platform(), agent())
            .unwrap();

        assert_eq!(rec_b.prev_record_hash, rec_a.chain_hash().unwrap());
        assert_eq!(emitter.chain_head().unwrap(), rec_b.chain_hash().unwrap());
        assert_ne!(head_after_a, emitter.chain_head().unwrap());
    }

    #[test]
    fn failed_update_then_rollback_emits_two_records_with_same_job_id() {
        let mut emitter = SoftwareEvidenceEmitter::new();
        let job = job(ActionKind::UpdatePackage, "p");
        // 1) The failed UpdatePackage itself.
        let fail = fail_result(ActionKind::UpdatePackage, &job);
        let fail_outcome = outcome(ActionKind::UpdatePackage, Some(1), b"update failed");
        let rec_failed = emitter
            .record_action(&job, &fail, &fail_outcome, platform(), agent())
            .unwrap();
        // 2) The rollback follow-up.
        let rollback = RollbackOutcome {
            job_id: job.job_id,
            package_id: "p".into(),
            previous_version: Some("1.0".into()),
            succeeded: true,
            message: "rolled back".into(),
            attempted_at: fixed_now(),
        };
        // Synthesize a result for the rollback row (caller supplies
        // a fresh evidence_id but reuses the originating job_id).
        let mut rollback_result = ok_result(ActionKind::UpdatePackage, &job);
        rollback_result.evidence_id = Uuid::new_v4();
        rollback_result.exit_code = Some(0);
        rollback_result.output = rollback.to_canonical_json();

        let rec_rb = emitter
            .record_rollback(&job, &rollback_result, &rollback, platform(), agent())
            .unwrap();

        assert_eq!(rec_failed.job_id, rec_rb.job_id);
        assert_ne!(rec_failed.evidence_id, rec_rb.evidence_id);
        assert_eq!(rec_rb.prev_record_hash, rec_failed.chain_hash().unwrap());
        rec_failed.validate().unwrap();
        rec_rb.validate().unwrap();
    }

    #[test]
    fn resume_with_head_picks_up_chain_state() {
        // Build a record on a fresh emitter and grab its chain
        // hash, then emit a second record on a *resumed* emitter
        // and check the linkage is correct.
        let mut emitter1 = SoftwareEvidenceEmitter::new();
        let job1 = job(ActionKind::InstallPackage, "p");
        let result1 = ok_result(ActionKind::InstallPackage, &job1);
        let outcome1 = outcome(ActionKind::InstallPackage, Some(0), b"x");
        let rec1 = emitter1
            .record_action(&job1, &result1, &outcome1, platform(), agent())
            .unwrap();

        let mut emitter2 = SoftwareEvidenceEmitter::resume_with_head(rec1.chain_hash().unwrap());
        assert!(!emitter2.is_empty());
        let job2 = job(ActionKind::UninstallPackage, "p");
        let result2 = ok_result(ActionKind::UninstallPackage, &job2);
        let outcome2 = outcome(ActionKind::UninstallPackage, Some(0), b"y");
        let rec2 = emitter2
            .record_action(&job2, &result2, &outcome2, platform(), agent())
            .unwrap();
        assert_eq!(rec2.prev_record_hash, rec1.chain_hash().unwrap());
    }

    #[test]
    fn outcome_action_status_maps_zero_to_success_and_nonzero_to_failure() {
        let mut o = outcome(ActionKind::InstallPackage, Some(0), b"");
        assert_eq!(o.action_status(), ActionStatus::Success);
        o.exit_code = Some(2);
        assert_eq!(o.action_status(), ActionStatus::Failure);
        o.exit_code = None;
        assert_eq!(o.action_status(), ActionStatus::Failure);
    }
}
