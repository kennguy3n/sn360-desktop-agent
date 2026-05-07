//! `ActionResult` — the agent's structured report of what happened
//! when a `SignedActionJob` ran.
//!
//! Mirrors `docs/device-control/SCHEMAS.md` § 8.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{ActionKind, ActionStatus, JobRefused};

/// Hard cap on `ActionResult.output` (SCHEMAS.md § 2.4).
pub const ACTION_RESULT_OUTPUT_MAX_BYTES: usize = 64 * 1024;

/// Truncation marker prepended to truncated `output` so log readers
/// can spot the truncation without consulting `output_truncated`.
pub const TRUNCATION_MARKER: &str = "[output truncated — full bytes hashed in evidence] ";

/// The agent's report of what happened when a `SignedActionJob` ran.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionResult {
    pub job_id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub schema_version: u16,
    pub action: ActionKind,
    pub status: ActionStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused_reason: Option<JobRefused>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub output: String,
    pub output_truncated: bool,
    pub evidence_id: Uuid,
}

#[derive(Debug, thiserror::Error)]
pub enum ActionResultError {
    #[error("schema_version is {0}; this build only understands version 1")]
    SchemaVersionUnsupported(u16),
    #[error("started_at must be ≤ finished_at")]
    BadTimeOrder,
    #[error("status = Refused requires refused_reason to be Some(_)")]
    MissingRefusedReason,
    #[error("status = {0:?} forbids refused_reason being Some(_)")]
    UnexpectedRefusedReason(ActionStatus),
    #[error("status = Refused requires started_at == finished_at (no side effect ran)")]
    RefusedHadSideEffect,
    #[error("output is {actual} bytes; max is {max}")]
    OutputTooLarge { actual: usize, max: usize },
}

impl ActionResult {
    /// Validate the structural invariants from SCHEMAS.md § 8.2.
    pub fn validate(&self) -> Result<(), ActionResultError> {
        if self.schema_version != crate::version::ACTION_RESULT_SCHEMA_VERSION {
            return Err(ActionResultError::SchemaVersionUnsupported(
                self.schema_version,
            ));
        }
        if self.started_at > self.finished_at {
            return Err(ActionResultError::BadTimeOrder);
        }
        match self.status {
            ActionStatus::Refused => {
                if self.refused_reason.is_none() {
                    return Err(ActionResultError::MissingRefusedReason);
                }
                if self.started_at != self.finished_at {
                    return Err(ActionResultError::RefusedHadSideEffect);
                }
            }
            other => {
                if self.refused_reason.is_some() {
                    return Err(ActionResultError::UnexpectedRefusedReason(other));
                }
            }
        }
        if self.output.len() > ACTION_RESULT_OUTPUT_MAX_BYTES {
            return Err(ActionResultError::OutputTooLarge {
                actual: self.output.len(),
                max: ACTION_RESULT_OUTPUT_MAX_BYTES,
            });
        }
        Ok(())
    }
}

/// Truncate `output` to `ACTION_RESULT_OUTPUT_MAX_BYTES` if needed.
///
/// Returns `(possibly_truncated, was_truncated)`. The truncation
/// marker is prepended so consumers can spot the loss without
/// consulting `output_truncated`. Callers should pair this with
/// the SHA-256 of the original full bytes for the matching
/// `EvidenceRecord.output_sha256`.
pub fn bound_output(output: String) -> (String, bool) {
    if output.len() <= ACTION_RESULT_OUTPUT_MAX_BYTES {
        return (output, false);
    }
    // Slice on a UTF-8 char boundary to avoid panicking on multi-
    // byte sequences. We over-truncate by up to 3 bytes in the
    // worst case (UTF-8 sequences are at most 4 bytes long), but
    // never under-truncate.
    let mut limit = ACTION_RESULT_OUTPUT_MAX_BYTES.saturating_sub(TRUNCATION_MARKER.len());
    while limit > 0 && !output.is_char_boundary(limit) {
        limit -= 1;
    }
    let head = &output[..limit];
    let mut s = String::with_capacity(TRUNCATION_MARKER.len() + head.len());
    s.push_str(TRUNCATION_MARKER);
    s.push_str(head);
    (s, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ok_result() -> ActionResult {
        let t = Utc.with_ymd_and_hms(2026, 5, 7, 8, 30, 0).unwrap();
        ActionResult {
            job_id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            device_id: Uuid::nil(),
            schema_version: crate::version::ACTION_RESULT_SCHEMA_VERSION,
            action: ActionKind::UpdatePackage,
            status: ActionStatus::Success,
            refused_reason: None,
            started_at: t,
            finished_at: t + chrono::Duration::seconds(13),
            exit_code: Some(0),
            output: "ok".into(),
            output_truncated: false,
            evidence_id: Uuid::nil(),
        }
    }

    fn refused_result() -> ActionResult {
        let t = Utc.with_ymd_and_hms(2026, 5, 7, 8, 30, 0).unwrap();
        ActionResult {
            job_id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            device_id: Uuid::nil(),
            schema_version: crate::version::ACTION_RESULT_SCHEMA_VERSION,
            action: ActionKind::UpdatePackage,
            status: ActionStatus::Refused,
            refused_reason: Some(JobRefused::Expired),
            started_at: t,
            finished_at: t,
            exit_code: None,
            output: "expired".into(),
            output_truncated: false,
            evidence_id: Uuid::nil(),
        }
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let raw = r#"{
            "job_id":"00000000-0000-0000-0000-000000000000",
            "tenant_id":"00000000-0000-0000-0000-000000000000",
            "device_id":"00000000-0000-0000-0000-000000000000",
            "schema_version":1,
            "action":"update_package",
            "status":"success",
            "started_at":"2026-05-07T08:30:00Z",
            "finished_at":"2026-05-07T08:30:00Z",
            "output":"",
            "output_truncated":false,
            "evidence_id":"00000000-0000-0000-0000-000000000000",
            "extra":1
        }"#;
        assert!(serde_json::from_str::<ActionResult>(raw).is_err());
    }

    #[test]
    fn omits_none_optional_fields() {
        let r = ok_result();
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("refused_reason"));
        let s2 = serde_json::to_string(&refused_result()).unwrap();
        assert!(s2.contains("refused_reason"));
    }

    #[test]
    fn round_trip() {
        for r in [ok_result(), refused_result()] {
            let s = serde_json::to_string(&r).unwrap();
            let back: ActionResult = serde_json::from_str(&s).unwrap();
            assert_eq!(back, r);
        }
    }

    #[test]
    fn validate_accepts_well_formed() {
        ok_result().validate().unwrap();
        refused_result().validate().unwrap();
    }

    #[test]
    fn validate_rejects_bad_time_order() {
        let mut r = ok_result();
        std::mem::swap(&mut r.started_at, &mut r.finished_at);
        // Now started_at > finished_at by 13 seconds.
        assert!(matches!(r.validate(), Err(ActionResultError::BadTimeOrder)));
    }

    #[test]
    fn validate_rejects_refused_without_reason() {
        let mut r = refused_result();
        r.refused_reason = None;
        assert!(matches!(
            r.validate(),
            Err(ActionResultError::MissingRefusedReason)
        ));
    }

    #[test]
    fn validate_rejects_success_with_refused_reason() {
        let mut r = ok_result();
        r.refused_reason = Some(JobRefused::Expired);
        assert!(matches!(
            r.validate(),
            Err(ActionResultError::UnexpectedRefusedReason(
                ActionStatus::Success
            ))
        ));
    }

    #[test]
    fn validate_rejects_refused_with_side_effect() {
        let mut r = refused_result();
        r.finished_at = r.started_at + chrono::Duration::seconds(1);
        assert!(matches!(
            r.validate(),
            Err(ActionResultError::RefusedHadSideEffect)
        ));
    }

    #[test]
    fn validate_rejects_oversize_output() {
        let mut r = ok_result();
        r.output = "x".repeat(64 * 1024 + 1);
        assert!(matches!(
            r.validate(),
            Err(ActionResultError::OutputTooLarge { .. })
        ));
    }

    #[test]
    fn bound_output_passes_through_short_strings() {
        let (s, truncated) = bound_output("short".into());
        assert_eq!(s, "short");
        assert!(!truncated);
    }

    #[test]
    fn bound_output_truncates_long_strings_with_marker() {
        let big = "a".repeat(70 * 1024);
        let (s, truncated) = bound_output(big);
        assert!(truncated);
        assert!(s.starts_with(TRUNCATION_MARKER));
        assert!(s.len() <= ACTION_RESULT_OUTPUT_MAX_BYTES);
    }

    #[test]
    fn bound_output_does_not_split_utf8() {
        // Build a string of repeated 4-byte CJK chars whose total
        // byte length exceeds the cap, then truncate.
        let mut s = String::new();
        while s.len() < ACTION_RESULT_OUTPUT_MAX_BYTES + 16 {
            s.push('𠮷'); // 4-byte UTF-8
        }
        let (out, _) = bound_output(s);
        // String must be valid UTF-8 (Rust enforces this) and not
        // exceed the cap.
        assert!(out.len() <= ACTION_RESULT_OUTPUT_MAX_BYTES);
    }
}
