//! `Finding` — an observation produced by the agent.
//!
//! Mirrors `docs/wire-protocols/device-control.md` § 5.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{FindingKind, Severity};

/// A single observation the control plane should consider for risk
/// scoring or recommendations.
///
/// Findings are **idempotent by `finding_id`**: the agent re-uses
/// the same UUID for the same logical finding across re-emits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    /// Stable finding identity; UUIDv7 (time-ordered).
    pub finding_id: Uuid,
    /// Identity of the device that produced the finding.
    pub device_id: Uuid,
    /// Tenant the device belongs to.
    pub tenant_id: Uuid,
    /// Schema version (see [`crate::version::FINDING_SCHEMA_VERSION`]).
    pub schema_version: u16,
    /// What kind of finding this is.
    pub kind: FindingKind,
    /// Severity classification.
    pub severity: Severity,
    /// Human-readable, SME-targeted explanation; ≤ 512 chars.
    pub plain_english: String,
    /// Compact structured detail; ≤ 16 KiB serialised. Shape is
    /// determined by `kind` (see docs/wire-protocols/device-control.md § 5.3).
    pub evidence: serde_json::Value,
    /// When the agent observed the underlying state.
    pub observed_at: DateTime<Utc>,
    /// Optional: the queries / posture probes / inventory diff
    /// that produced this finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_refs: Option<Vec<SourceRef>>,
}

/// Forensic re-walk reference (docs/wire-protocols/device-control.md § 5.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    pub engine: String,
    pub reference: String,
}

/// Hard cap on `Finding.plain_english` (docs/wire-protocols/device-control.md § 2.4).
pub const FINDING_PLAIN_ENGLISH_MAX: usize = 512;

/// Hard cap on `Finding.evidence` serialised size (docs/wire-protocols/device-control.md § 2.4).
pub const FINDING_EVIDENCE_MAX_BYTES: usize = 16 * 1024;

/// Errors detected when building a `Finding` locally before it
/// goes on the wire.
///
/// The router translates these into `JobRefused` reasons where
/// applicable; producers (e.g. `sda-posture`) use them to keep
/// over-cap or malformed findings off the bus entirely.
#[derive(Debug, thiserror::Error)]
pub enum FindingError {
    #[error("plain_english is empty but severity = {0:?} requires it")]
    PlainEnglishRequired(Severity),
    #[error("plain_english is {actual} chars; max is {max}")]
    PlainEnglishTooLong { actual: usize, max: usize },
    #[error("evidence is {actual} bytes; max is {max}")]
    EvidenceTooLarge { actual: usize, max: usize },
    #[error("evidence is invalid JSON for kind {kind:?}: {detail}")]
    EvidenceInvalidShape { kind: FindingKind, detail: String },
    #[error("schema_version is {0}; this build only understands version 1")]
    SchemaVersionUnsupported(u16),
}

impl Finding {
    /// Validate the structural invariants from docs/wire-protocols/device-control.md § 5.2.
    ///
    /// This deliberately does **not** check semantic invariants
    /// (e.g. `tenant_id == self_tenant_id`). Those are bus / router
    /// concerns and live in [`crate::router`].
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema_version != crate::version::FINDING_SCHEMA_VERSION {
            return Err(FindingError::SchemaVersionUnsupported(self.schema_version));
        }
        let len = self.plain_english.chars().count();
        if len > FINDING_PLAIN_ENGLISH_MAX {
            return Err(FindingError::PlainEnglishTooLong {
                actual: len,
                max: FINDING_PLAIN_ENGLISH_MAX,
            });
        }
        if matches!(
            self.severity,
            Severity::Medium | Severity::High | Severity::Critical
        ) && self.plain_english.trim().is_empty()
        {
            return Err(FindingError::PlainEnglishRequired(self.severity));
        }
        let evidence_bytes = serde_json::to_vec(&self.evidence)
            .map_err(|e| FindingError::EvidenceInvalidShape {
                kind: self.kind,
                detail: e.to_string(),
            })?
            .len();
        if evidence_bytes > FINDING_EVIDENCE_MAX_BYTES {
            return Err(FindingError::EvidenceTooLarge {
                actual: evidence_bytes,
                max: FINDING_EVIDENCE_MAX_BYTES,
            });
        }
        validate_evidence_shape(self.kind, &self.evidence)?;
        Ok(())
    }
}

/// Validate that `evidence` matches the per-kind shape table in
/// docs/wire-protocols/device-control.md § 5.3.
///
/// Phase 1 enforces *structural* presence of the required keys
/// (e.g. `package` for `OutdatedApp`), not full type correctness —
/// the control plane Risk Engine is the canonical validator. We
/// accept extra fields here because the JSON blob may carry forward
/// debugging context; the wire's `deny_unknown_fields` only applies
/// to the outer `Finding` struct.
pub(crate) fn validate_evidence_shape(
    kind: FindingKind,
    evidence: &serde_json::Value,
) -> Result<(), FindingError> {
    let obj = match evidence {
        serde_json::Value::Object(m) => m,
        _ if matches!(kind, FindingKind::Other) => return Ok(()),
        _ => {
            return Err(FindingError::EvidenceInvalidShape {
                kind,
                detail: "expected a JSON object".into(),
            });
        }
    };
    let required: &[&str] = match kind {
        FindingKind::PermanentAdmin => &["admins"],
        FindingKind::OutdatedApp => &["package", "current_version", "available_version"],
        FindingKind::DeviceMissing => &["last_checkin_at", "missed_intervals"],
        FindingKind::UnapprovedSoftware => &["package", "version", "approval_state"],
        FindingKind::AdminAccessRequested => &["requested_by", "duration_minutes"],
        FindingKind::PostureViolation => &["control", "expected", "actual"],
        FindingKind::VulnerabilityMatch => &["cve", "package", "version"],
        FindingKind::AdminDrift => &["drift_kind", "user"],
        FindingKind::DeviceControlBundleVerificationFailure => &["reason"],
        // --- Desktop MDM findings (Phase M1–M3) ---
        FindingKind::DiskEncryptionOff => &["detected_at"],
        FindingKind::FirewallOff => &["detected_at"],
        FindingKind::ScreenLockOff => &["detected_at"],
        FindingKind::OsPatchOverdue => &["missing_count"],
        FindingKind::RecoveryKeyNotEscrowed => &["detected_at"],
        FindingKind::DeviceLost => &["reported_at"],
        FindingKind::ConfigProfileTampered => &["profile_id", "reason"],
        FindingKind::Other => &[],
    };
    for &key in required {
        if !obj.contains_key(key) {
            return Err(FindingError::EvidenceInvalidShape {
                kind,
                detail: format!("missing required key `{key}`"),
            });
        }
    }
    Ok(())
}

/// Render the canonical SME-facing description for a `Finding`.
///
/// Used by producers to populate `plain_english` consistently. The
/// helper is deliberately minimal — translation lives in the
/// control-plane UI; the agent only needs an English baseline so
/// operators can read offline evidence dumps.
pub fn render_plain_english(kind: FindingKind, evidence: &serde_json::Value) -> String {
    fn s<'a>(v: &'a serde_json::Value, key: &str) -> Option<&'a str> {
        v.get(key)?.as_str()
    }
    fn n(v: &serde_json::Value, key: &str) -> Option<i64> {
        v.get(key)?.as_i64()
    }
    match kind {
        // --- Desktop MDM findings (Phase M1–M3) ---
        FindingKind::DiskEncryptionOff => {
            "Disk encryption is OFF — enable BitLocker / FileVault / LUKS.".to_string()
        }
        FindingKind::FirewallOff => {
            "Host firewall is OFF — enable Windows Defender Firewall / pf / nftables.".to_string()
        }
        FindingKind::ScreenLockOff => {
            "Screen lock is disabled — enforce automatic lock on idle.".to_string()
        }
        FindingKind::OsPatchOverdue => {
            let missing = n(evidence, "missing_count").unwrap_or(0);
            format!(
                "{missing} OS security patch{} overdue — install during next maintenance window.",
                if missing == 1 { " is" } else { "es are" }
            )
        }
        FindingKind::RecoveryKeyNotEscrowed => {
            "Disk-encryption recovery key has not been escrowed to the control plane.".to_string()
        }
        FindingKind::DeviceLost => {
            "Device reported as lost — remote lock / lost-mode active.".to_string()
        }
        FindingKind::ConfigProfileTampered => {
            let id = s(evidence, "profile_id").unwrap_or("(unknown)");
            format!(
                "Config profile {id} failed signature verification — previous profile retained."
            )
        }
        FindingKind::PermanentAdmin => {
            let count = evidence
                .get("admins")
                .and_then(|a| a.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            format!(
                "{count} permanent admin{} on this device — review and convert to JIT.",
                if count == 1 { "" } else { "s" }
            )
        }
        FindingKind::OutdatedApp => {
            let pkg = s(evidence, "package").unwrap_or("(unknown package)");
            let cur = s(evidence, "current_version").unwrap_or("?");
            let avail = s(evidence, "available_version").unwrap_or("?");
            format!("{pkg} is on {cur}; {avail} is available — update recommended.")
        }
        FindingKind::DeviceMissing => {
            let missed = n(evidence, "missed_intervals").unwrap_or(0);
            format!(
                "Device has missed {missed} consecutive check-in interval{}.",
                if missed == 1 { "" } else { "s" }
            )
        }
        FindingKind::UnapprovedSoftware => {
            let pkg = s(evidence, "package").unwrap_or("(unknown package)");
            let v = s(evidence, "version").unwrap_or("?");
            format!("{pkg} {v} is not on the approved software list.")
        }
        FindingKind::AdminAccessRequested => {
            let user = s(evidence, "requested_by").unwrap_or("(unknown user)");
            let mins = n(evidence, "duration_minutes").unwrap_or(0);
            format!("{user} requested admin access for {mins} minute(s).")
        }
        FindingKind::PostureViolation => {
            let control = s(evidence, "control").unwrap_or("(unknown)");
            let expected = s(evidence, "expected").unwrap_or("(?)");
            let actual = s(evidence, "actual").unwrap_or("(?)");
            format!("{control} posture is {actual}; expected {expected}.")
        }
        FindingKind::VulnerabilityMatch => {
            let cve = s(evidence, "cve").unwrap_or("(unknown CVE)");
            let pkg = s(evidence, "package").unwrap_or("(unknown package)");
            let ver = s(evidence, "version").unwrap_or("?");
            format!("{cve} affects {pkg} {ver}.")
        }
        FindingKind::AdminDrift => {
            let dk = s(evidence, "drift_kind").unwrap_or("unknown");
            let user = s(evidence, "user").unwrap_or("(unknown)");
            match dk {
                "untracked_admin" => {
                    format!("{user} has admin rights but no tracked JIT grant — possible drift.")
                }
                "missing_privilege" => {
                    format!("{user} has a tracked grant but admin rights were externally removed.")
                }
                _ => format!("Admin drift detected for {user} (kind: {dk})."),
            }
        }
        FindingKind::DeviceControlBundleVerificationFailure => {
            let reason = s(evidence, "reason").unwrap_or("unknown reason");
            format!("USB-policy bundle verification failed: {reason}.")
        }
        FindingKind::Other => "Engine-specific finding — see evidence for detail.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;
    use uuid::Uuid;

    fn finding(kind: FindingKind, evidence: serde_json::Value) -> Finding {
        Finding {
            finding_id: Uuid::nil(),
            device_id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            schema_version: crate::version::FINDING_SCHEMA_VERSION,
            kind,
            severity: Severity::Low,
            plain_english: "ok".into(),
            evidence,
            observed_at: Utc.with_ymd_and_hms(2026, 5, 7, 8, 0, 0).unwrap(),
            source_refs: None,
        }
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let raw = r#"{
            "finding_id": "00000000-0000-0000-0000-000000000000",
            "device_id":  "00000000-0000-0000-0000-000000000000",
            "tenant_id":  "00000000-0000-0000-0000-000000000000",
            "schema_version": 1,
            "kind": "permanent_admin",
            "severity": "low",
            "plain_english": "x",
            "evidence": {"admins": []},
            "observed_at": "2026-05-07T08:00:00Z",
            "extra_field_that_should_not_exist": true
        }"#;
        assert!(serde_json::from_str::<Finding>(raw).is_err());
    }

    #[test]
    fn omits_none_source_refs_on_serialize() {
        let f = finding(FindingKind::Other, json!({}));
        let s = serde_json::to_string(&f).unwrap();
        assert!(!s.contains("source_refs"));
    }

    #[test]
    fn round_trips_through_serde_json() {
        let f = finding(
            FindingKind::PermanentAdmin,
            json!({"admins": [{"user": "alice", "since": "2026-01-01T00:00:00Z", "via": "local"}]}),
        );
        let s = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&s).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn validate_accepts_well_formed_low_severity_finding() {
        let f = finding(FindingKind::PermanentAdmin, json!({"admins": []}));
        f.validate().expect("should be valid");
    }

    #[test]
    fn validate_rejects_wrong_schema_version() {
        let mut f = finding(FindingKind::PermanentAdmin, json!({"admins": []}));
        f.schema_version = 999;
        let err = f.validate().unwrap_err();
        assert!(matches!(err, FindingError::SchemaVersionUnsupported(999)));
    }

    #[test]
    fn validate_rejects_oversize_plain_english() {
        let mut f = finding(FindingKind::PermanentAdmin, json!({"admins": []}));
        f.plain_english = "x".repeat(513);
        let err = f.validate().unwrap_err();
        assert!(
            matches!(
                err,
                FindingError::PlainEnglishTooLong {
                    actual: 513,
                    max: 512
                }
            ),
            "got {err:?}",
        );
    }

    #[test]
    fn validate_requires_plain_english_on_high_severity() {
        let mut f = finding(FindingKind::PermanentAdmin, json!({"admins": []}));
        f.severity = Severity::High;
        f.plain_english = "  ".into();
        let err = f.validate().unwrap_err();
        assert!(matches!(
            err,
            FindingError::PlainEnglishRequired(Severity::High)
        ));
    }

    #[test]
    fn validate_allows_empty_plain_english_on_low_severity() {
        let mut f = finding(FindingKind::PermanentAdmin, json!({"admins": []}));
        f.severity = Severity::Info;
        f.plain_english = String::new();
        f.validate()
            .expect("info severity allows empty plain_english");
    }

    #[test]
    fn validate_rejects_oversize_evidence() {
        let huge: Vec<u8> = vec![b'a'; 17 * 1024];
        let mut f = finding(
            FindingKind::Other,
            json!({"blob": String::from_utf8(huge).unwrap()}),
        );
        f.severity = Severity::Info;
        f.plain_english = String::new();
        let err = f.validate().unwrap_err();
        assert!(matches!(err, FindingError::EvidenceTooLarge { .. }));
    }

    #[test]
    fn validate_evidence_shape_for_each_kind() {
        validate_evidence_shape(FindingKind::PermanentAdmin, &json!({"admins": []})).unwrap();
        validate_evidence_shape(
            FindingKind::OutdatedApp,
            &json!({
                "package": "p",
                "current_version": "1",
                "available_version": "2"
            }),
        )
        .unwrap();
        validate_evidence_shape(
            FindingKind::PostureViolation,
            &json!({"control": "BitLocker", "expected": "on", "actual": "off"}),
        )
        .unwrap();
        validate_evidence_shape(FindingKind::Other, &json!("string-is-fine-for-other")).unwrap();
        validate_evidence_shape(
            FindingKind::AdminDrift,
            &json!({"drift_kind": "untracked_admin", "user": "alice"}),
        )
        .unwrap();
    }

    #[test]
    fn validate_evidence_shape_rejects_missing_keys() {
        let err = validate_evidence_shape(FindingKind::OutdatedApp, &json!({"package": "p"}));
        assert!(matches!(
            err,
            Err(FindingError::EvidenceInvalidShape { .. })
        ));
    }

    #[test]
    fn validate_evidence_shape_rejects_non_object_for_strict_kinds() {
        let err = validate_evidence_shape(FindingKind::OutdatedApp, &json!("nope"));
        assert!(matches!(
            err,
            Err(FindingError::EvidenceInvalidShape { .. })
        ));
    }

    #[test]
    fn render_plain_english_handles_all_kinds() {
        let cases: &[(FindingKind, serde_json::Value, &str)] = &[
            (
                FindingKind::PermanentAdmin,
                json!({"admins": [{}, {}]}),
                "2 permanent admins",
            ),
            (
                FindingKind::OutdatedApp,
                json!({"package": "Acme", "current_version": "1.0", "available_version": "2.0"}),
                "Acme is on 1.0",
            ),
            (
                FindingKind::DeviceMissing,
                json!({"missed_intervals": 4}),
                "4 consecutive check-in interval",
            ),
            (
                FindingKind::UnapprovedSoftware,
                json!({"package": "X", "version": "1"}),
                "X 1 is not on the approved",
            ),
            (
                FindingKind::AdminAccessRequested,
                json!({"requested_by": "alice", "duration_minutes": 30}),
                "alice requested admin access",
            ),
            (
                FindingKind::PostureViolation,
                json!({"control": "BitLocker", "expected": "on", "actual": "off"}),
                "BitLocker posture is off",
            ),
            (
                FindingKind::VulnerabilityMatch,
                json!({"cve": "CVE-2026-1", "package": "P", "version": "1"}),
                "CVE-2026-1 affects P 1",
            ),
            (
                FindingKind::AdminDrift,
                json!({"drift_kind": "untracked_admin", "user": "alice"}),
                "alice has admin rights but no tracked JIT grant",
            ),
            (FindingKind::Other, json!({}), "Engine-specific"),
        ];
        for (k, e, expect) in cases {
            let got = render_plain_english(*k, e);
            assert!(
                got.contains(expect),
                "render_plain_english({:?}) = {:?}, expected substring {:?}",
                k,
                got,
                expect
            );
        }
    }

    #[test]
    fn render_plain_english_singular_admin() {
        let s = render_plain_english(FindingKind::PermanentAdmin, &json!({"admins": [{}]}));
        assert!(s.starts_with("1 permanent admin "), "got {s}");
    }
}
