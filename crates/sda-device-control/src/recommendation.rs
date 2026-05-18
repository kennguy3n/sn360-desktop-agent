//! `Recommendation` — control-plane suggestion attached to one or
//! more findings.
//!
//! Mirrors `docs/wire-protocols/device-control.md` § 6.
//!
//! The agent does **not** produce `Recommendation`s — they are
//! emitted by the control-plane Risk Engine. We define the type
//! here so the agent can decode incoming recommendations for
//! informational use (e.g. surfacing them to a future on-device
//! tray UI in Phase 4).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{ActionKind, Severity};

/// A control-plane suggestion responding to one or more findings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recommendation {
    pub recommendation_id: Uuid,
    pub tenant_id: Uuid,
    pub schema_version: u16,
    pub device_ids: Vec<Uuid>,
    pub finding_ids: Vec<Uuid>,
    pub action: ActionKind,
    pub args: serde_json::Value,
    pub plain_english: String,
    pub one_click: bool,
    pub severity: Severity,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
}

/// Hard cap on `Recommendation.plain_english` (`docs/wire-protocols/device-control.md` § 2.4).
pub const RECOMMENDATION_PLAIN_ENGLISH_MAX: usize = 512;

#[derive(Debug, thiserror::Error)]
pub enum RecommendationError {
    #[error("device_ids must contain at least one entry")]
    NoDeviceIds,
    #[error("finding_ids must contain at least one entry")]
    NoFindingIds,
    #[error("plain_english is {actual} chars; max is {max}")]
    PlainEnglishTooLong { actual: usize, max: usize },
    #[error("schema_version is {0}; this build only understands version 1")]
    SchemaVersionUnsupported(u16),
}

impl Recommendation {
    /// Validate the structural invariants from `docs/wire-protocols/device-control.md` § 6.2.
    pub fn validate(&self) -> Result<(), RecommendationError> {
        if self.schema_version != crate::version::RECOMMENDATION_SCHEMA_VERSION {
            return Err(RecommendationError::SchemaVersionUnsupported(
                self.schema_version,
            ));
        }
        if self.device_ids.is_empty() {
            return Err(RecommendationError::NoDeviceIds);
        }
        if self.finding_ids.is_empty() {
            return Err(RecommendationError::NoFindingIds);
        }
        let chars = self.plain_english.chars().count();
        if chars > RECOMMENDATION_PLAIN_ENGLISH_MAX {
            return Err(RecommendationError::PlainEnglishTooLong {
                actual: chars,
                max: RECOMMENDATION_PLAIN_ENGLISH_MAX,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn rec() -> Recommendation {
        Recommendation {
            recommendation_id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            schema_version: crate::version::RECOMMENDATION_SCHEMA_VERSION,
            device_ids: vec![Uuid::nil()],
            finding_ids: vec![Uuid::nil()],
            action: ActionKind::UpdatePackage,
            args: json!({"package_id": "p", "to_version": "1.0", "channel": "stable"}),
            plain_english: "Update p to 1.0".into(),
            one_click: true,
            severity: Severity::Medium,
            created_at: Utc.with_ymd_and_hms(2026, 5, 7, 8, 0, 0).unwrap(),
            valid_until: None,
        }
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let raw = r#"{
            "recommendation_id": "00000000-0000-0000-0000-000000000000",
            "tenant_id":         "00000000-0000-0000-0000-000000000000",
            "schema_version":    1,
            "device_ids":        ["00000000-0000-0000-0000-000000000000"],
            "finding_ids":       ["00000000-0000-0000-0000-000000000000"],
            "action":            "update_package",
            "args":              {},
            "plain_english":     "x",
            "one_click":         true,
            "severity":          "medium",
            "created_at":        "2026-05-07T08:00:00Z",
            "extra":             1
        }"#;
        assert!(serde_json::from_str::<Recommendation>(raw).is_err());
    }

    #[test]
    fn omits_none_valid_until() {
        let r = rec();
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("valid_until"));
    }

    #[test]
    fn round_trip() {
        let r = rec();
        let s = serde_json::to_string(&r).unwrap();
        let back: Recommendation = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn validate_accepts_well_formed() {
        rec().validate().unwrap();
    }

    #[test]
    fn validate_rejects_empty_device_ids() {
        let mut r = rec();
        r.device_ids.clear();
        assert!(matches!(
            r.validate(),
            Err(RecommendationError::NoDeviceIds)
        ));
    }

    #[test]
    fn validate_rejects_empty_finding_ids() {
        let mut r = rec();
        r.finding_ids.clear();
        assert!(matches!(
            r.validate(),
            Err(RecommendationError::NoFindingIds)
        ));
    }

    #[test]
    fn validate_rejects_oversize_plain_english() {
        let mut r = rec();
        r.plain_english = "x".repeat(513);
        let err = r.validate().unwrap_err();
        assert!(matches!(
            err,
            RecommendationError::PlainEnglishTooLong {
                actual: 513,
                max: 512
            }
        ));
    }

    #[test]
    fn validate_rejects_unsupported_version() {
        let mut r = rec();
        r.schema_version = 2;
        assert!(matches!(
            r.validate(),
            Err(RecommendationError::SchemaVersionUnsupported(2))
        ));
    }
}
