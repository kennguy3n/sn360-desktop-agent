//! Schema version constants for Device Control.
//!
//! Mirrors `docs/wire-protocols/device-control.md` § 10
//! ("Versioning"). Bumping any of these constants is a major
//! protocol change requiring a new clean-room ADR per
//! `docs/licensing.md` § 7.3 (Device Control — clean-room
//! rationale) and `docs/device-control.md` § 11 (Clean-room
//! policy).

/// Schema version stamped on every emitted `Finding`.
pub const FINDING_SCHEMA_VERSION: u16 = 1;

/// Schema version stamped on every `Recommendation` accepted by the
/// agent.
pub const RECOMMENDATION_SCHEMA_VERSION: u16 = 1;

/// Schema version stamped on every `SignedActionJob` accepted by
/// the agent.
pub const SIGNED_ACTION_JOB_SCHEMA_VERSION: u16 = 1;

/// Schema version stamped on every `ActionResult` emitted by the
/// agent.
pub const ACTION_RESULT_SCHEMA_VERSION: u16 = 1;

/// Schema version stamped on every `EvidenceRecord` emitted by the
/// agent.
pub const EVIDENCE_RECORD_SCHEMA_VERSION: u16 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_phase1_versions_are_one() {
        // Phase 1 ships at v1 across the board. If this assertion
        // fires, you must update `docs/wire-protocols/device-control.md` § 10 and add a new ADR.
        assert_eq!(FINDING_SCHEMA_VERSION, 1);
        assert_eq!(RECOMMENDATION_SCHEMA_VERSION, 1);
        assert_eq!(SIGNED_ACTION_JOB_SCHEMA_VERSION, 1);
        assert_eq!(ACTION_RESULT_SCHEMA_VERSION, 1);
        assert_eq!(EVIDENCE_RECORD_SCHEMA_VERSION, 1);
    }
}
