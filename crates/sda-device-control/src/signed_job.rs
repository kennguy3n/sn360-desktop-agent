//! `SignedActionJob` — Ed25519-signed instruction the agent will
//! execute.
//!
//! Mirrors `docs/device-control/SCHEMAS.md` § 7.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::ActionKind;

/// Hard cap on `SignedActionJob.args` serialised size (SCHEMAS.md
/// § 2.4).
pub const SIGNED_JOB_ARGS_MAX_BYTES: usize = 64 * 1024;

/// `GrantJitAdmin.duration_minutes` cap from PROPOSAL.md § 14.
pub const GRANT_JIT_ADMIN_MAX_DURATION_MINUTES: u32 = 480;

/// `RunScript.timeout_seconds` cap from PROPOSAL.md § 14.
pub const RUN_SCRIPT_MAX_TIMEOUT_SECONDS: u32 = 30 * 60;

/// `StartRemoteSupport.max_duration_minutes` cap from PROPOSAL.md
/// § 14.
pub const START_REMOTE_SUPPORT_MAX_DURATION_MINUTES: u32 = 240;

/// `QueryAdHoc.max_rows` cap (PROPOSAL.md § 6.1).
pub const QUERY_AD_HOC_MAX_ROWS: u32 = 10_000;

/// An Ed25519-signed instruction the control plane has issued to
/// this agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedActionJob {
    pub job_id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub schema_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation_id: Option<Uuid>,
    pub action: ActionKind,
    pub args: serde_json::Value,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub signature: Vec<u8>,
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<Uuid>,
    /// Additional signatures for dual-control actions (e.g.
    /// `RemoteWipe`). The router enforces `signatures.len() >= 2`
    /// for any action that requires dual control — see
    /// `router::validate` step 11 (ARCHITECTURE.md § 4.4 of
    /// `docs/desktop-mdm/`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_signatures: Vec<AdditionalSignature>,
}

/// Second-and-onward approver signatures over the same canonical
/// payload as `SignedActionJob.signature`. The primary signature is
/// always carried inline on the parent struct so existing wire-
/// format consumers keep round-tripping. Distinct approver enforcement
/// happens in the router (different `key_id`s must resolve to
/// different `approver_user_id`s through `JobValidationHooks`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdditionalSignature {
    pub signature: Vec<u8>,
    pub key_id: String,
}

/// Errors raised when parsing or validating a `SignedActionJob`
/// before the router pipeline runs.
///
/// These errors map onto the [`crate::types::JobRefused`] reasons in
/// SCHEMAS.md § 8.3 — see [`crate::router`] for the mapping.
#[derive(Debug, thiserror::Error)]
pub enum SignedJobError {
    #[error("schema_version is {0}; this build only understands version 1")]
    SchemaVersionUnsupported(u16),
    #[error("args serialised to {actual} bytes; max is {max}")]
    ArgsTooLarge { actual: usize, max: usize },
    #[error("not_before > not_after — invalid window")]
    InvalidWindow,
    #[error("args parse error for action {action:?}: {detail}")]
    ArgsParseError { action: ActionKind, detail: String },
}

impl SignedActionJob {
    /// Validate the structural invariants from SCHEMAS.md § 7 that
    /// don't require external state (key store, clock, tenant id).
    /// Run inside `router::validate` after step 2.
    pub fn validate_structure(&self) -> Result<(), SignedJobError> {
        if self.schema_version != crate::version::SIGNED_ACTION_JOB_SCHEMA_VERSION {
            return Err(SignedJobError::SchemaVersionUnsupported(
                self.schema_version,
            ));
        }
        let bytes = serde_json::to_vec(&self.args)
            .map_err(|e| SignedJobError::ArgsParseError {
                action: self.action,
                detail: e.to_string(),
            })?
            .len();
        if bytes > SIGNED_JOB_ARGS_MAX_BYTES {
            return Err(SignedJobError::ArgsTooLarge {
                actual: bytes,
                max: SIGNED_JOB_ARGS_MAX_BYTES,
            });
        }
        if self.not_before > self.not_after {
            return Err(SignedJobError::InvalidWindow);
        }
        Ok(())
    }

    /// Parse `args` against the per-`ActionKind` strict struct
    /// (SCHEMAS.md § 7.3). Step 10 of the validation pipeline.
    pub fn parse_args(&self) -> Result<JobArgs, SignedJobError> {
        JobArgs::parse(self.action, &self.args).map_err(|detail| SignedJobError::ArgsParseError {
            action: self.action,
            detail,
        })
    }
}

// === Per-ActionKind args sub-schemas ==================================

/// Args for `RemoteWipe`. Both fields are advisory — the agent
/// always performs the strongest available wipe (crypto-shred + OS
/// factory reset) but honours `wait_for_ac` when present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteWipeArgs {
    /// Reason text retained in the evidence record.
    pub reason: String,
    /// If true, skip the slow overwrite pass and rely on crypto-shred.
    #[serde(default)]
    pub crypto_shred_only: bool,
    /// If true, defer until the device is on AC power.
    #[serde(default)]
    pub wait_for_ac: bool,
}

/// Args for `RemoteLock`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteLockArgs {
    /// User-facing message shown on the lock screen (truncated to 240
    /// chars by the agent).
    #[serde(default)]
    pub message: String,
}

/// Args for `EnterLostMode`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterLostModeArgs {
    pub message: String,
}

/// Args for `ExitLostMode`. No payload — keep an empty struct so
/// `deny_unknown_fields` still rejects garbage.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitLostModeArgs {}

/// Args for `EscrowRecoveryKey`. The agent ignores everything except
/// `force`; including the field lets the control plane request a
/// re-escrow without the agent silently de-duplicating.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowRecoveryKeyArgs {
    #[serde(default)]
    pub force: bool,
}

/// Args for `InstallOsUpdate`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallOsUpdateArgs {
    #[serde(default = "yes")]
    pub include_security: bool,
    #[serde(default)]
    pub include_feature: bool,
    /// One of `"never"`, `"if_required"`, `"force"`. The agent
    /// translates this to `pal::mdm::RebootPolicy`.
    #[serde(default = "default_reboot_policy")]
    pub reboot_policy: String,
}

fn yes() -> bool {
    true
}
fn default_reboot_policy() -> String {
    "never".to_string()
}

/// Args for `ApplyConfigProfile`. The actual signed profile body is
/// fetched out-of-band (TRDS bundle), so this struct only carries
/// the descriptor used to look it up.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyConfigProfileArgs {
    pub profile_id: Uuid,
    /// Lowercase hex SHA-256 of the canonical profile body. Must
    /// match what `MdmProvider::apply_config_profile` ultimately
    /// sees on disk.
    pub profile_sha256: String,
}

/// Args for `EnableDiskEncryption`. No payload.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnableDiskEncryptionArgs {}

/// Args for `EnableFirewall`. No payload.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnableFirewallArgs {}

/// Args for `SetScreenLock`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetScreenLockArgs {
    pub timeout_secs: u32,
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallPackageArgs {
    pub package_id: String,
    pub version: String,
    pub channel: String,
    pub source_url: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePackageArgs {
    pub package_id: String,
    pub to_version: String,
    pub channel: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UninstallPackageArgs {
    pub package_id: String,
    /// Either a literal version like `"1.2.3"` or `"*"` for any.
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantJitAdminArgs {
    pub user: String,
    pub duration_minutes: u32,
    pub reason: String,
    pub approver_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeAdminArgs {
    pub user: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunScriptArgs {
    pub script_id: String,
    pub script_sha256: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub timeout_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushAppControlPolicyArgs {
    pub policy_id: Uuid,
    pub policy_sha256: String,
    pub policy_url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRemoteSupportArgs {
    pub operator_id: Uuid,
    pub session_id: Uuid,
    pub consent_required: bool,
    pub max_duration_minutes: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndRemoteSupportArgs {
    pub session_id: Uuid,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryAdHocArgs {
    pub query_id: Uuid,
    pub engine: String,
    pub sql: String,
    pub max_rows: u32,
}

/// Strongly-typed envelope around the parsed `args` for one job.
#[derive(Debug, Clone, PartialEq)]
pub enum JobArgs {
    InstallPackage(InstallPackageArgs),
    UpdatePackage(UpdatePackageArgs),
    UninstallPackage(UninstallPackageArgs),
    GrantJitAdmin(GrantJitAdminArgs),
    RevokeAdmin(RevokeAdminArgs),
    RunScript(RunScriptArgs),
    PushAppControlPolicy(PushAppControlPolicyArgs),
    StartRemoteSupport(StartRemoteSupportArgs),
    EndRemoteSupport(EndRemoteSupportArgs),
    QueryAdHoc(QueryAdHocArgs),
    // --- Desktop MDM args (Phase M1–M3) ---
    RemoteWipe(RemoteWipeArgs),
    RemoteLock(RemoteLockArgs),
    EnterLostMode(EnterLostModeArgs),
    ExitLostMode(ExitLostModeArgs),
    EscrowRecoveryKey(EscrowRecoveryKeyArgs),
    InstallOsUpdate(InstallOsUpdateArgs),
    ApplyConfigProfile(ApplyConfigProfileArgs),
    EnableDiskEncryption(EnableDiskEncryptionArgs),
    EnableFirewall(EnableFirewallArgs),
    SetScreenLock(SetScreenLockArgs),
}

impl JobArgs {
    fn parse(action: ActionKind, args: &serde_json::Value) -> Result<Self, String> {
        fn from_value<T>(args: &serde_json::Value) -> Result<T, String>
        where
            T: for<'de> Deserialize<'de>,
        {
            serde_json::from_value::<T>(args.clone()).map_err(|e| e.to_string())
        }
        let parsed = match action {
            ActionKind::InstallPackage => JobArgs::InstallPackage(from_value(args)?),
            ActionKind::UpdatePackage => JobArgs::UpdatePackage(from_value(args)?),
            ActionKind::UninstallPackage => JobArgs::UninstallPackage(from_value(args)?),
            ActionKind::GrantJitAdmin => {
                let v: GrantJitAdminArgs = from_value(args)?;
                if v.duration_minutes == 0 {
                    return Err("duration_minutes must be > 0".into());
                }
                if v.duration_minutes > GRANT_JIT_ADMIN_MAX_DURATION_MINUTES {
                    return Err(format!(
                        "duration_minutes = {} exceeds cap of {}",
                        v.duration_minutes, GRANT_JIT_ADMIN_MAX_DURATION_MINUTES
                    ));
                }
                JobArgs::GrantJitAdmin(v)
            }
            ActionKind::RevokeAdmin => JobArgs::RevokeAdmin(from_value(args)?),
            ActionKind::RunScript => {
                let v: RunScriptArgs = from_value(args)?;
                if v.timeout_seconds == 0 {
                    return Err("timeout_seconds must be > 0".into());
                }
                if v.timeout_seconds > RUN_SCRIPT_MAX_TIMEOUT_SECONDS {
                    return Err(format!(
                        "timeout_seconds = {} exceeds cap of {}",
                        v.timeout_seconds, RUN_SCRIPT_MAX_TIMEOUT_SECONDS
                    ));
                }
                if !is_lower_hex_64(&v.script_sha256) {
                    return Err("script_sha256 must be 64 lowercase hex chars".into());
                }
                JobArgs::RunScript(v)
            }
            ActionKind::PushAppControlPolicy => {
                let v: PushAppControlPolicyArgs = from_value(args)?;
                if !is_lower_hex_64(&v.policy_sha256) {
                    return Err("policy_sha256 must be 64 lowercase hex chars".into());
                }
                JobArgs::PushAppControlPolicy(v)
            }
            ActionKind::StartRemoteSupport => {
                let v: StartRemoteSupportArgs = from_value(args)?;
                if v.max_duration_minutes == 0 {
                    return Err("max_duration_minutes must be > 0".into());
                }
                if v.max_duration_minutes > START_REMOTE_SUPPORT_MAX_DURATION_MINUTES {
                    return Err(format!(
                        "max_duration_minutes = {} exceeds cap of {}",
                        v.max_duration_minutes, START_REMOTE_SUPPORT_MAX_DURATION_MINUTES
                    ));
                }
                JobArgs::StartRemoteSupport(v)
            }
            ActionKind::EndRemoteSupport => JobArgs::EndRemoteSupport(from_value(args)?),
            ActionKind::QueryAdHoc => {
                let v: QueryAdHocArgs = from_value(args)?;
                if v.max_rows == 0 {
                    return Err("max_rows must be > 0".into());
                }
                if v.max_rows > QUERY_AD_HOC_MAX_ROWS {
                    return Err(format!(
                        "max_rows = {} exceeds cap of {}",
                        v.max_rows, QUERY_AD_HOC_MAX_ROWS
                    ));
                }
                JobArgs::QueryAdHoc(v)
            }
            // --- Desktop MDM action args (Phase M1–M3) ---
            ActionKind::RemoteWipe => {
                let v: RemoteWipeArgs = from_value(args)?;
                if v.reason.trim().is_empty() {
                    return Err("reason must be non-empty".into());
                }
                JobArgs::RemoteWipe(v)
            }
            ActionKind::RemoteLock => {
                let mut v: RemoteLockArgs = from_value(args)?;
                // Truncate over-long lock-screen messages so the OS
                // backend never has to worry about it.
                if v.message.len() > 240 {
                    v.message.truncate(240);
                }
                JobArgs::RemoteLock(v)
            }
            ActionKind::EnterLostMode => {
                let v: EnterLostModeArgs = from_value(args)?;
                if v.message.trim().is_empty() {
                    return Err("message must be non-empty".into());
                }
                JobArgs::EnterLostMode(v)
            }
            ActionKind::ExitLostMode => JobArgs::ExitLostMode(from_value(args)?),
            ActionKind::EscrowRecoveryKey => JobArgs::EscrowRecoveryKey(from_value(args)?),
            ActionKind::InstallOsUpdate => {
                let v: InstallOsUpdateArgs = from_value(args)?;
                if !matches!(v.reboot_policy.as_str(), "never" | "if_required" | "force") {
                    return Err(format!(
                        "reboot_policy = {:?}; expected never|if_required|force",
                        v.reboot_policy
                    ));
                }
                JobArgs::InstallOsUpdate(v)
            }
            ActionKind::ApplyConfigProfile => {
                let v: ApplyConfigProfileArgs = from_value(args)?;
                if !is_lower_hex_64(&v.profile_sha256) {
                    return Err("profile_sha256 must be 64 lowercase hex chars".into());
                }
                JobArgs::ApplyConfigProfile(v)
            }
            ActionKind::EnableDiskEncryption => {
                JobArgs::EnableDiskEncryption(from_value(args)?)
            }
            ActionKind::EnableFirewall => JobArgs::EnableFirewall(from_value(args)?),
            ActionKind::SetScreenLock => {
                let v: SetScreenLockArgs = from_value(args)?;
                if v.timeout_secs == 0 || v.timeout_secs > 3600 {
                    return Err(format!(
                        "timeout_secs = {}; must be in 1..=3600",
                        v.timeout_secs
                    ));
                }
                JobArgs::SetScreenLock(v)
            }
        };
        Ok(parsed)
    }
}

fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn job(action: ActionKind, args: serde_json::Value) -> SignedActionJob {
        SignedActionJob {
            job_id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            device_id: Uuid::nil(),
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

    #[test]
    fn rejects_unknown_top_level_field() {
        let raw = r#"{
            "job_id":"00000000-0000-0000-0000-000000000000",
            "tenant_id":"00000000-0000-0000-0000-000000000000",
            "device_id":"00000000-0000-0000-0000-000000000000",
            "schema_version":1,
            "action":"update_package",
            "args":{},
            "not_before":"2026-05-07T08:00:00Z",
            "not_after":"2026-05-07T09:00:00Z",
            "signature":[],
            "key_id":"k",
            "extra":1
        }"#;
        assert!(serde_json::from_str::<SignedActionJob>(raw).is_err());
    }

    #[test]
    fn omits_none_optional_fields() {
        let j = job(ActionKind::UpdatePackage, json!({}));
        let s = serde_json::to_string(&j).unwrap();
        assert!(!s.contains("recommendation_id"));
        assert!(!s.contains("correlation_id"));
    }

    #[test]
    fn round_trip() {
        let j = job(ActionKind::UpdatePackage, json!({}));
        let s = serde_json::to_string(&j).unwrap();
        let back: SignedActionJob = serde_json::from_str(&s).unwrap();
        assert_eq!(back, j);
    }

    #[test]
    fn validate_structure_rejects_invalid_window() {
        let mut j = job(ActionKind::UpdatePackage, json!({}));
        std::mem::swap(&mut j.not_before, &mut j.not_after);
        assert!(matches!(
            j.validate_structure(),
            Err(SignedJobError::InvalidWindow)
        ));
    }

    #[test]
    fn validate_structure_rejects_bad_version() {
        let mut j = job(ActionKind::UpdatePackage, json!({}));
        j.schema_version = 99;
        assert!(matches!(
            j.validate_structure(),
            Err(SignedJobError::SchemaVersionUnsupported(99))
        ));
    }

    #[test]
    fn parse_update_package_strict() {
        let j = job(
            ActionKind::UpdatePackage,
            json!({"package_id": "p", "to_version": "1", "channel": "stable"}),
        );
        let parsed = j.parse_args().unwrap();
        match parsed {
            JobArgs::UpdatePackage(a) => {
                assert_eq!(a.package_id, "p");
                assert_eq!(a.to_version, "1");
                assert_eq!(a.channel, "stable");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_update_package_rejects_extra_field() {
        let j = job(
            ActionKind::UpdatePackage,
            json!({"package_id": "p", "to_version": "1", "channel": "stable", "extra": true}),
        );
        let err = j.parse_args().unwrap_err();
        assert!(matches!(err, SignedJobError::ArgsParseError { .. }));
    }

    #[test]
    fn parse_grant_jit_admin_enforces_duration_cap() {
        let j = job(
            ActionKind::GrantJitAdmin,
            json!({
                "user": "alice",
                "duration_minutes": 720,
                "reason": "test",
                "approver_id": "00000000-0000-0000-0000-000000000000"
            }),
        );
        let err = j.parse_args().unwrap_err();
        assert!(matches!(err, SignedJobError::ArgsParseError { .. }));
    }

    #[test]
    fn parse_grant_jit_admin_rejects_zero_duration() {
        let j = job(
            ActionKind::GrantJitAdmin,
            json!({
                "user": "alice",
                "duration_minutes": 0,
                "reason": "test",
                "approver_id": "00000000-0000-0000-0000-000000000000"
            }),
        );
        let err = j.parse_args().unwrap_err();
        assert!(matches!(err, SignedJobError::ArgsParseError { .. }));
    }

    #[test]
    fn parse_run_script_requires_lower_hex_sha() {
        let j = job(
            ActionKind::RunScript,
            json!({
                "script_id": "sid",
                "script_sha256": "NOT-HEX",
                "args": [],
                "timeout_seconds": 30
            }),
        );
        assert!(matches!(
            j.parse_args(),
            Err(SignedJobError::ArgsParseError { .. })
        ));
    }

    #[test]
    fn parse_run_script_accepts_canonical_sha256() {
        let j = job(
            ActionKind::RunScript,
            json!({
                "script_id": "sid",
                "script_sha256": "a".repeat(64),
                "args": ["--flag"],
                "timeout_seconds": 30
            }),
        );
        let parsed = j.parse_args().unwrap();
        match parsed {
            JobArgs::RunScript(a) => {
                assert_eq!(a.script_id, "sid");
                assert_eq!(a.timeout_seconds, 30);
                assert_eq!(a.args, vec!["--flag".to_string()]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_run_script_rejects_oversize_timeout() {
        let j = job(
            ActionKind::RunScript,
            json!({
                "script_id": "sid",
                "script_sha256": "a".repeat(64),
                "args": [],
                "timeout_seconds": 9999
            }),
        );
        assert!(matches!(
            j.parse_args(),
            Err(SignedJobError::ArgsParseError { .. })
        ));
    }

    #[test]
    fn parse_query_ad_hoc_caps_max_rows() {
        let j = job(
            ActionKind::QueryAdHoc,
            json!({
                "query_id": "00000000-0000-0000-0000-000000000000",
                "engine": "osquery",
                "sql": "SELECT 1",
                "max_rows": 999_999
            }),
        );
        assert!(matches!(
            j.parse_args(),
            Err(SignedJobError::ArgsParseError { .. })
        ));
    }

    #[test]
    fn parse_start_remote_support_caps_duration() {
        let j = job(
            ActionKind::StartRemoteSupport,
            json!({
                "operator_id": "00000000-0000-0000-0000-000000000000",
                "session_id": "00000000-0000-0000-0000-000000000000",
                "consent_required": true,
                "max_duration_minutes": 999
            }),
        );
        assert!(matches!(
            j.parse_args(),
            Err(SignedJobError::ArgsParseError { .. })
        ));
    }

    #[test]
    fn parse_remote_wipe_requires_reason() {
        let j = job(
            ActionKind::RemoteWipe,
            json!({"reason": "", "crypto_shred_only": false, "wait_for_ac": false}),
        );
        assert!(matches!(
            j.parse_args(),
            Err(SignedJobError::ArgsParseError { .. })
        ));
    }

    #[test]
    fn parse_remote_wipe_accepts_valid_args() {
        let j = job(
            ActionKind::RemoteWipe,
            json!({"reason": "theft", "crypto_shred_only": true}),
        );
        let parsed = j.parse_args().unwrap();
        match parsed {
            JobArgs::RemoteWipe(a) => {
                assert_eq!(a.reason, "theft");
                assert!(a.crypto_shred_only);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_remote_lock_truncates_long_messages() {
        let long = "x".repeat(500);
        let j = job(ActionKind::RemoteLock, json!({"message": long}));
        let parsed = j.parse_args().unwrap();
        match parsed {
            JobArgs::RemoteLock(a) => assert_eq!(a.message.len(), 240),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_set_screen_lock_rejects_zero_timeout() {
        let j = job(ActionKind::SetScreenLock, json!({"timeout_secs": 0}));
        assert!(matches!(
            j.parse_args(),
            Err(SignedJobError::ArgsParseError { .. })
        ));
    }

    #[test]
    fn parse_install_os_update_rejects_unknown_reboot_policy() {
        let j = job(
            ActionKind::InstallOsUpdate,
            json!({"reboot_policy": "sometimes"}),
        );
        assert!(matches!(
            j.parse_args(),
            Err(SignedJobError::ArgsParseError { .. })
        ));
    }

    #[test]
    fn parse_apply_config_profile_requires_hex_sha() {
        let j = job(
            ActionKind::ApplyConfigProfile,
            json!({
                "profile_id": "00000000-0000-0000-0000-000000000000",
                "profile_sha256": "NOT-HEX",
            }),
        );
        assert!(matches!(
            j.parse_args(),
            Err(SignedJobError::ArgsParseError { .. })
        ));
    }

    #[test]
    fn additional_signatures_default_empty_and_skipped() {
        let j = job(ActionKind::UpdatePackage, json!({}));
        let s = serde_json::to_string(&j).unwrap();
        assert!(
            !s.contains("additional_signatures"),
            "empty additional_signatures must be skipped on the wire"
        );
    }

    #[test]
    fn additional_signatures_round_trip() {
        let mut j = job(
            ActionKind::RemoteWipe,
            json!({"reason": "theft"}),
        );
        j.additional_signatures.push(AdditionalSignature {
            signature: vec![1; 64],
            key_id: "approver-b".into(),
        });
        let s = serde_json::to_string(&j).unwrap();
        let back: SignedActionJob = serde_json::from_str(&s).unwrap();
        assert_eq!(back, j);
    }

    #[test]
    fn args_too_large_is_detected() {
        let big = json!({"blob": "x".repeat(70 * 1024)});
        let j = job(ActionKind::UpdatePackage, big);
        let err = j.validate_structure().unwrap_err();
        assert!(matches!(err, SignedJobError::ArgsTooLarge { .. }));
    }
}
