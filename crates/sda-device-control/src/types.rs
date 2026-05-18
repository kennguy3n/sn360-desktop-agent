//! Shared type appendix for the Device Control schemas.
//!
//! Mirrors the encoding conventions, identifiers, time, and bounded-
//! size rules in `docs/wire-protocols/device-control.md` §§ 1–4.
//! These types are the canonical Rust representations of the wire
//! shapes; they are serialised via `serde` (camel-case for enum
//! tags is `rename_all = "snake_case"`, matching the wire spec).

use serde::{Deserialize, Serialize};

/// Severity ladder, aligned with `crates/sda-local-detection`.
///
/// `docs/wire-protocols/device-control.md` § 3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Operating-system family.
///
/// `docs/wire-protocols/device-control.md` § 3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformOs {
    Windows,
    Macos,
    Linux,
}

/// CPU architecture.
///
/// `docs/wire-protocols/device-control.md` § 3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformArch {
    #[serde(rename = "x86_64")]
    X86_64,
    Aarch64,
    I686,
    Armv7,
}

/// Platform descriptor recorded with every `EvidenceRecord`.
///
/// `docs/wire-protocols/device-control.md` § 3.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Platform {
    pub os: PlatformOs,
    pub version: String,
    pub arch: PlatformArch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distro: Option<String>,
}

/// Agent version captured at execution time.
///
/// `docs/wire-protocols/device-control.md` § 3.3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentVersion {
    pub version: String,
    pub build_sha: String,
    pub channel: String,
}

/// Closed enumeration of finding kinds.
///
/// `docs/wire-protocols/device-control.md` § 3.4. Phase 1 shipped the first eight variants;
/// `AdminDrift` was added in Phase 3 to surface JIT-admin drift
/// findings emitted by `sda-jit-admin::drift::DriftDetector`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    PermanentAdmin,
    OutdatedApp,
    DeviceMissing,
    UnapprovedSoftware,
    AdminAccessRequested,
    PostureViolation,
    VulnerabilityMatch,
    /// JIT-admin drift: an OS-level admin account is not tracked by
    /// the local grant ledger, OR a tracked grant's user is no
    /// longer in the OS-level admin group. Emitted by
    /// `sda-jit-admin::drift::DriftDetector` per `docs/device-control.md` § 7.
    AdminDrift,
    /// USB / removable-media policy bundle verification failure
    /// (Phase D2.7). Emitted when a freshly-pulled bundle slice
    /// cannot be parsed or its metadata sentinel is missing —
    /// the agent keeps the previously-applied policy set in
    /// effect (closed-by-default) and surfaces the failure as a
    /// high-severity finding so the dashboard can alert.
    DeviceControlBundleVerificationFailure,
    // --- Desktop MDM findings (Phase M1–M3) ---
    DiskEncryptionOff,
    FirewallOff,
    ScreenLockOff,
    OsPatchOverdue,
    RecoveryKeyNotEscrowed,
    DeviceLost,
    /// A signed config profile failed Ed25519 verification.
    ConfigProfileTampered,
    Other,
}

/// What a `SignedActionJob` will do.
///
/// `docs/wire-protocols/device-control.md` § 3.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    InstallPackage,
    UpdatePackage,
    UninstallPackage,
    GrantJitAdmin,
    RevokeAdmin,
    RunScript,
    PushAppControlPolicy,
    StartRemoteSupport,
    EndRemoteSupport,
    QueryAdHoc,
    // --- Desktop MDM actions (Phase M1–M3) ---
    RemoteWipe,
    RemoteLock,
    EnterLostMode,
    ExitLostMode,
    EscrowRecoveryKey,
    InstallOsUpdate,
    ApplyConfigProfile,
    EnableDiskEncryption,
    EnableFirewall,
    SetScreenLock,
    // --- EDR Parity actions (Phase E3) ---
    IsolateHost,
    UnisolateHost,
}

/// Outcome of a `SignedActionJob` execution.
///
/// `docs/wire-protocols/device-control.md` § 3.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Success,
    Failure,
    Refused,
    Skipped,
}

/// Refusal reason; present only when `ActionStatus = Refused`.
///
/// `docs/wire-protocols/device-control.md` § 8.3. The wire spelling MUST NOT change without a
/// major version bump — the customer-facing UI surfaces these
/// reasons verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobRefused {
    /// Step 2 failed: `deny_unknown_fields` rejected the payload.
    SchemaParseError,
    /// Step 3 failed: `key_id` is not in the local rotation set.
    UnknownKeyId,
    /// Step 4 failed: signature did not verify.
    BadSignature,
    /// Step 5 failed: `not_before`/`not_after` window is closed.
    Expired,
    /// Step 6 failed: `tenant_id` mismatch.
    TenantMismatch,
    /// Step 7 failed: `device_id` mismatch.
    DeviceMismatch,
    /// Step 8 failed: action not allow-listed for the current tier.
    ActionNotPermitted,
    /// Step 9 failed: outside maintenance / quiet-hours window.
    OutsideWindow,
    /// Step 10 failed: per-`ActionKind` args struct rejected the
    /// payload.
    ArgsParseError,
    /// Catch-all for refusals not covered above.
    PreconditionFailed,
    /// Phase 1 placeholder: the action is recognised but the
    /// executor sub-module is not yet implemented (e.g. Phase 3
    /// JIT admin grant).
    NotImplemented,
    // --- Desktop MDM refusals (Phase M2) ---
    /// Dual-control wipe: the inbound job carried fewer than two
    /// distinct approver signatures.
    WipeRequiresDualControl,
    /// A self-signed local job (auto-remediation) tried to invoke
    /// an action that is only allowed for control-plane jobs.
    LocalKeyNotAuthorisedForAction,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(value: &T) -> T {
        let s = serde_json::to_string(value).expect("serialize");
        serde_json::from_str(&s).expect("deserialize")
    }

    #[test]
    fn severity_serializes_lowercase() {
        let s = serde_json::to_string(&Severity::Critical).unwrap();
        assert_eq!(s, "\"critical\"");
        let s = serde_json::to_string(&Severity::Info).unwrap();
        assert_eq!(s, "\"info\"");
    }

    #[test]
    fn severity_roundtrip() {
        for v in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(rt(&v), v);
        }
    }

    #[test]
    fn platform_arch_serializes_x86_64_correctly() {
        let s = serde_json::to_string(&PlatformArch::X86_64).unwrap();
        // Must serialise as the literal `"x86_64"`, not `"x8664"`
        // — the control plane uses this string verbatim in
        // package-resolution paths.
        assert_eq!(s, "\"x86_64\"");
    }

    #[test]
    fn platform_arch_roundtrip() {
        for v in [
            PlatformArch::X86_64,
            PlatformArch::Aarch64,
            PlatformArch::I686,
            PlatformArch::Armv7,
        ] {
            assert_eq!(rt(&v), v);
        }
    }

    #[test]
    fn platform_os_roundtrip() {
        for v in [PlatformOs::Windows, PlatformOs::Macos, PlatformOs::Linux] {
            assert_eq!(rt(&v), v);
        }
    }

    #[test]
    fn platform_omits_none_distro() {
        let p = Platform {
            os: PlatformOs::Windows,
            version: "10.0.22631".into(),
            arch: PlatformArch::X86_64,
            distro: None,
        };
        let s = serde_json::to_string(&p).unwrap();
        assert!(!s.contains("distro"));
    }

    #[test]
    fn platform_includes_some_distro() {
        let p = Platform {
            os: PlatformOs::Linux,
            version: "24.04".into(),
            arch: PlatformArch::Aarch64,
            distro: Some("ubuntu".into()),
        };
        let s = serde_json::to_string(&p).unwrap();
        assert!(s.contains("\"distro\":\"ubuntu\""));
        assert_eq!(rt(&p), p);
    }

    #[test]
    fn platform_rejects_unknown_fields() {
        let bad = r#"{"os":"linux","version":"24.04","arch":"x86_64","extra":1}"#;
        let r: Result<Platform, _> = serde_json::from_str(bad);
        assert!(r.is_err());
    }

    #[test]
    fn agent_version_roundtrip_and_strict() {
        let av = AgentVersion {
            version: "0.10.0".into(),
            build_sha: "abc123".into(),
            channel: "stable".into(),
        };
        assert_eq!(rt(&av), av);
        let bad = r#"{"version":"x","build_sha":"y","channel":"z","extra":1}"#;
        assert!(serde_json::from_str::<AgentVersion>(bad).is_err());
    }

    #[test]
    fn finding_kind_wire_spelling() {
        assert_eq!(
            serde_json::to_string(&FindingKind::PermanentAdmin).unwrap(),
            "\"permanent_admin\""
        );
        assert_eq!(
            serde_json::to_string(&FindingKind::DeviceMissing).unwrap(),
            "\"device_missing\""
        );
        assert_eq!(
            serde_json::to_string(&FindingKind::VulnerabilityMatch).unwrap(),
            "\"vulnerability_match\""
        );
    }

    #[test]
    fn finding_kind_roundtrip_all_variants() {
        for v in [
            FindingKind::PermanentAdmin,
            FindingKind::OutdatedApp,
            FindingKind::DeviceMissing,
            FindingKind::UnapprovedSoftware,
            FindingKind::AdminAccessRequested,
            FindingKind::PostureViolation,
            FindingKind::VulnerabilityMatch,
            FindingKind::AdminDrift,
            FindingKind::DeviceControlBundleVerificationFailure,
            FindingKind::DiskEncryptionOff,
            FindingKind::FirewallOff,
            FindingKind::ScreenLockOff,
            FindingKind::OsPatchOverdue,
            FindingKind::RecoveryKeyNotEscrowed,
            FindingKind::DeviceLost,
            FindingKind::ConfigProfileTampered,
            FindingKind::Other,
        ] {
            assert_eq!(rt(&v), v);
        }
    }

    #[test]
    fn action_kind_wire_spelling() {
        assert_eq!(
            serde_json::to_string(&ActionKind::InstallPackage).unwrap(),
            "\"install_package\""
        );
        assert_eq!(
            serde_json::to_string(&ActionKind::GrantJitAdmin).unwrap(),
            "\"grant_jit_admin\""
        );
        assert_eq!(
            serde_json::to_string(&ActionKind::QueryAdHoc).unwrap(),
            "\"query_ad_hoc\""
        );
    }

    #[test]
    fn action_kind_roundtrip_all_variants() {
        for v in [
            ActionKind::InstallPackage,
            ActionKind::UpdatePackage,
            ActionKind::UninstallPackage,
            ActionKind::GrantJitAdmin,
            ActionKind::RevokeAdmin,
            ActionKind::RunScript,
            ActionKind::PushAppControlPolicy,
            ActionKind::StartRemoteSupport,
            ActionKind::EndRemoteSupport,
            ActionKind::QueryAdHoc,
            ActionKind::RemoteWipe,
            ActionKind::RemoteLock,
            ActionKind::EnterLostMode,
            ActionKind::ExitLostMode,
            ActionKind::EscrowRecoveryKey,
            ActionKind::InstallOsUpdate,
            ActionKind::ApplyConfigProfile,
            ActionKind::EnableDiskEncryption,
            ActionKind::EnableFirewall,
            ActionKind::SetScreenLock,
            ActionKind::IsolateHost,
            ActionKind::UnisolateHost,
        ] {
            assert_eq!(rt(&v), v);
        }
    }

    #[test]
    fn action_kind_wire_spelling_for_edr_parity_variants() {
        assert_eq!(
            serde_json::to_string(&ActionKind::IsolateHost).unwrap(),
            "\"isolate_host\""
        );
        assert_eq!(
            serde_json::to_string(&ActionKind::UnisolateHost).unwrap(),
            "\"unisolate_host\""
        );
    }

    #[test]
    fn action_status_wire_spelling() {
        assert_eq!(
            serde_json::to_string(&ActionStatus::Success).unwrap(),
            "\"success\""
        );
        assert_eq!(
            serde_json::to_string(&ActionStatus::Refused).unwrap(),
            "\"refused\""
        );
    }

    #[test]
    fn job_refused_wire_spelling_matches_schema() {
        // `docs/wire-protocols/device-control.md` § 8.3 — these wire spellings are part of the
        // public contract. Any change here is a major version bump.
        let cases = [
            (JobRefused::SchemaParseError, "schema_parse_error"),
            (JobRefused::UnknownKeyId, "unknown_key_id"),
            (JobRefused::BadSignature, "bad_signature"),
            (JobRefused::Expired, "expired"),
            (JobRefused::TenantMismatch, "tenant_mismatch"),
            (JobRefused::DeviceMismatch, "device_mismatch"),
            (JobRefused::ActionNotPermitted, "action_not_permitted"),
            (JobRefused::OutsideWindow, "outside_window"),
            (JobRefused::ArgsParseError, "args_parse_error"),
            (JobRefused::PreconditionFailed, "precondition_failed"),
            (JobRefused::NotImplemented, "not_implemented"),
            (
                JobRefused::WipeRequiresDualControl,
                "wipe_requires_dual_control",
            ),
            (
                JobRefused::LocalKeyNotAuthorisedForAction,
                "local_key_not_authorised_for_action",
            ),
        ];
        for (variant, wire) in cases {
            let got = serde_json::to_string(&variant).unwrap();
            assert_eq!(got, format!("\"{wire}\""), "wire spelling for {variant:?}");
            let back: JobRefused = serde_json::from_str(&got).unwrap();
            assert_eq!(back, variant);
        }
    }
}
