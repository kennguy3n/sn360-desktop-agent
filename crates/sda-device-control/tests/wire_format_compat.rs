//! Wire-format compatibility tests (Task D2-18).
//!
//! These tests pin the **JSON shape** the agent emits for every
//! Device Control schema (`Finding`, `Recommendation`,
//! `SignedActionJob`, `ActionResult`, `EvidenceRecord`) against the
//! Go projection in
//! `sn360-security-platform/services/_devicecontrolshared/types.go`.
//!
//! The Go projection is a **minimal subset** (only the fields the
//! services consume); the Rust agent emits a superset. These tests
//! pin both:
//!
//!   1. Every field the Go projection requires is emitted by the
//!      agent with the expected JSON name and type.
//!   2. Every wire-tagged enum (FindingKind, ActionKind, ActionStatus,
//!      Severity, PlatformOs, PlatformArch) emits the canonical
//!      snake_case spelling that the Go side stores in its
//!      `_devicecontrolshared` enum tables and migration 015.
//!
//! Every divergence is documented inline. If the agent's `serde`
//! derives ever drift from the canonical SCHEMAS.md form, these
//! tests fail loudly and the divergence is either re-canonicalised
//! in SCHEMAS.md or fixed.

use chrono::{TimeZone, Utc};
use sda_device_control::{
    ActionKind, ActionResult, ActionStatus, AgentVersion, EvidenceRecord, Finding, FindingKind,
    Platform, PlatformArch, PlatformOs, Recommendation, Severity, SignedActionJob,
    FIRST_RECORD_PREV_HASH,
};
use serde_json::{json, Value};
use uuid::Uuid;

/// Keys the platform's `_devicecontrolshared.Finding` requires.
/// `evidence` is `omitempty` on the Go side so we exclude it from
/// the required-set assertion.
const FINDING_REQUIRED_GO_KEYS: &[&str] = &[
    "finding_id",
    "device_id",
    "tenant_id",
    "kind",
    "severity",
    "plain_english",
    "observed_at",
];

/// Keys the platform's `_devicecontrolshared.Recommendation`
/// requires (every Go field is non-omitempty).
const RECOMMENDATION_REQUIRED_GO_KEYS: &[&str] = &[
    "recommendation_id",
    "tenant_id",
    "device_ids",
    "finding_ids",
    "action",
    "plain_english",
    "one_click",
    "created_at",
];

/// Keys the platform's `_devicecontrolshared.SignedActionJob`
/// requires (`recommendation_id` and `args` are `omitempty`).
const SIGNED_JOB_REQUIRED_GO_KEYS: &[&str] = &[
    "job_id",
    "tenant_id",
    "device_id",
    "action",
    "not_before",
    "not_after",
    "signature",
    "key_id",
];

/// Keys the platform's `_devicecontrolshared.ActionResult` requires
/// (`exit_code`, `output`, `evidence_id` are `omitempty` on the Go
/// side; they are present-and-required on the Rust side).
const ACTION_RESULT_REQUIRED_GO_KEYS: &[&str] = &[
    "job_id",
    "device_id",
    "tenant_id",
    "status",
    "started_at",
    "finished_at",
];

fn assert_json_object_keys(value: &Value, required: &[&str], context: &str) {
    let obj = value
        .as_object()
        .unwrap_or_else(|| panic!("{context}: expected JSON object, got {value:?}"));
    for key in required {
        assert!(
            obj.contains_key(*key),
            "{context}: missing required key '{key}' (got keys: {:?})",
            obj.keys().collect::<Vec<_>>()
        );
    }
}

fn fixed_uuid(b: u8) -> Uuid {
    Uuid::from_bytes([b; 16])
}

#[test]
fn finding_json_shape_matches_platform_projection() {
    let f = Finding {
        finding_id: fixed_uuid(1),
        device_id: fixed_uuid(2),
        tenant_id: fixed_uuid(3),
        schema_version: sda_device_control::FINDING_SCHEMA_VERSION,
        kind: FindingKind::DeviceMissing,
        severity: Severity::High,
        plain_english: "4 laptops haven't checked in for 14+ days — possibly lost".into(),
        evidence: json!({"missing_count": 4, "threshold_days": 14, "tenant_id": fixed_uuid(3)}),
        observed_at: Utc.with_ymd_and_hms(2026, 5, 10, 12, 0, 0).unwrap(),
        source_refs: None,
    };
    let v: Value = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
    assert_json_object_keys(&v, FINDING_REQUIRED_GO_KEYS, "Finding");

    // Per `_devicecontrolshared.Finding`, kind/severity are wire-tagged
    // strings (not numeric).
    assert_eq!(v["kind"], json!("device_missing"));
    assert_eq!(v["severity"], json!("high"));

    // observed_at must be RFC3339 (Go's time.Time JSON default).
    // For a negative-offset RFC3339 timestamp without fractional
    // seconds (e.g. "2026-05-10T12:00:00-05:00") the offset '-'
    // sits at byte 19 (right after the seconds field). Anything
    // earlier is a date separator that must be ignored.
    let observed = v["observed_at"].as_str().expect("observed_at is a string");
    assert!(
        observed.ends_with('Z') || observed.contains('+') || observed[19..].contains('-'),
        "observed_at must be RFC3339 with timezone: got {observed:?}"
    );

    // evidence is a nested JSON object (Go's json.RawMessage).
    assert!(v["evidence"].is_object(), "evidence must be a JSON object");

    // Round-trip: deserialise back into Finding.
    let back: Finding = serde_json::from_value(v).unwrap();
    assert_eq!(back, f);
}

#[test]
fn recommendation_json_shape_matches_platform_projection() {
    let r = Recommendation {
        recommendation_id: fixed_uuid(11),
        tenant_id: fixed_uuid(12),
        schema_version: sda_device_control::RECOMMENDATION_SCHEMA_VERSION,
        device_ids: vec![fixed_uuid(13)],
        finding_ids: vec![fixed_uuid(14), fixed_uuid(15)],
        action: ActionKind::InstallPackage,
        args: json!({"package": "google-chrome"}),
        plain_english: "Update Chrome on 1 device.".into(),
        one_click: true,
        severity: Severity::Medium,
        created_at: Utc.with_ymd_and_hms(2026, 5, 10, 12, 5, 0).unwrap(),
        valid_until: None,
    };
    let v: Value = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_json_object_keys(&v, RECOMMENDATION_REQUIRED_GO_KEYS, "Recommendation");

    assert_eq!(v["action"], json!("install_package"));
    assert!(v["device_ids"].is_array());
    assert!(v["finding_ids"].is_array());
    assert_eq!(v["one_click"], json!(true));

    let back: Recommendation = serde_json::from_value(v).unwrap();
    assert_eq!(back, r);
}

#[test]
fn signed_action_job_json_shape_matches_platform_projection() {
    let job = SignedActionJob {
        job_id: fixed_uuid(21),
        tenant_id: fixed_uuid(22),
        device_id: fixed_uuid(23),
        schema_version: sda_device_control::SIGNED_ACTION_JOB_SCHEMA_VERSION,
        recommendation_id: Some(fixed_uuid(24)),
        action: ActionKind::InstallPackage,
        args: json!({"package": "google-chrome", "version": "126.0.0.0"}),
        not_before: Utc.with_ymd_and_hms(2026, 5, 10, 12, 10, 0).unwrap(),
        not_after: Utc.with_ymd_and_hms(2026, 5, 10, 13, 10, 0).unwrap(),
        signature: vec![0u8; 64],
        key_id: "ed25519:platform-2026-05".into(),
        correlation_id: None,
        additional_signatures: Vec::new(),
    };
    let v: Value = serde_json::from_str(&serde_json::to_string(&job).unwrap()).unwrap();
    assert_json_object_keys(&v, SIGNED_JOB_REQUIRED_GO_KEYS, "SignedActionJob");

    assert_eq!(v["action"], json!("install_package"));

    // The `signature` field is `Vec<u8>` on the agent side and `[]byte`
    // on the Go side. Go's encoding/json default serialises `[]byte` as
    // base64 strings, while serde defaults to a JSON array of integers.
    // The agent currently emits the array form because the live wire
    // format is MessagePack (which encodes both as `bin`); the JSON
    // emission of `signature` is consumed inside the agent's on-disk
    // evidence cache where the array form round-trips correctly.
    //
    // This test pins the array form so a future move to base64 (which
    // would be the right thing once Go services start consuming
    // SignedActionJobs over JSON instead of MessagePack) shows up as a
    // failure here and forces the SCHEMAS.md update.
    assert!(
        v["signature"].is_array(),
        "signature is currently serialised as a JSON array of u8; \
         see comment for the upgrade path"
    );

    let back: SignedActionJob = serde_json::from_value(v).unwrap();
    assert_eq!(back, job);
}

#[test]
fn action_result_json_shape_matches_platform_projection() {
    let started = Utc.with_ymd_and_hms(2026, 5, 10, 12, 20, 0).unwrap();
    let finished = Utc.with_ymd_and_hms(2026, 5, 10, 12, 20, 5).unwrap();
    let ar = ActionResult {
        job_id: fixed_uuid(31),
        tenant_id: fixed_uuid(33),
        device_id: fixed_uuid(32),
        schema_version: sda_device_control::ACTION_RESULT_SCHEMA_VERSION,
        action: ActionKind::InstallPackage,
        status: ActionStatus::Success,
        refused_reason: None,
        started_at: started,
        finished_at: finished,
        exit_code: Some(0),
        output: "ok".into(),
        output_truncated: false,
        evidence_id: fixed_uuid(34),
    };
    let v: Value = serde_json::from_str(&serde_json::to_string(&ar).unwrap()).unwrap();
    assert_json_object_keys(&v, ACTION_RESULT_REQUIRED_GO_KEYS, "ActionResult");

    assert_eq!(v["status"], json!("success"));
    assert_eq!(v["exit_code"], json!(0));
    assert_eq!(v["output"], json!("ok"));
    assert_eq!(v["evidence_id"], json!(fixed_uuid(34)));

    // refused_reason is omitempty on the Rust side and absent here.
    let obj = v.as_object().unwrap();
    assert!(!obj.contains_key("refused_reason"));

    let back: ActionResult = serde_json::from_value(v).unwrap();
    assert_eq!(back, ar);
}

#[test]
fn action_result_refused_emits_refused_reason() {
    // Refused jobs require `started_at == finished_at` (validate()).
    let now = Utc.with_ymd_and_hms(2026, 5, 10, 12, 20, 5).unwrap();
    let ar = ActionResult {
        job_id: fixed_uuid(31),
        tenant_id: fixed_uuid(33),
        device_id: fixed_uuid(32),
        schema_version: sda_device_control::ACTION_RESULT_SCHEMA_VERSION,
        action: ActionKind::InstallPackage,
        status: ActionStatus::Refused,
        refused_reason: Some(sda_device_control::JobRefused::TenantMismatch),
        started_at: now,
        finished_at: now,
        exit_code: None,
        output: String::new(),
        output_truncated: false,
        evidence_id: fixed_uuid(34),
    };
    ar.validate().unwrap();
    let v: Value = serde_json::from_str(&serde_json::to_string(&ar).unwrap()).unwrap();
    assert_eq!(v["status"], json!("refused"));
    assert_eq!(v["refused_reason"], json!("tenant_mismatch"));
}

#[test]
fn evidence_record_json_shape_matches_schemas_md() {
    let er = EvidenceRecord {
        evidence_id: fixed_uuid(41),
        tenant_id: fixed_uuid(42),
        device_id: fixed_uuid(43),
        schema_version: sda_device_control::EVIDENCE_RECORD_SCHEMA_VERSION,
        job_id: fixed_uuid(44),
        recommendation_id: None,
        action: ActionKind::InstallPackage,
        args_canonical: r#"{"package":"chrome"}"#.into(),
        started_at: Utc.with_ymd_and_hms(2026, 5, 10, 12, 30, 0).unwrap(),
        finished_at: Utc.with_ymd_and_hms(2026, 5, 10, 12, 30, 5).unwrap(),
        status: ActionStatus::Success,
        refused_reason: None,
        exit_code: Some(0),
        output_sha256: [0xab; 32],
        platform: Platform {
            os: PlatformOs::Linux,
            version: "6.6.0".into(),
            arch: PlatformArch::X86_64,
            distro: Some("ubuntu-24.04".into()),
        },
        agent: AgentVersion {
            version: "0.9.0-beta.1".into(),
            build_sha: "deadbeef".into(),
            channel: "beta".into(),
        },
        prev_record_hash: FIRST_RECORD_PREV_HASH,
        signature: vec![0u8; 64],
        key_id: "ed25519:agent-2026-05".into(),
    };
    let v: Value = serde_json::from_str(&serde_json::to_string(&er).unwrap()).unwrap();
    let obj = v.as_object().unwrap();

    // Pin the canonical key set the agent emits. SCHEMAS.md § 9.
    let expected_keys: &[&str] = &[
        "evidence_id",
        "tenant_id",
        "device_id",
        "schema_version",
        "job_id",
        "action",
        "args_canonical",
        "started_at",
        "finished_at",
        "status",
        "exit_code",
        "output_sha256",
        "platform",
        "agent",
        "prev_record_hash",
        "signature",
        "key_id",
    ];
    for k in expected_keys {
        assert!(obj.contains_key(*k), "EvidenceRecord must emit key {k:?}");
    }

    // SCHEMAS.md § 6: `output_sha256` and `prev_record_hash` are
    // 32-byte SHA-256 values, encoded as lowercase hex on the
    // canonical-JSON path (the `byte_array_32` serde wrapper).
    assert!(v["output_sha256"].is_string());
    assert!(v["prev_record_hash"].is_string());
    let prev = v["prev_record_hash"].as_str().unwrap();
    assert_eq!(prev.len(), 64, "prev_record_hash must be 64 hex chars");
    assert!(prev.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(prev, "0".repeat(64), "FIRST_RECORD_PREV_HASH is all zeros");

    // Platform tag is wire-encoded snake_case (`linux`, not `Linux`).
    assert_eq!(v["platform"]["os"], json!("linux"));
    assert_eq!(v["platform"]["arch"], json!("x86_64"));

    let back: EvidenceRecord = serde_json::from_value(v).unwrap();
    assert_eq!(back, er);
}

#[test]
fn finding_kind_wire_strings_match_platform_enum() {
    use FindingKind::*;
    let cases: &[(FindingKind, &str)] = &[
        (PermanentAdmin, "permanent_admin"),
        (OutdatedApp, "outdated_app"),
        (DeviceMissing, "device_missing"),
        (UnapprovedSoftware, "unapproved_software"),
        (AdminAccessRequested, "admin_access_requested"),
        (PostureViolation, "posture_violation"),
        (VulnerabilityMatch, "vulnerability_match"),
        (AdminDrift, "admin_drift"),
        (
            DeviceControlBundleVerificationFailure,
            "device_control_bundle_verification_failure",
        ),
        (Other, "other"),
    ];
    for (variant, wire) in cases {
        let s = serde_json::to_value(variant).unwrap();
        assert_eq!(s, json!(wire), "{variant:?} must serialise as {wire:?}");
    }
}

#[test]
fn action_kind_wire_strings_match_platform_enum() {
    use ActionKind::*;
    let cases: &[(ActionKind, &str)] = &[
        (InstallPackage, "install_package"),
        (UpdatePackage, "update_package"),
        (UninstallPackage, "uninstall_package"),
        (GrantJitAdmin, "grant_jit_admin"),
        (RevokeAdmin, "revoke_admin"),
        (RunScript, "run_script"),
        (PushAppControlPolicy, "push_app_control_policy"),
        (StartRemoteSupport, "start_remote_support"),
        (EndRemoteSupport, "end_remote_support"),
        (QueryAdHoc, "query_ad_hoc"),
    ];
    for (variant, wire) in cases {
        let s = serde_json::to_value(variant).unwrap();
        assert_eq!(s, json!(wire), "{variant:?} must serialise as {wire:?}");
    }
}

#[test]
fn severity_wire_strings_match_platform_enum() {
    use Severity::*;
    let cases: &[(Severity, &str)] = &[
        (Info, "info"),
        (Low, "low"),
        (Medium, "medium"),
        (High, "high"),
        (Critical, "critical"),
    ];
    for (variant, wire) in cases {
        let s = serde_json::to_value(variant).unwrap();
        assert_eq!(s, json!(wire), "{variant:?} must serialise as {wire:?}");
    }
}

#[test]
fn action_status_wire_strings_match_platform_enum() {
    use ActionStatus::*;
    let cases: &[(ActionStatus, &str)] = &[
        (Success, "success"),
        (Failure, "failure"),
        (Refused, "refused"),
        (Skipped, "skipped"),
    ];
    for (variant, wire) in cases {
        let s = serde_json::to_value(variant).unwrap();
        assert_eq!(s, json!(wire), "{variant:?} must serialise as {wire:?}");
    }
}

#[test]
fn platform_os_wire_strings_match_platform_enum() {
    use PlatformOs::*;
    let cases: &[(PlatformOs, &str)] = &[(Windows, "windows"), (Macos, "macos"), (Linux, "linux")];
    for (variant, wire) in cases {
        let s = serde_json::to_value(variant).unwrap();
        assert_eq!(s, json!(wire), "{variant:?} must serialise as {wire:?}");
    }
}

#[test]
fn platform_arch_wire_strings_match_platform_enum() {
    use PlatformArch::*;
    let cases: &[(PlatformArch, &str)] = &[
        (X86_64, "x86_64"),
        (Aarch64, "aarch64"),
        (I686, "i686"),
        (Armv7, "armv7"),
    ];
    for (variant, wire) in cases {
        let s = serde_json::to_value(variant).unwrap();
        assert_eq!(s, json!(wire), "{variant:?} must serialise as {wire:?}");
    }
}
