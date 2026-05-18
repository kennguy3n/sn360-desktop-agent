//! Phase 4 app-control end-to-end suite (task 4.12).
//!
//! Hermetic exercises of the Phase 4 app-control surface shipped in
//! PR #7 (PAL trait + supervisor + monitor / enforce controllers)
//! and extended in this PR (Tasks 4.7 / 4.8 — WDAC / AppLocker /
//! Linux dm-verity-aware backends).
//!
//! The harness reuses the in-process [`EventBus`] so every scenario
//! walks the same wire shape the supervisor publishes in
//! `sda-agent::main`.
//!
//! Coverage:
//!
//! 1. Monitor-mode policy apply → observe binary → log decision →
//!    `AppControlPolicyApplied` + `AppControlDecision` events
//!    (`monitor_mode_logs_decision_without_blocking`).
//! 2. Enforce-mode policy apply → observe → policy push to backend
//!    → dual-control rollback restores prior policy
//!    (`enforce_mode_apply_then_dual_control_rollback`).
//! 3. Mode mismatch — applying an enforce-targeting policy when the
//!    supervisor is configured for monitor is rejected
//!    (`mode_mismatch_is_rejected`).
//! 4. Anti-regression — applying the same version twice is rejected
//!    (`policy_version_regression_is_rejected`).
//! 5. Tampered signature → reject + no event
//!    (`tampered_signature_is_rejected`).
//! 6. Linux dm-verity-aware backend renders the policy file and
//!    decision log (`linux_backend_renders_policy_artifact`).
//! 7. Windows WDAC backend translates rules to WDAC XML and emits
//!    the PowerShell command sequence
//!    (`windows_backend_renders_wdac_artifact`).
//! 8. AppLocker fallback for legacy Windows hosts
//!    (`windows_backend_falls_back_to_applocker_on_legacy_build`).
//!
//! All scenarios run on in-process state (mock providers, in-process
//! bus). `make e2e-app-control` runs in a few seconds on every CI
//! host.

#![cfg(unix)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use sda_app_control::{
    build_linux_policy_artifact, build_wdac_document, parse_dm_verity_status,
    powershell_apply_applocker_commands, powershell_apply_wdac_commands, render_linux_policy_file,
    render_wdac_xml, select_backend, AppControlError, AppControlSupervisor, DmVerityStatus,
    LinuxAppControlProviderImpl, WdacAppControlProvider, WdacBackend,
};
use sda_core::config::AppControlConfig;
use sda_event_bus::{Event, EventBus, EventKind};
use sda_pal::app_control::{
    AppControlError as PalError, AppControlMode, AppControlPolicyPayload, AppControlProvider,
    AppControlRule, SignedAppControlPolicy,
};
use tokio::sync::mpsc;

// ---------- Test harness ---------------------------------------------------

/// Recording provider — captures every `apply_verified_policy` call
/// so tests can assert what the supervisor handed to the OS-level
/// backend.
#[derive(Debug, Default)]
struct RecordingProvider {
    applied: Mutex<Vec<AppControlPolicyPayload>>,
    fail_next: Mutex<Option<String>>,
}

impl RecordingProvider {
    fn applied_versions(&self) -> Vec<u64> {
        self.applied
            .lock()
            .unwrap()
            .iter()
            .map(|p| p.version)
            .collect()
    }

    fn fail_next(&self, msg: &str) {
        *self.fail_next.lock().unwrap() = Some(msg.into());
    }
}

impl AppControlProvider for RecordingProvider {
    fn current_mode(&self) -> Result<AppControlMode, PalError> {
        Ok(AppControlMode::Enforce)
    }

    fn apply_verified_policy(&self, payload: &AppControlPolicyPayload) -> Result<(), PalError> {
        if let Some(msg) = self.fail_next.lock().unwrap().take() {
            return Err(PalError::Backend(msg));
        }
        self.applied.lock().unwrap().push(payload.clone());
        Ok(())
    }
}

fn rule(subject: &str, allow: bool) -> AppControlRule {
    AppControlRule {
        subject: subject.into(),
        allow,
        reason: format!("{} {}", if allow { "allow" } else { "deny" }, subject),
    }
}

/// Build a deterministically-signed policy bundle. The 32-byte
/// signing key seed is `[7]` so the verifying key is stable across
/// the test suite — production code rotates per-tenant keys.
fn signed_policy(
    version: u64,
    target_mode: AppControlMode,
    rules: Vec<AppControlRule>,
) -> (SignedAppControlPolicy, String) {
    let payload = AppControlPolicyPayload {
        version,
        issued_at: Utc::now(),
        target_mode,
        rules,
    };
    let canonical = serde_json::to_vec(&payload).unwrap();
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let sig = signing.sign(&canonical);
    let signed = SignedAppControlPolicy {
        canonical_payload_hex: hex::encode(&canonical),
        signature: hex::encode(sig.to_bytes()),
        signing_key: hex::encode(signing.verifying_key().to_bytes()),
    };
    let trusted = signed.signing_key.clone();
    (signed, trusted)
}

fn config(mode: &str, key: Option<String>) -> AppControlConfig {
    AppControlConfig {
        enabled: true,
        mode: mode.into(),
        trusted_signing_key: key,
    }
}

fn make_bus() -> (Arc<EventBus>, mpsc::Receiver<Event>) {
    let (bus, rx) = EventBus::new(64, 64);
    (Arc::new(bus), rx)
}

async fn drain_for(rx: &mut mpsc::Receiver<Event>, budget: Duration) -> Vec<EventKind> {
    let mut out = Vec::new();
    while let Ok(Some(ev)) = tokio::time::timeout(budget, rx.recv()).await {
        out.push(ev.kind);
    }
    out
}

// ---------- Scenario 1: monitor-mode logs decisions ------------------------

/// Monitor mode is the Phase 4 default. A
/// signed policy must be applied without ever pushing to the OS
/// backend, and observation must emit an `AppControlDecision`
/// event. `docs/device-control.md` § 8 acceptance #1: monitor mode is default.
#[tokio::test(flavor = "current_thread")]
async fn monitor_mode_logs_decision_without_blocking() {
    let (bus, mut rx) = make_bus();
    let provider = Arc::new(RecordingProvider::default());
    let (signed, trusted) = signed_policy(
        1,
        AppControlMode::Monitor,
        vec![
            rule("sha256:cafebabe", true),
            rule("sha256:deadbeef", false),
        ],
    );
    let mut sup = AppControlSupervisor::new(
        config("monitor", Some(trusted)),
        bus,
        Box::new(RecordingProviderHandle(provider.clone())),
    );

    sup.apply_policy(signed).expect("apply ok");
    let allow = sup.observe("sha256:cafebabe").expect("decision");
    let deny = sup.observe("sha256:deadbeef").expect("decision");
    let unknown = sup.observe("sha256:none").expect("decision");

    let kinds = drain_for(&mut rx, Duration::from_millis(200)).await;
    let applied: usize = kinds
        .iter()
        .filter(|k| matches!(k, EventKind::AppControlPolicyApplied { .. }))
        .count();
    let decisions: usize = kinds
        .iter()
        .filter(|k| matches!(k, EventKind::AppControlDecision { .. }))
        .count();
    assert_eq!(applied, 1);
    assert_eq!(decisions, 3);

    assert_eq!(allow.matched_allow, Some(true));
    assert_eq!(deny.matched_allow, Some(false));
    assert!(unknown.matched_allow.is_none());

    // Crucially: monitor mode never pushes to the OS backend.
    assert!(provider.applied_versions().is_empty());
}

// ---------- Scenario 2: enforce-mode dual-control rollback -----------------

/// Enforce mode pushes to the OS backend; a
/// follow-up rollback re-applies the previously active policy.
/// `docs/device-control.md` § 8 acceptance #2: enforce requires opt-in +
/// dual-control rollback.
#[tokio::test(flavor = "current_thread")]
async fn enforce_mode_apply_then_dual_control_rollback() {
    let (bus, mut rx) = make_bus();
    let provider = Arc::new(RecordingProvider::default());
    let (s1, trusted) = signed_policy(1, AppControlMode::Enforce, vec![rule("sha256:aaaa", true)]);
    let (s2, _) = signed_policy(2, AppControlMode::Enforce, vec![rule("sha256:bbbb", false)]);

    let mut sup = AppControlSupervisor::new(
        config("enforce", Some(trusted)),
        bus,
        Box::new(RecordingProviderHandle(provider.clone())),
    );

    sup.apply_policy(s1).expect("apply v1");
    sup.apply_policy(s2).expect("apply v2");

    let restored = sup.rollback().expect("rollback");
    assert_eq!(
        restored.payload.version, 1,
        "rollback must re-apply previous policy"
    );

    // Provider was called for: apply v1, apply v2, rollback (re-apply
    // v1). 3 invocations total.
    let versions = provider.applied_versions();
    assert_eq!(
        versions,
        vec![1, 2, 1],
        "provider invocations are: {versions:?}"
    );

    let kinds = drain_for(&mut rx, Duration::from_millis(200)).await;
    let applied: usize = kinds
        .iter()
        .filter(|k| matches!(k, EventKind::AppControlPolicyApplied { .. }))
        .count();
    assert!(
        applied >= 2,
        "must emit a PolicyApplied per accepted bundle"
    );
}

// ---------- Scenario 3: mode mismatch is rejected --------------------------

/// Mode mismatch (policy targets enforce while
/// the supervisor is in monitor) must short-circuit the apply path
/// without invoking the provider.
#[tokio::test(flavor = "current_thread")]
async fn mode_mismatch_is_rejected() {
    let (bus, _rx) = make_bus();
    let provider = Arc::new(RecordingProvider::default());
    let (signed, trusted) =
        signed_policy(1, AppControlMode::Enforce, vec![rule("sha256:aaaa", true)]);
    let mut sup = AppControlSupervisor::new(
        config("monitor", Some(trusted)),
        bus,
        Box::new(RecordingProviderHandle(provider.clone())),
    );
    let err = sup.apply_policy(signed).expect_err("must reject");
    assert!(matches!(err, AppControlError::ModeMismatch { .. }));
    assert!(provider.applied_versions().is_empty());
}

// ---------- Scenario 4: anti-regression ------------------------------------

/// Replaying the same policy version is
/// rejected by the policy verifier (anti-rollback guard from PR #7).
#[tokio::test(flavor = "current_thread")]
async fn policy_version_regression_is_rejected() {
    let (bus, _rx) = make_bus();
    let provider = Arc::new(RecordingProvider::default());
    let (s1, trusted) = signed_policy(2, AppControlMode::Monitor, vec![rule("sha256:aaaa", true)]);
    // Build a bundle stamped with a *lower* version, signed with
    // the same trusted key.
    let (s_low, _) = signed_policy(1, AppControlMode::Monitor, vec![rule("sha256:aaaa", true)]);

    let mut sup = AppControlSupervisor::new(
        config("monitor", Some(trusted)),
        bus,
        Box::new(RecordingProviderHandle(provider.clone())),
    );
    sup.apply_policy(s1).expect("apply v2 ok");
    let err = sup.apply_policy(s_low).expect_err("must reject regression");
    assert!(
        matches!(err, AppControlError::Verification(_)),
        "got: {err:?}"
    );
}

// ---------- Scenario 5: tampered signature ---------------------------------

/// A tampered signature must be rejected by the
/// verifier and must NOT emit a `PolicyApplied` event.
#[tokio::test(flavor = "current_thread")]
async fn tampered_signature_is_rejected() {
    let (bus, mut rx) = make_bus();
    let provider = Arc::new(RecordingProvider::default());
    let (mut signed, trusted) =
        signed_policy(1, AppControlMode::Monitor, vec![rule("sha256:aaaa", true)]);
    // Flip a byte in the signature.
    let mut sig = hex::decode(&signed.signature).unwrap();
    sig[0] ^= 0x01;
    signed.signature = hex::encode(sig);

    let mut sup = AppControlSupervisor::new(
        config("monitor", Some(trusted)),
        bus,
        Box::new(RecordingProviderHandle(provider.clone())),
    );
    let err = sup.apply_policy(signed).expect_err("must reject");
    assert!(matches!(err, AppControlError::Verification(_)));

    let kinds = drain_for(&mut rx, Duration::from_millis(150)).await;
    assert!(
        !kinds
            .iter()
            .any(|k| matches!(k, EventKind::AppControlPolicyApplied { .. })),
        "tampered policies must not emit applied events"
    );
}

// ---------- Scenario 6: Linux dm-verity-aware backend ----------------------

/// The Linux backend must:
///  1. Translate every signed rule into the on-disk policy file.
///  2. Surface dm-verity status on observations.
///  3. Match observations against the policy.
#[tokio::test(flavor = "current_thread")]
async fn linux_backend_renders_policy_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let provider = LinuxAppControlProviderImpl::new(dir.path().to_path_buf());

    // Surface a dm-verity status the supervisor can include in
    // decision evidence.
    let verity = parse_dm_verity_status(
        "/dev/mapper/root",
        "/dev/mapper/root is active and is in use.\n  type:  VERITY\n  status: verified\n  root hash: deadbeef\n",
    );
    assert_eq!(verity.status, DmVerityStatus::Verified);
    provider.record_dm_verity(verity);

    let payload = AppControlPolicyPayload {
        version: 5,
        issued_at: Utc::now(),
        target_mode: AppControlMode::Monitor,
        rules: vec![
            rule("sha256:trusted", true),
            rule("path:/usr/bin/curl", true),
            rule("package:nmap", false),
        ],
    };
    provider.apply_verified_policy(&payload).expect("apply ok");

    // Translation: rendered file contains every kind.
    let artefact = build_linux_policy_artifact(&payload);
    let body = render_linux_policy_file(&artefact);
    assert!(body.contains("sha256\ttrusted\tallow"));
    assert!(body.contains("path\t/usr/bin/curl\tallow"));
    assert!(body.contains("package\tnmap\tdeny"));
    assert!(body.contains("# version: 5"));

    // Observation: subject hits a known rule and carries verity
    // state into the evidence record.
    let obs = provider.observe("path:/usr/bin/curl").expect("obs");
    assert_eq!(obs.matched_allow, Some(true));
    assert_eq!(obs.matched_kind.as_deref(), Some("path"));
    assert_eq!(obs.verity_status, "verified");
    assert_eq!(obs.policy_version, 5);
}

// ---------- Scenario 7: Windows WDAC backend -------------------------------

/// Modern Windows hosts (build ≥ 18362) must
/// pick the WDAC backend and emit the PowerShell sequence the
/// supervisor invokes to push the policy to the OS.
#[tokio::test(flavor = "current_thread")]
async fn windows_backend_renders_wdac_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let provider =
        WdacAppControlProvider::with_backend(WdacBackend::Wdac, dir.path().to_path_buf());
    let payload = AppControlPolicyPayload {
        version: 9,
        issued_at: Utc::now(),
        target_mode: AppControlMode::Enforce,
        rules: vec![
            rule("sha256:cafebabe", true),
            rule("publisher:CN=Microsoft Corporation", true),
            rule("path:C\\Windows\\Temp\\evil.exe", false),
        ],
    };
    provider.apply_verified_policy(&payload).expect("apply ok");

    let record = provider.last_applied().expect("record");
    assert_eq!(record.backend, WdacBackend::Wdac);
    assert!(record.xml.contains("<SiPolicy"));
    assert!(record.xml.contains("Hash=\"cafebabe\""));
    assert!(record.xml.contains("Action=\"Allow\""));
    assert!(record.xml.contains("Action=\"Deny\""));

    // PowerShell sequence covers stamp + convert + copy + refresh.
    let joined: String = record
        .commands
        .iter()
        .flat_map(|c| c.args.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(joined.contains("Set-CIPolicyIdInfo"));
    assert!(joined.contains("ConvertFrom-CIPolicy"));
    assert!(joined.contains("Copy-Item"));
    assert!(joined.contains("PS_UpdateAndCompareCIPolicy"));

    // Translation surface: building the document directly produces
    // an equivalent rendered XML so consumers can diff bundles
    // without round-tripping through the provider.
    let doc = build_wdac_document(&payload);
    let direct = render_wdac_xml(&doc);
    assert!(direct.contains("<SiPolicy"));
    assert!(powershell_apply_wdac_commands(
        std::path::Path::new("/tmp/x.xml"),
        std::path::Path::new("/tmp/x.cip"),
        "id",
        "name"
    )
    .iter()
    .any(|c| c.args.iter().any(|a| a.contains("Set-CIPolicyIdInfo"))));
}

// ---------- Scenario 8: AppLocker fallback ---------------------------------

/// Pre-WDAC Windows builds (< 18362) must
/// fall back to AppLocker and emit the equivalent
/// `Set-AppLockerPolicy` sequence.
#[tokio::test(flavor = "current_thread")]
async fn windows_backend_falls_back_to_applocker_on_legacy_build() {
    assert_eq!(select_backend(18_361), WdacBackend::AppLocker);
    let dir = tempfile::tempdir().unwrap();
    let provider =
        WdacAppControlProvider::with_backend(WdacBackend::AppLocker, dir.path().to_path_buf());
    let payload = AppControlPolicyPayload {
        version: 1,
        issued_at: Utc::now(),
        target_mode: AppControlMode::Monitor,
        rules: vec![rule("sha256:cafebabe", true)],
    };
    provider.apply_verified_policy(&payload).expect("apply ok");

    let record = provider.last_applied().expect("record");
    assert_eq!(record.backend, WdacBackend::AppLocker);
    assert!(record.xml.contains("<AppLockerPolicy"));
    assert!(record.xml.contains("EnforcementMode=\"AuditOnly\""));
    assert_eq!(record.commands.len(), 1);
    assert!(record.commands[0]
        .args
        .iter()
        .any(|a| a.contains("Set-AppLockerPolicy")));

    // Direct command construction also produces the same shape.
    let cmds = powershell_apply_applocker_commands(std::path::Path::new("/tmp/al.xml"));
    assert_eq!(cmds.len(), 1);
}

// ---------- Helpers --------------------------------------------------------

/// Wrapper that hands an `Arc<RecordingProvider>` to the supervisor
/// without taking exclusive ownership — lets tests assert on the
/// provider after the supervisor is built.
struct RecordingProviderHandle(Arc<RecordingProvider>);

impl AppControlProvider for RecordingProviderHandle {
    fn current_mode(&self) -> Result<AppControlMode, PalError> {
        self.0.current_mode()
    }
    fn apply_verified_policy(&self, payload: &AppControlPolicyPayload) -> Result<(), PalError> {
        self.0.apply_verified_policy(payload)
    }
}

/// Defensive: the type that wraps `Arc<RecordingProvider>` must be
/// `Send + Sync` so it can be boxed into `Box<dyn AppControlProvider>`.
#[test]
fn recording_provider_handle_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RecordingProviderHandle>();
}

/// Tracks the assertion that fail-injection works — the provider
/// can refuse a policy push, exercising the supervisor's error
/// path. Used by the rollback story in production but exercised
/// here so a regression in `RecordingProvider::fail_next` is loud.
#[tokio::test(flavor = "current_thread")]
async fn provider_failure_surfaces_through_supervisor() {
    let (bus, _rx) = make_bus();
    let provider = Arc::new(RecordingProvider::default());
    provider.fail_next("simulated WDAC failure");
    let (signed, trusted) =
        signed_policy(1, AppControlMode::Enforce, vec![rule("sha256:aaaa", true)]);
    let mut sup = AppControlSupervisor::new(
        config("enforce", Some(trusted)),
        bus,
        Box::new(RecordingProviderHandle(provider.clone())),
    );
    let err = sup
        .apply_policy(signed)
        .expect_err("must surface backend error");
    assert!(matches!(err, AppControlError::Pal(PalError::Backend(_))));
}
