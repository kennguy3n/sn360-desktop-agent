//! Desktop MDM config-profile end-to-end suite.
//!
//! Hermetic exercises of the Phase-M3 surface (`docs/desktop-mdm/`)
//! using a recording [`MdmProvider`] mock and the public
//! [`sda_mdm::config_profile::load_and_verify`] / `apply_and_publish`
//! pipeline.
//!
//! Coverage:
//!
//! 1. A signed profile written to disk loads, verifies, and is
//!    applied via the PAL. The handler publishes exactly one
//!    [`EventKind::MdmConfigProfileApplied`] event carrying the
//!    `profile_id` and the canonical-JSON SHA-256 of the body.
//! 2. A profile whose body is mutated after signing is rejected by
//!    [`load_and_verify`] (`BadSignature`); the PAL is never
//!    invoked, and a `ConfigProfileTampered`
//!    [`EventKind::DeviceControlFinding`] is published so the LDE can
//!    raise a finding. The previously applied profile remains the
//!    last value the PAL saw.
//! 3. The canonical JSON handed to the PAL preserves every policy
//!    class (Bluetooth / camera / Wi-Fi) so per-OS apply paths see
//!    the same source-of-truth payload on every platform.

use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use chrono::{TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sda_event_bus::{Event, EventBus, EventKind};
use sda_mdm::config_profile::{
    apply_and_publish, load_and_verify, publish_tampered, ConfigProfileBody, ConfigProfileError,
    ConfigProfileStatus, MdmConfigProfileAppliedPayload, PasswordPolicy, PolicyMode,
    ScreenLockPolicy, SignedProfile, WifiPolicy,
};
use sda_pal::mdm::{
    EncryptionOutcome, MdmError, MdmProvider, OsUpdateOpts, OsUpdateOutcome, RawRecoveryKey,
    RecoveryKeyType, Result as MdmResult, SignedConfigProfile, WipeOpts, WipeOutcome,
};
use tempfile::TempDir;
use tokio::sync::mpsc::Receiver;
use uuid::Uuid;

// ---------- Test harness ---------------------------------------------------

/// Records every `apply_config_profile` call so the test can assert
/// the PAL received the expected canonical JSON exactly once (or
/// zero times in the tampered-profile case).
#[derive(Default)]
struct RecordingProvider {
    apply_calls: AtomicUsize,
    last_canonical: Mutex<Option<String>>,
    last_profile_id: Mutex<Option<Uuid>>,
    fail_apply: AtomicBool,
}

impl MdmProvider for RecordingProvider {
    fn wipe(&self, _o: &WipeOpts) -> MdmResult<WipeOutcome> {
        unreachable!("wipe is M2, not M3")
    }
    fn lock(&self, _m: &str) -> MdmResult<()> {
        unreachable!("lock is M2, not M3")
    }
    fn escrow_recovery_key(&self) -> MdmResult<RawRecoveryKey> {
        Ok(RawRecoveryKey {
            key_type: RecoveryKeyType::Luks,
            material: vec![],
        })
    }
    fn install_os_updates(&self, _o: &OsUpdateOpts) -> MdmResult<OsUpdateOutcome> {
        unreachable!("install_os_updates is M1, not M3")
    }
    fn apply_config_profile(&self, p: &SignedConfigProfile) -> MdmResult<()> {
        self.apply_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_canonical.lock().unwrap() = Some(p.canonical_json.clone());
        *self.last_profile_id.lock().unwrap() = Some(p.profile_id);
        if self.fail_apply.load(Ordering::SeqCst) {
            return Err(MdmError::Command("apply blocked".into()));
        }
        Ok(())
    }
    fn enable_disk_encryption(&self) -> MdmResult<EncryptionOutcome> {
        unreachable!("enable_disk_encryption is M1, not M3")
    }
    fn enable_firewall(&self) -> MdmResult<()> {
        unreachable!("enable_firewall is M1, not M3")
    }
    fn set_screen_lock(&self, _t: u32) -> MdmResult<()> {
        unreachable!("set_screen_lock is M1, not M3")
    }
    fn enter_lost_mode(&self, _m: &str) -> MdmResult<()> {
        unreachable!("enter_lost_mode is M2, not M3")
    }
    fn exit_lost_mode(&self) -> MdmResult<()> {
        unreachable!("exit_lost_mode is M2, not M3")
    }
}

fn pinned_keypair() -> (SigningKey, VerifyingKey, String) {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let vk = sk.verifying_key();
    (sk, vk, "sn360-mdm-2026-05".to_string())
}

fn sample_body(profile_id: Uuid) -> ConfigProfileBody {
    ConfigProfileBody {
        profile_id,
        tenant_id: Uuid::from_u128(0x_C0FFEE),
        schema_version: 1,
        issued_at: Utc.with_ymd_and_hms(2026, 5, 7, 8, 0, 0).unwrap(),
        password_policy: PasswordPolicy {
            min_length: 14,
            require_complexity: true,
            max_age_days: 60,
            max_attempts: 5,
            lockout_minutes: 15,
        },
        screen_lock: ScreenLockPolicy {
            timeout_secs: 300,
            require_password_on_resume: true,
        },
        bluetooth: PolicyMode::Block,
        camera: PolicyMode::Audit,
        wifi: WifiPolicy {
            allowed_ssids: vec!["corp-wifi".into(), "corp-guest".into()],
            block_open_networks: true,
        },
    }
}

fn write_signed_profile(
    dir: &TempDir,
    body: &ConfigProfileBody,
    sk: &SigningKey,
    key_id: &str,
) -> PathBuf {
    let preimage = serde_json::to_vec(body).expect("canonicalise body");
    let signature = sk.sign(&preimage);
    let signed = SignedProfile {
        body: body.clone(),
        signature: hex::encode(signature.to_bytes()),
        key_id: key_id.to_string(),
    };
    let path = dir.path().join("profile.json");
    std::fs::write(&path, serde_json::to_vec(&signed).unwrap()).unwrap();
    path
}

async fn drain_for(rx: &mut Receiver<Event>, budget: Duration) -> Vec<Event> {
    let mut out = Vec::new();
    while let Ok(Some(ev)) = tokio::time::timeout(budget, rx.recv()).await {
        out.push(ev);
    }
    out
}

// ---------- Scenario 1: signed profile applied + event emitted ----------

#[tokio::test(flavor = "current_thread")]
async fn signed_profile_applies_and_publishes_event() {
    let dir = TempDir::new().unwrap();
    let (sk, vk, key_id) = pinned_keypair();
    let profile_id = Uuid::from_u128(0xABCDE);
    let body = sample_body(profile_id);
    let path = write_signed_profile(&dir, &body, &sk, &key_id);

    // Step 1 — verify the signature against the pinned key.
    let pinned = vec![(key_id.clone(), vk)];
    let verified = load_and_verify(&path, &pinned).expect("valid signed profile must verify");
    assert_eq!(verified.profile_id(), profile_id);
    assert_eq!(verified.sha256.len(), 64, "sha256 must be hex-encoded");

    // Step 2 — apply via the PAL and publish on the bus.
    let (bus, mut rx) = EventBus::new(64, 64);
    let provider = Arc::new(RecordingProvider::default());
    let payload = apply_and_publish(&verified, provider.as_ref() as &dyn MdmProvider, &bus).await;

    assert_eq!(payload.status, ConfigProfileStatus::Applied);
    assert_eq!(payload.profile_id, profile_id);
    assert_eq!(payload.profile_sha256, verified.sha256);
    assert!(payload.error.is_none());
    assert_eq!(
        provider.apply_calls.load(Ordering::SeqCst),
        1,
        "apply_config_profile must be invoked exactly once"
    );
    assert_eq!(
        provider.last_profile_id.lock().unwrap().clone(),
        Some(profile_id),
        "PAL must receive the same profile_id we verified"
    );

    // Bus must have exactly one MdmConfigProfileApplied envelope
    // matching the payload we returned.
    let events = drain_for(&mut rx, Duration::from_millis(150)).await;
    let applied: Vec<MdmConfigProfileAppliedPayload> = events
        .iter()
        .filter_map(|ev| match &ev.kind {
            EventKind::MdmConfigProfileApplied { payload } => serde_json::from_str(payload).ok(),
            _ => None,
        })
        .collect();
    assert_eq!(
        applied.len(),
        1,
        "exactly one applied event must be emitted"
    );
    assert_eq!(applied[0].profile_id, profile_id);
    assert_eq!(applied[0].status, ConfigProfileStatus::Applied);
    assert_eq!(applied[0].profile_sha256, verified.sha256);
}

// ---------- Scenario 2: tampered body rejected, previous retained -------

#[tokio::test(flavor = "current_thread")]
async fn tampered_profile_rejected_and_previous_retained() {
    let dir = TempDir::new().unwrap();
    let (sk, vk, key_id) = pinned_keypair();
    let provider = Arc::new(RecordingProvider::default());

    // Step 1 — apply a clean profile so the PAL has a known last-good.
    let clean_id = Uuid::from_u128(0x_11111111);
    let clean_body = sample_body(clean_id);
    let clean_path = write_signed_profile(&dir, &clean_body, &sk, &key_id);
    let pinned = vec![(key_id.clone(), vk)];
    let verified =
        load_and_verify(&clean_path, &pinned).expect("the unmodified profile must verify");

    let (bus, mut rx) = EventBus::new(64, 64);
    apply_and_publish(&verified, provider.as_ref() as &dyn MdmProvider, &bus).await;
    let _ = drain_for(&mut rx, Duration::from_millis(50)).await;
    assert_eq!(
        provider.apply_calls.load(Ordering::SeqCst),
        1,
        "clean profile must apply once"
    );
    let retained = *provider.last_profile_id.lock().unwrap();
    assert_eq!(retained, Some(clean_id));

    // Step 2 — write a profile, sign it, then mutate the body after
    // signing. The on-disk JSON is now self-inconsistent.
    let tampered_id = Uuid::from_u128(0x_22222222);
    let tampered_path = dir.path().join("tampered.json");
    let preimage = serde_json::to_vec(&sample_body(tampered_id)).unwrap();
    let signature = sk.sign(&preimage);
    let mut tampered_body = sample_body(tampered_id);
    tampered_body.password_policy.min_length = 4; // weakens policy post-sign
    let signed = SignedProfile {
        body: tampered_body,
        signature: hex::encode(signature.to_bytes()),
        key_id: key_id.clone(),
    };
    std::fs::write(&tampered_path, serde_json::to_vec(&signed).unwrap()).unwrap();

    // Step 3 — load_and_verify must refuse the tampered body.
    let err = load_and_verify(&tampered_path, &pinned)
        .expect_err("post-sign mutation must fail signature verification");
    assert!(
        matches!(err, ConfigProfileError::BadSignature),
        "tampered body must fail with BadSignature, got: {err:?}"
    );

    // Step 4 — the supervisor would publish a tampered finding and
    // keep the previous profile. The PAL must not have been invoked
    // a second time.
    let _payload = publish_tampered(&bus, &tampered_path, "BadSignature").await;
    let events = drain_for(&mut rx, Duration::from_millis(150)).await;

    assert_eq!(
        provider.apply_calls.load(Ordering::SeqCst),
        1,
        "tampered profile must not be applied"
    );
    assert_eq!(
        *provider.last_profile_id.lock().unwrap(),
        Some(clean_id),
        "previous profile must remain the PAL's last-applied value"
    );

    // The supervisor publishes a ConfigProfileTampered finding via
    // DeviceControlFinding plus a tampered-status MdmConfigProfileApplied
    // envelope so the control plane can correlate both.
    let mut tampered_finding = false;
    let mut tampered_event = false;
    for ev in &events {
        match &ev.kind {
            EventKind::DeviceControlFinding { payload } => {
                let v: serde_json::Value = serde_json::from_str(payload).unwrap();
                if v["kind"] == "config_profile_tampered" {
                    tampered_finding = true;
                }
            }
            EventKind::MdmConfigProfileApplied { payload } => {
                let p: MdmConfigProfileAppliedPayload = serde_json::from_str(payload).unwrap();
                if p.status == ConfigProfileStatus::Tampered {
                    tampered_event = true;
                    assert_eq!(p.profile_id, Uuid::nil());
                }
            }
            _ => {}
        }
    }
    assert!(
        tampered_finding,
        "ConfigProfileTampered finding must be published"
    );
    assert!(
        tampered_event,
        "MdmConfigProfileApplied(status=Tampered) event must be published"
    );
}

// ---------- Scenario 3: Bluetooth / camera / Wi-Fi policy enforcement ----

#[tokio::test(flavor = "current_thread")]
async fn canonical_json_carries_bluetooth_camera_and_wifi_policies() {
    let dir = TempDir::new().unwrap();
    let (sk, vk, key_id) = pinned_keypair();
    let profile_id = Uuid::from_u128(0x_30303030);
    let body = sample_body(profile_id);
    let path = write_signed_profile(&dir, &body, &sk, &key_id);
    let pinned = vec![(key_id, vk)];
    let verified = load_and_verify(&path, &pinned).expect("valid profile must verify");

    let (bus, _rx) = EventBus::new(8, 8);
    let provider = Arc::new(RecordingProvider::default());
    let _ = apply_and_publish(&verified, provider.as_ref() as &dyn MdmProvider, &bus).await;

    // The PAL receives the canonical JSON verbatim — that's the
    // single source of truth every platform (`LinuxMdmProvider`,
    // `MacMdmProvider`, `WindowsMdmProvider`) enforces. Confirm
    // every policy class is preserved end-to-end so per-OS apply
    // paths cannot accidentally drop a class.
    let canonical = provider
        .last_canonical
        .lock()
        .unwrap()
        .clone()
        .expect("PAL must have received a canonical JSON");
    let parsed: serde_json::Value =
        serde_json::from_str(&canonical).expect("canonical JSON must round-trip");

    // Password policy
    assert_eq!(parsed["password_policy"]["min_length"], 14);
    assert_eq!(parsed["password_policy"]["require_complexity"], true);

    // Screen lock policy
    assert_eq!(parsed["screen_lock"]["timeout_secs"], 300);
    assert_eq!(parsed["screen_lock"]["require_password_on_resume"], true);

    // Bluetooth / camera / Wi-Fi — the three policy classes the
    // per-OS providers enforce via `apply_config_profile`.
    assert_eq!(parsed["bluetooth"], "block");
    assert_eq!(parsed["camera"], "audit");
    assert_eq!(parsed["wifi"]["block_open_networks"], true);
    let ssids = parsed["wifi"]["allowed_ssids"]
        .as_array()
        .expect("allowed_ssids must be present");
    assert_eq!(ssids.len(), 2);
    assert!(ssids.iter().any(|s| s == "corp-wifi"));
    assert!(ssids.iter().any(|s| s == "corp-guest"));
}
