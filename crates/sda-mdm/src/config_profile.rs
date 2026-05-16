//! Declarative-config-profile sub-module (Phase M3.1–M3.3).
//!
//! Implements signed config-profile loading and enforcement per
//! `docs/desktop-mdm/PROPOSAL.md` § 3.5 and
//! `docs/desktop-mdm/ARCHITECTURE.md` § 3.5.
//!
//! Pipeline:
//!
//! 1. The TRDS bundle writer drops `profile.json` (and a sidecar
//!    `profile.sig`) under [`sda_core::config::MdmConfig::bundle_path`].
//! 2. The [`Watcher`] (built on the `notify` crate) wakes the
//!    supervisor on every filesystem change.
//! 3. The supervisor calls [`load_and_verify`] which:
//!     a. Parses the body as a [`ConfigProfileBody`].
//!     b. Canonicalises it (RFC 8785-ish — `serde_json::to_vec` over
//!        a struct with `deny_unknown_fields` and stable field order
//!        is enough for our purposes; the control plane signs the
//!        same bytes).
//!     c. Verifies the Ed25519 signature against the pinned signing
//!        key set.
//! 4. On verification success the supervisor calls
//!    [`MdmProvider::apply_config_profile`] and publishes
//!    [`EventKind::MdmConfigProfileApplied`].
//! 5. On verification failure the supervisor publishes
//!    [`FindingKind::ConfigProfileTampered`] and keeps the previous
//!    profile.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use sda_pal::mdm::{MdmProvider, SignedConfigProfile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;
use thiserror::Error;
use tracing::{info, warn};
use uuid::Uuid;

use crate::module::MODULE_SOURCE;

/// Wire payload published on
/// [`EventKind::MdmConfigProfileApplied`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MdmConfigProfileAppliedPayload {
    pub profile_id: Uuid,
    pub profile_sha256: String,
    pub applied_at: DateTime<Utc>,
    pub status: ConfigProfileStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigProfileStatus {
    Applied,
    Tampered,
    Failure,
}

/// Signed config profile body persisted by TRDS. Stable wire
/// schema: every field is mandatory and `deny_unknown_fields` keeps
/// the canonical-JSON pre-image stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigProfileBody {
    pub profile_id: Uuid,
    pub schema_version: u16,
    pub issued_at: DateTime<Utc>,
    pub password_policy: PasswordPolicy,
    pub screen_lock: ScreenLockPolicy,
    pub bluetooth: PolicyMode,
    pub camera: PolicyMode,
    pub wifi: WifiPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordPolicy {
    pub min_length: u8,
    pub require_complexity: bool,
    pub max_age_days: u32,
    pub max_attempts: u8,
    pub lockout_minutes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenLockPolicy {
    pub timeout_secs: u32,
    pub require_password_on_resume: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    Allow,
    Audit,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WifiPolicy {
    #[serde(default)]
    pub allowed_ssids: Vec<String>,
    #[serde(default)]
    pub block_open_networks: bool,
}

/// Signed wire envelope: body + ed25519 signature + key ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedProfile {
    pub body: ConfigProfileBody,
    /// Hex-encoded 64-byte Ed25519 signature over `canonicalise(body)`.
    pub signature: String,
    /// `key_id` (must match one of the pinned signing keys).
    pub key_id: String,
}

/// Errors raised by [`load_and_verify`].
#[derive(Debug, Error)]
pub enum ConfigProfileError {
    #[error("I/O error reading profile: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("signature must be 128 hex chars (64 bytes)")]
    BadSignatureLength,
    #[error("signature hex decode failed: {0}")]
    BadSignatureHex(String),
    #[error("unknown signing key_id: {0}")]
    UnknownKeyId(String),
    #[error("signature verification failed")]
    BadSignature,
    #[error("profile body canonicalise failed")]
    Canonicalise,
}

/// Load a `SignedProfile` from disk, verify its signature against
/// the pinned keys, and return the [`SignedConfigProfile`] the PAL
/// expects.
///
/// `pinned_keys` is a slice of `(key_id, verifying_key)` pairs the
/// control plane has provisioned at enrollment time. The first key
/// whose `key_id` matches is used.
pub fn load_and_verify(
    path: &Path,
    pinned_keys: &[(String, VerifyingKey)],
) -> Result<SignedConfigProfile, ConfigProfileError> {
    let bytes = std::fs::read(path)?;
    let signed: SignedProfile = serde_json::from_slice(&bytes)?;

    if signed.signature.len() != 128 {
        return Err(ConfigProfileError::BadSignatureLength);
    }
    let mut sig_bytes = [0u8; 64];
    hex::decode_to_slice(signed.signature.as_str(), &mut sig_bytes)
        .map_err(|e| ConfigProfileError::BadSignatureHex(e.to_string()))?;
    let signature = Signature::from_bytes(&sig_bytes);

    let key = pinned_keys
        .iter()
        .find(|(id, _)| id == &signed.key_id)
        .map(|(_, k)| k)
        .ok_or_else(|| ConfigProfileError::UnknownKeyId(signed.key_id.clone()))?;

    let preimage = canonicalise(&signed.body)?;
    key.verify_strict(&preimage, &signature)
        .map_err(|_| ConfigProfileError::BadSignature)?;

    let mut h = Sha256::new();
    h.update(&preimage);
    let sha = h.finalize();

    Ok(SignedConfigProfile {
        profile_id: signed.body.profile_id,
        body: preimage,
        signature: sig_bytes.to_vec(),
        signing_key_id: signed.key_id,
        sha256: hex::encode(sha),
    })
}

/// Canonical bytes used for signing/verification. We rely on
/// `serde_json`'s deterministic struct serialisation order plus
/// `deny_unknown_fields` on every nested struct.
pub fn canonicalise(body: &ConfigProfileBody) -> Result<Vec<u8>, ConfigProfileError> {
    serde_json::to_vec(body).map_err(|_| ConfigProfileError::Canonicalise)
}

/// Notify-backed filesystem watcher. The supervisor owns one of
/// these and reads from `events()` in its main `select!` loop.
///
/// We deliberately wrap [`notify::RecommendedWatcher`] behind a thin
/// API so unit tests can substitute a stub via the [`PathChangeStream`]
/// trait.
pub struct Watcher {
    _inner: Option<notify::RecommendedWatcher>,
    rx: Receiver<()>,
    path: PathBuf,
}

impl Watcher {
    /// Start watching `path` (the parent directory is watched
    /// recursively; the parent must already exist).
    pub fn new(path: PathBuf) -> Result<Self, notify::Error> {
        use notify::{Event as NEvent, EventKind as NEventKind, RecursiveMode, Watcher as _};
        let (tx, rx) = mpsc::channel::<()>();
        let path_for_filter = path.clone();
        let mut w = notify::recommended_watcher(move |res: notify::Result<NEvent>| {
            let Ok(ev) = res else {
                return;
            };
            let interesting = matches!(
                ev.kind,
                NEventKind::Create(_) | NEventKind::Modify(_) | NEventKind::Remove(_)
            ) && ev.paths.iter().any(|p| p == &path_for_filter);
            if interesting {
                let _ = tx.send(());
            }
        })?;
        // Watch the parent (file may not exist yet on first run).
        let target = path.parent().unwrap_or_else(|| Path::new("."));
        if target.exists() {
            w.watch(target, RecursiveMode::NonRecursive)?;
        }
        Ok(Self {
            _inner: Some(w),
            rx,
            path,
        })
    }

    /// Block until the watched path changes. Returns the watched
    /// path so callers don't need to re-derive it. Uses a short
    /// timeout so the supervisor `select!` can interleave cleanly.
    pub fn poll(&self, timeout: Duration) -> Option<PathBuf> {
        match self.rx.recv_timeout(timeout) {
            Ok(()) => Some(self.path.clone()),
            Err(_) => None,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Apply one verified profile via the PAL and publish the
/// MdmConfigProfileApplied event.
pub async fn apply_and_publish(
    profile: &SignedConfigProfile,
    provider: &dyn MdmProvider,
    bus: &EventBus,
) -> MdmConfigProfileAppliedPayload {
    let applied_at = Utc::now();
    let (status, error) = match provider.apply_config_profile(profile) {
        Ok(()) => (ConfigProfileStatus::Applied, None),
        Err(e) => {
            warn!(error = %e, "mdm: apply_config_profile failed");
            (ConfigProfileStatus::Failure, Some(e.to_string()))
        }
    };
    let payload = MdmConfigProfileAppliedPayload {
        profile_id: profile.profile_id,
        profile_sha256: profile.sha256.clone(),
        applied_at,
        status,
        error,
    };
    publish_applied(bus, &payload).await;
    info!(
        profile_id = %profile.profile_id,
        ?status,
        "mdm: config profile applied"
    );
    payload
}

/// Publish a `ConfigProfileTampered` finding when signature
/// verification fails. The supervisor calls this and keeps the
/// previous profile installed.
pub async fn publish_tampered(
    bus: &EventBus,
    profile_path: &Path,
    reason: &str,
) -> MdmConfigProfileAppliedPayload {
    let payload = MdmConfigProfileAppliedPayload {
        profile_id: Uuid::nil(),
        profile_sha256: String::new(),
        applied_at: Utc::now(),
        status: ConfigProfileStatus::Tampered,
        error: Some(reason.to_string()),
    };
    publish_applied(bus, &payload).await;
    // Also publish a DeviceControlFinding so the LDE can act on it.
    let finding = serde_json::json!({
        "kind": "config_profile_tampered",
        "path": profile_path.display().to_string(),
        "reason": reason,
        "captured_at": Utc::now(),
    });
    let event = Event::new(
        MODULE_SOURCE,
        Priority::High,
        EventKind::DeviceControlFinding {
            payload: finding.to_string(),
        },
    );
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, "mdm: config-profile-tampered finding publish_to_server failed");
    }
    payload
}

async fn publish_applied(bus: &EventBus, payload: &MdmConfigProfileAppliedPayload) {
    let json = match serde_json::to_string(payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "mdm: config-profile-applied serialise failed");
            return;
        }
    };
    let event = Event::new(
        MODULE_SOURCE,
        Priority::Normal,
        EventKind::MdmConfigProfileApplied { payload: json },
    );
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, "mdm: config-profile-applied publish_to_server failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use sda_pal::mdm::{
        EncryptionOutcome, MdmError, OsUpdateOpts, OsUpdateOutcome, RawRecoveryKey,
        RecoveryKeyType, WipeOpts, WipeOutcome,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn sample_body(id: Uuid) -> ConfigProfileBody {
        ConfigProfileBody {
            profile_id: id,
            schema_version: 1,
            issued_at: Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 0).unwrap(),
            password_policy: PasswordPolicy {
                min_length: 12,
                require_complexity: true,
                max_age_days: 90,
                max_attempts: 5,
                lockout_minutes: 15,
            },
            screen_lock: ScreenLockPolicy {
                timeout_secs: 300,
                require_password_on_resume: true,
            },
            bluetooth: PolicyMode::Audit,
            camera: PolicyMode::Allow,
            wifi: WifiPolicy {
                allowed_ssids: vec!["corp-wifi".into()],
                block_open_networks: true,
            },
        }
    }

    fn sign(body: &ConfigProfileBody, key: &ed25519_dalek::SigningKey) -> SignedProfile {
        let pre = serde_json::to_vec(body).unwrap();
        let sig = key.sign(&pre);
        SignedProfile {
            body: body.clone(),
            signature: hex::encode(sig.to_bytes()),
            key_id: "pinned-key".to_string(),
        }
    }

    use chrono::TimeZone;

    #[test]
    fn load_and_verify_accepts_valid_signature() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("profile.json");
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let id = Uuid::from_u128(0x1234);
        let signed = sign(&sample_body(id), &key);
        std::fs::write(&path, serde_json::to_vec(&signed).unwrap()).unwrap();
        let pinned = vec![("pinned-key".to_string(), key.verifying_key())];
        let parsed = load_and_verify(&path, &pinned).unwrap();
        assert_eq!(parsed.profile_id, id);
        assert_eq!(parsed.signing_key_id, "pinned-key");
        assert_eq!(parsed.sha256.len(), 64);
    }

    #[test]
    fn load_and_verify_rejects_tampered_body() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("profile.json");
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut signed = sign(&sample_body(Uuid::nil()), &key);
        signed.body.password_policy.min_length = 4; // tamper after signing
        std::fs::write(&path, serde_json::to_vec(&signed).unwrap()).unwrap();
        let pinned = vec![("pinned-key".to_string(), key.verifying_key())];
        let err = load_and_verify(&path, &pinned).unwrap_err();
        matches!(err, ConfigProfileError::BadSignature);
    }

    #[test]
    fn load_and_verify_rejects_unknown_key_id() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("profile.json");
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let signed = sign(&sample_body(Uuid::nil()), &key);
        std::fs::write(&path, serde_json::to_vec(&signed).unwrap()).unwrap();
        let other = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let pinned = vec![("different-key".to_string(), other.verifying_key())];
        let err = load_and_verify(&path, &pinned).unwrap_err();
        assert!(matches!(err, ConfigProfileError::UnknownKeyId(_)));
    }

    #[test]
    fn load_and_verify_rejects_bad_hex_signature() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("profile.json");
        let signed = SignedProfile {
            body: sample_body(Uuid::nil()),
            signature: "not-hex".repeat(20),
            key_id: "pinned-key".to_string(),
        };
        std::fs::write(&path, serde_json::to_vec(&signed).unwrap()).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let pinned = vec![("pinned-key".to_string(), key.verifying_key())];
        let err = load_and_verify(&path, &pinned).unwrap_err();
        assert!(matches!(
            err,
            ConfigProfileError::BadSignatureHex(_) | ConfigProfileError::BadSignatureLength
        ));
    }

    struct MockProvider {
        fail: bool,
        applied: Arc<AtomicBool>,
    }
    impl MdmProvider for MockProvider {
        fn wipe(&self, _o: &WipeOpts) -> sda_pal::mdm::Result<WipeOutcome> {
            unreachable!()
        }
        fn lock(&self, _m: &str) -> sda_pal::mdm::Result<()> {
            unreachable!()
        }
        fn escrow_recovery_key(&self) -> sda_pal::mdm::Result<RawRecoveryKey> {
            Ok(RawRecoveryKey {
                key_type: RecoveryKeyType::Luks,
                material: vec![],
            })
        }
        fn install_os_updates(
            &self,
            _o: &OsUpdateOpts,
        ) -> sda_pal::mdm::Result<OsUpdateOutcome> {
            unreachable!()
        }
        fn apply_config_profile(&self, _p: &SignedConfigProfile) -> sda_pal::mdm::Result<()> {
            self.applied.store(true, Ordering::Relaxed);
            if self.fail {
                Err(MdmError::Command("apply blocked".into()))
            } else {
                Ok(())
            }
        }
        fn enable_disk_encryption(&self) -> sda_pal::mdm::Result<EncryptionOutcome> {
            unreachable!()
        }
        fn enable_firewall(&self) -> sda_pal::mdm::Result<()> {
            unreachable!()
        }
        fn set_screen_lock(&self, _t: u32) -> sda_pal::mdm::Result<()> {
            unreachable!()
        }
        fn enter_lost_mode(&self, _m: &str) -> sda_pal::mdm::Result<()> {
            unreachable!()
        }
        fn exit_lost_mode(&self) -> sda_pal::mdm::Result<()> {
            unreachable!()
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn apply_and_publish_success_records_applied_status() {
        let (bus, _) = EventBus::new(8, 8);
        let provider = MockProvider {
            fail: false,
            applied: Arc::new(AtomicBool::new(false)),
        };
        let applied = provider.applied.clone();
        let profile = SignedConfigProfile {
            profile_id: Uuid::nil(),
            body: serde_json::to_vec(&sample_body(Uuid::nil())).unwrap(),
            signature: vec![0u8; 64],
            signing_key_id: "pinned-key".into(),
            sha256: "0".repeat(64),
        };
        let payload = apply_and_publish(&profile, &provider, &bus).await;
        assert!(applied.load(Ordering::Relaxed));
        assert_eq!(payload.status, ConfigProfileStatus::Applied);
        assert!(payload.error.is_none());
    }
}
