//! Recovery-key escrow sub-module (Phase M1.3).
//!
//! Implements the once-per-boot escrow described in
//! `docs/desktop-mdm/PROPOSAL.md` § 3.6 and
//! `docs/desktop-mdm/ARCHITECTURE.md` § 3.3.
//!
//! Wire format:
//!
//! 1. The PAL ([`sda_pal::mdm::MdmProvider::escrow_recovery_key`])
//!    returns the raw recovery key material.
//! 2. We derive a per-device wrapping key:
//!    `wrap = HKDF-SHA256(seed, info = b"sda-mdm-recovery-key",
//!                         salt = device_id.as_bytes())`.
//! 3. The raw key is encrypted with ChaCha20-Poly1305 using a random
//!    96-bit nonce.
//! 4. The resulting envelope (ciphertext, nonce, tenant/device, key
//!    type, timestamp) is signed by the agent's Ed25519 evidence key.
//! 5. The signed envelope is published as
//!    [`EventKind::MdmRecoveryKeyEscrowed`] with `Priority::High`.
//!
//! Once-per-boot semantics are enforced by the [`EscrowGuard`] state
//! held by the supervisor — the second call within the same boot is
//! a no-op unless the underlying key has rotated (the PAL returns a
//! different `material`).

use chrono::Utc;
use ed25519_dalek::Signer;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use sda_pal::mdm::{MdmProvider, RawRecoveryKey, RecoveryKeyPayload};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::module::MODULE_SOURCE;

const HKDF_INFO: &[u8] = b"sda-mdm-recovery-key";

/// Errors produced by the recovery-key escrow sub-module.
#[derive(Debug, Error)]
pub enum RecoveryKeyError {
    #[error("provider returned no recovery key: {0}")]
    Provider(#[from] sda_pal::mdm::MdmError),
    #[error("ChaCha20-Poly1305 encryption failed")]
    Encrypt,
    #[error("HKDF expand failed")]
    HkdfExpand,
    #[error("RNG failed")]
    Rng,
    #[error("event publish failed: {0}")]
    Publish(String),
}

/// In-memory state tracking which recovery-key material has been
/// escrowed during this boot. The supervisor keeps one of these and
/// asks it whether the current material is "new" before invoking
/// [`escrow_once`].
#[derive(Debug, Default)]
pub struct EscrowGuard {
    /// SHA-256 of the most recently escrowed raw key material.
    last_material_sha256: Option<[u8; 32]>,
}

impl EscrowGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hash the raw material and compare against the last escrow. If
    /// the hashes differ (or no escrow has occurred this boot),
    /// returns `true` and records the new hash. Otherwise returns
    /// `false` so callers can skip the duplicate escrow.
    pub fn should_escrow(&mut self, material: &[u8]) -> bool {
        let h = sha256(material);
        match self.last_material_sha256 {
            Some(prev) if prev == h => false,
            _ => {
                self.last_material_sha256 = Some(h);
                true
            }
        }
    }
}

/// Wrap, sign, and publish a single recovery key.
///
/// `seed` is the per-device escrow seed provisioned at enrollment —
/// it never leaves the agent process. `signing_key` is the agent's
/// Ed25519 evidence key.
///
/// The function is intentionally synchronous so it can be exercised
/// in a unit test without spinning up tokio. The supervisor pushes
/// the resulting event onto the bus separately.
pub fn build_payload(
    raw: &RawRecoveryKey,
    seed: &[u8],
    tenant_id: Uuid,
    device_id: Uuid,
    signing_key: &ed25519_dalek::SigningKey,
    key_id: &str,
) -> Result<RecoveryKeyPayload, RecoveryKeyError> {
    // 1. Derive the wrapping key with HKDF-SHA256.
    let mut wrap_bytes = [0u8; 32];
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, device_id.as_bytes());
    let prk = salt.extract(seed);
    let okm = prk
        .expand(&[HKDF_INFO], hkdf::HKDF_SHA256)
        .map_err(|_| RecoveryKeyError::HkdfExpand)?;
    okm.fill(&mut wrap_bytes)
        .map_err(|_| RecoveryKeyError::HkdfExpand)?;

    // 2. Build the ChaCha20-Poly1305 sealing key.
    let unbound =
        UnboundKey::new(&CHACHA20_POLY1305, &wrap_bytes).map_err(|_| RecoveryKeyError::Encrypt)?;
    let key = LessSafeKey::new(unbound);

    // 3. Generate a random 96-bit nonce.
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| RecoveryKeyError::Rng)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // 4. Encrypt in place: copy the material, append the auth tag.
    let mut ciphertext = raw.material.clone();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|_| RecoveryKeyError::Encrypt)?;

    // 5. Build the wire envelope.
    let escrowed_at = Utc::now();
    let to_sign = signing_preimage(
        tenant_id,
        device_id,
        raw.key_type,
        &ciphertext,
        &nonce_bytes,
        escrowed_at,
    );
    let signature = signing_key.sign(&to_sign).to_bytes().to_vec();

    Ok(RecoveryKeyPayload {
        tenant_id,
        device_id,
        key_type: raw.key_type,
        ciphertext,
        nonce: nonce_bytes,
        escrowed_at,
        signature,
        key_id: key_id.to_string(),
    })
}

/// Pre-image fed into the Ed25519 signature. The control plane
/// re-builds the same bytes from the published payload to verify.
fn signing_preimage(
    tenant_id: Uuid,
    device_id: Uuid,
    key_type: sda_pal::mdm::RecoveryKeyType,
    ciphertext: &[u8],
    nonce: &[u8; 12],
    escrowed_at: chrono::DateTime<Utc>,
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(tenant_id.as_bytes());
    h.update(device_id.as_bytes());
    h.update(format!("{:?}", key_type).as_bytes());
    h.update(ciphertext);
    h.update(nonce);
    h.update(escrowed_at.to_rfc3339().as_bytes());
    h.finalize().to_vec()
}

/// Identity material bound into the recovery-key envelope. Bundled
/// so [`escrow_once`] does not grow an inscrutable argument list.
pub struct EscrowIdentity<'a> {
    pub seed: &'a [u8],
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub signing_key: &'a ed25519_dalek::SigningKey,
    pub key_id: &'a str,
}

/// One-shot helper used by the supervisor: pulls the raw key from
/// the PAL, dedups against the [`EscrowGuard`], builds the signed
/// payload, and publishes it on the bus.
///
/// Returns `Ok(None)` when the guard suppresses a duplicate, `Ok(Some(_))`
/// when a fresh payload was published, and `Err` for hard failures.
pub async fn escrow_once(
    provider: &dyn MdmProvider,
    bus: &EventBus,
    guard: &mut EscrowGuard,
    identity: &EscrowIdentity<'_>,
) -> Result<Option<RecoveryKeyPayload>, RecoveryKeyError> {
    let raw = match provider.escrow_recovery_key() {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "mdm: recovery-key escrow refused by PAL");
            return Err(RecoveryKeyError::Provider(e));
        }
    };

    if !guard.should_escrow(&raw.material) {
        debug!("mdm: recovery key unchanged — skipping duplicate escrow");
        return Ok(None);
    }

    let payload = build_payload(
        &raw,
        identity.seed,
        identity.tenant_id,
        identity.device_id,
        identity.signing_key,
        identity.key_id,
    )?;
    let json =
        serde_json::to_string(&payload).map_err(|e| RecoveryKeyError::Publish(e.to_string()))?;
    let event = Event::new(
        MODULE_SOURCE,
        Priority::High,
        EventKind::MdmRecoveryKeyEscrowed { payload: json },
    );
    // Per the event-bus contract `publish_to_server` already does a
    // local broadcast — do NOT add a fallback `publish()` here.
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, "mdm: recovery key event publish_to_server failed");
    }
    info!(key_id = %payload.key_id, "mdm: recovery key escrowed");
    Ok(Some(payload))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::aead::{BoundKey, NonceSequence, OpeningKey};
    use sda_pal::mdm::RecoveryKeyType;

    fn signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[42u8; 32])
    }

    #[test]
    fn guard_blocks_duplicate_material() {
        let mut g = EscrowGuard::new();
        assert!(g.should_escrow(b"abc"));
        assert!(!g.should_escrow(b"abc"));
        assert!(g.should_escrow(b"abd"));
        assert!(!g.should_escrow(b"abd"));
    }

    #[test]
    fn payload_round_trips_decrypts_to_original() {
        let raw = RawRecoveryKey {
            key_type: RecoveryKeyType::BitLocker,
            material: b"123456-789012-345678-901234".to_vec(),
        };
        let seed = [9u8; 32];
        let tenant = Uuid::nil();
        let device = Uuid::from_u128(0x1234_5678);
        let key = signing_key();
        let payload = build_payload(&raw, &seed, tenant, device, &key, "test").unwrap();

        // Re-derive the wrapping key and decrypt.
        let mut wrap = [0u8; 32];
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, device.as_bytes());
        let prk = salt.extract(&seed);
        prk.expand(&[HKDF_INFO], hkdf::HKDF_SHA256)
            .unwrap()
            .fill(&mut wrap)
            .unwrap();
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &wrap).unwrap();

        struct OneShot([u8; 12]);
        impl NonceSequence for OneShot {
            fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
                Ok(Nonce::assume_unique_for_key(self.0))
            }
        }
        let mut opening = OpeningKey::new(unbound, OneShot(payload.nonce));
        let mut ct = payload.ciphertext.clone();
        let pt = opening
            .open_in_place(Aad::empty(), &mut ct)
            .expect("decrypt must succeed");
        assert_eq!(pt, raw.material.as_slice());
    }

    #[test]
    fn signature_verifies_over_payload() {
        let raw = RawRecoveryKey {
            key_type: RecoveryKeyType::FileVault,
            material: b"abcdef-ghijkl".to_vec(),
        };
        let seed = [1u8; 32];
        let tenant = Uuid::nil();
        let device = Uuid::nil();
        let key = signing_key();
        let payload = build_payload(&raw, &seed, tenant, device, &key, "evidence-v1").unwrap();

        let preimage = signing_preimage(
            payload.tenant_id,
            payload.device_id,
            payload.key_type,
            &payload.ciphertext,
            &payload.nonce,
            payload.escrowed_at,
        );
        let verifying = key.verifying_key();
        let sig_bytes: [u8; 64] = payload.signature.try_into().expect("64 byte sig");
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying
            .verify_strict(&preimage, &sig)
            .expect("signature must verify");
    }

    #[test]
    fn payload_serde_json_round_trips() {
        let raw = RawRecoveryKey {
            key_type: RecoveryKeyType::Luks,
            material: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        };
        let payload = build_payload(
            &raw,
            &[0u8; 32],
            Uuid::nil(),
            Uuid::nil(),
            &signing_key(),
            "k1",
        )
        .unwrap();
        let json = serde_json::to_string(&payload).unwrap();
        let back: RecoveryKeyPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back, payload);
    }
}
