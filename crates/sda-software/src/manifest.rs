//! Approved-software catalogue manifest types and signature
//! verification.
//!
//! The manifest is fetched from
//! [`SoftwareConfig::catalogue_url`](sda_core::config::SoftwareConfig::catalogue_url)
//! and verified against
//! [`SoftwareConfig::pinned_signing_key_hex`](sda_core::config::SoftwareConfig::pinned_signing_key_hex)
//! before any artefact is exposed to the action orchestrator. Per
//! `docs/device-control/PHASES.md` task 2.6 the manifest carries:
//!
//! - An Ed25519 detached signature over the canonical-JSON pre-image
//!   (`signature` field replaced by an empty string, key sort).
//! - A pinned SHA-256 per artefact so the agent can verify the bytes
//!   it actually downloaded match what the catalogue authority signed.
//!
//! Verification is intentionally split from network fetch so unit
//! tests can drive the verifier with hand-constructed bytes (see the
//! `tests` module below) without spinning up an HTTP server.

use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Errors raised while parsing or verifying a catalogue manifest.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// Manifest body did not deserialise into [`Manifest`].
    #[error("manifest JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    /// Pinned key was not a 32-byte hex string.
    #[error("pinned signing key is not 64 hex characters")]
    PinnedKeyShape,
    /// Pinned key bytes were not a valid Ed25519 public key.
    #[error("pinned signing key bytes are not a valid Ed25519 public key")]
    PinnedKeyInvalid,
    /// Signature field was not 128 hex chars / 64 bytes.
    #[error("signature is not 128 hex characters / 64 bytes")]
    SignatureShape,
    /// Signature did not verify against the pinned key.
    #[error("manifest signature did not verify against the pinned key")]
    SignatureMismatch,
    /// Per-artefact `sha256` field shape was wrong.
    #[error("artefact {id} has malformed sha256")]
    ArtefactHashShape { id: String },
    /// Computed SHA-256 of the artefact bytes did not match the
    /// pinned hash.
    #[error("artefact {id} downloaded bytes do not match pinned sha256")]
    ArtefactHashMismatch { id: String },
    /// Manifest schema version is unsupported.
    #[error("manifest schema_version {0} is unsupported")]
    SchemaVersion(u16),
}

/// Approved-software catalogue manifest. Mirrors the structure
/// described in `docs/device-control/ARCHITECTURE.md` § 2.5.
///
/// `signature` is the lowercase-hex Ed25519 detached signature over
/// the canonical pre-image (this same struct serialised to canonical
/// JSON with `signature` replaced by an empty string).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub schema_version: u16,
    /// Free-form catalogue identity (e.g. `"sn360-acme-prod"`).
    pub catalogue_id: String,
    /// Bumped each time the control plane re-publishes the catalogue.
    pub revision: u64,
    /// Approved artefacts.
    pub artefacts: Vec<Artefact>,
    /// Lowercase hex; 64 hex chars / 32 bytes when expanded.
    pub key_id: String,
    /// Lowercase hex; 128 hex chars / 64 bytes when expanded.
    pub signature: String,
}

/// One row of the approved catalogue.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Artefact {
    /// Stable PAL identifier (`"Mozilla.Firefox"`, `"firefox"`,
    /// `"org.mozilla.firefox"`).
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Version string the catalogue is approving.
    pub version: String,
    /// Source URL the agent downloads from. The agent verifies the
    /// downloaded bytes match [`Self::sha256`] before invoking the
    /// installer.
    pub url: String,
    /// Lowercase-hex SHA-256 of the artefact bytes (64 chars).
    pub sha256: String,
    /// Approval state — Phase 2 surfaces this as a Recommendation.
    /// Defaults to `"Approved"` when the field is missing for back-
    /// compat with early manifests.
    #[serde(default = "default_approval_state")]
    pub approval_state: String,
}

fn default_approval_state() -> String {
    "Approved".to_string()
}

/// Schema version this build understands.
pub const MANIFEST_SCHEMA_VERSION: u16 = 1;

impl Manifest {
    /// Parse a manifest from JSON bytes (no signature check).
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        let m: Manifest = serde_json::from_slice(bytes)?;
        if m.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(ManifestError::SchemaVersion(m.schema_version));
        }
        Ok(m)
    }

    /// Compute the canonical pre-image — the bytes that get signed.
    /// The pre-image is the manifest serialised with `signature`
    /// replaced by the empty string, sorted lexicographically. We
    /// reuse the project-wide canonicaliser via `serde_json::Value`
    /// so the byte-stream matches what the control plane signs.
    ///
    /// `pub(crate)` so sibling modules in `sda-software` (and their
    /// unit tests) can reuse the canonical encoding when constructing
    /// signed test fixtures, without exposing it to downstream
    /// crates.
    pub(crate) fn canonical_pre_image(&self) -> Result<Vec<u8>, ManifestError> {
        let mut value = serde_json::to_value(self)?;
        if let Some(obj) = value.as_object_mut() {
            obj.insert("signature".into(), serde_json::Value::String(String::new()));
        }
        Ok(canonicalize_value(&value))
    }

    /// Verify the manifest signature against `pinned_pubkey_hex`.
    /// Returns `Ok(())` only when the signature is well-formed and
    /// validates.
    pub fn verify_signature(&self, pinned_pubkey_hex: &str) -> Result<(), ManifestError> {
        let pubkey_bytes = parse_hex_fixed::<PUBLIC_KEY_LENGTH>(pinned_pubkey_hex)
            .ok_or(ManifestError::PinnedKeyShape)?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|_| ManifestError::PinnedKeyInvalid)?;
        let sig_bytes = parse_hex_fixed::<SIGNATURE_LENGTH>(&self.signature)
            .ok_or(ManifestError::SignatureShape)?;
        let signature = Signature::from_bytes(&sig_bytes);
        let pre_image = self.canonical_pre_image()?;
        verifying_key
            .verify(&pre_image, &signature)
            .map_err(|_| ManifestError::SignatureMismatch)
    }
}

impl Artefact {
    /// Verify that `bytes` hashes to [`Artefact::sha256`].
    pub fn verify_sha256(&self, bytes: &[u8]) -> Result<(), ManifestError> {
        let expected = parse_hex_fixed::<32>(&self.sha256).ok_or_else(|| {
            ManifestError::ArtefactHashShape {
                id: self.id.clone(),
            }
        })?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != expected {
            return Err(ManifestError::ArtefactHashMismatch {
                id: self.id.clone(),
            });
        }
        Ok(())
    }
}

/// Decode a lowercase-hex string into a fixed-size byte array.
/// Returns `None` on malformed input (wrong length or non-hex byte).
pub(crate) fn parse_hex_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(10 + c - b'a'),
        b'A'..=b'F' => Some(10 + c - b'A'),
        _ => None,
    }
}

/// Local copy of the RFC 8785 canonicaliser — kept here to avoid a
/// cross-crate dependency on `sda-device-control`. Behaviour matches
/// `crates/sda-device-control/src/canonicalize.rs` for the integer /
/// string / array / object subset used by manifests (no floats).
fn canonicalize_value(v: &serde_json::Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    write_value(v, &mut out);
    out
}

fn write_value(v: &serde_json::Value, out: &mut Vec<u8>) {
    match v {
        serde_json::Value::Null => out.extend_from_slice(b"null"),
        serde_json::Value::Bool(true) => out.extend_from_slice(b"true"),
        serde_json::Value::Bool(false) => out.extend_from_slice(b"false"),
        serde_json::Value::Number(n) => {
            // Catalogue manifests only use integers (schema_version,
            // revision). Floats would be a producer bug; we emit
            // their string form so verification fails loudly rather
            // than silently agreeing with a non-canonical encoding.
            out.extend_from_slice(n.to_string().as_bytes());
        }
        serde_json::Value::String(s) => write_string(s, out),
        serde_json::Value::Array(arr) => {
            out.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out);
            }
            out.push(b']');
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| {
                let a_units: Vec<u16> = a.encode_utf16().collect();
                let b_units: Vec<u16> = b.encode_utf16().collect();
                a_units.cmp(&b_units)
            });
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_value(map.get(*k).expect("key from map"), out);
            }
            out.push(b'}');
        }
    }
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\x08' => out.extend_from_slice(b"\\b"),
            '\x0c' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample_manifest(signature_hex: &str, key_id: &str) -> Manifest {
        Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            catalogue_id: "sn360-test".into(),
            revision: 7,
            artefacts: vec![Artefact {
                id: "Mozilla.Firefox".into(),
                name: "Mozilla Firefox".into(),
                version: "120.0".into(),
                url: "https://example.test/firefox.exe".into(),
                sha256: "0".repeat(64),
                approval_state: "Approved".into(),
            }],
            key_id: key_id.into(),
            signature: signature_hex.into(),
        }
    }

    fn sign(manifest: &mut Manifest, signing_key: &SigningKey) {
        let saved = std::mem::take(&mut manifest.signature);
        let pre_image = manifest.canonical_pre_image().unwrap();
        manifest.signature = saved;
        let sig = signing_key.sign(&pre_image);
        manifest.signature = hex::encode(sig.to_bytes());
    }

    #[test]
    fn parse_round_trips() {
        let m = sample_manifest("aa", "bb");
        let json = serde_json::to_vec(&m).unwrap();
        let back = Manifest::parse(&json).unwrap();
        assert_eq!(back.catalogue_id, "sn360-test");
        assert_eq!(back.revision, 7);
        assert_eq!(back.artefacts.len(), 1);
    }

    #[test]
    fn parse_rejects_unsupported_schema_version() {
        let mut m = sample_manifest("aa", "bb");
        m.schema_version = 99;
        let json = serde_json::to_vec(&m).unwrap();
        assert!(matches!(
            Manifest::parse(&json),
            Err(ManifestError::SchemaVersion(99))
        ));
    }

    #[test]
    fn approval_state_defaults_to_approved_when_field_missing() {
        let raw = serde_json::json!({
            "schema_version": 1,
            "catalogue_id": "c",
            "revision": 1,
            "artefacts": [{
                "id": "p",
                "name": "P",
                "version": "1",
                "url": "u",
                "sha256": "0".repeat(64),
            }],
            "key_id": "kk",
            "signature": "0".repeat(128),
        });
        let bytes = serde_json::to_vec(&raw).unwrap();
        let m = Manifest::parse(&bytes).unwrap();
        assert_eq!(m.artefacts[0].approval_state, "Approved");
    }

    #[test]
    fn signature_round_trips_with_a_real_key() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let mut m = sample_manifest("", &pubkey_hex);
        sign(&mut m, &signing_key);
        m.verify_signature(&pubkey_hex).expect("verify");
    }

    #[test]
    fn signature_rejects_tampered_payload() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let mut m = sample_manifest("", &pubkey_hex);
        sign(&mut m, &signing_key);
        // Tamper after signing.
        m.artefacts[0].version = "999.0".into();
        let err = m.verify_signature(&pubkey_hex).unwrap_err();
        assert!(matches!(err, ManifestError::SignatureMismatch));
    }

    #[test]
    fn signature_rejects_wrong_key() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let mut m = sample_manifest("", &pubkey_hex);
        sign(&mut m, &signing_key);
        // Verify against a different pinned key.
        let other = SigningKey::from_bytes(&[2u8; 32]);
        let other_pub = hex::encode(other.verifying_key().to_bytes());
        let err = m.verify_signature(&other_pub).unwrap_err();
        assert!(matches!(err, ManifestError::SignatureMismatch));
    }

    #[test]
    fn signature_rejects_malformed_pinned_key_shape() {
        let m = sample_manifest("00", "k");
        let err = m.verify_signature("zzzz").unwrap_err();
        assert!(matches!(err, ManifestError::PinnedKeyShape));
    }

    #[test]
    fn signature_rejects_malformed_signature_shape() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let m = sample_manifest("nothex", &pubkey_hex);
        let err = m.verify_signature(&pubkey_hex).unwrap_err();
        assert!(matches!(err, ManifestError::SignatureShape));
    }

    #[test]
    fn artefact_sha256_validates_correct_bytes() {
        let bytes = b"hello world";
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let hash_hex = hex::encode(hasher.finalize());
        let a = Artefact {
            id: "p".into(),
            name: "P".into(),
            version: "1".into(),
            url: "u".into(),
            sha256: hash_hex,
            approval_state: "Approved".into(),
        };
        a.verify_sha256(bytes).unwrap();
    }

    #[test]
    fn artefact_sha256_rejects_wrong_bytes() {
        let a = Artefact {
            id: "p".into(),
            name: "P".into(),
            version: "1".into(),
            url: "u".into(),
            sha256: "0".repeat(64),
            approval_state: "Approved".into(),
        };
        let err = a.verify_sha256(b"different").unwrap_err();
        assert!(matches!(err, ManifestError::ArtefactHashMismatch { .. }));
    }

    #[test]
    fn artefact_sha256_rejects_malformed_hex() {
        let a = Artefact {
            id: "p".into(),
            name: "P".into(),
            version: "1".into(),
            url: "u".into(),
            sha256: "not-hex".into(),
            approval_state: "Approved".into(),
        };
        let err = a.verify_sha256(b"x").unwrap_err();
        assert!(matches!(err, ManifestError::ArtefactHashShape { .. }));
    }

    #[test]
    fn parse_hex_fixed_rejects_wrong_length() {
        assert!(parse_hex_fixed::<32>("aa").is_none());
        assert!(parse_hex_fixed::<32>(&"a".repeat(63)).is_none());
        assert!(parse_hex_fixed::<32>(&"a".repeat(65)).is_none());
    }

    #[test]
    fn parse_hex_fixed_rejects_non_hex_chars() {
        let s = "z".repeat(64);
        assert!(parse_hex_fixed::<32>(&s).is_none());
    }
}
