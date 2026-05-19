//! Approved-software catalogue manifest types and signature
//! verification.
//!
//! The manifest is fetched from
//! [`SoftwareConfig::catalogue_url`](sda_core::config::SoftwareConfig::catalogue_url)
//! and verified against the keys configured in
//! [`SoftwareConfig::pinned_signing_keys`](sda_core::config::SoftwareConfig::pinned_signing_keys)
//! (or the legacy single-key
//! [`SoftwareConfig::pinned_signing_key_hex`](sda_core::config::SoftwareConfig::pinned_signing_key_hex))
//! before any artefact is exposed to the action orchestrator. Per
//! `docs/device-control.md` § 6 (Approved software catalogue) the manifest carries:
//!
//! - An Ed25519 detached signature over the canonical-JSON pre-image
//!   (`signature` field replaced by an empty string, key sort).
//! - A `signed_at` timestamp the agent uses to reject manifests that
//!   are older than the operator-configured maximum age.
//! - A pinned SHA-256 per artefact so the agent can verify the bytes
//!   it actually downloaded match what the catalogue authority signed.
//!
//! Verification is intentionally split from network fetch so unit
//! tests can drive the verifier with hand-constructed bytes (see the
//! `tests` module below) without spinning up an HTTP server.
//!
//! ## Verifier surface
//!
//! [`Verifier`] is the production-grade entry point — pass it the
//! [`SoftwareConfig`](sda_core::config::SoftwareConfig) and it will:
//!
//! 1. Look up the manifest's `key_id` in the configured pinned set
//!    (rejecting [`ManifestError::UnknownKeyId`] when no match).
//! 2. Verify the Ed25519 signature against that key
//!    ([`ManifestError::SignatureMismatch`] on failure).
//! 3. Check the manifest is not older than `manifest_max_age_secs`
//!    ([`ManifestError::Expired`] when stale).
//!
//! Each failure mode is surfaced as a distinct error variant so the
//! supervisor task can emit precise findings to the operator.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use ed25519_dalek::{
    Signature, Verifier as Ed25519Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use sda_core::config::{PinnedSigningKey, SoftwareConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Errors raised while parsing or verifying a catalogue manifest.
///
/// Every wire-level failure mode is its own variant so the
/// supervisor task can map errors back to operator-readable
/// findings without inspecting strings.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// Manifest body did not deserialise into [`Manifest`].
    #[error("manifest JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    /// Pinned key was not a 32-byte hex string.
    #[error("pinned signing key {key_id} is not 64 hex characters")]
    PinnedKeyShape {
        /// `key_id` of the pinned key whose hex shape was wrong.
        key_id: String,
    },
    /// Pinned key bytes were not a valid Ed25519 public key.
    #[error("pinned signing key {key_id} bytes are not a valid Ed25519 public key")]
    PinnedKeyInvalid {
        /// `key_id` of the pinned key whose bytes were rejected by
        /// Ed25519.
        key_id: String,
    },
    /// Manifest's `key_id` was not in the configured pinned set.
    #[error("manifest key_id {0} is not in the pinned signing-key set")]
    UnknownKeyId(String),
    /// Verifier was constructed from a [`SoftwareConfig`] that had no
    /// pinned keys at all (neither `pinned_signing_keys` nor the
    /// legacy `pinned_signing_key_hex`). Surfaces as a distinct
    /// variant so the supervisor task can log a clear diagnostic.
    #[error("software config has no pinned signing keys configured")]
    NoPinnedKeys,
    /// Signature field was not 128 hex chars / 64 bytes.
    #[error("signature is not 128 hex characters / 64 bytes")]
    SignatureShape,
    /// Signature did not verify against the pinned key.
    #[error("manifest signature did not verify against the pinned key")]
    SignatureMismatch,
    /// Per-artefact `sha256` field shape was wrong.
    #[error("artefact {id} has malformed sha256")]
    ArtefactHashShape {
        /// `id` of the artefact whose hash field was malformed.
        id: String,
    },
    /// Computed SHA-256 of the artefact bytes did not match the
    /// pinned hash.
    #[error("artefact {id} downloaded bytes do not match pinned sha256")]
    ArtefactHashMismatch {
        /// `id` of the artefact whose bytes failed verification.
        id: String,
    },
    /// Manifest schema version is unsupported.
    #[error("manifest schema_version {0} is unsupported")]
    SchemaVersion(u16),
    /// Manifest's `signed_at` is older than the configured maximum
    /// age, or is set in the future beyond clock skew tolerance.
    #[error("manifest is expired (signed_at {signed_at}, max_age_secs {max_age_secs})")]
    Expired {
        /// `signed_at` field on the manifest that triggered the
        /// rejection.
        signed_at: DateTime<Utc>,
        /// Configured maximum age in seconds.
        max_age_secs: u64,
    },
    /// Manifest is missing a `signed_at` timestamp. Required as of
    /// schema version 1 hardening; old unsigned-time
    /// manifests cannot be evaluated for expiry and are therefore
    /// rejected.
    #[error("manifest is missing the required signed_at timestamp")]
    MissingSignedAt,
}

/// Approved-software catalogue manifest. Mirrors the structure
/// described in `docs/device-control.md` § 6 (Approved software catalogue).
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
    /// UTC timestamp when the catalogue authority signed this
    /// manifest. The agent rejects manifests where `now -
    /// signed_at` exceeds the operator-configured maximum age.
    /// Optional on the wire for backward compatibility — the
    /// hardened verifier rejects manifests without it
    /// ([`ManifestError::MissingSignedAt`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<DateTime<Utc>>,
    /// Approved artefacts.
    pub artefacts: Vec<Artefact>,
    /// Stable identifier of the signing key used to produce
    /// [`Self::signature`]. Looked up by the agent's pinned-key
    /// set; mismatches surface as [`ManifestError::UnknownKeyId`].
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
    /// Approval state — surfaced as a Recommendation on the bus.
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

/// Tolerance applied to `signed_at` to absorb minor clock skew
/// between the catalogue authority and the agent.
pub const MANIFEST_CLOCK_SKEW_TOLERANCE_SECS: u64 = 60;

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
    ///
    /// Retained for callers that already maintain a single pinned
    /// key by hand. New code should prefer [`Verifier::verify`]
    /// which also enforces `key_id` membership and expiry.
    pub fn verify_signature(&self, pinned_pubkey_hex: &str) -> Result<(), ManifestError> {
        let pubkey_bytes =
            parse_hex_fixed::<PUBLIC_KEY_LENGTH>(pinned_pubkey_hex).ok_or_else(|| {
                ManifestError::PinnedKeyShape {
                    key_id: self.key_id.clone(),
                }
            })?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| {
            ManifestError::PinnedKeyInvalid {
                key_id: self.key_id.clone(),
            }
        })?;
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

/// Production-grade manifest verifier supporting key rotation and
/// expiry checking.
///
/// Construct from a [`SoftwareConfig`] with [`Verifier::from_config`]
/// or directly with [`Verifier::new`]. Holds parsed Ed25519 verifying
/// keys keyed by their stable `key_id`, plus the configured maximum
/// manifest age.
#[derive(Debug, Clone)]
pub struct Verifier {
    keys: BTreeMap<String, VerifyingKey>,
    max_age_secs: u64,
}

impl Verifier {
    /// Construct a verifier from a [`SoftwareConfig`]. Parses every
    /// configured pinned key (including the legacy single-key
    /// fallback) into Ed25519 verifying keys, returning errors if
    /// any key is malformed.
    ///
    /// When `pinned_signing_keys` has at least one entry, the legacy
    /// `pinned_signing_key_hex` field is ignored entirely. When the
    /// list is empty and the legacy field is set, the legacy field
    /// is used with `key_id = "default"`.
    ///
    /// At least one pinned key is required —
    /// [`ManifestError::NoPinnedKeys`] is returned if none are
    /// configured.
    pub fn from_config(config: &SoftwareConfig) -> Result<Self, ManifestError> {
        let mut keys: BTreeMap<String, VerifyingKey> = BTreeMap::new();
        if !config.pinned_signing_keys.is_empty() {
            for entry in &config.pinned_signing_keys {
                let parsed = parse_pinned_key(entry)?;
                keys.insert(entry.key_id.clone(), parsed);
            }
        } else if let Some(hex) = config.pinned_signing_key_hex.as_deref() {
            let entry = PinnedSigningKey {
                key_id: "default".to_string(),
                public_key_hex: hex.to_string(),
            };
            let parsed = parse_pinned_key(&entry)?;
            keys.insert(entry.key_id, parsed);
        }
        if keys.is_empty() {
            return Err(ManifestError::NoPinnedKeys);
        }
        Ok(Self {
            keys,
            max_age_secs: config.manifest_max_age_secs,
        })
    }

    /// Construct a verifier from an explicit list of pinned keys.
    /// Mostly useful in unit tests that don't want to go through
    /// [`SoftwareConfig`].
    pub fn new(keys: &[PinnedSigningKey], max_age_secs: u64) -> Result<Self, ManifestError> {
        if keys.is_empty() {
            return Err(ManifestError::NoPinnedKeys);
        }
        let mut parsed: BTreeMap<String, VerifyingKey> = BTreeMap::new();
        for entry in keys {
            parsed.insert(entry.key_id.clone(), parse_pinned_key(entry)?);
        }
        Ok(Self {
            keys: parsed,
            max_age_secs,
        })
    }

    /// `key_id`s currently configured for verification. Sorted
    /// lexicographically (the underlying map is a [`BTreeMap`]).
    pub fn key_ids(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }

    /// Configured maximum manifest age in seconds.
    pub fn max_age_secs(&self) -> u64 {
        self.max_age_secs
    }

    /// Run the production verification pipeline on `manifest` at the
    /// observed wall clock `now`:
    ///
    /// 1. The manifest's `key_id` must be in the pinned set
    ///    ([`ManifestError::UnknownKeyId`] otherwise).
    /// 2. The manifest must carry a `signed_at` timestamp
    ///    ([`ManifestError::MissingSignedAt`] otherwise).
    /// 3. `now - signed_at` must be within `max_age_secs +
    ///    MANIFEST_CLOCK_SKEW_TOLERANCE_SECS` and `signed_at` must
    ///    not be in the future beyond
    ///    `MANIFEST_CLOCK_SKEW_TOLERANCE_SECS`
    ///    ([`ManifestError::Expired`] otherwise).
    /// 4. The Ed25519 signature must verify against the pinned key
    ///    selected in step 1
    ///    ([`ManifestError::SignatureMismatch`] otherwise).
    pub fn verify(&self, manifest: &Manifest, now: DateTime<Utc>) -> Result<(), ManifestError> {
        let key = self
            .keys
            .get(&manifest.key_id)
            .ok_or_else(|| ManifestError::UnknownKeyId(manifest.key_id.clone()))?;
        let signed_at = manifest.signed_at.ok_or(ManifestError::MissingSignedAt)?;
        let age_secs = (now - signed_at).num_seconds();
        let tolerance = MANIFEST_CLOCK_SKEW_TOLERANCE_SECS as i64;
        let max = self.max_age_secs as i64 + tolerance;
        if age_secs > max || age_secs < -tolerance {
            return Err(ManifestError::Expired {
                signed_at,
                max_age_secs: self.max_age_secs,
            });
        }
        let sig_bytes = parse_hex_fixed::<SIGNATURE_LENGTH>(&manifest.signature)
            .ok_or(ManifestError::SignatureShape)?;
        let signature = Signature::from_bytes(&sig_bytes);
        let pre_image = manifest.canonical_pre_image()?;
        key.verify(&pre_image, &signature)
            .map_err(|_| ManifestError::SignatureMismatch)
    }
}

fn parse_pinned_key(entry: &PinnedSigningKey) -> Result<VerifyingKey, ManifestError> {
    let bytes = parse_hex_fixed::<PUBLIC_KEY_LENGTH>(&entry.public_key_hex).ok_or_else(|| {
        ManifestError::PinnedKeyShape {
            key_id: entry.key_id.clone(),
        }
    })?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| ManifestError::PinnedKeyInvalid {
        key_id: entry.key_id.clone(),
    })
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
    use chrono::Duration as ChronoDuration;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample_manifest(signature_hex: &str, key_id: &str) -> Manifest {
        Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            catalogue_id: "sn360-test".into(),
            revision: 7,
            signed_at: None,
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

    fn pinned(key_id: &str, signing_key: &SigningKey) -> PinnedSigningKey {
        PinnedSigningKey {
            key_id: key_id.into(),
            public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
        }
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
        assert!(matches!(err, ManifestError::PinnedKeyShape { .. }));
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

    #[test]
    fn verifier_accepts_valid_manifest_with_signed_at() {
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let pinned_key = pinned("sn360-2026-05", &signing_key);
        let now = Utc::now();
        let mut m = sample_manifest("", "sn360-2026-05");
        m.signed_at = Some(now - ChronoDuration::seconds(3600));
        sign(&mut m, &signing_key);
        let v = Verifier::new(&[pinned_key], 7 * 24 * 3600).unwrap();
        v.verify(&m, now).expect("valid manifest verifies");
    }

    #[test]
    fn verifier_rejects_unknown_key_id() {
        let signing_key = SigningKey::from_bytes(&[4u8; 32]);
        let pinned_key = pinned("sn360-2026-05", &signing_key);
        let now = Utc::now();
        let mut m = sample_manifest("", "some-other-key-id");
        m.signed_at = Some(now);
        sign(&mut m, &signing_key);
        let v = Verifier::new(&[pinned_key], 7 * 24 * 3600).unwrap();
        let err = v.verify(&m, now).unwrap_err();
        assert!(matches!(err, ManifestError::UnknownKeyId(_)));
    }

    #[test]
    fn verifier_rejects_expired_manifest() {
        let signing_key = SigningKey::from_bytes(&[5u8; 32]);
        let pinned_key = pinned("sn360-2026-05", &signing_key);
        let now = Utc::now();
        let mut m = sample_manifest("", "sn360-2026-05");
        m.signed_at = Some(now - ChronoDuration::seconds(7 * 24 * 3600 + 3600));
        sign(&mut m, &signing_key);
        let v = Verifier::new(&[pinned_key], 7 * 24 * 3600).unwrap();
        let err = v.verify(&m, now).unwrap_err();
        assert!(matches!(err, ManifestError::Expired { .. }));
    }

    #[test]
    fn verifier_rejects_future_signed_at_beyond_skew() {
        let signing_key = SigningKey::from_bytes(&[6u8; 32]);
        let pinned_key = pinned("sn360-2026-05", &signing_key);
        let now = Utc::now();
        let mut m = sample_manifest("", "sn360-2026-05");
        m.signed_at = Some(now + ChronoDuration::seconds(3600));
        sign(&mut m, &signing_key);
        let v = Verifier::new(&[pinned_key], 7 * 24 * 3600).unwrap();
        let err = v.verify(&m, now).unwrap_err();
        assert!(matches!(err, ManifestError::Expired { .. }));
    }

    #[test]
    fn verifier_accepts_within_clock_skew_tolerance() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let pinned_key = pinned("sn360-2026-05", &signing_key);
        let now = Utc::now();
        let mut m = sample_manifest("", "sn360-2026-05");
        m.signed_at = Some(now + ChronoDuration::seconds(30));
        sign(&mut m, &signing_key);
        let v = Verifier::new(&[pinned_key], 7 * 24 * 3600).unwrap();
        v.verify(&m, now)
            .expect("manifest within +-60s skew should verify");
    }

    #[test]
    fn verifier_rejects_missing_signed_at() {
        let signing_key = SigningKey::from_bytes(&[8u8; 32]);
        let pinned_key = pinned("sn360-2026-05", &signing_key);
        let now = Utc::now();
        let mut m = sample_manifest("", "sn360-2026-05");
        m.signed_at = None;
        sign(&mut m, &signing_key);
        let v = Verifier::new(&[pinned_key], 7 * 24 * 3600).unwrap();
        let err = v.verify(&m, now).unwrap_err();
        assert!(matches!(err, ManifestError::MissingSignedAt));
    }

    #[test]
    fn verifier_rejects_tampered_hash() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let pinned_key = pinned("sn360-2026-05", &signing_key);
        let now = Utc::now();
        let mut m = sample_manifest("", "sn360-2026-05");
        m.signed_at = Some(now);
        sign(&mut m, &signing_key);
        // Tamper with the artefact body after signing — this also
        // exercises the SignatureMismatch path on a manifest that
        // would otherwise be valid (correct key_id, in-window).
        m.artefacts[0].sha256 = "1".repeat(64);
        let v = Verifier::new(&[pinned_key], 7 * 24 * 3600).unwrap();
        let err = v.verify(&m, now).unwrap_err();
        assert!(matches!(err, ManifestError::SignatureMismatch));
    }

    #[test]
    fn verifier_supports_key_rotation() {
        let key_old = SigningKey::from_bytes(&[10u8; 32]);
        let key_new = SigningKey::from_bytes(&[11u8; 32]);
        let v = Verifier::new(
            &[pinned("old", &key_old), pinned("new", &key_new)],
            7 * 24 * 3600,
        )
        .unwrap();
        let now = Utc::now();
        // Sign with the new key and verify it routes to the new
        // pinned entry.
        let mut m = sample_manifest("", "new");
        m.signed_at = Some(now);
        sign(&mut m, &key_new);
        v.verify(&m, now).expect("new key still pinned");
        // Sign with the retired key and verify the old pinned
        // entry still accepts it (the rotation is a superset).
        let mut m_old = sample_manifest("", "old");
        m_old.signed_at = Some(now);
        sign(&mut m_old, &key_old);
        v.verify(&m_old, now).expect("old key still pinned");
        // A manifest claiming `key_id = "new"` but signed by the
        // old key must fail with SignatureMismatch (the key_id
        // pointer was bogus).
        let mut spoof = sample_manifest("", "new");
        spoof.signed_at = Some(now);
        sign(&mut spoof, &key_old);
        let err = v.verify(&spoof, now).unwrap_err();
        assert!(matches!(err, ManifestError::SignatureMismatch));
    }

    #[test]
    fn verifier_from_config_uses_legacy_field_when_no_rotation_set() {
        let signing_key = SigningKey::from_bytes(&[12u8; 32]);
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let cfg = SoftwareConfig {
            enabled: true,
            catalogue_url: Some("https://example.test/c.json".into()),
            pinned_signing_key_hex: Some(pubkey_hex),
            pinned_signing_keys: Vec::new(),
            manifest_max_age_secs: 7 * 24 * 3600,
            refresh_interval_secs: 3600,
        };
        let v = Verifier::from_config(&cfg).unwrap();
        assert_eq!(v.key_ids(), vec!["default".to_string()]);
        let now = Utc::now();
        let mut m = sample_manifest("", "default");
        m.signed_at = Some(now);
        sign(&mut m, &signing_key);
        v.verify(&m, now).expect("legacy single key works");
    }

    #[test]
    fn verifier_from_config_prefers_pinned_signing_keys() {
        let legacy_key = SigningKey::from_bytes(&[13u8; 32]);
        let new_key = SigningKey::from_bytes(&[14u8; 32]);
        let cfg = SoftwareConfig {
            enabled: true,
            catalogue_url: Some("https://example.test/c.json".into()),
            pinned_signing_key_hex: Some(hex::encode(legacy_key.verifying_key().to_bytes())),
            pinned_signing_keys: vec![pinned("primary", &new_key)],
            manifest_max_age_secs: 7 * 24 * 3600,
            refresh_interval_secs: 3600,
        };
        let v = Verifier::from_config(&cfg).unwrap();
        assert_eq!(v.key_ids(), vec!["primary".to_string()]);
        let now = Utc::now();
        // Manifest signed by the legacy key with key_id "default"
        // must be rejected because pinned_signing_keys takes
        // precedence.
        let mut m = sample_manifest("", "default");
        m.signed_at = Some(now);
        sign(&mut m, &legacy_key);
        let err = v.verify(&m, now).unwrap_err();
        assert!(matches!(err, ManifestError::UnknownKeyId(_)));
    }

    #[test]
    fn verifier_from_config_rejects_empty_key_set() {
        let cfg = SoftwareConfig::default();
        let err = Verifier::from_config(&cfg).unwrap_err();
        assert!(matches!(err, ManifestError::NoPinnedKeys));
    }

    #[test]
    fn verifier_rejects_malformed_pinned_key_shape() {
        let bad = PinnedSigningKey {
            key_id: "kid".into(),
            public_key_hex: "zzzz".into(),
        };
        let err = Verifier::new(&[bad], 60).unwrap_err();
        assert!(matches!(err, ManifestError::PinnedKeyShape { .. }));
    }
}
