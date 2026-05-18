//! `EvidenceRecord` — append-only audit projection of an
//! `ActionResult` plus the `SignedActionJob` it executed.
//!
//! Mirrors `docs/wire-protocols/device-control.md` § 9.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::action_result::ActionResult;
use crate::canonicalize::{canonicalize, CanonicalizeError};
use crate::signed_job::SignedActionJob;
use crate::types::{ActionKind, ActionStatus, AgentVersion, JobRefused, Platform};

/// 32 bytes of zero — sentinel `prev_record_hash` for the first
/// record on a device's evidence chain (SCHEMAS.md § 9.1).
pub const FIRST_RECORD_PREV_HASH: [u8; 32] = [0u8; 32];

/// An append-only audit projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    pub evidence_id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub schema_version: u16,
    pub job_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation_id: Option<Uuid>,
    pub action: ActionKind,
    /// RFC 8785 canonical-JSON encoding of `SignedActionJob.args`,
    /// stored as a string so the chain hash is stable independent
    /// of consumer JSON libraries.
    pub args_canonical: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub status: ActionStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused_reason: Option<JobRefused>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// SHA-256 of the *full* (un-truncated) bounded output. The
    /// truncated head lives in `ActionResult.output`.
    #[serde(with = "byte_array_32")]
    pub output_sha256: [u8; 32],
    pub platform: Platform,
    pub agent: AgentVersion,
    /// Hash of the previous evidence record on this device's chain
    /// (32 bytes; SHA-256). The first record uses
    /// [`FIRST_RECORD_PREV_HASH`].
    #[serde(with = "byte_array_32")]
    pub prev_record_hash: [u8; 32],
    pub signature: Vec<u8>,
    pub key_id: String,
}

/// Errors raised during evidence chain operations.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("schema_version is {0}; this build only understands version 1")]
    SchemaVersionUnsupported(u16),
    #[error("started_at must be ≤ finished_at")]
    BadTimeOrder,
    #[error("status = Refused requires refused_reason to be Some(_)")]
    MissingRefusedReason,
    #[error("status = {0:?} forbids refused_reason being Some(_)")]
    UnexpectedRefusedReason(ActionStatus),
    #[error("canonicalize failed: {0}")]
    Canonicalize(#[from] CanonicalizeError),
    #[error("serde_json failed: {0}")]
    Serde(#[from] serde_json::Error),
}

impl EvidenceRecord {
    /// Validate the structural invariants from SCHEMAS.md § 9.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.schema_version != crate::version::EVIDENCE_RECORD_SCHEMA_VERSION {
            return Err(EvidenceError::SchemaVersionUnsupported(self.schema_version));
        }
        if self.started_at > self.finished_at {
            return Err(EvidenceError::BadTimeOrder);
        }
        match self.status {
            ActionStatus::Refused => {
                if self.refused_reason.is_none() {
                    return Err(EvidenceError::MissingRefusedReason);
                }
            }
            other => {
                if self.refused_reason.is_some() {
                    return Err(EvidenceError::UnexpectedRefusedReason(other));
                }
            }
        }
        Ok(())
    }

    /// Compute the canonical pre-image used to:
    /// - generate this record's `signature` (SCHEMAS.md § 9.2), and
    /// - derive the `prev_record_hash` of the *next* record on the
    ///   chain.
    ///
    /// The pre-image is the canonical JSON of the record with
    /// `signature` replaced by an empty string.
    pub fn canonical_pre_image(&self) -> Result<Vec<u8>, EvidenceError> {
        let mut value = serde_json::to_value(self)?;
        if let Some(obj) = value.as_object_mut() {
            obj.insert("signature".into(), serde_json::Value::String(String::new()));
        }
        Ok(canonicalize(&value)?)
    }

    /// SHA-256 of the canonical record *including* the signature
    /// — this is what the next record's `prev_record_hash` must
    /// equal (SCHEMAS.md § 9.2).
    pub fn chain_hash(&self) -> Result<[u8; 32], EvidenceError> {
        let value = serde_json::to_value(self)?;
        let bytes = canonicalize(&value)?;
        Ok(sha256(&bytes))
    }
}

/// Convenience helper: hash arbitrary bytes with SHA-256.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Phase 1 placeholder signature for an `EvidenceRecord`. Phase 2
/// replaces this with a real Ed25519 signature once the
/// `sda-evidence-keys` infrastructure lands. Until then the bytes
/// stored in `EvidenceRecord.signature` are deterministically
/// derived from the canonical pre-image so they round-trip cleanly
/// through the bus and pass `EvidenceRecord::validate`.
pub const PHASE1_STUB_KEY_ID: &str = "sda-evidence-stub-phase1";

/// Build the deterministic Phase 1 stub signature: `SHA-256(pre_image)`
/// padded to 64 bytes by repeating the first 32 bytes. The shape is
/// kept as `Vec<u8>` of length 64 to match the eventual Ed25519
/// signature size — verifiers MUST treat any record signed with
/// `PHASE1_STUB_KEY_ID` as untrusted, but the byte length stays
/// stable across the Phase 1 → Phase 2 transition.
pub fn phase1_stub_signature(pre_image: &[u8]) -> Vec<u8> {
    let h = sha256(pre_image);
    let mut sig = Vec::with_capacity(64);
    sig.extend_from_slice(&h);
    sig.extend_from_slice(&h);
    sig
}

/// Append-only chain head for a device's evidence sequence.
///
/// `last_chain_hash` is the SHA-256 of the canonical encoding of the
/// most recently appended record (i.e. the value the *next* record
/// must store in `prev_record_hash`). For a fresh agent it is
/// [`FIRST_RECORD_PREV_HASH`], so the very first record produced
/// links to the zero sentinel as required by SCHEMAS.md § 9.1.
#[derive(Debug, Clone, Default)]
pub struct EvidenceChain {
    last_chain_hash: Option<[u8; 32]>,
}

impl EvidenceChain {
    /// Construct a fresh chain whose first record will link to
    /// [`FIRST_RECORD_PREV_HASH`].
    pub fn new() -> Self {
        Self {
            last_chain_hash: None,
        }
    }

    /// Construct a chain that already has at least one record on it
    /// (e.g. recovered from disk after a restart).
    pub fn with_last(last: [u8; 32]) -> Self {
        Self {
            last_chain_hash: Some(last),
        }
    }

    /// Return the hash that the *next* record's `prev_record_hash`
    /// field must contain.
    pub fn next_prev_hash(&self) -> [u8; 32] {
        self.last_chain_hash.unwrap_or(FIRST_RECORD_PREV_HASH)
    }

    /// Mark `record` as appended to the chain by recording its
    /// `chain_hash` as the new head.
    pub fn append(&mut self, record: &EvidenceRecord) -> Result<(), EvidenceError> {
        let h = record.chain_hash()?;
        self.last_chain_hash = Some(h);
        Ok(())
    }

    /// True when no record has been appended yet (first-record case).
    pub fn is_empty(&self) -> bool {
        self.last_chain_hash.is_none()
    }
}

/// Inputs the executor passes to `build_signed_evidence_record`. The
/// fields mirror the columns of `EvidenceRecord` that come from
/// outside the `ActionResult` itself.
#[derive(Debug, Clone)]
pub struct EvidenceContext<'a> {
    pub args_canonical: String,
    pub output_full: &'a [u8],
    pub platform: Platform,
    pub agent: AgentVersion,
}

/// Build an `EvidenceRecord` from an `ActionResult`, the originating
/// `SignedActionJob`, the device-side context, and the chain's
/// current head.
///
/// The returned record:
/// - hashes the *full* output bytes into `output_sha256`;
/// - links into the chain by setting `prev_record_hash =
///   chain.next_prev_hash()`;
/// - carries a deterministic Phase 1 stub signature
///   ([`phase1_stub_signature`]) keyed by [`PHASE1_STUB_KEY_ID`];
/// - copies the canonical args of the originating job into
///   `args_canonical`; and
/// - re-uses the `evidence_id` already on the `ActionResult` so the
///   pair stays correlated end-to-end.
pub fn build_signed_evidence_record(
    job: &SignedActionJob,
    result: &ActionResult,
    chain: &EvidenceChain,
    ctx: EvidenceContext<'_>,
) -> Result<EvidenceRecord, EvidenceError> {
    let mut record = EvidenceRecord {
        evidence_id: result.evidence_id,
        tenant_id: result.tenant_id,
        device_id: result.device_id,
        schema_version: crate::version::EVIDENCE_RECORD_SCHEMA_VERSION,
        job_id: result.job_id,
        recommendation_id: job.recommendation_id,
        action: result.action,
        args_canonical: ctx.args_canonical,
        started_at: result.started_at,
        finished_at: result.finished_at,
        status: result.status,
        refused_reason: result.refused_reason,
        exit_code: result.exit_code,
        output_sha256: sha256(ctx.output_full),
        platform: ctx.platform,
        agent: ctx.agent,
        prev_record_hash: chain.next_prev_hash(),
        // The stub signature is derived from the canonical
        // pre-image, which itself is computed with `signature` set
        // to "" — so we cannot fill `signature` in until after the
        // pre-image is built. Start with an empty Vec.
        signature: Vec::new(),
        key_id: PHASE1_STUB_KEY_ID.to_string(),
    };
    let pre_image = record.canonical_pre_image()?;
    record.signature = phase1_stub_signature(&pre_image);
    record.validate()?;
    Ok(record)
}

/// `serde` adapter for the two fixed-size byte arrays on
/// `EvidenceRecord`.
///
/// On the wire (MessagePack) we want the natural binary encoding;
/// in canonical JSON we emit lowercase hex per SCHEMAS.md § 3.7.
/// We pick lowercase hex here because the canonical encoding is
/// what signers / verifiers consume, and MessagePack's `serde`
/// integration accepts strings transparently.
mod byte_array_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut out = String::with_capacity(64);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = String::deserialize(d)?;
        if s.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64-char hex string, got {} chars",
                s.len()
            )));
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
            let hi = hex_nibble(chunk[0])?;
            let lo = hex_nibble(chunk[1])?;
            out[i] = (hi << 4) | lo;
        }
        Ok(out)
    }

    fn hex_nibble<E: serde::de::Error>(c: u8) -> Result<u8, E> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(10 + c - b'a'),
            b'A'..=b'F' => Ok(10 + c - b'A'),
            _ => Err(serde::de::Error::custom(format!(
                "non-hex character {:?}",
                c as char
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PlatformArch, PlatformOs};
    use chrono::TimeZone;

    fn record(prev: [u8; 32], status: ActionStatus, refused: Option<JobRefused>) -> EvidenceRecord {
        let t = Utc.with_ymd_and_hms(2026, 5, 7, 8, 30, 0).unwrap();
        EvidenceRecord {
            evidence_id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            device_id: Uuid::nil(),
            schema_version: crate::version::EVIDENCE_RECORD_SCHEMA_VERSION,
            job_id: Uuid::nil(),
            recommendation_id: None,
            action: ActionKind::UpdatePackage,
            args_canonical: "{\"channel\":\"stable\",\"package_id\":\"p\",\"to_version\":\"1\"}"
                .into(),
            started_at: t,
            finished_at: if matches!(status, ActionStatus::Refused) {
                t
            } else {
                t + chrono::Duration::seconds(13)
            },
            status,
            refused_reason: refused,
            exit_code: if matches!(status, ActionStatus::Refused) {
                None
            } else {
                Some(0)
            },
            output_sha256: [0xab; 32],
            platform: Platform {
                os: PlatformOs::Linux,
                version: "24.04".into(),
                arch: PlatformArch::X86_64,
                distro: Some("ubuntu".into()),
            },
            agent: AgentVersion {
                version: "0.10.0".into(),
                build_sha: "0123456789abcdef0123456789abcdef01234567".into(),
                channel: "stable".into(),
            },
            prev_record_hash: prev,
            signature: vec![0; 64],
            key_id: "sda-evidence-2026-05".into(),
        }
    }

    #[test]
    fn round_trip_through_serde_json() {
        let r = record(FIRST_RECORD_PREV_HASH, ActionStatus::Success, None);
        let s = serde_json::to_string(&r).unwrap();
        // hex-encoded byte arrays are emitted as strings, not as
        // integer arrays.
        assert!(s.contains("\"prev_record_hash\":\""));
        assert!(s.contains("\"output_sha256\":\""));
        let back: EvidenceRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let raw =
            serde_json::to_string(&record(FIRST_RECORD_PREV_HASH, ActionStatus::Success, None))
                .unwrap();
        // Inject an extra field
        let bad = raw.replace('}', ",\"extra\":1}");
        assert!(serde_json::from_str::<EvidenceRecord>(&bad).is_err());
    }

    #[test]
    fn omits_none_optional_fields() {
        let r = record(FIRST_RECORD_PREV_HASH, ActionStatus::Success, None);
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("recommendation_id"));
        assert!(!s.contains("refused_reason"));
    }

    #[test]
    fn validate_rejects_refused_without_reason() {
        let r = record(FIRST_RECORD_PREV_HASH, ActionStatus::Refused, None);
        assert!(matches!(
            r.validate(),
            Err(EvidenceError::MissingRefusedReason)
        ));
    }

    #[test]
    fn validate_rejects_success_with_reason() {
        let r = record(
            FIRST_RECORD_PREV_HASH,
            ActionStatus::Success,
            Some(JobRefused::Expired),
        );
        assert!(matches!(
            r.validate(),
            Err(EvidenceError::UnexpectedRefusedReason(
                ActionStatus::Success
            ))
        ));
    }

    #[test]
    fn validate_accepts_well_formed_records() {
        record(FIRST_RECORD_PREV_HASH, ActionStatus::Success, None)
            .validate()
            .unwrap();
        record(
            FIRST_RECORD_PREV_HASH,
            ActionStatus::Refused,
            Some(JobRefused::Expired),
        )
        .validate()
        .unwrap();
    }

    #[test]
    fn canonical_pre_image_blanks_signature() {
        let r = record(FIRST_RECORD_PREV_HASH, ActionStatus::Success, None);
        let pre_image = r.canonical_pre_image().unwrap();
        let s = String::from_utf8(pre_image).unwrap();
        // The signature field must appear with an empty-string
        // value in the pre-image.
        assert!(s.contains("\"signature\":\"\""));
        // …and must NOT contain the array form of the signature
        // bytes.
        assert!(!s.contains("\"signature\":[0"));
    }

    #[test]
    fn chain_links_correctly_across_records() {
        // A → B → C, where each record's prev_record_hash equals
        // the SHA-256 of the previous record's full canonical
        // encoding (signature included, per SCHEMAS.md § 9.2).
        let a = record(FIRST_RECORD_PREV_HASH, ActionStatus::Success, None);
        let a_hash = a.chain_hash().unwrap();
        assert_ne!(a_hash, FIRST_RECORD_PREV_HASH);
        let b = record(a_hash, ActionStatus::Success, None);
        let b_hash = b.chain_hash().unwrap();
        let c = record(b_hash, ActionStatus::Success, None);
        // Tampering with B (e.g. flipping a status field) must
        // cause C's expected prev_record_hash to no longer match.
        let mut b_tampered = b.clone();
        b_tampered.status = ActionStatus::Failure;
        let b_tampered_hash = b_tampered.chain_hash().unwrap();
        assert_ne!(b_tampered_hash, c.prev_record_hash);
    }

    #[test]
    fn first_record_uses_zero_prev_hash() {
        // SCHEMAS.md § 9.1 — the first record on the chain uses
        // [0u8; 32]. We don't enforce this in `validate()` (the
        // agent's evidence store holds chain state, not the wire
        // schema), but the constant must remain stable.
        assert_eq!(FIRST_RECORD_PREV_HASH, [0u8; 32]);
    }

    #[test]
    fn hex_serialization_uses_lowercase() {
        let r = EvidenceRecord {
            output_sha256: [0xab; 32],
            ..record(FIRST_RECORD_PREV_HASH, ActionStatus::Success, None)
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"output_sha256\":\"abababab"));
    }

    #[test]
    fn hex_deserialization_rejects_bad_length() {
        let mut s =
            serde_json::to_string(&record(FIRST_RECORD_PREV_HASH, ActionStatus::Success, None))
                .unwrap();
        // Break the prev_record_hash to be 2 chars (way too
        // short) so the byte_array_32 deserializer rejects it.
        s = s.replacen(
            "\"prev_record_hash\":\"0000000000000000000000000000000000000000000000000000000000000000\"",
            "\"prev_record_hash\":\"00\"",
            1,
        );
        assert!(serde_json::from_str::<EvidenceRecord>(&s).is_err());
    }
}
