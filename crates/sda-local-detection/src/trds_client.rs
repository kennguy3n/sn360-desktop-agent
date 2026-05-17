//! Tenant Rule Distribution Service (TRDS) client + bundle verifier.
//!
//! Pulls signed rule bundles from a remote TRDS endpoint over HTTPS,
//! verifies their Ed25519 signature against a locally pinned key
//! rotation set, and surfaces the verified [`RuleBundle`] for atomic
//! hot-reload into the LDE pipeline.  See Phase E2.1 / E2.2 in
//! `docs/edr-parity/PHASES.md`.
//!
//! The signed envelope is JSON-encoded for simplicity (the bundle
//! itself remains MessagePack):
//!
//! ```json
//! {
//!   "version": 42,
//!   "key_id":   "edr-rules-2026-q2",
//!   "bundle_b64":    "<base64(msgpack(RuleBundle))>",
//!   "signature_b64": "<base64(Ed25519 signature over the raw msgpack bytes)>"
//! }
//! ```

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::rule_store::RuleBundle;

/// JSON envelope returned by the TRDS endpoint.
///
/// `serde` field renames keep the wire format compact / explicit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBundleEnvelope {
    /// Monotonic bundle version.  Must match the embedded bundle's
    /// own `version` field (defence-in-depth against substitution).
    pub version: u64,
    /// Identifier of the signing key — must be present in the local
    /// rotation set.
    pub key_id: String,
    /// Base64-encoded MessagePack `RuleBundle`.
    pub bundle_b64: String,
    /// Base64-encoded Ed25519 signature over the **raw** decoded
    /// MessagePack bytes (NOT the base64 string).
    pub signature_b64: String,
}

/// Public-key entry for the bundle verifier.
///
/// `public_hex` is the lower-case hex encoding of the 32-byte
/// `ed25519_dalek::VerifyingKey` (i.e. the raw `to_bytes()` output).
#[derive(Debug, Clone)]
pub struct SigningKey {
    pub key_id: String,
    pub public_hex: String,
}

impl SigningKey {
    /// Parse the hex pubkey into a `VerifyingKey`.
    pub fn verifying_key(&self) -> Result<VerifyingKey, TrdsError> {
        let bytes = hex::decode(&self.public_hex)
            .map_err(|e| TrdsError::BadKeyHex(format!("{}: {e}", self.key_id)))?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| TrdsError::BadKeyHex(format!("{}: expected 32 raw bytes", self.key_id)))?;
        VerifyingKey::from_bytes(&arr)
            .map_err(|e| TrdsError::BadKeyHex(format!("{}: {e}", self.key_id)))
    }
}

/// A verified, ready-to-install bundle.
#[derive(Debug, Clone)]
pub struct VerifiedBundle {
    pub version: u64,
    pub key_id: String,
    pub bundle: RuleBundle,
}

/// All failure modes that the TRDS client / verifier can produce.
#[derive(Debug, Error)]
pub enum TrdsError {
    #[error("TRDS endpoint URL is malformed: {0}")]
    BadEndpoint(String),
    #[error("HTTP transport error: {0}")]
    Http(String),
    #[error("TRDS server returned HTTP {0}")]
    HttpStatus(u16),
    #[error("envelope JSON malformed: {0}")]
    BadEnvelope(String),
    #[error("envelope base64 malformed: {0}")]
    BadBase64(String),
    #[error("embedded MessagePack bundle malformed: {0}")]
    BadBundle(String),
    #[error("bundle version mismatch: envelope={envelope}, bundle={bundle}")]
    VersionMismatch { envelope: u64, bundle: u64 },
    #[error("signing key_id {0:?} not in rotation set")]
    UnknownKeyId(String),
    #[error("invalid signing public key (hex): {0}")]
    BadKeyHex(String),
    #[error("signature did not verify against key {0:?}")]
    SignatureInvalid(String),
}

/// Errors that are publishable as a [`LocalDetectionAlert`] — anything
/// the operator should see in the SIEM.
impl TrdsError {
    pub fn is_security_alert(&self) -> bool {
        matches!(
            self,
            TrdsError::SignatureInvalid(_)
                | TrdsError::UnknownKeyId(_)
                | TrdsError::VersionMismatch { .. }
        )
    }
}

/// Tiny TRDS HTTP client.
///
/// We deliberately wrap [`reqwest::Client`] rather than expose it so
/// tests can substitute a fake transport via [`Self::for_tests`].
#[derive(Debug)]
pub struct TrdsClient {
    endpoint: String,
    http: reqwest::Client,
}

impl TrdsClient {
    /// Construct a client that pulls signed envelopes from `endpoint`.
    pub fn new(endpoint: impl Into<String>, timeout: Duration) -> Result<Self, TrdsError> {
        let endpoint = endpoint.into();
        if endpoint.is_empty() {
            return Err(TrdsError::BadEndpoint("empty URL".into()));
        }
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .build()
            .map_err(|e| TrdsError::Http(e.to_string()))?;
        Ok(Self { endpoint, http })
    }

    /// Fetch the latest envelope from the configured endpoint.
    ///
    /// `current_version` is sent as an `If-None-Match` style query
    /// parameter so a sufficiently smart TRDS server can return 304 to
    /// signal "no change".  We do **not** rely on the server's behaviour:
    /// callers must additionally compare bundle versions after
    /// verification.
    pub async fn fetch_envelope(
        &self,
        current_version: u64,
    ) -> Result<Option<SignedBundleEnvelope>, TrdsError> {
        let mut url = reqwest::Url::parse(&self.endpoint)
            .map_err(|e| TrdsError::BadEndpoint(format!("{}: {e}", self.endpoint)))?;
        url.query_pairs_mut()
            .append_pair("since_version", &current_version.to_string());

        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| TrdsError::Http(e.to_string()))?;

        // Both `304 Not Modified` and `204 No Content` map to "no
        // newer bundle" — the e2e mock TRDS server (and, per
        // convention, the platform-side TRDS) returns 204 with an
        // empty body for the steady-state "nothing to do" case.
        // Treating 204 as an error path (the body fails JSON decode)
        // would emit a misleading "TRDS pull failed" warn! on every
        // poll cycle.
        if resp.status() == reqwest::StatusCode::NOT_MODIFIED
            || resp.status() == reqwest::StatusCode::NO_CONTENT
        {
            return Ok(None);
        }

        let status = resp.status();
        if !status.is_success() {
            return Err(TrdsError::HttpStatus(status.as_u16()));
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| TrdsError::Http(e.to_string()))?;
        let envelope: SignedBundleEnvelope =
            serde_json::from_slice(&body).map_err(|e| TrdsError::BadEnvelope(e.to_string()))?;
        Ok(Some(envelope))
    }
}

/// Verify a [`SignedBundleEnvelope`] against the local key rotation set
/// and return the decoded, validated bundle.
///
/// Verification steps (Phase E2.2):
///
/// 1. The envelope's `key_id` must appear in `keys`.
/// 2. The envelope's `bundle_b64` and `signature_b64` must base64-decode.
/// 3. The signature must verify against the named key's public bytes
///    when applied over the raw MessagePack bundle bytes.
/// 4. The MessagePack must decode into a [`RuleBundle`].
/// 5. The envelope's declared `version` must equal the bundle's
///    `version` field (no substitution).
pub fn verify_envelope(
    envelope: &SignedBundleEnvelope,
    keys: &[SigningKey],
) -> Result<VerifiedBundle, TrdsError> {
    let key = keys
        .iter()
        .find(|k| k.key_id == envelope.key_id)
        .ok_or_else(|| TrdsError::UnknownKeyId(envelope.key_id.clone()))?;
    let vk = key.verifying_key()?;

    let bundle_bytes = B64
        .decode(envelope.bundle_b64.as_bytes())
        .map_err(|e| TrdsError::BadBase64(format!("bundle_b64: {e}")))?;
    let sig_bytes = B64
        .decode(envelope.signature_b64.as_bytes())
        .map_err(|e| TrdsError::BadBase64(format!("signature_b64: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| TrdsError::BadBase64("signature_b64: expected 64 raw bytes".into()))?;
    let signature = Signature::from_bytes(&sig_arr);

    vk.verify(&bundle_bytes, &signature)
        .map_err(|_| TrdsError::SignatureInvalid(envelope.key_id.clone()))?;

    let bundle =
        RuleBundle::from_msgpack(&bundle_bytes).map_err(|e| TrdsError::BadBundle(e.to_string()))?;

    if bundle.version != envelope.version {
        return Err(TrdsError::VersionMismatch {
            envelope: envelope.version,
            bundle: bundle.version,
        });
    }

    Ok(VerifiedBundle {
        version: envelope.version,
        key_id: envelope.key_id.clone(),
        bundle,
    })
}

/// Build a [`SignedBundleEnvelope`] for testing / tooling.
#[cfg(test)]
pub(crate) fn sign_envelope(
    bundle: &RuleBundle,
    signing: &ed25519_dalek::SigningKey,
    key_id: impl Into<String>,
) -> anyhow::Result<SignedBundleEnvelope> {
    use ed25519_dalek::Signer;
    let bytes = bundle.to_msgpack()?;
    let sig = signing.sign(&bytes);
    Ok(SignedBundleEnvelope {
        version: bundle.version,
        key_id: key_id.into(),
        bundle_b64: B64.encode(&bytes),
        signature_b64: B64.encode(sig.to_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_store::{IocList, RuleBundle, StringIoc, SEV_HIGH};
    use ed25519_dalek::{SigningKey as Sk, SECRET_KEY_LENGTH};

    fn fixed_key(byte: u8) -> Sk {
        let mut bytes = [0u8; SECRET_KEY_LENGTH];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = byte.wrapping_add(i as u8);
        }
        Sk::from_bytes(&bytes)
    }

    fn sample_bundle(v: u64) -> RuleBundle {
        RuleBundle {
            version: v,
            generated_at: "2026-05-01T00:00:00Z".into(),
            iocs: IocList {
                strings: vec![StringIoc {
                    id: "ioc-1".into(),
                    value: "evil.example.com".into(),
                    kind: "domain".into(),
                    severity: SEV_HIGH.into(),
                    description: "trds test".into(),
                }],
                hashes: vec![],
                ips: vec![],
            },
            behavioral: vec![],
            yara_paths: vec![],
        }
    }

    fn pubkey_hex(sk: &Sk) -> String {
        hex::encode(sk.verifying_key().to_bytes())
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let sk = fixed_key(7);
        let env = sign_envelope(&sample_bundle(42), &sk, "edr-prod-2026-q2").unwrap();
        let keys = vec![SigningKey {
            key_id: "edr-prod-2026-q2".into(),
            public_hex: pubkey_hex(&sk),
        }];
        let verified = verify_envelope(&env, &keys).expect("valid signature");
        assert_eq!(verified.version, 42);
        assert_eq!(verified.bundle.iocs.strings.len(), 1);
        assert_eq!(verified.key_id, "edr-prod-2026-q2");
    }

    #[test]
    fn unknown_key_id_rejected_with_security_alert() {
        let sk = fixed_key(8);
        let env = sign_envelope(&sample_bundle(1), &sk, "unpinned-key").unwrap();
        let keys = vec![SigningKey {
            key_id: "edr-prod-2026-q2".into(),
            public_hex: pubkey_hex(&sk),
        }];
        let err = verify_envelope(&env, &keys).unwrap_err();
        assert!(matches!(err, TrdsError::UnknownKeyId(_)));
        assert!(err.is_security_alert());
    }

    #[test]
    fn tampered_bundle_fails_signature_check() {
        let sk = fixed_key(9);
        let mut env = sign_envelope(&sample_bundle(2), &sk, "edr-prod-2026-q2").unwrap();
        // Replace bundle bytes with a different bundle that the signature
        // can't possibly cover.
        let other = sample_bundle(99);
        env.bundle_b64 = B64.encode(other.to_msgpack().unwrap());
        let keys = vec![SigningKey {
            key_id: "edr-prod-2026-q2".into(),
            public_hex: pubkey_hex(&sk),
        }];
        let err = verify_envelope(&env, &keys).unwrap_err();
        assert!(matches!(err, TrdsError::SignatureInvalid(_)));
        assert!(err.is_security_alert());
    }

    #[test]
    fn version_substitution_rejected() {
        let sk = fixed_key(11);
        let mut env = sign_envelope(&sample_bundle(5), &sk, "edr-prod-2026-q2").unwrap();
        // Re-sign a v=5 bundle but claim the envelope ships v=6.
        env.version = 6;
        let keys = vec![SigningKey {
            key_id: "edr-prod-2026-q2".into(),
            public_hex: pubkey_hex(&sk),
        }];
        let err = verify_envelope(&env, &keys).unwrap_err();
        // The signature still verifies (bundle bytes unchanged) but the
        // version mismatch trips the substitution check.
        assert!(matches!(err, TrdsError::VersionMismatch { .. }));
    }

    #[test]
    fn invalid_base64_envelope_rejected() {
        let sk = fixed_key(12);
        let mut env = sign_envelope(&sample_bundle(3), &sk, "edr-prod-2026-q2").unwrap();
        env.bundle_b64 = "!!!not base64!!!".into();
        let keys = vec![SigningKey {
            key_id: "edr-prod-2026-q2".into(),
            public_hex: pubkey_hex(&sk),
        }];
        let err = verify_envelope(&env, &keys).unwrap_err();
        assert!(matches!(err, TrdsError::BadBase64(_)));
    }

    #[test]
    fn bad_key_hex_surfaces_clear_error() {
        let bad = SigningKey {
            key_id: "edr-prod-2026-q2".into(),
            public_hex: "zzzz".into(),
        };
        let err = bad.verifying_key().unwrap_err();
        assert!(matches!(err, TrdsError::BadKeyHex(_)));
    }

    #[test]
    fn empty_endpoint_url_rejected_at_construction() {
        let err = TrdsClient::new("", Duration::from_secs(1)).unwrap_err();
        assert!(matches!(err, TrdsError::BadEndpoint(_)));
    }

    #[tokio::test]
    async fn http_404_surfaces_as_http_status_error() {
        // Bind to a local port that we know will return 404 via a
        // hand-rolled tokio listener — keeps the test hermetic without
        // pulling in a mock-server crate.
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let resp =
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = sock.write_all(resp).await;
            }
        });

        let client =
            TrdsClient::new(format!("http://{addr}/trds"), Duration::from_secs(2)).unwrap();
        let err = client.fetch_envelope(0).await.unwrap_err();
        assert!(matches!(err, TrdsError::HttpStatus(404)));
    }

    /// Regression for the Phase E2 review finding: a `204 No Content`
    /// response from the TRDS server (the steady-state "no newer
    /// bundle" signal — see `crates/sda-agent/tests/e2e_lde_hotreload.rs`)
    /// must be treated as `Ok(None)`, not as a transport error.  Before
    /// the fix, 204 fell through to `bytes()` + `serde_json::from_slice`
    /// and surfaced as `TrdsError::BadEnvelope`, causing the LDE to
    /// log a misleading `"TRDS pull failed"` warn! on every poll cycle.
    #[tokio::test]
    async fn http_204_no_content_treated_as_no_new_bundle() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let resp =
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = sock.write_all(resp).await;
            }
        });

        let client =
            TrdsClient::new(format!("http://{addr}/trds"), Duration::from_secs(2)).unwrap();
        let res = client.fetch_envelope(0).await.expect("204 must not error");
        assert!(
            res.is_none(),
            "204 No Content must map to Ok(None), got {res:?}"
        );
    }

    /// Companion regression: an explicit `304 Not Modified` must also
    /// map to `Ok(None)`.  This is the original code path, but it's
    /// worth pinning so a future refactor that touches the
    /// status-code matching block (e.g. swapping to a match arm) can't
    /// regress just one of the two "no new bundle" status codes.
    #[tokio::test]
    async fn http_304_not_modified_treated_as_no_new_bundle() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let resp =
                    b"HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = sock.write_all(resp).await;
            }
        });

        let client =
            TrdsClient::new(format!("http://{addr}/trds"), Duration::from_secs(2)).unwrap();
        let res = client.fetch_envelope(0).await.expect("304 must not error");
        assert!(res.is_none(), "304 Not Modified must map to Ok(None)");
    }
}
