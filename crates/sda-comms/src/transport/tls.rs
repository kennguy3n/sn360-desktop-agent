//! TLS 1.3 transport primitives (proposal § 8.2).
//!
//! This module produces a `rustls` [`ClientConfig`] from the agent's
//! config surface (`config.server.enhanced.*`) and exposes a helper
//! for connecting an opened [`tokio::net::TcpStream`] into a TLS 1.3
//! stream. It deliberately restricts the allowed protocol versions
//! to TLS 1.3 only — downgrade to 1.2 is not permitted for opt-in
//! enhanced sessions.
//!
//! Certificate trust:
//!
//! * Default behaviour trusts the `webpki-roots` bundle (Mozilla's
//!   public-web CA list) so operators can point `server.address` at
//!   a publicly-trusted endpoint without extra configuration.
//! * If `tls_ca_bundle_path` is set, that PEM bundle replaces the
//!   public roots entirely — typical for private-CA deployments.
//! * If `tls_pinned_sha256` is set, a custom verifier layers
//!   leaf-certificate SHA-256 pinning on top of the chain check.
//!   A pin mismatch fails the handshake.
//!
//! The pin format is lowercase hex with no colons (matches
//! `openssl x509 -fingerprint -sha256 | awk -F= '{print $2}' | tr -d : | tr A-Z a-z`).

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sda_core::config::EnhancedProtocolConfig;
use sha2::{Digest, Sha256};

/// ALPN identifier the enhanced SDA protocol advertises when tunnelled
/// over TLS-wrapped TCP. The HTTP/2 connector in the sibling
/// [`crate::transport::http2`] module advertises `"h2"` instead.
pub const ALPN_SDA_ENHANCED: &[u8] = b"sda/1.0";

/// Build a TLS-1.3-only [`ClientConfig`] from the agent's enhanced
/// protocol configuration.
///
/// Returns an error if `tls` is disabled in `cfg`, if a supplied CA
/// bundle can't be parsed, or if the pinned fingerprint isn't a
/// valid 32-byte lowercase-hex string.
pub fn build_client_config(cfg: &EnhancedProtocolConfig) -> Result<Arc<ClientConfig>> {
    build_client_config_with_alpn(cfg, &[ALPN_SDA_ENHANCED])
}

/// Variant of [`build_client_config`] that lets callers override the
/// advertised ALPN list. The HTTP/2 module uses this to offer `"h2"`.
pub(crate) fn build_client_config_with_alpn(
    cfg: &EnhancedProtocolConfig,
    alpn: &[&[u8]],
) -> Result<Arc<ClientConfig>> {
    if !cfg.tls {
        bail!("enhanced TLS is disabled; refusing to build a rustls ClientConfig");
    }

    // TLS 1.3 only — no downgrade allowed for enhanced sessions.
    let provider = rustls::crypto::ring::default_provider();
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("selecting TLS 1.3")?;

    let roots = load_roots(cfg.tls_ca_bundle_path.as_deref())?;

    let mut client = if let Some(ref pin) = cfg.tls_pinned_sha256 {
        let expected = parse_pin(pin)?;
        let verifier = Arc::new(PinnedLeafVerifier {
            expected,
            roots: Arc::new(roots),
        });
        builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    } else {
        builder.with_root_certificates(roots).with_no_client_auth()
    };

    client.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(client))
}

fn load_roots(bundle_path: Option<&Path>) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    if let Some(path) = bundle_path {
        let pem = std::fs::read(path)
            .with_context(|| format!("reading CA bundle at {}", path.display()))?;
        let mut reader = std::io::Cursor::new(pem);
        let mut count = 0usize;
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.context("parsing PEM certificate from CA bundle")?;
            roots
                .add(cert)
                .context("adding PEM certificate to root store")?;
            count += 1;
        }
        if count == 0 {
            bail!(
                "no PEM certificates found in CA bundle at {}",
                path.display()
            );
        }
    } else {
        // Fall back to the webpki-roots bundle. Downstream operators
        // wanting to trust only a private CA should set
        // `tls_ca_bundle_path`.
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    Ok(roots)
}

fn parse_pin(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        bail!(
            "pinned SHA-256 fingerprint must be 64 hex characters, got {}",
            hex.len()
        );
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow!("invalid hex at byte {}: {}", i, e))?;
    }
    Ok(out)
}

/// Custom verifier that does standard chain validation AND pins the
/// leaf certificate's SHA-256 to an operator-specified fingerprint.
#[derive(Debug)]
struct PinnedLeafVerifier {
    expected: [u8; 32],
    roots: Arc<RootCertStore>,
}

impl ServerCertVerifier for PinnedLeafVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
            self.roots.clone(),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|e| rustls::Error::General(e.to_string()))?;
        inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;

        // …then enforce the SHA-256 pin on top.
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if actual != self.expected {
            return Err(rustls::Error::General(format!(
                "leaf certificate pin mismatch: expected {}, got {}",
                hex_encode(&self.expected),
                hex_encode(&actual),
            )));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.2 is disabled via `with_protocol_versions` above, but
        // the trait still requires an implementation. Refuse
        // explicitly so a future regression that re-enables 1.2
        // doesn't silently accept signatures here.
        Err(rustls::Error::General(
            "TLS 1.2 handshake signatures are not accepted in enhanced mode".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
            self.roots.clone(),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|e| rustls::Error::General(e.to_string()))?;
        inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Same set rustls' default verifier accepts in TLS 1.3.
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_fails_when_tls_disabled() {
        let cfg = EnhancedProtocolConfig::default();
        assert!(build_client_config(&cfg).is_err());
    }

    #[test]
    fn build_succeeds_with_tls_enabled_and_defaults() {
        let cfg = EnhancedProtocolConfig {
            tls: true,
            ..Default::default()
        };
        let client = build_client_config(&cfg).expect("client config");
        assert_eq!(client.alpn_protocols, vec![ALPN_SDA_ENHANCED.to_vec()]);
    }

    #[test]
    fn build_fails_with_malformed_pin() {
        let cfg = EnhancedProtocolConfig {
            tls: true,
            tls_pinned_sha256: Some("not-hex".to_string()),
            ..Default::default()
        };
        assert!(build_client_config(&cfg).is_err());
    }

    #[test]
    fn build_succeeds_with_valid_pin() {
        let cfg = EnhancedProtocolConfig {
            tls: true,
            tls_pinned_sha256: Some("a".repeat(64)),
            ..Default::default()
        };
        assert!(build_client_config(&cfg).is_ok());
    }

    #[test]
    fn build_fails_when_ca_bundle_missing() {
        let cfg = EnhancedProtocolConfig {
            tls: true,
            tls_ca_bundle_path: Some("/definitely/does/not/exist.pem".into()),
            ..Default::default()
        };
        assert!(build_client_config(&cfg).is_err());
    }

    #[test]
    fn build_fails_on_empty_ca_bundle() {
        use std::io::Write;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp.as_file(), "# empty bundle, no certs here").unwrap();
        let cfg = EnhancedProtocolConfig {
            tls: true,
            tls_ca_bundle_path: Some(tmp.path().to_path_buf()),
            ..Default::default()
        };
        let err = build_client_config(&cfg).unwrap_err();
        assert!(
            err.to_string().contains("no PEM certificates"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_pin_round_trip() {
        let pin = "a".repeat(64);
        let parsed = parse_pin(&pin).unwrap();
        assert_eq!(parsed, [0xaa; 32]);
    }

    #[test]
    fn hex_encode_matches_fmt() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }
}
