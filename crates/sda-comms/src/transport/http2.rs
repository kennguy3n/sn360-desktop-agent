//! HTTP/2 transport primitives (Phase 5.6 / proposal § 8.2).
//!
//! This module is the building block for the opt-in HTTP/2 uplink to
//! an SDA-aware server. It exposes [`build_client_config`], which
//! returns a TLS-1.3 [`rustls::ClientConfig`] with the ALPN list
//! forced to `[b"h2"]` — any server that negotiates a different
//! protocol will trigger a handshake failure rather than silently
//! falling back.
//!
//! The actual request/response plumbing (multiplexed streams, server
//! push, message batching) is deliberately NOT wired in here. This
//! crate ships the shared TLS bootstrap under test so operators have
//! a stable knob (`config.server.enhanced.tls = true` +
//! `config.server.protocol = "http2"`) before the full HTTP/2
//! ConnectionManager lands.

use std::sync::Arc;

use anyhow::{bail, Result};
use rustls::ClientConfig;
use sda_core::config::{EnhancedProtocolConfig, ServerConfig};

use super::tls::build_client_config_with_alpn;

/// ALPN identifier for HTTP/2 as defined by RFC 7540 § 3.1.
pub const ALPN_H2: &[u8] = b"h2";

/// Build a TLS 1.3 + ALPN=h2 `ClientConfig` from the agent config.
///
/// HTTP/2 traffic is always encrypted in the enhanced protocol — we
/// don't support h2c (HTTP/2 cleartext) because the whole point of
/// the enhanced mode is to replace the legacy AES-CBC wrapper with
/// proper TLS. Callers must therefore set
/// `config.server.enhanced.tls = true` in addition to picking
/// `protocol = "http2"`.
pub fn build_client_config(cfg: &EnhancedProtocolConfig) -> Result<Arc<ClientConfig>> {
    if !cfg.tls {
        bail!(
            "HTTP/2 transport requires enhanced.tls = true; refusing to build a cleartext h2 client"
        );
    }
    build_client_config_with_alpn(cfg, &[ALPN_H2])
}

/// Validate that the combination of [`ServerConfig`] fields is
/// consistent when the operator has asked for HTTP/2. Returns the
/// reason as a human-readable string on the error path so the agent
/// can surface a config-time diagnostic before the first connect
/// attempt.
///
/// This is intentionally cheap and side-effect-free: callers should
/// invoke it during config load (not inside the hot connect loop).
pub fn validate_server_config(server: &ServerConfig) -> Result<(), String> {
    if server.protocol != "http2" {
        return Ok(());
    }
    if !server.enhanced.tls {
        return Err("server.protocol = \"http2\" requires server.enhanced.tls = true".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::config::ServerConfig;

    #[test]
    fn build_fails_when_tls_disabled() {
        let cfg = EnhancedProtocolConfig::default();
        let err = build_client_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("requires enhanced.tls = true"));
    }

    #[test]
    fn build_uses_h2_alpn() {
        let cfg = EnhancedProtocolConfig {
            tls: true,
            ..Default::default()
        };
        let client = build_client_config(&cfg).unwrap();
        assert_eq!(client.alpn_protocols, vec![ALPN_H2.to_vec()]);
    }

    #[test]
    fn validate_accepts_tcp_default() {
        let server = ServerConfig {
            address: "localhost".into(),
            port: 1514,
            protocol: "tcp".into(),
            keepalive_interval: 600,
            enhanced: EnhancedProtocolConfig::default(),
        };
        assert!(validate_server_config(&server).is_ok());
    }

    #[test]
    fn validate_accepts_http2_with_tls() {
        let server = ServerConfig {
            address: "localhost".into(),
            port: 443,
            protocol: "http2".into(),
            keepalive_interval: 600,
            enhanced: EnhancedProtocolConfig {
                tls: true,
                ..Default::default()
            },
        };
        assert!(validate_server_config(&server).is_ok());
    }

    #[test]
    fn validate_rejects_http2_without_tls() {
        let server = ServerConfig {
            address: "localhost".into(),
            port: 443,
            protocol: "http2".into(),
            keepalive_interval: 600,
            enhanced: EnhancedProtocolConfig::default(),
        };
        let err = validate_server_config(&server).unwrap_err();
        assert!(err.contains("requires server.enhanced.tls = true"));
    }
}
