//! Opt-in alternative transports (proposal § 8.2).
//!
//! The agent's default path remains the legacy Wazuh TCP/UDP
//! protocol implemented in [`crate::connection`]. The submodules here
//! add:
//!
//! * [`tls`] — wraps a TCP connection in TLS 1.3 (via `rustls`),
//!   with optional leaf-certificate pinning for strict deployments.
//! * [`http2`] — establishes an HTTP/2-over-TLS client connection
//!   using the same `tokio-rustls` stack.
//!
//! Both modules are deliberately small: they expose the connection
//! primitives (configuration parsing + TLS handshake) but do NOT
//! replace [`crate::connection::ConnectionManager`]. The intent is
//! that a future wire-in can compose these primitives with the
//! existing cipher / framing logic, but this crate ships the
//! building blocks under test first so the config surface is stable
//! for operators before the full integration lands.

pub mod http2;
pub mod tls;
