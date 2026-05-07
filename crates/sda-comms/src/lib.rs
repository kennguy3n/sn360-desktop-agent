//! Communication layer for the SN360 Desktop Agent.
//!
//! The native-protocol building blocks ([`msgpack`], [`transport`])
//! are always compiled. The legacy SIEM adapter (Wazuh v4.x wire
//! protocol with Blowfish-CBC / AES-256-CBC encryption, TCP/UDP
//! transport, `authd`-compatible enrolment, and the periodic keepalive
//! that drives it) is gated behind the `legacy-siem` Cargo feature so
//! a proprietary-only distribution can compile it out.
//!
//! Note: [`keepalive`] currently depends on
//! [`connection::ConnectionManager`] and [`protocol::WazuhMessage`],
//! so it is gated alongside the other legacy modules. Reviving a
//! transport-agnostic keepalive would require decoupling those
//! imports first.

#[cfg(feature = "legacy-siem")]
pub mod blowfish_wazuh;
#[cfg(feature = "legacy-siem")]
pub mod connection;
#[cfg(feature = "legacy-siem")]
pub mod crypto;
#[cfg(feature = "legacy-siem")]
pub mod enrollment;
#[cfg(feature = "legacy-siem")]
pub mod keepalive;
pub mod msgpack;
#[cfg(feature = "legacy-siem")]
pub mod protocol;
pub mod transport;
