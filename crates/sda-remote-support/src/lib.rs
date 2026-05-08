//! Remote-support session orchestration (Phase 4, Task 4.2 / 4.3).
//!
//! This crate sits between `sda-pal::remote_support` (the OS-level
//! capture / transport stubs) and the agent supervisor. It owns:
//!
//! * Session state-machine: `Pending → ConsentRequested → Active → Ended`.
//! * Consent flow (always required per PROPOSAL.md § 9.7).
//! * Time-bounded sessions enforced by a wall-clock cap.
//! * The clean-room MeshCentral-style wire protocol — frame
//!   types, MessagePack encoding, sequence + heartbeat validation,
//!   per-session keys derived from the control-plane session
//!   token. **Not** a port of MeshCentral source code; the protocol
//!   below is a fresh implementation whose only inheritance from
//!   MeshCentral is the bidirectional-frame shape (PROPOSAL.md
//!   § 9.7, ARCHITECTURE.md § 9 row 9).
//!
//! The supervisor is wired in `crates/sda-agent/src/main.rs`
//! conditionally on `modules.remote_support.enabled`.

pub mod consent;
pub mod module;
pub mod protocol;
pub mod session;

pub use consent::{ConsentDecision, ConsentManager, ConsentPrompt};
pub use module::{
    RemoteSupportError, RemoteSupportEvent, RemoteSupportModule, RemoteSupportRequest,
    RemoteSupportSupervisor,
};
pub use protocol::{
    derive_session_keys, Frame, FrameError, FrameType, ProtocolEngine, SessionKeys,
};
pub use session::{Session, SessionState};
