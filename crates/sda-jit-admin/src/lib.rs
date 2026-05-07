//! `sda-jit-admin` — just-in-time admin grant lifecycle + revocation
//! watchdog (Phase 3.2 + 3.3).
//!
//! See `docs/device-control/PROPOSAL.md` § 9.3 and
//! `docs/device-control/ARCHITECTURE.md` § 5 for the full
//! specification.
//!
//! The crate ships four public pieces:
//!
//! 1. [`grant::GrantRecord`] / [`grant::GrantState`] — the persisted
//!    representation of an active or terminal grant.
//! 2. [`state_machine::StateMachine`] — pure-logic state machine that
//!    validates lifecycle transitions and emits the corresponding
//!    `EventKind::JitAdmin*` payloads.
//! 3. [`store::GrantStore`] — disk-backed JSON ledger that survives
//!    agent restarts and round-trips schema versions.
//! 4. [`watchdog::RevocationWatchdog`] — async timer + heartbeat
//!    monitor that calls [`AdminManager::revoke_admin`](sda_pal::admin_manager::AdminManager)
//!    when a grant should be revoked.
//!
//! [`module::JitAdminModule`] is the agent-supervisor entry point
//! that wires all four pieces together against
//! `modules.jit_admin.enabled`.

#![deny(rust_2018_idioms)]

pub mod grant;
pub mod state_machine;
pub mod store;
pub mod watchdog;
mod module;

pub use grant::{GrantRecord, GrantState};
pub use module::{JitAdminHandle, JitAdminModule, JitAdminSender};
pub use state_machine::{StateMachine, StateTransition, TransitionError};
pub use store::{GrantStore, StoreError};
pub use watchdog::{RevocationReason, RevocationWatchdog, WatchdogConfig};
