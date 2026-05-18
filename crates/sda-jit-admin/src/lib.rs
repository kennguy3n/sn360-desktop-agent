//! `sda-jit-admin` — just-in-time admin grant lifecycle + revocation
//! watchdog + drift detector (Phase 3.2 / 3.3 / 3.5).
//!
//! See `docs/device-control.md` § 7 (Just-in-Time admin) and
//! `docs/architecture.md` § 4 (PAL traits) for the full
//! specification.
//!
//! The crate ships five public pieces:
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
//! 5. [`drift::DriftDetector`] — pure-logic comparison between
//!    [`AdminManager::list_admins`](sda_pal::admin_manager::AdminManager::list_admins)
//!    and the active grant ledger; surfaces unauthorised admins as
//!    [`drift::Drift`] entries (Phase 3.5 / `docs/device-control.md` § 7).
//!
//! [`module::JitAdminModule`] is the agent-supervisor entry point
//! that wires all five pieces together against
//! `modules.jit_admin.enabled`.

#![deny(rust_2018_idioms)]

pub mod drift;
pub mod grant;
mod module;
pub mod state_machine;
pub mod store;
pub mod watchdog;

pub use drift::{Drift, DriftDetector, DriftError, DriftKind};
pub use grant::{GrantRecord, GrantState};
pub use module::{JitAdminHandle, JitAdminModule, JitAdminRequest, JitAdminSender};
pub use state_machine::{StateMachine, StateTransition, TransitionError};
pub use store::{GrantStore, StoreError};
pub use watchdog::{RevocationReason, RevocationWatchdog, WatchdogConfig};
