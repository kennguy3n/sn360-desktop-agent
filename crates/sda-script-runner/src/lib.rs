//! `sda-script-runner` — signed-script execution module for SDA
//! Device Control (Phase 2.7).
//!
//! See `docs/device-control.md` § 2 (Modules — `sda-script-runner`)
//! and § 4 (Signed-job lifecycle).
//!
//! The script runner accepts canonically-named, Ed25519-signed
//! scripts (e.g. `sn360.diagnostics.tcp_ping`) from the control
//! plane, runs them under a hard wall-clock + output-byte budget,
//! and emits the result as `EventKind::ScriptRunResult` plus an
//! `EventKind::EvidenceRecord` projection so the action survives in
//! the audit trail. The agent never inherits its environment block,
//! never opens a PTY, and never accepts stdin so an attacker cannot
//! escape through environment-leakage or interactive prompts.
//!
//! The crate ships three pieces:
//!
//! 1. [`allowlist::Allowlist`] — a deny-by-default glob matcher
//!    over canonical script names (e.g. `sn360.diagnostics.*`).
//! 2. [`runner::ScriptRunner`] / [`runner::ScriptRequest`] — the
//!    in-process engine that verifies the signature, runs the
//!    script, and produces a [`runner::ScriptOutcome`] payload.
//! 3. [`ScriptRunnerModule`] — the `sda-agent` supervisor task
//!    wired in `crates/sda-agent/src/main.rs` conditional on
//!    `modules.script_runner.enabled`.

pub mod allowlist;
mod module;
pub mod runner;

pub use allowlist::Allowlist;
pub use module::ScriptRunnerModule;
pub use runner::{
    ScriptOutcome, ScriptRequest, ScriptRunner, ScriptRunnerConfig as RunnerConfig,
    ScriptRunnerError,
};
