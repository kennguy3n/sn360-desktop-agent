//! Application-control orchestration module (Phase 4, Task 4.5).
//!
//! Sits between `sda-pal::app_control` (the OS-level binding to
//! Santa / WDAC / dm-verity) and the agent supervisor. It owns:
//!
//! * **Policy verification** ([`policy`]): Ed25519 signature
//!   validation + per-rule canonical-hash check, layered on top of
//!   [`sda_pal::app_control::verify_policy`].
//! * **Monitor mode** ([`monitor`]): the Phase-4 default. Allow /
//!   deny decisions are LOGGED but never block. Required by
//!   PROPOSAL.md § 9.6 ("Phase 4 ships in monitor-only mode").
//! * **Enforce mode** ([`enforce`]): policy is pushed to the OS
//!   backend so unauthorized binaries are blocked. Requires explicit
//!   tenant opt-in and a [`enforce::DualControlRollback`] handle so
//!   a misbehaving policy can be rolled back automatically.
//! * **Module supervisor** ([`module`]): `tokio::select!`-driven
//!   task that ingests `AppControlCommand`s and emits
//!   `EventKind::AppControlPolicyApplied` and
//!   `EventKind::AppControlDecision` events on the bus.

pub mod enforce;
pub mod linux;
pub mod module;
pub mod monitor;
pub mod policy;
pub mod wdac;

pub use enforce::{DualControlRollback, EnforceController, RollbackError};
pub use linux::{
    build_policy_artifact as build_linux_policy_artifact, parse_dm_verity_status,
    render_policy_file as render_linux_policy_file, DmVerityState, DmVerityStatus,
    LinuxAppControlProvider as LinuxAppControlProviderImpl, LinuxDecisionRecord,
    LinuxPolicyArtifact, LinuxPolicyEntry, LinuxSubjectKind,
};
pub use module::{
    AppControlCommand, AppControlError, AppControlEvent, AppControlModule, AppControlSupervisor,
};
pub use monitor::{Decision, MonitorController};
pub use policy::{verify_signed_policy, PolicyVerificationError, VerifiedPolicy};
pub use wdac::{
    build_applocker_document, build_wdac_document, powershell_apply_applocker_commands,
    powershell_apply_wdac_commands, render_applocker_xml, render_wdac_xml, select_backend,
    AppLockerPolicyDocument, PowerShellCommand, SubjectKind as WdacSubjectKind,
    WdacAppControlProvider, WdacApplyRecord, WdacBackend, WdacPolicyDocument, WdacRuleEntry,
};
