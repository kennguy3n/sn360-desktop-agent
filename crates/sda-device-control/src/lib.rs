//! `sda-device-control` — Device Control router and canonical
//! schemas for the SN360 Desktop Agent.
//!
//! This crate ships the Phase 1 scaffold of the Device Control
//! feature set described in `docs/device-control/PROPOSAL.md`. It
//! contains:
//!
//! * The five canonical schemas: [`Finding`], [`Recommendation`],
//!   [`SignedActionJob`], [`ActionResult`], [`EvidenceRecord`].
//! * RFC 8785 [canonical-JSON] serialiser used as the signature
//!   pre-image and for evidence-chain hashing.
//! * The 10-step signed-job validation [`router`].
//!
//! The crate is intentionally executor-free for Phase 1 — the
//! per-`ActionKind` orchestration (install, update, JIT admin
//! grant, …) is wired up in Phase 2/3 in dedicated executor
//! crates. The Phase 1 [`DeviceControlModule::start`] entry point
//! parks on the shutdown signal so a `modules.device_control.enabled`
//! flag can be flipped on without any executable side effects.
//!
//! All wire types match `docs/device-control/SCHEMAS.md` exactly.
//! Diverging from that document is a major-version protocol break.

pub mod action_result;
pub mod canonicalize;
pub mod evidence;
pub mod finding;
pub mod recommendation;
pub mod router;
pub mod signed_job;
pub mod types;
pub mod version;

pub use action_result::{
    ActionResult, ActionResultError, ACTION_RESULT_OUTPUT_MAX_BYTES, TRUNCATION_MARKER,
};
pub use canonicalize::{canonicalize as canonicalize_json, CanonicalizeError};
pub use evidence::{sha256, EvidenceError, EvidenceRecord, FIRST_RECORD_PREV_HASH};
pub use finding::{
    render_plain_english, Finding, FindingError, SourceRef, FINDING_EVIDENCE_MAX_BYTES,
    FINDING_PLAIN_ENGLISH_MAX,
};
pub use recommendation::{Recommendation, RecommendationError, RECOMMENDATION_PLAIN_ENGLISH_MAX};
pub use router::{
    validate as validate_signed_job, AgentIdentity, JobValidationHooks, Phase1Stub, ValidatedJob,
    CLOCK_SKEW_TOLERANCE,
};
pub use signed_job::{
    EndRemoteSupportArgs, GrantJitAdminArgs, InstallPackageArgs, JobArgs, PushAppControlPolicyArgs,
    QueryAdHocArgs, RevokeAdminArgs, RunScriptArgs, SignedActionJob, SignedJobError,
    StartRemoteSupportArgs, UninstallPackageArgs, UpdatePackageArgs,
    GRANT_JIT_ADMIN_MAX_DURATION_MINUTES, QUERY_AD_HOC_MAX_ROWS, RUN_SCRIPT_MAX_TIMEOUT_SECONDS,
    SIGNED_JOB_ARGS_MAX_BYTES, START_REMOTE_SUPPORT_MAX_DURATION_MINUTES,
};
pub use types::{
    ActionKind, ActionStatus, AgentVersion, FindingKind, JobRefused, Platform, PlatformArch,
    PlatformOs, Severity,
};
pub use version::{
    ACTION_RESULT_SCHEMA_VERSION, EVIDENCE_RECORD_SCHEMA_VERSION, FINDING_SCHEMA_VERSION,
    RECOMMENDATION_SCHEMA_VERSION, SIGNED_ACTION_JOB_SCHEMA_VERSION,
};

use sda_core::config::AgentConfig;
use sda_core::module::ModuleHandle;
use sda_core::signal::ShutdownSignal;
use sda_event_bus::EventBus;
use tracing::{info, warn};

/// Phase 1 module entry point.
///
/// In Phase 1 this future does no work beyond logging that it
/// started; the per-action executors and the inbound-job listener
/// land in later phases. Importantly, when
/// `modules.device_control.enabled = false` (the default), this
/// task is never spawned at all — the agent's idle footprint is
/// unchanged from a pre-Device-Control build (PROPOSAL.md § 13).
///
/// The signature mirrors the existing `sda-fim` / `sda-rootcheck`
/// modules so the agent's wiring code can call all modules through
/// a single shape.
pub struct DeviceControlModule;

impl DeviceControlModule {
    /// Spawn the Device Control supervisor task, returning a
    /// [`ModuleHandle`] that the agent's lifecycle code owns.
    ///
    /// `_bus` is unused in Phase 1 — the bus subscription lands
    /// together with the per-action executors. `_config` is
    /// retained so the call site doesn't change between phases.
    pub fn start(
        _config: &AgentConfig,
        _bus: EventBus,
        mut shutdown: ShutdownSignal,
    ) -> ModuleHandle {
        info!(
            "device-control module starting (Phase 1 scaffold; \
            executors land in Phase 2/3)"
        );
        let task = tokio::spawn(async move {
            // Park on the shared shutdown signal. We deliberately
            // do not consume bus traffic in Phase 1 because there
            // is no executor to run yet.
            shutdown.wait().await;
            warn!("device-control module shutting down");
            Ok(())
        });
        ModuleHandle::new("device-control", task)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn re_exports_compile() {
        // Smoke test: every public item in the prelude is reachable
        // through the crate root, so downstream callers don't have
        // to remember the module structure.
        let _ = FINDING_SCHEMA_VERSION;
        let _ = ACTION_RESULT_SCHEMA_VERSION;
        let _ = EVIDENCE_RECORD_SCHEMA_VERSION;
        let _ = RECOMMENDATION_SCHEMA_VERSION;
        let _ = SIGNED_ACTION_JOB_SCHEMA_VERSION;
        let _ = CLOCK_SKEW_TOLERANCE;
        let _ = SIGNED_JOB_ARGS_MAX_BYTES;
        let _ = ACTION_RESULT_OUTPUT_MAX_BYTES;
        let _ = FINDING_PLAIN_ENGLISH_MAX;
        let _ = RECOMMENDATION_PLAIN_ENGLISH_MAX;
        let _ = FINDING_EVIDENCE_MAX_BYTES;
        let _ = QUERY_AD_HOC_MAX_ROWS;
        let _ = GRANT_JIT_ADMIN_MAX_DURATION_MINUTES;
        let _ = RUN_SCRIPT_MAX_TIMEOUT_SECONDS;
        let _ = START_REMOTE_SUPPORT_MAX_DURATION_MINUTES;
        let _ = TRUNCATION_MARKER;
    }
}
