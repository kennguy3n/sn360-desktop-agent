//! `sda-device-control` — Device Control router and canonical
//! schemas for the SN360 Desktop Agent.
//!
//! This crate contains:
//!
//! * The five canonical schemas: [`Finding`], [`Recommendation`],
//!   [`SignedActionJob`], [`ActionResult`], [`EvidenceRecord`].
//! * RFC 8785 [canonical-JSON] serialiser used as the signature
//!   pre-image and for evidence-chain hashing.
//! * The 12-step signed-job validation [`router`] with pluggable
//!   [`JobValidationHooks`] (Ed25519 signature verification,
//!   maintenance-window evaluation, dual-control, local ephemeral
//!   keys).
//! * USB device-policy enforcement via [`usb_policy`] and
//!   per-platform watchers (Linux udev, macOS IOKit, Windows
//!   SetupDi).
//!
//! The [`DeviceControlModule::start`] entry point parks on the
//! shutdown signal when enabled — per-action executors are
//! dispatched through the router’s hooks.  When
//! `modules.device_control.enabled = false` (the default), the
//! module is never spawned.
//!
//! All wire types match `docs/wire-protocols/device-control.md`
//! exactly.  Diverging from that document is a major-version
//! protocol break.

pub mod action_result;
pub mod canonicalize;
pub mod evidence;
pub mod finding;
pub mod recommendation;
pub mod router;
pub mod signed_job;
pub mod types;
pub mod usb_policy;
pub mod version;
pub mod windows;

// Per-OS USB-policy enforcement modules. Each one builds the
// `DeviceCandidate` from the OS event source (Linux udev, Windows
// SetupDi, macOS IOKit) and dispatches to
// [`usb_policy::DevicePolicyStore::evaluate`] for the decision.
// They share a hermetic IPC contract under [`usb_ipc`] so the
// per-OS helpers can be exercised from a synthetic harness.
pub mod usb_ipc;
#[cfg(any(target_os = "linux", test))]
pub mod usb_linux;
#[cfg(any(target_os = "macos", test))]
pub mod usb_macos;
pub mod usb_module;
pub mod usb_supervisor;
#[cfg(any(target_os = "windows", test))]
pub mod usb_windows;

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
    validate as validate_signed_job, AgentIdentity, JobValidationHooks, Phase1Stub,
    ProductionHooks, ValidatedJob, CLOCK_SKEW_TOLERANCE,
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
pub use usb_ipc::{
    decode_query_request, decode_query_response, encode_query_request, encode_query_response,
    UsbIpcError, UsbIpcQueryRequest, UsbIpcQueryResponse,
};
pub use usb_module::{
    supervisor_from_config as usb_supervisor_from_config,
    try_apply_from_disk as try_apply_usb_bundle_slice_from_disk, UsbPolicyModule,
    DEFAULT_BUNDLE_METADATA_PATH as USB_DEFAULT_BUNDLE_METADATA_PATH,
    DEFAULT_BUNDLE_SLICE_PATH as USB_DEFAULT_BUNDLE_SLICE_PATH,
};
pub use usb_policy::{
    Action as UsbPolicyAction, Decision as UsbPolicyDecision, DeviceCandidate, DeviceClass,
    DevicePolicy, DevicePolicySet, DevicePolicyStore, PolicyMatch, PolicySetError,
    POLICY_SLICE_MAX_BYTES,
};
pub use usb_supervisor::{
    UsbPolicyApplyError, UsbPolicyApplyOutcome, UsbPolicySupervisor, UsbPolicySupervisorConfig,
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

/// Device Control module entry point.
///
/// When `modules.device_control.enabled = false` (the default),
/// this task is never spawned at all — the agent's idle footprint
/// is unchanged (`docs/device-control.md` § 11).
///
/// The signature mirrors the existing `sda-fim` / `sda-rootcheck`
/// modules so the agent's wiring code can call all modules through
/// a single shape.
pub struct DeviceControlModule;

impl DeviceControlModule {
    /// Spawn the Device Control supervisor task, returning a
    /// [`ModuleHandle`] that the agent's lifecycle code owns.
    ///
    /// `_bus` is unused — the bus subscription will land together
    /// with the per-action executors.  `_config` is retained so
    /// the call site is stable.
    pub fn start(
        _config: &AgentConfig,
        _bus: EventBus,
        mut shutdown: ShutdownSignal,
    ) -> ModuleHandle {
        info!("device-control module starting");
        let task = tokio::spawn(async move {
            // Park on the shared shutdown signal. We deliberately
            // do not consume bus traffic because there is no
            // executor to run yet.
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
