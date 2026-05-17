//! Host isolation module (Phase E3 of the EDR Parity workstream).
//!
//! Consumes `IsolateHost` / `UnisolateHost` `SignedActionJob`s,
//! validates them via the existing 10-step signed-job pipeline
//! (`sda_device_control::router::validate`), translates the
//! caller-supplied + configured allow-list into a
//! `Vec<ipnet::IpNet>`, and invokes
//! [`sda_pal::host_isolation::HostIsolation::isolate`] /
//! [`unisolate`]. On every state transition the module publishes
//! [`EventKind::HostIsolationStateChanged`] on the shared event
//! bus so the control plane (and the local detection engine) can
//! observe the new posture.
//!
//! Safety invariants from `docs/edr-parity/ARCHITECTURE.md` § 11:
//!
//! 1. `allow_ips` always includes
//!    `modules.host_isolation.control_plane_cidrs`.
//! 2. Loopback (`127.0.0.0/8` + `::1/128`) is always allowed
//!    (enforced by the PAL via `normalize_allow_ips`).
//! 3. An `IsolateHost` job with `enabled = false` is refused
//!    silently so the control plane can distinguish a
//!    disabled-by-policy host from a transient firewall failure.
//! 4. Jobs whose signature does not verify never reach the PAL
//!    (refused by `router::validate` at step 4).
//! 5. The agent emits `HostIsolationStateChanged` only on actual
//!    transitions to keep the audit chain tight.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

use sda_core::config::{AgentConfig, HostIsolationConfig};
use sda_core::module::{AgentModule, ModuleHandle, ModuleHealth, ModuleStatus};
use sda_core::signal::ShutdownSignal;
use sda_device_control::router::{self, AgentIdentity, JobValidationHooks, Phase1Stub};
use sda_device_control::signed_job::{JobArgs, SignedActionJob};
use sda_device_control::types::{ActionKind, JobRefused};
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use sda_pal::host_isolation::{default_host_isolation, HostIsolation};

const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// Default mailbox depth between the job submitter (comms / device-
/// control router) and the host-isolation run loop. Plenty of head-
/// room: isolation jobs are rare (operator-driven), so a deep queue
/// only matters when the agent buffers transient burst load.
const DEFAULT_JOB_MAILBOX_DEPTH: usize = 64;

/// Public submission handle.
///
/// The agent's job dispatcher (or an integration test) holds one of
/// these and calls [`HostIsolationSubmitter::submit`] every time a
/// new `IsolateHost` / `UnisolateHost` job lands. The run loop
/// validates and dispatches it; backpressure manifests as a
/// rejected submit (`Err(SubmitError::Full)` from `try_submit`).
#[derive(Clone)]
pub struct HostIsolationSubmitter {
    tx: mpsc::Sender<SignedActionJob>,
}

impl HostIsolationSubmitter {
    /// Hand a job to the run loop. Returns `Err` only on shutdown
    /// (the run loop has dropped the receiver).
    pub async fn submit(&self, job: SignedActionJob) -> Result<(), SubmitError> {
        self.tx.send(job).await.map_err(|_| SubmitError::Closed)
    }

    /// Non-blocking submit. Returns `Err(SubmitError::Full)` when the
    /// mailbox is at capacity.
    pub fn try_submit(&self, job: SignedActionJob) -> Result<(), SubmitError> {
        match self.tx.try_send(job) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(SubmitError::Full),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(SubmitError::Closed),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    #[error("host-isolation mailbox is full")]
    Full,
    #[error("host-isolation module has shut down")]
    Closed,
}

/// Boxed-dyn adapter so callers can keep hooks in an `Arc` while
/// `router::validate` requires a sized generic `H: JobValidationHooks`.
struct DynHooks(Arc<dyn JobValidationHooks + Send + Sync>);

impl JobValidationHooks for DynHooks {
    fn verify_signature(&self, job: &SignedActionJob) -> Result<(), JobRefused> {
        self.0.verify_signature(job)
    }
    fn action_permitted(&self, action: ActionKind) -> bool {
        self.0.action_permitted(action)
    }
    fn in_window(&self, now: DateTime<Utc>) -> bool {
        self.0.in_window(now)
    }
    fn verify_additional_signature(
        &self,
        job: &SignedActionJob,
        sig: &sda_device_control::signed_job::AdditionalSignature,
    ) -> Result<(), JobRefused> {
        self.0.verify_additional_signature(job, sig)
    }
    fn approver_user_id(&self, key_id: &str) -> Option<uuid::Uuid> {
        self.0.approver_user_id(key_id)
    }
    fn is_local_ephemeral_key(&self, key_id: &str) -> bool {
        self.0.is_local_ephemeral_key(key_id)
    }
}

/// Module entry-point. Wraps the AtomicU8 status pattern shared by
/// every SDA module.
pub struct HostIsolationModule {
    status: Arc<AtomicU8>,
}

impl Default for HostIsolationModule {
    fn default() -> Self {
        Self {
            status: Arc::new(AtomicU8::new(STATUS_INITIALIZED)),
        }
    }
}

impl HostIsolationModule {
    /// Spawn the run loop with the default per-OS PAL implementation
    /// and the [`Phase1Stub`] validation hooks. Suitable for the
    /// agent's main startup path; integration tests use
    /// [`HostIsolationModule::start_with`] to inject mocks.
    pub fn start(
        config: &AgentConfig,
        identity: AgentIdentity,
        bus: EventBus,
        shutdown: ShutdownSignal,
    ) -> (ModuleHandle, HostIsolationSubmitter) {
        let cfg = config.modules.host_isolation.clone();
        let pal: Arc<dyn HostIsolation> = Arc::from(default_host_isolation());
        let hooks: Arc<dyn JobValidationHooks + Send + Sync> = Arc::new(Phase1Stub);
        Self::start_with(cfg, identity, pal, hooks, bus, shutdown)
    }

    /// Spawn the run loop with caller-supplied PAL + validation
    /// hooks. Returns the run-loop handle and a submitter the agent
    /// uses to hand jobs to the module.
    pub fn start_with(
        cfg: HostIsolationConfig,
        identity: AgentIdentity,
        pal: Arc<dyn HostIsolation>,
        hooks: Arc<dyn JobValidationHooks + Send + Sync>,
        bus: EventBus,
        shutdown: ShutdownSignal,
    ) -> (ModuleHandle, HostIsolationSubmitter) {
        let (tx, rx) = mpsc::channel(DEFAULT_JOB_MAILBOX_DEPTH);
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);
        let task = tokio::spawn(async move {
            if let Err(e) = run(
                cfg,
                identity,
                pal,
                hooks,
                bus,
                shutdown,
                rx,
                task_status.clone(),
            )
            .await
            {
                error!(error = %e, "host isolation module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });
        (
            ModuleHandle::new("host_isolation", task),
            HostIsolationSubmitter { tx },
        )
    }
}

impl AgentModule for HostIsolationModule {
    fn name(&self) -> &'static str {
        "host_isolation"
    }

    fn status(&self) -> ModuleStatus {
        match self.status.load(Ordering::Relaxed) {
            STATUS_RUNNING => ModuleStatus::Running,
            STATUS_STOPPED => ModuleStatus::Stopped,
            STATUS_FAILED => ModuleStatus::Failed,
            _ => ModuleStatus::Initialized,
        }
    }

    fn health(&self) -> ModuleHealth {
        match self.status.load(Ordering::Relaxed) {
            STATUS_FAILED => ModuleHealth::Unhealthy,
            _ => ModuleHealth::Healthy,
        }
    }
}

/// Wire-shape of the `EventKind::HostIsolationStateChanged` payload
/// (ARCHITECTURE.md § 8).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostIsolationStateChangedPayload {
    /// True after a successful `IsolateHost`, false after a
    /// successful `UnisolateHost`.
    pub isolated: bool,
    /// Canonical, sorted, deduplicated allow-list as written to the
    /// per-OS firewall (loopback included). Empty when `isolated`
    /// is false.
    pub allowed_ips: Vec<String>,
    /// `isolate_host` or `unisolate_host`.
    pub action: String,
    /// Optional human-readable reason from the originating
    /// `SignedActionJob` args.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `job_id` of the originating `SignedActionJob`. Lets the
    /// control plane chain isolation state changes back to the
    /// approval workflow that authorised them.
    pub job_id: String,
    /// Wallclock observation time (ISO-8601 UTC).
    pub observed_at: String,
    /// Wire-schema version. Bump when fields are added/removed.
    pub schema_version: u16,
}

const PAYLOAD_SCHEMA_VERSION: u16 = 1;

/// Counters used by the agent vitals integration (parity with
/// `ProcessMonitorModule` / `NetworkMonitorModule`).
#[derive(Debug, Default)]
struct HostIsolationVitals {
    submitted: AtomicU64,
    isolated: AtomicU64,
    unisolated: AtomicU64,
    refused: AtomicU64,
    pal_errors: AtomicU64,
}

#[allow(clippy::too_many_arguments)]
async fn run(
    cfg: HostIsolationConfig,
    identity: AgentIdentity,
    pal: Arc<dyn HostIsolation>,
    hooks: Arc<dyn JobValidationHooks + Send + Sync>,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    mut rx: mpsc::Receiver<SignedActionJob>,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    info!(
        enabled = cfg.enabled,
        control_plane_cidrs = cfg.control_plane_cidrs.len(),
        always_allow_dns = cfg.always_allow_dns,
        "starting host isolation module"
    );
    status.store(STATUS_RUNNING, Ordering::Relaxed);
    let vitals = Arc::new(HostIsolationVitals::default());
    // Soft cache so we can emit `HostIsolationStateChanged` only on
    // actual transitions; the PAL is still the authoritative source
    // of truth via `is_isolated`.
    let last_state = Arc::new(Mutex::new(pal.is_isolated().unwrap_or(false)));
    let hooks_dyn = DynHooks(hooks);

    // Concurrency invariant: `handle_job` is `.await`-driven inline
    // inside this `select!` loop, and the only `rx.recv()` consumer
    // is right here.  That means at most one job is in flight at any
    // moment: `pal.isolate()`, the `last_state` lock acquisition, and
    // the `emit_state_changed` publish all run serially per-job.
    //
    // Without that serialization the "only on actual transitions"
    // invariant could be violated — two concurrent `IsolateHost`
    // jobs could both invoke `pal.isolate()` before either took the
    // `last_state` mutex, then both observe `*g == false`, and emit
    // two `HostIsolationStateChanged` events for what is logically a
    // single transition.  The mpsc + `tokio::select!` arrangement
    // makes that race unreachable in the current architecture; if a
    // future refactor introduces a worker pool or multiplexes jobs
    // over multiple tasks, the invariant must be re-proved (likely
    // by moving the PAL call inside the `last_state` critical
    // section).
    loop {
        tokio::select! {
            biased;
            _ = shutdown.wait() => {
                info!("host isolation module shutdown received");
                break;
            }
            maybe_job = rx.recv() => {
                let Some(job) = maybe_job else { break; };
                vitals.submitted.fetch_add(1, Ordering::Relaxed);
                handle_job(
                    &cfg,
                    &identity,
                    pal.as_ref(),
                    &hooks_dyn,
                    &bus,
                    &vitals,
                    &last_state,
                    job,
                ).await;
            }
        }
    }
    status.store(STATUS_STOPPED, Ordering::Relaxed);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_job(
    cfg: &HostIsolationConfig,
    identity: &AgentIdentity,
    pal: &dyn HostIsolation,
    hooks: &DynHooks,
    bus: &EventBus,
    vitals: &HostIsolationVitals,
    last_state: &Mutex<bool>,
    job: SignedActionJob,
) {
    // Step 1: run the 10-step validation pipeline.
    let validated = match router::validate(&job, identity, Utc::now(), hooks) {
        Ok(v) => v,
        Err(reason) => {
            warn!(
                action = ?job.action,
                refused = ?reason,
                job_id = %job.job_id,
                "host isolation job refused by validator"
            );
            vitals.refused.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    // Step 2: ignore anything that isn't isolate/unisolate (the
    // validator already routed by `ActionKind`, but this is a
    // defensive double-check so a future ActionKind variant can't
    // silently land in this module).
    if !matches!(
        job.action,
        ActionKind::IsolateHost | ActionKind::UnisolateHost
    ) {
        warn!(
            action = ?job.action,
            job_id = %job.job_id,
            "host isolation received non-isolation action; ignoring",
        );
        return;
    }

    // Step 3: refuse silently if the module is disabled by policy.
    if !cfg.enabled {
        warn!(
            job_id = %job.job_id,
            "host isolation module disabled in config; refusing job"
        );
        vitals.refused.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // Step 4: enforce the `control_plane_cidrs` non-empty invariant
    // documented on `HostIsolationConfig::control_plane_cidrs`
    // (`crates/sda-core/src/config.rs`).  Isolating with only loopback
    // + DNS in the allow-list severs the management channel, leaving
    // the host unable to receive the `UnisolateHost` recovery job
    // (physical-access-only recovery).  We refuse `IsolateHost`
    // silently in that case but **not** `UnisolateHost` — unisolation
    // must always be permitted so an operator who misconfigures the
    // agent can still recover via a signed unisolate.
    if matches!(job.action, ActionKind::IsolateHost) && cfg.control_plane_cidrs.is_empty() {
        warn!(
            job_id = %job.job_id,
            "host isolation refused: control_plane_cidrs is empty; isolating without a \
             control-plane allow-list would sever the management channel"
        );
        vitals.refused.fetch_add(1, Ordering::Relaxed);
        return;
    }

    match validated.args {
        JobArgs::IsolateHost(args) => {
            let extras = match parse_extra_allow_ips(&args.extra_allow_ips) {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, job_id = %job.job_id, "isolate_host extra_allow_ips invalid");
                    vitals.refused.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            let allow = build_allow_ips(cfg, &extras);
            if let Err(e) = pal.isolate(&allow) {
                error!(error = %e, job_id = %job.job_id, "host isolation: PAL isolate failed");
                vitals.pal_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
            vitals.isolated.fetch_add(1, Ordering::Relaxed);
            let mut g = last_state.lock().await;
            let transitioned = !*g;
            *g = true;
            let allow_ips = pal.current_allowed_ips().unwrap_or_else(|_| allow.clone());
            if transitioned {
                emit_state_changed(
                    bus,
                    HostIsolationStateChangedPayload {
                        isolated: true,
                        allowed_ips: allow_ips.iter().map(|n| n.to_string()).collect(),
                        action: "isolate_host".into(),
                        reason: args.reason.clone(),
                        job_id: job.job_id.to_string(),
                        observed_at: Utc::now().to_rfc3339(),
                        schema_version: PAYLOAD_SCHEMA_VERSION,
                    },
                )
                .await;
            }
        }
        JobArgs::UnisolateHost(args) => {
            if let Err(e) = pal.unisolate() {
                error!(error = %e, job_id = %job.job_id, "host isolation: PAL unisolate failed");
                vitals.pal_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
            vitals.unisolated.fetch_add(1, Ordering::Relaxed);
            let mut g = last_state.lock().await;
            let transitioned = *g;
            *g = false;
            if transitioned {
                emit_state_changed(
                    bus,
                    HostIsolationStateChangedPayload {
                        isolated: false,
                        allowed_ips: Vec::new(),
                        action: "unisolate_host".into(),
                        reason: args.reason.clone(),
                        job_id: job.job_id.to_string(),
                        observed_at: Utc::now().to_rfc3339(),
                        schema_version: PAYLOAD_SCHEMA_VERSION,
                    },
                )
                .await;
            }
        }
        other => {
            warn!(
                action = ?other,
                job_id = %job.job_id,
                "host isolation got non-isolation parsed args; dropping",
            );
        }
    }
}

/// Parse the operator-supplied `extra_allow_ips` strings into
/// `ipnet::IpNet`. The signed-job parser already validates these,
/// but parse-again here is cheap and lets [`HostIsolationModule`]
/// be reused outside the device-control router.
fn parse_extra_allow_ips(strings: &[String]) -> Result<Vec<IpNet>, String> {
    let mut out = Vec::with_capacity(strings.len());
    for s in strings {
        out.push(
            s.parse::<IpNet>()
                .map_err(|e| format!("invalid CIDR {s:?}: {e}"))?,
        );
    }
    Ok(out)
}

/// Build the merged allow-list from configuration + the caller's
/// extras. Loopback is appended unconditionally by the PAL
/// (`normalize_allow_ips`); we do not double-add it here.
pub fn build_allow_ips(cfg: &HostIsolationConfig, extras: &[IpNet]) -> Vec<IpNet> {
    let mut out: Vec<IpNet> = extras.to_vec();
    for raw in &cfg.control_plane_cidrs {
        if let Ok(cidr) = raw.parse::<IpNet>() {
            if !out.contains(&cidr) {
                out.push(cidr);
            }
        } else {
            warn!(raw = %raw, "host isolation control_plane_cidrs: invalid CIDR, dropped");
        }
    }
    // Sort + dedup for determinism so consecutive `isolate` calls
    // with the same logical input hash to the same firewall write
    // (and the PAL idempotency check matches).
    out.sort_by_key(|n| n.to_string());
    out.dedup();
    out
}

async fn emit_state_changed(bus: &EventBus, payload: HostIsolationStateChangedPayload) {
    let json = match serde_json::to_string(&payload) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "host isolation: payload serialization failed");
            return;
        }
    };
    let kind = EventKind::HostIsolationStateChanged { payload: json };
    let event = Event::new("host_isolation", Priority::High, kind);
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, "host isolation: server-bound publish failed");
    } else {
        debug!(
            isolated = payload.isolated,
            allowed = payload.allowed_ips.len(),
            action = %payload.action,
            "host isolation state changed published"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use sda_core::config::HostIsolationConfig;
    use sda_core::signal::ShutdownController;
    use sda_event_bus::EventBus;
    use sda_pal::host_isolation::{HostIsolationError, MockHostIsolation};
    use uuid::Uuid;

    fn identity() -> AgentIdentity {
        AgentIdentity {
            tenant_id: Uuid::nil(),
            device_id: Uuid::nil(),
        }
    }

    fn enabled_cfg() -> HostIsolationConfig {
        HostIsolationConfig {
            enabled: true,
            control_plane_cidrs: vec!["10.20.0.0/16".into(), "203.0.113.0/24".into()],
            always_allow_dns: true,
            always_allow_loopback: true,
        }
    }

    /// Accepting hooks that mirror `Phase1Stub` but allow every
    /// action and signature so the tests can exercise the happy
    /// path without setting up a key store.
    struct AcceptHooks;
    impl JobValidationHooks for AcceptHooks {
        fn verify_signature(&self, _job: &SignedActionJob) -> Result<(), JobRefused> {
            Ok(())
        }
        fn action_permitted(&self, _a: ActionKind) -> bool {
            true
        }
        fn in_window(&self, _now: DateTime<Utc>) -> bool {
            true
        }
    }

    fn isolate_job(extras: Vec<String>, reason: Option<String>) -> SignedActionJob {
        SignedActionJob {
            job_id: Uuid::new_v4(),
            tenant_id: Uuid::nil(),
            device_id: Uuid::nil(),
            schema_version: 1,
            recommendation_id: None,
            action: ActionKind::IsolateHost,
            args: serde_json::json!({
                "extra_allow_ips": extras,
                "reason": reason,
            }),
            not_before: Utc::now() - Duration::seconds(30),
            not_after: Utc::now() + Duration::hours(1),
            signature: vec![1, 2, 3, 4],
            key_id: "ctrl-plane:hex".into(),
            correlation_id: None,
            additional_signatures: Vec::new(),
        }
    }

    fn unisolate_job() -> SignedActionJob {
        SignedActionJob {
            job_id: Uuid::new_v4(),
            tenant_id: Uuid::nil(),
            device_id: Uuid::nil(),
            schema_version: 1,
            recommendation_id: None,
            action: ActionKind::UnisolateHost,
            args: serde_json::json!({"reason": "operator"}),
            not_before: Utc::now() - Duration::seconds(30),
            not_after: Utc::now() + Duration::hours(1),
            signature: vec![1, 2, 3, 4],
            key_id: "ctrl-plane:hex".into(),
            correlation_id: None,
            additional_signatures: Vec::new(),
        }
    }

    #[test]
    fn build_allow_ips_includes_control_plane_cidrs() {
        let cfg = enabled_cfg();
        let allow = build_allow_ips(&cfg, &[]);
        let strings: Vec<String> = allow.iter().map(|n| n.to_string()).collect();
        assert!(strings.iter().any(|s| s == "10.20.0.0/16"));
        assert!(strings.iter().any(|s| s == "203.0.113.0/24"));
    }

    #[test]
    fn build_allow_ips_merges_extras_and_dedupes() {
        let cfg = enabled_cfg();
        let extras: Vec<IpNet> = vec![
            "10.20.0.0/16".parse().unwrap(),
            "192.168.1.0/24".parse().unwrap(),
        ];
        let allow = build_allow_ips(&cfg, &extras);
        let count_v4 = allow
            .iter()
            .filter(|n| n.to_string() == "10.20.0.0/16")
            .count();
        assert_eq!(count_v4, 1, "duplicates collapsed");
        assert!(allow.iter().any(|n| n.to_string() == "192.168.1.0/24"));
    }

    #[test]
    fn build_allow_ips_drops_invalid_cidrs_with_warning() {
        let cfg = HostIsolationConfig {
            enabled: true,
            control_plane_cidrs: vec!["not-a-cidr".into(), "10.0.0.0/8".into()],
            always_allow_dns: true,
            always_allow_loopback: true,
        };
        let allow = build_allow_ips(&cfg, &[]);
        let strings: Vec<String> = allow.iter().map(|n| n.to_string()).collect();
        assert!(strings.iter().any(|s| s == "10.0.0.0/8"));
        assert!(!strings.iter().any(|s| s.contains("not-a-cidr")));
    }

    #[test]
    fn parse_extra_allow_ips_rejects_invalid_cidr() {
        let bad: Vec<String> = vec!["totally bogus".into()];
        let err = parse_extra_allow_ips(&bad).expect_err("error");
        assert!(err.contains("invalid CIDR"));
    }

    #[test]
    fn parse_extra_allow_ips_accepts_v4_and_v6() {
        let good: Vec<String> = vec!["10.0.0.0/8".into(), "2001:db8::/32".into()];
        let parsed = parse_extra_allow_ips(&good).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn host_isolation_config_defaults_match_phase_e3_spec() {
        let c = HostIsolationConfig::default();
        assert!(!c.enabled);
        assert!(c.control_plane_cidrs.is_empty());
        assert!(c.always_allow_dns);
        assert!(c.always_allow_loopback);
    }

    #[tokio::test]
    async fn happy_path_isolate_then_unisolate_emits_two_state_changes() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let mut sub = bus.subscribe();
        let pal: Arc<dyn HostIsolation> = Arc::new(MockHostIsolation::new());
        let hooks: Arc<dyn JobValidationHooks + Send + Sync> = Arc::new(AcceptHooks);
        let (controller, signal) = ShutdownController::new();
        let (handle, submitter) = HostIsolationModule::start_with(
            enabled_cfg(),
            identity(),
            pal.clone(),
            hooks,
            bus,
            signal,
        );

        submitter
            .submit(isolate_job(vec![], Some("ir".into())))
            .await
            .unwrap();
        let ev1 = tokio::time::timeout(std::time::Duration::from_secs(2), sub.recv())
            .await
            .expect("isolate state change")
            .unwrap();
        assert!(matches!(
            ev1.kind,
            EventKind::HostIsolationStateChanged { .. }
        ));
        if let EventKind::HostIsolationStateChanged { ref payload } = ev1.kind {
            let p: HostIsolationStateChangedPayload = serde_json::from_str(payload).unwrap();
            assert!(p.isolated);
            assert_eq!(p.action, "isolate_host");
            assert_eq!(p.reason.as_deref(), Some("ir"));
        }

        submitter.submit(unisolate_job()).await.unwrap();
        let ev2 = tokio::time::timeout(std::time::Duration::from_secs(2), sub.recv())
            .await
            .expect("unisolate state change")
            .unwrap();
        if let EventKind::HostIsolationStateChanged { ref payload } = ev2.kind {
            let p: HostIsolationStateChangedPayload = serde_json::from_str(payload).unwrap();
            assert!(!p.isolated);
            assert_eq!(p.action, "unisolate_host");
        }

        controller.shutdown();
        let _ = handle.task.await;
        assert!(!pal.is_isolated().unwrap());
    }

    #[tokio::test]
    async fn duplicate_isolate_does_not_re_emit_state_changed() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let mut sub = bus.subscribe();
        let pal: Arc<dyn HostIsolation> = Arc::new(MockHostIsolation::new());
        let hooks: Arc<dyn JobValidationHooks + Send + Sync> = Arc::new(AcceptHooks);
        let (controller, signal) = ShutdownController::new();
        let (handle, submitter) =
            HostIsolationModule::start_with(enabled_cfg(), identity(), pal, hooks, bus, signal);

        submitter.submit(isolate_job(vec![], None)).await.unwrap();
        // First event observed.
        let _ev = tokio::time::timeout(std::time::Duration::from_secs(2), sub.recv())
            .await
            .expect("first isolate")
            .unwrap();
        submitter.submit(isolate_job(vec![], None)).await.unwrap();
        // No second event in 200 ms because the soft-cache says we
        // are already isolated.
        let res = tokio::time::timeout(std::time::Duration::from_millis(200), sub.recv()).await;
        assert!(res.is_err(), "duplicate isolate did not re-emit");

        controller.shutdown();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn invalid_extra_allow_ips_is_refused_silently() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let mut sub = bus.subscribe();
        let pal: Arc<dyn HostIsolation> = Arc::new(MockHostIsolation::new());
        let hooks: Arc<dyn JobValidationHooks + Send + Sync> = Arc::new(AcceptHooks);
        let (controller, signal) = ShutdownController::new();
        let (handle, submitter) = HostIsolationModule::start_with(
            enabled_cfg(),
            identity(),
            pal.clone(),
            hooks,
            bus,
            signal,
        );
        // Construct a job whose `extra_allow_ips` is invalid; the
        // router will refuse this in step 10 with ArgsParseError.
        let mut j = isolate_job(vec!["not-a-cidr".into()], None);
        j.args = serde_json::json!({"extra_allow_ips": ["not-a-cidr"]});
        submitter.submit(j).await.unwrap();
        let res = tokio::time::timeout(std::time::Duration::from_millis(200), sub.recv()).await;
        assert!(res.is_err(), "no state change emitted on invalid CIDR");
        assert!(!pal.is_isolated().unwrap());
        controller.shutdown();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn disabled_config_refuses_isolation_without_touching_pal() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let mut sub = bus.subscribe();
        let pal: Arc<dyn HostIsolation> = Arc::new(MockHostIsolation::new());
        let hooks: Arc<dyn JobValidationHooks + Send + Sync> = Arc::new(AcceptHooks);
        let (controller, signal) = ShutdownController::new();
        let mut cfg = enabled_cfg();
        cfg.enabled = false;
        let (handle, submitter) =
            HostIsolationModule::start_with(cfg, identity(), pal.clone(), hooks, bus, signal);
        submitter.submit(isolate_job(vec![], None)).await.unwrap();
        let res = tokio::time::timeout(std::time::Duration::from_millis(200), sub.recv()).await;
        assert!(res.is_err(), "disabled module emitted state change");
        assert!(!pal.is_isolated().unwrap());
        controller.shutdown();
        let _ = handle.task.await;
    }

    /// Regression for the Phase E3 review finding: enforcing the
    /// non-empty `control_plane_cidrs` invariant documented on
    /// `HostIsolationConfig::control_plane_cidrs`.  Isolating with
    /// only loopback + DNS in the allow-list severs the management
    /// channel and leaves the host unreachable for the
    /// `UnisolateHost` recovery job, so the module MUST refuse the
    /// `IsolateHost` action silently and never touch the PAL.
    #[tokio::test]
    async fn empty_control_plane_cidrs_refuses_isolation_without_touching_pal() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let mut sub = bus.subscribe();
        let pal: Arc<dyn HostIsolation> = Arc::new(MockHostIsolation::new());
        let hooks: Arc<dyn JobValidationHooks + Send + Sync> = Arc::new(AcceptHooks);
        let (controller, signal) = ShutdownController::new();
        let mut cfg = enabled_cfg();
        cfg.control_plane_cidrs.clear();
        let (handle, submitter) =
            HostIsolationModule::start_with(cfg, identity(), pal.clone(), hooks, bus, signal);
        submitter.submit(isolate_job(vec![], None)).await.unwrap();
        let res = tokio::time::timeout(std::time::Duration::from_millis(200), sub.recv()).await;
        assert!(
            res.is_err(),
            "empty control_plane_cidrs must not produce a state change"
        );
        assert!(
            !pal.is_isolated().unwrap(),
            "empty control_plane_cidrs must not flip the PAL into the isolated state"
        );
        controller.shutdown();
        let _ = handle.task.await;
    }

    /// Companion regression: the empty-`control_plane_cidrs` guard
    /// MUST NOT block `UnisolateHost`.  If an operator misconfigures
    /// the agent (e.g. drops the control-plane CIDRs after a
    /// previous `IsolateHost` already locked the firewall), the
    /// recovery path via a signed unisolate must still drain — else
    /// the box is stuck until physical access.
    #[tokio::test]
    async fn empty_control_plane_cidrs_still_allows_unisolation() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let mut sub = bus.subscribe();
        // Seed the PAL as already isolated so we can observe the
        // unisolate transition produce a `HostIsolationStateChanged`.
        let mock = MockHostIsolation::new();
        mock.isolate(&[]).unwrap();
        let pal: Arc<dyn HostIsolation> = Arc::new(mock);
        let hooks: Arc<dyn JobValidationHooks + Send + Sync> = Arc::new(AcceptHooks);
        let (controller, signal) = ShutdownController::new();
        let mut cfg = enabled_cfg();
        cfg.control_plane_cidrs.clear();
        // Use `start_with` directly + the seeded mock so the run
        // loop's `pal.is_isolated()` reads `true` and the unisolate
        // transition fires.
        let (handle, submitter) =
            HostIsolationModule::start_with(cfg, identity(), pal.clone(), hooks, bus, signal);
        submitter.submit(unisolate_job()).await.unwrap();
        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), sub.recv())
            .await
            .expect("unisolate must drain even when control_plane_cidrs is empty")
            .unwrap();
        assert!(matches!(
            ev.kind,
            EventKind::HostIsolationStateChanged { .. }
        ));
        if let EventKind::HostIsolationStateChanged { ref payload } = ev.kind {
            let p: HostIsolationStateChangedPayload = serde_json::from_str(payload).unwrap();
            assert!(!p.isolated, "unisolate must succeed and clear state");
            assert_eq!(p.action, "unisolate_host");
        }
        controller.shutdown();
        let _ = handle.task.await;
        assert!(
            !pal.is_isolated().unwrap(),
            "PAL must be unisolated after the recovery job"
        );
    }

    #[tokio::test]
    async fn pal_failure_does_not_advance_state_or_emit_event() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let mut sub = bus.subscribe();
        let mock = MockHostIsolation::new();
        mock.fail_next_isolate_with(HostIsolationError::Command("simulated".into()));
        let pal: Arc<dyn HostIsolation> = Arc::new(mock);
        let hooks: Arc<dyn JobValidationHooks + Send + Sync> = Arc::new(AcceptHooks);
        let (controller, signal) = ShutdownController::new();
        let (handle, submitter) = HostIsolationModule::start_with(
            enabled_cfg(),
            identity(),
            pal.clone(),
            hooks,
            bus,
            signal,
        );
        submitter.submit(isolate_job(vec![], None)).await.unwrap();
        let res = tokio::time::timeout(std::time::Duration::from_millis(200), sub.recv()).await;
        assert!(res.is_err(), "PAL failure must not publish state change");
        assert!(!pal.is_isolated().unwrap());
        controller.shutdown();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn unsigned_job_is_refused_by_router_validator() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let mut sub = bus.subscribe();
        let pal: Arc<dyn HostIsolation> = Arc::new(MockHostIsolation::new());
        // Phase1Stub rejects every signature with UnknownKeyId so
        // we can prove the validator runs and the PAL is never
        // touched.
        let hooks: Arc<dyn JobValidationHooks + Send + Sync> = Arc::new(Phase1Stub);
        let (controller, signal) = ShutdownController::new();
        let (handle, submitter) = HostIsolationModule::start_with(
            enabled_cfg(),
            identity(),
            pal.clone(),
            hooks,
            bus,
            signal,
        );
        submitter.submit(isolate_job(vec![], None)).await.unwrap();
        let res = tokio::time::timeout(std::time::Duration::from_millis(200), sub.recv()).await;
        assert!(res.is_err(), "unsigned job emitted state change");
        assert!(!pal.is_isolated().unwrap());
        controller.shutdown();
        let _ = handle.task.await;
    }

    #[test]
    fn host_isolation_payload_round_trips_via_serde() {
        let p = HostIsolationStateChangedPayload {
            isolated: true,
            allowed_ips: vec!["127.0.0.0/8".into(), "10.20.0.0/16".into()],
            action: "isolate_host".into(),
            reason: Some("operator".into()),
            job_id: Uuid::new_v4().to_string(),
            observed_at: Utc::now().to_rfc3339(),
            schema_version: PAYLOAD_SCHEMA_VERSION,
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: HostIsolationStateChangedPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(p, back);
    }
}
