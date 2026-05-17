//! Top-level [`MdmModule`] — orchestrator for the seven Desktop MDM
//! sub-modules.
//!
//! Per `docs/desktop-mdm/ARCHITECTURE.md` § 6, the agent registers
//! the MDM module at startup-position 10 (immediately after Device
//! Control). On `start()` the module:
//!
//! 1. Spawns the [`auto_remediate`] supervisor against the posture
//!    bus (M1.2).
//! 2. Mounts the [`config_profile`] watcher on the TRDS bundle path
//!    (M3.3).
//! 3. Fires [`recovery_key::escrow_once`] (M1.3) — non-blocking,
//!    will no-op on subsequent boots once the per-boot guard fires.
//! 4. Wires the [`os_patch::tick`] callback into the maintenance
//!    window scheduler (M1.4).
//! 5. Spawns the inbound-job dispatcher task (M2+) that consumes
//!    validated [`SignedActionJob`]s off a [`tokio::sync::mpsc`]
//!    channel and routes them through [`MdmModule::dispatch`].
//!
//! Inbound [`SignedActionJob`]s — the per-incident wipe, lock,
//! lost-mode, and config-profile-push paths — flow through
//! [`MdmModule::dispatch`] after the
//! [`sda_device_control::router`] validation pipeline accepts them.
//!
//! ## Job flow
//!
//! The router does not invoke handlers directly; instead, after the
//! step-12 validation in `sda_device_control::router::validate`,
//! the agent main pushes the accepted job into the MDM module's
//! [`MdmModule::action_sender`] channel. The dispatcher task
//! inside [`MdmModule::start`] reads the channel and calls
//! [`MdmModule::dispatch`].
//!
//! This pattern keeps the validation surface (Device Control) and
//! the side-effecting surface (MDM PAL calls) decoupled, while
//! still making `dispatch` reachable from the runtime — the
//! [`std::sync::Arc<MdmModule>`] returned by [`MdmModule::start`]
//! lives on in agent main alongside the channel sender.

use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use sda_core::config::MdmConfig;
use sda_core::location::LastKnownLocationStore;
use sda_core::module::ModuleHandle;
use sda_core::signal::ShutdownSignal;
use sda_device_control::signed_job::{JobArgs, SignedActionJob};
use sda_device_control::types::ActionKind;
use sda_event_bus::EventBus;
use sda_pal::mdm::MdmProvider;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};
use uuid::Uuid;

use crate::lost_mode::{IpGeolocator, LocationReporterHandle, NoopGeolocator};
use crate::{auto_remediate, config_profile, lock, lost_mode, os_patch, recovery_key, wipe};

/// Source tag used in every [`sda_event_bus::Event`] published from
/// this crate. Matches the `mdm:*` convention used by the comms
/// layer in [`sda_comms::protocol::WazuhMessage::encode_body`].
pub const MODULE_SOURCE: &str = "mdm";

/// Errors raised by [`MdmModule::dispatch`].
#[derive(Debug, Error)]
pub enum MdmModuleError {
    /// The job's `action` is not one this module knows how to
    /// handle. The caller (router) should have filtered this out.
    #[error("unsupported MDM action: {0:?}")]
    UnsupportedAction(ActionKind),
    /// The parsed [`JobArgs`] variant did not match the declared
    /// [`ActionKind`]. This indicates a bug in the upstream
    /// validator.
    #[error("job-args / action-kind mismatch")]
    ArgsMismatch,
    /// Signed-job decode failure.
    #[error("signed job error: {0}")]
    SignedJob(#[from] sda_device_control::signed_job::SignedJobError),
    /// Recovery-key sub-module failure.
    #[error("recovery-key error: {0}")]
    RecoveryKey(#[from] recovery_key::RecoveryKeyError),
    /// Config-profile sub-module failure.
    #[error("config-profile error: {0}")]
    ConfigProfile(#[from] config_profile::ConfigProfileError),
}

/// Identity context shared with the recovery-key escrow sub-module.
/// The agent populates this at enrollment time. The `seed` and
/// `signing_key` never leave the process.
#[derive(Clone)]
pub struct RecoveryEscrowIdentity {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub escrow_seed: Vec<u8>,
    pub signing_key: Arc<SigningKey>,
    pub key_id: String,
}

/// Power state adapter — supervisor wraps the agent's
/// `PowerMonitor` or substitutes a stub in tests.
pub type SharedPowerState = Arc<dyn os_patch::PowerStateProvider>;

/// Bounded queue depth for the inbound-job channel. Keeps memory
/// usage flat under a flood of incoming jobs; the upstream router
/// applies its own back-pressure when this fills up.
const JOB_QUEUE_CAPACITY: usize = 64;

/// Top-level Desktop MDM module.
pub struct MdmModule {
    cfg: MdmConfig,
    provider: Arc<dyn MdmProvider>,
    bus: EventBus,
    /// Pinned signing keys for config-profile verification. The
    /// agent loads these from the same key registry it uses for
    /// `SignedActionJob` validation.
    pinned_profile_keys: Arc<Vec<(String, VerifyingKey)>>,
    /// Auto-remediator (kept on the module so callers can read its
    /// ephemeral key — the router validator needs it to authorise
    /// local-signed posture-fix jobs).
    auto: Arc<auto_remediate::AutoRemediator>,
    /// Recovery-key escrow identity (optional — agents that haven't
    /// enrolled yet can skip escrow until the next boot).
    recovery_identity: Option<RecoveryEscrowIdentity>,
    /// Once-per-boot guard for `recovery_key::escrow_once`.
    recovery_guard: Arc<Mutex<recovery_key::EscrowGuard>>,
    /// Power monitor adapter for `os_patch::tick`.
    power: SharedPowerState,
    /// Shared last-known-location store. The
    /// [`crate::lost_mode::LocationReporterHandle`] writes into this
    /// while the device is in lost mode; the agent-vitals heartbeat
    /// reads from it when assembling the next `AgentVitals` payload.
    location_store: LastKnownLocationStore,
    /// IP-geolocation backend used by the reporter. Tests inject
    /// [`NoopGeolocator`]; production agents inject an HTTP client.
    geolocator: Arc<dyn IpGeolocator>,
    /// Reporter task handle (started by `EnterLostMode`, aborted by
    /// `ExitLostMode` or agent shutdown).
    reporter_handle: Arc<Mutex<LocationReporterHandle>>,
    /// Inbound-job channel sender. Cloned and handed to callers
    /// (the agent main forwards router-accepted MDM jobs into this
    /// channel via [`MdmModule::action_sender`]).
    action_tx: mpsc::Sender<SignedActionJob>,
    /// Inbound-job channel receiver. [`MdmModule::start`] takes the
    /// receiver out of the Mutex and spawns the dispatcher task; on
    /// the rare case `start` is called twice, the second call no-ops
    /// the dispatcher (the receiver has already been moved).
    action_rx: Mutex<Option<mpsc::Receiver<SignedActionJob>>>,
}

impl MdmModule {
    /// Wire the module against the agent's bus, PAL, and config.
    pub fn new(
        cfg: MdmConfig,
        provider: Arc<dyn MdmProvider>,
        bus: EventBus,
        pinned_profile_keys: Vec<(String, VerifyingKey)>,
        power: SharedPowerState,
        recovery_identity: Option<RecoveryEscrowIdentity>,
    ) -> Self {
        Self::with_geolocator(
            cfg,
            provider,
            bus,
            pinned_profile_keys,
            power,
            recovery_identity,
            LastKnownLocationStore::new(),
            Arc::new(NoopGeolocator),
        )
    }

    /// Construct with a caller-owned location store and geolocator
    /// backend. The agent main passes the store down so the
    /// agent-vitals heartbeat can read the same value the reporter
    /// writes.
    #[allow(clippy::too_many_arguments)]
    pub fn with_geolocator(
        cfg: MdmConfig,
        provider: Arc<dyn MdmProvider>,
        bus: EventBus,
        pinned_profile_keys: Vec<(String, VerifyingKey)>,
        power: SharedPowerState,
        recovery_identity: Option<RecoveryEscrowIdentity>,
        location_store: LastKnownLocationStore,
        geolocator: Arc<dyn IpGeolocator>,
    ) -> Self {
        let auto = Arc::new(auto_remediate::AutoRemediator::new(
            cfg.auto_remediate.clone(),
            provider.clone(),
            bus.clone(),
        ));
        let (action_tx, action_rx) = mpsc::channel(JOB_QUEUE_CAPACITY);
        Self {
            cfg,
            provider,
            bus,
            pinned_profile_keys: Arc::new(pinned_profile_keys),
            auto,
            recovery_identity,
            recovery_guard: Arc::new(Mutex::new(recovery_key::EscrowGuard::new())),
            power,
            location_store,
            geolocator,
            reporter_handle: Arc::new(Mutex::new(LocationReporterHandle::new())),
            action_tx,
            action_rx: Mutex::new(Some(action_rx)),
        }
    }

    /// Sender end of the inbound-job channel. The agent main hands
    /// validated MDM-flavour [`SignedActionJob`]s to this sender;
    /// the dispatcher task spawned inside [`MdmModule::start`] reads
    /// the corresponding receiver and routes each job through
    /// [`MdmModule::dispatch`].
    pub fn action_sender(&self) -> mpsc::Sender<SignedActionJob> {
        self.action_tx.clone()
    }

    /// Public handle to the auto-remediator's ephemeral key. The
    /// router validator's local-key allow-list reads from this when
    /// it authorises a posture-fix `SignedActionJob`.
    pub fn ephemeral_key(&self) -> auto_remediate::EphemeralKey {
        self.auto.ephemeral_key()
    }

    /// Spawn every supervisor task and return a [`ModuleHandle`]
    /// the agent lifecycle can wait on for shutdown.
    ///
    /// Takes `self: Arc<Self>` rather than `self` directly so the
    /// agent main keeps a live reference to the module after
    /// `start` returns. That reference is what makes
    /// [`MdmModule::dispatch`] reachable: the inbound-job dispatcher
    /// task spawned here calls `dispatch` on the same Arc, and the
    /// agent main can also call it directly (e.g. from a future
    /// router refactor) without going through the channel.
    pub fn start(self: Arc<Self>, shutdown: ShutdownSignal) -> ModuleHandle {
        let name = "mdm";
        if !self.cfg.enabled {
            info!("mdm: module disabled by config, idle-loop only");
            let task = tokio::spawn(async move {
                let mut s = shutdown;
                s.wait().await;
                Ok(())
            });
            return ModuleHandle::new(name, task);
        }

        let reporter_for_shutdown = self.reporter_handle.clone();
        let auto = self.auto.clone();
        let bus = self.bus.clone();
        let provider = self.provider.clone();
        let pinned_profile_keys = self.pinned_profile_keys.clone();
        let recovery_guard = self.recovery_guard.clone();
        let recovery_identity = self.recovery_identity.clone();
        let recovery_enabled = self.cfg.recovery_key_escrow.enabled;
        let watcher_path = self.cfg.bundle_path.clone();

        // 1. Auto-remediation supervisor.
        let auto_task = auto_remediate::spawn(auto, bus.clone(), shutdown.clone());

        // 2. Config-profile watcher.
        //    NOTE on latency: the watcher polls the underlying
        //    `notify` mpsc with a 500 ms tokio::time::sleep tick, so
        //    a file change may take up to 500 ms to be observed
        //    even though `notify` itself fires within milliseconds.
        //    This is acceptable for the config-profile use case —
        //    the operator-visible bound is "sub-second" — and keeps
        //    the watcher off the tokio reactor's hot path. If the
        //    SLA tightens, switch to `tokio::sync::mpsc` with a
        //    `notify` glue adapter and drop the polling.
        let watcher_task = tokio::spawn(run_config_profile_watcher(
            watcher_path,
            provider.clone(),
            pinned_profile_keys.clone(),
            bus.clone(),
            shutdown.clone(),
        ));

        // 3. One-shot recovery-key escrow (best effort, fires once
        //    per boot; skipped if the agent doesn't have an enrolled
        //    escrow identity yet).
        if recovery_enabled {
            if let Some(identity) = recovery_identity {
                let p = provider.clone();
                let b = bus.clone();
                let g = recovery_guard.clone();
                tokio::spawn(async move {
                    let mut guard = g.lock().await;
                    let id = recovery_key::EscrowIdentity {
                        seed: &identity.escrow_seed,
                        tenant_id: identity.tenant_id,
                        device_id: identity.device_id,
                        signing_key: identity.signing_key.as_ref(),
                        key_id: &identity.key_id,
                    };
                    if let Err(e) = recovery_key::escrow_once(p.as_ref(), &b, &mut guard, &id).await
                    {
                        warn!(error = %e, "mdm: recovery-key escrow_once failed at startup");
                    }
                });
            } else {
                info!("mdm: recovery-key escrow skipped — no enrollment identity");
            }
        }

        // 4. Inbound-job dispatcher. Reads from the per-module
        //    `action_rx` channel and routes each accepted job
        //    through `dispatch`. Without this task, the dispatch
        //    path is unreachable — the agent main's only handle is
        //    the `Arc<MdmModule>` returned by `start`, which it must
        //    hand the sender out of.
        let dispatch_self = self.clone();
        let dispatch_shutdown = shutdown.clone();
        let dispatch_task = tokio::spawn(async move {
            // Take ownership of the receiver. If `start` is somehow
            // called twice, the second call's receiver is `None` —
            // we log + park rather than panic so the supervisor
            // child still drops cleanly on shutdown.
            let mut rx = match dispatch_self.action_rx.lock().await.take() {
                Some(rx) => rx,
                None => {
                    warn!("mdm: action receiver already taken — dispatcher idle");
                    let mut s = dispatch_shutdown;
                    s.wait().await;
                    return;
                }
            };
            let mut s = dispatch_shutdown;
            loop {
                tokio::select! {
                    _ = s.wait() => {
                        info!("mdm: dispatcher shutting down");
                        return;
                    }
                    maybe = rx.recv() => {
                        match maybe {
                            Some(job) => {
                                if let Err(e) = dispatch_self.dispatch(&job).await {
                                    warn!(error = %e, action = ?job.action, "mdm: dispatch failed");
                                }
                            }
                            None => {
                                // All senders dropped; nothing more
                                // is going to arrive. Park on
                                // shutdown so we don't busy-loop.
                                info!("mdm: action channel closed — dispatcher idle");
                                s.wait().await;
                                return;
                            }
                        }
                    }
                }
            }
        });

        // 5. Top-level join task: parks until shutdown, then aborts
        //    supervisor children. The OS-patch tick is owned by
        //    `sda-software`'s maintenance-window scheduler in the
        //    agent main; the supervisor only exposes `tick()` as a
        //    callable.
        let task = tokio::spawn(async move {
            let mut s = shutdown;
            s.wait().await;
            info!("mdm: shutdown signal received");
            auto_task.abort();
            watcher_task.abort();
            dispatch_task.abort();
            // Stop the lost-mode location reporter if it was
            // started by a previous EnterLostMode dispatch.
            reporter_for_shutdown.lock().await.stop();
            Ok(())
        });
        ModuleHandle::new(name, task)
    }

    /// Route an inbound, validated [`SignedActionJob`] to the
    /// matching sub-module.
    ///
    /// The router upstream is responsible for signature and
    /// dual-control enforcement; this function trusts that the job
    /// has cleared the [`sda_device_control::router`] pipeline.
    pub async fn dispatch(&self, job: &SignedActionJob) -> Result<(), MdmModuleError> {
        let args = job.parse_args()?;
        match (job.action, &args) {
            (ActionKind::RemoteWipe, JobArgs::RemoteWipe(a)) => {
                // Pass the supervisor's power state so the wipe
                // handler can honour `wait_for_ac` — if the device
                // is on battery and the job opted into the AC gate,
                // the handler short-circuits with a
                // `DeferredOnBattery` audit envelope rather than
                // touching the PAL.
                let _ = wipe::handle(
                    job,
                    a,
                    self.provider.as_ref(),
                    self.power.as_ref(),
                    &self.bus,
                )
                .await;
            }
            (ActionKind::RemoteLock, JobArgs::RemoteLock(a)) => {
                let _ = lock::handle(job.job_id, a, self.provider.as_ref(), &self.bus).await;
            }
            (ActionKind::EnterLostMode, JobArgs::EnterLostMode(a)) => {
                let _ = lost_mode::enter(
                    job.job_id,
                    a,
                    self.provider.as_ref(),
                    &self.bus,
                    self.reporter_handle.clone(),
                    self.location_store.clone(),
                    self.geolocator.clone(),
                )
                .await;
            }
            (ActionKind::ExitLostMode, JobArgs::ExitLostMode(a)) => {
                let _ = lost_mode::exit(
                    job.job_id,
                    a,
                    self.provider.as_ref(),
                    &self.bus,
                    self.reporter_handle.clone(),
                )
                .await;
            }
            (ActionKind::EscrowRecoveryKey, JobArgs::EscrowRecoveryKey(_)) => {
                if let Some(identity) = &self.recovery_identity {
                    let mut guard = self.recovery_guard.lock().await;
                    let id = recovery_key::EscrowIdentity {
                        seed: &identity.escrow_seed,
                        tenant_id: identity.tenant_id,
                        device_id: identity.device_id,
                        signing_key: identity.signing_key.as_ref(),
                        key_id: &identity.key_id,
                    };
                    recovery_key::escrow_once(self.provider.as_ref(), &self.bus, &mut guard, &id)
                        .await?;
                } else {
                    warn!("mdm: EscrowRecoveryKey job dropped — no enrollment identity");
                }
            }
            (ActionKind::InstallOsUpdate, JobArgs::InstallOsUpdate(a)) => {
                // Operator-initiated `InstallOsUpdate` overrides the
                // local `OsPatchConfig` entirely — the control plane
                // has already decided per-job semantics, so the
                // device's stored auto-install toggles and battery-
                // deferral preference are irrelevant. We translate
                // the wire args directly into `OsUpdateOpts` and
                // call `tick_explicit` (which skips the battery
                // gate; see `os_patch.rs`).
                let opts = sda_pal::mdm::OsUpdateOpts {
                    include_security: a.include_security,
                    include_feature: a.include_feature,
                    reboot_policy: os_patch::reboot_policy_from_wire(a.reboot_policy.as_str()),
                };
                let _ = os_patch::tick_explicit(opts, self.provider.as_ref(), &self.bus).await;
            }
            (ActionKind::ApplyConfigProfile, JobArgs::ApplyConfigProfile(a)) => {
                // Defend against TOCTOU between bundle write and
                // job dispatch: even if the profile signature
                // verifies, the on-disk bytes must match the
                // SHA-256 the control plane committed in the job
                // payload. Otherwise an attacker who can drop a
                // *separately* validly-signed profile (different
                // `profile_id`) into the bundle path between the
                // job being signed and the agent dispatching it
                // could trick the agent into applying the wrong
                // policy. The cross-check turns that into a
                // ConfigProfileTampered finding.
                let path = self.cfg.bundle_path.clone();
                let profile = config_profile::load_and_verify(
                    path.as_path(),
                    self.pinned_profile_keys.as_slice(),
                )?;
                if profile.profile_id() != a.profile_id || profile.sha256 != a.profile_sha256 {
                    warn!(
                        expected_id = %a.profile_id,
                        got_id = %profile.profile_id(),
                        expected_sha = %a.profile_sha256,
                        got_sha = %profile.sha256,
                        "mdm: ApplyConfigProfile job args do not match on-disk profile"
                    );
                    let reason = if profile.profile_id() != a.profile_id {
                        format!(
                            "profile_id mismatch: job=`{}` disk=`{}`",
                            a.profile_id,
                            profile.profile_id()
                        )
                    } else {
                        format!(
                            "profile_sha256 mismatch: job=`{}` disk=`{}`",
                            a.profile_sha256, profile.sha256
                        )
                    };
                    config_profile::publish_tampered(&self.bus, path.as_path(), &reason).await;
                } else {
                    config_profile::apply_and_publish(&profile, self.provider.as_ref(), &self.bus)
                        .await;
                }
            }
            (ActionKind::EnableDiskEncryption, JobArgs::EnableDiskEncryption(_)) => {
                if let Err(e) = self.provider.enable_disk_encryption() {
                    warn!(error = %e, "mdm: EnableDiskEncryption PAL call failed");
                }
            }
            (ActionKind::EnableFirewall, JobArgs::EnableFirewall(_)) => {
                if let Err(e) = self.provider.enable_firewall() {
                    warn!(error = %e, "mdm: EnableFirewall PAL call failed");
                }
            }
            (ActionKind::SetScreenLock, JobArgs::SetScreenLock(a)) => {
                // Thread the control-plane-provided timeout through
                // to the PAL. The router has already enforced the
                // 1..=3600 range (see `signed_job::JobArgs::parse`),
                // so the value is safe to forward without
                // re-validation here.
                if let Err(e) = self.provider.set_screen_lock(a.timeout_secs) {
                    warn!(error = %e, timeout_secs = a.timeout_secs, "mdm: SetScreenLock PAL call failed");
                }
            }
            (kind, _) => return Err(MdmModuleError::UnsupportedAction(kind)),
        }
        Ok(())
    }
}

async fn run_config_profile_watcher(
    path: std::path::PathBuf,
    provider: Arc<dyn MdmProvider>,
    pinned_keys: Arc<Vec<(String, VerifyingKey)>>,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
) {
    use std::time::Duration;

    // Best-effort initial apply if the file already exists.
    if path.exists() {
        match config_profile::load_and_verify(&path, pinned_keys.as_slice()) {
            Ok(profile) => {
                config_profile::apply_and_publish(&profile, provider.as_ref(), &bus).await;
            }
            Err(e) => {
                warn!(error = %e, path = %path.display(), "mdm: initial config-profile load failed");
                config_profile::publish_tampered(&bus, &path, &e.to_string()).await;
            }
        }
    }

    let watcher = match config_profile::Watcher::new(path.clone()) {
        Ok(w) => w,
        Err(e) => {
            warn!(error = %e, "mdm: failed to mount config-profile watcher; disabling");
            shutdown.wait().await;
            return;
        }
    };

    loop {
        tokio::select! {
            _ = shutdown.wait() => {
                info!("mdm: config-profile watcher shutting down");
                return;
            }
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                if let Some(changed) = watcher.poll(Duration::from_millis(0)) {
                    info!(path = %changed.display(), "mdm: config-profile file changed");
                    match config_profile::load_and_verify(&changed, pinned_keys.as_slice()) {
                        Ok(profile) => {
                            config_profile::apply_and_publish(
                                &profile,
                                provider.as_ref(),
                                &bus,
                            )
                            .await;
                        }
                        Err(e) => {
                            warn!(error = %e, "mdm: config-profile verification failed");
                            config_profile::publish_tampered(&bus, &changed, &e.to_string()).await;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_source_is_mdm() {
        assert_eq!(MODULE_SOURCE, "mdm");
    }
}
