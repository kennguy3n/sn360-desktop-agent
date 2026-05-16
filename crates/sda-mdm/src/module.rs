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
//!
//! Inbound [`SignedActionJob`]s — the per-incident wipe, lock,
//! lost-mode, and config-profile-push paths — flow through
//! [`MdmModule::dispatch`] after the
//! [`sda_device_control::router`] validation pipeline accepts them.

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
use tokio::sync::Mutex;
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
        }
    }

    /// Public handle to the auto-remediator's ephemeral key. The
    /// router validator's local-key allow-list reads from this when
    /// it authorises a posture-fix `SignedActionJob`.
    pub fn ephemeral_key(&self) -> auto_remediate::EphemeralKey {
        self.auto.ephemeral_key()
    }

    /// Spawn every supervisor task and return a [`ModuleHandle`]
    /// the agent lifecycle can wait on for shutdown.
    pub fn start(self, shutdown: ShutdownSignal) -> ModuleHandle {
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

        let MdmModule {
            cfg,
            provider,
            bus,
            pinned_profile_keys,
            auto,
            recovery_identity,
            recovery_guard,
            power: _power,
            location_store: _,
            geolocator: _,
            reporter_handle,
        } = self;
        // Capture the reporter so the shutdown task can stop it.
        let reporter_for_shutdown = reporter_handle.clone();

        // 1. Auto-remediation supervisor.
        let auto_task = auto_remediate::spawn(auto.clone(), bus.clone(), shutdown.clone());

        // 2. Config-profile watcher.
        let watcher_path = cfg.bundle_path.clone();
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
        if cfg.recovery_key_escrow.enabled {
            if let Some(identity) = recovery_identity {
                let p = provider.clone();
                let b = bus.clone();
                let g = recovery_guard.clone();
                tokio::spawn(async move {
                    let mut guard = g.lock().await;
                    if let Err(e) = recovery_key::escrow_once(
                        p.as_ref(),
                        &b,
                        &mut guard,
                        &identity.escrow_seed,
                        identity.tenant_id,
                        identity.device_id,
                        identity.signing_key.as_ref(),
                        &identity.key_id,
                    )
                    .await
                    {
                        warn!(error = %e, "mdm: recovery-key escrow_once failed at startup");
                    }
                });
            } else {
                info!("mdm: recovery-key escrow skipped — no enrollment identity");
            }
        }

        // 4. Top-level join task: parks until shutdown, then aborts
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
                let _ = wipe::handle(job, a, self.provider.as_ref(), &self.bus).await;
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
                    recovery_key::escrow_once(
                        self.provider.as_ref(),
                        &self.bus,
                        &mut guard,
                        &identity.escrow_seed,
                        identity.tenant_id,
                        identity.device_id,
                        identity.signing_key.as_ref(),
                        &identity.key_id,
                    )
                    .await?;
                } else {
                    warn!("mdm: EscrowRecoveryKey job dropped — no enrollment identity");
                }
            }
            (ActionKind::InstallOsUpdate, JobArgs::InstallOsUpdate(_)) => {
                let _ = os_patch::tick(
                    &self.cfg.os_patch,
                    self.provider.as_ref(),
                    self.power.as_ref(),
                    &self.bus,
                )
                .await;
            }
            (ActionKind::ApplyConfigProfile, JobArgs::ApplyConfigProfile(_)) => {
                let path = self.cfg.bundle_path.clone();
                let profile = config_profile::load_and_verify(
                    path.as_path(),
                    self.pinned_profile_keys.as_slice(),
                )?;
                config_profile::apply_and_publish(&profile, self.provider.as_ref(), &self.bus)
                    .await;
            }
            (ActionKind::EnableDiskEncryption, JobArgs::EnableDiskEncryption(_))
            | (ActionKind::EnableFirewall, JobArgs::EnableFirewall(_))
            | (ActionKind::SetScreenLock, JobArgs::SetScreenLock(_)) => {
                // The auto-remediator is normally the source of
                // these three actions; when a control-plane job
                // requests them directly we fall back to a single
                // synchronous PAL call here.
                run_local_action(&job.action, self.provider.as_ref()).await;
            }
            (kind, _) => return Err(MdmModuleError::UnsupportedAction(kind)),
        }
        Ok(())
    }
}

async fn run_local_action(action: &ActionKind, provider: &dyn MdmProvider) {
    let result = match action {
        ActionKind::EnableDiskEncryption => provider.enable_disk_encryption().map(|_| ()),
        ActionKind::EnableFirewall => provider.enable_firewall(),
        ActionKind::SetScreenLock => provider.set_screen_lock(600),
        _ => return,
    };
    if let Err(e) = result {
        warn!(error = %e, ?action, "mdm: local-action PAL call failed");
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
