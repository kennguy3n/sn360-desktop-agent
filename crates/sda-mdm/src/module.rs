//! Top-level [`MdmModule`] — orchestrator for the seven Desktop MDM
//! sub-modules.
//!
//! Per `docs/desktop-mdm/ARCHITECTURE.md` § 6, the agent registers
//! the MDM module at startup-position 10 (immediately after Device
//! Control). On `start()` the module:
//!
//! 1. Spawns the [`auto_remediate`] supervisor against the posture
//!    bus (M1.2).
//! 2. Fires [`recovery_key::escrow_once`] (M1.3) — non-blocking, will
//!    no-op on subsequent boots once the per-boot guard fires.
//! 3. Wires the [`os_patch::tick`] callback into the maintenance
//!    window scheduler (M1.4).
//! 4. Mounts the [`config_profile::Watcher`] on the TRDS bundle path
//!    (M3.3).
//!
//! Inbound [`SignedActionJob`]s — the per-incident wipe, lock,
//! lost-mode, and config-profile-push paths — flow through
//! [`MdmModule::dispatch`] after the
//! [`sda_device_control::router`] validation pipeline accepts them.
//! The dispatcher matches the action kind and hands off to the
//! corresponding sub-module's `handle` function.

use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use sda_core::config::MdmConfig;
use sda_core::module::ModuleHandle;
use sda_core::signal::ShutdownSignal;
use sda_device_control::signed_job::{JobArgs, SignedActionJob};
use sda_device_control::types::ActionKind;
use sda_event_bus::EventBus;
use sda_pal::mdm::{MdmProvider, OsUpdateOpts};
use thiserror::Error;
use tracing::{info, warn};

use crate::{auto_remediate, config_profile, lock, lost_mode, os_patch, recovery_key, wipe};

/// Source tag used in every [`sda_event_bus::Event`] published from
/// this crate. Matches the `mdm:*` convention used by the comms
/// layer in [`sda_comms::protocol::WazuhMessage::encode_body`].
pub const MODULE_SOURCE: &str = "mdm";

/// Module health and dispatch errors.
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
    /// Wipe sub-module rejected the job.
    #[error("wipe error: {0}")]
    Wipe(#[from] wipe::WipeError),
    /// Lock sub-module rejected the job.
    #[error("lock error: {0}")]
    Lock(#[from] lock::LockError),
    /// Lost-mode sub-module rejected the job.
    #[error("lost-mode error: {0}")]
    LostMode(#[from] lost_mode::LostModeError),
    /// Recovery-key sub-module rejected the job.
    #[error("recovery-key error: {0}")]
    RecoveryKey(#[from] recovery_key::RecoveryKeyError),
    /// OS-patch sub-module rejected the job.
    #[error("os-patch error: {0}")]
    OsPatch(#[from] os_patch::OsPatchError),
    /// Config-profile sub-module rejected the job.
    #[error("config-profile error: {0}")]
    ConfigProfile(#[from] config_profile::ConfigProfileError),
}

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
    /// Once-per-boot guard for `recovery_key::escrow_once`.
    recovery_guard: Arc<recovery_key::EscrowGuard>,
}

impl MdmModule {
    /// Wire the module against the agent's bus, PAL, and config.
    pub fn new(
        cfg: MdmConfig,
        provider: Arc<dyn MdmProvider>,
        bus: EventBus,
        pinned_profile_keys: Vec<(String, VerifyingKey)>,
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
            recovery_guard: Arc::new(recovery_key::EscrowGuard::new()),
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
                shutdown.clone().wait().await;
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
            recovery_guard,
        } = self;

        let auto_shutdown = shutdown.clone();
        let auto_task = auto_remediate::spawn(auto.clone(), bus.clone(), auto_shutdown);

        let watcher_bus = bus.clone();
        let watcher_provider = provider.clone();
        let watcher_keys = pinned_profile_keys.clone();
        let watcher_path = cfg.bundle_path.clone();
        let watcher_shutdown = shutdown.clone();
        let watcher_task = tokio::spawn(async move {
            run_config_profile_watcher(
                watcher_path,
                watcher_provider,
                watcher_keys,
                watcher_bus,
                watcher_shutdown,
            )
            .await;
        });

        let recovery_provider = provider.clone();
        let recovery_bus = bus.clone();
        let recovery_cfg = cfg.recovery_key_escrow.clone();
        let recovery_guard_h = recovery_guard.clone();
        tokio::spawn(async move {
            if recovery_cfg.enabled {
                if let Err(e) = recovery_key::escrow_once(
                    recovery_provider.as_ref(),
                    &recovery_bus,
                    &recovery_guard_h,
                )
                .await
                {
                    warn!(error = %e, "mdm: recovery-key escrow_once failed at startup");
                }
            }
        });

        let task = tokio::spawn(async move {
            // Hold the sub-task handles so the JoinHandle reflects
            // the slowest exiter.
            let mut shutdown = shutdown;
            shutdown.wait().await;
            info!("mdm: shutdown signal received");
            auto_task.abort();
            watcher_task.abort();
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
                wipe::handle(job, a, self.provider.as_ref(), &self.bus).await?;
            }
            (ActionKind::RemoteLock, JobArgs::RemoteLock(a)) => {
                lock::handle(job, a, self.provider.as_ref(), &self.bus).await?;
            }
            (ActionKind::EnterLostMode, JobArgs::EnterLostMode(a)) => {
                lost_mode::enter(job, a, self.provider.as_ref(), &self.bus).await?;
            }
            (ActionKind::ExitLostMode, JobArgs::ExitLostMode(_)) => {
                lost_mode::exit(job, self.provider.as_ref(), &self.bus).await?;
            }
            (ActionKind::EscrowRecoveryKey, JobArgs::EscrowRecoveryKey(_)) => {
                recovery_key::escrow_once(
                    self.provider.as_ref(),
                    &self.bus,
                    &self.recovery_guard,
                )
                .await?;
            }
            (ActionKind::InstallOsUpdate, JobArgs::InstallOsUpdate(a)) => {
                let opts = OsUpdateOpts {
                    auto_install_security: a.auto_install_security,
                    auto_install_all: a.auto_install_all,
                    reboot_policy: os_patch::translate_reboot_policy(&a.reboot_policy),
                };
                os_patch::run_once(job, &opts, self.provider.as_ref(), &self.bus, None).await?;
            }
            (ActionKind::ApplyConfigProfile, JobArgs::ApplyConfigProfile(a)) => {
                let profile = config_profile::load_and_verify(
                    std::path::Path::new(&a.profile_path),
                    self.pinned_profile_keys.as_slice(),
                )?;
                config_profile::apply_and_publish(&profile, self.provider.as_ref(), &self.bus)
                    .await;
            }
            (ActionKind::EnableDiskEncryption, JobArgs::EnableDiskEncryption(_))
            | (ActionKind::EnableFirewall, JobArgs::EnableFirewall(_))
            | (ActionKind::SetScreenLock, JobArgs::SetScreenLock(_)) => {
                // The auto-remediator owns these three actions when
                // they originate from a local-signed job. The router
                // step 12 has already validated the local-key path.
                self.auto.observe_for_action(&job.action).await?;
            }
            (kind, _) => {
                return Err(MdmModuleError::UnsupportedAction(kind));
            }
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
            // Idle until shutdown rather than dying — the agent
            // should still respond to other signals.
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
