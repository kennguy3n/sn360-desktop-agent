//! OS-patch orchestration sub-module (Phase M1.4).
//!
//! Implements the maintenance-window driven OS-patch loop per
//! `docs/desktop-mdm.md` § 6 (OS patch orchestration).
//!
//! Phase M1 scope:
//!
//! * [`tick`] is called by the supervisor at the maintenance-window
//!   tick (the same timer driven by `sda-software`). It consults a
//!   [`PowerStateProvider`] and defers when the device is on
//!   battery and `defer_on_battery` is set in config.
//! * On every non-deferred tick we invoke
//!   [`MdmProvider::install_os_updates`] with the [`OsUpdateOpts`]
//!   produced by [`config_to_opts`].
//! * The provider's stdout is hashed with SHA-256 inside the PAL
//!   (already wired in `LinuxMdmProvider::install_os_updates` /
//!   `MacMdmProvider` / `WindowsMdmProvider`); we surface the
//!   resulting [`OsUpdateOutcome`] as
//!   [`EventKind::MdmOsUpdateResult`].

use chrono::{DateTime, Utc};
use sda_core::config::OsPatchConfig;
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use sda_pal::mdm::{MdmProvider, OsUpdateOpts, RebootPolicy};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::module::MODULE_SOURCE;

/// Wire payload published on [`EventKind::MdmOsUpdateResult`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MdmOsUpdateResultPayload {
    pub job_id: Uuid,
    pub status: OsPatchStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub updates_installed: u32,
    pub reboot_required: bool,
    /// Lower-case hex of `OsUpdateOutcome::log_sha256`.
    pub log_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Outcome category for [`MdmOsUpdateResultPayload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsPatchStatus {
    Success,
    /// The tick was deferred because the device was on battery and
    /// `defer_on_battery` was enabled. No PAL call was made.
    DeferredOnBattery,
    Failure,
}

/// Best-effort power state surface. We do NOT hard-depend on
/// [`sda_core::power::PowerMonitor`] here so the sub-module is unit-
/// testable without a tokio runtime; the supervisor adapts the real
/// monitor onto this trait at startup.
pub trait PowerStateProvider: Send + Sync {
    fn is_on_battery(&self) -> bool;
}

/// Adapter that bridges the agent's
/// [`sda_core::power::PowerProfileReceiver`] onto the
/// [`PowerStateProvider`] trait. `is_on_battery` returns `true` for
/// every battery-backed [`sda_core::power::PowerProfile`] variant —
/// `BatteryActive`, `BatteryIdle`, and `CriticalBattery`.
pub struct WatchPowerStateProvider {
    rx: tokio::sync::watch::Receiver<sda_core::power::PowerProfile>,
}

impl WatchPowerStateProvider {
    pub fn new(rx: tokio::sync::watch::Receiver<sda_core::power::PowerProfile>) -> Self {
        Self { rx }
    }
}

impl PowerStateProvider for WatchPowerStateProvider {
    fn is_on_battery(&self) -> bool {
        use sda_core::power::PowerProfile;
        matches!(
            *self.rx.borrow(),
            PowerProfile::BatteryActive | PowerProfile::BatteryIdle | PowerProfile::CriticalBattery
        )
    }
}

/// Translate the user-supplied [`OsPatchConfig`] into the PAL-facing
/// [`OsUpdateOpts`]. Visible for testing.
pub fn config_to_opts(cfg: &OsPatchConfig) -> OsUpdateOpts {
    OsUpdateOpts {
        include_security: cfg.auto_install_security,
        include_feature: cfg.auto_install_all,
        // Reboot policy is decided by the control plane via the
        // `RebootPolicy` field on `InstallOsUpdate` jobs; auto-tick
        // never reboots without an explicit job.
        reboot_policy: RebootPolicy::Never,
    }
}

/// Map the wire-format reboot-policy string carried on
/// `InstallOsUpdateArgs` to the PAL enum.
///
/// Wire values `"never" | "if_required" | "force"` (per
/// `docs/desktop-mdm.md` § 9 and validated by
/// `sda_device_control::signed_job::JobArgs::parse`) translate to:
///
/// * `"never"` → [`RebootPolicy::Never`] — agent surfaces
///   `reboot_required` to the user but never triggers a reboot.
/// * `"if_required"` → [`RebootPolicy::OnIdle`] — only when the
///   underlying PAL report says a reboot is needed AND the user has
///   been idle for a while.
/// * `"force"` → [`RebootPolicy::OnMaintenanceWindow`] — reboot at
///   the next maintenance window without waiting for idle. This is
///   the closest PAL match for "operator wants this to take effect
///   ASAP without surprising the user mid-task".
///
/// Any unrecognised value falls back to `Never` so a future protocol
/// drift cannot cause an unintended reboot. The router has already
/// rejected unknown values upstream, so the fallback is purely
/// defence in depth. Visible for testing.
pub fn reboot_policy_from_wire(s: &str) -> RebootPolicy {
    match s {
        "never" => RebootPolicy::Never,
        "if_required" => RebootPolicy::OnIdle,
        "force" => RebootPolicy::OnMaintenanceWindow,
        _ => RebootPolicy::Never,
    }
}

/// Run one maintenance-window tick.
///
/// Returns the published payload. Errors from the PAL fold into a
/// `Failure` payload so the audit chain always captures a record.
pub async fn tick(
    cfg: &OsPatchConfig,
    provider: &dyn MdmProvider,
    power: &dyn PowerStateProvider,
    bus: &EventBus,
) -> MdmOsUpdateResultPayload {
    let started_at = Utc::now();
    let job_id = Uuid::new_v4();
    if cfg.defer_on_battery && power.is_on_battery() {
        let finished_at = Utc::now();
        let payload = MdmOsUpdateResultPayload {
            job_id,
            status: OsPatchStatus::DeferredOnBattery,
            started_at,
            finished_at,
            updates_installed: 0,
            reboot_required: false,
            log_sha256: hex::encode([0u8; 32]),
            error: None,
        };
        publish(bus, &payload).await;
        info!("mdm: os-patch tick deferred — device on battery");
        return payload;
    }

    let opts = config_to_opts(cfg);
    run_install_and_publish(provider, bus, opts, job_id, started_at).await
}

/// Run an operator-initiated `InstallOsUpdate` job.
///
/// Unlike [`tick`], this entrypoint:
///
/// * Uses the [`OsUpdateOpts`] supplied by the caller (the dispatch
///   path maps `InstallOsUpdateArgs` into them) instead of reading
///   from [`OsPatchConfig`]. The control plane has decided the
///   per-job semantics; the local config is irrelevant.
/// * Skips the `defer_on_battery` check. The control plane has
///   already weighed power state on its side (it issued the job),
///   so the agent honours it immediately even on battery.
///
/// Returns the published payload. PAL errors fold into a `Failure`
/// payload so the audit chain always captures a record.
pub async fn tick_explicit(
    opts: OsUpdateOpts,
    provider: &dyn MdmProvider,
    bus: &EventBus,
) -> MdmOsUpdateResultPayload {
    let started_at = Utc::now();
    let job_id = Uuid::new_v4();
    run_install_and_publish(provider, bus, opts, job_id, started_at).await
}

/// Shared body for [`tick`] and [`tick_explicit`]: call the PAL,
/// fold success/failure into a [`MdmOsUpdateResultPayload`], publish
/// it on the bus, and return it.
async fn run_install_and_publish(
    provider: &dyn MdmProvider,
    bus: &EventBus,
    opts: OsUpdateOpts,
    job_id: Uuid,
    started_at: DateTime<Utc>,
) -> MdmOsUpdateResultPayload {
    let result = provider.install_os_updates(&opts);
    let finished_at = Utc::now();
    let payload = match result {
        Ok(outcome) => {
            info!(
                installed = outcome.updates_installed,
                reboot = outcome.reboot_required,
                "mdm: os-patch tick succeeded"
            );
            MdmOsUpdateResultPayload {
                job_id,
                status: OsPatchStatus::Success,
                started_at,
                finished_at,
                updates_installed: outcome.updates_installed,
                reboot_required: outcome.reboot_required,
                log_sha256: hex::encode(outcome.log_sha256),
                error: None,
            }
        }
        Err(e) => {
            warn!(error = %e, "mdm: os-patch tick failed");
            MdmOsUpdateResultPayload {
                job_id,
                status: OsPatchStatus::Failure,
                started_at,
                finished_at,
                updates_installed: 0,
                reboot_required: false,
                log_sha256: hex::encode([0u8; 32]),
                error: Some(e.to_string()),
            }
        }
    };
    publish(bus, &payload).await;
    payload
}

async fn publish(bus: &EventBus, payload: &MdmOsUpdateResultPayload) {
    let json = match serde_json::to_string(payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "mdm: os-update-result serialise failed");
            return;
        }
    };
    let event = Event::new(
        MODULE_SOURCE,
        Priority::Normal,
        EventKind::MdmOsUpdateResult { payload: json },
    );
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, "mdm: os-update-result publish_to_server failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_pal::mdm::{
        EncryptionOutcome, MdmError, OsUpdateOutcome, RawRecoveryKey, RecoveryKeyType,
        SignedConfigProfile, WipeOpts, WipeOutcome,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    struct AcPower;
    impl PowerStateProvider for AcPower {
        fn is_on_battery(&self) -> bool {
            false
        }
    }
    struct OnBattery;
    impl PowerStateProvider for OnBattery {
        fn is_on_battery(&self) -> bool {
            true
        }
    }

    struct MockProvider {
        ticks: Arc<AtomicUsize>,
        fail: bool,
        last_security: Arc<AtomicBool>,
        last_feature: Arc<AtomicBool>,
    }

    impl MdmProvider for MockProvider {
        fn wipe(&self, _o: &WipeOpts) -> sda_pal::mdm::Result<WipeOutcome> {
            unreachable!()
        }
        fn lock(&self, _m: &str) -> sda_pal::mdm::Result<()> {
            unreachable!()
        }
        fn escrow_recovery_key(&self) -> sda_pal::mdm::Result<RawRecoveryKey> {
            Ok(RawRecoveryKey {
                key_type: RecoveryKeyType::Luks,
                material: vec![],
            })
        }
        fn install_os_updates(&self, opts: &OsUpdateOpts) -> sda_pal::mdm::Result<OsUpdateOutcome> {
            self.ticks.fetch_add(1, Ordering::Relaxed);
            self.last_security
                .store(opts.include_security, Ordering::Relaxed);
            self.last_feature
                .store(opts.include_feature, Ordering::Relaxed);
            if self.fail {
                Err(MdmError::Command("patch backend offline".into()))
            } else {
                Ok(OsUpdateOutcome {
                    updates_installed: 3,
                    reboot_required: true,
                    log_sha256: [0xAB; 32],
                })
            }
        }
        fn apply_config_profile(&self, _p: &SignedConfigProfile) -> sda_pal::mdm::Result<()> {
            unreachable!()
        }
        fn enable_disk_encryption(&self) -> sda_pal::mdm::Result<EncryptionOutcome> {
            unreachable!()
        }
        fn enable_firewall(&self) -> sda_pal::mdm::Result<()> {
            unreachable!()
        }
        fn set_screen_lock(&self, _t: u32) -> sda_pal::mdm::Result<()> {
            unreachable!()
        }
        fn enter_lost_mode(&self, _m: &str) -> sda_pal::mdm::Result<()> {
            unreachable!()
        }
        fn exit_lost_mode(&self) -> sda_pal::mdm::Result<()> {
            unreachable!()
        }
    }

    fn mock_provider(fail: bool) -> MockProvider {
        MockProvider {
            ticks: Arc::new(AtomicUsize::new(0)),
            fail,
            last_security: Arc::new(AtomicBool::new(false)),
            last_feature: Arc::new(AtomicBool::new(false)),
        }
    }

    fn cfg() -> OsPatchConfig {
        OsPatchConfig {
            enabled: true,
            auto_install_security: true,
            auto_install_all: false,
            defer_on_battery: true,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tick_runs_on_ac_power() {
        let (bus, _) = EventBus::new(8, 8);
        let p = mock_provider(false);
        let ticks = p.ticks.clone();
        let r = tick(&cfg(), &p, &AcPower, &bus).await;
        assert_eq!(ticks.load(Ordering::Relaxed), 1);
        assert_eq!(r.status, OsPatchStatus::Success);
        assert_eq!(r.updates_installed, 3);
        assert!(r.reboot_required);
        assert_eq!(r.log_sha256, hex::encode([0xAB; 32]));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tick_defers_on_battery_when_configured() {
        let (bus, _) = EventBus::new(8, 8);
        let p = mock_provider(false);
        let ticks = p.ticks.clone();
        let r = tick(&cfg(), &p, &OnBattery, &bus).await;
        assert_eq!(ticks.load(Ordering::Relaxed), 0);
        assert_eq!(r.status, OsPatchStatus::DeferredOnBattery);
        assert_eq!(r.updates_installed, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tick_runs_on_battery_when_defer_disabled() {
        let (bus, _) = EventBus::new(8, 8);
        let p = mock_provider(false);
        let ticks = p.ticks.clone();
        let mut c = cfg();
        c.defer_on_battery = false;
        let r = tick(&c, &p, &OnBattery, &bus).await;
        assert_eq!(ticks.load(Ordering::Relaxed), 1);
        assert_eq!(r.status, OsPatchStatus::Success);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tick_records_failure() {
        let (bus, _) = EventBus::new(8, 8);
        let p = mock_provider(true);
        let r = tick(&cfg(), &p, &AcPower, &bus).await;
        assert_eq!(r.status, OsPatchStatus::Failure);
        assert!(r.error.is_some());
    }

    #[test]
    fn config_to_opts_security_only() {
        let c = OsPatchConfig {
            enabled: true,
            auto_install_security: true,
            auto_install_all: false,
            defer_on_battery: true,
        };
        let o = config_to_opts(&c);
        assert!(o.include_security);
        assert!(!o.include_feature);
        assert_eq!(o.reboot_policy, RebootPolicy::Never);
    }

    #[test]
    fn config_to_opts_all_updates() {
        let c = OsPatchConfig {
            enabled: true,
            auto_install_security: true,
            auto_install_all: true,
            defer_on_battery: false,
        };
        let o = config_to_opts(&c);
        assert!(o.include_security);
        assert!(o.include_feature);
    }
}
