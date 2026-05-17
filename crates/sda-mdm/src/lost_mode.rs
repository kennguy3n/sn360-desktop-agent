//! Lost-mode sub-module (Phase M2.3).
//!
//! Implements the `EnterLostMode` / `ExitLostMode` handlers per
//! `docs/desktop-mdm/ARCHITECTURE.md` § 3.7.
//!
//! Lost-mode is a soft state: it does not destroy data, it pins the
//! device to a kiosk-style display message and unlocks only via an
//! out-of-band ExitLostMode job. While the state is active, a
//! background reporter task re-publishes the device's last known
//! location (as an additive field on the existing
//! [`sda_event_bus::EventKind::AgentVitals`] heartbeat payload) on
//! every successful network reconnect.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sda_core::location::{LastKnownLocation, LastKnownLocationStore};
use sda_device_control::signed_job::{EnterLostModeArgs, ExitLostModeArgs};
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use sda_pal::mdm::MdmProvider;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::module::MODULE_SOURCE;

/// Payload published on [`EventKind::MdmLostModeEntered`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MdmLostModeEnteredPayload {
    pub job_id: Uuid,
    pub status: LostModeStatus,
    pub message: String,
    pub entered_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Payload published on [`EventKind::MdmLostModeExited`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MdmLostModeExitedPayload {
    pub job_id: Uuid,
    pub status: LostModeStatus,
    pub exited_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LostModeStatus {
    Success,
    Failure,
}

/// Pluggable IP-geolocation surface. The production agent hooks a
/// real HTTP client that queries an IP-geo service; tests inject
/// [`NoopGeolocator`] or a mock.
pub trait IpGeolocator: Send + Sync {
    fn locate(&self) -> Option<LastKnownLocation>;
}

/// Stub geolocator that always returns `None`. Used when no
/// geolocation service is configured.
pub struct NoopGeolocator;
impl IpGeolocator for NoopGeolocator {
    fn locate(&self) -> Option<LastKnownLocation> {
        None
    }
}

/// Default reporter interval while in lost mode: 5 minutes.
const LOCATION_REPORT_INTERVAL: Duration = Duration::from_secs(300);

/// Shared handle for the background location reporter task. The
/// module holds this behind an `Arc<Mutex<…>>` so that `enter()` can
/// start the reporter and `exit()` can cancel it via
/// [`tokio::task::JoinHandle::abort`].
pub struct LocationReporterHandle {
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Default for LocationReporterHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl LocationReporterHandle {
    pub fn new() -> Self {
        Self { task: None }
    }

    /// Spawn the reporter loop. If one is already running it is
    /// aborted first.
    pub fn start(&mut self, store: LastKnownLocationStore, geolocator: Arc<dyn IpGeolocator>) {
        self.stop();
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(LOCATION_REPORT_INTERVAL).await;
                if let Some(loc) = geolocator.locate() {
                    store.set(loc);
                    debug!(lat = loc.lat, lon = loc.lon, "mdm: location updated");
                }
            }
        });
        self.task = Some(task);
    }

    /// Stop the reporter (if running). Called by [`exit`] and on
    /// agent shutdown.
    pub fn stop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

/// Run the enter-lost-mode handler.
///
/// On success the supplied `reporter` is started against the
/// supplied location store + geolocator; the reporter ticks every
/// [`LOCATION_REPORT_INTERVAL`] (5 min by default) and updates the
/// store, which the agent-vitals heartbeat reads when assembling the
/// next `AgentVitals` payload.
pub async fn enter(
    job_id: Uuid,
    args: &EnterLostModeArgs,
    provider: &dyn MdmProvider,
    bus: &EventBus,
    reporter: Arc<Mutex<LocationReporterHandle>>,
    store: LastKnownLocationStore,
    geolocator: Arc<dyn IpGeolocator>,
) -> MdmLostModeEnteredPayload {
    let entered_at = Utc::now();
    let result = provider.enter_lost_mode(&args.message);
    let (status, error) = match &result {
        Ok(()) => {
            // Best-effort: do one synchronous location reading right
            // away so the next AgentVitals heartbeat carries a
            // non-stale position, then start the periodic reporter.
            if let Some(loc) = geolocator.locate() {
                store.set(loc);
            }
            let mut h = reporter.lock().await;
            h.start(store.clone(), geolocator.clone());
            (LostModeStatus::Success, None)
        }
        Err(e) => {
            warn!(error = %e, "mdm: enter_lost_mode failed");
            (LostModeStatus::Failure, Some(e.to_string()))
        }
    };
    let payload = MdmLostModeEnteredPayload {
        job_id,
        status,
        message: args.message.clone(),
        entered_at,
        error,
    };
    publish_entered(bus, &payload).await;
    info!(?status, "mdm: lost-mode entered");
    payload
}

/// Run the exit-lost-mode handler.
///
/// Stops the background location reporter started by [`enter`]. The
/// last reported location remains in the store so callers can still
/// surface it as a stale-but-useful position after exit.
pub async fn exit(
    job_id: Uuid,
    _args: &ExitLostModeArgs,
    provider: &dyn MdmProvider,
    bus: &EventBus,
    reporter: Arc<Mutex<LocationReporterHandle>>,
) -> MdmLostModeExitedPayload {
    let exited_at = Utc::now();
    let result = provider.exit_lost_mode();
    let (status, error) = match &result {
        Ok(()) => {
            let mut h = reporter.lock().await;
            h.stop();
            (LostModeStatus::Success, None)
        }
        Err(e) => {
            warn!(error = %e, "mdm: exit_lost_mode failed");
            (LostModeStatus::Failure, Some(e.to_string()))
        }
    };
    let payload = MdmLostModeExitedPayload {
        job_id,
        status,
        exited_at,
        error,
    };
    publish_exited(bus, &payload).await;
    info!(?status, "mdm: lost-mode exited");
    payload
}

async fn publish_entered(bus: &EventBus, payload: &MdmLostModeEnteredPayload) {
    let json = match serde_json::to_string(payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "mdm: lost-mode-entered serialise failed");
            return;
        }
    };
    let event = Event::new(
        MODULE_SOURCE,
        Priority::High,
        EventKind::MdmLostModeEntered { payload: json },
    );
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, "mdm: lost-mode-entered publish_to_server failed");
    }
}

async fn publish_exited(bus: &EventBus, payload: &MdmLostModeExitedPayload) {
    let json = match serde_json::to_string(payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "mdm: lost-mode-exited serialise failed");
            return;
        }
    };
    let event = Event::new(
        MODULE_SOURCE,
        Priority::High,
        EventKind::MdmLostModeExited { payload: json },
    );
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, "mdm: lost-mode-exited publish_to_server failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_pal::mdm::{
        EncryptionOutcome, MdmError, OsUpdateOpts, OsUpdateOutcome, RawRecoveryKey,
        RecoveryKeyType, SignedConfigProfile, WipeOpts, WipeOutcome,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct MockProvider {
        entered: Arc<AtomicBool>,
        exited: Arc<AtomicBool>,
        fail_enter: bool,
        fail_exit: bool,
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
        fn install_os_updates(&self, _o: &OsUpdateOpts) -> sda_pal::mdm::Result<OsUpdateOutcome> {
            unreachable!()
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
            self.entered.store(true, Ordering::Relaxed);
            if self.fail_enter {
                Err(MdmError::Command("enter blocked".into()))
            } else {
                Ok(())
            }
        }
        fn exit_lost_mode(&self) -> sda_pal::mdm::Result<()> {
            self.exited.store(true, Ordering::Relaxed);
            if self.fail_exit {
                Err(MdmError::Command("exit blocked".into()))
            } else {
                Ok(())
            }
        }
    }

    fn provider() -> MockProvider {
        MockProvider {
            entered: Arc::new(AtomicBool::new(false)),
            exited: Arc::new(AtomicBool::new(false)),
            fail_enter: false,
            fail_exit: false,
        }
    }

    fn reporter() -> Arc<Mutex<LocationReporterHandle>> {
        Arc::new(Mutex::new(LocationReporterHandle::new()))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enter_success() {
        let (bus, _) = EventBus::new(8, 8);
        let p = provider();
        let entered = p.entered.clone();
        let args = EnterLostModeArgs {
            message: "Please call".into(),
        };
        let store = LastKnownLocationStore::new();
        let geo: Arc<dyn IpGeolocator> = Arc::new(NoopGeolocator);
        let r = enter(Uuid::nil(), &args, &p, &bus, reporter(), store, geo).await;
        assert!(entered.load(Ordering::Relaxed));
        assert_eq!(r.status, LostModeStatus::Success);
        assert!(r.error.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exit_success() {
        let (bus, _) = EventBus::new(8, 8);
        let p = provider();
        let exited = p.exited.clone();
        let r = exit(Uuid::nil(), &ExitLostModeArgs {}, &p, &bus, reporter()).await;
        assert!(exited.load(Ordering::Relaxed));
        assert_eq!(r.status, LostModeStatus::Success);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enter_failure_records_error() {
        let (bus, _) = EventBus::new(8, 8);
        let mut p = provider();
        p.fail_enter = true;
        let args = EnterLostModeArgs {
            message: "x".into(),
        };
        let store = LastKnownLocationStore::new();
        let geo: Arc<dyn IpGeolocator> = Arc::new(NoopGeolocator);
        let r = enter(Uuid::nil(), &args, &p, &bus, reporter(), store, geo).await;
        assert_eq!(r.status, LostModeStatus::Failure);
        assert!(r.error.is_some());
    }

    #[test]
    fn last_known_location_round_trips() {
        let loc = LastKnownLocation {
            lat: 37.7749,
            lon: -122.4194,
            accuracy_m: 25.0,
            reported_at: Utc::now(),
        };
        let s = serde_json::to_string(&loc).unwrap();
        let back: LastKnownLocation = serde_json::from_str(&s).unwrap();
        assert_eq!(back.lat, loc.lat);
        assert_eq!(back.lon, loc.lon);
        assert_eq!(back.accuracy_m, loc.accuracy_m);
    }
}
