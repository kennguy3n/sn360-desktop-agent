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

use chrono::{DateTime, Utc};
use sda_device_control::signed_job::{EnterLostModeArgs, ExitLostModeArgs};
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use sda_pal::mdm::MdmProvider;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
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

/// Best-effort IP-geolocation report. Phase M2 ships the wire format
/// — the live reporter (`report_location_interval_secs`) populates
/// it on every successful network reconnect.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LastKnownLocation {
    pub lat: f64,
    pub lon: f64,
    /// Estimated accuracy radius in metres.
    pub accuracy_m: f64,
    pub reported_at: DateTime<Utc>,
}

/// Run the enter-lost-mode handler.
pub async fn enter(
    job_id: Uuid,
    args: &EnterLostModeArgs,
    provider: &dyn MdmProvider,
    bus: &EventBus,
) -> MdmLostModeEnteredPayload {
    let entered_at = Utc::now();
    let result = provider.enter_lost_mode(&args.message);
    let (status, error) = match &result {
        Ok(()) => (LostModeStatus::Success, None),
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
pub async fn exit(
    job_id: Uuid,
    _args: &ExitLostModeArgs,
    provider: &dyn MdmProvider,
    bus: &EventBus,
) -> MdmLostModeExitedPayload {
    let exited_at = Utc::now();
    let result = provider.exit_lost_mode();
    let (status, error) = match &result {
        Ok(()) => (LostModeStatus::Success, None),
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
        fn install_os_updates(
            &self,
            _o: &OsUpdateOpts,
        ) -> sda_pal::mdm::Result<OsUpdateOutcome> {
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

    #[tokio::test(flavor = "current_thread")]
    async fn enter_success() {
        let (bus, _) = EventBus::new(8, 8);
        let p = provider();
        let entered = p.entered.clone();
        let args = EnterLostModeArgs {
            message: "Please call".into(),
        };
        let r = enter(Uuid::nil(), &args, &p, &bus).await;
        assert!(entered.load(Ordering::Relaxed));
        assert_eq!(r.status, LostModeStatus::Success);
        assert!(r.error.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exit_success() {
        let (bus, _) = EventBus::new(8, 8);
        let p = provider();
        let exited = p.exited.clone();
        let r = exit(Uuid::nil(), &ExitLostModeArgs {}, &p, &bus).await;
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
        let r = enter(Uuid::nil(), &args, &p, &bus).await;
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
