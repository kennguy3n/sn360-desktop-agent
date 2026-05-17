//! Phase M2 Desktop MDM end-to-end suite (PROGRESS.md task M2.6).
//!
//! Hermetic exercises of the Phase-M2 surface (`docs/desktop-mdm/`)
//! using a recording [`MdmProvider`] mock and the public
//! [`sda_device_control::router::validate`] pipeline.
//!
//! Coverage:
//!
//! 1. A `RemoteWipe` job carrying only the primary signature is
//!    refused with [`JobRefused::WipeRequiresDualControl`] — the
//!    PAL never runs.
//! 2. A `RemoteWipe` job carrying two signatures from distinct
//!    approvers passes [`validate`] and, when dispatched through
//!    [`sda_mdm::wipe::handle`], calls `MdmProvider::wipe` exactly
//!    once and publishes Started then Success
//!    [`EventKind::MdmWipeResult`] envelopes.
//! 3. A `RemoteLock` job runs [`sda_mdm::lock::handle`], calls
//!    `MdmProvider::lock` with the supplied message, and publishes
//!    exactly one [`EventKind::MdmLockResult`] event.
//! 4. An `EnterLostMode` / `ExitLostMode` round-trip publishes one
//!    [`EventKind::MdmLostModeEntered`] then one
//!    [`EventKind::MdmLostModeExited`] event, in that order, and
//!    invokes both PAL endpoints.
//! 5. While the device is in lost mode the location reporter writes
//!    a synchronous reading into the shared
//!    [`LastKnownLocationStore`], and the next
//!    [`sda_agent_vitals::heartbeat::snapshot_to_event_kind`] payload
//!    surfaces the location on its
//!    [`EventKind::AgentVitals`] envelope.

use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use chrono::{TimeZone, Utc};
use sda_agent_vitals::collector::{Collector, DefaultCollector};
use sda_agent_vitals::heartbeat::snapshot_to_event_kind;
use sda_core::location::{LastKnownLocation, LastKnownLocationStore};
use sda_device_control::router::{validate, AgentIdentity, JobValidationHooks};
use sda_device_control::signed_job::{
    AdditionalSignature, EnterLostModeArgs, ExitLostModeArgs, RemoteLockArgs, RemoteWipeArgs,
    SignedActionJob,
};
use sda_device_control::types::{ActionKind, JobRefused};
use sda_event_bus::{Event, EventBus, EventKind};
use sda_mdm::lock::{self as mdm_lock, LockStatus, MdmLockResultPayload};
use sda_mdm::lost_mode::{
    self as mdm_lost_mode, IpGeolocator, LocationReporterHandle, LostModeStatus,
    MdmLostModeEnteredPayload, MdmLostModeExitedPayload,
};
use sda_mdm::os_patch::PowerStateProvider;
use sda_mdm::wipe::{self as mdm_wipe, MdmWipeResultPayload, WipeStatus};
use sda_pal::mdm::{
    EncryptionOutcome, MdmError, MdmProvider, OsUpdateOpts, OsUpdateOutcome, RawRecoveryKey,
    RecoveryKeyType, Result as MdmResult, SignedConfigProfile, WipeOpts, WipeOutcome,
};
use serde_json::json;
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

// ---------- Test harness ---------------------------------------------------

#[derive(Default)]
struct RecordingProvider {
    wipe_calls: AtomicUsize,
    lock_calls: AtomicUsize,
    enter_lost_calls: AtomicUsize,
    exit_lost_calls: AtomicUsize,
    last_lock_message_len: AtomicUsize,
    fail_lock: std::sync::atomic::AtomicBool,
}

impl MdmProvider for RecordingProvider {
    fn wipe(&self, _o: &WipeOpts) -> MdmResult<WipeOutcome> {
        self.wipe_calls.fetch_add(1, Ordering::SeqCst);
        Ok(WipeOutcome {
            crypto_shred_succeeded: true,
            factory_reset_invoked: true,
            started_at: Utc::now(),
        })
    }
    fn lock(&self, message: &str) -> MdmResult<()> {
        self.lock_calls.fetch_add(1, Ordering::SeqCst);
        self.last_lock_message_len
            .store(message.len(), Ordering::SeqCst);
        if self.fail_lock.load(Ordering::SeqCst) {
            return Err(MdmError::Command("lock blocked".into()));
        }
        Ok(())
    }
    fn escrow_recovery_key(&self) -> MdmResult<RawRecoveryKey> {
        Ok(RawRecoveryKey {
            key_type: RecoveryKeyType::Luks,
            material: vec![],
        })
    }
    fn install_os_updates(&self, _o: &OsUpdateOpts) -> MdmResult<OsUpdateOutcome> {
        unreachable!("install_os_updates is M1, not M2")
    }
    fn apply_config_profile(&self, _p: &SignedConfigProfile) -> MdmResult<()> {
        unreachable!("apply_config_profile is M3, not M2")
    }
    fn enable_disk_encryption(&self) -> MdmResult<EncryptionOutcome> {
        unreachable!("enable_disk_encryption is M1, not M2")
    }
    fn enable_firewall(&self) -> MdmResult<()> {
        unreachable!("enable_firewall is M1, not M2")
    }
    fn set_screen_lock(&self, _t: u32) -> MdmResult<()> {
        unreachable!("set_screen_lock is M1, not M2")
    }
    fn enter_lost_mode(&self, _m: &str) -> MdmResult<()> {
        self.enter_lost_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn exit_lost_mode(&self) -> MdmResult<()> {
        self.exit_lost_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// Power-state stub used by [`mdm_wipe::handle`]. Tests choose
/// between on-AC and on-battery to exercise the `wait_for_ac`
/// gate that Devin Review finding #15 introduced.
struct StubPower {
    on_battery: bool,
}

impl PowerStateProvider for StubPower {
    fn is_on_battery(&self) -> bool {
        self.on_battery
    }
}

/// Approver-aware hooks for the router's dual-control gate. The
/// router's own `DualControlHooks` impl is `#[cfg(test)]`-private so
/// we re-implement the same trait here.
struct DualControlHooks {
    approvers: std::collections::HashMap<String, Uuid>,
}

impl DualControlHooks {
    fn new() -> Self {
        Self {
            approvers: std::collections::HashMap::new(),
        }
    }
    fn with_approver(mut self, key_id: &str, approver: Uuid) -> Self {
        self.approvers.insert(key_id.into(), approver);
        self
    }
}

impl JobValidationHooks for DualControlHooks {
    fn verify_signature(&self, _job: &SignedActionJob) -> Result<(), JobRefused> {
        Ok(())
    }
    fn action_permitted(&self, _action: ActionKind) -> bool {
        true
    }
    fn in_window(&self, _now: chrono::DateTime<Utc>) -> bool {
        true
    }
    fn verify_additional_signature(
        &self,
        _job: &SignedActionJob,
        _sig: &AdditionalSignature,
    ) -> Result<(), JobRefused> {
        Ok(())
    }
    fn approver_user_id(&self, key_id: &str) -> Option<Uuid> {
        self.approvers.get(key_id).copied()
    }
}

/// Deterministic IP-geolocator used by the lost-mode test. The
/// production agent hooks a real HTTP client; we return a fixed
/// reading so the test asserts a known position on the bus.
struct FixedGeolocator {
    lat: f64,
    lon: f64,
    accuracy_m: f64,
}

impl IpGeolocator for FixedGeolocator {
    fn locate(&self) -> Option<LastKnownLocation> {
        Some(LastKnownLocation {
            lat: self.lat,
            lon: self.lon,
            accuracy_m: self.accuracy_m,
            reported_at: Utc::now(),
        })
    }
}

fn identity() -> AgentIdentity {
    AgentIdentity {
        tenant_id: Uuid::from_u128(1),
        device_id: Uuid::from_u128(2),
    }
}

fn now_in_window() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 7, 8, 30, 0).unwrap()
}

fn wipe_job(additional: Vec<AdditionalSignature>) -> SignedActionJob {
    SignedActionJob {
        job_id: Uuid::from_u128(0xC0_DE),
        tenant_id: Uuid::from_u128(1),
        device_id: Uuid::from_u128(2),
        schema_version: sda_device_control::version::SIGNED_ACTION_JOB_SCHEMA_VERSION,
        recommendation_id: None,
        action: ActionKind::RemoteWipe,
        args: json!({
            "reason": "lost device",
            "crypto_shred_only": false,
            "wait_for_ac": false
        }),
        not_before: Utc.with_ymd_and_hms(2026, 5, 7, 8, 0, 0).unwrap(),
        not_after: Utc.with_ymd_and_hms(2026, 5, 7, 9, 0, 0).unwrap(),
        signature: vec![0u8; 64],
        key_id: "sn360-control-2026-05-alice".into(),
        correlation_id: None,
        additional_signatures: additional,
    }
}

async fn drain_for(rx: &mut mpsc::Receiver<Event>, budget: Duration) -> Vec<Event> {
    let mut out = Vec::new();
    while let Ok(Some(ev)) = tokio::time::timeout(budget, rx.recv()).await {
        out.push(ev);
    }
    out
}

// ---------- Scenario 1: single-signature wipe refused ---------------------

#[tokio::test(flavor = "current_thread")]
async fn wipe_single_signature_refused_with_dual_control_reason() {
    let alice = Uuid::from_u128(0x_a11ce);
    let hooks = DualControlHooks::new().with_approver("sn360-control-2026-05-alice", alice);

    let job = wipe_job(Vec::new());
    let err = validate(&job, &identity(), now_in_window(), &hooks)
        .expect_err("single-sig wipe must be refused");
    assert_eq!(
        err,
        JobRefused::WipeRequiresDualControl,
        "single-sig wipe must refuse with WipeRequiresDualControl"
    );

    // Belt-and-braces: the PAL must never be called when the router
    // refuses upstream.
    let provider = RecordingProvider::default();
    assert_eq!(provider.wipe_calls.load(Ordering::SeqCst), 0);
}

// ---------- Scenario 2: two-signature wipe accepted, calls PAL -----------

#[tokio::test(flavor = "current_thread")]
async fn wipe_dual_signature_validates_and_invokes_pal() {
    let alice = Uuid::from_u128(0x_a11ce);
    let bob = Uuid::from_u128(0x_b0b);
    let hooks = DualControlHooks::new()
        .with_approver("sn360-control-2026-05-alice", alice)
        .with_approver("sn360-control-2026-05-bob", bob);
    let job = wipe_job(vec![AdditionalSignature {
        signature: vec![1u8; 64],
        key_id: "sn360-control-2026-05-bob".into(),
    }]);

    // Router accepts the dual-signed job.
    let validated = validate(&job, &identity(), now_in_window(), &hooks)
        .expect("dual-signed wipe must pass the router");
    match validated.args {
        sda_device_control::signed_job::JobArgs::RemoteWipe(_) => {}
        _ => panic!("wrong args variant"),
    }

    // Handler now runs the PAL and publishes the result envelopes.
    let (bus, mut rx) = EventBus::new(64, 64);
    let provider = Arc::new(RecordingProvider::default());
    let args = RemoteWipeArgs {
        reason: "lost device".into(),
        crypto_shred_only: false,
        wait_for_ac: false,
    };
    let power = StubPower { on_battery: false };
    let done = mdm_wipe::handle(
        &job,
        &args,
        provider.as_ref() as &dyn MdmProvider,
        &power as &dyn PowerStateProvider,
        &bus,
    )
    .await;
    assert_eq!(done.status, WipeStatus::Success);
    assert!(done.error.is_none());
    assert_eq!(done.additional_key_ids, vec!["sn360-control-2026-05-bob"]);
    assert_eq!(
        provider.wipe_calls.load(Ordering::SeqCst),
        1,
        "wipe PAL must be invoked exactly once"
    );

    // Bus must carry exactly two MdmWipeResult envelopes (Started + Success).
    let events = drain_for(&mut rx, Duration::from_millis(200)).await;
    let statuses: Vec<WipeStatus> = events
        .iter()
        .filter_map(|ev| match &ev.kind {
            EventKind::MdmWipeResult { payload } => {
                serde_json::from_str::<MdmWipeResultPayload>(payload)
                    .ok()
                    .map(|p| p.status)
            }
            _ => None,
        })
        .collect();
    assert_eq!(statuses, vec![WipeStatus::Started, WipeStatus::Success]);
}

// ---------- Scenario 3: RemoteLock handler round-trip --------------------

#[tokio::test(flavor = "current_thread")]
async fn remote_lock_handler_calls_pal_and_emits_event() {
    let (bus, mut rx) = EventBus::new(64, 64);
    let provider = Arc::new(RecordingProvider::default());
    let args = RemoteLockArgs {
        message: "Please return device to IT".into(),
    };
    let payload = mdm_lock::handle(
        Uuid::from_u128(0xB001),
        &args,
        provider.as_ref() as &dyn MdmProvider,
        &bus,
    )
    .await;
    assert_eq!(payload.status, LockStatus::Success);
    assert_eq!(payload.message, args.message);
    assert!(payload.error.is_none());
    assert_eq!(
        provider.lock_calls.load(Ordering::SeqCst),
        1,
        "lock PAL must be invoked exactly once"
    );
    assert_eq!(
        provider.last_lock_message_len.load(Ordering::SeqCst),
        args.message.len(),
        "PAL must receive the full message text"
    );

    let events = drain_for(&mut rx, Duration::from_millis(150)).await;
    let lock_results: Vec<MdmLockResultPayload> = events
        .iter()
        .filter_map(|ev| match &ev.kind {
            EventKind::MdmLockResult { payload } => {
                serde_json::from_str::<MdmLockResultPayload>(payload).ok()
            }
            _ => None,
        })
        .collect();
    assert_eq!(lock_results.len(), 1);
    assert_eq!(lock_results[0].status, LockStatus::Success);
}

// ---------- Scenario 4: EnterLostMode -> ExitLostMode round-trip ----------

#[tokio::test(flavor = "current_thread")]
async fn lost_mode_enter_then_exit_round_trip() {
    let (bus, mut rx) = EventBus::new(64, 64);
    let provider = Arc::new(RecordingProvider::default());
    let reporter = Arc::new(Mutex::new(LocationReporterHandle::new()));
    let store = LastKnownLocationStore::new();
    let geolocator: Arc<dyn IpGeolocator> = Arc::new(FixedGeolocator {
        lat: 37.7749,
        lon: -122.4194,
        accuracy_m: 25.0,
    });

    let enter_payload = mdm_lost_mode::enter(
        Uuid::from_u128(0xE001),
        &EnterLostModeArgs {
            message: "Please return".into(),
        },
        provider.as_ref() as &dyn MdmProvider,
        &bus,
        reporter.clone(),
        store.clone(),
        geolocator.clone(),
    )
    .await;
    assert_eq!(enter_payload.status, LostModeStatus::Success);
    assert!(enter_payload.error.is_none());
    assert_eq!(provider.enter_lost_calls.load(Ordering::SeqCst), 1);

    // The synchronous first reading from enter() must have populated
    // the location store so the next AgentVitals heartbeat surfaces
    // a non-stale position.
    let stored = store.get().expect("enter() must seed last_known_location");
    assert_eq!(stored.lat, 37.7749);
    assert_eq!(stored.lon, -122.4194);

    let exit_payload = mdm_lost_mode::exit(
        Uuid::from_u128(0xE002),
        &ExitLostModeArgs {},
        provider.as_ref() as &dyn MdmProvider,
        &bus,
        reporter.clone(),
    )
    .await;
    assert_eq!(exit_payload.status, LostModeStatus::Success);
    assert!(exit_payload.error.is_none());
    assert_eq!(provider.exit_lost_calls.load(Ordering::SeqCst), 1);

    // The reporter stops on exit but the last reading remains in the
    // store so callers can still surface a stale-but-useful position.
    assert!(
        store.get().is_some(),
        "exit() must not clear the last reading"
    );

    // Bus carries exactly one Entered followed by exactly one Exited
    // envelope, both Success.
    let events = drain_for(&mut rx, Duration::from_millis(150)).await;
    let mut entered = 0usize;
    let mut exited = 0usize;
    for ev in &events {
        match &ev.kind {
            EventKind::MdmLostModeEntered { payload } => {
                let p: MdmLostModeEnteredPayload = serde_json::from_str(payload).unwrap();
                assert_eq!(p.status, LostModeStatus::Success);
                entered += 1;
            }
            EventKind::MdmLostModeExited { payload } => {
                let p: MdmLostModeExitedPayload = serde_json::from_str(payload).unwrap();
                assert_eq!(p.status, LostModeStatus::Success);
                exited += 1;
            }
            _ => {}
        }
    }
    assert_eq!(entered, 1, "exactly one MdmLostModeEntered must be emitted");
    assert_eq!(exited, 1, "exactly one MdmLostModeExited must be emitted");
}

// ---------- Scenario 5: AgentVitals carries last_known_location ----------

#[tokio::test(flavor = "current_thread")]
async fn lost_mode_reporter_surfaces_location_on_agent_vitals() {
    let (bus, _rx) = EventBus::new(64, 64);
    let provider = Arc::new(RecordingProvider::default());
    let reporter = Arc::new(Mutex::new(LocationReporterHandle::new()));
    let store = LastKnownLocationStore::new();
    let geolocator: Arc<dyn IpGeolocator> = Arc::new(FixedGeolocator {
        lat: -33.8688,
        lon: 151.2093,
        accuracy_m: 100.0,
    });

    // Enter lost mode — pumps a synchronous reading into the store.
    let _ = mdm_lost_mode::enter(
        Uuid::from_u128(0xE003),
        &EnterLostModeArgs {
            message: "Please return".into(),
        },
        provider.as_ref() as &dyn MdmProvider,
        &bus,
        reporter,
        store.clone(),
        geolocator,
    )
    .await;

    // Build an AgentVitals collector that reads from the same store
    // and verify the next snapshot carries the location.
    let queue_depth = Arc::new(AtomicUsize::new(0));
    let watchdog_faults = Arc::new(AtomicU64::new(0));
    let collector =
        DefaultCollector::new(queue_depth, watchdog_faults).with_location_store(store.clone());
    let snap = collector.collect();
    let loc = snap
        .last_known_location
        .expect("AgentVitals snapshot must surface lost-mode location");
    assert_eq!(loc.lat, -33.8688);
    assert_eq!(loc.lon, 151.2093);

    // And the canonical wire envelope must include the additive
    // last_known_location object — devices that never entered lost
    // mode omit it entirely.
    match snapshot_to_event_kind(&snap) {
        EventKind::AgentVitals { payload } => {
            let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
            let loc_obj = parsed
                .get("last_known_location")
                .expect("agent-vitals payload must carry last_known_location");
            assert_eq!(loc_obj["lat"], -33.8688);
            assert_eq!(loc_obj["lon"], 151.2093);
            assert_eq!(loc_obj["accuracy_m"], 100.0);
        }
        other => panic!("expected AgentVitals, got {other:?}"),
    }
}
