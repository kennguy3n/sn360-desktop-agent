//! Remote-wipe sub-module (Phase M2.1).
//!
//! Handles inbound [`sda_device_control::signed_job::SignedActionJob`]s
//! whose [`sda_device_control::types::ActionKind`] is `RemoteWipe`.
//! See `docs/desktop-mdm.md` § 3 (Remote wipe) for the
//! evidence-before-action and dual-control invariants.
//!
//! Dual-control enforcement (`signatures.len() >= 2` from distinct
//! approvers) lives in [`sda_device_control::router::validate`];
//! by the time we are called the router has already accepted the
//! job. The handler still records the dual-sig key IDs on the
//! emitted result for audit purposes.
//!
//! Flow:
//!
//! 1. Emit [`EventKind::MdmWipeResult`] with `status = Started`
//!    BEFORE invoking the irreversible action. This guarantees the
//!    audit chain captures the intent even if the device never
//!    reboots after the wipe.
//! 2. Call [`MdmProvider::wipe`] with `crypto_shred_only` if the
//!    job asks for it.
//! 3. Emit [`EventKind::MdmWipeResult`] with `status = Success | Failure`
//!    and the timing envelope.

use chrono::{DateTime, Utc};
use sda_device_control::signed_job::{RemoteWipeArgs, SignedActionJob};
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use sda_pal::mdm::{MdmProvider, WipeOpts};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::module::MODULE_SOURCE;
use crate::os_patch::PowerStateProvider;

/// Wire payload published on [`EventKind::MdmWipeResult`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MdmWipeResultPayload {
    pub job_id: Uuid,
    pub status: WipeStatus,
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    pub reason: String,
    pub crypto_shred_only: bool,
    /// `key_id` of the first signature on the job (the primary
    /// approver). Recorded so the audit chain captures the dual-
    /// control approval set.
    pub primary_key_id: String,
    /// `key_id`s of all additional approvers attached via
    /// `additional_signatures`.
    pub additional_key_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Phase of a wipe operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WipeStatus {
    Started,
    Success,
    Failure,
    /// The job asked for `wait_for_ac` and the device is currently
    /// on battery. No PAL call was made and the wipe is NOT queued
    /// — the control plane is expected to redrive the job once the
    /// device is back on AC. We emit one envelope (no `Started`
    /// pair) so the audit chain captures the deferral decision.
    DeferredOnBattery,
}

/// Run a `RemoteWipe` job end-to-end.
///
/// `wait_for_ac` and `crypto_shred_only` come from the parsed args.
/// `power` is consulted only when `args.wait_for_ac` is `true` —
/// the handler short-circuits with a `DeferredOnBattery` envelope
/// when the device is currently on battery, so the PAL is never
/// asked to wipe a laptop that might lose power partway through.
/// Returns the *final* payload (the `Started` envelope is published
/// internally before the irreversible PAL call).
pub async fn handle(
    job: &SignedActionJob,
    args: &RemoteWipeArgs,
    provider: &dyn MdmProvider,
    power: &dyn PowerStateProvider,
    bus: &EventBus,
) -> MdmWipeResultPayload {
    let started_at = Utc::now();
    let crypto_shred_only = args.crypto_shred_only;
    let primary_key_id = job.key_id.clone();
    let additional_key_ids: Vec<String> = job
        .additional_signatures
        .iter()
        .map(|s| s.key_id.clone())
        .collect();

    // 0. Wait-for-AC gate. The PAL's per-OS `wipe()` impls honour
    //    `WipeOpts.crypto_shred_only` (skip the factory-reset step
    //    when set — see `sda_pal::mdm::should_perform_factory_reset`)
    //    but NOT `wait_for_ac`: once a platform impl is called the
    //    wipe runs to completion, so the AC deferral has to happen
    //    at this orchestrator layer, before the irreversible PAL
    //    call. We deliberately emit a single envelope (no `Started`
    //    pair) so the audit chain captures one row per deferral
    //    instead of an orphaned `Started`.
    if args.wait_for_ac && power.is_on_battery() {
        let deferred = MdmWipeResultPayload {
            job_id: job.job_id,
            status: WipeStatus::DeferredOnBattery,
            started_at,
            finished_at: Some(Utc::now()),
            reason: args.reason.clone(),
            crypto_shred_only,
            primary_key_id,
            additional_key_ids,
            error: None,
        };
        publish(bus, &deferred).await;
        info!(
            job_id = %job.job_id,
            "mdm: wipe deferred — wait_for_ac requested and device is on battery"
        );
        return deferred;
    }

    // 1. Evidence-before-action: emit Started before the PAL call.
    let started = MdmWipeResultPayload {
        job_id: job.job_id,
        status: WipeStatus::Started,
        started_at,
        finished_at: None,
        reason: args.reason.clone(),
        crypto_shred_only,
        primary_key_id: primary_key_id.clone(),
        additional_key_ids: additional_key_ids.clone(),
        error: None,
    };
    publish(bus, &started).await;
    info!(
        job_id = %job.job_id,
        approvers = additional_key_ids.len() + 1,
        "mdm: wipe started"
    );

    // 2. Invoke the PAL.
    let opts = WipeOpts {
        crypto_shred_only,
        wait_for_ac: args.wait_for_ac,
    };
    let result = provider.wipe(&opts);
    let finished_at = Utc::now();
    let (status, error) = match &result {
        Ok(_) => (WipeStatus::Success, None),
        Err(e) => {
            warn!(error = %e, "mdm: wipe failed");
            (WipeStatus::Failure, Some(e.to_string()))
        }
    };

    let done = MdmWipeResultPayload {
        job_id: job.job_id,
        status,
        started_at,
        finished_at: Some(finished_at),
        reason: args.reason.clone(),
        crypto_shred_only,
        primary_key_id,
        additional_key_ids,
        error,
    };
    publish(bus, &done).await;
    info!(job_id = %job.job_id, ?status, "mdm: wipe finished");
    done
}

async fn publish(bus: &EventBus, payload: &MdmWipeResultPayload) {
    let json = match serde_json::to_string(payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "mdm: wipe-result serialise failed");
            return;
        }
    };
    let event = Event::new(
        MODULE_SOURCE,
        Priority::High,
        EventKind::MdmWipeResult { payload: json },
    );
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, "mdm: wipe-result publish_to_server failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_device_control::signed_job::AdditionalSignature;
    use sda_device_control::types::ActionKind;
    use sda_pal::mdm::{
        EncryptionOutcome, MdmError, OsUpdateOpts, OsUpdateOutcome, RawRecoveryKey,
        RecoveryKeyType, SignedConfigProfile, WipeOutcome,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    struct OnAc;
    impl PowerStateProvider for OnAc {
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

    fn job_with_two_sigs() -> SignedActionJob {
        SignedActionJob {
            schema_version: 1,
            job_id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            device_id: Uuid::nil(),
            correlation_id: Some(Uuid::nil()),
            recommendation_id: None,
            action: ActionKind::RemoteWipe,
            args: serde_json::json!({ "reason": "lost", "crypto_shred_only": false }),
            not_before: Utc::now() - chrono::Duration::minutes(5),
            not_after: Utc::now() + chrono::Duration::minutes(5),
            signature: vec![0u8; 64],
            key_id: "primary-key".into(),
            additional_signatures: vec![AdditionalSignature {
                signature: vec![0u8; 64],
                key_id: "secondary-key".into(),
            }],
        }
    }

    struct MockProvider {
        fail: bool,
        wipes: Arc<AtomicUsize>,
        last_shred_only: Arc<AtomicBool>,
    }

    impl MdmProvider for MockProvider {
        fn wipe(&self, opts: &WipeOpts) -> sda_pal::mdm::Result<WipeOutcome> {
            self.wipes.fetch_add(1, Ordering::Relaxed);
            self.last_shred_only
                .store(opts.crypto_shred_only, Ordering::Relaxed);
            if self.fail {
                Err(MdmError::Command("wipe blocked".into()))
            } else {
                Ok(WipeOutcome {
                    crypto_shred_succeeded: true,
                    factory_reset_invoked: !opts.crypto_shred_only,
                    started_at: Utc::now(),
                })
            }
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
            unreachable!()
        }
        fn exit_lost_mode(&self) -> sda_pal::mdm::Result<()> {
            unreachable!()
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_emits_started_then_success() {
        let (bus, _srv) = EventBus::new(8, 8);
        let mut sub = bus.subscribe();
        let provider = MockProvider {
            fail: false,
            wipes: Arc::new(AtomicUsize::new(0)),
            last_shred_only: Arc::new(AtomicBool::new(false)),
        };
        let job = job_with_two_sigs();
        let args = RemoteWipeArgs {
            reason: "lost".into(),
            crypto_shred_only: false,
            wait_for_ac: false,
        };
        let payload = handle(&job, &args, &provider, &OnAc, &bus).await;
        assert_eq!(payload.status, WipeStatus::Success);
        assert_eq!(payload.additional_key_ids, vec!["secondary-key"]);

        // Drain the local broadcast — must see two events: Started then Success.
        let first = sub.recv().await.unwrap();
        let second = sub.recv().await.unwrap();
        let unpack = |ev: Event| match ev.kind {
            EventKind::MdmWipeResult { payload } => {
                serde_json::from_str::<MdmWipeResultPayload>(&payload).unwrap()
            }
            _ => panic!("expected MdmWipeResult"),
        };
        assert_eq!(unpack(first).status, WipeStatus::Started);
        assert_eq!(unpack(second).status, WipeStatus::Success);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_propagates_crypto_shred_flag() {
        let (bus, _srv) = EventBus::new(8, 8);
        let shred = Arc::new(AtomicBool::new(false));
        let provider = MockProvider {
            fail: false,
            wipes: Arc::new(AtomicUsize::new(0)),
            last_shred_only: shred.clone(),
        };
        let job = job_with_two_sigs();
        let args = RemoteWipeArgs {
            reason: "lost".into(),
            crypto_shred_only: true,
            wait_for_ac: false,
        };
        let _ = handle(&job, &args, &provider, &OnAc, &bus).await;
        assert!(shred.load(Ordering::Relaxed));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_failure_emits_failure_payload() {
        let (bus, _srv) = EventBus::new(8, 8);
        let provider = MockProvider {
            fail: true,
            wipes: Arc::new(AtomicUsize::new(0)),
            last_shred_only: Arc::new(AtomicBool::new(false)),
        };
        let job = job_with_two_sigs();
        let args = RemoteWipeArgs {
            reason: "lost".into(),
            crypto_shred_only: false,
            wait_for_ac: false,
        };
        let payload = handle(&job, &args, &provider, &OnAc, &bus).await;
        assert_eq!(payload.status, WipeStatus::Failure);
        assert!(payload.error.is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_defers_when_wait_for_ac_and_on_battery() {
        // Regression test for the wait_for_ac bug Devin Review
        // flagged as #15: per-OS PAL `wipe()` impls ignored
        // `WipeOpts.wait_for_ac`. The handler now short-circuits
        // at this layer.
        let (bus, _srv) = EventBus::new(8, 8);
        let wipes = Arc::new(AtomicUsize::new(0));
        let provider = MockProvider {
            fail: false,
            wipes: wipes.clone(),
            last_shred_only: Arc::new(AtomicBool::new(false)),
        };
        let job = job_with_two_sigs();
        let args = RemoteWipeArgs {
            reason: "lost".into(),
            crypto_shred_only: false,
            wait_for_ac: true,
        };
        let payload = handle(&job, &args, &provider, &OnBattery, &bus).await;
        assert_eq!(payload.status, WipeStatus::DeferredOnBattery);
        assert!(payload.finished_at.is_some());
        assert!(payload.error.is_none());
        assert_eq!(
            wipes.load(Ordering::Relaxed),
            0,
            "PAL wipe must not be called when deferring on battery"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_proceeds_when_wait_for_ac_but_on_ac() {
        let (bus, _srv) = EventBus::new(8, 8);
        let wipes = Arc::new(AtomicUsize::new(0));
        let provider = MockProvider {
            fail: false,
            wipes: wipes.clone(),
            last_shred_only: Arc::new(AtomicBool::new(false)),
        };
        let job = job_with_two_sigs();
        let args = RemoteWipeArgs {
            reason: "lost".into(),
            crypto_shred_only: false,
            wait_for_ac: true,
        };
        let payload = handle(&job, &args, &provider, &OnAc, &bus).await;
        assert_eq!(payload.status, WipeStatus::Success);
        assert_eq!(wipes.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_proceeds_when_on_battery_but_wait_for_ac_false() {
        // Without `wait_for_ac`, the handler must call the PAL
        // regardless of power state.
        let (bus, _srv) = EventBus::new(8, 8);
        let wipes = Arc::new(AtomicUsize::new(0));
        let provider = MockProvider {
            fail: false,
            wipes: wipes.clone(),
            last_shred_only: Arc::new(AtomicBool::new(false)),
        };
        let job = job_with_two_sigs();
        let args = RemoteWipeArgs {
            reason: "lost".into(),
            crypto_shred_only: false,
            wait_for_ac: false,
        };
        let payload = handle(&job, &args, &provider, &OnBattery, &bus).await;
        assert_eq!(payload.status, WipeStatus::Success);
        assert_eq!(wipes.load(Ordering::Relaxed), 1);
    }
}
