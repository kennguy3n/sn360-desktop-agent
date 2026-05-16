//! Remote-lock sub-module (Phase M2.2).
//!
//! Handles inbound [`sda_device_control::signed_job::SignedActionJob`]s
//! whose [`sda_device_control::types::ActionKind`] is `RemoteLock`.
//! See `docs/desktop-mdm/ARCHITECTURE.md` § 3.2.
//!
//! Flow:
//!
//! 1. Parse the [`sda_device_control::signed_job::RemoteLockArgs`].
//! 2. Call [`MdmProvider::lock`] with the truncated message.
//! 3. Emit [`EventKind::MdmLockResult`] (`Priority::High`).
//!
//! Unlike [`crate::wipe`] there is no evidence-before-action step —
//! `lock` is reversible.

use chrono::{DateTime, Utc};
use sda_device_control::signed_job::RemoteLockArgs;
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use sda_pal::mdm::{MdmError, MdmProvider};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::module::MODULE_SOURCE;

/// Wire payload published on [`EventKind::MdmLockResult`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MdmLockResultPayload {
    pub job_id: Uuid,
    pub status: LockStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Outcome of a [`MdmProvider::lock`] invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockStatus {
    Success,
    Failure,
}

/// Execute one `RemoteLock` job and publish the result.
///
/// Errors from the PAL are not propagated to the caller — they are
/// folded into a `LockStatus::Failure` payload so the audit chain
/// always sees a record.
pub async fn handle(
    job_id: Uuid,
    args: &RemoteLockArgs,
    provider: &dyn MdmProvider,
    bus: &EventBus,
) -> MdmLockResultPayload {
    let started_at = Utc::now();
    let result = provider.lock(&args.message);
    let finished_at = Utc::now();
    let (status, error) = match &result {
        Ok(()) => (LockStatus::Success, None),
        Err(MdmError::Unsupported(reason)) => {
            warn!(reason = %reason, "mdm: lock unsupported on this host");
            (LockStatus::Failure, Some(reason.clone()))
        }
        Err(e) => {
            warn!(error = %e, "mdm: lock failed");
            (LockStatus::Failure, Some(e.to_string()))
        }
    };

    let payload = MdmLockResultPayload {
        job_id,
        status,
        started_at,
        finished_at,
        message: args.message.clone(),
        error,
    };
    publish(bus, &payload).await;
    info!(?status, "mdm: lock result");
    payload
}

async fn publish(bus: &EventBus, payload: &MdmLockResultPayload) {
    let json = match serde_json::to_string(payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "mdm: lock-result serialise failed");
            return;
        }
    };
    let event = Event::new(
        MODULE_SOURCE,
        Priority::High,
        EventKind::MdmLockResult { payload: json },
    );
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, "mdm: lock-result publish_to_server failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_pal::mdm::{
        EncryptionOutcome, OsUpdateOpts, OsUpdateOutcome, RawRecoveryKey, RecoveryKeyType,
        SignedConfigProfile, WipeOpts, WipeOutcome,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    struct MockProvider {
        fail: bool,
        called: Arc<AtomicBool>,
        msg_len: Arc<AtomicUsize>,
    }

    impl MdmProvider for MockProvider {
        fn wipe(&self, _opts: &WipeOpts) -> sda_pal::mdm::Result<WipeOutcome> {
            unreachable!()
        }
        fn lock(&self, message: &str) -> sda_pal::mdm::Result<()> {
            self.called.store(true, Ordering::Relaxed);
            self.msg_len.store(message.len(), Ordering::Relaxed);
            if self.fail {
                Err(MdmError::Command("boom".into()))
            } else {
                Ok(())
            }
        }
        fn escrow_recovery_key(&self) -> sda_pal::mdm::Result<RawRecoveryKey> {
            Ok(RawRecoveryKey {
                key_type: RecoveryKeyType::Luks,
                material: vec![],
            })
        }
        fn install_os_updates(
            &self,
            _opts: &OsUpdateOpts,
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
            unreachable!()
        }
        fn exit_lost_mode(&self) -> sda_pal::mdm::Result<()> {
            unreachable!()
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_success_emits_success_payload() {
        let (bus, _srv) = EventBus::new(8, 8);
        let called = Arc::new(AtomicBool::new(false));
        let msg_len = Arc::new(AtomicUsize::new(0));
        let provider = MockProvider {
            fail: false,
            called: called.clone(),
            msg_len: msg_len.clone(),
        };
        let args = RemoteLockArgs {
            message: "Please return device".into(),
        };
        let payload = handle(Uuid::nil(), &args, &provider, &bus).await;
        assert!(called.load(Ordering::Relaxed));
        assert_eq!(msg_len.load(Ordering::Relaxed), args.message.len());
        assert_eq!(payload.status, LockStatus::Success);
        assert!(payload.error.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_failure_emits_failure_payload() {
        let (bus, _srv) = EventBus::new(8, 8);
        let provider = MockProvider {
            fail: true,
            called: Arc::new(AtomicBool::new(false)),
            msg_len: Arc::new(AtomicUsize::new(0)),
        };
        let args = RemoteLockArgs {
            message: "hello".into(),
        };
        let payload = handle(Uuid::nil(), &args, &provider, &bus).await;
        assert_eq!(payload.status, LockStatus::Failure);
        assert!(payload.error.is_some());
    }

    #[test]
    fn payload_round_trips() {
        let now = Utc::now();
        let p = MdmLockResultPayload {
            job_id: Uuid::nil(),
            status: LockStatus::Success,
            started_at: now,
            finished_at: now,
            message: "Please return device".into(),
            error: None,
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: MdmLockResultPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back, p);
    }
}
