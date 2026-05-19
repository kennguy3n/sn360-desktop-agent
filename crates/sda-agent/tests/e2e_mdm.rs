//! Desktop MDM end-to-end suite.
//!
//! Hermetic exercises of the Desktop MDM surface (`docs/desktop-mdm/`)
//! using a recording [`MdmProvider`] mock — the same harness pattern
//! used by `e2e_device_control.rs` and `e2e_remote_support.rs`.
//!
//! Coverage:
//!
//! 1. A single `PostureSnapshot` with all three Off toggles drives
//!    the [`auto_remediate`] supervisor to invoke
//!    `enable_disk_encryption` + `enable_firewall` + `set_screen_lock`
//!    exactly once each, publishing three
//!    `MdmAutoRemediationResult` events with status `success`.
//! 2. A second snapshot **within the 24h debounce window** does
//!    NOT re-invoke the PAL — the events carry status `debounced`.
//! 3. A snapshot whose PAL call **fails** publishes a Failure
//!    auto-remediation event so the audit chain captures the
//!    unfixed posture defect.
//! 4. [`recovery_key::escrow_once`] is exactly one-shot per
//!    `EscrowGuard` — the second call returns `Ok(None)` and only
//!    publishes one `MdmRecoveryKeyEscrowed` event.
//! 5. [`os_patch::tick`] running with a battery-backed
//!    `PowerStateProvider` and `defer_on_battery = true` returns
//!    `DeferredOnBattery` and the PAL `install_os_updates` is never
//!    called.
//! 6. [`os_patch::tick`] running with AC-power state calls
//!    `install_os_updates` and publishes a single
//!    `MdmOsUpdateResult` event with status `success`.

use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use sda_core::config::{AutoRemediateConfig, OsPatchConfig};
use sda_event_bus::{Event, EventBus, EventKind};
use sda_mdm::auto_remediate::{AutoRemediator, MdmAutoRemediationResultPayload, RemediateStatus};
use sda_mdm::os_patch::{tick as os_patch_tick, OsPatchStatus, PowerStateProvider};
use sda_mdm::recovery_key::{escrow_once, EscrowGuard, EscrowIdentity};
use sda_pal::mdm::{
    EncryptionOutcome, MdmError, MdmProvider, OsUpdateOpts, OsUpdateOutcome, RawRecoveryKey,
    RecoveryKeyType, Result as MdmResult, SignedConfigProfile, WipeOpts, WipeOutcome,
};
use sda_pal::posture::{PostureSnapshot, PostureToggle};
use tokio::sync::mpsc;
use uuid::Uuid;

// ---------- Test harness ---------------------------------------------------

/// Recording PAL provider used by all M1 scenarios. Tracks how many
/// times each method was called and lets individual tests force
/// `enable_*` to fail.
#[derive(Default)]
struct RecordingProvider {
    encrypt_calls: AtomicUsize,
    firewall_calls: AtomicUsize,
    screenlock_calls: AtomicUsize,
    install_calls: AtomicUsize,
    fail_encrypt: AtomicBool,
    fail_firewall: AtomicBool,
    fail_screenlock: AtomicBool,
}

impl MdmProvider for RecordingProvider {
    fn wipe(&self, _o: &WipeOpts) -> MdmResult<WipeOutcome> {
        unreachable!("wipe should not run in M1 e2e")
    }
    fn lock(&self, _m: &str) -> MdmResult<()> {
        unreachable!("lock should not run in M1 e2e")
    }
    fn escrow_recovery_key(&self) -> MdmResult<RawRecoveryKey> {
        Ok(RawRecoveryKey {
            key_type: RecoveryKeyType::Luks,
            material: vec![0xAB; 32],
        })
    }
    fn install_os_updates(&self, _o: &OsUpdateOpts) -> MdmResult<OsUpdateOutcome> {
        self.install_calls.fetch_add(1, Ordering::SeqCst);
        Ok(OsUpdateOutcome {
            updates_installed: 3,
            reboot_required: false,
            log_sha256: [0xCD; 32],
        })
    }
    fn apply_config_profile(&self, _p: &SignedConfigProfile) -> MdmResult<()> {
        unreachable!("apply_config_profile is M3, not M1")
    }
    fn enable_disk_encryption(&self) -> MdmResult<EncryptionOutcome> {
        self.encrypt_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_encrypt.load(Ordering::SeqCst) {
            return Err(MdmError::Command("disk-encryption blocked".into()));
        }
        Ok(EncryptionOutcome {
            enabled: true,
            recovery_key_escrowed: false,
            provider: "luks".into(),
        })
    }
    fn enable_firewall(&self) -> MdmResult<()> {
        self.firewall_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_firewall.load(Ordering::SeqCst) {
            return Err(MdmError::Command("firewall blocked".into()));
        }
        Ok(())
    }
    fn set_screen_lock(&self, _t: u32) -> MdmResult<()> {
        self.screenlock_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_screenlock.load(Ordering::SeqCst) {
            return Err(MdmError::Command("dconf blocked".into()));
        }
        Ok(())
    }
    fn enter_lost_mode(&self, _m: &str) -> MdmResult<()> {
        unreachable!("lost-mode is M2, not M1")
    }
    fn exit_lost_mode(&self) -> MdmResult<()> {
        unreachable!("lost-mode is M2, not M1")
    }
}

/// Stub power-state provider — constant On-Battery or AC depending on
/// the boolean passed at construction time.
struct StaticPower {
    on_battery: bool,
}

impl PowerStateProvider for StaticPower {
    fn is_on_battery(&self) -> bool {
        self.on_battery
    }
}

/// All three posture toggles `Off` — drives auto-remediation through
/// every kind in one snapshot.
fn snapshot_all_off() -> PostureSnapshot {
    PostureSnapshot {
        disk_encryption: PostureToggle::Off,
        firewall_enabled: PostureToggle::Off,
        screen_lock_enabled: PostureToggle::Off,
        os_patch_level: Some("2026-04".into()),
        os_version: Some("24.04".into()),
    }
}

fn auto_cfg(debounce_secs: u64) -> AutoRemediateConfig {
    AutoRemediateConfig {
        disk_encryption: true,
        firewall: true,
        screen_lock: true,
        screen_lock_timeout_secs: 300,
        remediation_debounce_secs: debounce_secs,
    }
}

async fn drain_for(rx: &mut mpsc::Receiver<Event>, budget: Duration) -> Vec<Event> {
    let mut out = Vec::new();
    while let Ok(Some(ev)) = tokio::time::timeout(budget, rx.recv()).await {
        out.push(ev);
    }
    out
}

fn auto_remediation_payloads(events: &[Event]) -> Vec<MdmAutoRemediationResultPayload> {
    events
        .iter()
        .filter_map(|ev| match &ev.kind {
            EventKind::MdmAutoRemediationResult { payload } => {
                serde_json::from_str::<MdmAutoRemediationResultPayload>(payload).ok()
            }
            _ => None,
        })
        .collect()
}

// ---------- Scenario 1: all-off snapshot drives all three fixes -----------

#[tokio::test(flavor = "current_thread")]
async fn auto_remediation_dispatches_all_three_off_signals() {
    let (bus, mut rx) = EventBus::new(64, 64);
    let provider: Arc<RecordingProvider> = Arc::new(RecordingProvider::default());
    let remediator = AutoRemediator::new(
        auto_cfg(86_400),
        provider.clone() as Arc<dyn MdmProvider>,
        bus.clone(),
    );

    remediator.observe(&snapshot_all_off()).await;

    assert_eq!(provider.encrypt_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.firewall_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.screenlock_calls.load(Ordering::SeqCst), 1);

    let events = drain_for(&mut rx, Duration::from_millis(200)).await;
    let payloads = auto_remediation_payloads(&events);
    assert_eq!(
        payloads.len(),
        3,
        "expected three auto-remediation events, got: {payloads:?}",
    );
    assert!(payloads
        .iter()
        .all(|p| p.status == RemediateStatus::Success));
}

// ---------- Scenario 2: debounce window suppresses duplicates -------------

#[tokio::test(flavor = "current_thread")]
async fn auto_remediation_debounces_within_window() {
    let (bus, mut rx) = EventBus::new(64, 64);
    let provider: Arc<RecordingProvider> = Arc::new(RecordingProvider::default());
    let remediator = AutoRemediator::new(
        auto_cfg(86_400), // 24h window — second pass must NOT re-invoke PAL
        provider.clone() as Arc<dyn MdmProvider>,
        bus.clone(),
    );

    remediator.observe(&snapshot_all_off()).await;
    let _ = drain_for(&mut rx, Duration::from_millis(100)).await;

    remediator.observe(&snapshot_all_off()).await;
    let events = drain_for(&mut rx, Duration::from_millis(100)).await;
    let payloads = auto_remediation_payloads(&events);

    // PAL counts must NOT have advanced.
    assert_eq!(provider.encrypt_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.firewall_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.screenlock_calls.load(Ordering::SeqCst), 1);

    // And every second-pass event must carry status `debounced`.
    assert_eq!(payloads.len(), 3);
    assert!(
        payloads
            .iter()
            .all(|p| p.status == RemediateStatus::Debounced),
        "expected Debounced for every second-pass event, got: {payloads:?}"
    );
}

// ---------- Scenario 3: PAL failure publishes a Failure event -------------

#[tokio::test(flavor = "current_thread")]
async fn auto_remediation_failure_publishes_fallback_finding() {
    let (bus, mut rx) = EventBus::new(64, 64);
    let provider: Arc<RecordingProvider> = Arc::new(RecordingProvider::default());
    provider.fail_firewall.store(true, Ordering::SeqCst);
    let remediator = AutoRemediator::new(
        auto_cfg(86_400),
        provider.clone() as Arc<dyn MdmProvider>,
        bus.clone(),
    );

    remediator
        .observe(&PostureSnapshot {
            disk_encryption: PostureToggle::On,
            firewall_enabled: PostureToggle::Off,
            screen_lock_enabled: PostureToggle::On,
            os_patch_level: None,
            os_version: None,
        })
        .await;

    let events = drain_for(&mut rx, Duration::from_millis(200)).await;
    let auto = auto_remediation_payloads(&events);
    assert_eq!(auto.len(), 1);
    assert_eq!(auto[0].status, RemediateStatus::Failure);
    assert!(
        auto[0].error.is_some(),
        "Failure payload must carry the PAL error string"
    );
}

// ---------- Scenario 4: recovery key escrow is one-shot per boot ----------

#[tokio::test(flavor = "current_thread")]
async fn recovery_key_escrow_is_one_shot_per_boot() {
    let (bus, mut rx) = EventBus::new(64, 64);
    let provider: Arc<RecordingProvider> = Arc::new(RecordingProvider::default());
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let seed = *b"e2e-recovery-key-seed-32-bytes!!";
    let identity = EscrowIdentity {
        seed: &seed,
        tenant_id: Uuid::from_u128(0x71),
        device_id: Uuid::from_u128(0xD1),
        signing_key: &signing,
        key_id: "e2e-evidence-key",
    };
    let mut guard = EscrowGuard::new();

    // First call must publish.
    let first = escrow_once(
        provider.as_ref() as &dyn MdmProvider,
        &bus,
        &mut guard,
        &identity,
    )
    .await
    .expect("first escrow ok")
    .expect("first escrow must publish a fresh payload");
    assert!(!first.ciphertext.is_empty());
    assert!(!first.signature.is_empty());
    assert_eq!(first.key_id, "e2e-evidence-key");

    // Second call must short-circuit because the guard already saw
    // this material (Ok(None) — the supervisor treats it as "already
    // escrowed this boot").
    let second = escrow_once(
        provider.as_ref() as &dyn MdmProvider,
        &bus,
        &mut guard,
        &identity,
    )
    .await
    .expect("second escrow must not error");
    assert!(
        second.is_none(),
        "second escrow within the same boot must return Ok(None)"
    );

    // Exactly one MdmRecoveryKeyEscrowed event must have landed.
    let events = drain_for(&mut rx, Duration::from_millis(200)).await;
    let count = events
        .iter()
        .filter(|ev| matches!(ev.kind, EventKind::MdmRecoveryKeyEscrowed { .. }))
        .count();
    assert_eq!(count, 1, "exactly one escrow event must be published");
}

// ---------- Scenario 5: battery-aware OS patch deferral -------------------

#[tokio::test(flavor = "current_thread")]
async fn os_patch_defers_on_battery_saver() {
    let (bus, mut rx) = EventBus::new(64, 64);
    let provider: Arc<RecordingProvider> = Arc::new(RecordingProvider::default());
    let cfg = OsPatchConfig {
        enabled: true,
        auto_install_security: true,
        auto_install_all: false,
        defer_on_battery: true,
    };

    let outcome = os_patch_tick(
        &cfg,
        provider.as_ref() as &dyn MdmProvider,
        &StaticPower { on_battery: true },
        &bus,
    )
    .await;

    assert_eq!(outcome.status, OsPatchStatus::DeferredOnBattery);
    assert_eq!(
        provider.install_calls.load(Ordering::SeqCst),
        0,
        "PAL must not be touched on deferred ticks"
    );

    // The tick still publishes a "deferred" result envelope so the
    // audit chain captures the decision — that's the documented
    // behaviour in os_patch::tick.
    let events = drain_for(&mut rx, Duration::from_millis(150)).await;
    let count = events
        .iter()
        .filter(|ev| matches!(ev.kind, EventKind::MdmOsUpdateResult { .. }))
        .count();
    assert_eq!(
        count, 1,
        "deferred tick must still publish a single MdmOsUpdateResult envelope"
    );
}

// ---------- Scenario 6: OS patch normal-power round-trip ------------------

#[tokio::test(flavor = "current_thread")]
async fn os_patch_runs_and_publishes_result_on_ac() {
    let (bus, mut rx) = EventBus::new(64, 64);
    let provider: Arc<RecordingProvider> = Arc::new(RecordingProvider::default());
    let cfg = OsPatchConfig {
        enabled: true,
        auto_install_security: true,
        auto_install_all: true,
        defer_on_battery: true,
    };

    let outcome = os_patch_tick(
        &cfg,
        provider.as_ref() as &dyn MdmProvider,
        &StaticPower { on_battery: false },
        &bus,
    )
    .await;
    assert_eq!(outcome.status, OsPatchStatus::Success);
    assert_eq!(outcome.updates_installed, 3);
    assert!(!outcome.reboot_required);
    assert_eq!(provider.install_calls.load(Ordering::SeqCst), 1);

    let events = drain_for(&mut rx, Duration::from_millis(200)).await;
    let count = events
        .iter()
        .filter(|ev| matches!(ev.kind, EventKind::MdmOsUpdateResult { .. }))
        .count();
    assert_eq!(count, 1, "exactly one MdmOsUpdateResult must be published");
}
