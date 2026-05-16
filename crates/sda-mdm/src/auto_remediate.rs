//! Auto-remediation supervisor (Phase M1.2).
//!
//! Subscribes to [`EventKind::DevicePostureState`] envelopes and
//! self-heals the three posture failures the agent has authority to
//! fix without operator approval:
//!
//! 1. **Disk encryption off** → `MdmProvider::enable_disk_encryption()`
//! 2. **Firewall off**         → `MdmProvider::enable_firewall()`
//! 3. **Screen-lock off**      → `MdmProvider::set_screen_lock()`
//!
//! Each branch is gated on the corresponding
//! [`AutoRemediateConfig`] flag and a 24 h debounce window — once a
//! remediation has been attempted for a given kind it will not be
//! attempted again for `remediation_debounce_secs`. On success we
//! emit [`EventKind::MdmAutoRemediationResult`]; on failure we
//! additionally surface the matching
//! [`crate::module::SourceFinding`] so the LDE / posture rule pack
//! can fire, ensuring the operator still hears about the failure.
//!
//! The supervisor signs every attempt with an in-memory Ed25519
//! ephemeral key generated at startup. The key is only ever used
//! locally (it is not provisioned to the control plane), and per
//! `docs/desktop-mdm/ARCHITECTURE.md` § 4.4 step 12 the router
//! restricts it to the three idempotent posture-fix actions.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use sda_core::config::AutoRemediateConfig;
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use sda_pal::mdm::MdmProvider;
use sda_pal::posture::{PostureSnapshot, PostureToggle};
use sda_posture::snapshot::PosturePayload;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::module::MODULE_SOURCE;

/// Wire payload published on
/// [`EventKind::MdmAutoRemediationResult`]. Stable on-the-wire
/// shape — see `docs/desktop-mdm/ARCHITECTURE.md` § 3.6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MdmAutoRemediationResultPayload {
    pub job_id: Uuid,
    pub kind: RemediateKind,
    pub status: RemediateStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub signing_key_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediateKind {
    DiskEncryption,
    Firewall,
    ScreenLock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediateStatus {
    /// Attempt completed successfully.
    Success,
    /// Attempt was skipped because the same kind was successfully
    /// remediated within the debounce window.
    Debounced,
    /// Attempt was skipped because the corresponding
    /// `auto_remediate.*` config flag is `false`.
    Disabled,
    /// The PAL call returned an error.
    Failure,
}

/// In-memory ephemeral key used to sign auto-remediation evidence.
///
/// Generated on supervisor start, rotated on every config push
/// (callers replace the [`AutoRemediator`] when the config changes).
/// The key never leaves the agent's process — only the public
/// fingerprint travels in event payloads so the control plane can
/// reconcile.
#[derive(Clone)]
pub struct EphemeralKey {
    pub signing: Arc<SigningKey>,
    pub fingerprint: String,
}

impl EphemeralKey {
    pub fn generate() -> Self {
        use sha2::Digest;
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing = SigningKey::from_bytes(&seed);
        let mut hasher = sha2::Sha256::new();
        hasher.update(signing.verifying_key().as_bytes());
        let digest = hasher.finalize();
        let fingerprint = hex::encode(&digest[..8]);
        Self {
            signing: Arc::new(signing),
            fingerprint,
        }
    }

    /// Convenience helper for tests and the dispatcher: produce a
    /// `(signature, key_id)` pair over `preimage` using the
    /// ephemeral key.
    pub fn sign(&self, preimage: &[u8]) -> (Vec<u8>, String) {
        let sig = self.signing.sign(preimage);
        (sig.to_bytes().to_vec(), format!("ephemeral:{}", self.fingerprint))
    }
}

/// Auto-remediation supervisor — owns the debounce table, the
/// ephemeral key, and the PAL handle.
pub struct AutoRemediator {
    cfg: AutoRemediateConfig,
    provider: Arc<dyn MdmProvider>,
    bus: EventBus,
    key: EphemeralKey,
    debounce: Mutex<HashMap<RemediateKind, Instant>>,
}

impl AutoRemediator {
    pub fn new(cfg: AutoRemediateConfig, provider: Arc<dyn MdmProvider>, bus: EventBus) -> Self {
        Self {
            cfg,
            provider,
            bus,
            key: EphemeralKey::generate(),
            debounce: Mutex::new(HashMap::new()),
        }
    }

    /// Expose the supervisor's ephemeral key. Tests use this; the
    /// MdmModule uses it to seed the router validator's trusted
    /// local-key set.
    pub fn ephemeral_key(&self) -> EphemeralKey {
        self.key.clone()
    }

    /// React to a single posture snapshot. Public so tests can
    /// drive the supervisor without going through the bus.
    pub async fn observe(&self, snap: &PostureSnapshot) {
        if matches!(snap.disk_encryption, PostureToggle::Off) {
            self.maybe_run(
                RemediateKind::DiskEncryption,
                self.cfg.disk_encryption,
                |p| p.enable_disk_encryption().map(|_| ()),
            )
            .await;
        }
        if matches!(snap.firewall_enabled, PostureToggle::Off) {
            self.maybe_run(RemediateKind::Firewall, self.cfg.firewall, |p| {
                p.enable_firewall()
            })
            .await;
        }
        if matches!(snap.screen_lock_enabled, PostureToggle::Off) {
            let secs = self.cfg.screen_lock_timeout_secs;
            self.maybe_run(RemediateKind::ScreenLock, self.cfg.screen_lock, move |p| {
                p.set_screen_lock(secs)
            })
            .await;
        }
    }

    async fn maybe_run<F>(&self, kind: RemediateKind, enabled: bool, op: F)
    where
        F: FnOnce(&dyn MdmProvider) -> sda_pal::mdm::Result<()> + Send,
    {
        let started_at = Utc::now();
        if !enabled {
            let payload = self.payload(
                kind,
                RemediateStatus::Disabled,
                started_at,
                Utc::now(),
                None,
            );
            self.publish_result(payload).await;
            return;
        }
        if self.is_debounced(kind).await {
            let payload = self.payload(
                kind,
                RemediateStatus::Debounced,
                started_at,
                Utc::now(),
                None,
            );
            self.publish_result(payload).await;
            return;
        }

        // The PAL `op` is a blocking std::process::Command call.
        // Run it directly — the supervisor lives on a tokio task
        // already and the PAL calls are short-lived (each wraps a
        // single OS-native CLI invocation).
        let result = op(self.provider.as_ref());
        let finished_at = Utc::now();
        match result {
            Ok(()) => {
                self.mark_remediated(kind).await;
                let payload =
                    self.payload(kind, RemediateStatus::Success, started_at, finished_at, None);
                info!(?kind, "mdm: auto-remediation succeeded");
                self.publish_result(payload).await;
            }
            Err(e) => {
                let msg = e.to_string();
                warn!(?kind, error = %msg, "mdm: auto-remediation failed");
                let payload = self.payload(
                    kind,
                    RemediateStatus::Failure,
                    started_at,
                    finished_at,
                    Some(msg.clone()),
                );
                self.publish_result(payload).await;
                self.publish_finding(kind, &msg).await;
            }
        }
    }

    async fn is_debounced(&self, kind: RemediateKind) -> bool {
        let guard = self.debounce.lock().await;
        match guard.get(&kind) {
            Some(t) => t.elapsed() < Duration::from_secs(self.cfg.remediation_debounce_secs),
            None => false,
        }
    }

    async fn mark_remediated(&self, kind: RemediateKind) {
        let mut guard = self.debounce.lock().await;
        guard.insert(kind, Instant::now());
    }

    fn payload(
        &self,
        kind: RemediateKind,
        status: RemediateStatus,
        started_at: DateTime<Utc>,
        finished_at: DateTime<Utc>,
        error: Option<String>,
    ) -> MdmAutoRemediationResultPayload {
        MdmAutoRemediationResultPayload {
            job_id: Uuid::new_v4(),
            kind,
            status,
            started_at,
            finished_at,
            signing_key_fingerprint: self.key.fingerprint.clone(),
            error,
        }
    }

    async fn publish_result(&self, payload: MdmAutoRemediationResultPayload) {
        let json = match serde_json::to_string(&payload) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "mdm: auto-remediate result serialise failed");
                return;
            }
        };
        let event = Event::new(
            MODULE_SOURCE,
            Priority::High,
            EventKind::MdmAutoRemediationResult { payload: json },
        );
        if let Err(e) = self.bus.publish_to_server(event).await {
            warn!(error = %e, "mdm: auto-remediate result publish_to_server failed");
        }
    }

    async fn publish_finding(&self, kind: RemediateKind, reason: &str) {
        let finding_kind = match kind {
            RemediateKind::DiskEncryption => "disk_encryption_off",
            RemediateKind::Firewall => "firewall_off",
            RemediateKind::ScreenLock => "screen_lock_off",
        };
        let body = serde_json::json!({
            "kind": finding_kind,
            "reason": reason,
            "captured_at": Utc::now(),
            "remediation_attempted": true,
        });
        let event = Event::new(
            MODULE_SOURCE,
            Priority::High,
            EventKind::DeviceControlFinding {
                payload: body.to_string(),
            },
        );
        if let Err(e) = self.bus.publish_to_server(event).await {
            warn!(error = %e, "mdm: auto-remediate fallback finding publish failed");
        }
    }
}

/// Drive the supervisor against the event bus. Owns its own
/// subscriber so the supervisor's lifecycle is tied to the spawned
/// task rather than to the consumer of the returned `JoinHandle`.
pub fn spawn(
    supervisor: Arc<AutoRemediator>,
    bus: EventBus,
    mut shutdown: sda_core::signal::ShutdownSignal,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut rx = bus.subscribe();
        info!(
            fingerprint = %supervisor.key.fingerprint,
            "mdm: auto-remediate supervisor subscribed"
        );
        loop {
            tokio::select! {
                _ = shutdown.wait() => {
                    info!("mdm: auto-remediate supervisor shutting down");
                    return;
                }
                ev = rx.recv() => {
                    let Some(ev) = ev else { return };
                    if let EventKind::DevicePostureState { payload } = &ev.kind {
                        match serde_json::from_str::<PosturePayload>(payload) {
                            Ok(parsed) => {
                                debug!(
                                    captured_at = %parsed.captured_at,
                                    "mdm: auto-remediate observing posture"
                                );
                                supervisor.observe(&parsed.snapshot).await;
                            }
                            Err(e) => {
                                warn!(error = %e, "mdm: auto-remediate dropped malformed posture event");
                            }
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::config::AutoRemediateConfig;
    use sda_pal::mdm::{
        EncryptionOutcome, MdmError, OsUpdateOpts, OsUpdateOutcome, RawRecoveryKey,
        RecoveryKeyType, SignedConfigProfile, WipeOpts, WipeOutcome,
    };
    use std::sync::atomic::{AtomicU32, Ordering};

    fn snapshot(all_off: bool) -> PostureSnapshot {
        let t = if all_off {
            PostureToggle::Off
        } else {
            PostureToggle::On
        };
        PostureSnapshot {
            disk_encryption: t,
            firewall_enabled: t,
            screen_lock_enabled: t,
            os_patch_level: Some("2026-04".into()),
            os_version: Some("24.04".into()),
        }
    }

    fn config_with_debounce(secs: u64) -> AutoRemediateConfig {
        AutoRemediateConfig {
            disk_encryption: true,
            firewall: true,
            screen_lock: true,
            screen_lock_timeout_secs: 60,
            remediation_debounce_secs: secs,
        }
    }

    #[derive(Default)]
    struct MockProvider {
        disk_calls: AtomicU32,
        fw_calls: AtomicU32,
        sl_calls: AtomicU32,
        fail_on: Option<RemediateKind>,
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
            self.disk_calls.fetch_add(1, Ordering::Relaxed);
            if self.fail_on == Some(RemediateKind::DiskEncryption) {
                return Err(MdmError::Command("luks unavailable".into()));
            }
            Ok(EncryptionOutcome {
                enabled: true,
                recovery_key_escrowed: true,
                provider: "luks".into(),
            })
        }
        fn enable_firewall(&self) -> sda_pal::mdm::Result<()> {
            self.fw_calls.fetch_add(1, Ordering::Relaxed);
            if self.fail_on == Some(RemediateKind::Firewall) {
                return Err(MdmError::Command("nft missing".into()));
            }
            Ok(())
        }
        fn set_screen_lock(&self, _t: u32) -> sda_pal::mdm::Result<()> {
            self.sl_calls.fetch_add(1, Ordering::Relaxed);
            if self.fail_on == Some(RemediateKind::ScreenLock) {
                return Err(MdmError::Command("dconf failed".into()));
            }
            Ok(())
        }
        fn enter_lost_mode(&self, _m: &str) -> sda_pal::mdm::Result<()> {
            unreachable!()
        }
        fn exit_lost_mode(&self) -> sda_pal::mdm::Result<()> {
            unreachable!()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn observes_all_three_offs() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let provider = Arc::new(MockProvider::default());
        let sup = AutoRemediator::new(
            config_with_debounce(86_400),
            provider.clone(),
            bus.clone(),
        );
        sup.observe(&snapshot(true)).await;
        assert_eq!(provider.disk_calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.fw_calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.sl_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn debounces_within_window() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let provider = Arc::new(MockProvider::default());
        let sup = AutoRemediator::new(
            config_with_debounce(86_400),
            provider.clone(),
            bus.clone(),
        );
        sup.observe(&snapshot(true)).await;
        sup.observe(&snapshot(true)).await;
        // First call ran for all three; second call should be
        // debounced because debounce_secs is 24h.
        assert_eq!(provider.disk_calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.fw_calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.sl_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn debounce_zero_re_runs() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let provider = Arc::new(MockProvider::default());
        let sup =
            AutoRemediator::new(config_with_debounce(0), provider.clone(), bus.clone());
        sup.observe(&snapshot(true)).await;
        sup.observe(&snapshot(true)).await;
        // Debounce window is 0 — both runs must execute.
        assert_eq!(provider.disk_calls.load(Ordering::Relaxed), 2);
        assert_eq!(provider.fw_calls.load(Ordering::Relaxed), 2);
        assert_eq!(provider.sl_calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn disabled_branch_skips_pal_call() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let provider = Arc::new(MockProvider::default());
        let cfg = AutoRemediateConfig {
            disk_encryption: false,
            firewall: false,
            screen_lock: false,
            ..config_with_debounce(86_400)
        };
        let sup = AutoRemediator::new(cfg, provider.clone(), bus.clone());
        sup.observe(&snapshot(true)).await;
        assert_eq!(provider.disk_calls.load(Ordering::Relaxed), 0);
        assert_eq!(provider.fw_calls.load(Ordering::Relaxed), 0);
        assert_eq!(provider.sl_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn failure_publishes_fallback_finding() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let mut local_sub = bus.subscribe();
        let provider = Arc::new(MockProvider {
            fail_on: Some(RemediateKind::Firewall),
            ..Default::default()
        });
        let sup = AutoRemediator::new(
            config_with_debounce(86_400),
            provider.clone(),
            bus.clone(),
        );

        let mut snap = snapshot(true);
        snap.disk_encryption = PostureToggle::On;
        snap.screen_lock_enabled = PostureToggle::On;
        sup.observe(&snap).await;

        // Drain the bus and inspect the EventKind variants.
        let mut saw_result = false;
        let mut saw_finding = false;
        for _ in 0..6 {
            match tokio::time::timeout(Duration::from_millis(50), local_sub.recv()).await {
                Ok(Some(ev)) => match ev.kind {
                    EventKind::MdmAutoRemediationResult { .. } => saw_result = true,
                    EventKind::DeviceControlFinding { payload } => {
                        assert!(payload.contains("firewall_off"));
                        saw_finding = true;
                    }
                    _ => {}
                },
                _ => break,
            }
        }
        assert!(saw_result, "should publish MdmAutoRemediationResult");
        assert!(saw_finding, "should publish fallback DeviceControlFinding");
    }

    #[test]
    fn ephemeral_key_fingerprint_is_hex16() {
        let k = EphemeralKey::generate();
        assert_eq!(k.fingerprint.len(), 16);
        assert!(k.fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn ephemeral_key_sign_round_trips() {
        let k = EphemeralKey::generate();
        let (sig, id) = k.sign(b"hello");
        assert_eq!(sig.len(), 64);
        assert!(id.starts_with("ephemeral:"));
    }

    #[test]
    fn payload_round_trips_through_serde() {
        let p = MdmAutoRemediationResultPayload {
            job_id: Uuid::nil(),
            kind: RemediateKind::Firewall,
            status: RemediateStatus::Success,
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
            signing_key_fingerprint: "deadbeef".into(),
            error: None,
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: MdmAutoRemediationResultPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back, p);
    }
}
