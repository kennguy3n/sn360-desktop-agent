//! Top-level module wiring: the supervisor that ingests
//! [`AppControlCommand`]s, drives [`MonitorController`] /
//! [`EnforceController`], and emits events on the bus.

use std::sync::Arc;

use chrono::Utc;
use sda_core::config::AppControlConfig;
use sda_event_bus::{Event, EventBus, EventKind, Priority};
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
use sda_pal::app_control::default_app_control_provider;
use sda_pal::app_control::{
    AppControlError as PalError, AppControlMode, AppControlProvider, SignedAppControlPolicy,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};

use crate::enforce::{EnforceController, RollbackError};
use crate::monitor::MonitorController;
use crate::policy::{verify_signed_policy, PolicyVerificationError, VerifiedPolicy};

/// Errors produced by the supervisor.
#[derive(Debug, thiserror::Error)]
pub enum AppControlError {
    /// Caller asked the supervisor to apply a policy when no trusted
    /// signing key is configured.
    #[error("no trusted signing key configured")]
    NoTrustedKey,
    /// Caller asked the supervisor to apply a policy that does not
    /// verify cleanly.
    #[error("policy verification failed: {0}")]
    Verification(#[from] PolicyVerificationError),
    /// Caller asked the supervisor to apply or roll back a policy
    /// that the OS-level backend rejected.
    #[error("pal error: {0}")]
    Pal(#[from] PalError),
    /// Caller asked the supervisor to roll back without a previous
    /// policy.
    #[error("rollback failed: {0}")]
    Rollback(#[from] RollbackError),
    /// Caller asked the supervisor to apply a policy that targets a
    /// mode the supervisor is not configured for.
    #[error("policy targets {policy_mode:?} but supervisor configured for {configured_mode:?}")]
    ModeMismatch {
        configured_mode: AppControlMode,
        policy_mode: AppControlMode,
    },
}

/// Operator-issued command directed at the supervisor.
#[derive(Debug, Clone)]
pub enum AppControlCommand {
    /// Push a signed policy bundle. The supervisor verifies the
    /// signature, then routes through monitor or enforce based on
    /// configuration.
    ApplyPolicy(SignedAppControlPolicy),
    /// Roll back the most-recently-applied policy. Only valid in
    /// enforce mode.
    Rollback,
    /// Observe a binary against the active policy. Used by the LDE
    /// and other modules to feed real-world subjects into monitor
    /// mode for evaluation.
    Observe { subject: String },
}

/// Notification emitted by the supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "event")]
pub enum AppControlEvent {
    /// A signed policy was successfully verified and applied.
    PolicyApplied {
        version: u64,
        mode: String,
        rule_count: usize,
        signing_key: String,
        applied_at: chrono::DateTime<chrono::Utc>,
    },
    /// A subject was evaluated; in monitor mode this is the
    /// hypothetical decision, in enforce mode this is what the OS
    /// backend actually did.
    Decision {
        subject: String,
        matched_allow: Option<bool>,
        matched_rule_hash: Option<String>,
        evaluated_at: chrono::DateTime<chrono::Utc>,
        mode: String,
    },
    /// A rollback was successfully completed.
    Rollback {
        restored_version: u64,
        rolled_back_at: chrono::DateTime<chrono::Utc>,
    },
}

/// Stateful supervisor — owns one of monitor / enforce, never both.
pub struct AppControlSupervisor {
    config: AppControlConfig,
    bus: Arc<EventBus>,
    mode: AppControlMode,
    monitor: Option<MonitorController>,
    enforce: Option<EnforceController>,
    last_applied_version: Option<u64>,
}

impl std::fmt::Debug for AppControlSupervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppControlSupervisor")
            .field("mode", &self.mode)
            .field("has_monitor", &self.monitor.is_some())
            .field("has_enforce", &self.enforce.is_some())
            .field("last_applied_version", &self.last_applied_version)
            .finish()
    }
}

impl AppControlSupervisor {
    /// Build a supervisor with the platform-default PAL provider.
    /// Returns `None` on hosts the PAL does not support.
    ///
    /// On Linux the rich [`crate::linux::LinuxAppControlProvider`]
    /// is used so the supervisor exercises the dm-verity-aware
    /// policy persistence path.  On Windows the rich
    /// [`crate::wdac::WdacAppControlProvider`] is used so the
    /// supervisor renders WDAC / AppLocker XML and invokes the
    /// signed-policy push.  On macOS the PAL Santa stub is used.
    pub fn with_defaults(config: AppControlConfig, bus: Arc<EventBus>) -> Option<Self> {
        let provider: Box<dyn AppControlProvider> = {
            #[cfg(target_os = "linux")]
            {
                Box::new(crate::linux::LinuxAppControlProvider::default_dir())
            }
            #[cfg(target_os = "windows")]
            {
                let staging = std::path::PathBuf::from(
                    std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into()),
                )
                .join("sn360-desktop-agent")
                .join("app-control");
                // OS build is best-effort; the modern WDAC stack is
                // GA on every supported Windows 10 22H2 / 11 host.
                Box::new(crate::wdac::WdacAppControlProvider::new(19_045, staging))
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            {
                default_app_control_provider()?
            }
        };
        Some(Self::new(config, bus, provider))
    }

    /// Build a supervisor with a caller-supplied PAL provider. Used
    /// by unit tests.
    pub fn new(
        config: AppControlConfig,
        bus: Arc<EventBus>,
        provider: Box<dyn AppControlProvider>,
    ) -> Self {
        let mode = parse_mode(&config.mode);
        let (monitor, enforce) = match mode {
            AppControlMode::Monitor | AppControlMode::Disabled => {
                (Some(MonitorController::new()), None)
            }
            AppControlMode::Enforce => (None, Some(EnforceController::new(provider))),
        };
        Self {
            config,
            bus,
            mode,
            monitor,
            enforce,
            last_applied_version: None,
        }
    }

    /// Configured mode (Monitor / Enforce / Disabled).
    pub fn mode(&self) -> AppControlMode {
        self.mode
    }

    /// Apply a signed policy bundle.
    pub fn apply_policy(
        &mut self,
        signed: SignedAppControlPolicy,
    ) -> Result<VerifiedPolicy, AppControlError> {
        let trusted = self
            .config
            .trusted_signing_key
            .as_deref()
            .ok_or(AppControlError::NoTrustedKey)?;
        let verified = verify_signed_policy(&signed, trusted, self.last_applied_version)?;
        if verified.payload.target_mode != self.mode && self.mode != AppControlMode::Disabled {
            return Err(AppControlError::ModeMismatch {
                configured_mode: self.mode,
                policy_mode: verified.payload.target_mode,
            });
        }
        match (&mut self.monitor, &mut self.enforce) {
            (Some(m), None) => m.install_policy(verified.clone()),
            (None, Some(e)) => e.apply(signed, verified.clone())?,
            // Either we built both controllers (config bug) or
            // neither (no PAL support) — refuse to apply.
            _ => {
                return Err(AppControlError::Pal(PalError::NotSupported));
            }
        }
        self.last_applied_version = Some(verified.payload.version);
        let event = AppControlEvent::PolicyApplied {
            version: verified.payload.version,
            mode: self.mode.as_str().to_string(),
            rule_count: verified.payload.rules.len(),
            signing_key: signed_signing_key(trusted),
            applied_at: Utc::now(),
        };
        self.emit(EventKind::AppControlPolicyApplied {
            payload: serde_json::to_string(&event).unwrap_or_default(),
        });
        Ok(verified)
    }

    /// Roll back the most-recently-applied policy. Only valid in
    /// enforce mode.
    pub fn rollback(&mut self) -> Result<VerifiedPolicy, AppControlError> {
        let enforce = self
            .enforce
            .as_mut()
            .ok_or(AppControlError::Rollback(RollbackError::NoPrevious))?;
        let restored = enforce.rollback()?;
        self.last_applied_version = Some(restored.payload.version);
        let event = AppControlEvent::Rollback {
            restored_version: restored.payload.version,
            rolled_back_at: Utc::now(),
        };
        self.emit(EventKind::AppControlPolicyApplied {
            payload: serde_json::to_string(&event).unwrap_or_default(),
        });
        Ok(restored)
    }

    /// Observe a subject against the active policy.
    pub fn observe(&mut self, subject: impl Into<String>) -> Option<crate::monitor::Decision> {
        let subject = subject.into();
        let decision = self.monitor.as_mut()?.observe(subject.clone());
        let event = AppControlEvent::Decision {
            subject: decision.subject.clone(),
            matched_allow: decision.matched_allow,
            matched_rule_hash: decision.matched_rule_hash.clone(),
            evaluated_at: decision.observed_at,
            mode: self.mode.as_str().to_string(),
        };
        self.emit(EventKind::AppControlDecision {
            payload: serde_json::to_string(&event).unwrap_or_default(),
        });
        Some(decision)
    }

    fn emit(&self, kind: EventKind) {
        let event = Event::new("sda-app-control", Priority::High, kind);
        let bus = self.bus.clone();
        // `publish_to_server` already broadcasts locally even when
        // the server-bound queue send fails. Do NOT add a
        // `bus.publish` fallback — that would double-broadcast.
        tokio::spawn(async move {
            if let Err(e) = bus.publish_to_server(event).await {
                tracing::debug!(error = %e, "app-control publish_to_server failed");
            }
        });
    }
}

/// Convert a config-string mode to the canonical [`AppControlMode`].
/// Unknown values fall back to `Disabled` so a typo cannot
/// accidentally start blocking traffic.
fn parse_mode(s: &str) -> AppControlMode {
    match s.trim().to_ascii_lowercase().as_str() {
        "monitor" => AppControlMode::Monitor,
        "enforce" => AppControlMode::Enforce,
        _ => AppControlMode::Disabled,
    }
}

/// Lowercase-hex normalize the trusted signing key for emitted
/// events.
fn signed_signing_key(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Top-level module wrapper.
pub struct AppControlModule {
    supervisor: Arc<Mutex<AppControlSupervisor>>,
}

impl AppControlModule {
    /// Build a module backed by the platform default provider.
    pub fn with_defaults(config: AppControlConfig, bus: Arc<EventBus>) -> Option<Self> {
        let supervisor = AppControlSupervisor::with_defaults(config, bus)?;
        Some(Self {
            supervisor: Arc::new(Mutex::new(supervisor)),
        })
    }

    /// Build a module from an existing supervisor — used by tests.
    pub fn new(supervisor: AppControlSupervisor) -> Self {
        Self {
            supervisor: Arc::new(Mutex::new(supervisor)),
        }
    }

    /// Spawn the supervisor's main loop. The returned sender is the
    /// only handle the agent main keeps; dropping it terminates the
    /// task.
    pub fn start(
        self,
    ) -> (
        mpsc::UnboundedSender<AppControlCommand>,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, mut rx) = mpsc::unbounded_channel::<AppControlCommand>();
        let supervisor = self.supervisor.clone();
        let handle = tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                let mut sup = supervisor.lock().await;
                match cmd {
                    AppControlCommand::ApplyPolicy(p) => {
                        if let Err(e) = sup.apply_policy(p) {
                            tracing::warn!(error = %e, "app-control apply_policy failed");
                        }
                    }
                    AppControlCommand::Rollback => {
                        if let Err(e) = sup.rollback() {
                            tracing::warn!(error = %e, "app-control rollback failed");
                        }
                    }
                    AppControlCommand::Observe { subject } => {
                        sup.observe(subject);
                    }
                }
            }
        });
        (tx, handle)
    }

    /// Borrow the supervisor — useful for tests.
    pub fn supervisor(&self) -> Arc<Mutex<AppControlSupervisor>> {
        self.supervisor.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ed25519_dalek::{Signer, SigningKey};
    use sda_pal::app_control::{AppControlPolicyPayload, AppControlRule, SignedAppControlPolicy};

    /// Build a signed policy targeting `target_mode`.
    fn signed_policy(
        version: u64,
        target_mode: AppControlMode,
        rules: Vec<AppControlRule>,
    ) -> (SignedAppControlPolicy, String) {
        let payload = AppControlPolicyPayload {
            version,
            issued_at: Utc::now(),
            target_mode,
            rules,
        };
        let canonical = serde_json::to_vec(&payload).unwrap();
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let sig = signing.sign(&canonical);
        let signed = SignedAppControlPolicy {
            canonical_payload_hex: hex::encode(&canonical),
            signature: hex::encode(sig.to_bytes()),
            signing_key: hex::encode(signing.verifying_key().to_bytes()),
        };
        let trusted = signed.signing_key.clone();
        (signed, trusted)
    }

    fn rule(subject: &str, allow: bool) -> AppControlRule {
        AppControlRule {
            subject: subject.into(),
            allow,
            reason: "test".into(),
        }
    }

    fn make_bus() -> (Arc<EventBus>, tokio::sync::mpsc::Receiver<Event>) {
        let (bus, rx) = EventBus::new(64, 64);
        (Arc::new(bus), rx)
    }

    /// Stub provider that always succeeds.
    struct OkProvider;
    impl AppControlProvider for OkProvider {
        fn current_mode(&self) -> Result<AppControlMode, PalError> {
            Ok(AppControlMode::Enforce)
        }
        fn apply_verified_policy(
            &self,
            _payload: &AppControlPolicyPayload,
        ) -> Result<(), PalError> {
            Ok(())
        }
    }

    fn config(mode: &str, key: Option<String>) -> AppControlConfig {
        AppControlConfig {
            enabled: true,
            mode: mode.into(),
            trusted_signing_key: key,
        }
    }

    #[tokio::test]
    async fn parse_mode_falls_back_to_disabled() {
        assert_eq!(parse_mode("monitor"), AppControlMode::Monitor);
        assert_eq!(parse_mode("enforce"), AppControlMode::Enforce);
        assert_eq!(parse_mode("disabled"), AppControlMode::Disabled);
        assert_eq!(parse_mode("typo"), AppControlMode::Disabled);
    }

    #[tokio::test]
    async fn apply_in_monitor_mode_records_and_emits_event() {
        let (bus, mut rx) = make_bus();
        let (signed, trusted) =
            signed_policy(1, AppControlMode::Monitor, vec![rule("sha256:aa", true)]);
        let mut sup =
            AppControlSupervisor::new(config("monitor", Some(trusted)), bus, Box::new(OkProvider));
        sup.apply_policy(signed).expect("happy path");
        // Event must land on the bus.
        let evt = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            evt.kind,
            EventKind::AppControlPolicyApplied { .. }
        ));
    }

    #[tokio::test]
    async fn apply_without_trusted_key_fails_cleanly() {
        let (bus, _rx) = make_bus();
        let (signed, _trusted) =
            signed_policy(1, AppControlMode::Monitor, vec![rule("sha256:aa", true)]);
        let mut sup = AppControlSupervisor::new(config("monitor", None), bus, Box::new(OkProvider));
        let err = sup.apply_policy(signed).err().unwrap();
        assert!(matches!(err, AppControlError::NoTrustedKey));
    }

    #[tokio::test]
    async fn apply_with_mode_mismatch_is_rejected() {
        let (bus, _rx) = make_bus();
        let (signed, trusted) =
            signed_policy(1, AppControlMode::Enforce, vec![rule("sha256:aa", true)]);
        let mut sup =
            AppControlSupervisor::new(config("monitor", Some(trusted)), bus, Box::new(OkProvider));
        let err = sup.apply_policy(signed).err().unwrap();
        assert!(matches!(err, AppControlError::ModeMismatch { .. }));
    }

    #[tokio::test]
    async fn observe_in_monitor_emits_decision_event() {
        let (bus, mut rx) = make_bus();
        let (signed, trusted) =
            signed_policy(1, AppControlMode::Monitor, vec![rule("sha256:bad", false)]);
        let mut sup =
            AppControlSupervisor::new(config("monitor", Some(trusted)), bus, Box::new(OkProvider));
        sup.apply_policy(signed).unwrap();
        // Drain the apply event.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
        let d = sup.observe("sha256:bad").unwrap();
        assert_eq!(d.matched_allow, Some(false));
        let evt = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(evt.kind, EventKind::AppControlDecision { .. }));
    }

    #[tokio::test]
    async fn enforce_mode_apply_then_rollback() {
        let (bus, _rx) = make_bus();
        let (s1, trusted) =
            signed_policy(1, AppControlMode::Enforce, vec![rule("sha256:aa", true)]);
        let (s2, _) = signed_policy(2, AppControlMode::Enforce, vec![rule("sha256:bb", false)]);
        let mut sup =
            AppControlSupervisor::new(config("enforce", Some(trusted)), bus, Box::new(OkProvider));
        sup.apply_policy(s1).unwrap();
        sup.apply_policy(s2).unwrap();
        // Rollback re-applies the previously-active policy (v1); the
        // displaced bundle is v2.
        let restored = sup.rollback().unwrap();
        assert_eq!(restored.payload.version, 1);
    }

    #[tokio::test]
    async fn rollback_in_monitor_mode_is_an_error() {
        let (bus, _rx) = make_bus();
        let (signed, trusted) =
            signed_policy(1, AppControlMode::Monitor, vec![rule("sha256:aa", true)]);
        let mut sup =
            AppControlSupervisor::new(config("monitor", Some(trusted)), bus, Box::new(OkProvider));
        sup.apply_policy(signed).unwrap();
        let err = sup.rollback().err().unwrap();
        assert!(matches!(err, AppControlError::Rollback(_)));
    }

    #[tokio::test]
    async fn observe_without_apply_returns_none_match() {
        let (bus, _rx) = make_bus();
        let mut sup = AppControlSupervisor::new(
            config("monitor", Some(hex::encode([7u8; 32]))),
            bus,
            Box::new(OkProvider),
        );
        let d = sup.observe("sha256:aa").unwrap();
        assert!(d.matched_allow.is_none());
    }

    #[tokio::test]
    async fn module_start_drives_command_loop() {
        let (bus, _rx) = make_bus();
        let (signed, trusted) =
            signed_policy(1, AppControlMode::Monitor, vec![rule("sha256:aa", true)]);
        let supervisor =
            AppControlSupervisor::new(config("monitor", Some(trusted)), bus, Box::new(OkProvider));
        let module = AppControlModule::new(supervisor);
        let supervisor_ref = module.supervisor();
        let (tx, handle) = module.start();
        tx.send(AppControlCommand::ApplyPolicy(signed)).unwrap();
        tx.send(AppControlCommand::Observe {
            subject: "sha256:aa".into(),
        })
        .unwrap();
        // Give the loop a moment to process.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        drop(tx);
        handle.await.unwrap();
        let sup = supervisor_ref.lock().await;
        assert_eq!(sup.last_applied_version, Some(1));
    }
}
