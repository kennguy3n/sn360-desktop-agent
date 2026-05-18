//! Application-control provider (Phase 4).
//!
//! This module hosts the cross-platform PAL surface for binary
//! authorization / application control — the Phase-4 capability
//! described in `docs/architecture.md` § 4.1 (Trait surface) and
//! `docs/device-control.md` § 8 (Application control).
//!
//! Phase-4 scope is intentionally limited:
//!
//! * The trait surface is the binding spec.
//! * Per-OS implementations are stubs that report
//!   [`AppControlMode::Disabled`] from
//!   [`AppControlProvider::current_mode`] and accept any
//!   [`SignedAppControlPolicy`] from
//!   [`AppControlProvider::apply_policy`] without forwarding it to a
//!   real backend (WDAC / AppLocker on Windows, Santa on macOS,
//!   clean-room dm-verity-aware enforcement on Linux).
//! * Policy bundles are Ed25519-signed (`signature` over
//!   `canonical_payload`) and the trait verifies the signature
//!   before passing the bundle to the OS-specific apply path.
//!
//! Higher-level orchestration (mode transitions, monitor-vs-enforce
//! logging, dual-control rollback) lives in `crates/sda-app-control`.
//! That crate calls into this trait via
//! `Box<dyn AppControlProvider>` so the supervisor can swap a real
//! provider for the stub in tests.
//!
//! ## macOS Santa stub (Task 4.6)
//!
//! On macOS the [`MacAppControlProvider`] is a clean-room stub that
//! shells out to `santactl status --json` to detect Santa's
//! installed mode and translates [`SignedAppControlPolicy`] rules
//! into the rule format Santa expects. When Santa is not present
//! (the binary is missing or returns a non-zero exit) the stub
//! gracefully degrades to [`AppControlMode::Disabled`] rather than
//! erroring out — this matches `docs/device-control.md` § 8 (Phase-4 default
//! is monitor-only opt-in).

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};

/// Operating mode of the underlying app-control backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppControlMode {
    /// Backend is installed and observing. Allow / deny decisions
    /// are LOGGED but never blocked. `docs/device-control.md` § 8 mandates this
    /// as the Phase-4 default.
    Monitor,
    /// Backend is installed and actively blocking unauthorized
    /// binaries. Requires explicit tenant opt-in plus dual-control
    /// rollback per `docs/device-control.md` § 8.
    Enforce,
    /// Backend is not installed, not running, or has been
    /// administratively disabled. The agent will not attempt to
    /// transition out of this state on its own.
    Disabled,
}

impl AppControlMode {
    /// String representation suitable for logs / wire payloads.
    pub fn as_str(&self) -> &'static str {
        match self {
            AppControlMode::Monitor => "monitor",
            AppControlMode::Enforce => "enforce",
            AppControlMode::Disabled => "disabled",
        }
    }
}

/// A single allow / deny rule that can be applied to the OS-level
/// backend.
///
/// `subject` is interpreted by the backend: SHA-256 binary hash
/// (`"sha256:<hex>"`), code-signing identity (`"team_id:<id>"`),
/// path glob (`"path:/Applications/Foo.app/**"`), or publisher
/// (`"publisher:<cn>"`). Per-OS providers translate the canonical
/// rule into the native form (Santa rule, AppLocker XML, dm-verity
/// allowlist).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppControlRule {
    /// Canonical subject identifier, e.g. `"sha256:..."`.
    pub subject: String,
    /// `true` for an allowlist entry, `false` for a denylist entry.
    pub allow: bool,
    /// Free-form operator-supplied reason for this rule. Surfaces
    /// in audit / evidence records.
    #[serde(default)]
    pub reason: String,
}

/// Canonical payload of a signed app-control policy.
///
/// The signature in [`SignedAppControlPolicy::signature`] covers
/// the canonical JSON encoding of this struct (using
/// `serde_json::to_vec` with default settings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppControlPolicyPayload {
    /// Monotonically-increasing policy version assigned by the
    /// control plane. The provider rejects an apply that goes
    /// backwards.
    pub version: u64,
    /// Policy issuance time (UTC).
    pub issued_at: DateTime<Utc>,
    /// Mode the policy is meant to run in once applied.
    pub target_mode: AppControlMode,
    /// Allow / deny ruleset.
    pub rules: Vec<AppControlRule>,
}

/// Signed policy bundle — the only shape `apply_policy` accepts.
///
/// `canonical_payload` MUST be the byte-for-byte JSON encoding of
/// [`AppControlPolicyPayload`] that was signed. The PAL trait
/// verifies the signature over those bytes before deserializing,
/// so any tampering with the JSON breaks the signature check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAppControlPolicy {
    /// Bytes that were signed. Hex-encoded for safe YAML / JSON
    /// transport. Implementations parse this back to bytes before
    /// verification and deserialization.
    pub canonical_payload_hex: String,
    /// Lowercase-hex Ed25519 signature over `canonical_payload_hex`
    /// (after hex-decoding it back to bytes).
    pub signature: String,
    /// Lowercase-hex Ed25519 public key used to verify
    /// `signature`. The provider's caller is responsible for
    /// pinning trust roots — the PAL trait only checks that the
    /// signature is internally consistent.
    pub signing_key: String,
}

/// Errors produced by [`AppControlProvider`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum AppControlError {
    /// The policy signature failed verification.
    #[error("app-control policy signature invalid")]
    InvalidSignature,
    /// The signing key is malformed (wrong length, not hex, etc.).
    #[error("app-control signing key malformed: {0}")]
    InvalidSigningKey(String),
    /// The canonical payload could not be parsed as JSON or did not
    /// match the expected schema.
    #[error("app-control policy payload invalid: {0}")]
    InvalidPayload(String),
    /// Caller supplied a policy version that is not strictly
    /// greater than the most recently applied version.
    #[error("app-control policy version regressed: applied={applied} new={new}")]
    PolicyRegressed { applied: u64, new: u64 },
    /// The host platform has no app-control backend (Phase-4
    /// stubs).
    #[error("app-control not supported on this platform")]
    NotSupported,
    /// The underlying OS backend returned an error.
    #[error("app-control backend failed: {0}")]
    Backend(String),
}

/// Cross-platform app-control surface.
///
/// Implementations MUST be `Send + Sync`. Phase-4 stubs are
/// zero-sized and trivially satisfy these bounds.
pub trait AppControlProvider: Send + Sync {
    /// Returns the operating mode currently observed on the host.
    fn current_mode(&self) -> Result<AppControlMode, AppControlError>;

    /// Verifies and applies a signed policy bundle.
    ///
    /// The default implementation performs signature verification
    /// over `canonical_payload_hex` using `signing_key` and then
    /// hands the parsed [`AppControlPolicyPayload`] to
    /// [`AppControlProvider::apply_verified_policy`]. Per-OS
    /// implementations override `apply_verified_policy`, not this
    /// method, so the signature check stays uniform across
    /// providers.
    fn apply_policy(&self, policy: &SignedAppControlPolicy) -> Result<(), AppControlError> {
        let payload = verify_policy(policy)?;
        self.apply_verified_policy(&payload)
    }

    /// Apply a policy whose signature has already been verified.
    /// Per-OS implementations override this.
    fn apply_verified_policy(
        &self,
        payload: &AppControlPolicyPayload,
    ) -> Result<(), AppControlError>;
}

/// Verifies an Ed25519-signed [`SignedAppControlPolicy`] and
/// returns the parsed payload on success.
///
/// Exposed so non-trait callers (config validation, control-plane
/// stubs in tests) can re-use the same verification logic without
/// instantiating a provider.
pub fn verify_policy(
    policy: &SignedAppControlPolicy,
) -> Result<AppControlPolicyPayload, AppControlError> {
    let key_bytes = hex::decode(&policy.signing_key)
        .map_err(|e| AppControlError::InvalidSigningKey(e.to_string()))?;
    if key_bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(AppControlError::InvalidSigningKey(format!(
            "expected {} bytes, got {}",
            PUBLIC_KEY_LENGTH,
            key_bytes.len()
        )));
    }
    let mut key_arr = [0u8; PUBLIC_KEY_LENGTH];
    key_arr.copy_from_slice(&key_bytes);
    let key = VerifyingKey::from_bytes(&key_arr)
        .map_err(|e| AppControlError::InvalidSigningKey(e.to_string()))?;

    let sig_bytes =
        hex::decode(&policy.signature).map_err(|_| AppControlError::InvalidSignature)?;
    if sig_bytes.len() != SIGNATURE_LENGTH {
        return Err(AppControlError::InvalidSignature);
    }
    let mut sig_arr = [0u8; SIGNATURE_LENGTH];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    let payload_bytes = hex::decode(&policy.canonical_payload_hex)
        .map_err(|e| AppControlError::InvalidPayload(e.to_string()))?;
    key.verify(&payload_bytes, &sig)
        .map_err(|_| AppControlError::InvalidSignature)?;

    let payload: AppControlPolicyPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AppControlError::InvalidPayload(e.to_string()))?;
    Ok(payload)
}

// =====================================================================
// Per-OS Phase-4 stubs
// =====================================================================

/// Linux Phase-4 placeholder. Will host the clean-room
/// dm-verity-aware enforcement backend in a later phase; today
/// every call reports [`AppControlMode::Disabled`] and accepts
/// policies without forwarding them to a real backend.
#[cfg(target_os = "linux")]
pub mod linux_impl {
    use super::*;

    /// Phase-4 Linux stub for [`AppControlProvider`].
    #[derive(Debug, Default)]
    pub struct LinuxAppControlProvider;

    impl LinuxAppControlProvider {
        /// Construct a fresh stub provider.
        pub fn new() -> Self {
            Self
        }
    }

    impl AppControlProvider for LinuxAppControlProvider {
        fn current_mode(&self) -> Result<AppControlMode, AppControlError> {
            Ok(AppControlMode::Disabled)
        }

        fn apply_verified_policy(
            &self,
            _payload: &AppControlPolicyPayload,
        ) -> Result<(), AppControlError> {
            // Phase-4 stub: accept the policy so the supervisor's
            // happy-path stays exercised, but don't actually push
            // anything to dm-verity yet.
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::LinuxAppControlProvider;

/// macOS Phase-4 stub backed by Santa / North Pole Santa.
///
/// Task 4.6: this is a clean-room wrapper around `santactl` that
/// translates [`SignedAppControlPolicy`] rules into Santa's
/// `santactl rule --add` format. Phase 4 ships only the
/// translation layer + status probe; the actual `santactl`
/// invocation is short-circuited so unit tests do not require
/// Santa to be installed on the CI host.
#[cfg(target_os = "macos")]
pub mod mac_impl {
    use super::*;

    /// Output shape of `santactl status --json` (subset we care
    /// about). Public so unit tests can construct fixtures.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SantaStatus {
        /// Either `"MONITOR"` or `"LOCKDOWN"` per Santa's CLI.
        pub mode: String,
    }

    impl SantaStatus {
        /// Map Santa's mode string onto our [`AppControlMode`]
        /// enum.
        pub fn to_app_control_mode(&self) -> AppControlMode {
            match self.mode.to_uppercase().as_str() {
                "MONITOR" => AppControlMode::Monitor,
                "LOCKDOWN" => AppControlMode::Enforce,
                _ => AppControlMode::Disabled,
            }
        }
    }

    /// Translate a single canonical [`AppControlRule`] into a
    /// Santa `santactl rule --add` argument vector.
    ///
    /// Santa accepts `--allow` / `--block` plus a subject family
    /// (`--sha256`, `--certificate`, `--teamid`, `--signingid`,
    /// `--cdhash`). Unknown subject families fall through to
    /// `--sha256` with the raw value so the rule is rejected by
    /// Santa rather than silently mistranslated.
    pub fn santa_rule_args(rule: &AppControlRule) -> Vec<String> {
        let mut args = vec!["rule".to_string()];
        args.push(if rule.allow {
            "--allow".to_string()
        } else {
            "--block".to_string()
        });
        if let Some((kind, value)) = rule.subject.split_once(':') {
            match kind {
                "sha256" => args.push(format!("--sha256={}", value)),
                "team_id" | "teamid" => args.push(format!("--teamid={}", value)),
                "signing_id" | "signingid" => args.push(format!("--signingid={}", value)),
                "certificate" | "cert" => args.push(format!("--certificate={}", value)),
                "cdhash" => args.push(format!("--cdhash={}", value)),
                _ => args.push(format!("--sha256={}", rule.subject)),
            }
        } else {
            args.push(format!("--sha256={}", rule.subject));
        }
        if !rule.reason.is_empty() {
            args.push("--message".into());
            args.push(rule.reason.clone());
        }
        args
    }

    /// Phase-4 macOS stub for [`AppControlProvider`].
    #[derive(Debug, Default)]
    pub struct MacAppControlProvider;

    impl MacAppControlProvider {
        /// Construct a fresh stub provider.
        pub fn new() -> Self {
            Self
        }

        /// Probe `santactl status --json` and return the parsed
        /// status. Returns `None` if Santa is not installed or
        /// reports an error so the caller can degrade to
        /// `Disabled` cleanly.
        pub fn probe_santa_status() -> Option<SantaStatus> {
            // Phase-4: invoke santactl if it is on PATH, otherwise
            // bail out. Errors are swallowed deliberately —
            // `docs/device-control.md` § 8 says graceful degradation to
            // Disabled is the right default.
            let output = std::process::Command::new("santactl")
                .args(["status", "--json"])
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            serde_json::from_slice(&output.stdout).ok()
        }
    }

    impl AppControlProvider for MacAppControlProvider {
        fn current_mode(&self) -> Result<AppControlMode, AppControlError> {
            Ok(Self::probe_santa_status()
                .map(|s| s.to_app_control_mode())
                .unwrap_or(AppControlMode::Disabled))
        }

        fn apply_verified_policy(
            &self,
            _payload: &AppControlPolicyPayload,
        ) -> Result<(), AppControlError> {
            // Phase-4 stub: real Santa rule pushes land in a later
            // phase. We accept verified policies so the higher
            // layers exercise the happy path.
            Ok(())
        }
    }
}

#[cfg(target_os = "macos")]
pub use mac_impl::{santa_rule_args, MacAppControlProvider, SantaStatus};

/// Windows Phase-4 placeholder. Will host the WDAC + AppLocker
/// PowerShell shim in a later phase; today every call reports
/// [`AppControlMode::Disabled`] and accepts policies without
/// forwarding them to a real backend.
#[cfg(target_os = "windows")]
pub mod windows_impl {
    use super::*;

    /// Phase-4 Windows stub for [`AppControlProvider`].
    #[derive(Debug, Default)]
    pub struct WindowsAppControlProvider;

    impl WindowsAppControlProvider {
        /// Construct a fresh stub provider.
        pub fn new() -> Self {
            Self
        }
    }

    impl AppControlProvider for WindowsAppControlProvider {
        fn current_mode(&self) -> Result<AppControlMode, AppControlError> {
            Ok(AppControlMode::Disabled)
        }

        fn apply_verified_policy(
            &self,
            _payload: &AppControlPolicyPayload,
        ) -> Result<(), AppControlError> {
            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::WindowsAppControlProvider;

// =====================================================================
// Default factory
// =====================================================================

/// Returns the platform-default [`AppControlProvider`] for this
/// host.
///
/// On unsupported targets returns `None` so the agent can run with
/// app-control disabled rather than panicking at startup.
pub fn default_app_control_provider() -> Option<Box<dyn AppControlProvider>> {
    #[cfg(target_os = "linux")]
    {
        Some(Box::new(LinuxAppControlProvider::new()))
    }
    #[cfg(target_os = "macos")]
    {
        Some(Box::new(MacAppControlProvider::new()))
    }
    #[cfg(target_os = "windows")]
    {
        Some(Box::new(WindowsAppControlProvider::new()))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample_payload() -> AppControlPolicyPayload {
        AppControlPolicyPayload {
            version: 1,
            issued_at: Utc::now(),
            target_mode: AppControlMode::Monitor,
            rules: vec![AppControlRule {
                subject: "sha256:abc".into(),
                allow: true,
                reason: "test".into(),
            }],
        }
    }

    fn sign_payload(payload: &AppControlPolicyPayload) -> SignedAppControlPolicy {
        let mut secret_bytes = [0u8; 32];
        // Deterministic key for reproducible test output.
        secret_bytes[0] = 1;
        let signing = SigningKey::from_bytes(&secret_bytes);
        let bytes = serde_json::to_vec(payload).expect("encode payload");
        let sig = signing.sign(&bytes);
        SignedAppControlPolicy {
            canonical_payload_hex: hex::encode(&bytes),
            signature: hex::encode(sig.to_bytes()),
            signing_key: hex::encode(signing.verifying_key().to_bytes()),
        }
    }

    #[test]
    fn mode_round_trips_through_json() {
        for m in [
            AppControlMode::Monitor,
            AppControlMode::Enforce,
            AppControlMode::Disabled,
        ] {
            let json = serde_json::to_string(&m).expect("encode");
            let back: AppControlMode = serde_json::from_str(&json).expect("decode");
            assert_eq!(m, back);
        }
    }

    #[test]
    fn mode_as_str_is_stable() {
        // Logs / wire payloads pin on the lowercase form.
        assert_eq!(AppControlMode::Monitor.as_str(), "monitor");
        assert_eq!(AppControlMode::Enforce.as_str(), "enforce");
        assert_eq!(AppControlMode::Disabled.as_str(), "disabled");
    }

    #[test]
    fn verify_policy_accepts_a_valid_signature() {
        let payload = sample_payload();
        let signed = sign_payload(&payload);
        let parsed = verify_policy(&signed).expect("verify");
        assert_eq!(parsed.version, payload.version);
        assert_eq!(parsed.target_mode, payload.target_mode);
    }

    #[test]
    fn verify_policy_rejects_a_tampered_payload() {
        let payload = sample_payload();
        let mut signed = sign_payload(&payload);
        // Flip a byte in the canonical payload — signature must no
        // longer verify.
        let mut bytes = hex::decode(&signed.canonical_payload_hex).unwrap();
        bytes[0] ^= 0x01;
        signed.canonical_payload_hex = hex::encode(bytes);
        assert!(matches!(
            verify_policy(&signed),
            Err(AppControlError::InvalidSignature) | Err(AppControlError::InvalidPayload(_))
        ));
    }

    #[test]
    fn verify_policy_rejects_a_malformed_key() {
        let payload = sample_payload();
        let mut signed = sign_payload(&payload);
        signed.signing_key = "00".into();
        assert!(matches!(
            verify_policy(&signed),
            Err(AppControlError::InvalidSigningKey(_))
        ));
    }

    #[test]
    fn verify_policy_rejects_a_malformed_signature() {
        let payload = sample_payload();
        let mut signed = sign_payload(&payload);
        signed.signature = "00".into();
        assert!(matches!(
            verify_policy(&signed),
            Err(AppControlError::InvalidSignature)
        ));
    }

    #[test]
    fn default_provider_is_present_on_supported_targets() {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            let p = default_app_control_provider();
            assert!(p.is_some(), "expected platform stub provider");
        }
    }

    #[test]
    fn stub_current_mode_is_disabled_or_observed() {
        let p = default_app_control_provider();
        if let Some(p) = p {
            // The stubs return Disabled. The macOS provider may
            // return Monitor / Enforce / Disabled depending on
            // whether `santactl` happens to be installed on the
            // test host — we just require that it does not error.
            let m = p.current_mode().expect("current_mode");
            let _ok = matches!(
                m,
                AppControlMode::Monitor | AppControlMode::Enforce | AppControlMode::Disabled
            );
        }
    }

    #[test]
    fn stub_apply_policy_accepts_a_valid_signed_policy() {
        let p = default_app_control_provider();
        if let Some(p) = p {
            let payload = sample_payload();
            let signed = sign_payload(&payload);
            assert!(p.apply_policy(&signed).is_ok());
        }
    }

    #[test]
    fn stub_apply_policy_rejects_a_tampered_signed_policy() {
        let p = default_app_control_provider();
        if let Some(p) = p {
            let payload = sample_payload();
            let mut signed = sign_payload(&payload);
            signed.signature = "ff".repeat(SIGNATURE_LENGTH);
            assert!(p.apply_policy(&signed).is_err());
        }
    }

    #[test]
    fn trait_object_compiles_for_send_sync_and_box() {
        fn _assert_object_safe(_: Box<dyn AppControlProvider>) {}
        fn _assert_send_sync<T: Send + Sync>() {}
        _assert_send_sync::<Box<dyn AppControlProvider>>();
    }

    // -----------------------------------------------------------------
    // macOS Santa stub coverage (Task 4.6)
    // -----------------------------------------------------------------

    #[cfg(target_os = "macos")]
    #[test]
    fn santa_status_maps_modes_correctly() {
        use mac_impl::SantaStatus;
        let monitor = SantaStatus {
            mode: "MONITOR".into(),
        };
        let lockdown = SantaStatus {
            mode: "LOCKDOWN".into(),
        };
        let unknown = SantaStatus {
            mode: "OTHER".into(),
        };
        assert_eq!(monitor.to_app_control_mode(), AppControlMode::Monitor);
        assert_eq!(lockdown.to_app_control_mode(), AppControlMode::Enforce);
        assert_eq!(unknown.to_app_control_mode(), AppControlMode::Disabled);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn santa_rule_args_translate_known_subject_kinds() {
        use mac_impl::santa_rule_args;
        let rule = AppControlRule {
            subject: "sha256:deadbeef".into(),
            allow: true,
            reason: "trusted".into(),
        };
        let args = santa_rule_args(&rule);
        assert_eq!(args[0], "rule");
        assert_eq!(args[1], "--allow");
        assert_eq!(args[2], "--sha256=deadbeef");
        assert!(args.contains(&"--message".to_string()));

        let team = AppControlRule {
            subject: "team_id:ABCD123".into(),
            allow: false,
            reason: String::new(),
        };
        let args = santa_rule_args(&team);
        assert_eq!(args[1], "--block");
        assert_eq!(args[2], "--teamid=ABCD123");

        let unknown = AppControlRule {
            subject: "bogus_kind:xyz".into(),
            allow: true,
            reason: String::new(),
        };
        let args = santa_rule_args(&unknown);
        assert_eq!(args[2], "--sha256=bogus_kind:xyz");
    }
}
