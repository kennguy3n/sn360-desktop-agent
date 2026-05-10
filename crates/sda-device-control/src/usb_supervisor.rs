//! USB-policy supervisor.
//!
//! Owns a [`crate::DevicePolicyStore`], applies bundle slices
//! atomically (D2.1 + D2.7), and exposes a synchronous evaluation
//! API used by the per-OS helper IPC servers. The supervisor is
//! `Send + Sync` so the agent's `tokio` runtime can share it
//! across the udev-listener / named-pipe-acceptor / IOKit-callback
//! tasks via `Arc<UsbPolicySupervisor>`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::usb_policy::{
    Action, Decision, DeviceCandidate, DevicePolicySet, DevicePolicyStore, PolicySetError,
};

/// Configuration knob set for the supervisor.
///
/// Mirrors [`sda_core::config::UsbPolicyConfig`] when populated
/// from `modules.device_control.usb_policy.*`. Kept as its own
/// struct so the supervisor can be unit-tested without spinning up
/// `sda-core`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbPolicySupervisorConfig {
    /// Tenant id stamped onto every audit envelope. Sourced from
    /// the bundle metadata so the agent never has to be configured
    /// with it explicitly.
    pub tenant_id: String,
    /// Action used when no policy matches a candidate AND a
    /// verified policy set is loaded.
    #[serde(default = "default_default_action")]
    pub default_action: Action,
    /// Action used when no verified policy set is loaded yet
    /// (fresh boot, or last bundle was tampered). Operators that
    /// want closed-by-default flip this to [`Action::Block`].
    #[serde(default = "default_fallback_action")]
    pub fallback_action: Action,
}

fn default_default_action() -> Action {
    Action::Audit
}
fn default_fallback_action() -> Action {
    Action::Audit
}

impl Default for UsbPolicySupervisorConfig {
    fn default() -> Self {
        Self {
            tenant_id: String::new(),
            default_action: default_default_action(),
            fallback_action: default_fallback_action(),
        }
    }
}

/// Errors returned by [`UsbPolicySupervisor::apply_bundle_slice`].
#[derive(Debug, thiserror::Error)]
pub enum UsbPolicyApplyError {
    /// Bundle signature failed to verify; the supervisor will keep
    /// enforcing its previous policy set (D2.7 invariant).
    #[error("bundle verification failed: {reason}")]
    BundleUnverified { reason: String },
    /// The slice parsed but contained malformed rows.
    #[error("policy slice malformed: {0}")]
    PolicyParse(#[from] PolicySetError),
}

/// Outcome of [`UsbPolicySupervisor::apply_bundle_slice`].
#[derive(Debug, Clone)]
pub struct UsbPolicyApplyOutcome {
    pub previous_len: usize,
    pub new_len: usize,
    pub previous_was_disabled_sentinel: bool,
}

/// Supervisor state shared by every per-OS helper IPC server.
///
/// Holds:
///
/// * A [`DevicePolicyStore`] — atomic CAS on bundle apply.
/// * Decision counters (Prometheus is wired separately by the
///   agent host so this crate stays metrics-free).
/// * The configured tenant id used to stamp audit envelopes.
#[derive(Debug)]
pub struct UsbPolicySupervisor {
    store: DevicePolicyStore,
    tenant_id: std::sync::RwLock<String>,
    counters: DecisionCounters,
}

#[derive(Debug, Default)]
struct DecisionCounters {
    block: AtomicU64,
    allow: AtomicU64,
    audit: AtomicU64,
    apply_ok: AtomicU64,
    apply_unverified: AtomicU64,
    apply_malformed: AtomicU64,
}

/// Snapshot of decision counters for diagnostics / metrics export.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsbPolicyCounters {
    pub block: u64,
    pub allow: u64,
    pub audit: u64,
    pub apply_ok: u64,
    pub apply_unverified: u64,
    pub apply_malformed: u64,
}

impl UsbPolicySupervisor {
    /// Build a fresh supervisor pre-loaded with the closed-by-default
    /// boot sentinel (empty + disabled). The first successful
    /// [`Self::apply_bundle_slice`] flips the store into the
    /// enabled state.
    pub fn new(config: &UsbPolicySupervisorConfig) -> Arc<Self> {
        Arc::new(Self {
            store: DevicePolicyStore::new(config.default_action, config.fallback_action),
            tenant_id: std::sync::RwLock::new(config.tenant_id.clone()),
            counters: DecisionCounters::default(),
        })
    }

    /// Replace the in-memory tenant id (called by the bundle apply
    /// path so the agent does not have to be configured with it
    /// statically).
    pub fn set_tenant_id(&self, tenant_id: impl Into<String>) {
        *self
            .tenant_id
            .write()
            .expect("usb-policy tenant_id RwLock poisoned") = tenant_id.into();
    }

    /// Snapshot the current tenant id.
    pub fn tenant_id(&self) -> String {
        self.tenant_id
            .read()
            .expect("usb-policy tenant_id RwLock poisoned")
            .clone()
    }

    /// Apply a freshly-pulled policy slice from a successfully
    /// verified TRDS bundle. Caller is responsible for verifying
    /// the bundle signature first; they then hand the raw slice
    /// here.
    ///
    /// Returns the outcome on success or an error that the caller
    /// surfaces as a `Finding` (D2.7).
    pub fn apply_bundle_slice(
        &self,
        slice: &[u8],
    ) -> Result<UsbPolicyApplyOutcome, UsbPolicyApplyError> {
        let new_set = match DevicePolicySet::parse_slice(slice) {
            Ok(s) => s,
            Err(e) => {
                self.counters
                    .apply_malformed
                    .fetch_add(1, Ordering::Relaxed);
                return Err(e.into());
            }
        };
        let prev = self.store.apply(new_set);
        self.counters.apply_ok.fetch_add(1, Ordering::Relaxed);
        let outcome = UsbPolicyApplyOutcome {
            previous_len: prev.len(),
            new_len: self.store.current().len(),
            previous_was_disabled_sentinel: !prev.is_enabled(),
        };
        info!(
            previous_len = outcome.previous_len,
            new_len = outcome.new_len,
            "applied USB device-control policy slice"
        );
        Ok(outcome)
    }

    /// Record a bundle-verification failure WITHOUT replacing the
    /// current policy set (D2.7: closed-by-default). Returns the
    /// supervisor's view of the failure so the caller can mint a
    /// `Finding` of severity `High`.
    pub fn record_bundle_unverified(&self, reason: impl Into<String>) -> UsbPolicyApplyError {
        self.counters
            .apply_unverified
            .fetch_add(1, Ordering::Relaxed);
        let r = reason.into();
        warn!(reason = %r, "bundle verification failed; keeping last-known-good policy set");
        UsbPolicyApplyError::BundleUnverified { reason: r }
    }

    /// Synchronous decision evaluation. Cheap; see
    /// [`DevicePolicyStore::evaluate`].
    pub fn evaluate(&self, cand: &DeviceCandidate) -> Decision {
        let decision = self.store.evaluate(cand);
        match decision.action {
            Action::Block => {
                self.counters.block.fetch_add(1, Ordering::Relaxed);
            }
            Action::Allow => {
                self.counters.allow.fetch_add(1, Ordering::Relaxed);
            }
            Action::Audit => {
                self.counters.audit.fetch_add(1, Ordering::Relaxed);
            }
        }
        decision
    }

    /// Build an `(decision, audit_payload)` tuple in one go.
    ///
    /// The supervisor stamps the audit envelope with the tenant id
    /// so callers (per-OS helpers, e2e harness) don't have to plumb
    /// it through.
    pub fn evaluate_with_payload(
        &self,
        cand: &DeviceCandidate,
    ) -> Result<(Decision, String), crate::CanonicalizeError> {
        let decision = self.evaluate(cand);
        let payload = decision.to_event_payload(&self.tenant_id(), cand)?;
        Ok((decision, payload))
    }

    /// Snapshot of decision counters for tests and metrics.
    pub fn counters(&self) -> UsbPolicyCounters {
        UsbPolicyCounters {
            block: self.counters.block.load(Ordering::Relaxed),
            allow: self.counters.allow.load(Ordering::Relaxed),
            audit: self.counters.audit.load(Ordering::Relaxed),
            apply_ok: self.counters.apply_ok.load(Ordering::Relaxed),
            apply_unverified: self.counters.apply_unverified.load(Ordering::Relaxed),
            apply_malformed: self.counters.apply_malformed.load(Ordering::Relaxed),
        }
    }

    /// `true` when the current policy set was built from a verified
    /// bundle (i.e. at least one successful apply has occurred). Used
    /// by the supervisor's startup logic to log the closed-by-default
    /// state and by the e2e harness to assert pre-conditions.
    pub fn has_verified_set(&self) -> bool {
        self.store.current().is_enabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb_policy::{DeviceClass, DevicePolicy, PolicyMatch};

    fn cfg() -> UsbPolicySupervisorConfig {
        UsbPolicySupervisorConfig {
            tenant_id: "tenant-a".into(),
            default_action: Action::Audit,
            fallback_action: Action::Audit,
        }
    }

    fn block_all_usb_slice() -> Vec<u8> {
        let row = DevicePolicy {
            id: "00000000-0000-0000-0000-000000000001".into(),
            tenant_id: "tenant-a".into(),
            name: "block all usb".into(),
            enabled: true,
            device_class: DeviceClass::Usb,
            match_block: PolicyMatch::default(),
            action: Action::Block,
            priority: 100,
            severity: 7,
        };
        serde_json::to_vec(&[row]).unwrap()
    }

    fn usb_cand() -> DeviceCandidate {
        DeviceCandidate {
            device_class: DeviceClass::Usb,
            vendor_id: Some("05ac".into()),
            product_id: Some("0220".into()),
            serial: None,
            bus_path: None,
        }
    }

    #[test]
    fn fresh_supervisor_uses_fallback_until_first_apply() {
        let mut c = cfg();
        c.fallback_action = Action::Block;
        let sup = UsbPolicySupervisor::new(&c);
        assert!(!sup.has_verified_set());
        assert_eq!(sup.evaluate(&usb_cand()).action, Action::Block);
    }

    #[test]
    fn apply_bundle_slice_takes_effect_immediately() {
        let sup = UsbPolicySupervisor::new(&cfg());
        let outcome = sup.apply_bundle_slice(&block_all_usb_slice()).unwrap();
        assert_eq!(outcome.new_len, 1);
        assert!(outcome.previous_was_disabled_sentinel);
        assert!(sup.has_verified_set());
        assert_eq!(sup.evaluate(&usb_cand()).action, Action::Block);
        assert_eq!(sup.counters().block, 1);
    }

    #[test]
    fn malformed_slice_does_not_clobber_existing_policy() {
        let sup = UsbPolicySupervisor::new(&cfg());
        sup.apply_bundle_slice(&block_all_usb_slice()).unwrap();
        let bad = br#"[{"id":"x","tenant_id":"t","name":"n","device_class":"usb","action":"shred","priority":1}]"#;
        let err = sup.apply_bundle_slice(bad).unwrap_err();
        assert!(matches!(err, UsbPolicyApplyError::PolicyParse(_)));
        // Last-known-good still in effect.
        assert_eq!(sup.evaluate(&usb_cand()).action, Action::Block);
        assert_eq!(sup.counters().apply_malformed, 1);
        assert_eq!(sup.counters().apply_ok, 1);
    }

    #[test]
    fn record_bundle_unverified_keeps_last_known_good() {
        let sup = UsbPolicySupervisor::new(&cfg());
        sup.apply_bundle_slice(&block_all_usb_slice()).unwrap();
        let err = sup.record_bundle_unverified("ed25519 verify failed");
        assert!(matches!(err, UsbPolicyApplyError::BundleUnverified { .. }));
        assert_eq!(sup.evaluate(&usb_cand()).action, Action::Block);
        assert_eq!(sup.counters().apply_unverified, 1);
    }

    #[test]
    fn evaluate_with_payload_uses_tenant_id() {
        let sup = UsbPolicySupervisor::new(&cfg());
        sup.apply_bundle_slice(&block_all_usb_slice()).unwrap();
        let (decision, payload) = sup.evaluate_with_payload(&usb_cand()).unwrap();
        assert_eq!(decision.action, Action::Block);
        assert!(payload.contains(r#""tenant_id":"tenant-a""#));
        assert!(payload.contains(r#""decision":"block""#));
    }

    #[test]
    fn set_tenant_id_updates_audit_envelope() {
        let sup = UsbPolicySupervisor::new(&cfg());
        sup.apply_bundle_slice(&block_all_usb_slice()).unwrap();
        sup.set_tenant_id("tenant-b");
        let (_, payload) = sup.evaluate_with_payload(&usb_cand()).unwrap();
        assert!(payload.contains(r#""tenant_id":"tenant-b""#));
    }
}
