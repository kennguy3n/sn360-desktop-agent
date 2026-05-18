//! USB / removable-media policy enforcement (Phase D2).
//!
//! Implements the agent-side half of the SN360 Device Control
//! workstream defined in [`docs/device-control.md`][prop].
//!
//! The control plane authors policies in the `device_policies`
//! table, the TRDS-compiler embeds them into the per-tenant signed
//! bundle as `policy/device-control/policies.json`, and the agent
//! loads that slice on every successful bundle pull. This module
//! provides:
//!
//! * [`DeviceCandidate`] — an OS-agnostic descriptor of an attach
//!   event (`device_class`, `vendor_id`, `product_id`, `serial`,
//!   bus path).
//! * [`DevicePolicy`] / [`DevicePolicySet`] — the policy schema and
//!   priority-ordered evaluator that returns
//!   [`Decision::Block`] / [`Decision::Allow`] / [`Decision::Audit`].
//! * [`DevicePolicyStore`] — a thread-safe holder backed by an
//!   atomic compare-and-swap so a successful bundle apply replaces
//!   the policy set immediately for subsequent attach events
//!   without ever blocking the enforcement path.
//! * [`Decision::to_event_payload`] — produces the canonical
//!   `connector_type: "device-control"` envelope expected by the
//!   `sn360-device-control` decoder under
//!   `services/tenant-controller/internal/renderer/templates/decoders/`.
//!
//! The module is `cfg`-portable on purpose. Per-OS enforcement
//! (Linux udev helper, Windows named-pipe service, macOS
//! NetworkExtension companion) lives in
//! [`crate::usb_linux`], [`crate::usb_windows`], and
//! [`crate::usb_macos`] respectively, all of which delegate to
//! [`DevicePolicySet::evaluate`] for the decision.
//!
//! [prop]: https://github.com/kennguy3n/sn360-desktop-agent/blob/main/docs/device-control.md

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::canonicalize::canonicalize as canonicalize_json;

/// Maximum on-disk size of `policy/device-control/policies.json`
/// the agent will accept. The control-plane caps the table at a
/// few thousand rows per tenant; 1 MiB is two orders of magnitude
/// of headroom and bounds the parse cost of a tampered slice.
pub const POLICY_SLICE_MAX_BYTES: usize = 1 << 20;

/// Errors returned by [`DevicePolicySet`] parsing.
#[derive(Debug, thiserror::Error)]
pub enum PolicySetError {
    /// The slice exceeded [`POLICY_SLICE_MAX_BYTES`].
    #[error("policy slice {got} bytes exceeds limit of {limit} bytes")]
    SliceTooLarge { got: usize, limit: usize },
    /// The slice was not valid JSON.
    #[error("policy slice is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A policy carried an unknown `action`.
    #[error("policy {id} has unknown action {action:?}")]
    UnknownAction { id: String, action: String },
    /// A policy carried an unknown `device_class`.
    #[error("policy {id} has unknown device_class {device_class:?}")]
    UnknownDeviceClass { id: String, device_class: String },
}

/// Device class taxonomy from PROPOSAL § 3.2.
///
/// `Other` is a catch-all so a future control-plane release that
/// adds a new class doesn't break existing agents — the agent
/// simply applies no policies to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceClass {
    Usb,
    Removable,
    Bluetooth,
    Mtp,
    Wpd,
    Audio,
    NetworkTether,
    /// Catch-all bucket for forward-compatibility.
    #[serde(other)]
    #[default]
    Other,
}

impl DeviceClass {
    /// Parse a kebab-case device class name as used on the wire.
    /// Returns `None` for unknown classes; callers typically reject
    /// the bundle slice in that case to avoid silently misclassifying.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "usb" => Some(Self::Usb),
            "removable" => Some(Self::Removable),
            "bluetooth" => Some(Self::Bluetooth),
            "mtp" => Some(Self::Mtp),
            "wpd" => Some(Self::Wpd),
            "audio" => Some(Self::Audio),
            "network-tether" => Some(Self::NetworkTether),
            _ => None,
        }
    }

    /// Wire-format kebab-case name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Usb => "usb",
            Self::Removable => "removable",
            Self::Bluetooth => "bluetooth",
            Self::Mtp => "mtp",
            Self::Wpd => "wpd",
            Self::Audio => "audio",
            Self::NetworkTether => "network-tether",
            Self::Other => "other",
        }
    }
}

/// A single OS attach event normalised into a device-control
/// candidate. Optional fields are `None` when the OS did not
/// surface that attribute (e.g. some bus types do not expose a
/// vendor ID at all).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DeviceCandidate {
    /// Device class as reported by the OS.
    pub device_class: DeviceClass,
    /// 16-bit vendor identifier in lowercase hex (e.g. `"05ac"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_id: Option<String>,
    /// 16-bit product identifier in lowercase hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_id: Option<String>,
    /// Device-reported serial number. Treated as opaque.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// Platform-native bus path (e.g. `/sys/bus/usb/devices/3-1`,
    /// `\\?\USB#VID_05AC&PID_8262#…`, `IOService:/...`). Used for
    /// audit-record correlation, not for matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bus_path: Option<String>,
}

/// Action tag from PROPOSAL § 3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Block,
    Allow,
    Audit,
}

/// Match block carried inside [`DevicePolicy::match_json`].
///
/// Each field is optional. An empty match block matches every
/// device of the policy's `device_class`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMatch {
    /// Lowercase-hex vendor id; matched case-insensitively.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_id: Option<String>,
    /// Lowercase-hex product id; matched case-insensitively.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_id: Option<String>,
    /// Exact-string serial match. Wildcards are intentionally not
    /// supported in v0 to keep the control-plane CRUD validatable
    /// without a regex engine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// Optional bus-path substring (case-sensitive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bus: Option<String>,
}

/// A single device policy row as carried in the TRDS slice.
///
/// Mirrors the `device_policies` table in
/// `sn360-security-platform/migrations/014_device_policies.up.sql`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePolicy {
    /// UUID assigned by the control plane.
    pub id: String,
    /// Tenant the policy belongs to. Carried for evidence
    /// correlation; the agent only ever sees its own tenant's
    /// slice so cross-tenant evaluation is structurally impossible.
    pub tenant_id: String,
    /// Human-readable name (admin-facing in the dashboard).
    pub name: String,
    /// Disabled rows are parsed but never participate in
    /// evaluation; this matches the dashboard's soft-delete
    /// semantics so a disabled rule round-trips without losing the
    /// SQL row.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Class this policy applies to.
    pub device_class: DeviceClass,
    /// Match block. Defaults to "match everything in `device_class`".
    #[serde(default)]
    #[serde(rename = "match")]
    pub match_block: PolicyMatch,
    /// Action to take on a match.
    pub action: Action,
    /// Lower numbers win. Ties broken by `id` lexicographically so
    /// evaluation is deterministic across agents in a fleet.
    #[serde(default = "default_priority")]
    pub priority: i32,
    /// Severity label (1–10) propagated to the audit envelope.
    #[serde(default = "default_severity")]
    pub severity: u8,
}

fn default_true() -> bool {
    true
}
fn default_priority() -> i32 {
    100
}
fn default_severity() -> u8 {
    5
}

impl DevicePolicy {
    /// Returns true iff this policy is `enabled` and its match
    /// block is satisfied by `cand`.
    pub fn matches(&self, cand: &DeviceCandidate) -> bool {
        if !self.enabled {
            return false;
        }
        if self.device_class != cand.device_class {
            return false;
        }
        let m = &self.match_block;
        if let Some(want) = m.vendor_id.as_deref() {
            match cand.vendor_id.as_deref() {
                Some(got) if got.eq_ignore_ascii_case(want) => {}
                _ => return false,
            }
        }
        if let Some(want) = m.product_id.as_deref() {
            match cand.product_id.as_deref() {
                Some(got) if got.eq_ignore_ascii_case(want) => {}
                _ => return false,
            }
        }
        if let Some(want) = m.serial.as_deref() {
            match cand.serial.as_deref() {
                Some(got) if got == want => {}
                _ => return false,
            }
        }
        if let Some(want) = m.bus.as_deref() {
            match cand.bus_path.as_deref() {
                Some(got) if got.contains(want) => {}
                _ => return false,
            }
        }
        true
    }
}

/// Evaluator built once per bundle apply.
///
/// Cheap to clone (`Arc` internally) so callers should pass
/// references and clone only when handing the set to a worker.
#[derive(Debug, Clone, Default)]
pub struct DevicePolicySet {
    inner: Arc<PolicySetInner>,
}

#[derive(Debug, Default)]
struct PolicySetInner {
    /// Pre-sorted by (priority, id) so evaluation is a linear scan
    /// of pre-ranked rules. The first match wins.
    sorted: Vec<DevicePolicy>,
    /// Sentinel from PROPOSAL § D2.7: `false` means the bundle
    /// explicitly carried no policies (or is unverified). The
    /// agent uses this to distinguish "tenant has no rules" from
    /// "tampered bundle, keep last-known-good".
    enabled: bool,
}

impl DevicePolicySet {
    /// Empty, **disabled** policy set. Used as the boot-time
    /// closed-by-default sentinel. Until a verified bundle lands,
    /// [`Self::evaluate`] returns the configured default action
    /// (typically `Audit`); this set itself never blocks.
    pub fn empty_disabled() -> Self {
        Self::default()
    }

    /// Build an *enabled* set from already-validated rows.
    pub fn from_rows(mut rows: Vec<DevicePolicy>) -> Self {
        rows.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
        Self {
            inner: Arc::new(PolicySetInner {
                sorted: rows,
                enabled: true,
            }),
        }
    }

    /// Parse `policy/device-control/policies.json`. The slice is a
    /// JSON array of [`DevicePolicy`] rows with the schema documented
    /// in [`crate::usb_policy`].
    ///
    /// Slices larger than [`POLICY_SLICE_MAX_BYTES`] are rejected
    /// without parsing — this guards against a tampered or
    /// pathologically large bundle starving the agent.
    pub fn parse_slice(bytes: &[u8]) -> Result<Self, PolicySetError> {
        if bytes.len() > POLICY_SLICE_MAX_BYTES {
            return Err(PolicySetError::SliceTooLarge {
                got: bytes.len(),
                limit: POLICY_SLICE_MAX_BYTES,
            });
        }
        let rows: Vec<serde_json::Value> = serde_json::from_slice(bytes)?;
        let mut parsed = Vec::with_capacity(rows.len());
        for v in rows {
            // Re-deserialize with `serde` so we get strict
            // unknown-field rejection from `deny_unknown_fields`,
            // and enrich the error path with the row id when one
            // is present.
            let row: DevicePolicy = serde_json::from_value(v.clone()).map_err(|err| {
                if let Some(id) = v.get("id").and_then(|v| v.as_str()) {
                    if let Some(action) = v.get("action").and_then(|v| v.as_str()) {
                        if Action::deserialize(serde_json::Value::String(action.into())).is_err() {
                            return PolicySetError::UnknownAction {
                                id: id.to_string(),
                                action: action.into(),
                            };
                        }
                    }
                    if let Some(class) = v.get("device_class").and_then(|v| v.as_str()) {
                        if DeviceClass::parse(class).is_none() {
                            return PolicySetError::UnknownDeviceClass {
                                id: id.to_string(),
                                device_class: class.into(),
                            };
                        }
                    }
                }
                PolicySetError::Json(err)
            })?;
            parsed.push(row);
        }
        Ok(Self::from_rows(parsed))
    }

    /// Number of rows in the set (including disabled rows).
    pub fn len(&self) -> usize {
        self.inner.sorted.len()
    }

    /// `true` when [`Self::len`] is zero.
    pub fn is_empty(&self) -> bool {
        self.inner.sorted.is_empty()
    }

    /// `true` when the set was built from a successfully verified
    /// bundle. Empty-but-enabled is the legitimate "no rules
    /// authored" state; empty-and-disabled is the boot-time
    /// sentinel.
    pub fn is_enabled(&self) -> bool {
        self.inner.enabled
    }

    /// Iterator over the sorted policies for diagnostics.
    pub fn policies(&self) -> impl ExactSizeIterator<Item = &DevicePolicy> {
        self.inner.sorted.iter()
    }

    /// Evaluate `cand` against the set.
    ///
    /// Returns the first match in priority order, or
    /// `default_action` if no rule matches. `default_action` is
    /// the configured policy when the set is enabled; when the set
    /// is disabled (boot, tampered bundle) the caller should pass
    /// the configured *fallback* default.
    pub fn evaluate(&self, cand: &DeviceCandidate, default_action: Action) -> Decision {
        for p in &self.inner.sorted {
            if p.matches(cand) {
                return Decision {
                    action: p.action,
                    matched_policy_id: Some(p.id.clone()),
                    matched_policy_name: Some(p.name.clone()),
                    severity: p.severity,
                };
            }
        }
        Decision {
            action: default_action,
            matched_policy_id: None,
            matched_policy_name: None,
            severity: 5,
        }
    }
}

/// Outcome of [`DevicePolicySet::evaluate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_policy_name: Option<String>,
    pub severity: u8,
}

impl Decision {
    /// Build the canonical-JSON audit envelope expected by the
    /// `sn360-device-control` Wazuh decoder. The structure is:
    ///
    /// ```json
    /// {
    ///   "connector_type": "device-control",
    ///   "tenant_id": "...",
    ///   "decision": "block",
    ///   "device": { "device_class": "usb", "vendor_id": "...", ... },
    ///   "matched_policy": { "id": "...", "name": "...", "severity": 9 },
    ///   "default_action_used": false
    /// }
    /// ```
    ///
    /// Returns RFC 8785 canonical JSON so per-tenant signature
    /// re-checks (the gateway may sign forwarded events) are byte-
    /// stable.
    pub fn to_event_payload(
        &self,
        tenant_id: &str,
        cand: &DeviceCandidate,
    ) -> Result<String, crate::CanonicalizeError> {
        let payload = serde_json::json!({
            "connector_type": "device-control",
            "tenant_id": tenant_id,
            "decision": match self.action {
                Action::Block => "block",
                Action::Allow => "allow",
                Action::Audit => "audit",
            },
            "device": cand,
            "matched_policy": match (&self.matched_policy_id, &self.matched_policy_name) {
                (Some(id), Some(name)) => serde_json::json!({
                    "id": id,
                    "name": name,
                    "severity": self.severity,
                }),
                _ => serde_json::Value::Null,
            },
            "default_action_used": self.matched_policy_id.is_none(),
        });
        let bytes = canonicalize_json(&payload)?;
        // canonicalize() guarantees ASCII-only output (RFC 8785).
        Ok(String::from_utf8(bytes).expect("canonicalize emits ASCII"))
    }
}

/// Thread-safe holder backed by an [`arc_swap::ArcSwap`]-equivalent
/// using the standard library so we don't pull in a new dep.
///
/// The store always returns a `Arc<DevicePolicySet>` to readers;
/// writers atomically swap a freshly-built set in. The previous
/// set lives until the last reader drops its `Arc`.
#[derive(Debug)]
pub struct DevicePolicyStore {
    inner: std::sync::RwLock<Arc<DevicePolicySet>>,
    /// Configured default action used when no rule matches OR the
    /// set is disabled (boot / tampered-bundle path).
    default_action: Action,
    /// Boot-time fallback used when the set is disabled. By
    /// default this is `Audit` — the agent records every attach
    /// event without changing OS behaviour until a verified bundle
    /// arrives. Operators can opt in to closed-by-default
    /// (`Block`) via `modules.device_control.usb_policy.fallback_action`.
    fallback_action: Action,
}

impl DevicePolicyStore {
    /// Build a fresh store seeded with the boot-time sentinel
    /// (empty + disabled). Until [`Self::apply`] is called the
    /// store evaluates every candidate using `fallback_action`.
    pub fn new(default_action: Action, fallback_action: Action) -> Self {
        Self {
            inner: std::sync::RwLock::new(Arc::new(DevicePolicySet::empty_disabled())),
            default_action,
            fallback_action,
        }
    }

    /// Atomic compare-and-swap apply. Always succeeds — the
    /// caller is responsible for verifying the bundle signature
    /// before constructing `new_set`. Returns the previous set so
    /// callers can log a diff for the audit pipeline.
    pub fn apply(&self, new_set: DevicePolicySet) -> Arc<DevicePolicySet> {
        let new_arc = Arc::new(new_set);
        let mut guard = self
            .inner
            .write()
            .expect("DevicePolicyStore RwLock poisoned");
        std::mem::replace(&mut *guard, new_arc)
    }

    /// Cheap reader. Clones the inner `Arc`, never the policy data.
    pub fn current(&self) -> Arc<DevicePolicySet> {
        self.inner
            .read()
            .expect("DevicePolicyStore RwLock poisoned")
            .clone()
    }

    /// Convenience: evaluate without requiring callers to plumb
    /// the fallback through manually.
    pub fn evaluate(&self, cand: &DeviceCandidate) -> Decision {
        let set = self.current();
        let default = if set.is_enabled() {
            self.default_action
        } else {
            self.fallback_action
        };
        set.evaluate(cand, default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_all_usb() -> DevicePolicy {
        DevicePolicy {
            id: "00000000-0000-0000-0000-000000000001".into(),
            tenant_id: "tenant-a".into(),
            name: "block all usb".into(),
            enabled: true,
            device_class: DeviceClass::Usb,
            match_block: PolicyMatch::default(),
            action: Action::Block,
            priority: 100,
            severity: 7,
        }
    }

    fn allow_apple_keyboard() -> DevicePolicy {
        DevicePolicy {
            id: "00000000-0000-0000-0000-000000000002".into(),
            tenant_id: "tenant-a".into(),
            name: "allow apple keyboard".into(),
            enabled: true,
            device_class: DeviceClass::Usb,
            match_block: PolicyMatch {
                vendor_id: Some("05ac".into()),
                product_id: Some("0220".into()),
                ..Default::default()
            },
            action: Action::Allow,
            priority: 10,
            severity: 1,
        }
    }

    fn usb_candidate(vendor: &str, product: &str) -> DeviceCandidate {
        DeviceCandidate {
            device_class: DeviceClass::Usb,
            vendor_id: Some(vendor.into()),
            product_id: Some(product.into()),
            serial: None,
            bus_path: None,
        }
    }

    #[test]
    fn priority_order_allow_beats_block() {
        let set = DevicePolicySet::from_rows(vec![block_all_usb(), allow_apple_keyboard()]);
        let decision = set.evaluate(&usb_candidate("05ac", "0220"), Action::Audit);
        assert_eq!(decision.action, Action::Allow);
        assert_eq!(
            decision.matched_policy_name.as_deref(),
            Some("allow apple keyboard")
        );
    }

    #[test]
    fn block_when_specific_match_misses() {
        let set = DevicePolicySet::from_rows(vec![block_all_usb(), allow_apple_keyboard()]);
        let decision = set.evaluate(&usb_candidate("1234", "5678"), Action::Audit);
        assert_eq!(decision.action, Action::Block);
    }

    #[test]
    fn no_match_falls_back_to_default() {
        let set = DevicePolicySet::from_rows(vec![allow_apple_keyboard()]);
        let cand = DeviceCandidate {
            device_class: DeviceClass::Bluetooth,
            ..Default::default()
        };
        assert_eq!(set.evaluate(&cand, Action::Audit).action, Action::Audit);
        assert_eq!(set.evaluate(&cand, Action::Block).action, Action::Block);
    }

    #[test]
    fn vendor_match_is_case_insensitive() {
        let set = DevicePolicySet::from_rows(vec![allow_apple_keyboard()]);
        let cand = usb_candidate("05AC", "0220");
        assert_eq!(set.evaluate(&cand, Action::Audit).action, Action::Allow);
    }

    #[test]
    fn disabled_policy_is_skipped() {
        let mut p = block_all_usb();
        p.enabled = false;
        let set = DevicePolicySet::from_rows(vec![p]);
        let decision = set.evaluate(&usb_candidate("0", "0"), Action::Audit);
        assert_eq!(decision.action, Action::Audit);
        assert!(decision.matched_policy_id.is_none());
    }

    #[test]
    fn parse_slice_round_trips() {
        let rows = vec![block_all_usb(), allow_apple_keyboard()];
        let bytes = serde_json::to_vec(&rows).unwrap();
        let set = DevicePolicySet::parse_slice(&bytes).unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.is_enabled());
    }

    #[test]
    fn parse_slice_rejects_unknown_action() {
        let raw = r#"[{"id":"1","tenant_id":"t","name":"x","device_class":"usb","action":"shred","priority":1}]"#;
        let err = DevicePolicySet::parse_slice(raw.as_bytes()).unwrap_err();
        assert!(
            matches!(err, PolicySetError::UnknownAction { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_slice_rejects_oversized_input() {
        let big = vec![b'x'; POLICY_SLICE_MAX_BYTES + 1];
        let err = DevicePolicySet::parse_slice(&big).unwrap_err();
        assert!(matches!(err, PolicySetError::SliceTooLarge { .. }));
    }

    #[test]
    fn parse_slice_accepts_unknown_device_class_via_other_bucket() {
        // Forward-compat: a future class lands as `Other`. The
        // policy still parses (so the bundle does not get
        // rejected wholesale), it just never matches a real
        // candidate because no candidate ever reports `Other`.
        let raw = r#"[{"id":"1","tenant_id":"t","name":"x","device_class":"future-thing","action":"audit","priority":1}]"#;
        let set = DevicePolicySet::parse_slice(raw.as_bytes()).unwrap();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn cas_swap_takes_effect_immediately_for_subsequent_attaches() {
        let store = DevicePolicyStore::new(Action::Audit, Action::Audit);

        // Pre-CAS: no rules, audit-on-empty.
        assert_eq!(
            store.evaluate(&usb_candidate("05ac", "0220")).action,
            Action::Audit
        );

        // CAS in a block-all set; next read sees the new set.
        let prev = store.apply(DevicePolicySet::from_rows(vec![block_all_usb()]));
        assert!(!prev.is_enabled(), "previous was the empty boot sentinel");
        assert_eq!(
            store.evaluate(&usb_candidate("05ac", "0220")).action,
            Action::Block
        );

        // CAS in a more-permissive set; no flapping.
        let _ = store.apply(DevicePolicySet::from_rows(vec![allow_apple_keyboard()]));
        assert_eq!(
            store.evaluate(&usb_candidate("05ac", "0220")).action,
            Action::Allow
        );
    }

    #[test]
    fn boot_time_fallback_used_until_first_apply() {
        let store = DevicePolicyStore::new(Action::Audit, Action::Block);
        // Disabled boot sentinel routes through `fallback_action`.
        assert_eq!(
            store.evaluate(&usb_candidate("0", "0")).action,
            Action::Block
        );

        // Once a verified bundle lands, the *enabled* default
        // applies for unmatched candidates.
        store.apply(DevicePolicySet::from_rows(vec![allow_apple_keyboard()]));
        assert_eq!(
            store.evaluate(&usb_candidate("0", "0")).action,
            Action::Audit
        );
    }

    #[test]
    fn closed_by_default_invariant_unverified_bundle_keeps_last_known_good() {
        // Simulate D2.7: agent has a valid set; a tampered bundle
        // arrives. The orchestration layer is responsible for not
        // calling `apply` with the tampered slice, so the store
        // continues to evaluate against the previously-applied set.
        let store = DevicePolicyStore::new(Action::Audit, Action::Audit);
        store.apply(DevicePolicySet::from_rows(vec![block_all_usb()]));
        // The orchestrator detects a verification failure and
        // intentionally does NOT call `apply`. Subsequent attaches
        // still see the block.
        assert_eq!(
            store.evaluate(&usb_candidate("0", "0")).action,
            Action::Block
        );
    }

    #[test]
    fn decision_to_event_payload_is_canonical_json() {
        let set = DevicePolicySet::from_rows(vec![block_all_usb()]);
        let decision = set.evaluate(&usb_candidate("05ac", "0220"), Action::Audit);
        let payload = decision
            .to_event_payload("tenant-a", &usb_candidate("05ac", "0220"))
            .expect("canonicalize");

        // RFC 8785: keys sorted, no whitespace.
        assert!(payload.contains(r#""connector_type":"device-control""#));
        assert!(payload.contains(r#""decision":"block""#));
        assert!(payload.contains(r#""tenant_id":"tenant-a""#));
        assert!(
            payload.contains(r#""matched_policy":{"id":"00000000-0000-0000-0000-000000000001""#)
        );
        // Stable across re-canonicalisation.
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let recanon = canonicalize_json(&parsed).unwrap();
        assert_eq!(payload.as_bytes(), recanon.as_slice());
    }
}
