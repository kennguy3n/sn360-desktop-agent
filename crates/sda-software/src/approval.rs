//! Approval-state surfacing (Phase 2.9).
//!
//! Compares the local set of installed packages (typically reported
//! by `sda-pal::package_manager::PackageManager`) against the latest
//! verified [`Catalogue`](crate::catalogue::Catalogue) and produces
//! plain-English [`DeviceControlRecommendation`] payloads for any
//! installed package whose catalogue row is *not* `Approved`.
//!
//! The control plane owns the canonical
//! `Recommendation` schema (see
//! `docs/wire-protocols/device-control.md` § 6); on the agent side we only
//! need to *emit* equivalent JSON via `EventKind::DeviceControlRecommendation`,
//! so this module builds the JSON value directly through `serde_json`
//! rather than taking a dependency on `sda-device-control`. This keeps
//! the dependency graph acyclic — `sda-device-control` is the consumer
//! of the bus, not a producer here.
//!
//! ## Behaviour matrix
//!
//! | catalogue `approval_state` | parsed [`ApprovalState`]    | recommendation emitted? | plain English                                          |
//! |---------------------------|-----------------------------|-------------------------|--------------------------------------------------------|
//! | `"Approved"`              | [`ApprovalState::Approved`] | no                      | —                                                      |
//! | `"Pending"`               | [`ApprovalState::Pending`]  | yes                     | "Package <id> is pending administrator approval…"      |
//! | `"Denied"`                | [`ApprovalState::Denied`]   | yes                     | "Package <id> was denied by your administrator…"       |
//! | `"Recalled"`              | [`ApprovalState::Recalled`] | yes                     | "Package <id> was recalled by your administrator…"     |
//! | not in catalogue at all   | [`ApprovalState::Unknown`]  | yes                     | "Package <id> is not on your organisation's approved…" |
//!
//! Packages that are `Approved` and present in the catalogue produce
//! no recommendation — the agent only surfaces *deviations*.
//!
//! ## State transitions
//!
//! [`ApprovalAuditor::evaluate`] is purely functional and stateless;
//! the caller is expected to wrap it in a loop that drives a refreshed
//! [`Catalogue`] and a refreshed installed-package list each tick.
//! [`ApprovalAuditor::diff`] additionally reports state transitions
//! since the last evaluation so the supervisor can debounce
//! redundant emissions when nothing changed.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::catalogue::Catalogue;

/// SDA-side mirror of the catalogue's `approval_state` field, plus a
/// distinct [`Self::Unknown`] for installed packages that are not
/// listed in the catalogue at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApprovalState {
    /// Catalogue says this package is approved.
    Approved,
    /// Catalogue lists the package but it has not yet been signed off.
    Pending,
    /// Catalogue lists the package and explicitly denies it.
    Denied,
    /// Catalogue lists the package and tagged it as recalled (was
    /// approved, has since been pulled back by the operator).
    Recalled,
    /// Package is installed locally but missing from the catalogue.
    Unknown,
}

impl ApprovalState {
    /// Parse the catalogue's free-form `approval_state` string into an
    /// [`ApprovalState`]. Comparison is case-insensitive so that
    /// catalogues authored on different platforms agree.
    ///
    /// Unknown / empty strings collapse to [`Self::Unknown`] —
    /// strict catalogue authors should pin one of the four canonical
    /// values.
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "approved" => Self::Approved,
            "pending" => Self::Pending,
            "denied" => Self::Denied,
            "recalled" => Self::Recalled,
            _ => Self::Unknown,
        }
    }

    /// Whether this state warrants a `DeviceControlRecommendation`
    /// emission. `Approved` is silent; everything else gets surfaced.
    pub fn is_actionable(self) -> bool {
        !matches!(self, Self::Approved)
    }
}

/// Best-effort description of a locally installed package.
///
/// `id` is the PAL identifier (`Mozilla.Firefox`, `firefox`,
/// `org.mozilla.firefox`, …) and must match the catalogue's `id`
/// field for a hit. `version` is informational; mismatched versions
/// of an `Approved` package are silent today (a future task may flag
/// "approved but wrong version" as an additional state).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InstalledPackage {
    pub id: String,
    pub version: String,
}

impl InstalledPackage {
    /// Convenience constructor used heavily in unit tests.
    pub fn new(id: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            version: version.into(),
        }
    }
}

/// One package's approval-state classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalEvaluation {
    pub package_id: String,
    pub installed_version: String,
    pub state: ApprovalState,
    /// Plain-English explanation, suitable for surfacing on a tray
    /// UI or in a recommendation payload. Capped at
    /// `RECOMMENDATION_PLAIN_ENGLISH_MAX` (512 chars), matching
    /// docs/wire-protocols/device-control.md § 2.4.
    pub plain_english: String,
}

/// Result of a single [`ApprovalAuditor::diff`] run.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApprovalDiff {
    /// All currently-actionable evaluations (i.e. not [`ApprovalState::Approved`]).
    pub current: Vec<ApprovalEvaluation>,
    /// Evaluations whose state changed since the last [`ApprovalAuditor::diff`]
    /// call (or which appeared for the first time).
    pub transitions: Vec<ApprovalTransition>,
}

/// One state transition detected between two consecutive audits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalTransition {
    pub package_id: String,
    pub previous: Option<ApprovalState>,
    pub current: ApprovalState,
}

/// Stateful evaluator. Keeps the previous tick's classifications in
/// memory so [`Self::diff`] can suppress redundant recommendation
/// emissions on subsequent refreshes.
#[derive(Debug, Default, Clone)]
pub struct ApprovalAuditor {
    last: BTreeMap<String, ApprovalState>,
}

impl ApprovalAuditor {
    /// Construct a fresh auditor with no remembered history.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stateless evaluation — classify each installed package against
    /// the catalogue and return one [`ApprovalEvaluation`] per
    /// package. Emits an entry for **every** package, including
    /// approved ones, so callers can render a complete table; use
    /// [`ApprovalEvaluation::state`]'s [`ApprovalState::is_actionable`]
    /// helper to filter to non-approved rows.
    pub fn evaluate(
        &self,
        installed: &[InstalledPackage],
        catalogue: &Catalogue,
    ) -> Vec<ApprovalEvaluation> {
        installed
            .iter()
            .map(|pkg| {
                let state = catalogue
                    .get(&pkg.id)
                    .map(|art| ApprovalState::parse(&art.approval_state))
                    .unwrap_or(ApprovalState::Unknown);
                ApprovalEvaluation {
                    package_id: pkg.id.clone(),
                    installed_version: pkg.version.clone(),
                    plain_english: render_plain_english(&pkg.id, state),
                    state,
                }
            })
            .collect()
    }

    /// Stateful evaluation — runs [`Self::evaluate`] and additionally
    /// reports state transitions relative to the previous call. The
    /// internal cache is updated *only* with the current actionable
    /// (non-Approved) classifications so that an installed package
    /// re-entering an actionable state on a subsequent tick still
    /// produces a transition.
    ///
    /// Approved packages are pruned from the diff's `current` list
    /// because callers want to react to deviations only.
    pub fn diff(&mut self, installed: &[InstalledPackage], catalogue: &Catalogue) -> ApprovalDiff {
        let evaluations = self.evaluate(installed, catalogue);
        let mut transitions = Vec::new();
        let mut next: BTreeMap<String, ApprovalState> = BTreeMap::new();
        let mut current_actionable = Vec::new();

        for eval in &evaluations {
            let previous = self.last.get(&eval.package_id).copied();
            if previous != Some(eval.state) {
                transitions.push(ApprovalTransition {
                    package_id: eval.package_id.clone(),
                    previous,
                    current: eval.state,
                });
            }
            if eval.state.is_actionable() {
                next.insert(eval.package_id.clone(), eval.state);
                current_actionable.push(eval.clone());
            }
        }

        // Packages that disappeared from the installed list since
        // last tick — surface a transition to None so a downstream
        // operator UI can clear stale rows. We deliberately do not
        // emit a `DeviceControlRecommendation` for these, since the
        // package is no longer on the device.
        for (pkg_id, prev_state) in &self.last {
            if !next.contains_key(pkg_id) && !evaluations.iter().any(|e| &e.package_id == pkg_id) {
                transitions.push(ApprovalTransition {
                    package_id: pkg_id.clone(),
                    previous: Some(*prev_state),
                    current: ApprovalState::Approved, // sentinel: cleared
                });
            }
        }

        self.last = next;

        ApprovalDiff {
            current: current_actionable,
            transitions,
        }
    }
}

/// Build the canonical JSON payload to wrap in
/// [`sda_event_bus::EventKind::DeviceControlRecommendation`].
///
/// Mirrors the `Recommendation` schema in docs/wire-protocols/device-control.md § 6:
/// `recommendation_id`, `tenant_id`, `device_ids`, `finding_ids`,
/// `action`, `args`, `plain_english`, `one_click`, `severity`,
/// `created_at`, `schema_version` (1).
///
/// The agent does not own a finding for the package directly;
/// `finding_ids` is left empty here — the supervisor task that owns
/// the [`ApprovalAuditor`] is expected to insert the relevant
/// `DeviceControlFinding` ids before marshalling onto the bus
/// (see Phase 2.9 wiring in [`crate::module`]).
pub fn build_recommendation_payload(
    eval: &ApprovalEvaluation,
    tenant_id: Uuid,
    device_id: Uuid,
    now: DateTime<Utc>,
) -> String {
    let action = match eval.state {
        ApprovalState::Recalled | ApprovalState::Denied => "uninstall_package",
        ApprovalState::Pending => "update_package",
        // Unknown installed packages are flagged for inventory only.
        ApprovalState::Unknown => "uninstall_package",
        // Approved packages should never reach this function but we
        // handle the case to keep the function total.
        ApprovalState::Approved => "update_package",
    };
    let severity = match eval.state {
        ApprovalState::Recalled => "high",
        ApprovalState::Denied => "high",
        ApprovalState::Pending => "low",
        ApprovalState::Unknown => "medium",
        ApprovalState::Approved => "info",
    };
    let value = json!({
        "recommendation_id": Uuid::new_v4(),
        "tenant_id":         tenant_id,
        "schema_version":    1,
        "device_ids":        [device_id],
        "finding_ids":       [],
        "action":            action,
        "args":              {
            "package_id": eval.package_id,
            "channel":    "stable",
        },
        "plain_english":     eval.plain_english,
        "one_click":         eval.state != ApprovalState::Unknown,
        "severity":          severity,
        "created_at":        now,
    });
    serde_json::to_string(&value).expect("serde_json::to_string of a Value is infallible")
}

/// Hard cap on the recommendation `plain_english` body — kept in
/// sync with `sda-device-control::recommendation::RECOMMENDATION_PLAIN_ENGLISH_MAX`.
/// Duplicated here to avoid taking a build-time dependency on
/// `sda-device-control`.
pub const RECOMMENDATION_PLAIN_ENGLISH_MAX: usize = 512;

fn render_plain_english(package_id: &str, state: ApprovalState) -> String {
    let raw = match state {
        ApprovalState::Approved => format!(
            "Package {package_id} is approved by your administrator and is up to date with the catalogue."
        ),
        ApprovalState::Pending => format!(
            "Package {package_id} is pending administrator approval. The agent will not initiate further changes until it is approved or denied."
        ),
        ApprovalState::Denied => format!(
            "Package {package_id} was denied by your administrator. The agent will recommend uninstalling it."
        ),
        ApprovalState::Recalled => format!(
            "Package {package_id} was recalled by your administrator. The agent will recommend uninstalling it."
        ),
        ApprovalState::Unknown => format!(
            "Package {package_id} is not on your organisation's approved catalogue. Please review with your administrator."
        ),
    };
    truncate_chars(&raw, RECOMMENDATION_PLAIN_ENGLISH_MAX)
}

/// Truncate a `&str` to a maximum number of *Unicode scalar values*
/// (chars), matching docs/wire-protocols/device-control.md § 2.4's char-based cap.
fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    s.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Artefact, Manifest, MANIFEST_SCHEMA_VERSION};
    use chrono::TimeZone;

    fn art(id: &str, approval: &str) -> Artefact {
        Artefact {
            id: id.into(),
            name: id.into(),
            version: "1.0".into(),
            url: "https://example.test/a".into(),
            sha256: "0".repeat(64),
            approval_state: approval.into(),
        }
    }

    fn catalogue(rows: Vec<Artefact>) -> Catalogue {
        let m = Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            catalogue_id: "test".into(),
            revision: 1,
            signed_at: None,
            artefacts: rows,
            key_id: "k".into(),
            signature: String::new(),
        };
        Catalogue::from_manifest(m).expect("test manifest builds a catalogue")
    }

    #[test]
    fn parse_is_case_insensitive() {
        assert_eq!(ApprovalState::parse("Approved"), ApprovalState::Approved);
        assert_eq!(ApprovalState::parse("approved"), ApprovalState::Approved);
        assert_eq!(ApprovalState::parse("PENDING"), ApprovalState::Pending);
        assert_eq!(ApprovalState::parse(" Denied "), ApprovalState::Denied);
        assert_eq!(ApprovalState::parse("recalled"), ApprovalState::Recalled);
        assert_eq!(ApprovalState::parse(""), ApprovalState::Unknown);
        assert_eq!(ApprovalState::parse("garbage"), ApprovalState::Unknown);
    }

    #[test]
    fn approved_is_not_actionable() {
        assert!(!ApprovalState::Approved.is_actionable());
        assert!(ApprovalState::Pending.is_actionable());
        assert!(ApprovalState::Denied.is_actionable());
        assert!(ApprovalState::Recalled.is_actionable());
        assert!(ApprovalState::Unknown.is_actionable());
    }

    #[test]
    fn evaluate_classifies_each_state_correctly() {
        let cat = catalogue(vec![
            art("ok-pkg", "Approved"),
            art("hold-pkg", "Pending"),
            art("blocked-pkg", "Denied"),
            art("pulled-pkg", "Recalled"),
        ]);
        let installed = vec![
            InstalledPackage::new("ok-pkg", "1.0"),
            InstalledPackage::new("hold-pkg", "0.9"),
            InstalledPackage::new("blocked-pkg", "2.0"),
            InstalledPackage::new("pulled-pkg", "3.0"),
            InstalledPackage::new("ghost-pkg", "0.1"),
        ];
        let auditor = ApprovalAuditor::new();
        let out = auditor.evaluate(&installed, &cat);
        let by_id: BTreeMap<_, _> = out.iter().map(|e| (e.package_id.as_str(), e)).collect();

        assert_eq!(by_id["ok-pkg"].state, ApprovalState::Approved);
        assert_eq!(by_id["hold-pkg"].state, ApprovalState::Pending);
        assert_eq!(by_id["blocked-pkg"].state, ApprovalState::Denied);
        assert_eq!(by_id["pulled-pkg"].state, ApprovalState::Recalled);
        assert_eq!(by_id["ghost-pkg"].state, ApprovalState::Unknown);

        // Plain-English bodies are stable, deterministic, and contain
        // the package id so operators can grep their own logs.
        assert!(by_id["hold-pkg"].plain_english.contains("hold-pkg"));
        assert!(by_id["blocked-pkg"].plain_english.contains("denied"));
        assert!(by_id["pulled-pkg"].plain_english.contains("recalled"));
        assert!(by_id["ghost-pkg"]
            .plain_english
            .contains("not on your organisation"));
    }

    #[test]
    fn diff_emits_initial_transitions_for_actionable_packages() {
        let cat = catalogue(vec![
            art("ok-pkg", "Approved"),
            art("hold-pkg", "Pending"),
            art("blocked-pkg", "Denied"),
        ]);
        let installed = vec![
            InstalledPackage::new("ok-pkg", "1.0"),
            InstalledPackage::new("hold-pkg", "0.9"),
            InstalledPackage::new("blocked-pkg", "2.0"),
        ];
        let mut auditor = ApprovalAuditor::new();
        let diff = auditor.diff(&installed, &cat);

        // The Approved package does *not* appear in `current` because
        // we only surface deviations.
        assert_eq!(diff.current.len(), 2);
        let ids: Vec<_> = diff.current.iter().map(|e| e.package_id.as_str()).collect();
        assert!(ids.contains(&"hold-pkg"));
        assert!(ids.contains(&"blocked-pkg"));

        // Every package — including Approved ones — produces a
        // transition on the first run, because there is no prior
        // history.
        assert_eq!(diff.transitions.len(), 3);
    }

    #[test]
    fn diff_suppresses_unchanged_states_on_subsequent_calls() {
        let cat = catalogue(vec![art("hold-pkg", "Pending")]);
        let installed = vec![InstalledPackage::new("hold-pkg", "0.9")];
        let mut auditor = ApprovalAuditor::new();
        let _ = auditor.diff(&installed, &cat);
        let diff = auditor.diff(&installed, &cat);
        // `current` still reflects the actionable state; transitions
        // is empty because nothing changed.
        assert_eq!(diff.current.len(), 1);
        assert_eq!(diff.transitions.len(), 0);
    }

    #[test]
    fn diff_reports_state_transitions_when_catalogue_changes() {
        let cat_pending = catalogue(vec![art("hold-pkg", "Pending")]);
        let cat_recalled = catalogue(vec![art("hold-pkg", "Recalled")]);
        let installed = vec![InstalledPackage::new("hold-pkg", "0.9")];
        let mut auditor = ApprovalAuditor::new();
        let _ = auditor.diff(&installed, &cat_pending);
        let diff = auditor.diff(&installed, &cat_recalled);
        assert_eq!(diff.transitions.len(), 1);
        let t = &diff.transitions[0];
        assert_eq!(t.package_id, "hold-pkg");
        assert_eq!(t.previous, Some(ApprovalState::Pending));
        assert_eq!(t.current, ApprovalState::Recalled);
    }

    #[test]
    fn diff_clears_disappeared_packages() {
        let cat = catalogue(vec![art("hold-pkg", "Pending")]);
        let installed = vec![InstalledPackage::new("hold-pkg", "0.9")];
        let mut auditor = ApprovalAuditor::new();
        let _ = auditor.diff(&installed, &cat);

        // Package uninstalled — empty installed list.
        let diff = auditor.diff(&[], &cat);
        assert!(diff.current.is_empty());
        // We surface a transition that the previously-actionable
        // package has been cleared. The `current` field of the
        // transition is the Approved sentinel.
        assert_eq!(diff.transitions.len(), 1);
        assert_eq!(diff.transitions[0].package_id, "hold-pkg");
        assert_eq!(diff.transitions[0].previous, Some(ApprovalState::Pending));
    }

    #[test]
    fn build_recommendation_payload_is_valid_canonical_json() {
        let eval = ApprovalEvaluation {
            package_id: "blocked-pkg".into(),
            installed_version: "1.0".into(),
            state: ApprovalState::Denied,
            plain_english: render_plain_english("blocked-pkg", ApprovalState::Denied),
        };
        let now = Utc.with_ymd_and_hms(2026, 5, 7, 8, 0, 0).unwrap();
        let payload = build_recommendation_payload(&eval, Uuid::nil(), Uuid::nil(), now);
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["action"], "uninstall_package");
        assert_eq!(value["severity"], "high");
        assert_eq!(value["one_click"], true);
        assert!(value["plain_english"].as_str().unwrap().contains("denied"));
        assert_eq!(value["args"]["package_id"], "blocked-pkg");
        // device_ids is a one-element array per docs/wire-protocols/device-control.md § 6.2.
        assert!(value["device_ids"].as_array().unwrap().len() == 1);
    }

    #[test]
    fn build_recommendation_payload_for_pending_uses_update_action() {
        let eval = ApprovalEvaluation {
            package_id: "hold-pkg".into(),
            installed_version: "0.9".into(),
            state: ApprovalState::Pending,
            plain_english: render_plain_english("hold-pkg", ApprovalState::Pending),
        };
        let now = Utc.with_ymd_and_hms(2026, 5, 7, 8, 0, 0).unwrap();
        let payload = build_recommendation_payload(&eval, Uuid::nil(), Uuid::nil(), now);
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(value["action"], "update_package");
        assert_eq!(value["severity"], "low");
    }

    #[test]
    fn plain_english_capped_at_512_chars_even_for_pathological_ids() {
        let huge_id = "x".repeat(2048);
        let body = render_plain_english(&huge_id, ApprovalState::Denied);
        assert!(body.chars().count() <= RECOMMENDATION_PLAIN_ENGLISH_MAX);
    }
}
