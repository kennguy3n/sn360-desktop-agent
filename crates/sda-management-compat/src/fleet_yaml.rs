//! Fleet GitOps YAML input schema.
//!
//! We deliberately model only the subset of Fleet's schema that
//! `docs/device-control.md` § 11 flags as portable. Anything not modelled here
//! is dropped on the floor with a `unknown_section` warning by
//! [`crate::translator::translate_yaml`] — there is intentionally no
//! `#[serde(deny_unknown_fields)]` on the top-level type because
//! Fleet's GitOps schema grows constantly and rejecting on every
//! new field would break customers' adoption flow on the next
//! Fleet release.
//!
//! The do-not-port list (`docs/device-control.md` § 11) is enforced positively:
//! we look for the named keys (`mdm`, `mobile_device_management`,
//! `ee`, …) and reject the YAML when we see them, rather than
//! relying on serde to ignore them.
//!
//! Reference: <https://fleetdm.com/docs/configuration/yaml-files>.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Top-level Fleet GitOps document.
///
/// Fleet supports both a single YAML file and a directory tree. We
/// only model the single-file form here; directory trees are
/// flattened upstream of this crate by the caller (typically the
/// control-plane onboarding service).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetConfig {
    /// Tenant identifier — Fleet calls this `team_name` or
    /// `org_name`. We require an explicit tenant on the SDA side
    /// (`tenant_id` arg to [`crate::translate_yaml`]) so this is
    /// only retained for cross-checking.
    #[serde(default)]
    pub team_name: Option<String>,

    /// Optional API version pin. Fleet uses `apiVersion: v1`. We
    /// accept any value but do not act on it; our translator is
    /// driven by the actual fields present.
    #[serde(default, rename = "apiVersion")]
    pub api_version: Option<String>,

    /// Scheduled osquery queries.
    #[serde(default)]
    pub queries: Vec<FleetQuery>,

    /// Compliance / detection policies.
    #[serde(default)]
    pub policies: Vec<FleetPolicy>,

    /// Software installers (Fleet calls these `software.packages`).
    #[serde(default)]
    pub software: Option<FleetSoftware>,

    /// Signed scripts (Fleet keeps these in a `scripts:` list of
    /// file paths under `controls.scripts`; we model them as a
    /// dedicated section to avoid coupling to the controls block).
    #[serde(default)]
    pub scripts: Vec<FleetScript>,

    /// Agent runtime knobs Fleet pushes to fleetd via
    /// `agent_options`.
    #[serde(default)]
    pub agent_options: Option<FleetAgentOptions>,

    /// Dynamic host groups (Fleet labels). The translator preserves
    /// the names but does not turn them into config — labels are a
    /// control-plane concept on SDA.
    #[serde(default)]
    pub labels: Vec<FleetLabel>,

    // ---------------------------------------------------------------
    // Fields we explicitly inspect for the do-not-port list.
    //
    // These are modelled as `serde_yaml::Value` rather than concrete
    // types because we never translate them — we only need to know
    // they were present so we can reject the document.
    // ---------------------------------------------------------------
    /// Fleet's `mdm` block (Apple MDM, Windows MDM). Triggers a
    /// rejection if non-null. `docs/device-control.md` § 11 + `docs/licensing.md` § 7.
    #[serde(default)]
    pub mdm: Option<serde_yaml::Value>,

    /// Alternate spelling of `mdm` Fleet uses in some docs.
    #[serde(default)]
    pub mobile_device_management: Option<serde_yaml::Value>,

    /// Fleet EE-licensed features live under `ee:` in some
    /// templates. Triggers a rejection.
    #[serde(default)]
    pub ee: Option<serde_yaml::Value>,

    /// Apple Volume Purchase Program — Fleet EE feature.
    #[serde(default)]
    pub vpp: Option<serde_yaml::Value>,

    /// Apple ADE / DEP enrollment — Fleet EE feature.
    #[serde(default)]
    pub automatic_enrollment: Option<serde_yaml::Value>,

    /// Catch-all for anything else Fleet adds. Surfaced via the
    /// translator as `unknown_section` warnings rather than fatal
    /// errors.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_yaml::Value>,
}

/// One scheduled osquery query, per Fleet's `queries` schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetQuery {
    pub name: String,
    /// SQL the osquery sidecar runs.
    pub query: String,
    /// Schedule interval in seconds. Fleet's default is 3600 s.
    #[serde(default = "default_query_interval_secs")]
    pub interval: u64,
    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Per-query platform restriction. Fleet uses
    /// `"linux,darwin,windows"`-style comma-separated lists.
    #[serde(default)]
    pub platform: Option<String>,
    /// Whether the query is paused. We translate `false` (the
    /// default) into an enabled query; `true` causes the translator
    /// to skip the query entirely.
    #[serde(default)]
    pub paused: bool,
}

fn default_query_interval_secs() -> u64 {
    3600
}

/// One Fleet policy: a boolean SQL query that returns "compliant"
/// rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetPolicy {
    pub name: String,
    pub query: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Operator-facing remediation text Fleet ships with each
    /// policy.
    #[serde(default)]
    pub resolution: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
    /// Severity is Fleet-EE only; we accept it on input but the
    /// translator drops it with an `ignored_field` warning.
    #[serde(default)]
    pub severity: Option<String>,
}

/// Top-level `software:` block. Fleet keeps a list of packages and
/// (in EE) a list of App Store apps. We only honour `packages`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetSoftware {
    #[serde(default)]
    pub packages: Vec<FleetSoftwarePackage>,

    /// Fleet EE: Apple App Store apps via VPP. Triggers a rejection
    /// if non-empty.
    #[serde(default)]
    pub app_store_apps: Vec<serde_yaml::Value>,
}

/// One Fleet software package. We keep the install URL / hash so
/// the control plane can re-sign it for the SDA catalogue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetSoftwarePackage {
    /// HTTPS URL Fleet downloads the package from.
    pub url: String,
    /// Optional SHA-256 of the package, lowercase hex.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Optional human-readable name for the package.
    #[serde(default)]
    pub name: Option<String>,
    /// Per-package install script (Fleet supports POSIX shell or
    /// PowerShell). Stored verbatim — the translator passes it to
    /// the script runner.
    #[serde(default)]
    pub install_script: Option<String>,
    /// Per-package uninstall script.
    #[serde(default)]
    pub uninstall_script: Option<String>,
}

/// One signed script Fleet ships under `controls.scripts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetScript {
    /// Stable name the operator references when invoking the
    /// script. Becomes the SDA `canonical_name`.
    pub name: String,
    /// Script body. The translator does NOT sign it — signing is
    /// the control plane's job. We pass the body through and let
    /// the catalogue producer sign.
    pub body: String,
    /// Platform the script is valid for. We translate Fleet's
    /// comma-separated string into the SDA per-platform allow-list.
    #[serde(default)]
    pub platform: Option<String>,
}

/// Fleet's `agent_options:` block — generic key/value bag pushed to
/// fleetd. We only translate the subset that maps onto SDA's
/// runtime config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetAgentOptions {
    /// Fleet's `command_line_flags.distributed_interval` (seconds).
    /// Translates to `modules.query.schedule_poll_secs` when
    /// present.
    #[serde(default)]
    pub distributed_interval: Option<u64>,
    /// Fleet's `config.options.logger_tls_period` — we ignore it
    /// (the SDA agent has its own logging stack).
    #[serde(default)]
    pub logger_tls_period: Option<u64>,
    /// Fleet's per-tenant maintenance window. Fleet calls this
    /// `update_channels.maintenance_window` in newer schemas; we
    /// treat any of the alias names as equivalent.
    #[serde(default)]
    pub maintenance_window: Option<FleetMaintenanceWindow>,
    /// Catch-all for anything else under `agent_options`.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_yaml::Value>,
}

/// Subset of Fleet's maintenance-window schema we honour.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetMaintenanceWindow {
    /// Local-time start in `HH:MM`.
    #[serde(default)]
    pub start: Option<String>,
    /// Local-time end in `HH:MM`.
    #[serde(default)]
    pub end: Option<String>,
    /// `mon`..`sun` days the window applies on.
    #[serde(default)]
    pub days: Vec<String>,
}

/// One Fleet label — a dynamic host group defined by an osquery
/// SQL query. SDA does not have a per-agent equivalent; the
/// translator emits these as control-plane hints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetLabel {
    pub name: String,
    /// SQL the label is computed from. Optional because Fleet also
    /// supports manual / static labels.
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
}
