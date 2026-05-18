//! Fleet → SDA-native translation.
//!
//! The translator operates in three passes:
//!
//! 1. **Reject pass** — bail on any presence of EE-only or
//!    do-not-port keys (`docs/device-control.md` § 11 + `docs/licensing.md` § 7). This is
//!    intentionally before any successful translation can be
//!    observed so partial output never leaks.
//! 2. **Tenant pass** — verify that Fleet's `team_name` is either
//!    absent or matches the SDA-side `tenant_id`. Cross-tenant data
//!    leakage must be impossible by construction, and the agent-side
//!    check is the last line of defence behind the control plane.
//! 3. **Translate pass** — walk each Fleet section and write into
//!    a fresh [`AgentConfig`]. Anything unrecognised is preserved
//!    only as a [`Translation::warnings`] entry.
//!
//! All warnings are non-fatal. Fatal conditions return
//! [`CompatError`]. The translator never panics on user input.

use std::collections::BTreeMap;

use sda_core::config::{
    AgentConfig, MaintenanceWindow, OsqueryConfig, QueryConfig, ScriptRunnerConfig, SoftwareConfig,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};

use crate::fleet_yaml::{FleetAgentOptions, FleetConfig, FleetLabel, FleetScript};

/// Result of a successful translation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Translation {
    /// Tenant the translation is scoped to. Agent-side modules
    /// must not load configuration that names a different tenant.
    pub tenant_id: String,
    /// SDA-native [`AgentConfig`] overlay produced from the Fleet
    /// document. The shim only writes into the sections it
    /// understands — the rest are left at their defaults.
    pub agent_config: AgentConfig,
    /// Fleet labels passed through verbatim. Labels are a
    /// control-plane concept on SDA; we preserve them so the
    /// onboarding service can register them as tag-based device
    /// groups.
    pub labels: Vec<TranslatedLabel>,
    /// Per-package install / uninstall scripts the catalogue
    /// producer needs to re-sign. The shim never signs them.
    pub package_scripts: Vec<TranslatedPackageScripts>,
    /// Non-fatal observations — unknown fields, EE-tinted opt-in
    /// flags we silently ignored, etc.
    pub warnings: Vec<String>,
}

/// Cross-platform label representation. Mirrors the Fleet shape
/// closely; the control plane normalises them further.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslatedLabel {
    pub name: String,
    pub query: Option<String>,
    pub description: Option<String>,
    pub platform: Option<String>,
}

impl From<&FleetLabel> for TranslatedLabel {
    fn from(l: &FleetLabel) -> Self {
        Self {
            name: l.name.clone(),
            query: l.query.clone(),
            description: l.description.clone(),
            platform: l.platform.clone(),
        }
    }
}

/// Per-package install / uninstall script bundle. The catalogue
/// producer re-signs these as part of the SDA signed catalogue
/// manifest — this crate only carries them across the gap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslatedPackageScripts {
    pub package_url: String,
    pub package_name: Option<String>,
    pub sha256: Option<String>,
    pub install_script: Option<String>,
    pub uninstall_script: Option<String>,
}

impl Translation {
    /// Encode the contained [`AgentConfig`] as YAML for direct
    /// inclusion in the agent's config file. Labels and package
    /// scripts are NOT serialised — they belong to the control
    /// plane onboarding flow and are exposed via
    /// [`Translation::labels`] / [`Translation::package_scripts`]
    /// for the caller to ship separately.
    pub fn to_yaml(&self) -> Result<String, CompatError> {
        serde_yaml::to_string(&self.agent_config).map_err(CompatError::Encode)
    }
}

/// Fatal translation errors. Anything that returns one of these
/// means the Fleet YAML cannot be loaded against an SDA agent
/// without operator intervention.
#[derive(Debug, Error)]
pub enum CompatError {
    /// Fleet YAML failed to parse against [`FleetConfig`].
    #[error("fleet yaml parse error: {0}")]
    Parse(#[source] serde_yaml::Error),

    /// Translated [`AgentConfig`] failed to encode back to YAML.
    #[error("encode error: {0}")]
    Encode(#[source] serde_yaml::Error),

    /// The document referenced an EE-only or do-not-port feature
    /// that `docs/licensing.md` § 7 forbids us from translating. The string
    /// identifies the offending key so the operator can remove it.
    #[error("rejected: {0} is on the do-not-port list (docs/device-control.md § 11 / docs/licensing.md § 7)")]
    UnsupportedFeature(&'static str),

    /// The document's `team_name` does not match the tenant the
    /// SDA agent is enrolled into. Catching this on the agent is
    /// belt-and-braces behind the control plane's row-level
    /// security; it is not the only line of defence.
    #[error("tenant mismatch: fleet team_name={fleet:?}, sda tenant_id={sda:?}")]
    TenantMismatch { fleet: String, sda: String },

    /// Caller passed an empty tenant_id. We refuse to translate in
    /// that case rather than silently scoping into the empty-string
    /// tenant.
    #[error("tenant_id must be non-empty")]
    EmptyTenant,
}

/// Translate a Fleet GitOps YAML document into an SDA-native
/// [`AgentConfig`] overlay scoped to `tenant_id`.
///
/// `tenant_id` is the SDA-side tenant the resulting config will be
/// loaded against. It is required (no default) so we cannot
/// accidentally scope a translation into the empty / default
/// tenant.
pub fn translate_yaml(yaml: &str, tenant_id: &str) -> Result<Translation, CompatError> {
    if tenant_id.is_empty() {
        return Err(CompatError::EmptyTenant);
    }

    let parsed: FleetConfig = serde_yaml::from_str(yaml).map_err(CompatError::Parse)?;
    translate(parsed, tenant_id)
}

/// Translate a pre-parsed Fleet document. Useful for tests and for
/// callers that already have a [`FleetConfig`] in hand.
pub fn translate(fleet: FleetConfig, tenant_id: &str) -> Result<Translation, CompatError> {
    if tenant_id.is_empty() {
        return Err(CompatError::EmptyTenant);
    }

    // Pass 1 — reject pass.
    reject_unsupported(&fleet)?;

    // Pass 2 — tenant pass.
    if let Some(team) = fleet.team_name.as_ref() {
        if !team.is_empty() && team != tenant_id {
            return Err(CompatError::TenantMismatch {
                fleet: team.clone(),
                sda: tenant_id.to_string(),
            });
        }
    }

    // Pass 3 — translate.
    let mut warnings = Vec::new();
    let mut agent_config = AgentConfig::default();

    translate_queries(&fleet, &mut agent_config, &mut warnings);
    translate_policies(&fleet, &mut warnings);
    translate_software(&fleet, &mut agent_config, &mut warnings);
    translate_scripts(&fleet, &mut agent_config, &mut warnings);
    translate_agent_options(&fleet, &mut agent_config, &mut warnings);

    let labels: Vec<TranslatedLabel> = fleet.labels.iter().map(TranslatedLabel::from).collect();
    let package_scripts = collect_package_scripts(&fleet);

    record_unknown_sections(&fleet.extra, &mut warnings);

    Ok(Translation {
        tenant_id: tenant_id.to_string(),
        agent_config,
        labels,
        package_scripts,
        warnings,
    })
}

/// Reject anything on `docs/device-control.md` § 11's do-not-port list. We
/// inspect specific keys rather than scanning for substrings so a
/// benign field like `mdm_enrolment_notes` would not trigger a
/// false positive.
fn reject_unsupported(fleet: &FleetConfig) -> Result<(), CompatError> {
    if !is_null(&fleet.mdm) {
        return Err(CompatError::UnsupportedFeature("mdm"));
    }
    if !is_null(&fleet.mobile_device_management) {
        return Err(CompatError::UnsupportedFeature("mobile_device_management"));
    }
    if !is_null(&fleet.ee) {
        return Err(CompatError::UnsupportedFeature("ee"));
    }
    if !is_null(&fleet.vpp) {
        return Err(CompatError::UnsupportedFeature("vpp"));
    }
    if !is_null(&fleet.automatic_enrollment) {
        return Err(CompatError::UnsupportedFeature("automatic_enrollment"));
    }
    if let Some(software) = fleet.software.as_ref() {
        if !software.app_store_apps.is_empty() {
            return Err(CompatError::UnsupportedFeature("software.app_store_apps"));
        }
    }
    Ok(())
}

fn is_null(v: &Option<serde_yaml::Value>) -> bool {
    match v {
        None => true,
        Some(serde_yaml::Value::Null) => true,
        // Empty mapping / sequence are treated as null. Fleet
        // templates often leave the keys present but empty.
        Some(serde_yaml::Value::Mapping(m)) => m.is_empty(),
        Some(serde_yaml::Value::Sequence(s)) => s.is_empty(),
        _ => false,
    }
}

/// Translate `queries` → `modules.query`. The osquery sidecar
/// itself is not configured by this shim; we only flip
/// `enabled = true` and propagate the schedule-poll interval if
/// `agent_options.distributed_interval` was set.
fn translate_queries(fleet: &FleetConfig, cfg: &mut AgentConfig, warnings: &mut Vec<String>) {
    if fleet.queries.is_empty() {
        return;
    }
    if fleet.queries.iter().any(|q| q.paused) {
        warnings.push("dropped paused fleet queries (paused = true)".into());
    }
    if fleet.queries.iter().any(|q| q.platform.is_some()) {
        warnings.push(
            "fleet per-query platform restriction is honoured by the osquery scheduler, \
             not by sda-management-compat — the agent reads it from the manifest produced \
             by the control plane"
                .into(),
        );
    }
    let enabled_count = fleet.queries.iter().filter(|q| !q.paused).count();
    if enabled_count == 0 {
        // All queries paused — leave the module disabled, but the
        // operator still sees a warning that we observed Fleet
        // queries.
        return;
    }
    cfg.modules.query = QueryConfig {
        enabled: true,
        osquery: OsqueryConfig::default(),
        ..QueryConfig::default()
    };
    debug!(count = enabled_count, "translated fleet queries");
}

/// Translate `policies` → control-plane policy hints. SDA's policy
/// evaluator (`sda-policy`) is the runtime; we do not have a
/// per-agent config slot for declarative policies, so the shim's
/// only job is to emit a warning summarising what the operator
/// must ship through the control plane separately.
fn translate_policies(fleet: &FleetConfig, warnings: &mut Vec<String>) {
    if fleet.policies.is_empty() {
        return;
    }
    let with_severity = fleet
        .policies
        .iter()
        .filter(|p| p.severity.is_some())
        .count();
    if with_severity > 0 {
        warnings.push(format!(
            "dropped fleet policy severity on {with_severity} entr{} (fleet ee field)",
            if with_severity == 1 { "y" } else { "ies" }
        ));
    }
    warnings.push(format!(
        "translated {} fleet policies — the agent does not load policy SQL directly; \
         ship them to the control plane via the standard policy onboarding flow",
        fleet.policies.len()
    ));
}

/// Translate `software` → `modules.software`. We do not have the
/// signed catalogue URL at this point — the control plane will
/// produce it from the package list — so we leave
/// `catalogue_url = None` and require the operator to populate it
/// downstream. The shim's job is to flip `enabled = true` and emit
/// a warning if any package was missing a SHA-256.
fn translate_software(fleet: &FleetConfig, cfg: &mut AgentConfig, warnings: &mut Vec<String>) {
    let Some(software) = fleet.software.as_ref() else {
        return;
    };
    if software.packages.is_empty() {
        return;
    }
    let unhashed = software
        .packages
        .iter()
        .filter(|p| p.sha256.is_none())
        .count();
    if unhashed > 0 {
        warnings.push(format!(
            "{unhashed} fleet software package(s) had no sha256 — the SDA catalogue producer \
             must hash them before signing"
        ));
    }
    cfg.modules.software = SoftwareConfig {
        enabled: true,
        ..SoftwareConfig::default()
    };
    debug!(
        packages = software.packages.len(),
        "translated fleet software"
    );
}

/// Translate `scripts` → `modules.script_runner`. We flip the
/// module on; signing keys are deliberately left at the SDA
/// defaults because the shim never produces signed scripts — that
/// is the catalogue producer's job.
fn translate_scripts(fleet: &FleetConfig, cfg: &mut AgentConfig, warnings: &mut Vec<String>) {
    if fleet.scripts.is_empty() {
        return;
    }
    cfg.modules.script_runner = ScriptRunnerConfig {
        enabled: true,
        ..ScriptRunnerConfig::default()
    };
    let unsigned = fleet
        .scripts
        .iter()
        .filter(|s| script_needs_signing(s))
        .count();
    if unsigned > 0 {
        warnings.push(format!(
            "{unsigned} fleet script(s) translated — bodies are unsigned and must be \
             re-signed by the catalogue producer before the agent will execute them"
        ));
    }
}

fn script_needs_signing(_s: &FleetScript) -> bool {
    // Every Fleet script needs re-signing — they are unsigned by
    // construction in Fleet's own model. We keep the helper as a
    // hook in case Fleet introduces a signed variant later.
    true
}

/// Translate `agent_options` → `modules.device_control` (and a
/// targeted assist into `modules.query.schedule_poll_secs` for
/// `distributed_interval`).
fn translate_agent_options(fleet: &FleetConfig, cfg: &mut AgentConfig, warnings: &mut Vec<String>) {
    let Some(opts) = fleet.agent_options.as_ref() else {
        return;
    };

    if let Some(secs) = opts.distributed_interval {
        if cfg.modules.query.enabled {
            cfg.modules.query.schedule_poll_secs = secs.max(1);
        } else {
            warnings.push(
                "fleet agent_options.distributed_interval is set but no queries were \
                 translated — leaving modules.query disabled"
                    .into(),
            );
        }
    }

    if let Some(window) = opts.maintenance_window.as_ref() {
        translate_maintenance_window(window, cfg);
    }

    record_unknown_agent_options(opts, warnings);
}

fn translate_maintenance_window(
    fleet_window: &crate::fleet_yaml::FleetMaintenanceWindow,
    cfg: &mut AgentConfig,
) {
    let mut sda_window = MaintenanceWindow {
        enabled: true,
        ..MaintenanceWindow::default()
    };
    if let Some(start) = fleet_window.start.as_ref() {
        sda_window.start.clone_from(start);
    }
    if let Some(end) = fleet_window.end.as_ref() {
        sda_window.end.clone_from(end);
    }
    if !fleet_window.days.is_empty() {
        sda_window.days = fleet_window
            .days
            .iter()
            .map(|d| d.to_ascii_lowercase())
            .collect();
    }
    cfg.modules.device_control.enabled = true;
    cfg.modules.device_control.maintenance_window = sda_window;
}

fn record_unknown_agent_options(opts: &FleetAgentOptions, warnings: &mut Vec<String>) {
    for key in opts.extra.keys() {
        warnings.push(format!(
            "ignoring unknown fleet agent_options.{key} — not portable to SDA"
        ));
        debug!(key = %key, "unknown fleet agent option");
    }
    if opts.logger_tls_period.is_some() {
        warnings.push(
            "fleet agent_options.logger_tls_period ignored — SDA has its own logging stack".into(),
        );
    }
}

fn collect_package_scripts(fleet: &FleetConfig) -> Vec<TranslatedPackageScripts> {
    let Some(software) = fleet.software.as_ref() else {
        return Vec::new();
    };
    software
        .packages
        .iter()
        .map(|p| TranslatedPackageScripts {
            package_url: p.url.clone(),
            package_name: p.name.clone(),
            sha256: p.sha256.clone(),
            install_script: p.install_script.clone(),
            uninstall_script: p.uninstall_script.clone(),
        })
        .collect()
}

fn record_unknown_sections(
    extra: &BTreeMap<String, serde_yaml::Value>,
    warnings: &mut Vec<String>,
) {
    for key in extra.keys() {
        // Suppress noise from common Fleet boilerplate that has no
        // SDA equivalent and is safe to drop.
        if matches!(
            key.as_str(),
            "kind"
                | "spec"
                | "controls"
                | "name"
                | "description"
                | "org_settings"
                | "team_settings"
        ) {
            debug!(section = %key, "ignored fleet section (no SDA equivalent)");
            continue;
        }
        warn!(section = %key, "unknown fleet top-level section");
        warnings.push(format!(
            "ignoring unknown fleet section `{key}` — not portable to SDA"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn translate_str(yaml: &str, tenant: &str) -> Result<Translation, CompatError> {
        translate_yaml(yaml, tenant)
    }

    #[test]
    fn empty_tenant_is_rejected() {
        let err = translate_str("queries: []", "").unwrap_err();
        assert!(matches!(err, CompatError::EmptyTenant));
    }

    #[test]
    fn empty_yaml_translates_to_default_config() {
        let t = translate_str("", "tenant-acme").expect("ok");
        assert_eq!(t.tenant_id, "tenant-acme");
        assert!(!t.agent_config.modules.query.enabled);
        assert!(!t.agent_config.modules.software.enabled);
        assert!(!t.agent_config.modules.script_runner.enabled);
    }

    #[test]
    fn mdm_block_is_rejected() {
        let yaml = "mdm:\n  enable_disk_encryption: true\n";
        let err = translate_str(yaml, "tenant-acme").unwrap_err();
        assert!(matches!(err, CompatError::UnsupportedFeature("mdm")));
    }

    #[test]
    fn mobile_device_management_block_is_rejected() {
        let yaml = "mobile_device_management:\n  apple:\n    enabled: true\n";
        let err = translate_str(yaml, "tenant-acme").unwrap_err();
        assert!(matches!(
            err,
            CompatError::UnsupportedFeature("mobile_device_management")
        ));
    }

    #[test]
    fn ee_block_is_rejected() {
        let yaml = "ee:\n  features:\n    - vulnerability_scanning\n";
        let err = translate_str(yaml, "tenant-acme").unwrap_err();
        assert!(matches!(err, CompatError::UnsupportedFeature("ee")));
    }

    #[test]
    fn vpp_block_is_rejected() {
        let yaml = "vpp:\n  token: abc\n";
        let err = translate_str(yaml, "tenant-acme").unwrap_err();
        assert!(matches!(err, CompatError::UnsupportedFeature("vpp")));
    }

    #[test]
    fn automatic_enrollment_is_rejected() {
        let yaml = "automatic_enrollment:\n  apple_bm_token: redacted\n";
        let err = translate_str(yaml, "tenant-acme").unwrap_err();
        assert!(matches!(
            err,
            CompatError::UnsupportedFeature("automatic_enrollment")
        ));
    }

    #[test]
    fn empty_mdm_block_is_treated_as_absent() {
        // Some Fleet templates leave `mdm:` present but empty as a
        // marker. We must not reject them — only non-empty blocks
        // are treated as opt-ins.
        let yaml = "mdm: {}\n";
        let t = translate_str(yaml, "tenant-acme").expect("empty mdm block ok");
        assert_eq!(t.tenant_id, "tenant-acme");
    }

    #[test]
    fn app_store_apps_are_rejected() {
        let yaml = "software:\n  app_store_apps:\n    - bundle_id: com.example.foo\n";
        let err = translate_str(yaml, "tenant-acme").unwrap_err();
        assert!(matches!(
            err,
            CompatError::UnsupportedFeature("software.app_store_apps")
        ));
    }

    #[test]
    fn tenant_mismatch_is_rejected() {
        let yaml = "team_name: tenant-other\nqueries: []\n";
        let err = translate_str(yaml, "tenant-acme").unwrap_err();
        assert!(matches!(err, CompatError::TenantMismatch { .. }));
    }

    #[test]
    fn matching_tenant_is_accepted() {
        let yaml = "team_name: tenant-acme\nqueries: []\n";
        let t = translate_str(yaml, "tenant-acme").expect("ok");
        assert_eq!(t.tenant_id, "tenant-acme");
    }

    #[test]
    fn empty_team_name_is_accepted() {
        let yaml = "team_name: \"\"\nqueries: []\n";
        let t = translate_str(yaml, "tenant-acme").expect("ok");
        assert_eq!(t.tenant_id, "tenant-acme");
    }

    #[test]
    fn queries_translate_to_module_query_enabled() {
        let yaml = r#"
queries:
  - name: q1
    query: "SELECT 1"
    interval: 600
"#;
        let t = translate_str(yaml, "tenant-acme").expect("ok");
        assert!(t.agent_config.modules.query.enabled);
    }

    #[test]
    fn paused_queries_emit_warning() {
        let yaml = r#"
queries:
  - name: q1
    query: "SELECT 1"
    paused: true
"#;
        let t = translate_str(yaml, "tenant-acme").expect("ok");
        assert!(!t.agent_config.modules.query.enabled);
        assert!(t
            .warnings
            .iter()
            .any(|w| w.contains("dropped paused fleet queries")));
    }

    #[test]
    fn software_packages_enable_module_software() {
        let yaml = r#"
software:
  packages:
    - url: https://example.com/foo.pkg
      sha256: deadbeef
      name: foo
"#;
        let t = translate_str(yaml, "tenant-acme").expect("ok");
        assert!(t.agent_config.modules.software.enabled);
        assert_eq!(t.package_scripts.len(), 1);
        assert_eq!(
            t.package_scripts[0].package_url,
            "https://example.com/foo.pkg"
        );
        assert_eq!(t.package_scripts[0].sha256.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn unhashed_software_emits_warning() {
        let yaml = r#"
software:
  packages:
    - url: https://example.com/foo.pkg
"#;
        let t = translate_str(yaml, "tenant-acme").expect("ok");
        assert!(t.warnings.iter().any(|w| w.contains("no sha256")));
    }

    #[test]
    fn scripts_enable_module_script_runner() {
        let yaml = r#"
scripts:
  - name: install-foo
    body: "echo hi"
"#;
        let t = translate_str(yaml, "tenant-acme").expect("ok");
        assert!(t.agent_config.modules.script_runner.enabled);
        assert!(t
            .warnings
            .iter()
            .any(|w| w.contains("re-signed by the catalogue producer")));
    }

    #[test]
    fn agent_options_distributed_interval_translates_to_query_poll() {
        let yaml = r#"
queries:
  - name: q1
    query: "SELECT 1"
agent_options:
  distributed_interval: 120
"#;
        let t = translate_str(yaml, "tenant-acme").expect("ok");
        assert!(t.agent_config.modules.query.enabled);
        assert_eq!(t.agent_config.modules.query.schedule_poll_secs, 120);
    }

    #[test]
    fn distributed_interval_without_queries_emits_warning() {
        let yaml = r#"
agent_options:
  distributed_interval: 120
"#;
        let t = translate_str(yaml, "tenant-acme").expect("ok");
        assert!(!t.agent_config.modules.query.enabled);
        assert!(t
            .warnings
            .iter()
            .any(|w| w.contains("distributed_interval")));
    }

    #[test]
    fn maintenance_window_translates_to_device_control() {
        let yaml = r#"
agent_options:
  maintenance_window:
    start: "02:00"
    end: "04:00"
    days: ["MON", "wed", "fri"]
"#;
        let t = translate_str(yaml, "tenant-acme").expect("ok");
        let mw = &t.agent_config.modules.device_control.maintenance_window;
        assert!(mw.enabled);
        assert_eq!(mw.start, "02:00");
        assert_eq!(mw.end, "04:00");
        assert_eq!(mw.days, vec!["mon".to_string(), "wed".into(), "fri".into()]);
        assert!(t.agent_config.modules.device_control.enabled);
    }

    #[test]
    fn labels_pass_through_verbatim() {
        let yaml = r#"
labels:
  - name: macos-laptops
    query: "SELECT 1 FROM os_version WHERE platform = 'darwin';"
    description: macOS only
"#;
        let t = translate_str(yaml, "tenant-acme").expect("ok");
        assert_eq!(t.labels.len(), 1);
        assert_eq!(t.labels[0].name, "macos-laptops");
        assert!(t.labels[0].query.as_deref().unwrap().contains("os_version"));
    }

    #[test]
    fn unknown_top_level_section_emits_warning_but_does_not_fail() {
        let yaml = r#"
queries: []
totally_made_up_section:
  foo: bar
"#;
        let t = translate_str(yaml, "tenant-acme").expect("ok");
        assert!(t
            .warnings
            .iter()
            .any(|w| w.contains("totally_made_up_section")));
    }

    #[test]
    fn benign_fleet_boilerplate_does_not_warn() {
        let yaml = r#"
kind: gitops
spec:
  controls: {}
queries: []
"#;
        let t = translate_str(yaml, "tenant-acme").expect("ok");
        assert!(t
            .warnings
            .iter()
            .all(|w| !w.contains("kind") && !w.contains("spec")));
    }

    #[test]
    fn unknown_agent_options_emit_warnings() {
        let yaml = r#"
agent_options:
  some_new_fleet_knob: 42
"#;
        let t = translate_str(yaml, "tenant-acme").expect("ok");
        assert!(t.warnings.iter().any(|w| w.contains("some_new_fleet_knob")));
    }

    #[test]
    fn policy_severity_is_dropped_with_warning() {
        let yaml = r#"
policies:
  - name: p1
    query: "SELECT 1"
    severity: high
"#;
        let t = translate_str(yaml, "tenant-acme").expect("ok");
        assert!(t.warnings.iter().any(|w| w.contains("severity")));
    }

    #[test]
    fn translation_round_trips_through_yaml() {
        let yaml = r#"
queries:
  - name: q1
    query: "SELECT 1"
software:
  packages:
    - url: https://example.com/foo.pkg
"#;
        let t = translate_str(yaml, "tenant-acme").expect("ok");
        let out = t.to_yaml().expect("encode");
        // The output is a normal AgentConfig YAML — must parse
        // back via serde_yaml without complaint.
        let _: AgentConfig = serde_yaml::from_str(&out).expect("re-parse agent config");
    }

    #[test]
    fn malformed_yaml_returns_parse_error() {
        let yaml = "queries:\n  - name: bad\n    query: [unterminated";
        let err = translate_str(yaml, "tenant-acme").unwrap_err();
        assert!(matches!(err, CompatError::Parse(_)));
    }
}
