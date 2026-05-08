//! Phase 5 management-compat end-to-end suite (PHASES.md task 5.7).
//!
//! Hermetic exercises of the [`sda_management_compat`] shim that
//! translates Fleet-flavoured GitOps YAML into SDA-native
//! [`AgentConfig`] sections. Phase 5 acceptance criteria from
//! `docs/device-control/PHASES.md`:
//!
//!   1. No agent-side change required to onboard MSP tenant —
//!      verified by `fleet_yaml_round_trips_into_loadable_agent_config`,
//!      which translates a representative Fleet document, encodes
//!      it as YAML, writes it to a tempfile, and re-loads it via
//!      `AgentConfig::from_yaml_file` exactly the way `sda-agent`
//!      itself does at boot.
//!   2. Cross-tenant data leakage impossible by construction —
//!      verified by `cross_tenant_translation_is_rejected`,
//!      `empty_team_name_is_accepted_for_any_tenant`, and
//!      `empty_tenant_id_is_rejected_outright`. A Fleet document
//!      whose `team_name` does not match the SDA-side `tenant_id`
//!      MUST surface a fatal `TenantMismatch` so the agent will
//!      never load another tenant's config.
//!   3. White-label exports never include another tenant's data —
//!      verified by `translation_carries_tenant_id_through_to_yaml`
//!      and `package_scripts_and_labels_are_separated_from_agent_yaml`,
//!      which pin the invariant that `Translation::tenant_id` is
//!      preserved end-to-end and that catalogue-side artifacts
//!      (labels, install scripts) are exposed separately from the
//!      agent-loadable `AgentConfig`.
//!
//! The shim runs entirely in-process: no event bus, no PAL, no
//! filesystem mutations beyond a tempdir for the round-trip test.
//! `make e2e-management-compat` runs in well under a second on
//! every CI host.

use std::io::Write;

use sda_core::config::AgentConfig;
use sda_management_compat::{translate_yaml, CompatError};
use tempfile::NamedTempFile;

// ---------- Fixtures ------------------------------------------------------

/// A representative Fleet GitOps document covering every section
/// the shim is required to translate (queries, policies, software
/// installers, scripts, agent_options/maintenance_window, labels).
/// Used by the round-trip and structural-coverage tests.
const FULL_FLEET_YAML: &str = r#"
team_name: tenant-acme
api_version: v1
queries:
  - name: q-uptime
    query: "SELECT total_seconds FROM uptime;"
    interval: 600
    description: agent uptime
  - name: q-paused
    query: "SELECT 1;"
    paused: true
policies:
  - name: p-firewall-on
    query: "SELECT 1 FROM windows_firewall WHERE state = 'on';"
    description: firewall must be on
    resolution: re-enable firewall
software:
  packages:
    - url: https://example.com/installers/foo.pkg
      sha256: 4a4b4c4d
      name: foo
      install_script: "/usr/sbin/installer -pkg foo.pkg -target /"
      uninstall_script: "/usr/sbin/installer -pkg foo-uninstall.pkg -target /"
scripts:
  - name: collect-diagnostics
    body: |
      #!/bin/sh
      uptime
agent_options:
  distributed_interval: 120
  maintenance_window:
    start: "02:00"
    end: "04:00"
    days: ["MON", "wed", "fri"]
labels:
  - name: macos-laptops
    query: "SELECT 1 FROM os_version WHERE platform = 'darwin';"
    description: macOS only
"#;

// ---------- Acceptance #1 — round-trip into a loadable AgentConfig ---------

/// PHASES.md Phase 5 acceptance #1 — the SDA agent must boot
/// against config translated from Fleet YAML without any
/// hand-edits.
///
/// Steps walked end-to-end:
///   1. Translate the full Fleet document.
///   2. Encode the resulting [`AgentConfig`] back as YAML.
///   3. Write the YAML into a tempfile.
///   4. Re-load it via [`AgentConfig::from_yaml_file`] — the same
///      function `sda-agent::main` calls on startup.
///
/// Asserts the round-trip preserves every flag the shim is
/// required to flip (`modules.query.enabled`,
/// `modules.software.enabled`, `modules.script_runner.enabled`,
/// `modules.device_control.enabled`,
/// `modules.device_control.maintenance_window.enabled`,
/// `modules.query.schedule_poll_secs`).
#[test]
fn fleet_yaml_round_trips_into_loadable_agent_config() {
    let translation =
        translate_yaml(FULL_FLEET_YAML, "tenant-acme").expect("full fleet doc must translate");

    let yaml = translation.to_yaml().expect("encode AgentConfig as YAML");

    let mut tmp = NamedTempFile::new().expect("tempfile");
    write!(tmp, "{}", yaml).expect("write yaml");
    tmp.flush().expect("flush yaml");

    let reloaded =
        AgentConfig::from_yaml_file(tmp.path()).expect("agent must load translated config");

    // Module flags the shim is contractually required to flip.
    assert!(
        reloaded.modules.query.enabled,
        "queries must enable modules.query"
    );
    assert!(
        reloaded.modules.software.enabled,
        "software.packages must enable modules.software"
    );
    assert!(
        reloaded.modules.script_runner.enabled,
        "scripts must enable modules.script_runner"
    );
    assert!(
        reloaded.modules.device_control.enabled,
        "agent_options.maintenance_window must enable modules.device_control"
    );

    // distributed_interval propagated into modules.query.schedule_poll_secs.
    assert_eq!(
        reloaded.modules.query.schedule_poll_secs, 120,
        "agent_options.distributed_interval must override modules.query.schedule_poll_secs",
    );

    // Maintenance window translated faithfully (days are lowercased
    // by the shim because SDA uses canonical 3-letter weekday tags).
    let mw = &reloaded.modules.device_control.maintenance_window;
    assert!(mw.enabled);
    assert_eq!(mw.start, "02:00");
    assert_eq!(mw.end, "04:00");
    assert_eq!(mw.days, vec!["mon".to_string(), "wed".into(), "fri".into()],);
}

// ---------- Acceptance #2 — cross-tenant isolation ------------------------

/// PHASES.md Phase 5 acceptance #2 — a Fleet document whose
/// `team_name` does not match the SDA-side `tenant_id` MUST be
/// rejected at translation time. This is the agent-side
/// belt-and-braces check behind the control-plane row-level
/// security; it is the last line of defence.
#[test]
fn cross_tenant_translation_is_rejected() {
    let yaml = "team_name: tenant-other\nqueries: []\n";
    let err = translate_yaml(yaml, "tenant-acme").unwrap_err();
    match err {
        CompatError::TenantMismatch { fleet, sda } => {
            assert_eq!(fleet, "tenant-other");
            assert_eq!(sda, "tenant-acme");
        }
        other => panic!("expected TenantMismatch, got {other:?}"),
    }
}

/// An empty / absent `team_name` is acceptable because the Fleet
/// document is not claiming a tenant — the SDA-side `tenant_id`
/// alone scopes the translation. This mirrors how the unit tests
/// in `sda-management-compat::translator::tests` behave; the E2E
/// pin is here so a refactor of the unit harness cannot silently
/// drop the contract.
#[test]
fn empty_team_name_is_accepted_for_any_tenant() {
    let yaml = "team_name: \"\"\nqueries: []\n";
    let t = translate_yaml(yaml, "tenant-acme").expect("empty team_name ok");
    assert_eq!(t.tenant_id, "tenant-acme");
}

/// Translation against an empty `tenant_id` is fatal. We refuse
/// to scope a translation into the empty / default tenant because
/// the agent's tenant gate would otherwise wave it through.
#[test]
fn empty_tenant_id_is_rejected_outright() {
    let yaml = "queries: []\n";
    let err = translate_yaml(yaml, "").unwrap_err();
    assert!(matches!(err, CompatError::EmptyTenant));
}

// ---------- Acceptance #2 — Fleet EE / do-not-port features rejected ------

/// Every key on PROPOSAL.md § 4.2's do-not-port list must
/// surface as a fatal [`CompatError::UnsupportedFeature`] at the
/// E2E layer — not just in the unit tests. The agent never sees
/// a partially-translated config in any of these cases.
#[test]
fn fleet_ee_features_are_rejected_end_to_end() {
    let cases: &[(&str, &str)] = &[
        ("mdm:\n  enable_disk_encryption: true\n", "mdm"),
        (
            "mobile_device_management:\n  apple:\n    enabled: true\n",
            "mobile_device_management",
        ),
        ("ee:\n  features:\n    - vulnerability_scanning\n", "ee"),
        ("vpp:\n  token: abc\n", "vpp"),
        (
            "automatic_enrollment:\n  apple_bm_token: redacted\n",
            "automatic_enrollment",
        ),
        (
            "software:\n  app_store_apps:\n    - bundle_id: com.example.foo\n",
            "software.app_store_apps",
        ),
    ];

    for (yaml, expected) in cases {
        let err = translate_yaml(yaml, "tenant-acme").expect_err(yaml);
        match err {
            CompatError::UnsupportedFeature(actual) => assert_eq!(
                &actual, expected,
                "{yaml} must reject as {expected}, got {actual}",
            ),
            other => panic!("{yaml}: expected UnsupportedFeature, got {other:?}"),
        }
    }
}

// ---------- Acceptance #3 — white-label exports stay tenant-scoped --------

/// PHASES.md Phase 5 acceptance #3 — the translation result must
/// carry the SDA-side `tenant_id` end-to-end so the catalogue
/// producer cannot accidentally publish another tenant's config
/// under the wrong tenant slug. Encoding to YAML must not strip
/// the tenant id from the [`Translation`] struct.
#[test]
fn translation_carries_tenant_id_through_to_yaml() {
    let translation =
        translate_yaml(FULL_FLEET_YAML, "tenant-acme").expect("full fleet doc must translate");
    assert_eq!(translation.tenant_id, "tenant-acme");

    // The encoded YAML is the AgentConfig payload — it does not
    // and should not embed a tenant id (that lives one level up
    // in the catalogue manifest), but the in-memory Translation
    // must still expose it for the caller's bookkeeping.
    let yaml = translation.to_yaml().expect("encode");
    assert!(!yaml.contains("tenant-acme"));
}

/// Catalogue-side artifacts (labels, install / uninstall scripts)
/// are deliberately exposed separately from the agent's
/// [`AgentConfig`] so the catalogue producer can re-sign them
/// before publishing. Pinning the contract here makes sure a
/// refactor of [`Translation`] cannot silently fold them into the
/// agent YAML — that would smuggle install scripts through the
/// agent loader and bypass the catalogue signing step.
#[test]
fn package_scripts_and_labels_are_separated_from_agent_yaml() {
    let translation =
        translate_yaml(FULL_FLEET_YAML, "tenant-acme").expect("full fleet doc must translate");

    // Labels and package scripts live on the Translation struct,
    // NOT inside the encoded AgentConfig YAML.
    assert_eq!(translation.labels.len(), 1);
    assert_eq!(translation.labels[0].name, "macos-laptops");
    assert_eq!(translation.package_scripts.len(), 1);
    assert_eq!(
        translation.package_scripts[0].package_url,
        "https://example.com/installers/foo.pkg"
    );

    let yaml = translation.to_yaml().expect("encode");
    assert!(
        !yaml.contains("macos-laptops"),
        "label names must NOT be embedded in the agent yaml — they are catalogue-side data",
    );
    assert!(
        !yaml.contains("/usr/sbin/installer"),
        "install scripts must NOT be embedded in the agent yaml — they are catalogue-side data",
    );
}

// ---------- Coverage — warnings surface for non-fatal observations --------

/// Translating a document that mixes paused queries, unhashed
/// software packages, unsigned scripts, and unknown agent_options
/// fields should yield at least one warning per category. This is
/// the primary signal the operator uses to spot Fleet config they
/// need to fix downstream — losing the warnings (e.g. by
/// short-circuiting in [`translate`]) is a regression even though
/// it would not break any contract under #[test] inputs above.
#[test]
fn warnings_surface_for_non_fatal_fleet_observations() {
    let yaml = r#"
queries:
  - name: q-paused
    query: "SELECT 1;"
    paused: true
software:
  packages:
    - url: https://example.com/foo.pkg
scripts:
  - name: collect-diagnostics
    body: "echo hi"
agent_options:
  some_new_fleet_knob: 42
policies:
  - name: p1
    query: "SELECT 1"
    severity: high
"#;
    let t = translate_yaml(yaml, "tenant-acme").expect("ok");
    assert!(
        t.warnings
            .iter()
            .any(|w| w.contains("dropped paused fleet queries")),
        "must warn on paused queries: {:?}",
        t.warnings,
    );
    assert!(
        t.warnings.iter().any(|w| w.contains("no sha256")),
        "must warn on unhashed packages: {:?}",
        t.warnings,
    );
    assert!(
        t.warnings
            .iter()
            .any(|w| w.contains("re-signed by the catalogue producer")),
        "must warn on unsigned scripts: {:?}",
        t.warnings,
    );
    assert!(
        t.warnings.iter().any(|w| w.contains("some_new_fleet_knob")),
        "must warn on unknown agent_options: {:?}",
        t.warnings,
    );
    assert!(
        t.warnings.iter().any(|w| w.contains("severity")),
        "must warn on policy.severity: {:?}",
        t.warnings,
    );
}

/// Malformed YAML must surface as [`CompatError::Parse`] — the
/// shim never tries to recover from a partially-parsed Fleet
/// document.
#[test]
fn malformed_fleet_yaml_returns_parse_error_end_to_end() {
    let yaml = "queries:\n  - name: bad\n    query: [unterminated";
    let err = translate_yaml(yaml, "tenant-acme").unwrap_err();
    assert!(matches!(err, CompatError::Parse(_)), "got {err:?}");
}
