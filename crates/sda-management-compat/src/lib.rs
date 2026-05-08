//! Fleet-flavoured GitOps YAML compatibility shim (Phase 5 / PROPOSAL.md
//! § 4.1).
//!
//! This crate exists for one reason: customers running Fleet today
//! already keep their queries, policies, software installers, and
//! script jobs in a Git-tracked YAML repository. We do not want to
//! force them to hand-rewrite that YAML to onboard SN360. Instead we
//! parse the subset of Fleet's GitOps schema that PROPOSAL.md § 4.1
//! flags as portable, translate each concept into the matching
//! SN360 native config section, and emit either a strongly-typed
//! [`sda_core::config::AgentConfig`] overlay or the YAML it
//! serialises into.
//!
//! The translation is deliberately one-way:
//!
//! * Fleet YAML → SDA-native config
//! * SDA-native config → Fleet YAML  (NOT supported)
//!
//! That asymmetry is by design — Fleet's schema cannot represent
//! SDA-native concepts (signed-job catalogue keys, dual-control
//! rollback, JIT-admin grants, app-control monitor mode), so a
//! round-trip through Fleet would silently drop them. Translating
//! one-way makes the data loss impossible.
//!
//! ## What is and is not translated
//!
//! Translated (PROPOSAL.md § 4.1):
//!
//! * `queries` → `modules.query`
//! * `policies` → `modules.local_detection`-style logical policies
//!   (kept declarative; the sda-policy evaluator lives elsewhere)
//! * `software` / installers → `modules.software` (catalogue URL,
//!   refresh interval). The actual signed catalogue manifest is
//!   produced by the control plane, not by this shim.
//! * `scripts` → `modules.script_runner`
//! * `agent_options` → `modules.device_control` (maintenance window,
//!   quiet hours, job budget where sensible)
//! * `labels` → tag-based device groups (control plane). We retain
//!   them in the translated output as a [`Translation::labels`]
//!   vector so the operator can ship them to the control plane
//!   separately.
//!
//! Rejected (PROPOSAL.md § 4.2 do-not-port + ADR-001):
//!
//! * Any `mdm` / `mobile_device_management` block (Apple MDM, Windows
//!   MDM, ADE/DEP, VPP).
//! * Anything inside an `ee/` directory or under an `ee:` top-level
//!   key — those are Fleet EE-licensed features.
//! * Fleet's MySQL schema, Sails.js website settings, `handbook/`,
//!   anything that pertains to Fleet's runtime rather than its
//!   declarative config.
//!
//! See the per-function docstrings in [`translator`] for the exact
//! mapping rules.
//!
//! ## Usage
//!
//! ```no_run
//! use sda_management_compat::{translate_yaml, Translation};
//!
//! let yaml = std::fs::read_to_string("fleet/config.yml").expect("read");
//! let translation: Translation = translate_yaml(&yaml, "tenant-acme")
//!     .expect("fleet yaml is portable");
//! let sda_overlay_yaml = translation.to_yaml().expect("encode");
//! std::fs::write("sda/config.yml", sda_overlay_yaml).expect("write");
//! ```

pub mod fleet_yaml;
pub mod translator;

pub use fleet_yaml::{
    FleetAgentOptions, FleetConfig, FleetPolicy, FleetQuery, FleetScript, FleetSoftwarePackage,
};
pub use translator::{translate_yaml, CompatError, Translation};
