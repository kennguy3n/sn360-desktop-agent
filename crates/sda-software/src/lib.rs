//! `sda-software` — approved-software catalogue + signed manifest
//! verifier for the SN360 Desktop Agent (Phase 2).
//!
//! This crate is the SDA-side counterpart to the control-plane
//! Software Inventory Service (SIS). It owns:
//!
//! 1. The catalogue manifest schema and Ed25519 signature verifier
//!    ([`manifest`]).
//! 2. The in-process [`CatalogueStore`](catalogue::CatalogueStore)
//!    that holds the most recently verified manifest so the action
//!    orchestrator can answer install / update / uninstall queries
//!    without re-fetching.
//! 3. [`SoftwareModule`] — the supervisor task wired into
//!    `sda-agent` whose Phase 2.5 scaffold parks on the shared
//!    shutdown signal so an SDA built with `modules.software.enabled
//!    = false` (the default) keeps idle CPU at zero.
//!
//! The actual install / update / uninstall executors delegate to the
//! [`sda_pal::package_manager::PackageManager`] PAL trait (Phase 2.1
//! — 2.4) so a single orchestrator drives WinGet on Windows, the
//! clean-room Munki-style local repo on macOS, and apt / dnf / yum /
//! zypper on Linux.

pub mod approval;
pub mod catalogue;
pub mod evidence;
pub mod manifest;
pub mod module;
pub mod rollback;

pub use approval::{
    build_recommendation_payload, ApprovalAuditor, ApprovalDiff, ApprovalEvaluation, ApprovalState,
    ApprovalTransition, InstalledPackage, RECOMMENDATION_PLAIN_ENGLISH_MAX,
};
pub use catalogue::{Catalogue, CatalogueStore};
pub use evidence::{output_sha256, SoftwareActionOutcome, SoftwareEvidenceEmitter};
pub use manifest::{Artefact, Manifest, ManifestError, MANIFEST_SCHEMA_VERSION};
pub use module::SoftwareModule;
pub use rollback::{
    RollbackEntry, RollbackError, RollbackManifest, RollbackOrchestrator, RollbackOutcome,
};
