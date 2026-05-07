//! Rollback path for failed package updates (Task 2.10).
//!
//! Per `docs/device-control/PROPOSAL.md` § 14.3 the agent maintains a
//! local rollback manifest before any `UpdatePackage` action runs.
//! If the package manager subsequently reports a non-zero exit on
//! the upgrade, the agent automatically calls
//! [`PackageManager::install`](sda_pal::package_manager::PackageManager::install)
//! with the previously-installed version so the device is left in a
//! known-good state.
//!
//! ## Lifecycle
//!
//! 1. **Pre-update snapshot**: [`RollbackOrchestrator::record_pre_update`]
//!    is called immediately before the update CLI is invoked. It
//!    captures `(job_id, package_id, previous_version, updated_at)`
//!    in [`RollbackManifest`] format and persists it to disk.
//! 2. **Update success**: [`RollbackOrchestrator::clear`] removes the
//!    entry — there is no longer any version to roll back to.
//! 3. **Update failure**: [`RollbackOrchestrator::execute_rollback`]
//!    re-installs the previously-recorded version using the same
//!    [`PackageManager`] surface and synthesises a
//!    [`RollbackOutcome`] payload the action orchestrator can splice
//!    into the failed `ActionResult`.
//!
//! ## Persistence
//!
//! State is persisted as a single JSON file with one [`RollbackEntry`]
//! per (job_id, package_id) tuple. Writes go through a temp-file +
//! rename so a crash mid-write cannot corrupt the manifest. The file
//! lives under whatever path the caller passes — typically the
//! agent's `cache_dir`.
//!
//! ## Cross-restart durability
//!
//! [`RollbackOrchestrator::load`] re-reads the manifest at start-up
//! and exposes any pending entries via
//! [`RollbackOrchestrator::pending_entries`] so a supervisor task
//! that crashed during the update window can finish (or ignore)
//! whatever was queued.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use sda_pal::package_manager::{InstallOpts, PackageManager, PackageRef};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Errors raised by the rollback orchestrator.
#[derive(Debug, thiserror::Error)]
pub enum RollbackError {
    /// Reading or writing the on-disk manifest failed.
    #[error("rollback manifest IO error: {0}")]
    Io(#[from] io::Error),
    /// The manifest file existed but JSON parsing failed.
    #[error("rollback manifest is malformed: {0}")]
    Decode(#[from] serde_json::Error),
    /// `execute_rollback` was called for a (job_id, package_id) that
    /// has no recorded prior version.
    #[error("no rollback entry recorded for job_id={job_id} package_id={package_id}")]
    NoEntry {
        /// `job_id` that was queried.
        job_id: Uuid,
        /// `package_id` that was queried.
        package_id: String,
    },
    /// The wrapped [`PackageManager`] returned an error during the
    /// rollback re-install.
    #[error("package manager rollback re-install failed: {0}")]
    Reinstall(String),
}

/// A single rollback record persisted to disk. Mirrors the schema
/// in PROPOSAL.md § 14.3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackEntry {
    /// Job id of the originating `UpdatePackage` action. Used to
    /// scope the entry to a specific signed job — multiple
    /// concurrent updates of the same package id (impossible in
    /// practice today, but we still key the manifest by both fields)
    /// stay isolated.
    pub job_id: Uuid,
    /// PAL package identifier whose previous version was recorded.
    pub package_id: String,
    /// The version string that was installed *before* the update
    /// ran. `None` means "package was not previously installed" —
    /// a successful update of a brand-new package has no previous
    /// version to roll back to and the agent simply uninstalls on
    /// failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_version: Option<String>,
    /// UTC timestamp the entry was recorded.
    pub recorded_at: DateTime<Utc>,
}

/// On-disk manifest. Wraps a `BTreeMap` keyed by
/// `(job_id, package_id)` so writes are stable / diffable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackManifest {
    /// One entry per `(job_id, package_id)` tuple. `BTreeMap` keeps
    /// the on-disk JSON deterministic even though the map keys are
    /// composite; we serialise it as an array of entries for that
    /// reason.
    #[serde(with = "rollback_entries_serde")]
    pub entries: BTreeMap<(Uuid, String), RollbackEntry>,
}

mod rollback_entries_serde {
    use super::*;
    use serde::ser::SerializeSeq;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(
        entries: &BTreeMap<(Uuid, String), RollbackEntry>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(entries.len()))?;
        for entry in entries.values() {
            seq.serialize_element(entry)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<BTreeMap<(Uuid, String), RollbackEntry>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: Vec<RollbackEntry> = Vec::<RollbackEntry>::deserialize(deserializer)?;
        Ok(raw
            .into_iter()
            .map(|e| ((e.job_id, e.package_id.clone()), e))
            .collect())
    }
}

/// Outcome surfaced by [`RollbackOrchestrator::execute_rollback`].
/// Callers fold this into the `ActionResult::output` so the control
/// plane and human operators can see what was attempted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackOutcome {
    pub job_id: Uuid,
    pub package_id: String,
    pub previous_version: Option<String>,
    /// `true` iff the re-install of `previous_version` succeeded.
    pub succeeded: bool,
    /// Operator-readable summary. Always populated.
    pub message: String,
    pub attempted_at: DateTime<Utc>,
}

impl RollbackOutcome {
    /// Render this outcome into the canonical JSON snippet appended
    /// to the failed `ActionResult.output`.
    pub fn to_canonical_json(&self) -> String {
        serde_json::to_string(self).expect("RollbackOutcome serialisation is infallible")
    }
}

/// Stateful orchestrator binding a [`PackageManager`] to a
/// disk-backed [`RollbackManifest`]. Cheap to construct (one
/// disk-read on `load`), cheap to clone (the wrapped manager is a
/// trait object).
pub struct RollbackOrchestrator {
    path: PathBuf,
    manifest: RollbackManifest,
}

impl RollbackOrchestrator {
    /// Open or create the manifest at `path`. Missing files start
    /// with an empty manifest — they are *not* an error, since the
    /// agent's first run has nothing to roll back.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, RollbackError> {
        let path = path.into();
        let manifest = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == ErrorKind::NotFound => RollbackManifest::default(),
            Err(e) => return Err(RollbackError::Io(e)),
        };
        Ok(Self { path, manifest })
    }

    /// Path the manifest is persisted to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Snapshot all currently-pending rollback entries (e.g. for the
    /// boot-time supervisor scan).
    pub fn pending_entries(&self) -> Vec<RollbackEntry> {
        self.manifest.entries.values().cloned().collect()
    }

    /// Return the rollback entry recorded for `(job_id, package_id)`,
    /// if any.
    pub fn lookup(&self, job_id: Uuid, package_id: &str) -> Option<&RollbackEntry> {
        self.manifest.entries.get(&(job_id, package_id.to_string()))
    }

    /// Record the package's pre-update version. Idempotent — calling
    /// twice with the same `(job_id, package_id)` overwrites the
    /// previous record, which is the right behaviour when the agent
    /// retries an update after a transient failure.
    pub fn record_pre_update(
        &mut self,
        job_id: Uuid,
        package_id: impl Into<String>,
        previous_version: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<(), RollbackError> {
        let package_id = package_id.into();
        let entry = RollbackEntry {
            job_id,
            package_id: package_id.clone(),
            previous_version,
            recorded_at: now,
        };
        self.manifest.entries.insert((job_id, package_id), entry);
        self.persist()
    }

    /// Clear the rollback entry — call after a successful update so
    /// the manifest does not grow unbounded.
    pub fn clear(&mut self, job_id: Uuid, package_id: &str) -> Result<(), RollbackError> {
        if self
            .manifest
            .entries
            .remove(&(job_id, package_id.to_string()))
            .is_some()
        {
            self.persist()?;
        }
        Ok(())
    }

    /// Roll a failed update back to the previously-installed version
    /// by calling [`PackageManager::install`] (or
    /// [`PackageManager::uninstall`] when there was no prior version).
    /// Always returns a [`RollbackOutcome`] — even on infrastructural
    /// failure — so the caller can fold the result into its
    /// `ActionResult.output`.
    pub fn execute_rollback(
        &mut self,
        manager: &dyn PackageManager,
        job_id: Uuid,
        package_id: &str,
        now: DateTime<Utc>,
    ) -> Result<RollbackOutcome, RollbackError> {
        let entry = self
            .manifest
            .entries
            .get(&(job_id, package_id.to_string()))
            .cloned()
            .ok_or_else(|| RollbackError::NoEntry {
                job_id,
                package_id: package_id.to_string(),
            })?;

        let outcome = match entry.previous_version.as_deref() {
            Some(prev) => {
                let pkg = PackageRef {
                    id: package_id.to_string(),
                    version: Some(prev.to_string()),
                };
                let opts = InstallOpts {
                    expected_sha256: None,
                    source_url: None,
                    force: true,
                };
                match manager.install(&pkg, &opts) {
                    Ok(()) => RollbackOutcome {
                        job_id,
                        package_id: package_id.to_string(),
                        previous_version: Some(prev.to_string()),
                        succeeded: true,
                        message: format!(
                            "rolled back package {package_id} to previous version {prev}"
                        ),
                        attempted_at: now,
                    },
                    Err(e) => RollbackOutcome {
                        job_id,
                        package_id: package_id.to_string(),
                        previous_version: Some(prev.to_string()),
                        succeeded: false,
                        message: format!("rollback re-install of {package_id}@{prev} failed: {e}"),
                        attempted_at: now,
                    },
                }
            }
            None => {
                // No prior version — roll forward by uninstalling the
                // half-installed update.
                let pkg = PackageRef {
                    id: package_id.to_string(),
                    version: None,
                };
                match manager.uninstall(&pkg) {
                    Ok(()) => RollbackOutcome {
                        job_id,
                        package_id: package_id.to_string(),
                        previous_version: None,
                        succeeded: true,
                        message: format!(
                            "rolled back package {package_id} by uninstalling — no prior version was recorded"
                        ),
                        attempted_at: now,
                    },
                    Err(e) => RollbackOutcome {
                        job_id,
                        package_id: package_id.to_string(),
                        previous_version: None,
                        succeeded: false,
                        message: format!(
                            "rollback uninstall of {package_id} failed: {e}"
                        ),
                        attempted_at: now,
                    },
                }
            }
        };

        // Whether or not the package-manager call succeeded, the
        // rollback attempt has been *made*; remove the entry so a
        // future update is not blocked by a stale record.
        self.manifest
            .entries
            .remove(&(job_id, package_id.to_string()));
        self.persist()?;
        Ok(outcome)
    }

    fn persist(&self) -> Result<(), RollbackError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let bytes = serde_json::to_vec_pretty(&self.manifest)?;
        // Write atomically: temp + rename keeps the manifest
        // consistent even if the process is killed mid-write.
        let mut tmp = self.path.clone();
        let mut tmp_name = tmp
            .file_name()
            .map(|n| n.to_owned())
            .unwrap_or_else(|| std::ffi::OsString::from("rollback.json"));
        tmp_name.push(".tmp");
        tmp.set_file_name(tmp_name);
        fs::write(&tmp, &bytes)?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_pal::package_manager::{InstalledPackage, PackageError};
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    /// One recorded call: `(op, package_id, version)`.
    type Call = (String, String, Option<String>);

    /// Test double — records every call so assertions can pin the
    /// sequence of install / uninstall invocations.
    #[derive(Default, Clone)]
    struct MockManager {
        calls: Arc<Mutex<Vec<Call>>>,
        // When `install_fail` is non-empty, the next install call
        // returns the first item as a Command error.
        install_fail: Arc<Mutex<Vec<String>>>,
    }

    impl MockManager {
        fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl PackageManager for MockManager {
        fn list_installed(&self) -> Result<Vec<InstalledPackage>, PackageError> {
            Ok(Vec::new())
        }
        fn install(&self, package: &PackageRef, _opts: &InstallOpts) -> Result<(), PackageError> {
            self.calls.lock().unwrap().push((
                "install".into(),
                package.id.clone(),
                package.version.clone(),
            ));
            if let Some(msg) = self.install_fail.lock().unwrap().pop() {
                return Err(PackageError::Command(msg));
            }
            Ok(())
        }
        fn update(&self, package: &PackageRef) -> Result<(), PackageError> {
            self.calls.lock().unwrap().push((
                "update".into(),
                package.id.clone(),
                package.version.clone(),
            ));
            Ok(())
        }
        fn uninstall(&self, package: &PackageRef) -> Result<(), PackageError> {
            self.calls.lock().unwrap().push((
                "uninstall".into(),
                package.id.clone(),
                package.version.clone(),
            ));
            Ok(())
        }
    }

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn load_returns_empty_manifest_when_file_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rollback.json");
        let orch = RollbackOrchestrator::load(&path).unwrap();
        assert!(orch.pending_entries().is_empty());
        assert_eq!(orch.path(), path);
    }

    #[test]
    fn record_pre_update_persists_entry_and_survives_reload() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rollback.json");
        let job = Uuid::new_v4();
        {
            let mut orch = RollbackOrchestrator::load(&path).unwrap();
            orch.record_pre_update(job, "Mozilla.Firefox", Some("119.0".into()), now())
                .unwrap();
            assert_eq!(orch.pending_entries().len(), 1);
        }
        let orch2 = RollbackOrchestrator::load(&path).unwrap();
        let entries = orch2.pending_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].job_id, job);
        assert_eq!(entries[0].package_id, "Mozilla.Firefox");
        assert_eq!(entries[0].previous_version.as_deref(), Some("119.0"));
    }

    #[test]
    fn clear_removes_entry_after_successful_update() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rollback.json");
        let mut orch = RollbackOrchestrator::load(&path).unwrap();
        let job = Uuid::new_v4();
        orch.record_pre_update(job, "p", Some("1.0".into()), now())
            .unwrap();
        orch.clear(job, "p").unwrap();
        assert!(orch.pending_entries().is_empty());
        // And it survives a reload.
        let orch2 = RollbackOrchestrator::load(&path).unwrap();
        assert!(orch2.pending_entries().is_empty());
    }

    #[test]
    fn execute_rollback_reinstalls_previous_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rollback.json");
        let mut orch = RollbackOrchestrator::load(&path).unwrap();
        let mgr = MockManager::default();
        let job = Uuid::new_v4();
        orch.record_pre_update(job, "p", Some("1.0".into()), now())
            .unwrap();

        let outcome = orch.execute_rollback(&mgr, job, "p", now()).unwrap();
        assert!(outcome.succeeded);
        assert_eq!(outcome.previous_version.as_deref(), Some("1.0"));
        let calls = mgr.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "install");
        assert_eq!(calls[0].1, "p");
        assert_eq!(calls[0].2.as_deref(), Some("1.0"));
        // Entry was cleared after the rollback attempt.
        assert!(orch.pending_entries().is_empty());
    }

    #[test]
    fn execute_rollback_uninstalls_when_no_previous_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rollback.json");
        let mut orch = RollbackOrchestrator::load(&path).unwrap();
        let mgr = MockManager::default();
        let job = Uuid::new_v4();
        orch.record_pre_update(job, "p", None, now()).unwrap();

        let outcome = orch.execute_rollback(&mgr, job, "p", now()).unwrap();
        assert!(outcome.succeeded);
        assert!(outcome.previous_version.is_none());
        let calls = mgr.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "uninstall");
    }

    #[test]
    fn execute_rollback_records_failure_when_reinstall_errors() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rollback.json");
        let mut orch = RollbackOrchestrator::load(&path).unwrap();
        let mgr = MockManager::default();
        // Pre-load a single failure response.
        mgr.install_fail
            .lock()
            .unwrap()
            .push("simulated reinstall failure".into());
        let job = Uuid::new_v4();
        orch.record_pre_update(job, "p", Some("1.0".into()), now())
            .unwrap();

        let outcome = orch.execute_rollback(&mgr, job, "p", now()).unwrap();
        assert!(!outcome.succeeded);
        assert!(outcome.message.contains("simulated reinstall failure"));
        // Still cleared.
        assert!(orch.pending_entries().is_empty());
    }

    #[test]
    fn execute_rollback_without_record_returns_no_entry_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rollback.json");
        let mut orch = RollbackOrchestrator::load(&path).unwrap();
        let mgr = MockManager::default();
        let err = orch
            .execute_rollback(&mgr, Uuid::nil(), "missing", now())
            .unwrap_err();
        assert!(matches!(err, RollbackError::NoEntry { .. }));
        // No package-manager calls were made.
        assert!(mgr.calls().is_empty());
    }

    #[test]
    fn manifest_round_trips_through_disk_with_multiple_entries() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rollback.json");
        let mut orch = RollbackOrchestrator::load(&path).unwrap();
        let job_a = Uuid::new_v4();
        let job_b = Uuid::new_v4();
        orch.record_pre_update(job_a, "a", Some("1.0".into()), now())
            .unwrap();
        orch.record_pre_update(job_b, "b", None, now()).unwrap();
        let orch2 = RollbackOrchestrator::load(&path).unwrap();
        let mut entries = orch2.pending_entries();
        entries.sort_by(|x, y| x.package_id.cmp(&y.package_id));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].package_id, "a");
        assert_eq!(entries[0].previous_version.as_deref(), Some("1.0"));
        assert_eq!(entries[1].package_id, "b");
        assert!(entries[1].previous_version.is_none());
    }

    #[test]
    fn rollback_outcome_renders_canonical_json() {
        let outcome = RollbackOutcome {
            job_id: Uuid::nil(),
            package_id: "p".into(),
            previous_version: Some("1.0".into()),
            succeeded: true,
            message: "ok".into(),
            attempted_at: chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 5, 7, 8, 0, 0).unwrap(),
        };
        let s = outcome.to_canonical_json();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["package_id"], "p");
        assert_eq!(v["previous_version"], "1.0");
        assert_eq!(v["succeeded"], true);
    }
}
