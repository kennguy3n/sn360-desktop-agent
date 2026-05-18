//! Disk-backed JSON ledger of [`GrantRecord`]s.
//!
//! The store is intentionally minimal — it does not own a database
//! handle. We keep it as a single JSON file inside the agent's
//! state directory because:
//!
//! - it's the same persistence model `sda-pal::admin_manager` uses
//!   for its own grant ledger (so an operator inspecting the system
//!   only has to learn one file format);
//! - the read-write rate is "a handful of writes per grant" and the
//!   ledger is bounded (active grants only); a database is
//!   overkill;
//! - corrupt-on-power-loss is mitigated by writing through a
//!   `tempfile` + atomic rename.
//!
//! See `docs/device-control.md` § 7 (Just-in-Time admin) for the
//! wire/audit schema.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::grant::GrantRecord;

/// Schema version stamped into the on-disk ledger so future
/// migrations can detect old layouts.
const SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("ledger schema {found} is newer than supported {expected}")]
    SchemaTooNew { found: u16, expected: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OnDisk {
    #[serde(default = "default_schema_version")]
    schema_version: u16,
    #[serde(default)]
    records: Vec<GrantRecord>,
}

fn default_schema_version() -> u16 {
    SCHEMA_VERSION
}

/// Disk-backed `Vec<GrantRecord>` ledger.
///
/// The store keeps a clone in memory and serialises the full ledger
/// on every write — `Vec::push` is cheap and the on-disk size is
/// bounded by the number of *active* grants per device (typically
/// 0–3).
#[derive(Debug)]
pub struct GrantStore {
    path: PathBuf,
    records: Vec<GrantRecord>,
}

impl GrantStore {
    /// Open the store at `path`, creating the parent directory and
    /// initialising an empty ledger if the file does not yet exist.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let records = if path.exists() {
            let bytes = fs::read(&path)?;
            if bytes.is_empty() {
                Vec::new()
            } else {
                let on_disk: OnDisk = serde_json::from_slice(&bytes)?;
                if on_disk.schema_version > SCHEMA_VERSION {
                    return Err(StoreError::SchemaTooNew {
                        found: on_disk.schema_version,
                        expected: SCHEMA_VERSION,
                    });
                }
                on_disk.records
            }
        } else {
            Vec::new()
        };
        Ok(Self { path, records })
    }

    /// Path of the underlying ledger file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read-only view of all records the store knows about.
    pub fn records(&self) -> &[GrantRecord] {
        &self.records
    }

    /// Lookup a record by id.
    pub fn get(&self, id: &str) -> Option<&GrantRecord> {
        self.records.iter().find(|r| r.id == id)
    }

    /// Insert a fresh record (does not de-duplicate; callers must
    /// call [`GrantStore::upsert`] when they may overwrite).
    pub fn insert(&mut self, record: GrantRecord) -> Result<(), StoreError> {
        self.records.push(record);
        self.flush()
    }

    /// Insert-or-replace a record by id.
    pub fn upsert(&mut self, record: GrantRecord) -> Result<(), StoreError> {
        if let Some(idx) = self.records.iter().position(|r| r.id == record.id) {
            self.records[idx] = record;
        } else {
            self.records.push(record);
        }
        self.flush()
    }

    /// Remove a record by id; returns `true` iff a record was
    /// removed. Useful for the boot-time GC sweep that drops
    /// terminal records older than a retention window.
    pub fn remove(&mut self, id: &str) -> Result<bool, StoreError> {
        let len_before = self.records.len();
        self.records.retain(|r| r.id != id);
        if self.records.len() != len_before {
            self.flush()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Persist the in-memory ledger to disk via tempfile + rename.
    fn flush(&self) -> Result<(), StoreError> {
        let on_disk = OnDisk {
            schema_version: SCHEMA_VERSION,
            records: self.records.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&on_disk)?;
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        tmp.write_all(&bytes)?;
        tmp.flush()?;
        tmp.persist(&self.path)
            .map_err(|e| StoreError::Io(e.error))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::GrantState;
    use chrono::Utc;
    use sda_pal::admin_manager::UserRef;

    fn user(name: &str) -> UserRef {
        UserRef {
            username: name.into(),
            domain: None,
        }
    }

    fn rec(id: &str) -> GrantRecord {
        let now = Utc::now();
        GrantRecord::new_requested(
            id,
            "ops",
            user("alice"),
            now + chrono::Duration::hours(1),
            now,
        )
    }

    #[test]
    fn open_creates_parent_directory_and_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("grants.json");
        let store = GrantStore::open(&path).unwrap();
        assert!(store.records().is_empty());
        assert!(path.parent().unwrap().exists());
    }

    #[test]
    fn upsert_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let mut store = GrantStore::open(&path).unwrap();
        store.upsert(rec("g-1")).unwrap();
        let mut updated = rec("g-1");
        updated.state = GrantState::Granted;
        store.upsert(updated).unwrap();

        let again = GrantStore::open(&path).unwrap();
        assert_eq!(again.records().len(), 1);
        assert_eq!(again.records()[0].state, GrantState::Granted);
    }

    #[test]
    fn remove_drops_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let mut store = GrantStore::open(&path).unwrap();
        store.upsert(rec("g-1")).unwrap();
        store.upsert(rec("g-2")).unwrap();
        assert!(store.remove("g-1").unwrap());
        assert_eq!(store.records().len(), 1);
        assert_eq!(store.records()[0].id, "g-2");

        let again = GrantStore::open(&path).unwrap();
        assert_eq!(again.records().len(), 1);
        assert_eq!(again.records()[0].id, "g-2");
    }

    #[test]
    fn newer_schema_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let on_disk = serde_json::json!({
            "schema_version": SCHEMA_VERSION + 1,
            "records": []
        });
        std::fs::write(&path, serde_json::to_vec(&on_disk).unwrap()).unwrap();
        let err = GrantStore::open(&path).expect_err("must reject newer schema");
        assert!(matches!(err, StoreError::SchemaTooNew { .. }), "{err:?}");
    }

    #[test]
    fn empty_file_is_accepted_as_empty_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        std::fs::write(&path, b"").unwrap();
        let store = GrantStore::open(&path).unwrap();
        assert!(store.records().is_empty());
    }
}
