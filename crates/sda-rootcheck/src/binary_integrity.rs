//! System binary integrity checks.
//!
//! Tracks SHA-256 hashes of critical system binaries against a
//! baseline file on disk. On first run the baseline is created from
//! the current filesystem state; on subsequent runs any drift is
//! reported as a rootcheck alert.
//!
//! The baseline is a simple JSON map of
//! `{ "path": { "sha256": "...", "recorded_at": "..." } }`. JSON was
//! chosen over SQLite to keep the rootcheck crate lightweight — the
//! baseline typically fits in well under 4 KB.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Read-buffer size used when hashing binaries (8 KB).
const HASH_BUF_SIZE: usize = 8 * 1024;

/// Compute the SHA-256 digest of a file as a lowercase hex string.
///
/// Performs blocking I/O; call from a blocking context (e.g.
/// `tokio::task::spawn_blocking`).
pub fn hash_file(path: &Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("failed to open {}: {}", path.display(), e))?;

    let mut hasher = Sha256::new();
    let mut buf = [0u8; HASH_BUF_SIZE];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path.display(), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// A single baseline entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BaselineEntry {
    pub sha256: String,
    /// RFC-3339 timestamp of when this entry was recorded.
    pub recorded_at: String,
}

/// On-disk baseline for tracked binaries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Baseline {
    pub entries: BTreeMap<String, BaselineEntry>,
}

impl Baseline {
    /// Load the baseline from disk, returning an empty baseline if
    /// the file does not exist yet.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read baseline {}: {}", path.display(), e))?;
        let baseline: Self = serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("failed to parse baseline: {}", e))?;
        Ok(baseline)
    }

    /// Persist the baseline to disk, creating parent directories as
    /// needed. The file is written atomically via a temp file +
    /// rename so an interrupted write can never leave a corrupted
    /// baseline behind.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow::anyhow!("failed to create baseline dir {}: {}", parent.display(), e)
            })?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize baseline: {}", e))?;

        let tmp: PathBuf = path.with_extension("json.tmp");
        std::fs::write(&tmp, json)
            .map_err(|e| anyhow::anyhow!("failed to write {}: {}", tmp.display(), e))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| anyhow::anyhow!("failed to rename baseline: {}", e))?;
        Ok(())
    }
}

/// Kind of drift reported against the baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftKind {
    /// Binary hash differs from the baseline.
    HashChanged {
        old_sha256: String,
        new_sha256: String,
    },
    /// Binary that was recorded in the baseline has since been removed.
    Missing { old_sha256: String },
}

/// A single drift finding produced by [`compare`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftAlert {
    pub path: String,
    pub kind: DriftKind,
}

/// Compute the SHA-256 of every path in `binaries` and compare
/// against `baseline`.
///
/// - Paths present in `baseline` but whose hash now differs →
///   [`DriftKind::HashChanged`].
/// - Paths present in `baseline` that no longer exist on disk →
///   [`DriftKind::Missing`].
/// - Paths not yet in `baseline` are inserted into `updated_baseline`
///   so the caller can persist them as "newly seen, trusted".
///
/// Returns `(drift_alerts, updated_baseline)`. The caller decides
/// whether to overwrite the on-disk baseline; typically this happens
/// after the first run (baseline was empty) but subsequent runs
/// leave the existing baseline in place even when drift is detected.
pub fn compare(baseline: &Baseline, binaries: &[String]) -> (Vec<DriftAlert>, Baseline) {
    let mut drift = Vec::new();
    let mut updated = baseline.clone();
    let now = chrono::Utc::now().to_rfc3339();

    for binary in binaries {
        let path = Path::new(binary);
        let existed_in_baseline = baseline.entries.contains_key(binary);

        if !path.exists() {
            if let Some(old) = baseline.entries.get(binary) {
                drift.push(DriftAlert {
                    path: binary.clone(),
                    kind: DriftKind::Missing {
                        old_sha256: old.sha256.clone(),
                    },
                });
            }
            continue;
        }

        let new_hash = match hash_file(path) {
            Ok(h) => h,
            Err(_) => continue,
        };

        match baseline.entries.get(binary) {
            Some(old) if old.sha256 != new_hash => {
                drift.push(DriftAlert {
                    path: binary.clone(),
                    kind: DriftKind::HashChanged {
                        old_sha256: old.sha256.clone(),
                        new_sha256: new_hash.clone(),
                    },
                });
            }
            _ => {}
        }

        if !existed_in_baseline {
            updated.entries.insert(
                binary.clone(),
                BaselineEntry {
                    sha256: new_hash,
                    recorded_at: now.clone(),
                },
            );
        }
    }

    (drift, updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_file(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
        path
    }

    #[test]
    fn test_hash_known_content() {
        let tmp = TempDir::new().unwrap();
        let p = write_file(&tmp, "ls", b"hello world");
        let hash = hash_file(&p).unwrap();
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_baseline_save_and_load_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let baseline_path = tmp.path().join("nested/dir/baseline.json");

        let mut baseline = Baseline::default();
        baseline.entries.insert(
            "/usr/bin/ls".to_string(),
            BaselineEntry {
                sha256: "abc123".to_string(),
                recorded_at: "2026-04-19T00:00:00Z".to_string(),
            },
        );

        baseline.save(&baseline_path).unwrap();
        let loaded = Baseline::load(&baseline_path).unwrap();
        assert_eq!(loaded.entries, baseline.entries);
    }

    #[test]
    fn test_baseline_load_missing_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("does-not-exist.json");
        let baseline = Baseline::load(&path).unwrap();
        assert!(baseline.entries.is_empty());
    }

    #[test]
    fn test_compare_first_run_has_no_drift_but_records_baseline() {
        let tmp = TempDir::new().unwrap();
        let ls = write_file(&tmp, "ls", b"ls-v1");
        let ps = write_file(&tmp, "ps", b"ps-v1");
        let binaries = vec![
            ls.to_string_lossy().to_string(),
            ps.to_string_lossy().to_string(),
        ];

        let (drift, updated) = compare(&Baseline::default(), &binaries);
        assert!(
            drift.is_empty(),
            "first-run comparison must not produce drift: {:?}",
            drift
        );
        assert_eq!(updated.entries.len(), 2);
        assert!(updated
            .entries
            .contains_key(&ls.to_string_lossy().to_string()));
    }

    #[test]
    fn test_compare_detects_hash_change() {
        let tmp = TempDir::new().unwrap();
        let ls = write_file(&tmp, "ls", b"ls-v1");
        let binaries = vec![ls.to_string_lossy().to_string()];

        let (_drift, baseline) = compare(&Baseline::default(), &binaries);

        // Replace the file contents to simulate tampering.
        std::fs::write(&ls, b"ls-tampered").unwrap();

        let (drift, _) = compare(&baseline, &binaries);
        assert_eq!(drift.len(), 1);
        match &drift[0].kind {
            DriftKind::HashChanged {
                old_sha256,
                new_sha256,
            } => {
                assert_ne!(old_sha256, new_sha256);
            }
            other => panic!("expected HashChanged, got {:?}", other),
        }
    }

    #[test]
    fn test_compare_detects_missing_binary() {
        let tmp = TempDir::new().unwrap();
        let ls = write_file(&tmp, "ls", b"ls-v1");
        let binaries = vec![ls.to_string_lossy().to_string()];

        let (_drift, baseline) = compare(&Baseline::default(), &binaries);
        std::fs::remove_file(&ls).unwrap();

        let (drift, _) = compare(&baseline, &binaries);
        assert_eq!(drift.len(), 1);
        assert!(matches!(drift[0].kind, DriftKind::Missing { .. }));
    }

    #[test]
    fn test_compare_stable_when_no_changes() {
        let tmp = TempDir::new().unwrap();
        let ls = write_file(&tmp, "ls", b"ls-v1");
        let binaries = vec![ls.to_string_lossy().to_string()];

        let (_drift, baseline) = compare(&Baseline::default(), &binaries);
        let (drift, _) = compare(&baseline, &binaries);
        assert!(drift.is_empty());
    }
}
