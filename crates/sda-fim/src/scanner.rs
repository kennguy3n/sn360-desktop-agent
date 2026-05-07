//! Periodic full-directory baseline scanner for FIM.
//!
//! Walks all configured directories, compares file metadata against the
//! SQLite state DB, and emits syscheck events for any differences.  This
//! catches changes that occurred while the agent was offline or that the
//! real-time watcher missed.

use std::path::Path;

use tracing::{debug, info, warn};
use walkdir::WalkDir;

use crate::db::StateDb;
use crate::event_format::{format_syscheck_event, ChangeType};
use crate::idle::is_system_idle;

use sda_core::config::FimDirectory;
use sda_event_bus::EventKind;

/// Result counters returned after a baseline scan completes.
#[derive(Debug, Clone, Default)]
pub struct ScanResult {
    pub files_scanned: u64,
    pub new_files: u64,
    pub modified_files: u64,
    pub deleted_files: u64,
}

/// Collected event ready to be published after the blocking scan finishes.
#[derive(Debug)]
pub struct PendingEvent {
    pub kind: EventKind,
}

/// Run a full baseline scan (blocking).
///
/// Opens its own `StateDb` connection so the real-time watcher's connection
/// is not contended.  Collects events into a `Vec<PendingEvent>` that the
/// caller publishes on the async `EventBus` after this function returns.
pub fn run_baseline_scan(
    db_path: &Path,
    directories: &[FimDirectory],
) -> anyhow::Result<(ScanResult, Vec<PendingEvent>)> {
    let db = StateDb::open(db_path)?;
    let scan_timestamp = chrono::Utc::now().to_rfc3339();

    let mut result = ScanResult::default();
    let mut events: Vec<PendingEvent> = Vec::new();

    for dir in directories {
        let dir_path = Path::new(&dir.path);
        if !dir_path.exists() {
            warn!(path = %dir.path, "baseline scan: directory does not exist, skipping");
            continue;
        }

        let walker = if dir.recursive {
            WalkDir::new(dir_path)
        } else {
            WalkDir::new(dir_path).max_depth(1)
        };

        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warn!(error = %e, "baseline scan: error walking directory");
                    continue;
                }
            };

            // Only process files, not directories.
            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();

            // Respect exclude patterns.
            if is_excluded(path, &dir.exclude) {
                debug!(path = %path.display(), "baseline scan: skipping excluded file");
                continue;
            }

            let path_str = path.to_string_lossy().to_string();

            // Collect metadata (blocking I/O).
            let new_entry = match crate::collect_metadata(path, dir.check_sha256) {
                Ok(e) => e,
                Err(e) => {
                    warn!(error = %e, path = %path_str, "baseline scan: failed to collect metadata");
                    continue;
                }
            };

            result.files_scanned += 1;

            // Look up existing entry in DB.
            let old_entry = match db.get_entry(&path_str) {
                Ok(e) => e,
                Err(e) => {
                    warn!(error = %e, path = %path_str, "baseline scan: DB lookup failed");
                    continue;
                }
            };

            match old_entry {
                None => {
                    // New file: not in DB.
                    let syscheck_json = format_syscheck_event(
                        ChangeType::Added,
                        &new_entry.path,
                        None,
                        Some(&new_entry),
                    );
                    if let Err(e) = db.upsert_entry(&new_entry) {
                        warn!(error = %e, path = %path_str, "baseline scan: DB upsert failed");
                    }
                    events.push(PendingEvent {
                        kind: EventKind::FileCreated {
                            path: path_str,
                            syscheck_payload: Some(syscheck_json),
                        },
                    });
                    result.new_files += 1;
                }
                Some(ref old) => {
                    let changed = old.sha256 != new_entry.sha256
                        || old.size != new_entry.size
                        || old.permissions != new_entry.permissions
                        || old.uid != new_entry.uid
                        || old.gid != new_entry.gid
                        || old.mtime != new_entry.mtime;

                    if changed {
                        let syscheck_json = format_syscheck_event(
                            ChangeType::Modified,
                            &new_entry.path,
                            Some(old),
                            Some(&new_entry),
                        );
                        if let Err(e) = db.upsert_entry(&new_entry) {
                            warn!(error = %e, path = %path_str, "baseline scan: DB upsert failed");
                        }
                        events.push(PendingEvent {
                            kind: EventKind::FileModified {
                                path: path_str,
                                syscheck_payload: Some(syscheck_json),
                            },
                        });
                        result.modified_files += 1;
                    } else {
                        // Unchanged — update last_scan timestamp only.
                        if let Err(e) = db.update_last_scan(&path_str, &scan_timestamp) {
                            warn!(error = %e, path = %path_str, "baseline scan: update_last_scan failed");
                        }
                    }
                }
            }

            // Yield to avoid starving other work.
            std::thread::yield_now();
        }
    }

    // Detect deletions: entries in DB whose last_scan is older than this scan.
    let stale_entries = db.get_entries_with_old_scan(&scan_timestamp)?;
    for stale in &stale_entries {
        // Only consider entries under a configured directory.
        let under_config = directories
            .iter()
            .any(|d| Path::new(&stale.path).starts_with(Path::new(&d.path)));
        if !under_config {
            continue;
        }

        let syscheck_json =
            format_syscheck_event(ChangeType::Deleted, &stale.path, Some(stale), None);

        if let Err(e) = db.delete_entry(&stale.path) {
            warn!(error = %e, path = %stale.path, "baseline scan: DB delete failed");
        }

        events.push(PendingEvent {
            kind: EventKind::FileDeleted {
                path: stale.path.clone(),
                syscheck_payload: Some(syscheck_json),
            },
        });
        result.deleted_files += 1;
    }

    Ok((result, events))
}

/// Check whether the system is idle before starting a scan.
///
/// If the system is busy, waits up to `max_retries` times (sleeping
/// `retry_delay` seconds between checks) before giving up.
pub fn wait_for_idle(max_retries: u32, retry_delay_secs: u64) -> bool {
    for attempt in 0..max_retries {
        if is_system_idle() {
            return true;
        }
        info!(
            attempt = attempt + 1,
            max_retries, "system busy, deferring baseline scan"
        );
        std::thread::sleep(std::time::Duration::from_secs(retry_delay_secs));
    }
    // Proceed anyway after exhausting retries.
    warn!("system still busy after retries, proceeding with baseline scan");
    false
}

/// Check whether a file path matches any of the exclude glob patterns.
fn is_excluded(path: &Path, excludes: &[String]) -> bool {
    let path_str = path.to_string_lossy();
    for pattern in excludes {
        if let Ok(glob) = glob_match(pattern, &path_str) {
            if glob {
                return true;
            }
        }
        // Also check if any path component matches the pattern exactly.
        // This handles patterns like ".cache" matching "/home/user/.cache/something".
        if !pattern.contains('*') {
            for component in path.components() {
                if component.as_os_str() == pattern.as_str() {
                    return true;
                }
            }
        }
    }
    false
}

/// Simple glob matching that supports `*` and `**` patterns.
fn glob_match(pattern: &str, text: &str) -> Result<bool, ()> {
    // Use the file name for patterns without path separators.
    let target = if pattern.contains('/') || pattern.contains('\\') {
        text.to_string()
    } else {
        Path::new(text)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default()
    };

    Ok(simple_glob(&target, pattern))
}

/// Minimal glob implementation: `*` matches anything except `/`,
/// `**` matches everything including `/`.
fn simple_glob(text: &str, pattern: &str) -> bool {
    if pattern == "**" || pattern == "*" {
        return true;
    }

    // Handle *.ext patterns (most common case).
    if let Some(ext) = pattern.strip_prefix("*.") {
        return text.ends_with(&format!(".{}", ext));
    }

    // Handle prefix* patterns.
    if let Some(prefix) = pattern.strip_suffix('*') {
        return text.starts_with(prefix);
    }

    // Exact match fallback.
    text == pattern
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::config::FimDirectory;
    use std::fs;
    use tempfile::TempDir;

    fn test_directory(path: &str) -> FimDirectory {
        FimDirectory {
            path: path.to_string(),
            recursive: true,
            realtime: true,
            check_sha256: true,
            exclude: Vec::new(),
        }
    }

    #[test]
    fn test_baseline_scan_detects_new_files() {
        let tmp = TempDir::new().unwrap();
        let db_dir = TempDir::new().unwrap();
        let db_path = db_dir.path().join("fim.db");

        // Create some files.
        fs::write(tmp.path().join("file1.txt"), "hello").unwrap();
        fs::write(tmp.path().join("file2.txt"), "world").unwrap();

        let dirs = vec![test_directory(tmp.path().to_str().unwrap())];
        let (result, events) = run_baseline_scan(&db_path, &dirs).unwrap();

        assert_eq!(result.files_scanned, 2);
        assert_eq!(result.new_files, 2);
        assert_eq!(result.modified_files, 0);
        assert_eq!(result.deleted_files, 0);
        assert_eq!(events.len(), 2);

        // Verify events are FileCreated with syscheck_payload.
        for ev in &events {
            match &ev.kind {
                EventKind::FileCreated {
                    syscheck_payload, ..
                } => {
                    assert!(syscheck_payload.is_some());
                    let payload = syscheck_payload.as_ref().unwrap();
                    let parsed: serde_json::Value = serde_json::from_str(payload).unwrap();
                    assert_eq!(parsed["type"], "event");
                    assert_eq!(parsed["data"]["type"], "added");
                }
                other => panic!("expected FileCreated, got: {:?}", other),
            }
        }
    }

    #[test]
    fn test_baseline_scan_detects_modified_files() {
        let tmp = TempDir::new().unwrap();
        let db_dir = TempDir::new().unwrap();
        let db_path = db_dir.path().join("fim.db");

        let file_path = tmp.path().join("file.txt");
        fs::write(&file_path, "original").unwrap();

        // First scan to populate DB.
        let dirs = vec![test_directory(tmp.path().to_str().unwrap())];
        let (r1, _) = run_baseline_scan(&db_path, &dirs).unwrap();
        assert_eq!(r1.new_files, 1);

        // Modify the file.
        fs::write(&file_path, "modified content that is different").unwrap();

        // Second scan should detect modification.
        let (r2, events) = run_baseline_scan(&db_path, &dirs).unwrap();
        assert_eq!(r2.files_scanned, 1);
        assert_eq!(r2.modified_files, 1);
        assert_eq!(r2.new_files, 0);
        assert_eq!(events.len(), 1);

        match &events[0].kind {
            EventKind::FileModified {
                syscheck_payload, ..
            } => {
                let payload = syscheck_payload.as_ref().unwrap();
                let parsed: serde_json::Value = serde_json::from_str(payload).unwrap();
                assert_eq!(parsed["data"]["type"], "modified");
                let changed = parsed["data"]["changed_attributes"].as_array().unwrap();
                assert!(!changed.is_empty());
            }
            other => panic!("expected FileModified, got: {:?}", other),
        }
    }

    #[test]
    fn test_baseline_scan_detects_deleted_files() {
        let tmp = TempDir::new().unwrap();
        let db_dir = TempDir::new().unwrap();
        let db_path = db_dir.path().join("fim.db");

        let file_path = tmp.path().join("gone.txt");
        fs::write(&file_path, "temporary").unwrap();

        // First scan to populate DB.
        let dirs = vec![test_directory(tmp.path().to_str().unwrap())];
        let (r1, _) = run_baseline_scan(&db_path, &dirs).unwrap();
        assert_eq!(r1.new_files, 1);

        // Delete the file.
        fs::remove_file(&file_path).unwrap();

        // Second scan should detect deletion.
        let (r2, events) = run_baseline_scan(&db_path, &dirs).unwrap();
        assert_eq!(r2.deleted_files, 1);

        let has_delete = events.iter().any(|e| {
            matches!(
                &e.kind,
                EventKind::FileDeleted {
                    path,
                    syscheck_payload: Some(_),
                } if path.contains("gone.txt")
            )
        });
        assert!(has_delete, "should have a FileDeleted event for gone.txt");
    }

    #[test]
    fn test_baseline_scan_skips_excluded_patterns() {
        let tmp = TempDir::new().unwrap();
        let db_dir = TempDir::new().unwrap();
        let db_path = db_dir.path().join("fim.db");

        fs::write(tmp.path().join("keep.txt"), "keep").unwrap();
        fs::write(tmp.path().join("skip.tmp"), "skip").unwrap();
        fs::write(tmp.path().join("also_skip.tmp"), "skip2").unwrap();

        let dirs = vec![FimDirectory {
            path: tmp.path().to_str().unwrap().to_string(),
            recursive: true,
            realtime: true,
            check_sha256: true,
            exclude: vec!["*.tmp".to_string()],
        }];

        let (result, events) = run_baseline_scan(&db_path, &dirs).unwrap();
        assert_eq!(result.files_scanned, 1);
        assert_eq!(result.new_files, 1);

        // Only keep.txt should be in the events.
        assert_eq!(events.len(), 1);
        match &events[0].kind {
            EventKind::FileCreated { path, .. } => {
                assert!(path.contains("keep.txt"));
            }
            other => panic!("expected FileCreated for keep.txt, got: {:?}", other),
        }
    }

    #[test]
    fn test_baseline_scan_respects_check_sha256_flag() {
        let tmp = TempDir::new().unwrap();
        let db_dir = TempDir::new().unwrap();
        let db_path = db_dir.path().join("fim.db");

        fs::write(tmp.path().join("file.txt"), "data").unwrap();

        let dirs = vec![FimDirectory {
            path: tmp.path().to_str().unwrap().to_string(),
            recursive: true,
            realtime: true,
            check_sha256: false,
            exclude: Vec::new(),
        }];

        let (result, events) = run_baseline_scan(&db_path, &dirs).unwrap();
        assert_eq!(result.new_files, 1);

        // When check_sha256 is false, the syscheck payload should not contain a sha256 value
        // in new_attributes (it will be absent or null).
        match &events[0].kind {
            EventKind::FileCreated {
                syscheck_payload, ..
            } => {
                let payload = syscheck_payload.as_ref().unwrap();
                let parsed: serde_json::Value = serde_json::from_str(payload).unwrap();
                // sha256 should not be present in new_attributes.
                assert!(
                    parsed["data"]["new_attributes"]["sha256"].is_null()
                        || parsed["data"]["new_attributes"]
                            .as_object()
                            .map(|o| !o.contains_key("sha256"))
                            .unwrap_or(true),
                    "sha256 should not be present when check_sha256 is false"
                );
            }
            other => panic!("expected FileCreated, got: {:?}", other),
        }
    }

    #[test]
    fn test_baseline_scan_no_changes() {
        let tmp = TempDir::new().unwrap();
        let db_dir = TempDir::new().unwrap();
        let db_path = db_dir.path().join("fim.db");

        fs::write(tmp.path().join("stable.txt"), "unchanged").unwrap();

        let dirs = vec![test_directory(tmp.path().to_str().unwrap())];

        // First scan populates DB.
        let (r1, _) = run_baseline_scan(&db_path, &dirs).unwrap();
        assert_eq!(r1.new_files, 1);

        // Second scan with no changes.
        let (r2, events) = run_baseline_scan(&db_path, &dirs).unwrap();
        assert_eq!(r2.files_scanned, 1);
        assert_eq!(r2.new_files, 0);
        assert_eq!(r2.modified_files, 0);
        assert_eq!(r2.deleted_files, 0);
        assert!(
            events.is_empty(),
            "no events should be emitted for unchanged files"
        );
    }

    #[test]
    fn test_baseline_scan_handles_permission_denied() {
        let tmp = TempDir::new().unwrap();
        let db_dir = TempDir::new().unwrap();
        let db_path = db_dir.path().join("fim.db");

        fs::write(tmp.path().join("readable.txt"), "ok").unwrap();

        // Create a file and make it unreadable (only on Unix).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let unreadable = tmp.path().join("noperm.txt");
            fs::write(&unreadable, "secret").unwrap();
            fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();
        }

        let dirs = vec![test_directory(tmp.path().to_str().unwrap())];
        let result = run_baseline_scan(&db_path, &dirs);
        assert!(
            result.is_ok(),
            "scan should complete despite permission errors"
        );

        let (scan_result, _) = result.unwrap();
        // At minimum the readable file should be scanned.
        assert!(scan_result.files_scanned >= 1);

        // Cleanup: restore permissions so tempdir cleanup works.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let unreadable = tmp.path().join("noperm.txt");
            let _ = fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o644));
        }
    }

    #[test]
    fn test_is_excluded() {
        assert!(is_excluded(
            Path::new("/tmp/foo.tmp"),
            &["*.tmp".to_string()]
        ));
        assert!(!is_excluded(
            Path::new("/tmp/foo.txt"),
            &["*.tmp".to_string()]
        ));
        assert!(is_excluded(
            Path::new("/home/user/.cache/something"),
            &[".cache".to_string()]
        ));
    }

    #[test]
    fn test_simple_glob() {
        assert!(simple_glob("file.tmp", "*.tmp"));
        assert!(!simple_glob("file.txt", "*.tmp"));
        assert!(simple_glob("anything", "*"));
        assert!(simple_glob("anything/nested", "**"));
        assert!(simple_glob("prefix_file", "prefix_*"));
        assert!(simple_glob("exact", "exact"));
        assert!(!simple_glob("not_exact", "exact"));
    }
}
