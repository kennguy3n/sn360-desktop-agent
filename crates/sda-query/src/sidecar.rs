//! osquery sidecar lifecycle (spawn / health-check / shutdown).
//!
//! Currently ships only the *resolution* and *probe* primitives —
//! we look up the configured binary path, decide whether the
//! sidecar can be launched at all, and emit a structured warning
//! if it can't. Actually spawning the child process and connecting
//! to its extension socket is not yet wired.
//!
//! Splitting this out now lets the [`crate::QueryModule::start`]
//! supervisor make the right scheduling decision (idle vs. active
//! poll) without compiling against `tokio::process` until the
//! executor catches up.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Sidecar resource budget — sourced from
/// `modules.query.osquery.budget` in the agent config.
///
/// We pull this into its own struct so the supervisor can tighten
/// it under [`sda_core::PowerProfile::CriticalBattery`] without
/// rewriting the sidecar config at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SidecarBudget {
    /// Hard cap on the sidecar's RSS, in MB.
    pub max_rss_mb: u32,
    /// Hard cap on the sidecar's CPU usage, as a percentage 0-100.
    pub max_cpu_percent: u8,
}

impl SidecarBudget {
    /// Defaults from `docs/configuration-reference.md` (Query /
    /// osquery sidecar section).
    pub const fn default_phase1() -> Self {
        Self {
            max_rss_mb: 60,
            max_cpu_percent: 5,
        }
    }
}

/// Result of probing the configured osquery path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// The binary exists and is executable.
    Available { path: PathBuf },
    /// The configured path does not exist or is not executable.
    /// The supervisor logs this as a warning and stays idle —
    /// the rest of the agent must keep working.
    Missing { tried: PathBuf, reason: String },
    /// `modules.query.osquery.mode` is not `"sidecar"`. We
    /// short-circuit the probe entirely.
    DisabledByConfig,
}

/// Probe the configured osquery binary path without spawning it.
///
/// This is a pure-fs check — we deliberately avoid `Command::new`
/// here so that running the unit tests on a CI host without
/// osquery installed does not ever try to fork a binary that's
/// missing.
pub fn probe(path: Option<&Path>) -> ProbeResult {
    let Some(path) = path else {
        return ProbeResult::DisabledByConfig;
    };
    if !path.exists() {
        return ProbeResult::Missing {
            tried: path.to_path_buf(),
            reason: "no such file".into(),
        };
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.permissions().mode();
                // Any execute bit (owner / group / world) is fine
                // — we just need to know we *could* exec the file.
                if mode & 0o111 == 0 {
                    return ProbeResult::Missing {
                        tried: path.to_path_buf(),
                        reason: "not executable (no +x bit)".into(),
                    };
                }
            }
            Err(e) => {
                return ProbeResult::Missing {
                    tried: path.to_path_buf(),
                    reason: format!("stat failed: {e}"),
                };
            }
        }
    }
    #[cfg(not(unix))]
    {
        // On Windows we trust the file extension + existence
        // — a deeper check would require parsing the PE header.
        let ext_ok = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("exe"))
            .unwrap_or(false);
        if !ext_ok {
            return ProbeResult::Missing {
                tried: path.to_path_buf(),
                reason: "expected .exe extension".into(),
            };
        }
    }
    ProbeResult::Available {
        path: path.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_defaults_match_architecture_doc() {
        let b = SidecarBudget::default_phase1();
        assert_eq!(b.max_rss_mb, 60);
        assert_eq!(b.max_cpu_percent, 5);
    }

    #[test]
    fn none_path_is_disabled() {
        assert_eq!(probe(None), ProbeResult::DisabledByConfig);
    }

    #[test]
    fn missing_file_is_reported() {
        let r = probe(Some(Path::new("/this/path/should/not/exist/osqueryd")));
        match r {
            ProbeResult::Missing { reason, .. } => assert!(reason.contains("no such file")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn existing_executable_is_available() {
        // /bin/sh is guaranteed to exist and be +x on a sane Linux
        // box; we use it as a stand-in for osqueryd here.
        let r = probe(Some(Path::new("/bin/sh")));
        assert!(matches!(r, ProbeResult::Available { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn existing_non_executable_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("not-executable");
        std::fs::write(&p, b"#!/bin/sh\necho hi").unwrap();
        // Default umask leaves it writable but not necessarily
        // executable; force-reset to mode 0o644.
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&p, perms).unwrap();
        let r = probe(Some(&p));
        match r {
            ProbeResult::Missing { reason, .. } => assert!(reason.contains("not executable")),
            other => panic!("unexpected: {other:?}"),
        }
    }
}
