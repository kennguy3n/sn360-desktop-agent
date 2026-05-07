//! Known rootkit signature paths.
//!
//! The built-in list is derived from the Wazuh `rootkit_files.txt`
//! signature database
//! (https://github.com/wazuh/wazuh/tree/master/etc/rootcheck).
//! Each entry is a path that should not exist on a clean desktop
//! system; if present, it is reported as a rootcheck alert.
//!
//! The signatures here are deliberately a curated subset of the
//! upstream list — they target the high-signal well-known rootkits
//! (Adore, LRK, t0rn, knark, Rk17, Suckit, etc.) rather than every
//! historical CVE. Operators can extend the list via
//! `RootcheckConfig::signature_paths`.

use std::path::Path;

/// A single rootkit signature entry.
#[derive(Debug, Clone)]
pub struct Signature {
    /// Path to check for existence.
    pub path: &'static str,
    /// Rootkit or malware family this signature is associated with.
    pub family: &'static str,
}

/// Built-in signature list.  Intentionally small and conservative so
/// the filesystem sweep is cheap on modern desktops.
pub const BUILTIN_SIGNATURES: &[Signature] = &[
    // Adore / ZK rootkit
    Signature {
        path: "/dev/.udev.d",
        family: "adore-ng",
    },
    Signature {
        path: "/usr/lib/libproc_hider.so",
        family: "libprocesshider",
    },
    // Note: /etc/ld.so.preload is intentionally NOT in this list.
    // It is a legitimate dynamic-linker configuration file (used by
    // jemalloc, tcmalloc, libsafe, etc.), so presence alone is not an
    // indicator. Upstream Wazuh rootcheck inspects the file's contents
    // for references to known malicious `.so` paths; a content-based
    // check would go here if that is ever added.
    // t0rn rootkit
    Signature {
        path: "/usr/src/.puta",
        family: "t0rn",
    },
    Signature {
        path: "/usr/info/.t0rn",
        family: "t0rn",
    },
    // LRK / Linux RootKit family
    Signature {
        path: "/dev/ptyp",
        family: "lrk",
    },
    Signature {
        path: "/dev/ptyq",
        family: "lrk",
    },
    Signature {
        path: "/dev/ptyr",
        family: "lrk",
    },
    // Knark kernel rootkit
    Signature {
        path: "/proc/knark",
        family: "knark",
    },
    // Suckit
    Signature {
        path: "/usr/share/.sniff",
        family: "suckit",
    },
    Signature {
        path: "/sbin/.login",
        family: "suckit",
    },
    // Ramen worm
    Signature {
        path: "/usr/src/.poop",
        family: "ramen",
    },
    // Rk17 / Rk18
    Signature {
        path: "/dev/rd/cdb",
        family: "rk17",
    },
    // Bashdoor / Shellshock backdoors
    Signature {
        path: "/tmp/.sshd",
        family: "bashdoor",
    },
    Signature {
        path: "/tmp/.X11-unix/.1",
        family: "bashdoor",
    },
    // Generic hidden directory indicators
    Signature {
        path: "/etc/.enyelkmHIDE^IT.ko",
        family: "enye-lkm",
    },
    Signature {
        path: "/usr/lib/.kinetic",
        family: "kinetic",
    },
];

/// Output of a single signature check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureHit {
    pub path: String,
    pub family: String,
}

/// Scan the given signature list against the filesystem and return
/// all paths that exist. `extra_paths` is appended to the built-in
/// list so operators can extend coverage without recompiling.
pub fn scan(extra_paths: &[String]) -> Vec<SignatureHit> {
    let mut hits = Vec::new();

    for sig in BUILTIN_SIGNATURES {
        if Path::new(sig.path).exists() {
            hits.push(SignatureHit {
                path: sig.path.to_string(),
                family: sig.family.to_string(),
            });
        }
    }

    for extra in extra_paths {
        if Path::new(extra).exists() {
            hits.push(SignatureHit {
                path: extra.clone(),
                family: "custom".to_string(),
            });
        }
    }

    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_clean_system_returns_no_hits() {
        // Built-in signatures should not match on a clean CI runner.
        // If one does, we surface it loudly so a maintainer can decide
        // whether the rootcheck signature list needs pruning.
        let hits = scan(&[]);
        assert!(
            hits.is_empty(),
            "unexpected rootcheck signature hit on CI: {:?}",
            hits
        );
    }

    #[test]
    fn test_extra_path_hit_reported() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("fake-rootkit-marker");
        std::fs::write(&file, b"").unwrap();

        let hits = scan(&[file.to_string_lossy().to_string()]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, file.to_string_lossy());
        assert_eq!(hits[0].family, "custom");
    }

    #[test]
    fn test_missing_extra_path_not_reported() {
        let hits = scan(&["/this/path/should/never/exist/xyzzy".to_string()]);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_builtin_signatures_are_absolute_paths() {
        for sig in BUILTIN_SIGNATURES {
            assert!(
                sig.path.starts_with('/'),
                "signature path should be absolute: {}",
                sig.path
            );
            assert!(!sig.family.is_empty(), "signature family must be set");
        }
    }
}
