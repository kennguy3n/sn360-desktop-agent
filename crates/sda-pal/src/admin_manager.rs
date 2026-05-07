//! Admin / root account inventory and JIT-grant management.
//!
//! This module is the cross-platform PAL surface for Device Control's
//! admin/root review and JIT-admin (Phase 3) features. The
//! [`AdminManager`] trait is implemented per OS via `cfg`-gated impls
//! that ship in this crate; callers (e.g. `sda-device-control`) should
//! always go through the trait and never reach for the OS-specific
//! types directly.
//!
//! Phase 1 scope (this file): `list_admins()` is functional on every
//! supported OS. `grant_admin` / `revoke_admin` / `observed_grants`
//! are stubs that return `Err` until the JIT-admin work in Phase 3.
//!
//! See `docs/device-control/ARCHITECTURE.md` § 5 for the trait
//! definition and `docs/device-control/SCHEMAS.md` § 5 for how the
//! types here surface on the wire as `Finding` / `Recommendation`
//! payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io;

/// Errors produced by [`AdminManager`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// The underlying OS command exited non-zero or could not be
    /// invoked.
    #[error("admin manager OS command failed: {0}")]
    Command(String),
    /// I/O error invoking the OS helper (e.g. binary not on PATH).
    #[error("admin manager IO error: {0}")]
    Io(#[from] io::Error),
    /// Operation is not implemented for this phase / platform yet.
    #[error("not implemented in Phase 1")]
    NotImplemented,
}

/// A single administrator-equivalent account observed on this device.
///
/// `username` is the local-OS-visible login (UTF-8). `source`
/// distinguishes `"local"` vs. `"domain"` (Windows AD) vs.
/// `"cloud"` (Entra ID, Jamf Connect, …) — Phase 1 only emits
/// `"local"` and (on Windows) `"domain"`. `since` is the best-effort
/// observation timestamp; agents that cannot derive it from event-log
/// metadata leave it `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminAccount {
    /// OS-visible account login (e.g. `"alice"`, `"DOMAIN\\bob"`).
    pub username: String,
    /// Where the account is anchored (`"local"`, `"domain"`,
    /// `"cloud"`).
    pub source: String,
    /// First time this admin was observed on this device, if known.
    pub since: Option<DateTime<Utc>>,
    /// Free-form group label that conferred admin (e.g. `"wheel"`,
    /// `"sudo"`, `"Administrators"`, `"admin"`).
    pub group: Option<String>,
}

/// Reference to a user that should be granted admin rights.
///
/// We deliberately do NOT use the host's native user-id type here —
/// the trait surface stays string-based so the same `UserRef` can be
/// passed to a Windows SID lookup, a macOS dscl call, or a Linux
/// useradd.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRef {
    /// Login name (e.g. `"alice"`, `"DOMAIN\\bob"`).
    pub username: String,
    /// Optional domain qualifier (Windows AD / Entra ID).
    pub domain: Option<String>,
}

/// Opaque handle to an active or historical JIT-admin grant.
///
/// Phase 3 will lookup `id` in a server-issued grant ledger to revoke
/// the grant or audit it; Phase 1 only ships the type so downstream
/// callers can compile against the final trait shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantHandle {
    /// Server-issued, opaque grant ID.
    pub id: String,
    /// User the grant applies to.
    pub user: UserRef,
    /// Wall-clock UTC time after which the grant must be revoked.
    pub until: DateTime<Utc>,
}

/// Cross-platform admin/root account inventory and JIT-admin control.
///
/// The full trait is the binding spec from
/// `docs/device-control/ARCHITECTURE.md` § 5. Phase 1 only requires
/// `list_admins` to be functional; the grant/revoke/observed methods
/// land in Phase 3.
pub trait AdminManager: Send + Sync {
    /// Enumerate every account that currently has admin/root rights
    /// on this device.
    fn list_admins(&self) -> Result<Vec<AdminAccount>, AdminError>;

    /// Grant `user` admin rights until `until`. Phase 3.
    fn grant_admin(&self, user: &UserRef, until: DateTime<Utc>) -> Result<GrantHandle, AdminError>;

    /// Revoke a previously-issued grant. Phase 3.
    fn revoke_admin(&self, handle: &GrantHandle) -> Result<(), AdminError>;

    /// Return every grant the agent has observed on this device.
    /// Phase 3.
    fn observed_grants(&self) -> Result<Vec<GrantHandle>, AdminError>;
}

// =====================================================================
// Linux implementation
// =====================================================================

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::fs;
    use std::process::Command;

    /// Linux admin-manager backed by `/etc/group` and `id` for UID 0
    /// detection. Enumerates `wheel` and `sudo` group members plus
    /// any non-root account whose UID == 0.
    pub struct LinuxAdminManager;

    impl Default for LinuxAdminManager {
        fn default() -> Self {
            Self::new()
        }
    }

    impl LinuxAdminManager {
        pub fn new() -> Self {
            Self
        }

        /// Parse `/etc/group` content for the named groups and return
        /// the union of their memberships, paired with the matching
        /// group name.
        pub(crate) fn parse_group_members(
            etc_group: &str,
            group_names: &[&str],
        ) -> Vec<(String, String)> {
            let mut out = Vec::new();
            for line in etc_group.lines() {
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut parts = line.split(':');
                let group = match parts.next() {
                    Some(g) => g,
                    None => continue,
                };
                if !group_names.contains(&group) {
                    continue;
                }
                // password (parts.next()), gid (parts.next()),
                // members (parts.next())
                let members = parts.nth(2).unwrap_or("");
                for m in members.split(',') {
                    let m = m.trim();
                    if !m.is_empty() {
                        out.push((m.to_string(), group.to_string()));
                    }
                }
            }
            out
        }

        /// Parse `/etc/passwd` content and return any login whose UID
        /// is 0 and is not literally named `root`.
        pub(crate) fn parse_uid_zero_aliases(etc_passwd: &str) -> Vec<String> {
            let mut out = Vec::new();
            for line in etc_passwd.lines() {
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut parts = line.split(':');
                let name = match parts.next() {
                    Some(n) => n,
                    None => continue,
                };
                // skip password field
                let _ = parts.next();
                let uid = parts.next().unwrap_or("");
                if uid == "0" && name != "root" {
                    out.push(name.to_string());
                }
            }
            out
        }
    }

    impl AdminManager for LinuxAdminManager {
        fn list_admins(&self) -> Result<Vec<AdminAccount>, AdminError> {
            let etc_group = fs::read_to_string("/etc/group").map_err(AdminError::from)?;
            let etc_passwd = fs::read_to_string("/etc/passwd").map_err(AdminError::from)?;

            let mut admins: Vec<AdminAccount> = Vec::new();

            // Always include root itself.
            admins.push(AdminAccount {
                username: "root".to_string(),
                source: "local".to_string(),
                since: None,
                group: Some("root".to_string()),
            });

            for (user, group) in Self::parse_group_members(&etc_group, &["wheel", "sudo", "admin"])
            {
                if !admins.iter().any(|a| a.username == user) {
                    admins.push(AdminAccount {
                        username: user,
                        source: "local".to_string(),
                        since: None,
                        group: Some(group),
                    });
                }
            }

            for alias in Self::parse_uid_zero_aliases(&etc_passwd) {
                if !admins.iter().any(|a| a.username == alias) {
                    admins.push(AdminAccount {
                        username: alias,
                        source: "local".to_string(),
                        since: None,
                        group: Some("uid0".to_string()),
                    });
                }
            }

            Ok(admins)
        }

        fn grant_admin(
            &self,
            _user: &UserRef,
            _until: DateTime<Utc>,
        ) -> Result<GrantHandle, AdminError> {
            Err(AdminError::NotImplemented)
        }

        fn revoke_admin(&self, _handle: &GrantHandle) -> Result<(), AdminError> {
            Err(AdminError::NotImplemented)
        }

        fn observed_grants(&self) -> Result<Vec<GrantHandle>, AdminError> {
            Err(AdminError::NotImplemented)
        }
    }

    /// Best-effort runtime fallback used by tests when `/etc/group`
    /// is unreadable. Not exported.
    #[allow(dead_code)]
    pub(crate) fn current_user_via_id() -> Option<String> {
        Command::new("id").arg("-un").output().ok().and_then(|out| {
            if out.status.success() {
                String::from_utf8(out.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::LinuxAdminManager;

// =====================================================================
// macOS implementation
// =====================================================================

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;
    use std::process::Command;

    /// macOS admin-manager backed by `dscl . -read /Groups/admin
    /// GroupMembership`.
    pub struct MacAdminManager;

    impl MacAdminManager {
        pub fn new() -> Self {
            Self
        }

        /// Parse the multi-line output of
        /// `dscl . -read /Groups/admin GroupMembership` and return
        /// the membership list. The output looks like:
        ///
        ///   `GroupMembership: root alice bob`
        ///
        /// or, for empty groups, no `GroupMembership:` line at all.
        pub(crate) fn parse_dscl_membership(out: &str) -> Vec<String> {
            for line in out.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("GroupMembership:") {
                    return rest.split_whitespace().map(|s| s.to_string()).collect();
                }
                if let Some(rest) = line.strip_prefix("GroupMembership :") {
                    return rest.split_whitespace().map(|s| s.to_string()).collect();
                }
            }
            Vec::new()
        }
    }

    impl AdminManager for MacAdminManager {
        fn list_admins(&self) -> Result<Vec<AdminAccount>, AdminError> {
            let output = Command::new("dscl")
                .args([".", "-read", "/Groups/admin", "GroupMembership"])
                .output()
                .map_err(AdminError::from)?;
            if !output.status.success() {
                return Err(AdminError::Command(format!(
                    "dscl exited with status {:?}",
                    output.status.code()
                )));
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            let users = Self::parse_dscl_membership(&stdout);
            Ok(users
                .into_iter()
                .map(|u| AdminAccount {
                    username: u,
                    source: "local".to_string(),
                    since: None,
                    group: Some("admin".to_string()),
                })
                .collect())
        }

        fn grant_admin(
            &self,
            _user: &UserRef,
            _until: DateTime<Utc>,
        ) -> Result<GrantHandle, AdminError> {
            Err(AdminError::NotImplemented)
        }

        fn revoke_admin(&self, _handle: &GrantHandle) -> Result<(), AdminError> {
            Err(AdminError::NotImplemented)
        }

        fn observed_grants(&self) -> Result<Vec<GrantHandle>, AdminError> {
            Err(AdminError::NotImplemented)
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos_impl::MacAdminManager;

// =====================================================================
// Windows implementation
// =====================================================================

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use std::process::Command;

    /// Windows admin-manager backed by `net localgroup Administrators`.
    pub struct WindowsAdminManager;

    impl WindowsAdminManager {
        pub fn new() -> Self {
            Self
        }

        /// Parse `net localgroup Administrators` output. Format:
        ///
        ///   ```text
        ///   Alias name     Administrators
        ///   Comment        Administrators have complete and unrestricted access ...
        ///
        ///   Members
        ///
        ///   ---------------------------------------------------------
        ///   Administrator
        ///   DOMAIN\alice
        ///   The command completed successfully.
        ///   ```
        pub(crate) fn parse_net_localgroup(out: &str) -> Vec<AdminAccount> {
            let mut admins = Vec::new();
            let mut in_members = false;
            for line in out.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if line.starts_with("---") {
                    // Line of dashes — start of the membership block.
                    in_members = true;
                    continue;
                }
                if !in_members {
                    continue;
                }
                if line
                    .to_ascii_lowercase()
                    .starts_with("the command completed")
                {
                    break;
                }
                let (username, source) = if let Some(idx) = line.find('\\') {
                    // DOMAIN\user → split on first backslash.
                    //
                    // Special case: ".\user" or "\user" (empty domain
                    // prefix) refers to a local-machine account in
                    // Windows naming. Treat those as "local"; only
                    // genuine non-empty / non-"." domain prefixes mean
                    // an Active Directory / Entra account.
                    let domain = &line[..idx];
                    let source = if domain == "." || domain.is_empty() {
                        "local".to_string()
                    } else {
                        "domain".to_string()
                    };
                    (line.to_string(), source)
                } else {
                    (line.to_string(), "local".to_string())
                };
                admins.push(AdminAccount {
                    username,
                    source,
                    since: None,
                    group: Some("Administrators".to_string()),
                });
            }
            admins
        }
    }

    impl AdminManager for WindowsAdminManager {
        fn list_admins(&self) -> Result<Vec<AdminAccount>, AdminError> {
            let output = Command::new("net")
                .args(["localgroup", "Administrators"])
                .output()
                .map_err(AdminError::from)?;
            if !output.status.success() {
                return Err(AdminError::Command(format!(
                    "net localgroup exited with status {:?}",
                    output.status.code()
                )));
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(Self::parse_net_localgroup(&stdout))
        }

        fn grant_admin(
            &self,
            _user: &UserRef,
            _until: DateTime<Utc>,
        ) -> Result<GrantHandle, AdminError> {
            Err(AdminError::NotImplemented)
        }

        fn revoke_admin(&self, _handle: &GrantHandle) -> Result<(), AdminError> {
            Err(AdminError::NotImplemented)
        }

        fn observed_grants(&self) -> Result<Vec<GrantHandle>, AdminError> {
            Err(AdminError::NotImplemented)
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::WindowsAdminManager;

// =====================================================================
// Default factory
// =====================================================================

/// Returns the platform-default [`AdminManager`] for this host.
///
/// On unsupported targets returns `None` instead of panicking so that
/// the agent can run with the admin-inventory feature disabled.
pub fn default_admin_manager() -> Option<Box<dyn AdminManager>> {
    #[cfg(target_os = "linux")]
    {
        Some(Box::new(LinuxAdminManager::new()))
    }
    #[cfg(target_os = "macos")]
    {
        Some(Box::new(MacAdminManager::new()))
    }
    #[cfg(target_os = "windows")]
    {
        Some(Box::new(WindowsAdminManager::new()))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_account_serde_roundtrip() {
        let acc = AdminAccount {
            username: "alice".to_string(),
            source: "local".to_string(),
            since: None,
            group: Some("wheel".to_string()),
        };
        let json = serde_json::to_string(&acc).unwrap();
        let back: AdminAccount = serde_json::from_str(&json).unwrap();
        assert_eq!(acc, back);
    }

    #[test]
    fn admin_error_not_implemented_message() {
        let err = AdminError::NotImplemented;
        assert_eq!(err.to_string(), "not implemented in Phase 1");
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;

        const SAMPLE_GROUP: &str = "\
root:x:0:
daemon:x:1:
sudo:x:27:alice,bob
wheel:x:10:carol
admin:x:11:dave
nogroup:x:65534:
";

        const SAMPLE_PASSWD: &str = "\
root:x:0:0:root:/root:/bin/bash
toor:x:0:0:alt-root:/root:/bin/bash
alice:x:1000:1000:alice:/home/alice:/bin/bash
bin:x:2:2:bin:/bin:/usr/sbin/nologin
";

        #[test]
        fn parses_wheel_sudo_admin_groups() {
            let mems =
                LinuxAdminManager::parse_group_members(SAMPLE_GROUP, &["wheel", "sudo", "admin"]);
            let names: Vec<String> = mems.iter().map(|(u, _)| u.clone()).collect();
            assert!(names.contains(&"alice".to_string()));
            assert!(names.contains(&"bob".to_string()));
            assert!(names.contains(&"carol".to_string()));
            assert!(names.contains(&"dave".to_string()));
            assert!(!names.contains(&"daemon".to_string()));
        }

        #[test]
        fn parses_uid_zero_aliases_excluding_root() {
            let aliases = LinuxAdminManager::parse_uid_zero_aliases(SAMPLE_PASSWD);
            assert_eq!(aliases, vec!["toor".to_string()]);
        }

        #[test]
        fn list_admins_on_build_host_returns_root() {
            let mgr = LinuxAdminManager::new();
            // On any reasonable Linux build host /etc/group + /etc/passwd
            // exist and contain root. We don't assert membership of
            // wheel/sudo because that varies by container.
            let admins = mgr.list_admins().expect("list_admins");
            assert!(
                admins.iter().any(|a| a.username == "root"),
                "expected root in admins: {admins:?}"
            );
        }

        #[test]
        fn grant_revoke_are_not_implemented() {
            let mgr = LinuxAdminManager::new();
            let user = UserRef {
                username: "alice".into(),
                domain: None,
            };
            let until = Utc::now();
            assert!(matches!(
                mgr.grant_admin(&user, until),
                Err(AdminError::NotImplemented)
            ));
            let handle = GrantHandle {
                id: "grant-1".into(),
                user,
                until,
            };
            assert!(matches!(
                mgr.revoke_admin(&handle),
                Err(AdminError::NotImplemented)
            ));
            assert!(matches!(
                mgr.observed_grants(),
                Err(AdminError::NotImplemented)
            ));
        }
    }

    // Cross-platform tests: dscl and net-localgroup parsing live in
    // their cfg-gated impls, but their parsing logic should still be
    // exercised on every CI host. We test the parsers via the
    // [`cfg(target_os = ...)`] gates below.
    #[cfg(target_os = "macos")]
    mod macos_tests {
        use super::*;

        #[test]
        fn parses_dscl_membership_line() {
            let out = "GroupMembership: root alice bob\n";
            let users = MacAdminManager::parse_dscl_membership(out);
            assert_eq!(users, vec!["root", "alice", "bob"]);
        }

        #[test]
        fn parses_dscl_membership_with_space_before_colon() {
            // Some macOS versions emit "GroupMembership :" with a space.
            let out = "GroupMembership : alice\n";
            let users = MacAdminManager::parse_dscl_membership(out);
            assert_eq!(users, vec!["alice"]);
        }

        #[test]
        fn parses_dscl_empty_membership() {
            let out = "name: admin\n";
            let users = MacAdminManager::parse_dscl_membership(out);
            assert!(users.is_empty());
        }

        #[test]
        fn list_admins_on_build_host_returns_some() {
            let mgr = MacAdminManager::new();
            let admins = mgr.list_admins().expect("list_admins");
            // Build host should always have at least the local admin.
            assert!(!admins.is_empty());
        }
    }

    #[cfg(target_os = "windows")]
    mod windows_tests {
        use super::*;

        const SAMPLE: &str = r"
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
CONTOSO\alice
.\bob
The command completed successfully.

";

        #[test]
        fn parses_net_localgroup_output() {
            let admins = WindowsAdminManager::parse_net_localgroup(SAMPLE);
            assert_eq!(admins.len(), 3);
            assert_eq!(admins[0].username, "Administrator");
            assert_eq!(admins[0].source, "local");
            assert_eq!(admins[1].username, "CONTOSO\\alice");
            assert_eq!(admins[1].source, "domain");
            // Regression test (PR #4 review): `.\bob` is the Windows
            // shorthand for a *local* account; the parser previously
            // misclassified it as `domain` because the simple
            // backslash-presence test ignored the special "." prefix.
            assert_eq!(admins[2].username, ".\\bob");
            assert_eq!(admins[2].source, "local");
        }

        #[test]
        fn dot_prefix_is_local_account() {
            // Just the `.\` line by itself, exercising the fix in
            // isolation from the rest of the membership block.
            let sample = "
Members

-------------------------------------------------------------------------------
.\\carol
The command completed successfully.

";
            let admins = WindowsAdminManager::parse_net_localgroup(sample);
            assert_eq!(admins.len(), 1);
            assert_eq!(admins[0].username, ".\\carol");
            assert_eq!(admins[0].source, "local");
        }

        #[test]
        fn empty_domain_prefix_is_local_account() {
            // Belt-and-braces: a literal leading backslash with no
            // domain at all is also local.
            let sample = "
Members

-------------------------------------------------------------------------------
\\dave
The command completed successfully.

";
            let admins = WindowsAdminManager::parse_net_localgroup(sample);
            assert_eq!(admins.len(), 1);
            assert_eq!(admins[0].username, "\\dave");
            assert_eq!(admins[0].source, "local");
        }

        #[test]
        fn parses_empty_membership() {
            let out = "
Alias name     Administrators
Comment        ...

Members

-------------------------------------------------------------------------------
The command completed successfully.

";
            let admins = WindowsAdminManager::parse_net_localgroup(out);
            assert!(admins.is_empty());
        }
    }
}
