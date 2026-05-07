//! Admin / root account inventory and JIT-grant management.
//!
//! This module is the cross-platform PAL surface for Device Control's
//! admin/root review and JIT-admin (Phase 3) features. The
//! [`AdminManager`] trait is implemented per OS via `cfg`-gated impls
//! that ship in this crate; callers (e.g. `sda-device-control`) should
//! always go through the trait and never reach for the OS-specific
//! types directly.
//!
//! Phase 1 scope: `list_admins()` is functional on every supported
//! OS.
//!
//! Phase 3 (this file): `grant_admin` / `revoke_admin` /
//! `observed_grants` issue real time-boxed admin grants on every
//! supported platform and persist them in a JSON state file under
//! the agent's cache directory. The actual privileged commands are
//! invoked through a [`CommandRunner`] indirection so that the per-OS
//! grant/revoke logic can be unit-tested without root.
//!
//! See `docs/device-control/ARCHITECTURE.md` § 5 for the trait
//! definition and `docs/device-control/SCHEMAS.md` § 5 for how the
//! types here surface on the wire as `Finding` / `Recommendation`
//! payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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
    /// Caller-supplied input failed validation (bad username, etc.).
    #[error("admin manager input invalid: {0}")]
    InvalidInput(String),
    /// The grant state file could not be parsed.
    #[error("admin manager grant state corrupt: {0}")]
    StateCorrupt(String),
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
// Command runner abstraction (test-friendly indirection)
// =====================================================================

/// Captured stdout / stderr / exit-status of an external command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl CommandOutput {
    /// `true` iff the wrapped command exited with status 0.
    pub fn is_success(&self) -> bool {
        self.status == 0
    }

    /// Raise [`AdminError::Command`] when the command failed, otherwise
    /// pass the output through.
    pub fn require_success(self, label: &str) -> Result<Self, AdminError> {
        if self.is_success() {
            Ok(self)
        } else {
            let stderr = String::from_utf8_lossy(&self.stderr).trim().to_string();
            Err(AdminError::Command(format!(
                "{label} exited with status {} stderr={stderr}",
                self.status
            )))
        }
    }
}

/// Cross-platform shim over `std::process::Command` so the per-OS
/// grant/revoke logic can be unit-tested with a fake runner.
pub trait CommandRunner: Send + Sync + std::fmt::Debug {
    /// Run `program` with `args` and return its captured output. The
    /// caller decides how to interpret the exit status.
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput, AdminError>;
}

/// Default [`CommandRunner`] that shells out via
/// `std::process::Command`.
#[derive(Debug, Default)]
pub struct OsCommandRunner;

impl CommandRunner for OsCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput, AdminError> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(AdminError::from)?;
        Ok(CommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

// =====================================================================
// Grant-state file helpers (cross-platform JSON ledger)
// =====================================================================

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct GrantState {
    /// Schema version for forward compatibility.
    #[serde(default = "default_state_version")]
    schema_version: u16,
    grants: Vec<GrantHandle>,
}

fn default_state_version() -> u16 {
    1
}

fn read_grants(state_file: &Path) -> Result<Vec<GrantHandle>, AdminError> {
    if !state_file.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(state_file).map_err(AdminError::from)?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let state: GrantState = serde_json::from_slice(&bytes)
        .map_err(|e| AdminError::StateCorrupt(format!("{state_file:?}: {e}")))?;
    Ok(state.grants)
}

/// Persist `grants` to `state_file` via a tempfile + atomic rename so
/// a crash mid-write cannot leave a partially-written ledger on disk.
///
/// The OS-level admin grant is applied *before* the ledger write
/// completes, so a non-atomic `fs::write` could be interrupted between
/// the grant taking effect and the ledger entry being persisted —
/// that orphan would survive across restarts because `read_grants`
/// either returns `StateCorrupt` (truncated JSON) or an empty vec
/// (zero-length file), and `revoke_admin` would have nothing to look
/// up. Mirrors the pattern already used by `GrantStore::flush` in
/// `sda-jit-admin` and `RollbackOrchestrator::persist` in
/// `sda-software`.
fn write_grants(state_file: &Path, grants: &[GrantHandle]) -> Result<(), AdminError> {
    if let Some(parent) = state_file.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(AdminError::from)?;
        }
    }
    let state = GrantState {
        schema_version: 1,
        grants: grants.to_vec(),
    };
    let bytes = serde_json::to_vec_pretty(&state)
        .map_err(|e| AdminError::StateCorrupt(format!("serialize: {e}")))?;
    let parent = state_file.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(AdminError::from)?;
    tmp.write_all(&bytes).map_err(AdminError::from)?;
    tmp.flush().map_err(AdminError::from)?;
    tmp.persist(state_file)
        .map_err(|e| AdminError::Io(e.error))?;
    Ok(())
}

/// Reject usernames containing characters that have meaning for shells,
/// path separators, or sudoers files.
///
/// Accepts the conservative POSIX-portable set
/// `[A-Za-z0-9._-]+` plus an optional single backslash for Windows
/// `DOMAIN\user` syntax. The first character must not be `-` so the
/// argument cannot be parsed as a flag.
fn validate_username(username: &str) -> Result<(), AdminError> {
    if username.is_empty() {
        return Err(AdminError::InvalidInput("empty username".into()));
    }
    if username.len() > 256 {
        return Err(AdminError::InvalidInput("username too long".into()));
    }
    if username.starts_with('-') {
        return Err(AdminError::InvalidInput(format!(
            "username may not start with '-': {username}"
        )));
    }
    let mut backslashes = 0;
    for ch in username.chars() {
        let ok = ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-');
        if ok {
            continue;
        }
        if ch == '\\' {
            backslashes += 1;
            if backslashes > 1 {
                return Err(AdminError::InvalidInput(format!(
                    "username has multiple backslashes: {username}"
                )));
            }
            continue;
        }
        return Err(AdminError::InvalidInput(format!(
            "username has disallowed character {ch:?}: {username}"
        )));
    }
    Ok(())
}

fn new_grant_id() -> String {
    // 128-bit random hex; matches the format the JIT-admin server uses
    // for opaque IDs while remaining trivially decodable.
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // Mix in a few bits from the current thread id so two calls in the
    // same nanosecond stay distinguishable.
    let tid = format!("{:?}", std::thread::current().id());
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    nanos.hash(&mut hasher);
    tid.hash(&mut hasher);
    let suffix = hasher.finish();
    format!("sda-jit-{nanos:x}-{suffix:x}")
}

// =====================================================================
// Linux implementation
// =====================================================================

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::fs;
    use std::process::Command;

    /// Default sudoers drop-in directory.
    pub(crate) const DEFAULT_SUDOERS_DIR: &str = "/etc/sudoers.d";
    /// Default JIT-admin grant ledger path.
    pub(crate) const DEFAULT_STATE_FILE: &str = "/var/lib/sn360/jit-admin-grants.json";

    /// Build the sudoers drop-in body for a JIT grant.
    pub(crate) fn render_sudoers(user: &str, grant_id: &str, until: DateTime<Utc>) -> String {
        // Hard-coded NOPASSWD ALL is what the JIT-admin spec asks for —
        // the watchdog enforces the time bound and the sudoers content
        // itself is removed at revocation.
        format!(
            "# sn360 JIT admin grant\n\
             # grant_id: {grant_id}\n\
             # until:    {until}\n\
             {user} ALL=(ALL) NOPASSWD:ALL\n",
            grant_id = grant_id,
            until = until.to_rfc3339(),
            user = user,
        )
    }

    /// Filesystem path of the drop-in for `user`.
    pub(crate) fn drop_in_path(sudoers_dir: &Path, user: &str) -> PathBuf {
        sudoers_dir.join(format!("sda-jit-{user}"))
    }

    /// Linux admin-manager backed by `/etc/group` and `id` for UID 0
    /// detection. Enumerates `wheel` and `sudo` group members plus
    /// any non-root account whose UID == 0.
    ///
    /// JIT-admin grants are issued by writing a `NOPASSWD` drop-in to
    /// `sudoers_dir` (default `/etc/sudoers.d`) after `visudo -c`
    /// validates it, and persisted in `state_file`. Revocation removes
    /// the drop-in and the corresponding ledger entry.
    pub struct LinuxAdminManager {
        runner: Box<dyn CommandRunner>,
        state_file: PathBuf,
        sudoers_dir: PathBuf,
        ledger_lock: Mutex<()>,
    }

    impl Default for LinuxAdminManager {
        fn default() -> Self {
            Self::new()
        }
    }

    impl LinuxAdminManager {
        /// Production constructor: uses the real `std::process::Command`
        /// runner and the canonical sudoers / state-file paths.
        pub fn new() -> Self {
            Self::with_components(
                Box::new(OsCommandRunner),
                PathBuf::from(DEFAULT_STATE_FILE),
                PathBuf::from(DEFAULT_SUDOERS_DIR),
            )
        }

        /// Test-friendly constructor: inject a mock runner and override
        /// every path the manager will write to.
        pub fn with_components(
            runner: Box<dyn CommandRunner>,
            state_file: PathBuf,
            sudoers_dir: PathBuf,
        ) -> Self {
            Self {
                runner,
                state_file,
                sudoers_dir,
                ledger_lock: Mutex::new(()),
            }
        }

        /// Path to the JSON ledger of active grants.
        pub fn state_file(&self) -> &Path {
            &self.state_file
        }

        /// Drop-in directory used for JIT-admin sudoers files.
        pub fn sudoers_dir(&self) -> &Path {
            &self.sudoers_dir
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
            user: &UserRef,
            until: DateTime<Utc>,
        ) -> Result<GrantHandle, AdminError> {
            validate_username(&user.username)?;
            let _guard = self
                .ledger_lock
                .lock()
                .map_err(|e| AdminError::Command(format!("ledger lock poisoned: {e}")))?;

            let grant_id = new_grant_id();
            let body = render_sudoers(&user.username, &grant_id, until);
            let drop_in = drop_in_path(&self.sudoers_dir, &user.username);

            // Write the candidate sudoers file to a sibling temp path
            // first so `visudo -c` can validate it before we make it
            // active.
            fs::create_dir_all(&self.sudoers_dir).map_err(AdminError::from)?;
            let tmp = self
                .sudoers_dir
                .join(format!("sda-jit-{}.tmp", user.username));
            fs::write(&tmp, body.as_bytes()).map_err(AdminError::from)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perm = fs::metadata(&tmp).map_err(AdminError::from)?.permissions();
                perm.set_mode(0o440);
                fs::set_permissions(&tmp, perm).map_err(AdminError::from)?;
            }
            let tmp_str = tmp.to_string_lossy().into_owned();
            let validation = self
                .runner
                .run("visudo", &["-c", "-f", &tmp_str])
                .inspect_err(|_| {
                    // If visudo is missing entirely we treat that as a
                    // grant failure so we never install an unvalidated
                    // sudoers file.
                    let _ = fs::remove_file(&tmp);
                })?;
            if !validation.is_success() {
                let _ = fs::remove_file(&tmp);
                let stderr = String::from_utf8_lossy(&validation.stderr)
                    .trim()
                    .to_string();
                return Err(AdminError::Command(format!(
                    "visudo rejected drop-in for {}: {stderr}",
                    user.username
                )));
            }

            // Atomic-ish swap into place.
            fs::rename(&tmp, &drop_in).map_err(AdminError::from)?;

            let mut grants = read_grants(&self.state_file)?;
            grants.retain(|g| g.user.username != user.username);
            let handle = GrantHandle {
                id: grant_id,
                user: user.clone(),
                until,
            };
            grants.push(handle.clone());
            write_grants(&self.state_file, &grants)?;
            Ok(handle)
        }

        fn revoke_admin(&self, handle: &GrantHandle) -> Result<(), AdminError> {
            let _guard = self
                .ledger_lock
                .lock()
                .map_err(|e| AdminError::Command(format!("ledger lock poisoned: {e}")))?;
            let drop_in = drop_in_path(&self.sudoers_dir, &handle.user.username);
            if drop_in.exists() {
                fs::remove_file(&drop_in).map_err(AdminError::from)?;
            }
            let grants = read_grants(&self.state_file)?;
            let kept: Vec<GrantHandle> = grants.into_iter().filter(|g| g.id != handle.id).collect();
            write_grants(&self.state_file, &kept)?;
            Ok(())
        }

        fn observed_grants(&self) -> Result<Vec<GrantHandle>, AdminError> {
            read_grants(&self.state_file)
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

    /// Default JIT-admin grant ledger path (macOS).
    pub(crate) const DEFAULT_STATE_FILE: &str =
        "/Library/Application Support/sn360/jit-admin-grants.json";

    /// macOS admin-manager backed by `dscl . -read /Groups/admin
    /// GroupMembership` for inventory and `dseditgroup -o edit` for
    /// JIT-admin grants and revocations.
    pub struct MacAdminManager {
        runner: Box<dyn CommandRunner>,
        state_file: PathBuf,
        ledger_lock: Mutex<()>,
    }

    impl Default for MacAdminManager {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MacAdminManager {
        pub fn new() -> Self {
            Self::with_components(Box::new(OsCommandRunner), PathBuf::from(DEFAULT_STATE_FILE))
        }

        pub fn with_components(runner: Box<dyn CommandRunner>, state_file: PathBuf) -> Self {
            Self {
                runner,
                state_file,
                ledger_lock: Mutex::new(()),
            }
        }

        pub fn state_file(&self) -> &Path {
            &self.state_file
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
            let output = self
                .runner
                .run("dscl", &[".", "-read", "/Groups/admin", "GroupMembership"])?
                .require_success("dscl")?;
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
            user: &UserRef,
            until: DateTime<Utc>,
        ) -> Result<GrantHandle, AdminError> {
            validate_username(&user.username)?;
            let _guard = self
                .ledger_lock
                .lock()
                .map_err(|e| AdminError::Command(format!("ledger lock poisoned: {e}")))?;
            self.runner
                .run(
                    "dseditgroup",
                    &["-o", "edit", "-a", &user.username, "-t", "user", "admin"],
                )?
                .require_success("dseditgroup add")?;
            let mut grants = read_grants(&self.state_file)?;
            grants.retain(|g| g.user.username != user.username);
            let handle = GrantHandle {
                id: new_grant_id(),
                user: user.clone(),
                until,
            };
            grants.push(handle.clone());
            write_grants(&self.state_file, &grants)?;
            Ok(handle)
        }

        fn revoke_admin(&self, handle: &GrantHandle) -> Result<(), AdminError> {
            let _guard = self
                .ledger_lock
                .lock()
                .map_err(|e| AdminError::Command(format!("ledger lock poisoned: {e}")))?;
            // dseditgroup is idempotent — removing a non-member is a
            // no-op. We still surface non-zero exits because they
            // typically indicate a permissions issue we want logged.
            self.runner
                .run(
                    "dseditgroup",
                    &[
                        "-o",
                        "edit",
                        "-d",
                        &handle.user.username,
                        "-t",
                        "user",
                        "admin",
                    ],
                )?
                .require_success("dseditgroup remove")?;
            let grants = read_grants(&self.state_file)?;
            let kept: Vec<GrantHandle> = grants.into_iter().filter(|g| g.id != handle.id).collect();
            write_grants(&self.state_file, &kept)?;
            Ok(())
        }

        fn observed_grants(&self) -> Result<Vec<GrantHandle>, AdminError> {
            read_grants(&self.state_file)
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

    /// Default JIT-admin grant ledger path (Windows).
    pub(crate) const DEFAULT_STATE_FILE: &str = r"C:\ProgramData\sn360\jit-admin-grants.json";

    /// Windows admin-manager backed by `net localgroup Administrators`
    /// for inventory and `net localgroup Administrators <user> /add`
    /// for JIT-admin grants and revocations.
    pub struct WindowsAdminManager {
        runner: Box<dyn CommandRunner>,
        state_file: PathBuf,
        ledger_lock: Mutex<()>,
    }

    impl Default for WindowsAdminManager {
        fn default() -> Self {
            Self::new()
        }
    }

    impl WindowsAdminManager {
        pub fn new() -> Self {
            Self::with_components(Box::new(OsCommandRunner), PathBuf::from(DEFAULT_STATE_FILE))
        }

        pub fn with_components(runner: Box<dyn CommandRunner>, state_file: PathBuf) -> Self {
            Self {
                runner,
                state_file,
                ledger_lock: Mutex::new(()),
            }
        }

        pub fn state_file(&self) -> &Path {
            &self.state_file
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
            let output = self
                .runner
                .run("net", &["localgroup", "Administrators"])?
                .require_success("net localgroup")?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(Self::parse_net_localgroup(&stdout))
        }

        fn grant_admin(
            &self,
            user: &UserRef,
            until: DateTime<Utc>,
        ) -> Result<GrantHandle, AdminError> {
            validate_username(&user.username)?;
            let _guard = self
                .ledger_lock
                .lock()
                .map_err(|e| AdminError::Command(format!("ledger lock poisoned: {e}")))?;
            self.runner
                .run(
                    "net",
                    &["localgroup", "Administrators", &user.username, "/add"],
                )?
                .require_success("net localgroup add")?;
            let mut grants = read_grants(&self.state_file)?;
            grants.retain(|g| g.user.username != user.username);
            let handle = GrantHandle {
                id: new_grant_id(),
                user: user.clone(),
                until,
            };
            grants.push(handle.clone());
            write_grants(&self.state_file, &grants)?;
            Ok(handle)
        }

        fn revoke_admin(&self, handle: &GrantHandle) -> Result<(), AdminError> {
            let _guard = self
                .ledger_lock
                .lock()
                .map_err(|e| AdminError::Command(format!("ledger lock poisoned: {e}")))?;
            self.runner
                .run(
                    "net",
                    &[
                        "localgroup",
                        "Administrators",
                        &handle.user.username,
                        "/delete",
                    ],
                )?
                .require_success("net localgroup delete")?;
            let grants = read_grants(&self.state_file)?;
            let kept: Vec<GrantHandle> = grants.into_iter().filter(|g| g.id != handle.id).collect();
            write_grants(&self.state_file, &kept)?;
            Ok(())
        }

        fn observed_grants(&self) -> Result<Vec<GrantHandle>, AdminError> {
            read_grants(&self.state_file)
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

    /// Single canned response for one program name.
    #[derive(Debug, Clone)]
    pub(crate) struct MockResponse {
        pub program: String,
        pub output: CommandOutput,
    }

    /// Test-double for [`CommandRunner`] that records every invocation
    /// and returns a queued canned response per program. Unknown
    /// programs return a generic success.
    #[derive(Debug, Default)]
    pub(crate) struct MockCommandRunner {
        pub calls: std::sync::Mutex<Vec<(String, Vec<String>)>>,
        pub responses: std::sync::Mutex<Vec<MockResponse>>,
    }

    impl MockCommandRunner {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn enqueue(&self, program: &str, output: CommandOutput) {
            self.responses.lock().unwrap().push(MockResponse {
                program: program.into(),
                output,
            });
        }

        pub fn enqueue_success(&self, program: &str) {
            self.enqueue(
                program,
                CommandOutput {
                    status: 0,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                },
            );
        }

        pub fn enqueue_failure(&self, program: &str, code: i32, stderr: &str) {
            self.enqueue(
                program,
                CommandOutput {
                    status: code,
                    stdout: Vec::new(),
                    stderr: stderr.as_bytes().to_vec(),
                },
            );
        }

        pub fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandRunner for MockCommandRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput, AdminError> {
            self.calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|s| s.to_string()).collect(),
            ));
            let mut responses = self.responses.lock().unwrap();
            // Pop the next response keyed on the program name; fall back
            // to a generic success.
            if let Some(idx) = responses.iter().position(|r| r.program == program) {
                Ok(responses.remove(idx).output)
            } else {
                Ok(CommandOutput {
                    status: 0,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
            }
        }
    }

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

    #[test]
    fn validate_username_accepts_simple_logins() {
        validate_username("alice").unwrap();
        validate_username("alice.bob").unwrap();
        validate_username("alice_bob").unwrap();
        validate_username("alice-bob").unwrap();
        validate_username("CONTOSO\\alice").unwrap();
    }

    #[test]
    fn validate_username_rejects_dangerous_inputs() {
        assert!(validate_username("").is_err());
        assert!(validate_username("-rm").is_err());
        assert!(validate_username("alice;rm -rf /").is_err());
        assert!(validate_username("alice space").is_err());
        assert!(validate_username("alice/bob").is_err());
        assert!(validate_username("a\\b\\c").is_err());
    }

    #[test]
    fn grant_state_round_trips_through_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let state_file = dir.path().join("grants.json");
        let handle = GrantHandle {
            id: "grant-xyz".into(),
            user: UserRef {
                username: "alice".into(),
                domain: None,
            },
            until: chrono::Utc::now(),
        };
        write_grants(&state_file, std::slice::from_ref(&handle)).unwrap();
        let read_back = read_grants(&state_file).unwrap();
        assert_eq!(read_back.len(), 1);
        assert_eq!(read_back[0].id, "grant-xyz");
        assert_eq!(read_back[0].user.username, "alice");
    }

    #[test]
    fn grant_state_corrupt_file_yields_state_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let state_file = dir.path().join("grants.json");
        std::fs::write(&state_file, b"not-json").unwrap();
        let err = read_grants(&state_file).expect_err("must fail on garbage");
        assert!(matches!(err, AdminError::StateCorrupt(_)), "got {err:?}");
    }

    #[test]
    fn grant_state_missing_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let state_file = dir.path().join("does-not-exist.json");
        assert!(read_grants(&state_file).unwrap().is_empty());
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

        fn fixtures() -> (
            tempfile::TempDir,
            std::sync::Arc<MockCommandRunner>,
            LinuxAdminManager,
        ) {
            let dir = tempfile::tempdir().unwrap();
            let state_file = dir.path().join("grants.json");
            let sudoers_dir = dir.path().join("sudoers.d");
            let runner = std::sync::Arc::new(MockCommandRunner::new());
            // Re-wrap the Arc in a Box-of-trait-object for the manager
            // so the test side keeps a clone of the Arc to inspect
            // recorded calls after each operation.
            #[derive(Debug)]
            struct ArcRunner(std::sync::Arc<MockCommandRunner>);
            impl CommandRunner for ArcRunner {
                fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput, AdminError> {
                    self.0.run(program, args)
                }
            }
            let mgr = LinuxAdminManager::with_components(
                Box::new(ArcRunner(runner.clone())),
                state_file,
                sudoers_dir,
            );
            (dir, runner, mgr)
        }

        #[test]
        fn grant_writes_validated_drop_in_and_persists_handle() {
            let (_dir, runner, mgr) = fixtures();
            // visudo -c → success on first call.
            runner.enqueue_success("visudo");
            let user = UserRef {
                username: "alice".into(),
                domain: None,
            };
            let until = Utc::now() + chrono::Duration::hours(1);
            let handle = mgr.grant_admin(&user, until).expect("grant");
            assert_eq!(handle.user.username, "alice");
            assert_eq!(handle.until, until);

            // Drop-in file present and validated.
            let drop_in = mgr.sudoers_dir().join("sda-jit-alice");
            let body = std::fs::read_to_string(&drop_in).unwrap();
            assert!(
                body.contains("alice ALL=(ALL) NOPASSWD:ALL"),
                "unexpected body: {body}"
            );
            assert!(
                body.contains(&format!("# grant_id: {}", handle.id)),
                "expected grant_id comment in body"
            );

            // visudo got invoked with -c -f <tmp-path>.
            let calls = runner.calls();
            let last = calls.last().expect("at least one call");
            assert_eq!(last.0, "visudo");
            assert_eq!(last.1[0], "-c");
            assert_eq!(last.1[1], "-f");

            // Grant ledger contains exactly one entry.
            let grants = mgr.observed_grants().unwrap();
            assert_eq!(grants.len(), 1);
            assert_eq!(grants[0].id, handle.id);
        }

        #[test]
        fn grant_fails_when_visudo_rejects_drop_in() {
            let (_dir, runner, mgr) = fixtures();
            runner.enqueue_failure("visudo", 1, "syntax error near `:`");
            let user = UserRef {
                username: "alice".into(),
                domain: None,
            };
            let err = mgr
                .grant_admin(&user, Utc::now())
                .expect_err("must reject invalid sudoers");
            assert!(matches!(err, AdminError::Command(_)), "got {err:?}");
            // No drop-in left behind, no entry in the ledger.
            assert!(!mgr.sudoers_dir().join("sda-jit-alice").exists());
            assert!(mgr.observed_grants().unwrap().is_empty());
        }

        #[test]
        fn revoke_removes_drop_in_and_clears_ledger_entry() {
            let (_dir, runner, mgr) = fixtures();
            runner.enqueue_success("visudo");
            let user = UserRef {
                username: "alice".into(),
                domain: None,
            };
            let handle = mgr.grant_admin(&user, Utc::now()).unwrap();
            assert!(mgr.sudoers_dir().join("sda-jit-alice").exists());

            mgr.revoke_admin(&handle).expect("revoke");
            assert!(!mgr.sudoers_dir().join("sda-jit-alice").exists());
            assert!(mgr.observed_grants().unwrap().is_empty());

            // Idempotent: revoking again is a no-op.
            mgr.revoke_admin(&handle).expect("idempotent revoke");
        }

        #[test]
        fn grant_for_same_user_replaces_previous_handle() {
            let (_dir, runner, mgr) = fixtures();
            runner.enqueue_success("visudo");
            runner.enqueue_success("visudo");
            let user = UserRef {
                username: "alice".into(),
                domain: None,
            };
            let first = mgr.grant_admin(&user, Utc::now()).unwrap();
            let second = mgr.grant_admin(&user, Utc::now()).unwrap();
            assert_ne!(first.id, second.id, "second grant must mint a new id");
            let grants = mgr.observed_grants().unwrap();
            assert_eq!(grants.len(), 1, "one user → one active grant");
            assert_eq!(grants[0].id, second.id);
        }

        #[test]
        fn invalid_username_is_rejected_before_any_command_runs() {
            let (_dir, runner, mgr) = fixtures();
            let user = UserRef {
                username: "alice; rm -rf /".into(),
                domain: None,
            };
            let err = mgr.grant_admin(&user, Utc::now()).expect_err("must reject");
            assert!(matches!(err, AdminError::InvalidInput(_)), "got {err:?}");
            assert!(runner.calls().is_empty());
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
