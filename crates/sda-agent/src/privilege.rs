//! Privilege separation (P3.2).
//!
//! Drops the agent from root (or Administrator on Windows) to a
//! dedicated unprivileged account once privileged initialization
//! (enrollment, key persistence in `/etc/sn360-desktop-agent/`, binding
//! low-numbered ports) is complete. Detection modules — FIM,
//! logcollector, inventory, SCA, rootcheck, LDE, enhanced-inventory —
//! run under the unprivileged account. Active-response commands that
//! genuinely need root go through a small setuid helper binary
//! configured via [`SecurityConfig::privilege_helper_path`].
//!
//! On Windows this is a compile-time no-op; the service manager is
//! responsible for launching `sda-agent.exe` under the right service
//! account (`LOCAL SERVICE` or a dedicated service user). On non-root
//! Unix startups this is also a no-op with an `info` log, so running
//! the agent under `cargo run` as a regular user still works for
//! development.

use anyhow::Result;
use sda_core::config::SecurityConfig;

/// Apply [`SecurityConfig::run_as_user`] / [`run_as_group`] by
/// `setgid`/`setuid`-ing the current process.
///
/// Safe to call unconditionally: returns `Ok(())` immediately when
/// `run_as_user` is `None`, when compiled for Windows, or when the
/// current process is not running as root (in which case it logs at
/// `info` and continues).
///
/// [`run_as_group`]: SecurityConfig::run_as_group
pub fn drop_privileges(security: &SecurityConfig) -> Result<()> {
    #[cfg(unix)]
    {
        unix::drop_privileges(security)
    }
    #[cfg(not(unix))]
    {
        if security.run_as_user.is_some() {
            tracing::info!(
                "privilege drop requested but not supported on this platform; \
                 relying on the service manager to launch under the right account"
            );
        }
        Ok(())
    }
}

#[cfg(unix)]
mod unix {
    use anyhow::{anyhow, Context, Result};
    use nix::unistd::{getuid, setgid, setuid, Gid, Group, Uid, User};
    use sda_core::config::SecurityConfig;
    use tracing::{info, warn};

    pub fn drop_privileges(security: &SecurityConfig) -> Result<()> {
        let Some(user_name) = security.run_as_user.as_deref() else {
            // Privilege dropping is opt-in; say nothing and let the
            // service manager decide.
            return Ok(());
        };

        if !getuid().is_root() {
            info!(
                target_user = user_name,
                "not running as root; skipping privilege drop"
            );
            return Ok(());
        }

        let user = User::from_name(user_name)
            .with_context(|| format!("failed to resolve user '{user_name}'"))?
            .ok_or_else(|| anyhow!("user '{user_name}' does not exist"))?;

        let gid = resolve_gid(security.run_as_group.as_deref(), user.gid)?;

        apply(user.uid, gid)?;

        info!(
            uid = user.uid.as_raw(),
            gid = gid.as_raw(),
            user = user_name,
            "privileges dropped"
        );

        if try_regain_root() {
            return Err(anyhow!(
                "privilege drop sanity check failed: process could regain uid 0"
            ));
        }

        Ok(())
    }

    fn resolve_gid(group_name: Option<&str>, fallback: Gid) -> Result<Gid> {
        let Some(name) = group_name else {
            return Ok(fallback);
        };
        let group = Group::from_name(name)
            .with_context(|| format!("failed to resolve group '{name}'"))?
            .ok_or_else(|| anyhow!("group '{name}' does not exist"))?;
        Ok(group.gid)
    }

    fn apply(uid: Uid, gid: Gid) -> Result<()> {
        // Empty supplementary-group list. Must run while still root.
        // `nix::unistd::setgroups` is only exposed on a subset of Unixes
        // (Linux, FreeBSD, ...) — so we go through libc directly, which
        // is universally available on the unix cfg.
        clear_supplementary_groups();
        setgid(gid).with_context(|| format!("setgid({})", gid.as_raw()))?;
        setuid(uid).with_context(|| format!("setuid({})", uid.as_raw()))?;
        Ok(())
    }

    #[cfg(unix)]
    fn clear_supplementary_groups() {
        // SAFETY: FFI call with a valid (null, count=0) tuple. The kernel
        // accepts an empty list and no memory is dereferenced.
        let rc = unsafe { libc::setgroups(0, std::ptr::null()) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            warn!(
                error = %err,
                "setgroups([]) failed; continuing with whatever the kernel \
                 inherited — some distros forbid this when /proc/self/setgroups \
                 is 'deny'"
            );
        }
    }

    /// After `setuid(non-root)` the kernel clears saved-uid, so a
    /// second `setuid(0)` call must fail. If it succeeds we've only
    /// done a partial drop (e.g. via `seteuid`) and an attacker who
    /// compromises a module could re-escalate.
    fn try_regain_root() -> bool {
        setuid(Uid::from_raw(0)).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::config::SecurityConfig;

    #[test]
    fn drop_privileges_is_noop_when_unset() {
        let cfg = SecurityConfig::default();
        assert!(cfg.run_as_user.is_none());
        // Must succeed in every CI environment regardless of uid.
        drop_privileges(&cfg).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn drop_privileges_is_noop_when_not_root() {
        // CI runs as a non-root user; verify we skip cleanly rather
        // than erroring out on an unresolvable user name.
        let cfg = SecurityConfig {
            run_as_user: Some("definitely-not-a-real-user-name-ab12cd34".into()),
            ..SecurityConfig::default()
        };
        // Because we bail out before lookup when not root, this should
        // succeed. If CI ever runs as root the bogus username lookup
        // will (correctly) fail — that's the intended behavior.
        if !nix::unistd::getuid().is_root() {
            drop_privileges(&cfg).unwrap();
        }
    }
}
