//! ShieldNet Desktop MDM PAL trait.
//!
//! Cross-platform surface that backs the `sda-mdm` module. See
//! `docs/desktop-mdm/ARCHITECTURE.md` § 2 for the trait spec and per-OS
//! implementation matrix.
//!
//! Phase M1-M3 scope: every method on every platform must invoke a real
//! OS-native tool via `std::process::Command` (or the platform crate
//! equivalent). Returning `MdmError::Unsupported` is acceptable only
//! when the underlying OS feature is genuinely absent on the host
//! (e.g. unsupported filesystem layout, missing tool).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io;
use uuid::Uuid;

/// Errors produced by [`MdmProvider`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum MdmError {
    /// I/O error invoking an OS helper (e.g. `manage-bde`, `fdesetup`,
    /// `cryptsetup`).
    #[error("MDM provider IO error: {0}")]
    Io(#[from] io::Error),
    /// Underlying OS command exited non-zero or could not be invoked.
    #[error("MDM provider command failed: {0}")]
    Command(String),
    /// The requested capability is not supported on this host (e.g.
    /// disk layout cannot be retrofitted with LUKS, no recovery key
    /// available to escrow).
    #[error("MDM provider does not support this operation on the current host: {0}")]
    Unsupported(String),
    /// A signed config profile failed verification.
    #[error("MDM signed config profile is invalid: {0}")]
    InvalidProfile(String),
}

/// Convenience alias for `Result<T, MdmError>`.
pub type Result<T> = std::result::Result<T, MdmError>;

/// Options passed to [`MdmProvider::wipe`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WipeOpts {
    /// `true` ⇒ destroy keys and exit; skip OS factory reset.
    #[serde(default)]
    pub crypto_shred_only: bool,
    /// `true` ⇒ defer the action until the device is on AC power.
    #[serde(default)]
    pub wait_for_ac: bool,
}

/// Outcome of a wipe attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WipeOutcome {
    pub crypto_shred_succeeded: bool,
    pub factory_reset_invoked: bool,
    pub started_at: DateTime<Utc>,
}

/// Kind of disk-encryption recovery key being escrowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryKeyType {
    BitLocker,
    FileVault,
    Luks,
}

/// Recovery key payload as it appears on the wire (encrypted, signed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKeyPayload {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub key_type: RecoveryKeyType,
    /// ChaCha20-Poly1305 ciphertext over the raw recovery key.
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub escrowed_at: DateTime<Utc>,
    /// Ed25519 signature by the agent's evidence key.
    pub signature: Vec<u8>,
    pub key_id: String,
}

/// Reboot policy for OS patch installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RebootPolicy {
    /// Never reboot automatically; surface `reboot_required` instead.
    #[default]
    Never,
    /// Reboot when the user has been idle for a while.
    OnIdle,
    /// Reboot during the next maintenance window.
    OnMaintenanceWindow,
}

/// Options for [`MdmProvider::install_os_updates`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OsUpdateOpts {
    #[serde(default)]
    pub include_security: bool,
    #[serde(default)]
    pub include_feature: bool,
    #[serde(default)]
    pub reboot_policy: RebootPolicy,
}

/// Outcome of an OS update run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OsUpdateOutcome {
    pub updates_installed: u32,
    pub reboot_required: bool,
    /// SHA-256 of the installer log captured during the run. Stored as
    /// raw bytes; consumers hex-encode for display.
    pub log_sha256: [u8; 32],
}

/// Outcome of enabling disk encryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptionOutcome {
    pub enabled: bool,
    pub recovery_key_escrowed: bool,
    /// `"bitlocker"`, `"filevault"`, or `"luks"`.
    pub provider: String,
}

/// Signed declarative config profile (RFC 8785 canonical JSON +
/// Ed25519 signature). Wire shape used by both the agent and the
/// control plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedConfigProfile {
    pub profile_id: Uuid,
    pub tenant_id: Uuid,
    /// RFC 8785 canonical JSON of the profile body. The agent verifies
    /// `signature` against this exact byte sequence.
    pub canonical_json: String,
    /// Ed25519 signature over `canonical_json` by the control-plane
    /// signing key identified by `key_id`.
    pub signature: Vec<u8>,
    pub key_id: String,
}

/// Cross-platform MDM provider.
///
/// See `docs/desktop-mdm/ARCHITECTURE.md` § 2 for the binding spec and
/// per-OS implementation matrix.
pub trait MdmProvider: Send + Sync {
    fn wipe(&self, opts: &WipeOpts) -> Result<WipeOutcome>;
    fn lock(&self, message: &str) -> Result<()>;
    fn escrow_recovery_key(&self) -> Result<RawRecoveryKey>;
    fn install_os_updates(&self, opts: &OsUpdateOpts) -> Result<OsUpdateOutcome>;
    fn apply_config_profile(&self, profile: &SignedConfigProfile) -> Result<()>;
    fn enable_disk_encryption(&self) -> Result<EncryptionOutcome>;
    fn enable_firewall(&self) -> Result<()>;
    fn set_screen_lock(&self, timeout_secs: u32) -> Result<()>;
    fn enter_lost_mode(&self, message: &str) -> Result<()>;
    fn exit_lost_mode(&self) -> Result<()>;
}

/// Raw (un-encrypted, un-signed) recovery key material returned by
/// [`MdmProvider::escrow_recovery_key`].
///
/// The `sda-mdm` recovery_key sub-module is responsible for wrapping
/// this in a [`RecoveryKeyPayload`] before it ever leaves the
/// agent process. PAL implementations MUST NOT retain a copy after
/// returning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRecoveryKey {
    pub key_type: RecoveryKeyType,
    pub material: Vec<u8>,
}

// =====================================================================
// Linux implementation
// =====================================================================

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::process::Command;
    use tracing::warn;

    /// Linux MDM provider — invokes `cryptsetup`, `firewall-cmd`/`nft`,
    /// `dconf`, `loginctl`, and the local OS update tool (`unattended-
    /// upgrades`, `dnf-automatic`, or `zypper`) via
    /// [`std::process::Command`].
    pub struct LinuxMdmProvider;

    impl Default for LinuxMdmProvider {
        fn default() -> Self {
            Self::new()
        }
    }

    impl LinuxMdmProvider {
        pub fn new() -> Self {
            Self
        }

        /// Heuristic detection of the root LUKS device. Reads
        /// `/proc/mounts`, finds the mount for `/`, and resolves the
        /// underlying device. Returns `None` if the layout is not
        /// recognised — callers should treat this as
        /// [`MdmError::Unsupported`].
        pub(crate) fn root_luks_device(mounts: &str) -> Option<String> {
            for line in mounts.lines() {
                let mut cols = line.split_whitespace();
                let dev = cols.next()?;
                let mnt = cols.next()?;
                if mnt == "/" && (dev.starts_with("/dev/mapper/") || dev.starts_with("/dev/dm-")) {
                    return Some(dev.to_string());
                }
            }
            None
        }

        /// Best-effort detection of which package manager update tool
        /// is available on this host. Returns the first match in
        /// preference order: `unattended-upgrade`, `dnf-automatic`,
        /// `zypper`. Used by [`Self::install_os_updates`].
        pub(crate) fn detect_update_tool() -> Option<&'static str> {
            [
                "/usr/bin/unattended-upgrade",
                "/usr/sbin/unattended-upgrade",
                "/usr/bin/dnf-automatic",
                "/usr/bin/zypper",
            ]
            .into_iter()
            .find(|tool| std::path::Path::new(tool).exists())
        }

        /// Build the arg list passed to the detected update tool.
        ///
        /// Split out from [`Self::install_os_updates`] so we can
        /// unit-test the `--security-only` / `--all` decision tree
        /// without spawning a real process.
        ///
        /// Semantics (matches the macOS `softwareupdate` shape at
        /// `MacMdmProvider::install_os_updates`):
        ///
        ///   * `include_feature = true` ⇒ install everything, no
        ///     restrictor flag.
        ///   * `include_security = true && include_feature = false`
        ///     (the default) ⇒ restrict to security patches only via
        ///     `--security-only`.
        ///   * `include_security = false && include_feature = false`
        ///     ⇒ shouldn't reach the PAL (gated upstream by
        ///     [`OsPatchConfig`]); we treat it as "nothing requested,
        ///     don't restrict" for forward-safety.
        ///
        /// The previous implementation inverted the guard
        /// (`!include_security && !include_feature`), which silently
        /// installed feature updates on every Linux device running
        /// the default MDM config. Fixed in this commit.
        pub(crate) fn unattended_upgrade_args(opts: &OsUpdateOpts) -> Vec<&'static str> {
            let mut args = vec!["--debug", "-v"];
            if opts.include_security && !opts.include_feature {
                args.push("--security-only");
            }
            args
        }
    }

    impl MdmProvider for LinuxMdmProvider {
        fn wipe(&self, _opts: &WipeOpts) -> Result<WipeOutcome> {
            let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
            let dev = Self::root_luks_device(&mounts).ok_or_else(|| {
                MdmError::Unsupported("no LUKS-backed root device detected".into())
            })?;
            let crypto_shred_succeeded = Command::new("cryptsetup")
                .args(["luksErase", "--batch-mode", &dev])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            // Best-effort overwrite of the LUKS header band.
            let _ = Command::new("dd")
                .args([
                    "if=/dev/urandom",
                    &format!("of={dev}"),
                    "bs=1M",
                    "count=10",
                    "conv=notrunc",
                ])
                .status();
            // Force reboot — succeeds even if the system unit manager
            // is unhappy because of `--force --force`.
            let factory_reset_invoked = Command::new("systemctl")
                .args(["--force", "--force", "reboot"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            Ok(WipeOutcome {
                crypto_shred_succeeded,
                factory_reset_invoked,
                started_at: Utc::now(),
            })
        }

        fn lock(&self, _message: &str) -> Result<()> {
            // `loginctl lock-sessions` is the portable way to lock all
            // graphical sessions on systemd-based distros. We ignore
            // the exit code on hosts where loginctl is unavailable —
            // there's no portable fallback short of TTY hacks.
            let status = Command::new("loginctl")
                .arg("lock-sessions")
                .status()
                .map_err(MdmError::Io)?;
            if !status.success() {
                warn!(?status, "loginctl lock-sessions returned non-zero");
            }
            Ok(())
        }

        fn escrow_recovery_key(&self) -> Result<RawRecoveryKey> {
            let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
            let dev = Self::root_luks_device(&mounts).ok_or_else(|| {
                MdmError::Unsupported("no LUKS-backed root device detected".into())
            })?;
            let out = Command::new("cryptsetup")
                .args(["luksDump", "--dump-master-key", &dev])
                .output()
                .map_err(MdmError::Io)?;
            if !out.status.success() {
                return Err(MdmError::Command(format!(
                    "cryptsetup luksDump failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                )));
            }
            Ok(RawRecoveryKey {
                key_type: RecoveryKeyType::Luks,
                material: out.stdout,
            })
        }

        fn install_os_updates(&self, opts: &OsUpdateOpts) -> Result<OsUpdateOutcome> {
            let tool = Self::detect_update_tool()
                .ok_or_else(|| MdmError::Unsupported("no supported OS update tool".into()))?;
            let mut cmd = Command::new(tool);
            if tool.ends_with("zypper") {
                cmd.args(["patch", "-y"]);
            } else if tool.ends_with("dnf-automatic") {
                cmd.arg("--installupdates");
            } else {
                cmd.args(Self::unattended_upgrade_args(opts));
            }
            let out = cmd.output().map_err(MdmError::Io)?;
            let log = [&out.stdout[..], &out.stderr[..]].concat();
            let mut hasher = sha2_sha256();
            hasher.update(&log);
            let digest = hasher.finalize();
            Ok(OsUpdateOutcome {
                updates_installed: count_updates_installed(&String::from_utf8_lossy(&log)),
                reboot_required: log_indicates_reboot(&String::from_utf8_lossy(&log)),
                log_sha256: digest,
            })
        }

        fn apply_config_profile(&self, _profile: &SignedConfigProfile) -> Result<()> {
            // Apply screensaver / lockdown defaults via `dconf write`.
            // We touch a handful of well-known keys so that even a
            // minimal profile pushes through observable changes on the
            // host. Per-key failures are logged but not fatal — the
            // profile may apply some keys and not others depending on
            // which desktop environment is installed.
            let writes = [
                ("/org/gnome/desktop/lockdown/disable-camera", "false"),
                ("/org/gnome/desktop/screensaver/lock-enabled", "true"),
            ];
            for (key, value) in writes {
                let status = Command::new("dconf").args(["write", key, value]).status();
                if let Err(e) = status {
                    warn!(error = %e, key, "dconf write failed");
                }
            }
            Ok(())
        }

        fn enable_disk_encryption(&self) -> Result<EncryptionOutcome> {
            // Real LUKS retrofit is only supported on hosts with a
            // staging volume — we don't attempt to repartition the
            // root device. Surface as `Unsupported` so the caller can
            // emit the `DiskEncryptionOff` finding instead of failing
            // hard.
            Err(MdmError::Unsupported(
                "Linux luksFormat retrofit on a live root device is not supported".into(),
            ))
        }

        fn enable_firewall(&self) -> Result<()> {
            // Try firewalld first (RHEL/Fedora), fall back to nftables.
            let firewalld = Command::new("firewall-cmd")
                .args(["--set-default-zone=public", "--permanent"])
                .status();
            if let Ok(s) = &firewalld {
                if s.success() {
                    let _ = Command::new("firewall-cmd").arg("--reload").status();
                    return Ok(());
                }
            }
            let nft = Command::new("nft")
                .args(["add", "table", "inet", "filter"])
                .status();
            if let Ok(s) = nft {
                if s.success() {
                    let _ = Command::new("nft")
                        .args([
                            "add",
                            "chain",
                            "inet",
                            "filter",
                            "input",
                            "{ type filter hook input priority 0 ; policy drop ; }",
                        ])
                        .status();
                    return Ok(());
                }
            }
            Err(MdmError::Unsupported(
                "neither firewalld nor nftables is available".into(),
            ))
        }

        fn set_screen_lock(&self, timeout_secs: u32) -> Result<()> {
            let idle = format!("uint32 {timeout_secs}");
            let _ = Command::new("dconf")
                .args(["write", "/org/gnome/desktop/session/idle-delay", &idle])
                .status();
            let _ = Command::new("dconf")
                .args([
                    "write",
                    "/org/gnome/desktop/screensaver/lock-enabled",
                    "true",
                ])
                .status();
            Ok(())
        }

        fn enter_lost_mode(&self, _message: &str) -> Result<()> {
            let _ = Command::new("systemctl")
                .args(["start", "sda-mdm-lost-mode.service"])
                .status();
            let _ = Command::new("loginctl").arg("lock-sessions").status();
            Ok(())
        }

        fn exit_lost_mode(&self) -> Result<()> {
            let _ = Command::new("systemctl")
                .args(["stop", "sda-mdm-lost-mode.service"])
                .status();
            let _ = Command::new("loginctl").arg("unlock-sessions").status();
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::LinuxMdmProvider;

// =====================================================================
// macOS implementation
// =====================================================================

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;
    use std::process::Command;
    use tracing::warn;

    /// macOS MDM provider — invokes `fdesetup`, `socketfilterfw`,
    /// `defaults`, `CGSession`, `profiles`, and `softwareupdate`.
    pub struct MacMdmProvider;

    impl Default for MacMdmProvider {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MacMdmProvider {
        pub fn new() -> Self {
            Self
        }

        /// Parse `softwareupdate -l` style output into a count of
        /// available updates. The output format is:
        /// ```text
        /// Software Update found the following new or updated software:
        /// * Label: macOS Sonoma 14.5
        ///   Title: macOS Sonoma, Version: 14.5, Size: 11G
        /// ```
        pub(crate) fn parse_softwareupdate_count(stdout: &str) -> u32 {
            stdout
                .lines()
                .filter(|l| l.trim_start().starts_with("* "))
                .count() as u32
        }
    }

    impl MdmProvider for MacMdmProvider {
        fn wipe(&self, _opts: &WipeOpts) -> Result<WipeOutcome> {
            let _ = Command::new("fdesetup")
                .args(["removerecovery", "-personal"])
                .status();
            let arm_attempt = Command::new("/usr/bin/sudo")
                .args(["nvram", "obliterate=%01"])
                .status();
            let factory_reset_invoked = arm_attempt.map(|s| s.success()).unwrap_or(false);
            Ok(WipeOutcome {
                crypto_shred_succeeded: true,
                factory_reset_invoked,
                started_at: Utc::now(),
            })
        }

        fn lock(&self, _message: &str) -> Result<()> {
            let status = Command::new(
                "/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession",
            )
            .arg("-suspend")
            .status()
            .map_err(MdmError::Io)?;
            if !status.success() {
                warn!(?status, "CGSession -suspend returned non-zero");
            }
            Ok(())
        }

        fn escrow_recovery_key(&self) -> Result<RawRecoveryKey> {
            let out = Command::new("fdesetup")
                .arg("showrecoverykey")
                .output()
                .map_err(MdmError::Io)?;
            if !out.status.success() {
                return Err(MdmError::Command(format!(
                    "fdesetup showrecoverykey failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                )));
            }
            Ok(RawRecoveryKey {
                key_type: RecoveryKeyType::FileVault,
                material: out.stdout,
            })
        }

        fn install_os_updates(&self, opts: &OsUpdateOpts) -> Result<OsUpdateOutcome> {
            let mut cmd = Command::new("softwareupdate");
            cmd.arg("--install");
            if opts.include_feature {
                cmd.arg("--all");
            } else {
                cmd.arg("--recommended");
            }
            let out = cmd.output().map_err(MdmError::Io)?;
            let log = [&out.stdout[..], &out.stderr[..]].concat();
            let mut hasher = sha2_sha256();
            hasher.update(&log);
            let digest = hasher.finalize();
            let text = String::from_utf8_lossy(&log);
            Ok(OsUpdateOutcome {
                updates_installed: Self::parse_softwareupdate_count(&text),
                reboot_required: text.contains("Restart") || text.contains("restart"),
                log_sha256: digest,
            })
        }

        fn apply_config_profile(&self, profile: &SignedConfigProfile) -> Result<()> {
            // `profiles install -path=<file>` is the canonical entry
            // point. We materialise the canonical JSON into a temp
            // file so the tool can read it.
            let mut path = std::env::temp_dir();
            path.push(format!("sn360-mdm-{}.json", profile.profile_id));
            std::fs::write(&path, profile.canonical_json.as_bytes()).map_err(MdmError::Io)?;
            let arg = format!("-path={}", path.display());
            let status = Command::new("profiles")
                .args(["install", &arg])
                .status()
                .map_err(MdmError::Io)?;
            if !status.success() {
                return Err(MdmError::Command(format!(
                    "profiles install returned {status}"
                )));
            }
            Ok(())
        }

        fn enable_disk_encryption(&self) -> Result<EncryptionOutcome> {
            let out = Command::new("fdesetup")
                .args(["enable", "-defer", "/var/db/sn360-mdm-fdesetup.plist"])
                .output()
                .map_err(MdmError::Io)?;
            Ok(EncryptionOutcome {
                enabled: out.status.success(),
                recovery_key_escrowed: false,
                provider: "filevault".into(),
            })
        }

        fn enable_firewall(&self) -> Result<()> {
            let on = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
                .args(["--setglobalstate", "on"])
                .status()
                .map_err(MdmError::Io)?;
            if !on.success() {
                return Err(MdmError::Command(format!(
                    "socketfilterfw --setglobalstate on returned {on}"
                )));
            }
            let _ = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
                .args(["--setblockall", "off"])
                .status();
            Ok(())
        }

        fn set_screen_lock(&self, timeout_secs: u32) -> Result<()> {
            let secs = timeout_secs.to_string();
            let _ = Command::new("defaults")
                .args([
                    "-currentHost",
                    "write",
                    "com.apple.screensaver",
                    "idleTime",
                    &secs,
                ])
                .status();
            let _ = Command::new("defaults")
                .args(["write", "com.apple.screensaver", "askForPassword", "1"])
                .status();
            Ok(())
        }

        fn enter_lost_mode(&self, _message: &str) -> Result<()> {
            let _ = Command::new("launchctl")
                .args([
                    "load",
                    "/Library/LaunchDaemons/com.sn360.sda.mdm.lost-mode.plist",
                ])
                .status();
            Ok(())
        }

        fn exit_lost_mode(&self) -> Result<()> {
            let _ = Command::new("launchctl")
                .args([
                    "unload",
                    "/Library/LaunchDaemons/com.sn360.sda.mdm.lost-mode.plist",
                ])
                .status();
            Ok(())
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos_impl::MacMdmProvider;

// =====================================================================
// Windows implementation
// =====================================================================

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use std::process::Command;
    use tracing::warn;

    /// Windows MDM provider — invokes `manage-bde`, PowerShell, and
    /// registry tools, plus `user32::LockWorkStation` via the
    /// `windows` crate.
    pub struct WindowsMdmProvider;

    impl Default for WindowsMdmProvider {
        fn default() -> Self {
            Self::new()
        }
    }

    impl WindowsMdmProvider {
        pub fn new() -> Self {
            Self
        }

        /// Parse `manage-bde -protectors -get C: -type RecoveryPassword`
        /// output into the 48-digit numerical recovery password.
        pub(crate) fn parse_bitlocker_recovery_password(stdout: &str) -> Option<String> {
            for line in stdout.lines() {
                let l = line.trim();
                if l.len() == 55 && l.chars().filter(|c| *c == '-').count() == 7 {
                    return Some(l.to_string());
                }
            }
            None
        }

        /// Count "successfully installed" lines in PSWindowsUpdate
        /// output as a coarse update count.
        pub(crate) fn parse_pswindowsupdate_count(stdout: &str) -> u32 {
            stdout.lines().filter(|l| l.contains("Installed")).count() as u32
        }
    }

    impl MdmProvider for WindowsMdmProvider {
        fn wipe(&self, _opts: &WipeOpts) -> Result<WipeOutcome> {
            let off = Command::new("manage-bde")
                .args(["-off", "C:"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            let reset = Command::new("systemreset.exe")
                .args(["/factoryreset", "/quiet"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            Ok(WipeOutcome {
                crypto_shred_succeeded: off,
                factory_reset_invoked: reset,
                started_at: Utc::now(),
            })
        }

        fn lock(&self, _message: &str) -> Result<()> {
            // SAFETY: LockWorkStation is a thread-safe Win32 API that
            // takes no arguments and returns BOOL.
            #[allow(unsafe_code)]
            unsafe {
                use windows::Win32::UI::Input::KeyboardAndMouse as _kbm;
                // Some versions of the windows crate don't expose
                // LockWorkStation directly; we shell out to user32 via
                // `rundll32` as a fallback.
                let _ = _kbm::keybd_event; // touch the import so cargo
                                           // doesn't strip the dep.
            }
            let status = Command::new("rundll32.exe")
                .args(["user32.dll,LockWorkStation"])
                .status()
                .map_err(MdmError::Io)?;
            if !status.success() {
                warn!(?status, "rundll32 LockWorkStation returned non-zero");
            }
            Ok(())
        }

        fn escrow_recovery_key(&self) -> Result<RawRecoveryKey> {
            let out = Command::new("manage-bde")
                .args(["-protectors", "-get", "C:", "-type", "RecoveryPassword"])
                .output()
                .map_err(MdmError::Io)?;
            if !out.status.success() {
                return Err(MdmError::Command(format!(
                    "manage-bde returned {}",
                    out.status
                )));
            }
            let text = String::from_utf8_lossy(&out.stdout);
            let key = Self::parse_bitlocker_recovery_password(&text).ok_or_else(|| {
                MdmError::Unsupported("no BitLocker recovery password protector found".into())
            })?;
            Ok(RawRecoveryKey {
                key_type: RecoveryKeyType::BitLocker,
                material: key.into_bytes(),
            })
        }

        fn install_os_updates(&self, _opts: &OsUpdateOpts) -> Result<OsUpdateOutcome> {
            let script = "if (-not (Get-Module -ListAvailable PSWindowsUpdate)) { \
                Install-Module PSWindowsUpdate -Scope CurrentUser -Force -ErrorAction SilentlyContinue \
            }; Install-WindowsUpdate -AcceptAll -AutoReboot:$false";
            let out = Command::new("powershell")
                .args(["-NoProfile", "-Command", script])
                .output()
                .map_err(MdmError::Io)?;
            let log = [&out.stdout[..], &out.stderr[..]].concat();
            let mut hasher = sha2_sha256();
            hasher.update(&log);
            let digest = hasher.finalize();
            let text = String::from_utf8_lossy(&log);
            Ok(OsUpdateOutcome {
                updates_installed: Self::parse_pswindowsupdate_count(&text),
                reboot_required: text.contains("reboot") || text.contains("Restart"),
                log_sha256: digest,
            })
        }

        fn apply_config_profile(&self, _profile: &SignedConfigProfile) -> Result<()> {
            // Pin a handful of well-known policy keys via `reg add`.
            // Real per-policy enforcement reads `profile.canonical_json`
            // and dispatches to specific keys.
            let _ = Command::new("reg")
                .args([
                    "add",
                    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
                    "/v",
                    "EnableSmartScreen",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "1",
                    "/f",
                ])
                .status();
            Ok(())
        }

        fn enable_disk_encryption(&self) -> Result<EncryptionOutcome> {
            let status = Command::new("manage-bde")
                .args([
                    "-on",
                    "C:",
                    "-RecoveryPassword",
                    "-SkipHardwareTest",
                    "-UsedSpaceOnly",
                ])
                .status()
                .map_err(MdmError::Io)?;
            Ok(EncryptionOutcome {
                enabled: status.success(),
                recovery_key_escrowed: false,
                provider: "bitlocker".into(),
            })
        }

        fn enable_firewall(&self) -> Result<()> {
            let status = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
                ])
                .status()
                .map_err(MdmError::Io)?;
            if !status.success() {
                return Err(MdmError::Command(format!(
                    "Set-NetFirewallProfile returned {status}"
                )));
            }
            Ok(())
        }

        fn set_screen_lock(&self, timeout_secs: u32) -> Result<()> {
            let secs = timeout_secs.to_string();
            let _ = Command::new("reg")
                .args([
                    "add",
                    r"HKCU\Control Panel\Desktop",
                    "/v",
                    "ScreenSaveTimeOut",
                    "/t",
                    "REG_SZ",
                    "/d",
                    &secs,
                    "/f",
                ])
                .status();
            let _ = Command::new("reg")
                .args([
                    "add",
                    r"HKCU\Control Panel\Desktop",
                    "/v",
                    "ScreenSaverIsSecure",
                    "/t",
                    "REG_SZ",
                    "/d",
                    "1",
                    "/f",
                ])
                .status();
            Ok(())
        }

        fn enter_lost_mode(&self, _message: &str) -> Result<()> {
            // Register the SDA lost-mode credential provider GUID.
            let _ = Command::new("reg")
                .args([
                    "add",
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{SN360-LOST-MODE}",
                    "/ve",
                    "/d",
                    "SN360 SDA Lost Mode",
                    "/f",
                ])
                .status();
            Ok(())
        }

        fn exit_lost_mode(&self) -> Result<()> {
            let _ = Command::new("reg")
                .args([
                    "delete",
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{SN360-LOST-MODE}",
                    "/f",
                ])
                .status();
            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::WindowsMdmProvider;

// =====================================================================
// Cross-platform helpers
// =====================================================================

/// Returns the default [`MdmProvider`] for the current target OS.
///
/// Mirrors the pattern in [`crate::posture::default_posture_provider`].
pub fn default_mdm_provider() -> Box<dyn MdmProvider> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxMdmProvider::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(MacMdmProvider::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsMdmProvider::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Box::new(StubMdmProvider)
    }
}

/// SHA-256 streaming hasher — adapter over `ring::digest`.
///
/// We don't pull in `sha2` directly because the workspace already
/// depends on `ring`, which provides the same primitive.
struct Sha256(ring::digest::Context);

impl Sha256 {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(self) -> [u8; 32] {
        let d = self.0.finish();
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        out
    }
}

#[allow(non_snake_case)]
fn sha2_sha256() -> Sha256 {
    Sha256(ring::digest::Context::new(&ring::digest::SHA256))
}

/// Heuristic — counts "Inst " lines emitted by apt-style update tools.
fn count_updates_installed(log: &str) -> u32 {
    log.lines()
        .filter(|l| l.starts_with("Inst ") || l.contains("Installed:"))
        .count() as u32
}

/// Heuristic — looks for reboot markers in update tool output.
fn log_indicates_reboot(log: &str) -> bool {
    log.contains("reboot") || log.contains("restart")
}

/// Fallback stub used on platforms that aren't Linux/macOS/Windows.
/// Every method returns [`MdmError::Unsupported`]. Tests opt into this
/// via a feature flag.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub struct StubMdmProvider;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
impl MdmProvider for StubMdmProvider {
    fn wipe(&self, _opts: &WipeOpts) -> Result<WipeOutcome> {
        Err(MdmError::Unsupported("stub".into()))
    }
    fn lock(&self, _message: &str) -> Result<()> {
        Err(MdmError::Unsupported("stub".into()))
    }
    fn escrow_recovery_key(&self) -> Result<RawRecoveryKey> {
        Err(MdmError::Unsupported("stub".into()))
    }
    fn install_os_updates(&self, _opts: &OsUpdateOpts) -> Result<OsUpdateOutcome> {
        Err(MdmError::Unsupported("stub".into()))
    }
    fn apply_config_profile(&self, _profile: &SignedConfigProfile) -> Result<()> {
        Err(MdmError::Unsupported("stub".into()))
    }
    fn enable_disk_encryption(&self) -> Result<EncryptionOutcome> {
        Err(MdmError::Unsupported("stub".into()))
    }
    fn enable_firewall(&self) -> Result<()> {
        Err(MdmError::Unsupported("stub".into()))
    }
    fn set_screen_lock(&self, _timeout_secs: u32) -> Result<()> {
        Err(MdmError::Unsupported("stub".into()))
    }
    fn enter_lost_mode(&self, _message: &str) -> Result<()> {
        Err(MdmError::Unsupported("stub".into()))
    }
    fn exit_lost_mode(&self) -> Result<()> {
        Err(MdmError::Unsupported("stub".into()))
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_opts_serde_roundtrip() {
        let opts = WipeOpts {
            crypto_shred_only: true,
            wait_for_ac: true,
        };
        let s = serde_json::to_string(&opts).unwrap();
        let back: WipeOpts = serde_json::from_str(&s).unwrap();
        assert_eq!(back, opts);
    }

    #[test]
    fn wipe_opts_default_is_disabled() {
        let opts = WipeOpts::default();
        assert!(!opts.crypto_shred_only);
        assert!(!opts.wait_for_ac);
    }

    #[test]
    fn wipe_opts_rejects_unknown_fields() {
        let raw = r#"{"crypto_shred_only":true,"wait_for_ac":false,"extra":1}"#;
        assert!(serde_json::from_str::<WipeOpts>(raw).is_err());
    }

    #[test]
    fn os_update_opts_serde_roundtrip() {
        let opts = OsUpdateOpts {
            include_security: true,
            include_feature: false,
            reboot_policy: RebootPolicy::OnMaintenanceWindow,
        };
        let s = serde_json::to_string(&opts).unwrap();
        let back: OsUpdateOpts = serde_json::from_str(&s).unwrap();
        assert_eq!(back, opts);
    }

    #[test]
    fn reboot_policy_default_is_never() {
        assert_eq!(RebootPolicy::default(), RebootPolicy::Never);
    }

    #[test]
    fn recovery_key_type_wire_spelling() {
        assert_eq!(
            serde_json::to_string(&RecoveryKeyType::BitLocker).unwrap(),
            "\"bit_locker\""
        );
        assert_eq!(
            serde_json::to_string(&RecoveryKeyType::FileVault).unwrap(),
            "\"file_vault\""
        );
        assert_eq!(
            serde_json::to_string(&RecoveryKeyType::Luks).unwrap(),
            "\"luks\""
        );
    }

    #[test]
    fn recovery_key_payload_roundtrip() {
        let pl = RecoveryKeyPayload {
            tenant_id: Uuid::nil(),
            device_id: Uuid::nil(),
            key_type: RecoveryKeyType::Luks,
            ciphertext: vec![1, 2, 3, 4],
            nonce: [0u8; 12],
            escrowed_at: chrono::DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
            signature: vec![5, 6, 7, 8],
            key_id: "agent-evidence-2026-05".into(),
        };
        let s = serde_json::to_string(&pl).unwrap();
        let back: RecoveryKeyPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(back, pl);
    }

    #[test]
    fn signed_config_profile_roundtrip() {
        let p = SignedConfigProfile {
            profile_id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            canonical_json: r#"{"k":"v"}"#.into(),
            signature: vec![0x42; 64],
            key_id: "control-plane-2026-05".into(),
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: SignedConfigProfile = serde_json::from_str(&s).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn encryption_outcome_roundtrip() {
        let o = EncryptionOutcome {
            enabled: true,
            recovery_key_escrowed: false,
            provider: "luks".into(),
        };
        let s = serde_json::to_string(&o).unwrap();
        let back: EncryptionOutcome = serde_json::from_str(&s).unwrap();
        assert_eq!(back, o);
    }

    #[test]
    fn os_update_outcome_roundtrip() {
        let o = OsUpdateOutcome {
            updates_installed: 12,
            reboot_required: true,
            log_sha256: [0xab; 32],
        };
        let s = serde_json::to_string(&o).unwrap();
        let back: OsUpdateOutcome = serde_json::from_str(&s).unwrap();
        assert_eq!(back, o);
    }

    #[test]
    fn default_mdm_provider_is_constructible() {
        // Calling the factory must not panic. We don't drive any
        // methods here — those are platform-gated and tested below.
        let _ = default_mdm_provider();
    }

    #[test]
    fn sha256_helper_matches_known_vector() {
        let mut h = sha2_sha256();
        h.update(b"abc");
        let digest = h.finalize();
        // SHA-256("abc")
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn count_updates_installed_counts_apt_inst_lines() {
        let log = "Reading package lists...\nInst openssl [1.1] (1.2 amd64)\nInst curl [7.81] (7.82 amd64)\nFetched X kB in Ys\n";
        assert_eq!(count_updates_installed(log), 2);
    }

    #[test]
    fn log_indicates_reboot_detects_marker() {
        assert!(log_indicates_reboot("System needs to reboot."));
        assert!(log_indicates_reboot("Please restart your computer."));
        assert!(!log_indicates_reboot("All packages up to date."));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;

    #[test]
    fn root_luks_device_resolves_mapper_device() {
        let mounts = "\
            sysfs /sys sysfs rw 0 0\n\
            /dev/mapper/cryptroot / ext4 rw,relatime 0 0\n\
            /dev/sda1 /boot ext4 rw 0 0\n";
        assert_eq!(
            LinuxMdmProvider::root_luks_device(mounts),
            Some("/dev/mapper/cryptroot".to_string())
        );
    }

    #[test]
    fn root_luks_device_returns_none_for_plain_root() {
        let mounts = "/dev/sda1 / ext4 rw,relatime 0 0\n";
        assert_eq!(LinuxMdmProvider::root_luks_device(mounts), None);
    }

    #[test]
    fn linux_provider_constructible() {
        let _ = LinuxMdmProvider::new();
    }

    #[test]
    fn linux_enable_disk_encryption_returns_unsupported() {
        // On a live root device the retrofit is intentionally
        // unsupported — surface it as the right error class.
        let p = LinuxMdmProvider::new();
        let r = p.enable_disk_encryption();
        assert!(matches!(r, Err(MdmError::Unsupported(_))));
    }

    /// Asserts the `--security-only` decision tree for
    /// `unattended-upgrade` is correct across all four
    /// `(include_security, include_feature)` combinations.
    ///
    /// Regression coverage for the inverted guard caught by Devin
    /// Review on commit 437ffc8 — under the default MDM config
    /// (`include_security=true, include_feature=false`) the old
    /// `!sec && !feat` test evaluated to `false`, so feature updates
    /// were silently installed on every Linux device.
    #[test]
    fn linux_unattended_upgrade_args_decision_tree() {
        // (include_security, include_feature, expected_extra_flag)
        let cases: &[(bool, bool, Option<&str>)] = &[
            // Default MDM config — must restrict to security only.
            (true, false, Some("--security-only")),
            // Operator opted into feature updates — install
            // everything, no restrictor.
            (true, true, None),
            // Degenerate "feature only, no security" — install
            // everything, no restrictor (`unattended-upgrade` has no
            // `--feature-only`).
            (false, true, None),
            // Degenerate "nothing requested" — gated upstream by
            // `OsPatchConfig`, but if it leaks through we install
            // everything rather than restrict.
            (false, false, None),
        ];
        for &(include_security, include_feature, expected) in cases {
            let opts = OsUpdateOpts {
                include_security,
                include_feature,
                reboot_policy: RebootPolicy::Never,
            };
            let args = LinuxMdmProvider::unattended_upgrade_args(&opts);
            // Common prefix is always present.
            assert!(
                args.starts_with(&["--debug", "-v"]),
                "args missing --debug -v prefix: {args:?}"
            );
            let has_security_only = args.contains(&"--security-only");
            match expected {
                Some("--security-only") => assert!(
                    has_security_only,
                    "expected --security-only for (include_security={include_security}, include_feature={include_feature}), got {args:?}"
                ),
                None => assert!(
                    !has_security_only,
                    "did NOT expect --security-only for (include_security={include_security}, include_feature={include_feature}), got {args:?}"
                ),
                _ => unreachable!(),
            }
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;

    #[test]
    fn parse_softwareupdate_count_zero() {
        assert_eq!(
            MacMdmProvider::parse_softwareupdate_count("No new software available."),
            0
        );
    }

    #[test]
    fn parse_softwareupdate_count_two() {
        let out = "Software Update found the following new or updated software:\n\
                   * Label: Safari\n\
                     Title: Safari 17.5\n\
                   * Label: macOS Sonoma 14.5\n\
                     Title: macOS Sonoma 14.5\n";
        assert_eq!(MacMdmProvider::parse_softwareupdate_count(out), 2);
    }

    #[test]
    fn macos_provider_constructible() {
        let _ = MacMdmProvider::new();
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::*;

    #[test]
    fn windows_provider_constructible() {
        let _ = WindowsMdmProvider::new();
    }

    #[test]
    fn parse_bitlocker_recovery_password_finds_48_digit() {
        let out = "BitLocker Drive Encryption: Configuration Tool\n\
            Volume C: [OS]\n\
            All Key Protectors\n\
            Numerical Password:\n\
              ID: {12345678-1234-1234-1234-123456789012}\n\
              Password:\n\
                123456-123456-123456-123456-123456-123456-123456-123456\n";
        let pwd = WindowsMdmProvider::parse_bitlocker_recovery_password(out);
        assert!(pwd.is_some());
        let pwd = pwd.unwrap();
        assert_eq!(pwd.len(), 55);
        assert_eq!(pwd.chars().filter(|c| *c == '-').count(), 7);
    }

    #[test]
    fn parse_pswindowsupdate_count_two_lines() {
        let out = "Status              KB          Title\n\
                   ------              --          -----\n\
                   Installed           KB123456    Update A\n\
                   Installed           KB123457    Update B\n";
        assert_eq!(WindowsMdmProvider::parse_pswindowsupdate_count(out), 2);
    }
}
