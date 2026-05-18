//! Device-posture snapshots: disk encryption, firewall, screen lock,
//! patch level, OS version.
//!
//! This is the cross-platform PAL surface that backs the
//! `sda-posture` module. The trait shape comes from
//! `docs/architecture.md` § 4.1 (Trait surface); the snapshot fields
//! line up 1:1 with the `Finding` evidence shapes for the
//! `disk_encryption_off`, `firewall_disabled`, `screen_lock_off`, and
//! `os_patch_outdated` `FindingKind` variants documented in
//! `docs/wire-protocols/device-control.md` § 5 (Finding).
//!
//! Phase 1 scope: every platform must produce a non-panicking
//! `PostureSnapshot`. Best-effort detection is acceptable —
//! `Unknown` is a valid value. Server-side scoring tolerates
//! `Unknown` and only fires `Finding`s when a value is positively
//! detected as off/missing.

use serde::{Deserialize, Serialize};
use std::io;

/// Errors produced by [`DevicePostureProvider`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum PostureError {
    /// I/O error invoking an OS helper (e.g. `manage-bde`,
    /// `fdesetup`, `lsblk`).
    #[error("posture provider IO error: {0}")]
    Io(#[from] io::Error),
    /// Underlying OS command exited non-zero or could not be invoked.
    #[error("posture provider command failed: {0}")]
    Command(String),
}

/// Tri-state used for every posture field that can be `On`, `Off`,
/// or genuinely undetectable on the current host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PostureToggle {
    /// Feature confirmed enabled.
    On,
    /// Feature confirmed disabled.
    Off,
    /// Could not determine state. Server treats this as "no
    /// finding" rather than "off".
    #[default]
    Unknown,
}

/// One device-posture snapshot. This is the cross-platform shape;
/// per-OS providers fill in what they can detect.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostureSnapshot {
    /// Whether disk encryption (BitLocker / FileVault / LUKS) is
    /// enabled on the system volume.
    pub disk_encryption: PostureToggle,
    /// Whether the host firewall is enabled.
    pub firewall_enabled: PostureToggle,
    /// Whether automatic screen-lock is enforced.
    pub screen_lock_enabled: PostureToggle,
    /// Patch-level descriptor. Free-form short string; semantics
    /// are platform-specific (e.g. KB count, last-update timestamp,
    /// `apt list --upgradable | wc -l`).
    pub os_patch_level: Option<String>,
    /// OS marketing version (e.g. `"Windows 11 23H2"`,
    /// `"macOS 14.5"`, `"Ubuntu 22.04.4 LTS"`).
    pub os_version: Option<String>,
}

impl Default for PostureSnapshot {
    fn default() -> Self {
        Self {
            disk_encryption: PostureToggle::Unknown,
            firewall_enabled: PostureToggle::Unknown,
            screen_lock_enabled: PostureToggle::Unknown,
            os_patch_level: None,
            os_version: None,
        }
    }
}

/// Cross-platform device-posture snapshot provider.
///
/// See `docs/architecture.md` § 4.1 (Trait surface) for the
/// binding trait spec.
pub trait DevicePostureProvider: Send + Sync {
    fn snapshot(&self) -> Result<PostureSnapshot, PostureError>;
}

// =====================================================================
// Linux implementation
// =====================================================================

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::process::Command;

    /// Linux posture provider. Best-effort: checks `lsblk --json`
    /// for crypto blockdevs, `firewall-cmd`/`ufw`/`nftables list`
    /// for the firewall state, and reads `/etc/os-release` for the
    /// OS version. Screen-lock detection is intentionally `Unknown`
    /// in Phase 1 because there is no portable way to reach the
    /// active session's screensaver settings from a system daemon.
    pub struct LinuxPostureProvider;

    impl Default for LinuxPostureProvider {
        fn default() -> Self {
            Self::new()
        }
    }

    impl LinuxPostureProvider {
        pub fn new() -> Self {
            Self
        }

        /// Detect crypto block devices in `lsblk` JSON output.
        /// `output` is whatever `lsblk --json -o NAME,TYPE,FSTYPE`
        /// would print (or a test fixture matching that shape).
        pub(crate) fn detect_disk_encryption_from_lsblk(output: &str) -> PostureToggle {
            let parsed: serde_json::Value = match serde_json::from_str(output) {
                Ok(v) => v,
                Err(_) => return PostureToggle::Unknown,
            };
            let devs = match parsed.get("blockdevices") {
                Some(d) => d,
                None => return PostureToggle::Unknown,
            };
            if Self::any_crypt_in_tree(devs) {
                PostureToggle::On
            } else {
                // We can confidently say "no crypt blockdev was
                // observed" but that's not the same as "no
                // encryption" (FBE / fscrypt / dm-integrity exist),
                // so leave Unknown rather than Off.
                PostureToggle::Unknown
            }
        }

        fn any_crypt_in_tree(node: &serde_json::Value) -> bool {
            match node {
                serde_json::Value::Array(arr) => arr.iter().any(Self::any_crypt_in_tree),
                serde_json::Value::Object(obj) => {
                    if let Some(t) = obj.get("type").and_then(|v| v.as_str()) {
                        if t.eq_ignore_ascii_case("crypt") {
                            return true;
                        }
                    }
                    if let Some(fs) = obj.get("fstype").and_then(|v| v.as_str()) {
                        if fs.eq_ignore_ascii_case("crypto_LUKS") {
                            return true;
                        }
                    }
                    if let Some(children) = obj.get("children") {
                        if Self::any_crypt_in_tree(children) {
                            return true;
                        }
                    }
                    false
                }
                _ => false,
            }
        }

        /// Parse `/etc/os-release` content into the marketing
        /// `PRETTY_NAME` field.
        pub(crate) fn parse_os_pretty_name(os_release: &str) -> Option<String> {
            for line in os_release.lines() {
                if let Some(rest) = line.strip_prefix("PRETTY_NAME=") {
                    return Some(rest.trim_matches('"').to_string());
                }
            }
            None
        }

        /// Map `firewall-cmd --state` / `ufw status` / `systemctl
        /// is-active nftables` short-output to a [`PostureToggle`].
        pub(crate) fn classify_firewall_command_output(
            cmd: &str,
            stdout: &str,
            success: bool,
        ) -> PostureToggle {
            let s = stdout.trim().to_ascii_lowercase();
            match cmd {
                "firewall-cmd" => {
                    // `firewall-cmd --state` exits non-zero (252) when
                    // firewalld is stopped, but still prints
                    // "not running" to stdout. We must classify that
                    // case as Off, not Unknown — otherwise we silently
                    // drop the "firewall is off" finding on every
                    // RHEL/Fedora host that uses firewalld.
                    if s == "running" && success {
                        PostureToggle::On
                    } else if s == "not running" {
                        PostureToggle::Off
                    } else {
                        PostureToggle::Unknown
                    }
                }
                "ufw" => {
                    // ufw status output: "Status: active" or
                    // "Status: inactive". Other lines may follow.
                    if s.contains("status: active") {
                        PostureToggle::On
                    } else if s.contains("status: inactive") {
                        PostureToggle::Off
                    } else {
                        PostureToggle::Unknown
                    }
                }
                "nftables" => {
                    if s == "active" {
                        PostureToggle::On
                    } else if s == "inactive" || s == "failed" {
                        PostureToggle::Off
                    } else {
                        PostureToggle::Unknown
                    }
                }
                _ => PostureToggle::Unknown,
            }
        }

        fn detect_firewall(&self) -> PostureToggle {
            // Try firewall-cmd first.
            if let Ok(out) = Command::new("firewall-cmd").arg("--state").output() {
                let res = Self::classify_firewall_command_output(
                    "firewall-cmd",
                    &String::from_utf8_lossy(&out.stdout),
                    out.status.success(),
                );
                if res != PostureToggle::Unknown {
                    return res;
                }
            }
            // Fallback to ufw.
            if let Ok(out) = Command::new("ufw").arg("status").output() {
                let res = Self::classify_firewall_command_output(
                    "ufw",
                    &String::from_utf8_lossy(&out.stdout),
                    out.status.success(),
                );
                if res != PostureToggle::Unknown {
                    return res;
                }
            }
            // Final fallback: systemctl is-active nftables.
            if let Ok(out) = Command::new("systemctl")
                .args(["is-active", "nftables"])
                .output()
            {
                return Self::classify_firewall_command_output(
                    "nftables",
                    &String::from_utf8_lossy(&out.stdout),
                    out.status.success(),
                );
            }
            PostureToggle::Unknown
        }

        fn detect_disk_encryption(&self) -> PostureToggle {
            let out = match Command::new("lsblk")
                .args(["--json", "-o", "NAME,TYPE,FSTYPE"])
                .output()
            {
                Ok(o) if o.status.success() => o,
                _ => return PostureToggle::Unknown,
            };
            let stdout = String::from_utf8_lossy(&out.stdout);
            Self::detect_disk_encryption_from_lsblk(&stdout)
        }

        fn detect_os_version(&self) -> Option<String> {
            std::fs::read_to_string("/etc/os-release")
                .ok()
                .and_then(|s| Self::parse_os_pretty_name(&s))
        }
    }

    impl DevicePostureProvider for LinuxPostureProvider {
        fn snapshot(&self) -> Result<PostureSnapshot, PostureError> {
            Ok(PostureSnapshot {
                disk_encryption: self.detect_disk_encryption(),
                firewall_enabled: self.detect_firewall(),
                // No portable user-session reachable from a system
                // daemon → Unknown.
                screen_lock_enabled: PostureToggle::Unknown,
                os_patch_level: None,
                os_version: self.detect_os_version(),
            })
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::LinuxPostureProvider;

// =====================================================================
// macOS implementation
// =====================================================================

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;
    use std::process::Command;

    /// macOS posture provider.
    pub struct MacPostureProvider;

    impl MacPostureProvider {
        pub fn new() -> Self {
            Self
        }

        /// Parse `fdesetup status` output into a [`PostureToggle`].
        /// Output lines:
        ///   `FileVault is On.`
        ///   `FileVault is Off.`
        ///   `FileVault is Off, but will be enabled after the next restart.`
        pub(crate) fn parse_fdesetup_status(stdout: &str) -> PostureToggle {
            let s = stdout.trim().to_ascii_lowercase();
            if s.starts_with("filevault is on") {
                PostureToggle::On
            } else if s.starts_with("filevault is off") {
                PostureToggle::Off
            } else {
                PostureToggle::Unknown
            }
        }

        /// Parse the macOS Application Firewall status output:
        ///   `Firewall is enabled. (State = 1)`
        ///   `Firewall is disabled. (State = 0)`
        pub(crate) fn parse_socketfilterfw(stdout: &str) -> PostureToggle {
            let s = stdout.trim().to_ascii_lowercase();
            if s.starts_with("firewall is enabled") {
                PostureToggle::On
            } else if s.starts_with("firewall is disabled") {
                PostureToggle::Off
            } else {
                PostureToggle::Unknown
            }
        }

        /// Parse `defaults read /Library/Preferences/com.apple.screensaver askForPassword`
        /// or the equivalent — `1` means "require password to unlock".
        pub(crate) fn parse_screensaver_ask_for_password(stdout: &str) -> PostureToggle {
            let s = stdout.trim();
            match s {
                "1" => PostureToggle::On,
                "0" => PostureToggle::Off,
                _ => PostureToggle::Unknown,
            }
        }

        fn detect_disk_encryption(&self) -> PostureToggle {
            match Command::new("fdesetup").arg("status").output() {
                Ok(o) if o.status.success() => {
                    Self::parse_fdesetup_status(&String::from_utf8_lossy(&o.stdout))
                }
                _ => PostureToggle::Unknown,
            }
        }

        fn detect_firewall(&self) -> PostureToggle {
            match Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
                .arg("--getglobalstate")
                .output()
            {
                Ok(o) if o.status.success() => {
                    Self::parse_socketfilterfw(&String::from_utf8_lossy(&o.stdout))
                }
                _ => PostureToggle::Unknown,
            }
        }

        fn detect_screen_lock(&self) -> PostureToggle {
            match Command::new("defaults")
                .args([
                    "read",
                    "/Library/Preferences/com.apple.screensaver",
                    "askForPassword",
                ])
                .output()
            {
                Ok(o) if o.status.success() => {
                    Self::parse_screensaver_ask_for_password(&String::from_utf8_lossy(&o.stdout))
                }
                _ => PostureToggle::Unknown,
            }
        }

        fn detect_os_version(&self) -> Option<String> {
            Command::new("sw_vers")
                .arg("-productVersion")
                .output()
                .ok()
                .and_then(|o| {
                    if o.status.success() {
                        Some(format!(
                            "macOS {}",
                            String::from_utf8_lossy(&o.stdout).trim()
                        ))
                    } else {
                        None
                    }
                })
        }
    }

    impl DevicePostureProvider for MacPostureProvider {
        fn snapshot(&self) -> Result<PostureSnapshot, PostureError> {
            Ok(PostureSnapshot {
                disk_encryption: self.detect_disk_encryption(),
                firewall_enabled: self.detect_firewall(),
                screen_lock_enabled: self.detect_screen_lock(),
                os_patch_level: None,
                os_version: self.detect_os_version(),
            })
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos_impl::MacPostureProvider;

// =====================================================================
// Windows implementation
// =====================================================================

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use std::process::Command;

    /// Windows posture provider.
    pub struct WindowsPostureProvider;

    impl WindowsPostureProvider {
        pub fn new() -> Self {
            Self
        }

        /// Parse `manage-bde -status C:` output. We look for the
        /// `Conversion Status:` line:
        ///   `Conversion Status:    Fully Encrypted` → On
        ///   `Conversion Status:    Fully Decrypted` → Off
        ///   `Conversion Status:    Encryption in Progress` → On
        pub(crate) fn parse_manage_bde(stdout: &str) -> PostureToggle {
            for line in stdout.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("Conversion Status:") {
                    let s = rest.trim().to_ascii_lowercase();
                    if s.starts_with("fully encrypted") || s.starts_with("encryption in progress") {
                        return PostureToggle::On;
                    }
                    if s.starts_with("fully decrypted") {
                        return PostureToggle::Off;
                    }
                }
            }
            PostureToggle::Unknown
        }

        /// Parse `netsh advfirewall show allprofiles` looking for
        /// the "State" line under each profile. If any profile is
        /// `OFF`, treat the whole device as Off; only return On if
        /// every profile is On.
        pub(crate) fn parse_netsh_advfirewall(stdout: &str) -> PostureToggle {
            let mut saw_state = false;
            let mut all_on = true;
            for line in stdout.lines() {
                let line = line.trim().to_ascii_lowercase();
                if line.starts_with("state") {
                    saw_state = true;
                    if line.ends_with("off") {
                        all_on = false;
                    } else if !line.ends_with("on") {
                        // Some other label — be conservative.
                        return PostureToggle::Unknown;
                    }
                }
            }
            if !saw_state {
                PostureToggle::Unknown
            } else if all_on {
                PostureToggle::On
            } else {
                PostureToggle::Off
            }
        }

        fn detect_disk_encryption(&self) -> PostureToggle {
            match Command::new("manage-bde").args(["-status", "C:"]).output() {
                Ok(o) if o.status.success() => {
                    Self::parse_manage_bde(&String::from_utf8_lossy(&o.stdout))
                }
                _ => PostureToggle::Unknown,
            }
        }

        fn detect_firewall(&self) -> PostureToggle {
            match Command::new("netsh")
                .args(["advfirewall", "show", "allprofiles"])
                .output()
            {
                Ok(o) if o.status.success() => {
                    Self::parse_netsh_advfirewall(&String::from_utf8_lossy(&o.stdout))
                }
                _ => PostureToggle::Unknown,
            }
        }

        fn detect_os_version(&self) -> Option<String> {
            Command::new("cmd")
                .args(["/C", "ver"])
                .output()
                .ok()
                .and_then(|o| {
                    if o.status.success() {
                        Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                    } else {
                        None
                    }
                })
        }
    }

    impl DevicePostureProvider for WindowsPostureProvider {
        fn snapshot(&self) -> Result<PostureSnapshot, PostureError> {
            Ok(PostureSnapshot {
                disk_encryption: self.detect_disk_encryption(),
                firewall_enabled: self.detect_firewall(),
                // Domain-policy screen-lock requires
                // `secedit`/Group Policy parsing — leave for Phase 3.
                screen_lock_enabled: PostureToggle::Unknown,
                os_patch_level: None,
                os_version: self.detect_os_version(),
            })
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::WindowsPostureProvider;

// =====================================================================
// Default factory
// =====================================================================

/// Returns the platform-default [`DevicePostureProvider`].
pub fn default_posture_provider() -> Option<Box<dyn DevicePostureProvider>> {
    #[cfg(target_os = "linux")]
    {
        Some(Box::new(LinuxPostureProvider::new()))
    }
    #[cfg(target_os = "macos")]
    {
        Some(Box::new(MacPostureProvider::new()))
    }
    #[cfg(target_os = "windows")]
    {
        Some(Box::new(WindowsPostureProvider::new()))
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
    fn snapshot_default_is_all_unknown() {
        let s = PostureSnapshot::default();
        assert_eq!(s.disk_encryption, PostureToggle::Unknown);
        assert_eq!(s.firewall_enabled, PostureToggle::Unknown);
        assert_eq!(s.screen_lock_enabled, PostureToggle::Unknown);
        assert!(s.os_patch_level.is_none());
        assert!(s.os_version.is_none());
    }

    #[test]
    fn snapshot_serde_roundtrip_lowercase_toggle() {
        let s = PostureSnapshot {
            disk_encryption: PostureToggle::On,
            firewall_enabled: PostureToggle::Off,
            screen_lock_enabled: PostureToggle::Unknown,
            os_patch_level: Some("12".into()),
            os_version: Some("Ubuntu 22.04.4 LTS".into()),
        };
        let json = serde_json::to_string(&s).unwrap();
        // PostureToggle uses lowercase serde rename; this is part of
        // the wire contract for the `device-posture-state` payload
        // (see docs/wire-protocols/device-control.md § 5).
        assert!(json.contains("\"on\""));
        assert!(json.contains("\"off\""));
        assert!(json.contains("\"unknown\""));
        let back: PostureSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;

        #[test]
        fn detect_luks_in_lsblk_json() {
            let lsblk = r#"{
                "blockdevices": [{
                    "name": "sda",
                    "type": "disk",
                    "children": [{
                        "name": "sda1",
                        "type": "part",
                        "fstype": "crypto_LUKS",
                        "children": [{
                            "name": "cryptroot",
                            "type": "crypt",
                            "fstype": "ext4"
                        }]
                    }]
                }]
            }"#;
            assert_eq!(
                LinuxPostureProvider::detect_disk_encryption_from_lsblk(lsblk),
                PostureToggle::On
            );
        }

        #[test]
        fn lsblk_without_crypt_returns_unknown_not_off() {
            let lsblk = r#"{
                "blockdevices": [{
                    "name": "sda",
                    "type": "disk",
                    "fstype": "ext4"
                }]
            }"#;
            assert_eq!(
                LinuxPostureProvider::detect_disk_encryption_from_lsblk(lsblk),
                PostureToggle::Unknown
            );
        }

        #[test]
        fn lsblk_garbage_returns_unknown() {
            assert_eq!(
                LinuxPostureProvider::detect_disk_encryption_from_lsblk("not json"),
                PostureToggle::Unknown
            );
        }

        #[test]
        fn parses_pretty_name_from_os_release() {
            let os_release = "\
NAME=\"Ubuntu\"
VERSION=\"22.04.4 LTS (Jammy Jellyfish)\"
ID=ubuntu
PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"
";
            assert_eq!(
                LinuxPostureProvider::parse_os_pretty_name(os_release),
                Some("Ubuntu 22.04.4 LTS".to_string())
            );
        }

        #[test]
        fn classify_firewalld_running() {
            assert_eq!(
                LinuxPostureProvider::classify_firewall_command_output(
                    "firewall-cmd",
                    "running\n",
                    true,
                ),
                PostureToggle::On,
            );
            assert_eq!(
                LinuxPostureProvider::classify_firewall_command_output(
                    "firewall-cmd",
                    "not running\n",
                    false,
                ),
                PostureToggle::Off,
            );
        }

        #[test]
        fn classify_ufw_active() {
            assert_eq!(
                LinuxPostureProvider::classify_firewall_command_output(
                    "ufw",
                    "Status: active\n",
                    true,
                ),
                PostureToggle::On,
            );
            assert_eq!(
                LinuxPostureProvider::classify_firewall_command_output(
                    "ufw",
                    "Status: inactive\n",
                    true,
                ),
                PostureToggle::Off,
            );
        }

        #[test]
        fn snapshot_on_build_host_does_not_panic() {
            let p = LinuxPostureProvider::new();
            let s = p.snapshot().expect("snapshot");
            // Sanity: every field is at least Unknown / None — the
            // shape itself is what we care about.
            let _ = serde_json::to_string(&s).expect("serializable");
        }
    }

    #[cfg(target_os = "macos")]
    mod macos_tests {
        use super::*;

        #[test]
        fn parse_fdesetup_on_off_unknown() {
            assert_eq!(
                MacPostureProvider::parse_fdesetup_status("FileVault is On.\n"),
                PostureToggle::On
            );
            assert_eq!(
                MacPostureProvider::parse_fdesetup_status("FileVault is Off.\n"),
                PostureToggle::Off
            );
            assert_eq!(
                MacPostureProvider::parse_fdesetup_status("ERROR\n"),
                PostureToggle::Unknown
            );
        }

        #[test]
        fn parse_socketfilterfw_states() {
            assert_eq!(
                MacPostureProvider::parse_socketfilterfw("Firewall is enabled. (State = 1)\n"),
                PostureToggle::On
            );
            assert_eq!(
                MacPostureProvider::parse_socketfilterfw("Firewall is disabled. (State = 0)\n"),
                PostureToggle::Off
            );
        }

        #[test]
        fn parse_screensaver_ask_for_password() {
            assert_eq!(
                MacPostureProvider::parse_screensaver_ask_for_password("1\n"),
                PostureToggle::On
            );
            assert_eq!(
                MacPostureProvider::parse_screensaver_ask_for_password("0\n"),
                PostureToggle::Off
            );
            assert_eq!(
                MacPostureProvider::parse_screensaver_ask_for_password(""),
                PostureToggle::Unknown
            );
        }

        #[test]
        fn snapshot_on_build_host_does_not_panic() {
            let p = MacPostureProvider::new();
            let _ = p.snapshot().expect("snapshot");
        }
    }

    #[cfg(target_os = "windows")]
    mod windows_tests {
        use super::*;

        #[test]
        fn parse_manage_bde_states() {
            assert_eq!(
                WindowsPostureProvider::parse_manage_bde(
                    "Disk volumes that can be protected with\n\
                     BitLocker Drive Encryption:\n\
                     Volume C: [OS]\n\
                     Conversion Status:    Fully Encrypted\n",
                ),
                PostureToggle::On,
            );
            assert_eq!(
                WindowsPostureProvider::parse_manage_bde("Conversion Status:    Fully Decrypted\n",),
                PostureToggle::Off,
            );
            assert_eq!(
                WindowsPostureProvider::parse_manage_bde("nothing relevant\n"),
                PostureToggle::Unknown,
            );
        }

        #[test]
        fn parse_netsh_all_on() {
            let out = "
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
...

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
...

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
";
            assert_eq!(
                WindowsPostureProvider::parse_netsh_advfirewall(out),
                PostureToggle::On,
            );
        }

        #[test]
        fn parse_netsh_one_profile_off_means_off() {
            let out = "
Domain Profile Settings:
State                                 ON
Private Profile Settings:
State                                 OFF
Public Profile Settings:
State                                 ON
";
            assert_eq!(
                WindowsPostureProvider::parse_netsh_advfirewall(out),
                PostureToggle::Off,
            );
        }

        #[test]
        fn snapshot_on_build_host_does_not_panic() {
            let p = WindowsPostureProvider::new();
            let _ = p.snapshot().expect("snapshot");
        }
    }
}
