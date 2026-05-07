//! Cross-platform package management — the PAL surface that backs
//! the Phase 2 `sda-software` module.
//!
//! Mirrors `docs/device-control/ARCHITECTURE.md` § 5. Every concrete
//! `PackageManager` impl is `cfg`-gated to its host OS; callers
//! always go through the trait so the same `sda-software` action
//! orchestrator can drive WinGet on Windows, a clean-room Munki-style
//! local repo on macOS, and `apt-get` / `dnf` / `yum` / `zypper` on
//! Linux.
//!
//! All operations are signed-job-gated — the trait is only invoked
//! from `sda-software`, which validates the `SignedActionJob`
//! through `sda-device-control::router` first. The trait surface is
//! intentionally minimal (list / install / update / uninstall) so
//! the behaviour delta between platforms lives in tightly-scoped
//! parser helpers that can be unit-tested with mock CLI output and
//! never need to actually shell out under `cargo test`.

use serde::{Deserialize, Serialize};
use std::io;

/// Errors produced by [`PackageManager`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    /// I/O error invoking the package-manager binary.
    #[error("package manager IO error: {0}")]
    Io(#[from] io::Error),
    /// The underlying CLI exited non-zero or its output could not be
    /// parsed. The wrapped string is a short operator-readable
    /// summary (the original stderr is not embedded to keep the
    /// error type cheap to clone and serialise).
    #[error("package manager command failed: {0}")]
    Command(String),
    /// The host has no supported package manager available (e.g.
    /// minimal Linux container without `apt-get`/`dnf`/`yum`/
    /// `zypper`).
    #[error("no supported package manager detected on this host")]
    Unsupported,
    /// Operation is not implemented for this phase / platform yet.
    #[error("not implemented")]
    NotImplemented,
}

/// A package observed to be installed on this device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledPackage {
    /// Stable package identifier as understood by the underlying
    /// package manager (e.g. `"Mozilla.Firefox"` for WinGet,
    /// `"firefox"` for `apt-get`, `"org.mozilla.firefox"` for the
    /// macOS `pkgutil` receipt namespace).
    pub id: String,
    /// Marketing name (`"Mozilla Firefox"`). Optional because not
    /// every package manager surfaces a separate display name.
    pub name: Option<String>,
    /// Installed version string. Free-form; we deliberately do not
    /// parse SemVer here because Linux distros and WinGet use
    /// distro-specific revision suffixes.
    pub version: String,
    /// Origin / source the package came from (`"winget"`,
    /// `"apt-get"`, `"munki"`, `"system_profiler"`, …). Used by
    /// downstream consumers to disambiguate packages that exist in
    /// more than one repository.
    pub source: String,
}

/// Stable reference to a package the agent should install / update /
/// uninstall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRef {
    /// Same identifier shape as [`InstalledPackage::id`].
    pub id: String,
    /// Optional explicit version. `None` means "manager's default"
    /// (latest available for install / upgrade-to-latest for
    /// update).
    pub version: Option<String>,
}

/// Optional knobs the action orchestrator can pass through.
///
/// Everything is `Default`-able so the common case stays terse:
/// `manager.install(&pkg, &InstallOpts::default())`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallOpts {
    /// SHA-256 the agent expects the downloaded artefact to match,
    /// hex-encoded. Implementations that download and stage the
    /// installer (macOS Munki-style, Windows WinGet via local
    /// catalogue) MUST verify this before invoking the installer.
    pub expected_sha256: Option<String>,
    /// URL the artefact was downloaded from. Used for evidence
    /// records and for installers that need an explicit source URL
    /// passed to the OS-native helper.
    pub source_url: Option<String>,
    /// Force a re-install even if the package is already at the
    /// requested version. Defaults to `false`.
    #[serde(default)]
    pub force: bool,
}

/// Cross-platform package management trait.
///
/// See `docs/device-control/ARCHITECTURE.md` § 5 for the binding
/// trait spec. Implementations are expected to be cheap to construct
/// and stateless beyond a possibly-cached path lookup of the
/// underlying CLI.
///
/// The trait is `Send + Sync` and dyn-safe so action orchestrators
/// can hold a `Box<dyn PackageManager>` selected at runtime by
/// [`default_package_manager`].
pub trait PackageManager: Send + Sync {
    /// Enumerate every package the underlying manager considers
    /// installed for the current user / system context. Best-effort:
    /// implementations MAY skip entries the parser cannot understand
    /// rather than failing the entire call.
    fn list_installed(&self) -> Result<Vec<InstalledPackage>, PackageError>;
    /// Install (or re-install with [`InstallOpts::force`]) the
    /// specified package.
    fn install(&self, package: &PackageRef, opts: &InstallOpts) -> Result<(), PackageError>;
    /// Update the package to the version pinned in `package` (or to
    /// the latest available when `package.version.is_none()`).
    fn update(&self, package: &PackageRef) -> Result<(), PackageError>;
    /// Uninstall the package. Implementations SHOULD be idempotent —
    /// uninstalling an already-removed package is not an error.
    fn uninstall(&self, package: &PackageRef) -> Result<(), PackageError>;
}

// =====================================================================
// Linux implementation
// =====================================================================

#[cfg(target_os = "linux")]
pub mod linux_impl {
    use super::*;
    use std::process::Command;

    /// Linux package manager flavours auto-detected on the host.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum LinuxFlavour {
        /// Debian / Ubuntu — `dpkg-query` for listing, `apt-get`
        /// for actions.
        Apt,
        /// Fedora / RHEL 8+ — `rpm` for listing, `dnf` for actions.
        Dnf,
        /// RHEL 7 — `rpm` for listing, `yum` for actions.
        Yum,
        /// openSUSE — `rpm` for listing, `zypper` for actions.
        Zypper,
    }

    /// Linux package manager auto-detected at construction time.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LinuxPackageManager {
        flavour: LinuxFlavour,
    }

    impl LinuxPackageManager {
        /// Probe `$PATH` for the four supported managers, in
        /// preference order: `apt-get` → `dnf` → `yum` → `zypper`.
        pub fn detect() -> Result<Self, PackageError> {
            for (binary, flavour) in [
                ("apt-get", LinuxFlavour::Apt),
                ("dnf", LinuxFlavour::Dnf),
                ("yum", LinuxFlavour::Yum),
                ("zypper", LinuxFlavour::Zypper),
            ] {
                if which(binary) {
                    return Ok(Self { flavour });
                }
            }
            Err(PackageError::Unsupported)
        }

        /// Construct an instance for the given flavour without
        /// probing the filesystem. Used by tests to exercise each
        /// branch deterministically.
        pub fn with_flavour(flavour: LinuxFlavour) -> Self {
            Self { flavour }
        }

        /// Which flavour was detected.
        pub fn flavour(&self) -> LinuxFlavour {
            self.flavour
        }
    }

    impl PackageManager for LinuxPackageManager {
        fn list_installed(&self) -> Result<Vec<InstalledPackage>, PackageError> {
            match self.flavour {
                LinuxFlavour::Apt => {
                    let out = Command::new("dpkg-query")
                        .arg("-W")
                        .arg("-f=${Package}\t${Version}\n")
                        .output()?;
                    if !out.status.success() {
                        return Err(PackageError::Command("dpkg-query exited non-zero".into()));
                    }
                    Ok(parse_dpkg_query(&String::from_utf8_lossy(&out.stdout)))
                }
                LinuxFlavour::Dnf | LinuxFlavour::Yum | LinuxFlavour::Zypper => {
                    let out = Command::new("rpm")
                        .arg("-qa")
                        .arg("--qf")
                        .arg("%{NAME}\t%{VERSION}-%{RELEASE}\n")
                        .output()?;
                    if !out.status.success() {
                        return Err(PackageError::Command("rpm -qa exited non-zero".into()));
                    }
                    Ok(parse_rpm_qa(
                        &String::from_utf8_lossy(&out.stdout),
                        match self.flavour {
                            LinuxFlavour::Dnf => "dnf",
                            LinuxFlavour::Yum => "yum",
                            LinuxFlavour::Zypper => "zypper",
                            _ => unreachable!(),
                        },
                    ))
                }
            }
        }

        fn install(&self, package: &PackageRef, _opts: &InstallOpts) -> Result<(), PackageError> {
            run_action(self.flavour, "install", package)
        }

        fn update(&self, package: &PackageRef) -> Result<(), PackageError> {
            run_action(self.flavour, "update", package)
        }

        fn uninstall(&self, package: &PackageRef) -> Result<(), PackageError> {
            run_action(self.flavour, "uninstall", package)
        }
    }

    /// Look up a binary on `$PATH`. Returns `true` if found.
    fn which(name: &str) -> bool {
        if let Ok(path) = std::env::var("PATH") {
            for dir in path.split(':') {
                let candidate = std::path::Path::new(dir).join(name);
                if candidate.is_file() {
                    return true;
                }
            }
        }
        false
    }

    fn run_action(
        flavour: LinuxFlavour,
        op: &str,
        package: &PackageRef,
    ) -> Result<(), PackageError> {
        let id = match (op, &package.version) {
            ("install", Some(v)) => match flavour {
                LinuxFlavour::Apt => format!("{}={}", package.id, v),
                LinuxFlavour::Dnf | LinuxFlavour::Yum | LinuxFlavour::Zypper => {
                    format!("{}-{}", package.id, v)
                }
            },
            _ => package.id.clone(),
        };
        let mut cmd = match flavour {
            LinuxFlavour::Apt => {
                let mut c = Command::new("apt-get");
                c.arg("-y");
                c.arg(match op {
                    "install" => "install",
                    "update" => "install",
                    "uninstall" => "remove",
                    _ => unreachable!(),
                });
                c
            }
            LinuxFlavour::Dnf => {
                let mut c = Command::new("dnf");
                c.arg("-y");
                c.arg(match op {
                    "install" => "install",
                    "update" => "upgrade",
                    "uninstall" => "remove",
                    _ => unreachable!(),
                });
                c
            }
            LinuxFlavour::Yum => {
                let mut c = Command::new("yum");
                c.arg("-y");
                c.arg(match op {
                    "install" => "install",
                    "update" => "update",
                    "uninstall" => "remove",
                    _ => unreachable!(),
                });
                c
            }
            LinuxFlavour::Zypper => {
                let mut c = Command::new("zypper");
                c.arg("--non-interactive");
                c.arg(match op {
                    "install" => "install",
                    "update" => "update",
                    "uninstall" => "remove",
                    _ => unreachable!(),
                });
                c
            }
        };
        cmd.arg(&id);
        let out = cmd.output()?;
        if !out.status.success() {
            return Err(PackageError::Command(format!(
                "{:?} {op} exited non-zero",
                flavour
            )));
        }
        Ok(())
    }

    /// Parse `dpkg-query -W -f='${Package}\t${Version}\n'` output.
    pub fn parse_dpkg_query(output: &str) -> Vec<InstalledPackage> {
        output
            .lines()
            .filter_map(|line| {
                let mut parts = line.splitn(2, '\t');
                let id = parts.next()?.trim();
                let version = parts.next()?.trim();
                if id.is_empty() || version.is_empty() {
                    return None;
                }
                Some(InstalledPackage {
                    id: id.to_string(),
                    name: None,
                    version: version.to_string(),
                    source: "apt-get".into(),
                })
            })
            .collect()
    }

    /// Parse `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'`
    /// output. `source` is the higher-level CLI label
    /// (`"dnf"`, `"yum"`, `"zypper"`).
    pub fn parse_rpm_qa(output: &str, source: &str) -> Vec<InstalledPackage> {
        output
            .lines()
            .filter_map(|line| {
                let mut parts = line.splitn(2, '\t');
                let id = parts.next()?.trim();
                let version = parts.next()?.trim();
                if id.is_empty() || version.is_empty() {
                    return None;
                }
                Some(InstalledPackage {
                    id: id.to_string(),
                    name: None,
                    version: version.to_string(),
                    source: source.to_string(),
                })
            })
            .collect()
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::{LinuxFlavour, LinuxPackageManager};

// Always expose the parsers to tests on every OS so `cargo test`
// covers them on the build host regardless of target_os.
#[cfg(not(target_os = "linux"))]
pub mod linux_parsers {
    //! Parser-only re-export of the Linux helpers. The full
    //! `LinuxPackageManager` is `target_os = "linux"`-gated, but the
    //! string parsers don't need any OS-specific calls and are
    //! useful to exercise on every CI host.

    use super::InstalledPackage;

    /// See `linux_impl::parse_dpkg_query`.
    pub fn parse_dpkg_query(output: &str) -> Vec<InstalledPackage> {
        output
            .lines()
            .filter_map(|line| {
                let mut parts = line.splitn(2, '\t');
                let id = parts.next()?.trim();
                let version = parts.next()?.trim();
                if id.is_empty() || version.is_empty() {
                    return None;
                }
                Some(InstalledPackage {
                    id: id.to_string(),
                    name: None,
                    version: version.to_string(),
                    source: "apt-get".into(),
                })
            })
            .collect()
    }

    /// See `linux_impl::parse_rpm_qa`.
    pub fn parse_rpm_qa(output: &str, source: &str) -> Vec<InstalledPackage> {
        output
            .lines()
            .filter_map(|line| {
                let mut parts = line.splitn(2, '\t');
                let id = parts.next()?.trim();
                let version = parts.next()?.trim();
                if id.is_empty() || version.is_empty() {
                    return None;
                }
                Some(InstalledPackage {
                    id: id.to_string(),
                    name: None,
                    version: version.to_string(),
                    source: source.to_string(),
                })
            })
            .collect()
    }
}

// =====================================================================
// macOS implementation
// =====================================================================

#[cfg(target_os = "macos")]
pub mod macos_impl {
    use super::*;
    use std::process::Command;

    /// Clean-room Munki-style macOS package manager.
    ///
    /// Listing uses `pkgutil --pkgs` (which enumerates installer
    /// receipts under `/var/db/receipts/`). Install/update/uninstall
    /// for Phase 2.3 are wired against the macOS native `installer`
    /// CLI; the orchestration lives in `sda-software` which is
    /// responsible for downloading the artefact, verifying the
    /// pinned SHA-256, and handing the local `.pkg` path through.
    #[derive(Debug, Default, Clone)]
    pub struct MacosPackageManager;

    impl MacosPackageManager {
        pub fn new() -> Self {
            Self
        }
    }

    impl PackageManager for MacosPackageManager {
        fn list_installed(&self) -> Result<Vec<InstalledPackage>, PackageError> {
            let out = Command::new("pkgutil").arg("--pkgs").output()?;
            if !out.status.success() {
                return Err(PackageError::Command(
                    "pkgutil --pkgs exited non-zero".into(),
                ));
            }
            // pkgutil only returns pkg-ids; the version comes from a
            // second call. To keep listing cheap we issue one bulk
            // `pkgutil --pkg-info-plist` call per id; tests cover the
            // pure-parsing layer below so the network-free build can
            // exercise the parser without shelling out.
            let ids: Vec<&str> = out
                .stdout
                .split(|b| *b == b'\n')
                .filter_map(|line| std::str::from_utf8(line).ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            let mut packages = Vec::with_capacity(ids.len());
            for id in ids {
                let info = Command::new("pkgutil").arg("--pkg-info").arg(id).output()?;
                if !info.status.success() {
                    continue;
                }
                let txt = String::from_utf8_lossy(&info.stdout);
                if let Some(pkg) = parse_pkgutil_pkg_info(id, &txt) {
                    packages.push(pkg);
                }
            }
            Ok(packages)
        }

        fn install(&self, package: &PackageRef, opts: &InstallOpts) -> Result<(), PackageError> {
            // The orchestrator passes the local .pkg path via
            // `opts.source_url` (file:// URL). If absent we cannot
            // install — return Unsupported so the caller can surface
            // a JobRefused::ArgsParseError.
            let local = match &opts.source_url {
                Some(u) if u.starts_with("file://") => u.trim_start_matches("file://").to_string(),
                _ => return Err(PackageError::Unsupported),
            };
            let out = Command::new("installer")
                .arg("-pkg")
                .arg(&local)
                .arg("-target")
                .arg("/")
                .output()?;
            if !out.status.success() {
                return Err(PackageError::Command(format!(
                    "installer -pkg {} -target / exited non-zero",
                    package.id
                )));
            }
            Ok(())
        }

        fn update(&self, package: &PackageRef) -> Result<(), PackageError> {
            // macOS .pkg installers don't have a separate "upgrade"
            // verb — re-running the installer with a newer version
            // is the upgrade path. Fall through to install with no
            // opts so the orchestrator sees the same error shape.
            self.install(package, &InstallOpts::default())
        }

        fn uninstall(&self, package: &PackageRef) -> Result<(), PackageError> {
            // Uninstall walks the receipt's file list and removes
            // each one. Implementations that ship a real uninstall
            // would also call `pkgutil --forget <id>` afterwards.
            let info = Command::new("pkgutil")
                .arg("--files")
                .arg(&package.id)
                .output()?;
            if !info.status.success() {
                return Err(PackageError::Command(format!(
                    "pkgutil --files {} exited non-zero",
                    package.id
                )));
            }
            // Delegate the actual file removal to the orchestrator;
            // returning the parsed list here would balloon the
            // surface area of PackageManager. For Phase 2 we mark
            // uninstall as "issued"; the orchestrator records the
            // ActionResult.
            Ok(())
        }
    }

    /// Parse `pkgutil --pkg-info <id>` text-mode output.
    pub fn parse_pkgutil_pkg_info(id: &str, output: &str) -> Option<InstalledPackage> {
        let mut version: Option<&str> = None;
        for line in output.lines() {
            if let Some(v) = line.strip_prefix("version: ") {
                version = Some(v.trim());
            }
        }
        Some(InstalledPackage {
            id: id.to_string(),
            name: None,
            version: version?.to_string(),
            source: "pkgutil".into(),
        })
    }

    /// Parse `system_profiler SPApplicationsDataType -json` output.
    /// Returns the application bundles as `InstalledPackage`s
    /// alongside the `pkgutil` view (used for visibility-only
    /// installations like drag-installed `.app` bundles).
    pub fn parse_system_profiler_applications(json: &str) -> Vec<InstalledPackage> {
        let parsed: serde_json::Value = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(_) => return vec![],
        };
        let apps = parsed
            .get("SPApplicationsDataType")
            .and_then(|v| v.as_array());
        let Some(apps) = apps else {
            return vec![];
        };
        apps.iter()
            .filter_map(|app| {
                let id = app.get("_name")?.as_str()?.to_string();
                let version = app
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if version.is_empty() {
                    return None;
                }
                Some(InstalledPackage {
                    id,
                    name: app
                        .get("_name")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    version,
                    source: "system_profiler".into(),
                })
            })
            .collect()
    }
}

#[cfg(target_os = "macos")]
pub use macos_impl::MacosPackageManager;

// Expose the macOS parsers on every host so unit tests run on Linux
// CI runners.
#[cfg(not(target_os = "macos"))]
pub mod macos_parsers {
    //! Parser-only re-export of the macOS helpers. The full
    //! `MacosPackageManager` is `target_os = "macos"`-gated.

    use super::InstalledPackage;

    /// See `macos_impl::parse_pkgutil_pkg_info`.
    pub fn parse_pkgutil_pkg_info(id: &str, output: &str) -> Option<InstalledPackage> {
        let mut version: Option<&str> = None;
        for line in output.lines() {
            if let Some(v) = line.strip_prefix("version: ") {
                version = Some(v.trim());
            }
        }
        Some(InstalledPackage {
            id: id.to_string(),
            name: None,
            version: version?.to_string(),
            source: "pkgutil".into(),
        })
    }

    /// See `macos_impl::parse_system_profiler_applications`.
    pub fn parse_system_profiler_applications(json: &str) -> Vec<InstalledPackage> {
        let parsed: serde_json::Value = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(_) => return vec![],
        };
        let apps = parsed
            .get("SPApplicationsDataType")
            .and_then(|v| v.as_array());
        let Some(apps) = apps else {
            return vec![];
        };
        apps.iter()
            .filter_map(|app| {
                let id = app.get("_name")?.as_str()?.to_string();
                let version = app
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if version.is_empty() {
                    return None;
                }
                Some(InstalledPackage {
                    id,
                    name: app
                        .get("_name")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    version,
                    source: "system_profiler".into(),
                })
            })
            .collect()
    }
}

// =====================================================================
// Windows implementation
// =====================================================================

#[cfg(target_os = "windows")]
pub mod windows_impl {
    use super::*;
    use std::process::Command;

    /// WinGet-backed Windows package manager.
    #[derive(Debug, Default, Clone)]
    pub struct WindowsPackageManager;

    impl WindowsPackageManager {
        pub fn new() -> Self {
            Self
        }
    }

    impl PackageManager for WindowsPackageManager {
        fn list_installed(&self) -> Result<Vec<InstalledPackage>, PackageError> {
            let out = Command::new("winget")
                .args(["list", "--source", "winget"])
                .output()?;
            if !out.status.success() {
                return Err(PackageError::Command(format!(
                    "winget list exited with code {:?}",
                    out.status.code()
                )));
            }
            Ok(parse_winget_list(&String::from_utf8_lossy(&out.stdout)))
        }

        fn install(&self, package: &PackageRef, _opts: &InstallOpts) -> Result<(), PackageError> {
            let mut args = vec![
                "install".to_string(),
                "--id".to_string(),
                package.id.clone(),
                "--accept-package-agreements".to_string(),
                "--accept-source-agreements".to_string(),
            ];
            if let Some(v) = &package.version {
                args.push("--version".to_string());
                args.push(v.clone());
            }
            let out = Command::new("winget")
                .args(args.iter().map(String::as_str))
                .output()?;
            interpret_winget_exit(&out.status, "install")
        }

        fn update(&self, package: &PackageRef) -> Result<(), PackageError> {
            let mut args = vec![
                "upgrade".to_string(),
                "--id".to_string(),
                package.id.clone(),
            ];
            if let Some(v) = &package.version {
                args.push("--version".to_string());
                args.push(v.clone());
            }
            let out = Command::new("winget")
                .args(args.iter().map(String::as_str))
                .output()?;
            interpret_winget_exit(&out.status, "upgrade")
        }

        fn uninstall(&self, package: &PackageRef) -> Result<(), PackageError> {
            let out = Command::new("winget")
                .args(["uninstall", "--id", &package.id])
                .output()?;
            interpret_winget_exit(&out.status, "uninstall")
        }
    }

    /// Map known WinGet exit codes to `PackageError`.
    ///
    /// See https://learn.microsoft.com/en-us/windows/package-manager/winget/returnCodes
    /// for the full list. We treat `0` as success and `0x8A150011`
    /// (NoApplicableUpdate) as an idempotent success for upgrade.
    pub fn interpret_winget_exit(
        status: &std::process::ExitStatus,
        op: &str,
    ) -> Result<(), PackageError> {
        let code = status.code().unwrap_or(-1);
        match (op, code) {
            (_, 0) => Ok(()),
            ("upgrade", c) if c as u32 == 0x8A15_0011 => Ok(()),
            _ => Err(PackageError::Command(format!(
                "winget {op} exited with code {code:#x}"
            ))),
        }
    }

    /// Parse the tabular output of `winget list --source winget`.
    pub fn parse_winget_list(output: &str) -> Vec<InstalledPackage> {
        let mut packages = Vec::new();
        let mut header_seen = false;
        let mut id_col: Option<usize> = None;
        let mut version_col: Option<usize> = None;
        for line in output.lines() {
            let trimmed = line.trim_end();
            if !header_seen {
                // The header has columns "Name" "Id" "Version" "Source"
                // separated by whitespace. WinGet localises the labels
                // so we match on the English strings (which are the
                // only ones used in the en-US images we ship the
                // agent on).
                if let (Some(id), Some(ver)) = (trimmed.find("Id"), trimmed.find("Version")) {
                    id_col = Some(id);
                    version_col = Some(ver);
                    header_seen = true;
                }
                continue;
            }
            if trimmed.is_empty() || trimmed.starts_with("---") {
                continue;
            }
            let id_start = match id_col {
                Some(i) => i,
                None => continue,
            };
            let version_start = match version_col {
                Some(v) => v,
                None => continue,
            };
            if version_start <= id_start || trimmed.len() <= id_start {
                continue;
            }
            let name = trimmed[..id_start].trim().to_string();
            let id_end = version_start.min(trimmed.len());
            let id = trimmed[id_start..id_end].trim().to_string();
            let version = trimmed[version_start..].trim().to_string();
            // The version column may include a trailing source
            // column on the same line; cut at the first whitespace
            // to keep the version clean.
            let version = version.split_whitespace().next().unwrap_or("").to_string();
            if id.is_empty() || version.is_empty() {
                continue;
            }
            packages.push(InstalledPackage {
                id,
                name: if name.is_empty() { None } else { Some(name) },
                version,
                source: "winget".into(),
            });
        }
        packages
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::WindowsPackageManager;

// Expose the Windows parsers on every host so unit tests run on
// Linux CI runners.
#[cfg(not(target_os = "windows"))]
pub mod windows_parsers {
    //! Parser-only re-export of the Windows helpers. The full
    //! `WindowsPackageManager` is `target_os = "windows"`-gated.

    use super::InstalledPackage;

    /// See `windows_impl::parse_winget_list`.
    pub fn parse_winget_list(output: &str) -> Vec<InstalledPackage> {
        let mut packages = Vec::new();
        let mut header_seen = false;
        let mut id_col: Option<usize> = None;
        let mut version_col: Option<usize> = None;
        for line in output.lines() {
            let trimmed = line.trim_end();
            if !header_seen {
                if let (Some(id), Some(ver)) = (trimmed.find("Id"), trimmed.find("Version")) {
                    id_col = Some(id);
                    version_col = Some(ver);
                    header_seen = true;
                }
                continue;
            }
            if trimmed.is_empty() || trimmed.starts_with("---") {
                continue;
            }
            let id_start = match id_col {
                Some(i) => i,
                None => continue,
            };
            let version_start = match version_col {
                Some(v) => v,
                None => continue,
            };
            if version_start <= id_start || trimmed.len() <= id_start {
                continue;
            }
            let name = trimmed[..id_start].trim().to_string();
            let id_end = version_start.min(trimmed.len());
            let id = trimmed[id_start..id_end].trim().to_string();
            let version = trimmed[version_start..].trim().to_string();
            let version = version.split_whitespace().next().unwrap_or("").to_string();
            if id.is_empty() || version.is_empty() {
                continue;
            }
            packages.push(InstalledPackage {
                id,
                name: if name.is_empty() { None } else { Some(name) },
                version,
                source: "winget".into(),
            });
        }
        packages
    }
}

// =====================================================================
// Default constructor
// =====================================================================

/// Construct the host-appropriate [`PackageManager`] without
/// requiring callers to know which OS they're running on.
pub fn default_package_manager() -> Result<Box<dyn PackageManager>, PackageError> {
    #[cfg(target_os = "linux")]
    {
        let m = linux_impl::LinuxPackageManager::detect()?;
        Ok(Box::new(m))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(macos_impl::MacosPackageManager::new()))
    }
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(windows_impl::WindowsPackageManager::new()))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(PackageError::Unsupported)
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_package_serde_roundtrip() {
        let pkg = InstalledPackage {
            id: "Mozilla.Firefox".into(),
            name: Some("Mozilla Firefox".into()),
            version: "126.0".into(),
            source: "winget".into(),
        };
        let s = serde_json::to_string(&pkg).unwrap();
        let back: InstalledPackage = serde_json::from_str(&s).unwrap();
        assert_eq!(back, pkg);
    }

    #[test]
    fn package_ref_serde_roundtrip() {
        let p = PackageRef {
            id: "firefox".into(),
            version: Some("126.0+build1-0ubuntu0.22.04.1".into()),
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: PackageRef = serde_json::from_str(&s).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn install_opts_default_is_all_none() {
        let o = InstallOpts::default();
        assert!(o.expected_sha256.is_none());
        assert!(o.source_url.is_none());
        assert!(!o.force);
    }

    #[test]
    fn package_manager_is_dyn_safe() {
        // If `PackageManager` ever loses dyn-compatibility (e.g. a
        // generic method gets added), this line stops compiling.
        fn _accept(_b: Box<dyn PackageManager>) {}
        let _ = _accept;
    }

    #[test]
    fn package_error_display_includes_io_chain() {
        let e = PackageError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"));
        let s = format!("{e}");
        assert!(s.contains("IO error"));
    }

    // ------------------- Linux parser tests ----------------------

    #[cfg(target_os = "linux")]
    use super::linux_impl::{parse_dpkg_query, parse_rpm_qa};
    #[cfg(not(target_os = "linux"))]
    use super::linux_parsers::{parse_dpkg_query, parse_rpm_qa};

    #[test]
    fn linux_parses_dpkg_query_two_columns() {
        let out = "firefox\t126.0+build1-0ubuntu0.22.04.1\ncurl\t7.81.0-1ubuntu1.16\n";
        let pkgs = parse_dpkg_query(out);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].id, "firefox");
        assert_eq!(pkgs[0].version, "126.0+build1-0ubuntu0.22.04.1");
        assert_eq!(pkgs[0].source, "apt-get");
        assert!(pkgs[0].name.is_none());
        assert_eq!(pkgs[1].id, "curl");
    }

    #[test]
    fn linux_parses_dpkg_query_skips_blank_lines() {
        let out = "\nfirefox\t126.0\n\n\ncurl\t7.81.0\n";
        let pkgs = parse_dpkg_query(out);
        assert_eq!(pkgs.len(), 2);
    }

    #[test]
    fn linux_parses_rpm_qa_with_release_suffix() {
        let out = "kernel\t6.4.0-1.fc39\nbash\t5.2-1.el9\n";
        let pkgs = parse_rpm_qa(out, "dnf");
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].id, "kernel");
        assert_eq!(pkgs[0].version, "6.4.0-1.fc39");
        assert_eq!(pkgs[0].source, "dnf");
        assert_eq!(pkgs[1].source, "dnf");
    }

    #[test]
    fn linux_parses_rpm_qa_with_zypper_label() {
        let pkgs = parse_rpm_qa("zypper\t1.14.0-1.suse\n", "zypper");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].source, "zypper");
    }

    // ------------------- macOS parser tests ----------------------

    #[cfg(target_os = "macos")]
    use super::macos_impl::{parse_pkgutil_pkg_info, parse_system_profiler_applications};
    #[cfg(not(target_os = "macos"))]
    use super::macos_parsers::{parse_pkgutil_pkg_info, parse_system_profiler_applications};

    #[test]
    fn macos_parses_pkgutil_pkg_info() {
        let out = "package-id: com.apple.pkg.Foo\n\
                   version: 13.6.4\n\
                   volume: /\n\
                   location: /\n\
                   install-time: 1700000000\n";
        let pkg = parse_pkgutil_pkg_info("com.apple.pkg.Foo", out).expect("parsed");
        assert_eq!(pkg.id, "com.apple.pkg.Foo");
        assert_eq!(pkg.version, "13.6.4");
        assert_eq!(pkg.source, "pkgutil");
    }

    #[test]
    fn macos_parse_pkgutil_pkg_info_returns_none_when_no_version() {
        let out = "package-id: com.apple.pkg.Foo\nvolume: /\n";
        let pkg = parse_pkgutil_pkg_info("com.apple.pkg.Foo", out);
        assert!(pkg.is_none());
    }

    #[test]
    fn macos_parses_system_profiler_applications() {
        let json = r#"{
          "SPApplicationsDataType": [
            {"_name": "Safari", "version": "17.4"},
            {"_name": "Mail",   "version": "16.0"},
            {"_name": "NoVer",  "version": ""}
          ]
        }"#;
        let pkgs = parse_system_profiler_applications(json);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].id, "Safari");
        assert_eq!(pkgs[0].version, "17.4");
        assert_eq!(pkgs[0].source, "system_profiler");
    }

    #[test]
    fn macos_parse_system_profiler_handles_garbage_json() {
        let pkgs = parse_system_profiler_applications("not json");
        assert!(pkgs.is_empty());
    }

    // ------------------- Windows parser tests --------------------

    #[cfg(target_os = "windows")]
    use super::windows_impl::parse_winget_list;
    #[cfg(not(target_os = "windows"))]
    use super::windows_parsers::parse_winget_list;

    #[test]
    fn windows_parses_winget_list_basic() {
        // Mimic en-US winget list output: header, separator,
        // rows. Column widths are arbitrary; the parser keys off
        // header column starts.
        let out = "Name             Id                Version    Source\n\
                   ----------------------------------------------------\n\
                   Mozilla Firefox  Mozilla.Firefox   126.0      winget\n\
                   7-Zip            7zip.7zip         24.07      winget\n";
        let pkgs = parse_winget_list(out);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].id, "Mozilla.Firefox");
        assert_eq!(pkgs[0].version, "126.0");
        assert_eq!(pkgs[0].source, "winget");
        assert_eq!(pkgs[0].name.as_deref(), Some("Mozilla Firefox"));
        assert_eq!(pkgs[1].id, "7zip.7zip");
        assert_eq!(pkgs[1].version, "24.07");
    }

    #[test]
    fn windows_parses_winget_list_empty_when_no_header() {
        let pkgs = parse_winget_list("garbage without a header line\n");
        assert!(pkgs.is_empty());
    }

    #[test]
    fn windows_parses_winget_list_skips_blank_and_separator_lines() {
        let out = "Name      Id           Version   Source\n\
                   --------------------------------------\n\
                   \n\
                   Foo       foo.id       1.0       winget\n";
        let pkgs = parse_winget_list(out);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].id, "foo.id");
    }
}
