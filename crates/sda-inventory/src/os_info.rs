//! OS information collection for the inventory module.
//!
//! - Linux: parses `/etc/os-release` and `uname` data.
//! - macOS: uses `sw_vers` and `uname`.
//! - Windows: uses `wmic` / `ver`.

use serde_json::Value;
use tracing::{debug, warn};

use crate::syscollector_format::build_osinfo;

/// Collect OS information and return it as a syscollector dbsync_osinfo payload.
pub fn collect_os_info() -> Value {
    #[cfg(target_os = "linux")]
    {
        collect_linux_os_info()
    }
    #[cfg(target_os = "macos")]
    {
        collect_macos_os_info()
    }
    #[cfg(target_os = "windows")]
    {
        collect_windows_os_info()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let data = serde_json::json!({
            "hostname": "unknown",
            "architecture": std::env::consts::ARCH,
            "os_name": std::env::consts::OS,
            "os_version": "",
            "os_codename": "",
            "os_major": "",
            "os_minor": "",
            "os_platform": "unknown",
            "sysname": "unknown",
            "release": "",
        });
        build_osinfo(data)
    }
}

#[cfg(target_os = "linux")]
fn collect_linux_os_info() -> Value {
    let os_release = parse_os_release();

    let hostname = read_file_trimmed("/etc/hostname").unwrap_or_else(gethostname_fallback);

    let kernel_release =
        read_file_trimmed("/proc/sys/kernel/osrelease").unwrap_or_else(|| "unknown".to_string());

    let kernel_name =
        read_file_trimmed("/proc/sys/kernel/ostype").unwrap_or_else(|| "Linux".to_string());

    let architecture = std::env::consts::ARCH.to_string();

    let data = serde_json::json!({
        "hostname": hostname,
        "architecture": architecture,
        "os_name": os_release.name,
        "os_version": os_release.version,
        "os_codename": os_release.version_codename,
        "os_major": os_release.version_major(),
        "os_minor": os_release.version_minor(),
        "os_platform": os_release.id,
        "sysname": kernel_name,
        "release": kernel_release,
    });

    debug!(os_name = %os_release.name, version = %os_release.version, "collected OS info");
    build_osinfo(data)
}

#[cfg(target_os = "macos")]
fn collect_macos_os_info() -> Value {
    let hostname = run_cmd_trimmed("hostname", &[]);
    let product_name = run_cmd_trimmed("sw_vers", &["-productName"]);
    let product_version = run_cmd_trimmed("sw_vers", &["-productVersion"]);
    let build_version = run_cmd_trimmed("sw_vers", &["-buildVersion"]);
    let kernel_release = run_cmd_trimmed("uname", &["-r"]);
    let architecture = std::env::consts::ARCH.to_string();

    let major = product_version.split('.').next().unwrap_or("").to_string();
    let minor = product_version.split('.').nth(1).unwrap_or("").to_string();

    let data = serde_json::json!({
        "hostname": hostname,
        "architecture": architecture,
        "os_name": product_name,
        "os_version": product_version,
        "os_codename": build_version,
        "os_major": major,
        "os_minor": minor,
        "os_platform": "darwin",
        "sysname": "Darwin",
        "release": kernel_release,
    });

    debug!(os_name = %product_name, version = %product_version, "collected OS info");
    build_osinfo(data)
}

#[cfg(target_os = "windows")]
fn collect_windows_os_info() -> Value {
    let hostname = run_cmd_trimmed("hostname", &[]);
    let ver_output = run_cmd_trimmed("cmd", &["/C", "ver"]);
    let architecture = std::env::consts::ARCH.to_string();

    let version = ver_output
        .split("Version ")
        .nth(1)
        .unwrap_or("")
        .trim_end_matches(']')
        .trim()
        .to_string();
    let major = version.split('.').next().unwrap_or("").to_string();
    let minor = version.split('.').nth(1).unwrap_or("").to_string();

    let data = serde_json::json!({
        "hostname": hostname,
        "architecture": architecture,
        "os_name": "Microsoft Windows",
        "os_version": version,
        "os_codename": "",
        "os_major": major,
        "os_minor": minor,
        "os_platform": "windows",
        "sysname": "Windows_NT",
        "release": version,
    });

    debug!(os_name = "Microsoft Windows", version = %version, "collected OS info");
    build_osinfo(data)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn run_cmd_trimmed(program: &str, args: &[&str]) -> String {
    std::process::Command::new(program)
        .args(args)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Parsed fields from `/etc/os-release`.
#[derive(Debug, Default)]
pub(crate) struct OsRelease {
    name: String,
    version: String,
    id: String,
    version_codename: String,
}

impl OsRelease {
    fn version_major(&self) -> String {
        self.version.split('.').next().unwrap_or("").to_string()
    }

    fn version_minor(&self) -> String {
        self.version.split('.').nth(1).unwrap_or("").to_string()
    }
}

/// Parse `/etc/os-release` into an `OsRelease` struct.
pub(crate) fn parse_os_release() -> OsRelease {
    let content = match std::fs::read_to_string("/etc/os-release") {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to read /etc/os-release");
            return OsRelease::default();
        }
    };
    parse_os_release_content(&content)
}

/// Parse os-release content from a string (testable without filesystem).
pub(crate) fn parse_os_release_content(content: &str) -> OsRelease {
    let mut release = OsRelease::default();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim_matches('"');
            match key {
                "NAME" => release.name = value.to_string(),
                "VERSION_ID" => release.version = value.to_string(),
                "ID" => release.id = value.to_string(),
                "VERSION_CODENAME" => release.version_codename = value.to_string(),
                _ => {}
            }
        }
    }

    release
}

fn read_file_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn gethostname_fallback() -> String {
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_os_release_ubuntu() {
        let content = r#"
NAME="Ubuntu"
VERSION_ID="22.04"
ID=ubuntu
VERSION_CODENAME=jammy
HOME_URL="https://www.ubuntu.com/"
"#;
        let release = parse_os_release_content(content);
        assert_eq!(release.name, "Ubuntu");
        assert_eq!(release.version, "22.04");
        assert_eq!(release.id, "ubuntu");
        assert_eq!(release.version_codename, "jammy");
        assert_eq!(release.version_major(), "22");
        assert_eq!(release.version_minor(), "04");
    }

    #[test]
    fn test_parse_os_release_fedora() {
        let content = r#"
NAME="Fedora Linux"
VERSION_ID="39"
ID=fedora
VERSION_CODENAME=""
"#;
        let release = parse_os_release_content(content);
        assert_eq!(release.name, "Fedora Linux");
        assert_eq!(release.version, "39");
        assert_eq!(release.id, "fedora");
        assert_eq!(release.version_major(), "39");
        assert_eq!(release.version_minor(), "");
    }

    #[test]
    fn test_parse_os_release_empty() {
        let release = parse_os_release_content("");
        assert_eq!(release.name, "");
        assert_eq!(release.version, "");
    }

    #[test]
    fn test_parse_os_release_comments_and_blanks() {
        let content = "# comment\n\nNAME=\"Test OS\"\n";
        let release = parse_os_release_content(content);
        assert_eq!(release.name, "Test OS");
    }

    #[test]
    fn test_collect_os_info_returns_valid_json() {
        let info = collect_os_info();
        assert_eq!(info["type"], "dbsync_osinfo");
        assert!(info["data"]["architecture"].is_string());
        assert!(info["data"]["hostname"].is_string());
    }
}
