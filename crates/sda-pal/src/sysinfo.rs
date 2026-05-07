//! Cross-platform system information collection.

use crate::types::{HardwareInfo, NetworkInterface, OsInfo, Package, ProcessInfo};

/// Collects system information for the current platform.
pub struct SystemInfoCollector;

impl SystemInfoCollector {
    pub fn new() -> Self {
        Self
    }

    /// Collect OS information.
    pub fn os_info(&self) -> OsInfo {
        #[cfg(target_os = "linux")]
        {
            linux_os_info()
        }
        #[cfg(target_os = "macos")]
        {
            OsInfo {
                name: "macOS".to_string(),
                version: "unknown".to_string(),
                architecture: std::env::consts::ARCH.to_string(),
                hostname: hostname(),
                kernel_version: "unknown".to_string(),
            }
        }
        #[cfg(target_os = "windows")]
        {
            OsInfo {
                name: "Windows".to_string(),
                version: "unknown".to_string(),
                architecture: std::env::consts::ARCH.to_string(),
                hostname: hostname(),
                kernel_version: "unknown".to_string(),
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            OsInfo {
                name: std::env::consts::OS.to_string(),
                version: "unknown".to_string(),
                architecture: std::env::consts::ARCH.to_string(),
                hostname: hostname(),
                kernel_version: "unknown".to_string(),
            }
        }
    }

    /// Collect hardware information.
    pub fn hardware_info(&self) -> HardwareInfo {
        #[cfg(target_os = "linux")]
        {
            linux_hardware_info()
        }
        #[cfg(not(target_os = "linux"))]
        {
            HardwareInfo {
                cpu_name: "unknown".to_string(),
                cpu_cores: 0,
                total_ram_mb: 0,
            }
        }
    }

    /// Collect network interface information.
    pub fn network_interfaces(&self) -> Vec<NetworkInterface> {
        // Placeholder -- full implementation per-platform in future phases
        Vec::new()
    }

    /// Collect installed packages.
    pub fn installed_packages(&self) -> Vec<Package> {
        // Placeholder -- full implementation per-platform in future phases
        Vec::new()
    }

    /// Collect running process information.
    pub fn running_processes(&self) -> Vec<ProcessInfo> {
        // Placeholder -- full implementation per-platform in future phases
        Vec::new()
    }
}

impl Default for SystemInfoCollector {
    fn default() -> Self {
        Self::new()
    }
}

fn hostname() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

#[cfg(target_os = "linux")]
fn linux_os_info() -> OsInfo {
    let mut name = "Linux".to_string();
    let mut version = "unknown".to_string();
    let mut kernel_version = "unknown".to_string();

    // Read /etc/os-release for distro info
    if let Ok(contents) = std::fs::read_to_string("/etc/os-release") {
        for line in contents.lines() {
            if let Some(val) = line.strip_prefix("NAME=") {
                name = val.trim_matches('"').to_string();
            } else if let Some(val) = line.strip_prefix("VERSION_ID=") {
                version = val.trim_matches('"').to_string();
            }
        }
    }

    // Read kernel version from /proc/version
    if let Ok(contents) = std::fs::read_to_string("/proc/version") {
        if let Some(first_part) = contents.split_whitespace().nth(2) {
            kernel_version = first_part.to_string();
        }
    }

    OsInfo {
        name,
        version,
        architecture: std::env::consts::ARCH.to_string(),
        hostname: hostname(),
        kernel_version,
    }
}

#[cfg(target_os = "linux")]
fn linux_hardware_info() -> HardwareInfo {
    let mut cpu_name = "unknown".to_string();
    let mut cpu_cores: u32 = 0;
    let mut total_ram_mb: u64 = 0;

    // Parse /proc/cpuinfo
    if let Ok(contents) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in contents.lines() {
            if let Some(val) = line.strip_prefix("model name") {
                if let Some(val) = val.strip_prefix('\t').and_then(|s| s.strip_prefix(": ")) {
                    cpu_name = val.trim().to_string();
                }
            }
            if line.starts_with("processor") {
                cpu_cores += 1;
            }
        }
    }

    // Parse /proc/meminfo
    if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
        for line in contents.lines() {
            if let Some(val) = line.strip_prefix("MemTotal:") {
                let val = val.trim().trim_end_matches(" kB").trim();
                if let Ok(kb) = val.parse::<u64>() {
                    total_ram_mb = kb / 1024;
                }
            }
        }
    }

    HardwareInfo {
        cpu_name,
        cpu_cores,
        total_ram_mb,
    }
}
