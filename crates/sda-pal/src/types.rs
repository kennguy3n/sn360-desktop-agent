use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A filesystem change event from the OS watcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsEvent {
    /// The path that changed.
    pub path: PathBuf,
    /// What kind of change occurred.
    pub kind: FsEventKind,
}

/// The kind of filesystem change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsEventKind {
    Created,
    Modified,
    Deleted,
    MetadataChanged,
    Renamed,
}

/// Basic OS information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub hostname: String,
    pub kernel_version: String,
}

/// Hardware information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub cpu_name: String,
    pub cpu_cores: u32,
    pub total_ram_mb: u64,
}

/// Network interface information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub mac_address: Option<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub is_up: bool,
}

/// Installed package information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
    pub vendor: Option<String>,
    pub install_time: Option<String>,
    pub format: String,
}

/// Running process information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub command: Option<String>,
    pub user: Option<String>,
    pub state: Option<String>,
    pub start_time: Option<String>,
}

/// Power/battery state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerState {
    /// Connected to AC power.
    AC,
    /// Running on battery.
    Battery,
    /// Unknown power state.
    Unknown,
}

/// Service status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStatus {
    Running,
    Stopped,
    Unknown,
}
