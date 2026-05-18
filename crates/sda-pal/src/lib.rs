//! Platform Abstraction Layer (PAL) for the SN360 Desktop Agent.
//!
//! Provides cross-platform traits and implementations for filesystem watching,
//! system information, power status, and service management.

pub mod admin_manager;
pub mod app_control;
pub mod dns_monitor;
pub mod fs_watcher;
pub mod host_isolation;
pub mod mdm;
pub mod memory_scanner;
pub mod network_monitor;
pub mod package_manager;
pub mod posture;
pub mod power;
pub mod process_monitor;
pub mod remote_support;
pub mod sysinfo;
pub mod types;

pub use types::*;
