//! Platform Abstraction Layer (PAL) for the SN360 Desktop Agent.
//!
//! Provides cross-platform traits and implementations for filesystem watching,
//! system information, power status, and service management.

pub mod admin_manager;
pub mod app_control;
pub mod fs_watcher;
pub mod package_manager;
pub mod posture;
pub mod power;
pub mod remote_support;
pub mod sysinfo;
pub mod types;

pub use types::*;
