//! Agent module trait and lifecycle management.

use serde::{Deserialize, Serialize};

/// Health status of a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleHealth {
    /// Module is operating normally.
    Healthy,
    /// Module has non-critical issues.
    Degraded,
    /// Module has failed and needs attention.
    Unhealthy,
}

/// Runtime status of a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleStatus {
    /// Module is initialized but not running.
    Initialized,
    /// Module is actively running.
    Running,
    /// Module is paused (e.g., due to power profile).
    Paused,
    /// Module has been stopped.
    Stopped,
    /// Module has encountered a fatal error.
    Failed,
}

/// Trait that all agent modules must implement.
///
/// Modules are the primary building blocks of the agent. Each module
/// handles a specific security function (FIM, log collection, etc.)
/// and communicates via the shared event bus.
pub trait AgentModule: Send + Sync {
    /// Human-readable module name.
    fn name(&self) -> &'static str;

    /// Current module status.
    fn status(&self) -> ModuleStatus;

    /// Current module health.
    fn health(&self) -> ModuleHealth;
}

/// Handle for a running module task.
pub struct ModuleHandle {
    pub name: &'static str,
    pub status: ModuleStatus,
    pub task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl ModuleHandle {
    pub fn new(name: &'static str, task: tokio::task::JoinHandle<anyhow::Result<()>>) -> Self {
        Self {
            name,
            status: ModuleStatus::Running,
            task,
        }
    }
}
