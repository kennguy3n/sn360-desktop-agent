//! Core agent runtime for the SN360 Desktop Agent.
//!
//! Provides lifecycle management, configuration loading, signal handling,
//! and module orchestration.

pub mod agent;
pub mod config;
pub mod module;
pub mod power;
pub mod signal;

pub use agent::Agent;
pub use config::AgentConfig;
pub use module::{AgentModule, ModuleHealth, ModuleStatus};
pub use power::{
    channel as power_profile_channel, spawn_power_profile_task, PowerProfile, PowerProfileReceiver,
    PowerProfileSender, POWER_PROFILE_IDLE_THRESHOLD, POWER_PROFILE_POLL_INTERVAL,
};
pub use signal::{ShutdownSignal, ShutdownTrigger};
