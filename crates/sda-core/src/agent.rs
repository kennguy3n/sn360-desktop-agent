//! Agent lifecycle management.
//!
//! The Agent struct orchestrates startup, module loading, and shutdown.

use std::collections::HashMap;

use tracing::{error, info, warn};

use crate::config::AgentConfig;
use crate::module::ModuleHandle;
use crate::signal::{ShutdownController, ShutdownSignal};
use sda_event_bus::EventBus;

/// Agent state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    /// Agent is initializing.
    Initializing,
    /// Agent is enrolling with the server.
    Enrolling,
    /// Agent is running normally.
    Running,
    /// Agent is shutting down.
    ShuttingDown,
    /// Agent has stopped.
    Stopped,
}

/// The main agent runtime.
///
/// Manages the agent lifecycle, module loading, event bus,
/// and server communication.
pub struct Agent {
    config: AgentConfig,
    state: AgentState,
    event_bus: EventBus,
    server_rx: Option<tokio::sync::mpsc::Receiver<sda_event_bus::Event>>,
    shutdown_controller: ShutdownController,
    shutdown_signal: ShutdownSignal,
    modules: HashMap<&'static str, ModuleHandle>,
    agent_id: Option<String>,
    agent_key: Option<String>,
}

impl Agent {
    /// Create a new agent with the given configuration.
    pub fn new(config: AgentConfig) -> Self {
        let (event_bus, server_rx) = EventBus::new(
            1024, // broadcast capacity
            1024, // server queue size — large enough to absorb the
                  // initial syscollector burst (packages, network, etc.)
                  // without dropping events before the forward loop
                  // drains them.
        );

        let (shutdown_controller, shutdown_signal) = ShutdownController::new();

        info!("initializing agent");

        Self {
            config,
            state: AgentState::Initializing,
            event_bus,
            server_rx: Some(server_rx),
            shutdown_controller,
            shutdown_signal,
            modules: HashMap::new(),
            agent_id: None,
            agent_key: None,
        }
    }

    /// Get the current agent state.
    pub fn state(&self) -> AgentState {
        self.state
    }

    /// Get a reference to the agent configuration.
    pub fn config(&self) -> &AgentConfig {
        &self.config
    }

    /// Replace the agent configuration (e.g. after cloud-config merge).
    pub fn update_config(&mut self, config: AgentConfig) {
        self.config = config;
    }

    /// Get a clone of the event bus (for passing to modules).
    pub fn event_bus(&self) -> EventBus {
        self.event_bus.clone()
    }

    /// Get a shutdown signal (for passing to modules).
    pub fn shutdown_signal(&self) -> ShutdownSignal {
        self.shutdown_controller.subscribe()
    }

    /// Set the agent ID (after enrollment).
    pub fn set_agent_id(&mut self, id: String) {
        self.agent_id = Some(id);
    }

    /// Set the agent key (after enrollment).
    pub fn set_agent_key(&mut self, key: String) {
        self.agent_key = Some(key);
    }

    /// Get the agent ID, if enrolled.
    pub fn agent_id(&self) -> Option<&str> {
        self.agent_id.as_deref()
    }

    /// Register a module with the agent.
    pub fn register_module(&mut self, handle: ModuleHandle) {
        info!(module = handle.name, "registered module");
        self.modules.insert(handle.name, handle);
    }

    /// Start the agent runtime.
    ///
    /// This sets up signal handlers and transitions to the Running state.
    /// Modules should be registered before calling this.
    pub async fn start(&mut self) {
        info!("starting agent");
        self.state = AgentState::Running;

        // Install signal handlers
        crate::signal::install_signal_handlers(&self.shutdown_controller).await;

        info!(modules = self.modules.len(), "agent started");
    }

    /// Wait for the shutdown signal.
    pub async fn wait_for_shutdown(&mut self) {
        self.shutdown_signal.wait().await;
        self.state = AgentState::ShuttingDown;
        info!("agent shutting down");
    }

    /// Initiate graceful shutdown.
    pub async fn shutdown(&mut self) {
        self.state = AgentState::ShuttingDown;
        info!("shutting down agent");

        // Signal all modules to stop
        self.shutdown_controller.shutdown();

        // Wait for module tasks to complete (with timeout)
        let timeout = tokio::time::Duration::from_secs(10);
        for (name, handle) in self.modules.drain() {
            match tokio::time::timeout(timeout, handle.task).await {
                Ok(Ok(Ok(()))) => {
                    info!(module = name, "module stopped cleanly");
                }
                Ok(Ok(Err(e))) => {
                    warn!(module = name, error = %e, "module stopped with error");
                }
                Ok(Err(e)) => {
                    error!(module = name, error = %e, "module task panicked");
                }
                Err(_) => {
                    warn!(module = name, "module did not stop within timeout");
                }
            }
        }

        self.state = AgentState::Stopped;
        info!("agent stopped");
    }

    /// Take ownership of the server event receiver.
    ///
    /// This is used by the communication layer to receive events
    /// that need to be forwarded to the server.
    pub fn take_server_rx(&mut self) -> Option<tokio::sync::mpsc::Receiver<sda_event_bus::Event>> {
        self.server_rx.take()
    }
}
