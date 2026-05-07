//! Action registry and dispatch for active response commands.

pub mod disable_account;
pub mod firewall_drop;
pub mod kill_process;

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Parameters passed to a response action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionParams {
    /// The IP address (for firewall actions).
    #[serde(default)]
    pub ip: Option<String>,
    /// Process ID (for kill actions).
    #[serde(default)]
    pub pid: Option<u32>,
    /// Username (for account actions).
    #[serde(default)]
    pub user: Option<String>,
    /// Timeout for the undo/revert (seconds). 0 = permanent.
    #[serde(default)]
    pub timeout: u64,
    /// Extra parameters as key-value pairs.
    #[serde(default)]
    pub extra: HashMap<String, String>,
}

/// Result of executing an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    /// Whether the action completed successfully.
    pub success: bool,
    /// Human-readable output/message.
    pub output: String,
}

impl ActionResult {
    pub fn ok(output: impl Into<String>) -> Self {
        Self {
            success: true,
            output: output.into(),
        }
    }

    pub fn err(output: impl Into<String>) -> Self {
        Self {
            success: false,
            output: output.into(),
        }
    }
}

/// Trait for response actions.
#[async_trait]
pub trait ResponseAction: Send + Sync {
    /// Action name (e.g., "block_ip", "kill_process").
    fn name(&self) -> &str;

    /// Execute the action with the given parameters.
    async fn execute(&self, params: &ActionParams, timeout: Duration) -> ActionResult;

    /// Undo/revert the action (e.g., unblock IP).
    async fn undo(&self, params: &ActionParams, timeout: Duration) -> ActionResult;
}

/// Registry of available response actions.
pub struct ActionRegistry {
    actions: HashMap<String, Box<dyn ResponseAction>>,
}

impl ActionRegistry {
    /// Create a new registry with built-in actions.
    pub fn new(allowed_actions: &[String]) -> Self {
        let mut actions: HashMap<String, Box<dyn ResponseAction>> = HashMap::new();

        // Register built-in actions if allowed
        if allowed_actions.contains(&"block_ip".to_string())
            || allowed_actions.contains(&"firewall-drop".to_string())
        {
            let action = firewall_drop::FirewallDropAction::new();
            actions.insert(action.name().to_string(), Box::new(action));
            // Also register the Wazuh standard name
            actions.insert(
                "firewall-drop".to_string(),
                Box::new(firewall_drop::FirewallDropAction::new()),
            );
        }

        if allowed_actions.contains(&"kill_process".to_string()) {
            let action = kill_process::KillProcessAction::new();
            actions.insert(action.name().to_string(), Box::new(action));
        }

        if allowed_actions.contains(&"disable_account".to_string())
            || allowed_actions.contains(&"disable-account".to_string())
        {
            let action = disable_account::DisableAccountAction::new();
            actions.insert(action.name().to_string(), Box::new(action));
            actions.insert(
                "disable-account".to_string(),
                Box::new(disable_account::DisableAccountAction::new()),
            );
        }

        Self { actions }
    }

    /// Dispatch an action by name.
    pub async fn dispatch(
        &self,
        action_name: &str,
        params: &ActionParams,
        timeout: Duration,
    ) -> ActionResult {
        // Normalize the action name (Wazuh uses both - and _ forms)
        let normalized = action_name.replace('-', "_");

        let action = self
            .actions
            .get(action_name)
            .or_else(|| self.actions.get(&normalized));

        match action {
            Some(action) => {
                debug!(action = action_name, "dispatching response action");
                action.execute(params, timeout).await
            }
            None => {
                warn!(action = action_name, "unknown action requested");
                ActionResult::err(format!("unknown action: {}", action_name))
            }
        }
    }

    /// Dispatch an undo action by name.
    pub async fn dispatch_undo(
        &self,
        action_name: &str,
        params: &ActionParams,
        timeout: Duration,
    ) -> ActionResult {
        let normalized = action_name.replace('-', "_");

        let action = self
            .actions
            .get(action_name)
            .or_else(|| self.actions.get(&normalized));

        match action {
            Some(action) => {
                debug!(action = action_name, "dispatching undo action");
                action.undo(params, timeout).await
            }
            None => {
                warn!(action = action_name, "unknown action for undo");
                ActionResult::err(format!("unknown action: {}", action_name))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_registry_unknown_action() {
        let registry = ActionRegistry::new(&["block_ip".to_string()]);
        let params = ActionParams {
            ip: None,
            pid: None,
            user: None,
            timeout: 0,
            extra: HashMap::new(),
        };
        let result = registry
            .dispatch("nonexistent", &params, Duration::from_secs(5))
            .await;
        assert!(!result.success);
        assert!(result.output.contains("unknown action"));
    }

    #[tokio::test]
    async fn test_registry_registers_allowed_actions() {
        let registry = ActionRegistry::new(&[
            "block_ip".to_string(),
            "kill_process".to_string(),
            "disable_account".to_string(),
        ]);
        // Verify action exists (dispatch won't say "unknown")
        let params = ActionParams {
            ip: Some("10.0.0.1".to_string()),
            pid: None,
            user: None,
            timeout: 0,
            extra: HashMap::new(),
        };
        let result = registry
            .dispatch("block_ip", &params, Duration::from_secs(5))
            .await;
        // It will either succeed or fail with a real error (not "unknown action")
        assert!(!result.output.contains("unknown action"));
    }
}
