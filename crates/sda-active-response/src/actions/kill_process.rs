//! Kill process action — terminates a process by PID.
//!
//! - Linux / macOS: `kill -9 <pid>`
//! - Windows: `taskkill /PID <pid> /F`

use std::time::Duration;

use async_trait::async_trait;
use tracing::info;

use super::{ActionParams, ActionResult, ResponseAction};
use crate::executor;

/// Terminates a process by PID.
pub struct KillProcessAction;

impl Default for KillProcessAction {
    fn default() -> Self {
        Self
    }
}

impl KillProcessAction {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ResponseAction for KillProcessAction {
    fn name(&self) -> &str {
        "kill_process"
    }

    async fn execute(&self, params: &ActionParams, timeout: Duration) -> ActionResult {
        // Preferred path: an explicit PID supplied either directly in the
        // AR JSON (`parameters.pid`) or by the calling module.
        if let Some(pid) = params.pid {
            if pid == 0 || pid == 1 {
                return ActionResult::err(format!("refusing to kill PID {}", pid));
            }
            info!(pid, "killing process");
            return platform_kill(pid, timeout).await;
        }

        // Fallback path: the AR command was triggered by an alert whose
        // decoded payload identifies the target by name rather than PID
        // (this is what `parse_ar_command` populates for the
        // regression-suite `kill_process_trigger <pattern>` convention).
        // Use pkill(1) so we can match on the full command line in the
        // same way the upstream wazuh-agent's active-response/bin
        // helper does.
        if let Some(pattern) = params.extra.get("process_pattern") {
            if pattern.is_empty() {
                return ActionResult::err("empty 'process_pattern' for kill_process action");
            }
            info!(pattern = %pattern, "killing processes matching pattern");
            return platform_pkill(pattern, timeout).await;
        }

        ActionResult::err("missing 'pid' or 'process_pattern' for kill_process action")
    }

    async fn undo(&self, _params: &ActionParams, _timeout: Duration) -> ActionResult {
        ActionResult::err("cannot undo process termination")
    }
}

#[cfg(unix)]
async fn platform_kill(pid: u32, timeout: Duration) -> ActionResult {
    let pid_str = pid.to_string();
    let result = executor::execute_command("kill", &["-9", &pid_str], timeout, false).await;

    if result.success {
        ActionResult::ok(format!("killed process {}", pid))
    } else if result.stderr.contains("No such process") {
        ActionResult::ok(format!("process {} already terminated", pid))
    } else {
        ActionResult::err(format!(
            "failed to kill process {}: {}",
            pid,
            result.combined_output()
        ))
    }
}

#[cfg(unix)]
async fn platform_pkill(pattern: &str, timeout: Duration) -> ActionResult {
    // pkill -9 -f exits 0 when at least one process was matched/killed
    // and 1 when no process matched. Either outcome is "successful" from
    // the AR perspective: the goal state (no matching process running) is
    // reached in both cases. Only treat 2 (syntax) and 3 (fatal error)
    // as failures.
    let result = executor::execute_command("pkill", &["-9", "-f", pattern], timeout, false).await;

    if result.success {
        ActionResult::ok(format!("killed processes matching '{}'", pattern))
    } else if result.exit_code == Some(1) {
        ActionResult::ok(format!(
            "no processes matched '{}' (already terminated)",
            pattern
        ))
    } else {
        ActionResult::err(format!(
            "pkill -f '{}' failed: {}",
            pattern,
            result.combined_output()
        ))
    }
}

#[cfg(target_os = "windows")]
async fn platform_pkill(pattern: &str, timeout: Duration) -> ActionResult {
    let _ = (pattern, timeout);
    ActionResult::err("kill_process by pattern is not implemented on Windows")
}

#[cfg(not(any(unix, target_os = "windows")))]
async fn platform_pkill(pattern: &str, _timeout: Duration) -> ActionResult {
    ActionResult::err(format!(
        "kill_process by pattern '{}' not supported on this platform",
        pattern
    ))
}

#[cfg(target_os = "windows")]
async fn platform_kill(pid: u32, timeout: Duration) -> ActionResult {
    let pid_str = pid.to_string();
    let result =
        executor::execute_command("taskkill", &["/PID", &pid_str, "/F"], timeout, false).await;

    if result.success {
        ActionResult::ok(format!("killed process {}", pid))
    } else {
        ActionResult::err(format!(
            "failed to kill process {}: {}",
            pid,
            result.combined_output()
        ))
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
async fn platform_kill(pid: u32, _timeout: Duration) -> ActionResult {
    ActionResult::err(format!(
        "kill_process not supported on this platform for PID {}",
        pid
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_missing_pid() {
        let action = KillProcessAction::new();
        let params = ActionParams {
            ip: None,
            pid: None,
            user: None,
            timeout: 0,
            extra: HashMap::new(),
        };
        let result = action.execute(&params, Duration::from_secs(5)).await;
        assert!(!result.success);
        assert!(result.output.contains("missing"));
    }

    #[tokio::test]
    async fn test_refuse_pid_1() {
        let action = KillProcessAction::new();
        let params = ActionParams {
            ip: None,
            pid: Some(1),
            user: None,
            timeout: 0,
            extra: HashMap::new(),
        };
        let result = action.execute(&params, Duration::from_secs(5)).await;
        assert!(!result.success);
        assert!(result.output.contains("refusing"));
    }

    #[tokio::test]
    async fn test_kill_nonexistent_pid() {
        let action = KillProcessAction::new();
        // Use a very high PID that almost certainly doesn't exist
        let params = ActionParams {
            ip: None,
            pid: Some(4_000_000),
            user: None,
            timeout: 0,
            extra: HashMap::new(),
        };
        let result = action.execute(&params, Duration::from_secs(5)).await;
        // Should handle gracefully (either success because "already terminated" or error)
        // The exact behavior depends on the system
        assert!(!result.output.is_empty());
    }
}
