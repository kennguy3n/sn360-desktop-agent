//! Sandboxed command executor with timeout enforcement.
//!
//! Spawns child processes for active response actions with configurable
//! timeout and optional privilege dropping on Unix systems.

use std::time::Duration;

use tokio::process::Command;
use tracing::{debug, error, warn};

/// Result of executing an active response command.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Whether the command completed successfully (exit code 0).
    pub success: bool,
    /// Exit code of the process, if available.
    pub exit_code: Option<i32>,
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
    /// Whether the command was killed due to timeout.
    pub timed_out: bool,
}

impl ExecutionResult {
    /// Create a timeout result.
    pub fn timeout() -> Self {
        Self {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: "command timed out".to_string(),
            timed_out: true,
        }
    }

    /// Combined output (stdout + stderr) for logging.
    pub fn combined_output(&self) -> String {
        let mut output = String::new();
        if !self.stdout.is_empty() {
            output.push_str(&self.stdout);
        }
        if !self.stderr.is_empty() {
            if !output.is_empty() {
                output.push('\n');
            }
            output.push_str(&self.stderr);
        }
        output
    }
}

/// Execute a command with timeout enforcement and optional sandboxing.
///
/// On Linux, if `drop_privileges` is true and the process is running as root,
/// the child process will have its UID/GID set to `nobody`.
pub async fn execute_command(
    program: &str,
    args: &[&str],
    timeout: Duration,
    drop_privileges: bool,
) -> ExecutionResult {
    debug!(
        program,
        ?args,
        ?timeout,
        drop_privileges,
        "executing command"
    );

    let mut cmd = Command::new(program);
    cmd.args(args);

    // Kill child on parent drop
    cmd.kill_on_drop(true);

    // Capture output
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    // On Unix: optionally drop privileges for the child process
    #[cfg(unix)]
    if drop_privileges {
        unsafe {
            cmd.pre_exec(|| {
                // Try to drop to nobody (uid=65534, gid=65534)
                // This is best-effort; if we're not root, it will fail silently
                let nobody_uid = 65534;
                let nobody_gid = 65534;
                let _ = libc::setgid(nobody_gid);
                let _ = libc::setuid(nobody_uid);
                Ok(())
            });
        }
    }

    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            error!(program, error = %e, "failed to spawn command");
            return ExecutionResult {
                success: false,
                exit_code: None,
                stdout: String::new(),
                stderr: format!("failed to spawn: {}", e),
                timed_out: false,
            };
        }
    };

    // Wait with timeout
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let success = output.status.success();
            let exit_code = output.status.code();

            debug!(program, success, ?exit_code, "command completed");

            ExecutionResult {
                success,
                exit_code,
                stdout,
                stderr,
                timed_out: false,
            }
        }
        Ok(Err(e)) => {
            error!(program, error = %e, "command I/O error");
            ExecutionResult {
                success: false,
                exit_code: None,
                stdout: String::new(),
                stderr: format!("I/O error: {}", e),
                timed_out: false,
            }
        }
        Err(_) => {
            warn!(program, "command timed out, killing");
            ExecutionResult::timeout()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_execute_successful_command() {
        let result = execute_command("echo", &["hello"], Duration::from_secs(5), false).await;
        assert!(result.success);
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout.trim(), "hello");
        assert!(!result.timed_out);
    }

    #[tokio::test]
    async fn test_execute_failing_command() {
        let result = execute_command("false", &[], Duration::from_secs(5), false).await;
        assert!(!result.success);
        assert_eq!(result.exit_code, Some(1));
        assert!(!result.timed_out);
    }

    #[tokio::test]
    async fn test_execute_timeout() {
        let result = execute_command("sleep", &["60"], Duration::from_millis(100), false).await;
        assert!(!result.success);
        assert!(result.timed_out);
    }

    #[tokio::test]
    async fn test_execute_nonexistent_command() {
        let result =
            execute_command("/nonexistent/binary", &[], Duration::from_secs(5), false).await;
        assert!(!result.success);
        assert!(result.stderr.contains("failed to spawn"));
    }

    #[tokio::test]
    async fn test_combined_output() {
        let result = execute_command(
            "sh",
            &["-c", "echo out; echo err >&2"],
            Duration::from_secs(5),
            false,
        )
        .await;
        assert!(result.success);
        assert_eq!(result.stdout.trim(), "out");
        assert_eq!(result.stderr.trim(), "err");
        let combined = result.combined_output();
        assert!(combined.contains("out"));
        assert!(combined.contains("err"));
    }
}
