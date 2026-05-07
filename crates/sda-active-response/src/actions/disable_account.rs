//! Disable account action — locks a user account.
//!
//! - Linux: `passwd -l <user>` / `passwd -u <user>`
//! - macOS: `dscl . -create /Users/<user> UserShell /usr/bin/false`
//! - Windows: `net user <user> /active:no`

use std::time::Duration;

use async_trait::async_trait;
use tracing::info;

use super::{ActionParams, ActionResult, ResponseAction};
use crate::executor;

/// Disables a user account using platform-native tools.
pub struct DisableAccountAction;

impl Default for DisableAccountAction {
    fn default() -> Self {
        Self
    }
}

impl DisableAccountAction {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ResponseAction for DisableAccountAction {
    fn name(&self) -> &str {
        "disable_account"
    }

    async fn execute(&self, params: &ActionParams, timeout: Duration) -> ActionResult {
        let user = match &params.user {
            Some(user) => user,
            None => {
                return ActionResult::err("missing 'user' parameter for disable_account action")
            }
        };

        if user.eq_ignore_ascii_case("root") || user.eq_ignore_ascii_case("administrator") {
            return ActionResult::err("refusing to disable root/Administrator account");
        }

        if !is_valid_username(user) {
            return ActionResult::err(format!("invalid username: {}", user));
        }

        info!(user, "disabling user account");

        platform_disable_account(user, timeout).await
    }

    async fn undo(&self, params: &ActionParams, timeout: Duration) -> ActionResult {
        let user = match &params.user {
            Some(user) => user,
            None => return ActionResult::err("missing 'user' parameter for enable_account action"),
        };

        if user.eq_ignore_ascii_case("root") || user.eq_ignore_ascii_case("administrator") {
            return ActionResult::err("refusing to re-enable root/Administrator account");
        }

        if !is_valid_username(user) {
            return ActionResult::err(format!("invalid username: {}", user));
        }

        info!(user, "re-enabling user account");

        platform_enable_account(user, timeout).await
    }
}

// ── Linux ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn platform_disable_account(user: &str, timeout: Duration) -> ActionResult {
    let result = executor::execute_command("passwd", &["-l", user], timeout, false).await;
    if result.success {
        ActionResult::ok(format!("disabled account {}", user))
    } else {
        ActionResult::err(format!(
            "failed to disable account {}: {}",
            user,
            result.combined_output()
        ))
    }
}

#[cfg(target_os = "linux")]
async fn platform_enable_account(user: &str, timeout: Duration) -> ActionResult {
    let result = executor::execute_command("passwd", &["-u", user], timeout, false).await;
    if result.success {
        ActionResult::ok(format!("re-enabled account {}", user))
    } else {
        ActionResult::err(format!(
            "failed to re-enable account {}: {}",
            user,
            result.combined_output()
        ))
    }
}

// ── macOS ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
const SHELL_STATE_DIR: &str = "/var/lib/sda-shell-state";

#[cfg(target_os = "macos")]
async fn platform_disable_account(user: &str, timeout: Duration) -> ActionResult {
    let user_path = format!("/Users/{}", user);

    // Verify the user exists by reading their current shell.
    let read_result = executor::execute_command(
        "dscl",
        &[".", "-read", &user_path, "UserShell"],
        timeout,
        false,
    )
    .await;
    if !read_result.success {
        return ActionResult::err(format!(
            "user '{}' does not exist in directory service",
            user
        ));
    }

    let output = read_result.stdout.trim().to_string();
    // Output format: "UserShell: /bin/zsh"
    if let Some(shell) = output.split_whitespace().last() {
        if shell != "/usr/bin/false" && shell != "/bin/false" {
            let _ = std::fs::create_dir_all(SHELL_STATE_DIR);
            let state_file = format!("{}/{}", SHELL_STATE_DIR, user);
            // Only save if no state file exists yet, to avoid overwriting
            // the original shell if disable_account is called twice.
            if !std::path::Path::new(&state_file).exists() {
                let _ = std::fs::write(&state_file, shell);
            }
        }
    }

    let result = executor::execute_command(
        "dscl",
        &[".", "-create", &user_path, "UserShell", "/usr/bin/false"],
        timeout,
        false,
    )
    .await;
    if result.success {
        ActionResult::ok(format!("disabled account {}", user))
    } else {
        ActionResult::err(format!(
            "failed to disable account {}: {}",
            user,
            result.combined_output()
        ))
    }
}

#[cfg(target_os = "macos")]
async fn platform_enable_account(user: &str, timeout: Duration) -> ActionResult {
    let user_path = format!("/Users/{}", user);

    // Restore the saved shell, falling back to /bin/zsh if none was saved.
    let state_file = format!("{}/{}", SHELL_STATE_DIR, user);
    let shell = std::fs::read_to_string(&state_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/bin/zsh".to_string());

    let result = executor::execute_command(
        "dscl",
        &[".", "-create", &user_path, "UserShell", &shell],
        timeout,
        false,
    )
    .await;

    if result.success {
        // Clean up state file on successful restore.
        let _ = std::fs::remove_file(&state_file);
        ActionResult::ok(format!("re-enabled account {} (shell: {})", user, shell))
    } else {
        ActionResult::err(format!(
            "failed to re-enable account {}: {}",
            user,
            result.combined_output()
        ))
    }
}

// ── Windows ──────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
async fn platform_disable_account(user: &str, timeout: Duration) -> ActionResult {
    let result =
        executor::execute_command("net", &["user", user, "/active:no"], timeout, false).await;
    if result.success {
        ActionResult::ok(format!("disabled account {}", user))
    } else {
        ActionResult::err(format!(
            "failed to disable account {}: {}",
            user,
            result.combined_output()
        ))
    }
}

#[cfg(target_os = "windows")]
async fn platform_enable_account(user: &str, timeout: Duration) -> ActionResult {
    let result =
        executor::execute_command("net", &["user", user, "/active:yes"], timeout, false).await;
    if result.success {
        ActionResult::ok(format!("re-enabled account {}", user))
    } else {
        ActionResult::err(format!(
            "failed to re-enable account {}: {}",
            user,
            result.combined_output()
        ))
    }
}

// ── Fallback ─────────────────────────────────────────────────────────────────

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
async fn platform_disable_account(user: &str, _timeout: Duration) -> ActionResult {
    ActionResult::err(format!(
        "disable_account not supported on this platform for user {}",
        user
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
async fn platform_enable_account(user: &str, _timeout: Duration) -> ActionResult {
    ActionResult::err(format!(
        "enable_account not supported on this platform for user {}",
        user
    ))
}

/// Basic username validation: alphanumeric, underscore, hyphen, dot.
/// Rejects `.` and `..` to prevent path traversal in state file paths.
fn is_valid_username(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 32
        && user != "."
        && user != ".."
        && user
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_valid_username() {
        assert!(is_valid_username("testuser"));
        assert!(is_valid_username("test_user"));
        assert!(is_valid_username("test-user"));
        assert!(is_valid_username("user.name"));
        assert!(!is_valid_username(""));
        assert!(!is_valid_username("user;rm -rf /"));
        assert!(!is_valid_username("user name"));
        assert!(!is_valid_username("."));
        assert!(!is_valid_username(".."));
    }

    #[tokio::test]
    async fn test_missing_user() {
        let action = DisableAccountAction::new();
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
    async fn test_refuse_root() {
        let action = DisableAccountAction::new();
        let params = ActionParams {
            ip: None,
            pid: None,
            user: Some("root".to_string()),
            timeout: 0,
            extra: HashMap::new(),
        };
        let result = action.execute(&params, Duration::from_secs(5)).await;
        assert!(!result.success);
        assert!(result.output.contains("refusing"));
    }

    #[tokio::test]
    async fn test_invalid_username() {
        let action = DisableAccountAction::new();
        let params = ActionParams {
            ip: None,
            pid: None,
            user: Some("user;rm -rf /".to_string()),
            timeout: 0,
            extra: HashMap::new(),
        };
        let result = action.execute(&params, Duration::from_secs(5)).await;
        assert!(!result.success);
        assert!(result.output.contains("invalid username"));
    }
}
