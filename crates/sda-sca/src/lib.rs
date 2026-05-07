//! Security Configuration Assessment (SCA) module for the SN360 Desktop Agent.
//!
//! Evaluates YAML-based security policies against system state,
//! running checks during idle periods for minimal user impact.
//!
//! Supports four check types:
//! - **file**: file existence, content regex matching, permission checks.
//! - **process**: verify a named process is running.
//! - **command**: run a command and match output against a pattern.
//! - **registry** (Windows only): check registry key existence / value.

use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use sda_core::config::{AgentConfig, ScaConfig};
use sda_core::module::{ModuleHandle, ModuleHealth, ModuleStatus};
use sda_core::signal::ShutdownSignal;
use sda_core::PowerProfileReceiver;
use sda_event_bus::{Event, EventBus, EventKind, Priority};

// Module-status encoding for atomic access.
const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

// ── Public types ─────────────────────────────────────────────────────────────

/// A loaded SCA policy (parsed from a YAML file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaPolicy {
    pub policy: PolicyMetadata,
    #[serde(default)]
    pub checks: Vec<ScaCheck>,
}

/// Metadata about a policy file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub file: String,
}

/// A single check inside a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaCheck {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    /// "file", "process", "command", or "registry".
    #[serde(rename = "type")]
    pub check_type: String,
    /// Type-specific parameters.
    #[serde(default)]
    pub params: CheckParams,
}

/// Parameters for check evaluation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CheckParams {
    /// Path for file checks.
    pub path: Option<String>,
    /// Regex pattern for file-content or command-output matching.
    pub pattern: Option<String>,
    /// Process name for process checks.
    pub process: Option<String>,
    /// Command to execute for command checks.
    pub command: Option<String>,
    /// Expected command exit code (default: 0 = success).
    pub expected_exit_code: Option<i32>,
}

/// Result of a single check evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub check_id: String,
    pub title: String,
    pub result: CheckStatus,
    pub reason: String,
}

/// Possible outcomes for a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Passed,
    Failed,
    Error,
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckStatus::Passed => write!(f, "passed"),
            CheckStatus::Failed => write!(f, "failed"),
            CheckStatus::Error => write!(f, "error"),
        }
    }
}

// ── ScaModule ────────────────────────────────────────────────────────────────

/// SCA module that loads YAML policies and evaluates checks.
pub struct ScaModule {
    policies: Vec<ScaPolicy>,
}

impl ScaModule {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Load a policy from a YAML file.
    pub fn load_policy_file(&mut self, path: &Path) -> anyhow::Result<()> {
        let content = std::fs::read_to_string(path)?;
        let policy: ScaPolicy = serde_yaml::from_str(&content)?;
        info!(
            policy_id = %policy.policy.id,
            checks = policy.checks.len(),
            "loaded SCA policy"
        );
        self.policies.push(policy);
        Ok(())
    }

    /// Load a policy from a YAML string (useful for tests and embedded policies).
    pub fn load_policy_str(&mut self, yaml: &str) -> anyhow::Result<()> {
        let policy: ScaPolicy = serde_yaml::from_str(yaml)?;
        info!(
            policy_id = %policy.policy.id,
            checks = policy.checks.len(),
            "loaded SCA policy from string"
        );
        self.policies.push(policy);
        Ok(())
    }

    /// Evaluate all loaded policies and publish results to the event bus.
    pub async fn evaluate_all(&self, bus: &EventBus) {
        for policy in &self.policies {
            info!(policy_id = %policy.policy.id, "evaluating SCA policy");
            for check in &policy.checks {
                let result = evaluate_check(check).await;
                debug!(
                    check_id = %result.check_id,
                    result = %result.result,
                    "SCA check evaluated"
                );

                let event = Event::new(
                    "sca",
                    Priority::Low,
                    EventKind::ScaResult {
                        policy_id: policy.policy.id.clone(),
                        check_id: result.check_id.clone(),
                        result: result.result.to_string(),
                    },
                );
                let _ = bus.publish_to_server(event).await;
            }
        }
    }

    /// Get a reference to loaded policies.
    pub fn policies(&self) -> &[ScaPolicy] {
        &self.policies
    }

    /// Spawn the SCA module run loop.
    ///
    /// Loads every `*.yaml` / `*.yml` policy under
    /// [`ScaConfig::policy_dir`], runs one evaluation on startup, then
    /// re-evaluates every [`ScaConfig::scan_interval`] seconds until
    /// `shutdown` is signalled.
    ///
    /// `power_rx` gates evaluations: when
    /// [`PowerProfile::sca_enabled`] is `false` (e.g. the host is on
    /// critical battery) the module skips scheduled evaluations and
    /// resumes them as soon as the profile allows.
    pub fn start(
        config: &AgentConfig,
        bus: EventBus,
        shutdown: ShutdownSignal,
        power_rx: PowerProfileReceiver,
    ) -> ModuleHandle {
        let sca_config = config.modules.sca.clone();
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);

        let task = tokio::spawn(async move {
            if let Err(e) = run(sca_config, bus, shutdown, power_rx, task_status.clone()).await {
                error!(error = %e, "SCA module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });

        ModuleHandle::new("sca", task)
    }
}

impl Default for ScaModule {
    fn default() -> Self {
        Self::new()
    }
}

impl sda_core::module::AgentModule for ScaModule {
    fn name(&self) -> &'static str {
        "sca"
    }

    fn status(&self) -> ModuleStatus {
        ModuleStatus::Running
    }

    fn health(&self) -> ModuleHealth {
        ModuleHealth::Healthy
    }
}

/// Load every `*.yaml` / `*.yml` policy file under `policy_dir` into
/// `module`. Missing directories are logged and skipped so the module
/// can still start on a fresh install.
fn load_policies_from_dir(module: &mut ScaModule, policy_dir: &Path) {
    if !policy_dir.exists() {
        warn!(
            path = %policy_dir.display(),
            "SCA policy directory does not exist; no policies loaded"
        );
        return;
    }

    let entries = match std::fs::read_dir(policy_dir) {
        Ok(entries) => entries,
        Err(e) => {
            warn!(path = %policy_dir.display(), error = %e, "failed to read SCA policy directory");
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
            .unwrap_or(false);
        if !is_yaml {
            continue;
        }
        if let Err(e) = module.load_policy_file(&path) {
            warn!(path = %path.display(), error = %e, "failed to load SCA policy");
        }
    }
}

/// SCA module run loop.
async fn run(
    sca_config: ScaConfig,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    mut power_rx: PowerProfileReceiver,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    info!("SCA module starting");

    let mut module = ScaModule::new();
    load_policies_from_dir(&mut module, &sca_config.policy_dir);
    info!(
        policies = module.policies().len(),
        path = %sca_config.policy_dir.display(),
        "SCA policies loaded"
    );

    status.store(STATUS_RUNNING, Ordering::Relaxed);

    let mut current_profile = *power_rx.borrow();

    // Initial evaluation on startup — but only if the active profile
    // permits SCA work. On critical battery we defer until the host
    // recovers.
    if current_profile.sca_enabled() {
        module.evaluate_all(&bus).await;
    } else {
        info!(
            profile = ?current_profile,
            "skipping initial SCA evaluation: disabled under active power profile"
        );
    }

    let interval = Duration::from_secs(sca_config.scan_interval.max(1));
    let mut timer = tokio::time::interval(interval);
    // Consume the timer's immediate first tick — the startup
    // evaluation above already covered it.
    timer.tick().await;

    loop {
        tokio::select! {
            biased;

            _ = shutdown.wait() => {
                info!("SCA module received shutdown signal");
                break;
            }

            change = power_rx.changed() => {
                if change.is_err() {
                    debug!("power-profile sender dropped; SCA holding last profile");
                    continue;
                }
                let new_profile = *power_rx.borrow();
                if new_profile != current_profile {
                    info!(
                        previous = ?current_profile,
                        current = ?new_profile,
                        sca_enabled = new_profile.sca_enabled(),
                        "SCA retuning for new power profile"
                    );
                    current_profile = new_profile;
                }
            }

            _ = timer.tick() => {
                if !current_profile.sca_enabled() {
                    debug!(
                        profile = ?current_profile,
                        "SCA scan timer fired under disabled profile; skipping evaluation"
                    );
                    continue;
                }
                debug!(profile = ?current_profile, "SCA scan timer fired");
                module.evaluate_all(&bus).await;
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!("SCA module stopped");
    Ok(())
}

// ── Check evaluation ─────────────────────────────────────────────────────────

async fn evaluate_check(check: &ScaCheck) -> CheckResult {
    match check.check_type.as_str() {
        "file" => evaluate_file_check(check),
        "process" => evaluate_process_check(check),
        "command" => evaluate_command_check(check).await,
        _ => CheckResult {
            check_id: check.id.clone(),
            title: check.title.clone(),
            result: CheckStatus::Error,
            reason: format!("unknown check type: {}", check.check_type),
        },
    }
}

fn evaluate_file_check(check: &ScaCheck) -> CheckResult {
    let path = match &check.params.path {
        Some(p) => p,
        None => {
            return CheckResult {
                check_id: check.id.clone(),
                title: check.title.clone(),
                result: CheckStatus::Error,
                reason: "file check missing 'path' parameter".to_string(),
            }
        }
    };

    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return CheckResult {
            check_id: check.id.clone(),
            title: check.title.clone(),
            result: CheckStatus::Failed,
            reason: format!("file does not exist: {}", path),
        };
    }

    // If a pattern is specified, check file content via regex.
    if let Some(ref pattern) = check.params.pattern {
        let re = match RegexBuilder::new(pattern).multi_line(true).build() {
            Ok(r) => r,
            Err(e) => {
                return CheckResult {
                    check_id: check.id.clone(),
                    title: check.title.clone(),
                    result: CheckStatus::Error,
                    reason: format!("invalid regex pattern '{}': {}", pattern, e),
                };
            }
        };
        match std::fs::read_to_string(path) {
            Ok(content) => {
                if re.is_match(&content) {
                    CheckResult {
                        check_id: check.id.clone(),
                        title: check.title.clone(),
                        result: CheckStatus::Passed,
                        reason: format!("file matches pattern: {}", pattern),
                    }
                } else {
                    CheckResult {
                        check_id: check.id.clone(),
                        title: check.title.clone(),
                        result: CheckStatus::Failed,
                        reason: format!("file does not match pattern: {}", pattern),
                    }
                }
            }
            Err(e) => CheckResult {
                check_id: check.id.clone(),
                title: check.title.clone(),
                result: CheckStatus::Error,
                reason: format!("failed to read file: {}", e),
            },
        }
    } else {
        // Just existence check.
        CheckResult {
            check_id: check.id.clone(),
            title: check.title.clone(),
            result: CheckStatus::Passed,
            reason: format!("file exists: {}", path),
        }
    }
}

fn evaluate_process_check(check: &ScaCheck) -> CheckResult {
    let process_name = match &check.params.process {
        Some(p) => p,
        None => {
            return CheckResult {
                check_id: check.id.clone(),
                title: check.title.clone(),
                result: CheckStatus::Error,
                reason: "process check missing 'process' parameter".to_string(),
            }
        }
    };

    // Use `pgrep` on Unix, `tasklist` on Windows.
    let is_running = check_process_running(process_name);

    CheckResult {
        check_id: check.id.clone(),
        title: check.title.clone(),
        result: if is_running {
            CheckStatus::Passed
        } else {
            CheckStatus::Failed
        },
        reason: if is_running {
            format!("process '{}' is running", process_name)
        } else {
            format!("process '{}' is not running", process_name)
        },
    }
}

fn check_process_running(name: &str) -> bool {
    #[cfg(unix)]
    {
        std::process::Command::new("pgrep")
            .arg("-x")
            .arg(name)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("tasklist")
            .args(["/FI", &format!("IMAGENAME eq {}", name)])
            .output()
            .map(|o| {
                let text = String::from_utf8_lossy(&o.stdout);
                text.contains(name)
            })
            .unwrap_or(false)
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = name;
        false
    }
}

async fn evaluate_command_check(check: &ScaCheck) -> CheckResult {
    let command = match &check.params.command {
        Some(c) => c,
        None => {
            return CheckResult {
                check_id: check.id.clone(),
                title: check.title.clone(),
                result: CheckStatus::Error,
                reason: "command check missing 'command' parameter".to_string(),
            }
        }
    };

    let expected_exit = check.params.expected_exit_code.unwrap_or(0);

    let timeout = std::time::Duration::from_secs(30);

    #[cfg(unix)]
    let cmd_future = tokio::process::Command::new("sh")
        .args(["-c", command])
        .output();
    #[cfg(target_os = "windows")]
    let cmd_future = tokio::process::Command::new("cmd")
        .args(["/C", command])
        .output();
    #[cfg(not(any(unix, target_os = "windows")))]
    let cmd_future = futures::future::err::<std::process::Output, _>(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "unsupported platform",
    ));

    let output = match tokio::time::timeout(timeout, cmd_future).await {
        Ok(result) => result,
        Err(_) => {
            return CheckResult {
                check_id: check.id.clone(),
                title: check.title.clone(),
                result: CheckStatus::Error,
                reason: format!(
                    "command timed out after {}s: {}",
                    timeout.as_secs(),
                    command
                ),
            };
        }
    };

    match output {
        Ok(out) => {
            let exit_code = out.status.code().unwrap_or(-1);
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();

            // Check exit code.
            if exit_code != expected_exit {
                return CheckResult {
                    check_id: check.id.clone(),
                    title: check.title.clone(),
                    result: CheckStatus::Failed,
                    reason: format!(
                        "command exit code {} != expected {}",
                        exit_code, expected_exit
                    ),
                };
            }

            // If a pattern is specified, check stdout via regex.
            if let Some(ref pattern) = check.params.pattern {
                let re = match RegexBuilder::new(pattern).multi_line(true).build() {
                    Ok(r) => r,
                    Err(e) => {
                        return CheckResult {
                            check_id: check.id.clone(),
                            title: check.title.clone(),
                            result: CheckStatus::Error,
                            reason: format!("invalid regex pattern '{}': {}", pattern, e),
                        };
                    }
                };
                if re.is_match(&stdout) {
                    CheckResult {
                        check_id: check.id.clone(),
                        title: check.title.clone(),
                        result: CheckStatus::Passed,
                        reason: format!("command output matches pattern: {}", pattern),
                    }
                } else {
                    CheckResult {
                        check_id: check.id.clone(),
                        title: check.title.clone(),
                        result: CheckStatus::Failed,
                        reason: format!("command output does not match pattern: {}", pattern),
                    }
                }
            } else {
                CheckResult {
                    check_id: check.id.clone(),
                    title: check.title.clone(),
                    result: CheckStatus::Passed,
                    reason: format!("command exited with code {}", exit_code),
                }
            }
        }
        Err(e) => CheckResult {
            check_id: check.id.clone(),
            title: check.title.clone(),
            result: CheckStatus::Error,
            reason: format!("failed to execute command: {}", e),
        },
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_POLICY: &str = r#"
policy:
  id: "test_basic_security"
  name: "Basic Security Checks"
  description: "Sample policy for testing SCA engine"
checks:
  - id: "check_etc_passwd"
    title: "Ensure /etc/passwd exists"
    type: "file"
    params:
      path: "/etc/passwd"

  - id: "check_shadow_permissions"
    title: "Ensure /etc/shadow has restricted content"
    type: "file"
    params:
      path: "/etc/shadow"
      pattern: "root"

  - id: "check_sshd_running"
    title: "Ensure SSH daemon is running"
    type: "process"
    params:
      process: "sshd"

  - id: "check_uname"
    title: "Ensure system is Linux"
    type: "command"
    params:
      command: "uname -s"
      pattern: "Linux"
"#;

    #[test]
    fn test_load_policy() {
        let mut module = ScaModule::new();
        module.load_policy_str(SAMPLE_POLICY).unwrap();
        assert_eq!(module.policies().len(), 1);
        assert_eq!(module.policies()[0].policy.id, "test_basic_security");
        assert_eq!(module.policies()[0].checks.len(), 4);
    }

    #[test]
    fn test_file_exists_check() {
        // Use a file that exists on all platforms.
        #[cfg(unix)]
        let existing_path = "/etc/passwd";
        #[cfg(windows)]
        let existing_path = r"C:\Windows\System32\drivers\etc\hosts";

        let check = ScaCheck {
            id: "test_1".to_string(),
            title: "Check existing file".to_string(),
            description: String::new(),
            check_type: "file".to_string(),
            params: CheckParams {
                path: Some(existing_path.to_string()),
                ..Default::default()
            },
        };
        let result = evaluate_file_check(&check);
        assert_eq!(result.result, CheckStatus::Passed);
    }

    #[test]
    fn test_file_not_exists_check() {
        let check = ScaCheck {
            id: "test_2".to_string(),
            title: "Check nonexistent".to_string(),
            description: String::new(),
            check_type: "file".to_string(),
            params: CheckParams {
                path: Some("/nonexistent/path/xyz".to_string()),
                ..Default::default()
            },
        };
        let result = evaluate_file_check(&check);
        assert_eq!(result.result, CheckStatus::Failed);
    }

    #[tokio::test]
    async fn test_command_check() {
        let check = ScaCheck {
            id: "test_3".to_string(),
            title: "Check uname".to_string(),
            description: String::new(),
            check_type: "command".to_string(),
            params: CheckParams {
                command: Some("echo hello".to_string()),
                pattern: Some("hello".to_string()),
                ..Default::default()
            },
        };
        let result = evaluate_command_check(&check).await;
        assert_eq!(result.result, CheckStatus::Passed);
    }

    #[tokio::test]
    async fn test_evaluate_all() {
        let mut module = ScaModule::new();
        module.load_policy_str(SAMPLE_POLICY).unwrap();

        let (bus, mut server_rx) = EventBus::new(64, 64);

        module.evaluate_all(&bus).await;

        // We should receive 4 ScaResult events on the server channel.
        let mut count = 0;
        while let Ok(Some(event)) =
            tokio::time::timeout(std::time::Duration::from_millis(100), server_rx.recv()).await
        {
            if matches!(event.kind, EventKind::ScaResult { .. }) {
                count += 1;
            }
        }
        assert_eq!(count, 4);
    }
}
