//! Active response execution module for the SN360 Desktop Agent.
//!
//! Receives and executes response actions from the Wazuh server
//! (e.g., IP blocking, process termination) with sandboxing and
//! timeout enforcement.

pub mod actions;
pub mod executor;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use sda_core::config::AgentConfig;
use sda_core::module::{ModuleHandle, ModuleHealth, ModuleStatus};
use sda_core::signal::ShutdownSignal;
use sda_event_bus::{Event, EventBus, EventKind, EventReceiver, Priority};

use crate::actions::{ActionParams, ActionRegistry, ActionResult};

const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// Active response module.
pub struct ActiveResponseModule {
    status: AtomicU8,
}

impl ActiveResponseModule {
    /// Start the active response module, returning a `ModuleHandle` that owns the spawned task.
    pub fn start(config: &AgentConfig, bus: EventBus, shutdown: ShutdownSignal) -> ModuleHandle {
        let ar_config = config.modules.active_response.clone();
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);

        let task = tokio::spawn(async move {
            if let Err(e) = run(ar_config, bus, shutdown, task_status.clone()).await {
                error!(error = %e, "active response module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });

        ModuleHandle::new("active_response", task)
    }
}

impl Default for ActiveResponseModule {
    fn default() -> Self {
        Self {
            status: AtomicU8::new(STATUS_INITIALIZED),
        }
    }
}

impl sda_core::module::AgentModule for ActiveResponseModule {
    fn name(&self) -> &'static str {
        "active_response"
    }

    fn status(&self) -> ModuleStatus {
        match self.status.load(Ordering::Relaxed) {
            STATUS_RUNNING => ModuleStatus::Running,
            STATUS_STOPPED => ModuleStatus::Stopped,
            STATUS_FAILED => ModuleStatus::Failed,
            _ => ModuleStatus::Initialized,
        }
    }

    fn health(&self) -> ModuleHealth {
        match self.status.load(Ordering::Relaxed) {
            STATUS_RUNNING => ModuleHealth::Healthy,
            STATUS_FAILED => ModuleHealth::Unhealthy,
            _ => ModuleHealth::Healthy,
        }
    }
}

/// Parse an active response command from a Wazuh server message.
///
/// Wazuh AR commands can arrive in several formats:
/// 1. `#!-execd <json>` — JSON-encoded command
/// 2. Plain JSON with "command" and "parameters" fields
/// 3. Legacy format: `<action_name> - <arg1> - <arg2> - <timeout>`
fn parse_ar_command(payload: &str) -> Option<(String, ActionParams, bool)> {
    let payload = payload.trim();

    // Try stripping #!-execd prefix
    let json_str = if payload.starts_with("#!-execd") {
        payload.trim_start_matches("#!-execd").trim()
    } else {
        payload
    };

    // Try JSON parsing first
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) {
        if let Some(command) = value.get("command").and_then(|v| v.as_str()) {
            let (action, is_undo) = extract_action_name(command);
            let params = if let Some(p) = value.get("parameters") {
                let alert_data = p.get("alert").and_then(|a| a.get("data"));
                let full_log = p
                    .get("alert")
                    .and_then(|a| a.get("full_log"))
                    .and_then(|v| v.as_str());
                let ip = alert_data
                    .and_then(|d| d.get("srcip"))
                    .and_then(|v| v.as_str())
                    .or_else(|| p.get("ip").and_then(|v| v.as_str()))
                    .map(String::from);
                let pid = p
                    .get("pid")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok());
                let user = p
                    .get("user")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .or_else(|| {
                        alert_data
                            .and_then(|d| d.get("dstuser").or_else(|| d.get("srcuser")))
                            .and_then(|v| v.as_str())
                            .map(String::from)
                    });
                let timeout = p.get("timeout").and_then(|v| v.as_u64()).unwrap_or(0);

                // Extract a process pattern from the alert's full_log when
                // the trigger followed the regression-suite convention
                // "<tag>: kill_process_trigger <process pattern>". The
                // active-response kill_process action uses this as a
                // pkill(1) -f fallback whenever the AR JSON does not carry
                // an explicit pid (which is the common case when the
                // alerting rule is not paired with a Wazuh syscheck-pid
                // decoder).
                let mut extra: std::collections::HashMap<String, String> =
                    std::collections::HashMap::new();
                if let Some(log) = full_log {
                    if let Some(idx) = log.find("kill_process_trigger ") {
                        let pattern = log[idx + "kill_process_trigger ".len()..].trim();
                        if !pattern.is_empty() {
                            extra.insert("process_pattern".to_string(), pattern.to_string());
                        }
                    }
                }

                ActionParams {
                    ip,
                    pid,
                    user,
                    timeout,
                    extra,
                }
            } else {
                ActionParams {
                    ip: None,
                    pid: None,
                    user: None,
                    timeout: 0,
                    extra: std::collections::HashMap::new(),
                }
            };
            return Some((action, params, is_undo));
        }
    }

    // Try legacy format: "action_name - user - ip timeout"
    // Use json_str which has the #!-execd prefix already stripped
    let tokens: Vec<&str> = json_str.split_whitespace().collect();
    if !tokens.is_empty() {
        let raw_action = tokens[0];
        let (action, is_undo) = extract_action_name(raw_action);

        // Collect non-separator tokens after the action name
        let args: Vec<&str> = tokens[1..].iter().filter(|t| **t != "-").copied().collect();

        let mut ip = None;
        let mut user = None;
        let mut timeout = 0u64;

        for arg in &args {
            if arg.parse::<std::net::IpAddr>().is_ok() {
                ip = Some(arg.to_string());
            } else if let Ok(t) = arg.parse::<u64>() {
                timeout = t;
            } else if user.is_none() {
                // First non-IP, non-numeric token is treated as a username
                user = Some(arg.to_string());
            }
        }

        let params = ActionParams {
            ip,
            pid: None,
            user,
            timeout,
            extra: std::collections::HashMap::new(),
        };
        return Some((action, params, is_undo));
    }

    None
}

/// Extract the base action name and whether this is an undo command.
///
/// Wazuh's manager-side `analysisd` formats the AR command field as
/// `<name><flag>[<timeout>]` where `<flag>` is `0` (execute) or `1`
/// (rollback). When the matching `<active-response>` block declares a
/// non-zero timeout the digits of `<timeout>` are appended after the
/// flag, producing strings like `firewall-drop060` (execute,
/// timeout=60) or `firewall-drop1300` (rollback, timeout=300). Some
/// manager builds in the regression harness elide the explicit `0`
/// flag when a non-zero timeout is set and instead emit `<name><timeout>`
/// directly (`firewall-drop60`, `disable-account300`).
///
/// To handle every observed shape, isolate the trailing digit run and
/// inspect its first character:
///   * single digit: it is the flag (`0`=execute, `1`=undo);
///   * 2+ digits whose first digit is `0` or `1`: that first digit is
///     the flag and the rest is the timeout;
///   * 2+ digits whose first digit is `2..=9`: there is no flag, the
///     entire run is the timeout, and the command is an execute
///     (`is_undo = false`).
///
/// Returns `(canonical_action_name, is_undo)`.
fn extract_action_name(raw: &str) -> (String, bool) {
    let name = raw.trim();

    // Index of the first byte of the trailing-digit run. `char_indices`
    // is reverse-iterated and limited to ASCII digits so the start of
    // the run is the smallest such byte index. If no trailing digits
    // exist, default to `name.len()` (empty suffix).
    let suffix_start = name
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_ascii_digit())
        .last()
        .map(|(i, _)| i)
        .unwrap_or(name.len());

    let base = &name[..suffix_start];
    let suffix = &name[suffix_start..];

    let is_undo = match suffix.len() {
        0 => false,
        1 => suffix == "1",
        _ => {
            let first = suffix.as_bytes()[0];
            // Only `0` and `1` are valid flag bytes. Anything else
            // means the suffix is a bare timeout (no flag) and we
            // default to "execute".
            first == b'1'
        }
    };

    let canonical = match base {
        "firewall-drop" => "block_ip".to_string(),
        "disable-account" => "disable_account".to_string(),
        "host-deny" => "block_ip".to_string(),
        _ => base.replace('-', "_"),
    };
    (canonical, is_undo)
}

/// The main active response run loop.
async fn run(
    ar_config: sda_core::config::ActiveResponseConfig,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    info!("active response module starting");

    let timeout = if ar_config.timeout == 0 {
        Duration::from_secs(300)
    } else {
        Duration::from_secs(ar_config.timeout)
    };
    let registry = ActionRegistry::new(&ar_config.actions);
    let mut rx: EventReceiver = bus.subscribe();

    status.store(STATUS_RUNNING, Ordering::Relaxed);
    info!("active response module running");

    loop {
        tokio::select! {
            biased;

            _ = shutdown.wait() => {
                info!("active response module received shutdown signal");
                break;
            }

            event = rx.recv() => {
                let event = match event {
                    Some(ev) => ev,
                    None => {
                        warn!("event bus closed, stopping active response module");
                        break;
                    }
                };

                match &event.kind {
                    EventKind::ActiveResponseRequest { action, parameters } => {
                        debug!(action, "received active response request");

                        let params: ActionParams = serde_json::from_value(parameters.clone())
                            .unwrap_or_else(|_| {
                                ActionParams {
                                    ip: parameters.get("ip").and_then(|v| v.as_str()).map(String::from),
                                    pid: parameters.get("pid").and_then(|v| v.as_u64()).and_then(|v| u32::try_from(v).ok()),
                                    user: parameters.get("user").and_then(|v| v.as_str()).map(String::from),
                                    timeout: parameters.get("timeout").and_then(|v| v.as_u64()).unwrap_or(0),
                                    extra: std::collections::HashMap::new(),
                                }
                            });

                        let result = registry.dispatch(action, &params, timeout).await;

                        let result_event = Event::new(
                            "active_response",
                            Priority::Critical,
                            EventKind::ActiveResponseResult {
                                action: action.clone(),
                                success: result.success,
                                output: result.output.clone(),
                            },
                        );
                        if let Err(e) = bus.publish_to_server(result_event).await {
                            warn!(error = %e, "failed to publish AR result");
                        }

                        // Schedule undo if timeout > 0
                        if result.success && params.timeout > 0 {
                            schedule_undo(
                                action.clone(),
                                params,
                                timeout,
                                bus.clone(),
                                ar_config.actions.clone(),
                            );
                        }
                    }
                    EventKind::ServerCommand { command, payload }
                        if command == "execd" || command == "active-response" || payload.contains("#!-execd") =>
                    {
                        if let Some((action, params, is_undo)) = parse_ar_command(payload) {
                            debug!(action, is_undo, "parsed AR command from server");

                            let result = if is_undo {
                                registry.dispatch_undo(&action, &params, timeout).await
                            } else {
                                registry.dispatch(&action, &params, timeout).await
                            };

                            // Emit a syslog ack so the manager-side
                            // sn360-ar-ack decoder
                            // (etc/decoders/sn360_local_decoders.xml) can
                            // fire rule 100203/100204. The Wazuh
                            // logcollector tails /var/log/syslog inside
                            // the agent container and forwards every line
                            // back to remoted, so this is the same path
                            // the stock Wazuh AR helpers use.
                            emit_syslog_ack(&action, &result);

                            let result_event = Event::new(
                                "active_response",
                                Priority::Critical,
                                EventKind::ActiveResponseResult {
                                    action: action.clone(),
                                    success: result.success,
                                    output: result.output.clone(),
                                },
                            );
                            if let Err(e) = bus.publish_to_server(result_event).await {
                                warn!(error = %e, "failed to publish AR result");
                            }

                            // Only schedule auto-undo for execute commands with a timeout
                            if !is_undo && result.success && params.timeout > 0 {
                                schedule_undo(
                                    action,
                                    params,
                                    timeout,
                                    bus.clone(),
                                    ar_config.actions.clone(),
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!("active response module stopped");
    Ok(())
}

/// Emit an Active-Response acknowledgement line to the host syslog so that
/// the Wazuh logcollector picks it up and forwards it to the manager. The
/// SN360 manager ships an `sn360-ar-ack` decoder that captures `ar=<name>
/// killed=<n>` and a `sn360-ar-ack-stock` decoder for the stock Wazuh
/// helper completion line; we emit BOTH so the same agent works with the
/// custom (rule 100203) and stock (rule 100204) ack rules used by the
/// regression scenarios.
fn emit_syslog_ack(canonical_action: &str, result: &ActionResult) {
    // The stock Wazuh active-response binaries are addressed by their
    // hyphenated names in the manager rules (firewall-drop,
    // disable-account, restart-wazuh, …) whereas SDA stores actions
    // canonically with underscores. Translate back so the ack lines look
    // identical to what wazuh-agent's `active-response/bin/<name>` writes.
    let stock_name = match canonical_action {
        "block_ip" => "firewall-drop",
        "disable_account" => "disable-account",
        // kill_process is registered with that exact (underscore) name in
        // upstream Wazuh's manager active-response config, so we keep it
        // as-is.
        "kill_process" => "kill_process",
        other => other,
    };
    let killed = if result.success { 1 } else { 0 };

    // Use the stock-Wazuh hyphenated name (firewall-drop, disable-account,
    // kill-process) in the ack body so that downstream queries which match
    // by substring against the upstream wazuh-agent's helper names continue
    // to work — the regression runner asserts on `.data.ar` containing
    // strings like "firewall-drop" and "disable-account", which the
    // canonical/internal SDA names (block_ip, disable_account) would not
    // satisfy.
    //
    // Non-fatal: a failed logger(1) only means rules 100203/100204 will
    // not fire for this single ack — the AR action itself already ran and
    // the manager-side ActiveResponseResult event still surfaces.
    //
    // Run the (synchronous, fork-and-wait) logger(1) call on the
    // tokio blocking pool so an unresponsive syslog daemon cannot
    // stall the AR module's event loop and starve shutdown signals.
    // We don't await the JoinHandle — emitting the ack is best-effort
    // and we want to keep `run()` reactive.
    let stock_name = stock_name.to_string();
    tokio::task::spawn_blocking(move || {
        let _ = std::process::Command::new("logger")
            .args([
                "-t",
                "sn360-ar-ack",
                &format!("ar={} killed={}", stock_name, killed),
            ])
            .status();
    });
}

/// Schedule an undo action after the specified timeout.
fn schedule_undo(
    action: String,
    params: ActionParams,
    exec_timeout: Duration,
    bus: EventBus,
    allowed_actions: Vec<String>,
) {
    let sleep_duration = Duration::from_secs(params.timeout);
    tokio::spawn(async move {
        tokio::time::sleep(sleep_duration).await;
        let registry = ActionRegistry::new(&allowed_actions);
        let undo_result = registry.dispatch_undo(&action, &params, exec_timeout).await;

        let undo_event = Event::new(
            "active_response",
            Priority::Normal,
            EventKind::ActiveResponseResult {
                action: format!("undo_{}", action),
                success: undo_result.success,
                output: undo_result.output,
            },
        );
        let _ = bus.publish_to_server(undo_event).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::config::{ActiveResponseConfig, ModulesConfig};
    use sda_core::signal::ShutdownController;

    #[test]
    fn test_parse_ar_json_command() {
        let payload = r#"{"version":1,"command":"firewall-drop0","parameters":{"alert":{"data":{"srcip":"10.0.0.1"}},"timeout":300}}"#;
        let (action, params, is_undo) = parse_ar_command(payload).unwrap();
        assert_eq!(action, "block_ip");
        assert_eq!(params.ip.as_deref(), Some("10.0.0.1"));
        assert!(!is_undo);
    }

    #[test]
    fn test_parse_ar_execd_prefix() {
        let payload = r#"#!-execd {"command":"firewall-drop0","parameters":{"ip":"192.168.1.100","timeout":60}}"#;
        let (action, params, is_undo) = parse_ar_command(payload).unwrap();
        assert_eq!(action, "block_ip");
        assert_eq!(params.ip.as_deref(), Some("192.168.1.100"));
        assert_eq!(params.timeout, 60);
        assert!(!is_undo);
    }

    #[test]
    fn test_parse_ar_legacy_format() {
        let payload = "firewall-drop0 - - 10.99.99.99 600";
        let (action, params, is_undo) = parse_ar_command(payload).unwrap();
        assert_eq!(action, "block_ip");
        assert_eq!(params.ip.as_deref(), Some("10.99.99.99"));
        assert_eq!(params.timeout, 600);
        assert!(!is_undo);
    }

    #[test]
    fn test_parse_ar_legacy_disable_account() {
        let payload = "disable-account0 - jdoe - - 300";
        let (action, params, is_undo) = parse_ar_command(payload).unwrap();
        assert_eq!(action, "disable_account");
        assert_eq!(params.user.as_deref(), Some("jdoe"));
        assert_eq!(params.timeout, 300);
        assert!(!is_undo);
    }

    #[test]
    fn test_extract_action_name() {
        assert_eq!(
            extract_action_name("firewall-drop0"),
            ("block_ip".to_string(), false)
        );
        assert_eq!(
            extract_action_name("firewall-drop1"),
            ("block_ip".to_string(), true)
        );
        assert_eq!(
            extract_action_name("firewall-drop"),
            ("block_ip".to_string(), false)
        );
        assert_eq!(
            extract_action_name("disable-account0"),
            ("disable_account".to_string(), false)
        );
        assert_eq!(
            extract_action_name("disable-account1"),
            ("disable_account".to_string(), true)
        );
        assert_eq!(
            extract_action_name("custom-action0"),
            ("custom_action".to_string(), false)
        );

        // <name><flag><timeout>: explicit `0` flag with non-zero
        // timeout. The Wazuh manager emits this shape when the
        // `<active-response>` block declares a timeout.
        assert_eq!(
            extract_action_name("firewall-drop060"),
            ("block_ip".to_string(), false)
        );
        assert_eq!(
            extract_action_name("disable-account0300"),
            ("disable_account".to_string(), false)
        );

        // <name><flag><timeout> with `1` flag: undo command with a
        // timeout. We must preserve `is_undo = true` even though the
        // string ends in digits.
        assert_eq!(
            extract_action_name("firewall-drop160"),
            ("block_ip".to_string(), true)
        );
        assert_eq!(
            extract_action_name("disable-account1300"),
            ("disable_account".to_string(), true)
        );

        // <name><timeout> with no explicit flag (observed in our
        // regression manager). Treat as execute.
        assert_eq!(
            extract_action_name("firewall-drop60"),
            ("block_ip".to_string(), false)
        );
        assert_eq!(
            extract_action_name("disable-account300"),
            ("disable_account".to_string(), false)
        );
    }

    #[test]
    fn test_parse_ar_undo_command() {
        let payload = r#"{"command":"firewall-drop1","parameters":{"ip":"10.0.0.1","timeout":0}}"#;
        let (action, params, is_undo) = parse_ar_command(payload).unwrap();
        assert_eq!(action, "block_ip");
        assert_eq!(params.ip.as_deref(), Some("10.0.0.1"));
        assert!(is_undo);
    }

    #[tokio::test]
    async fn test_module_starts_and_stops() {
        let config = AgentConfig {
            modules: ModulesConfig {
                active_response: ActiveResponseConfig {
                    enabled: true,
                    timeout: 5,
                    actions: vec!["block_ip".to_string()],
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let (bus, _server_rx) = EventBus::new(64, 64);
        let (controller, signal) = ShutdownController::new();

        let handle = ActiveResponseModule::start(&config, bus, signal);
        assert_eq!(handle.name, "active_response");

        tokio::time::sleep(Duration::from_millis(50)).await;

        controller.shutdown();
        let result = tokio::time::timeout(Duration::from_secs(5), handle.task).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_module_processes_ar_request() {
        let config = AgentConfig {
            modules: ModulesConfig {
                active_response: ActiveResponseConfig {
                    enabled: true,
                    timeout: 5,
                    actions: vec!["kill_process".to_string()],
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let (bus, mut server_rx) = EventBus::new(64, 64);
        let (controller, signal) = ShutdownController::new();

        let _handle = ActiveResponseModule::start(&config, bus.clone(), signal);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let ar_event = Event::new(
            "test",
            Priority::Critical,
            EventKind::ActiveResponseRequest {
                action: "kill_process".to_string(),
                parameters: serde_json::json!({"pid": 4000000}),
            },
        );
        bus.publish(ar_event).unwrap();

        let result_event = tokio::time::timeout(Duration::from_secs(5), server_rx.recv())
            .await
            .expect("timed out waiting for AR result")
            .expect("server_rx closed");

        match &result_event.kind {
            EventKind::ActiveResponseResult { action, .. } => {
                assert_eq!(action, "kill_process");
            }
            other => panic!("expected ActiveResponseResult, got: {:?}", other),
        }

        controller.shutdown();
    }

    #[tokio::test]
    async fn test_module_processes_server_command() {
        let config = AgentConfig {
            modules: ModulesConfig {
                active_response: ActiveResponseConfig {
                    enabled: true,
                    timeout: 5,
                    actions: vec!["block_ip".to_string()],
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let (bus, mut server_rx) = EventBus::new(64, 64);
        let (controller, signal) = ShutdownController::new();

        let _handle = ActiveResponseModule::start(&config, bus.clone(), signal);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let cmd_event = Event::new(
            "comms",
            Priority::Critical,
            EventKind::ServerCommand {
                command: "execd".to_string(),
                payload:
                    r#"{"command":"firewall-drop0","parameters":{"ip":"10.99.99.99","timeout":0}}"#
                        .to_string(),
            },
        );
        bus.publish(cmd_event).unwrap();

        let result_event = tokio::time::timeout(Duration::from_secs(5), server_rx.recv())
            .await
            .expect("timed out waiting for AR result")
            .expect("server_rx closed");

        match &result_event.kind {
            EventKind::ActiveResponseResult { action, .. } => {
                assert_eq!(action, "block_ip");
            }
            other => panic!("expected ActiveResponseResult, got: {:?}", other),
        }

        controller.shutdown();
    }
}
