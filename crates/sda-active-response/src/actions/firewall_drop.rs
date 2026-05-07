//! Firewall drop action — blocks an IP via platform-native firewall commands.
//!
//! - Linux: `iptables` (IPv4) / `ip6tables` (IPv6)
//! - macOS: `pfctl` with the `sda_blocked` table
//! - Windows: `netsh advfirewall`
//!
//! Both the macOS pfctl table and the Windows firewall rule name were
//! previously prefixed with `WDA` / `wda_`. On unblock, the platform helpers
//! try the current `SDA` / `sda_` identifier first and fall back to the
//! legacy name so that rules created by an earlier version of the agent can
//! still be cleaned up after upgrade.

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use tracing::{debug, info};

use super::{ActionParams, ActionResult, ResponseAction};
use crate::executor;

/// Blocks an IP address using the platform-native firewall.
pub struct FirewallDropAction;

impl Default for FirewallDropAction {
    fn default() -> Self {
        Self
    }
}

impl FirewallDropAction {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ResponseAction for FirewallDropAction {
    fn name(&self) -> &str {
        "block_ip"
    }

    async fn execute(&self, params: &ActionParams, timeout: Duration) -> ActionResult {
        let ip = match &params.ip {
            Some(ip) => ip,
            None => return ActionResult::err("missing 'ip' parameter for block_ip action"),
        };

        if !is_valid_ip(ip) {
            return ActionResult::err(format!("invalid IP address: {}", ip));
        }

        info!(ip, "blocking IP via firewall");

        platform_block_ip(ip, timeout).await
    }

    async fn undo(&self, params: &ActionParams, timeout: Duration) -> ActionResult {
        let ip = match &params.ip {
            Some(ip) => ip,
            None => return ActionResult::err("missing 'ip' parameter for unblock_ip action"),
        };

        if !is_valid_ip(ip) {
            return ActionResult::err(format!("invalid IP address: {}", ip));
        }

        info!(ip, "unblocking IP via firewall");

        platform_unblock_ip(ip, timeout).await
    }
}

/// Validate an IP address (accepts both IPv4 and IPv6).
///
/// Strips a trailing `%<zone_id>` (e.g. `fe80::1%eth0`) before parsing so
/// that link-local IPv6 addresses with a scope ID are accepted.
fn is_valid_ip(ip: &str) -> bool {
    strip_zone_id(ip).parse::<IpAddr>().is_ok()
}

/// Returns `true` when the (zone-stripped) address is IPv6.
fn is_ipv6(ip: &str) -> bool {
    let addr_part = strip_zone_id(ip);
    matches!(addr_part.parse::<IpAddr>(), Ok(IpAddr::V6(_)))
}

/// Strip the `%<zone_id>` suffix from an IPv6 address so the bare address
/// can be passed to firewall commands that do not accept scope IDs.
fn strip_zone_id(ip: &str) -> &str {
    match ip.find('%') {
        Some(idx) => &ip[..idx],
        None => ip,
    }
}

// ── Linux ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn platform_block_ip(ip: &str, timeout: Duration) -> ActionResult {
    let addr = strip_zone_id(ip);
    let cmd = if is_ipv6(ip) { "ip6tables" } else { "iptables" };
    let result = executor::execute_command(
        cmd,
        &["-I", "INPUT", "-s", addr, "-j", "DROP"],
        timeout,
        false,
    )
    .await;

    if result.success {
        debug!(ip, cmd, "IP blocked successfully");
        ActionResult::ok(format!("blocked IP {}", ip))
    } else {
        ActionResult::err(format!(
            "failed to block IP {}: {}",
            ip,
            result.combined_output()
        ))
    }
}

#[cfg(target_os = "linux")]
async fn platform_unblock_ip(ip: &str, timeout: Duration) -> ActionResult {
    let addr = strip_zone_id(ip);
    let cmd = if is_ipv6(ip) { "ip6tables" } else { "iptables" };
    let result = executor::execute_command(
        cmd,
        &["-D", "INPUT", "-s", addr, "-j", "DROP"],
        timeout,
        false,
    )
    .await;

    if result.success {
        ActionResult::ok(format!("unblocked IP {}", ip))
    } else {
        ActionResult::err(format!(
            "failed to unblock IP {}: {}",
            ip,
            result.combined_output()
        ))
    }
}

// ── macOS ────────────────────────────────────────────────────────────────────

/// pfctl table name used by the active-response module on macOS.
#[cfg(target_os = "macos")]
const PFCTL_TABLE: &str = "sda_blocked";

/// Legacy pfctl table name; kept so that `platform_unblock_ip` can still
/// clean up entries inserted by an older agent build that used `wda_blocked`.
#[cfg(target_os = "macos")]
const PFCTL_TABLE_LEGACY: &str = "wda_blocked";

#[cfg(target_os = "macos")]
async fn platform_block_ip(ip: &str, timeout: Duration) -> ActionResult {
    let addr = strip_zone_id(ip);
    let result = executor::execute_command(
        "pfctl",
        &["-t", PFCTL_TABLE, "-T", "add", addr],
        timeout,
        false,
    )
    .await;

    if result.success {
        debug!(ip, "IP blocked via pfctl");
        ActionResult::ok(format!("blocked IP {}", ip))
    } else {
        ActionResult::err(format!(
            "failed to block IP {}: {}",
            ip,
            result.combined_output()
        ))
    }
}

#[cfg(target_os = "macos")]
async fn platform_unblock_ip(ip: &str, timeout: Duration) -> ActionResult {
    let addr = strip_zone_id(ip);
    let result = executor::execute_command(
        "pfctl",
        &["-t", PFCTL_TABLE, "-T", "delete", addr],
        timeout,
        false,
    )
    .await;

    if result.success {
        // Best-effort cleanup of any stale entry in the legacy table so
        // upgrades from a wda_blocked-era agent do not leave orphaned blocks.
        let _ = executor::execute_command(
            "pfctl",
            &["-t", PFCTL_TABLE_LEGACY, "-T", "delete", addr],
            timeout,
            false,
        )
        .await;
        return ActionResult::ok(format!("unblocked IP {}", ip));
    }

    // Current-table delete failed (typically because the entry is not there).
    // Fall back to the legacy table before reporting failure.
    let legacy = executor::execute_command(
        "pfctl",
        &["-t", PFCTL_TABLE_LEGACY, "-T", "delete", addr],
        timeout,
        false,
    )
    .await;

    if legacy.success {
        debug!(ip, "IP unblocked via legacy pfctl table");
        ActionResult::ok(format!("unblocked IP {} (legacy table)", ip))
    } else {
        ActionResult::err(format!(
            "failed to unblock IP {}: {}",
            ip,
            result.combined_output()
        ))
    }
}

// ── Windows ──────────────────────────────────────────────────────────────────

/// Human-readable prefix used for Windows Firewall rule names added by the
/// active-response module. Pre-rename builds of the agent used `"WDA Block "`.
#[cfg(target_os = "windows")]
const WINDOWS_RULE_PREFIX: &str = "SDA Block ";

/// Legacy Windows Firewall rule prefix retained so that `platform_unblock_ip`
/// can still remove rules created by an older build after upgrade.
#[cfg(target_os = "windows")]
const WINDOWS_RULE_PREFIX_LEGACY: &str = "WDA Block ";

#[cfg(target_os = "windows")]
async fn platform_block_ip(ip: &str, timeout: Duration) -> ActionResult {
    let addr = strip_zone_id(ip);
    let rule_name = format!("{}{}", WINDOWS_RULE_PREFIX, addr);
    let result = executor::execute_command(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", rule_name),
            "dir=in",
            "action=block",
            &format!("remoteip={}", addr),
        ],
        timeout,
        false,
    )
    .await;

    if result.success {
        debug!(ip, "IP blocked via netsh");
        ActionResult::ok(format!("blocked IP {}", ip))
    } else {
        ActionResult::err(format!(
            "failed to block IP {}: {}",
            ip,
            result.combined_output()
        ))
    }
}

#[cfg(target_os = "windows")]
async fn platform_unblock_ip(ip: &str, timeout: Duration) -> ActionResult {
    let addr = strip_zone_id(ip);
    let rule_name = format!("{}{}", WINDOWS_RULE_PREFIX, addr);
    let legacy_rule_name = format!("{}{}", WINDOWS_RULE_PREFIX_LEGACY, addr);

    let result = executor::execute_command(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", rule_name),
        ],
        timeout,
        false,
    )
    .await;

    // Always attempt the legacy-name cleanup too so that rules created by
    // pre-rename builds are not orphaned on upgrade. `netsh ... delete rule`
    // with a name that does not exist simply reports "No rules match the
    // specified criteria" and exits non-zero; that outcome is fine here.
    let legacy = executor::execute_command(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", legacy_rule_name),
        ],
        timeout,
        false,
    )
    .await;

    if result.success || legacy.success {
        ActionResult::ok(format!("unblocked IP {}", ip))
    } else {
        ActionResult::err(format!(
            "failed to unblock IP {}: {}",
            ip,
            result.combined_output()
        ))
    }
}

// ── Fallback for unsupported platforms ───────────────────────────────────────

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
async fn platform_block_ip(ip: &str, _timeout: Duration) -> ActionResult {
    ActionResult::err(format!(
        "firewall block not supported on this platform for IP {}",
        ip
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
async fn platform_unblock_ip(ip: &str, _timeout: Duration) -> ActionResult {
    ActionResult::err(format!(
        "firewall unblock not supported on this platform for IP {}",
        ip
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_valid_ipv4() {
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("10.0.0.1"));
        assert!(is_valid_ip("255.255.255.255"));
        assert!(!is_valid_ip("256.1.1.1"));
        assert!(!is_valid_ip("not-an-ip"));
        assert!(!is_valid_ip(""));
    }

    #[test]
    fn test_valid_ipv6() {
        assert!(is_valid_ip("::1"));
        assert!(is_valid_ip("2001:db8::1"));
        assert!(is_valid_ip("fe80::1%eth0"));
        assert!(is_valid_ip("::ffff:192.168.1.1"));
        assert!(is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    }

    #[test]
    fn test_is_ipv6() {
        assert!(!is_ipv6("192.168.1.1"));
        assert!(is_ipv6("::1"));
        assert!(is_ipv6("2001:db8::1"));
        assert!(is_ipv6("fe80::1%eth0"));
    }

    #[tokio::test]
    async fn test_missing_ip_parameter() {
        let action = FirewallDropAction::new();
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
    async fn test_invalid_ip() {
        let action = FirewallDropAction::new();
        let params = ActionParams {
            ip: Some("not-valid".to_string()),
            pid: None,
            user: None,
            timeout: 0,
            extra: HashMap::new(),
        };
        let result = action.execute(&params, Duration::from_secs(5)).await;
        assert!(!result.success);
        assert!(result.output.contains("invalid IP"));
    }

    #[tokio::test]
    async fn test_invalid_ip_undo() {
        let action = FirewallDropAction::new();
        let params = ActionParams {
            ip: Some("garbage".to_string()),
            pid: None,
            user: None,
            timeout: 0,
            extra: HashMap::new(),
        };
        let result = action.undo(&params, Duration::from_secs(5)).await;
        assert!(!result.success);
        assert!(result.output.contains("invalid IP"));
    }
}
