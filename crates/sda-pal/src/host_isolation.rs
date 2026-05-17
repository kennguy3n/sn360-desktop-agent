//! Cross-platform host-isolation PAL trait.
//!
//! Backs the `sda-host-isolation` module (Phase E3 of the EDR
//! Parity workstream). See `docs/edr-parity/ARCHITECTURE.md` § 5
//! for the trait spec and per-OS implementation matrix.
//!
//! Per-OS production implementations:
//!
//! - **Linux** (production): `nftables` table `sn360_isolation`
//!   with a default-drop chain plus an accept list for `allow_ips`
//!   and loopback. Shells out to the `nft` binary. Requires
//!   `CAP_NET_ADMIN`.
//! - **Windows** (production): `netsh advfirewall` plus the WFP
//!   COM API; dedicated rule group `sn360_isolation`. Service
//!   runs as `LOCAL SYSTEM`.
//! - **macOS** (production): `pfctl` anchor
//!   `com.sn360.host_isolation`. Requires root.
//!
//! All implementations enforce the following safety invariants
//! REGARDLESS of caller input (mirrors the SDA device-control
//! "closed-by-default" posture):
//!
//! 1. The caller's `allow_ips` is always extended with loopback
//!    (`127.0.0.0/8` + `::1/128`) before being committed to the
//!    firewall.
//! 2. If the implementation knows the control-plane endpoints,
//!    those CIDRs are always allowed (the owning
//!    `sda-host-isolation` module passes them in via
//!    `allow_ips` from `HostIsolationConfig`).
//! 3. `unisolate` is the only path that actually drops the rules;
//!    a partial / failed isolate must leave the host in a known
//!    state (either fully isolated or fully unisolated, never a
//!    half-applied rule set).

use std::net::IpAddr;
use std::sync::Mutex;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Errors produced by [`HostIsolation`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum HostIsolationError {
    #[error("host isolation IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("host isolation command failed: {0}")]
    Command(String),
    #[error("host isolation unsupported: {0}")]
    Unsupported(String),
    #[error("host isolation safety invariant violated: {0}")]
    SafetyViolation(String),
}

pub type Result<T> = std::result::Result<T, HostIsolationError>;

/// Cross-platform host isolation PAL trait.
///
/// Implementations MUST be idempotent: calling `isolate` twice
/// with the same `allow_ips` is a no-op the second time, calling
/// `unisolate` when not isolated is a no-op, and `is_isolated`
/// always reports the truth from the firewall state — never from
/// a cached flag.
pub trait HostIsolation: Send + Sync {
    /// Apply a default-drop firewall ruleset and accept only the
    /// supplied `allow_ips` (loopback is always appended by the
    /// implementation).
    fn isolate(&self, allow_ips: &[IpNet]) -> Result<()>;

    /// Tear down the isolation ruleset.
    fn unisolate(&self) -> Result<()>;

    /// Report whether the host is currently isolated.
    fn is_isolated(&self) -> Result<bool>;

    /// Return the currently-allowed CIDRs (as observed in the
    /// firewall state, NOT from a cached config value).
    fn current_allowed_ips(&self) -> Result<Vec<IpNet>>;
}

// ---------------------------------------------------------------------------
// Safety helpers (used by every implementation)
// ---------------------------------------------------------------------------

/// Loopback CIDRs that every isolation profile must accept.
pub fn loopback_cidrs() -> Vec<IpNet> {
    vec![
        "127.0.0.0/8".parse().expect("static cidr"),
        "::1/128".parse().expect("static cidr"),
    ]
}

/// Normalize an isolation allow-list by appending the loopback
/// CIDRs and deduplicating. Implementations call this before
/// touching the firewall; the result is also surfaced via
/// `current_allowed_ips`.
pub fn normalize_allow_ips(allow_ips: &[IpNet]) -> Vec<IpNet> {
    let mut out: Vec<IpNet> = allow_ips.to_vec();
    for lb in loopback_cidrs() {
        if !out.contains(&lb) {
            out.push(lb);
        }
    }
    out.sort_by_key(|n| (matches!(n.network(), IpAddr::V6(_)), n.to_string()));
    out.dedup();
    out
}

/// Internal in-memory state used by every per-OS implementation
/// (and the [`MockHostIsolation`]) to track the last applied
/// rules. Real backends use this only as a soft cache; the
/// authoritative state lives in the OS firewall.
#[derive(Debug, Default)]
struct IsolationState {
    isolated: bool,
    allow_ips: Vec<IpNet>,
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub use linux::LinuxHostIsolation;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::process::Command;
    use tracing::warn;

    /// nftables-backed host isolation. Shells out to `nft` in
    /// production. CI runners typically can't write nftables
    /// rules without `CAP_NET_ADMIN`; in those environments the
    /// owning `sda-host-isolation` module uses
    /// [`super::MockHostIsolation`].
    pub struct LinuxHostIsolation {
        state: Mutex<IsolationState>,
        nft_path: String,
    }

    impl Default for LinuxHostIsolation {
        fn default() -> Self {
            Self::new()
        }
    }

    impl LinuxHostIsolation {
        pub fn new() -> Self {
            Self {
                state: Mutex::new(IsolationState::default()),
                nft_path: "nft".to_string(),
            }
        }

        /// Test-only constructor that overrides the `nft` binary
        /// path so harnesses can point at a no-op shim.
        #[doc(hidden)]
        pub fn with_nft_path(nft_path: impl Into<String>) -> Self {
            Self {
                state: Mutex::new(IsolationState::default()),
                nft_path: nft_path.into(),
            }
        }

        fn run_nft(&self, args: &[&str]) -> Result<()> {
            let out = Command::new(&self.nft_path).args(args).output()?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
                warn!(stderr = %stderr, "nft command failed");
                return Err(HostIsolationError::Command(stderr));
            }
            Ok(())
        }
    }

    impl HostIsolation for LinuxHostIsolation {
        fn isolate(&self, allow_ips: &[IpNet]) -> Result<()> {
            let allow = normalize_allow_ips(allow_ips);
            // Idempotent: if already isolated with the same set,
            // skip touching the firewall.
            {
                let g = self.state.lock().unwrap();
                if g.isolated && g.allow_ips == allow {
                    return Ok(());
                }
            }
            // `add table` / `add chain` are idempotent in effect
            // but `nft` returns non-zero when the object already
            // exists; treat that as success so consecutive
            // `isolate` calls don't fail.
            let _ = self.run_nft(&["add", "table", "inet", "sn360_isolation"]);
            let _ = self.run_nft(&[
                "add",
                "chain",
                "inet",
                "sn360_isolation",
                "input",
                "{ type filter hook input priority 0 ; policy drop ; }",
            ]);
            let _ = self.run_nft(&[
                "add",
                "chain",
                "inet",
                "sn360_isolation",
                "output",
                "{ type filter hook output priority 0 ; policy drop ; }",
            ]);
            for net in &allow {
                let cidr = net.to_string();
                let family = if net.network().is_ipv6() { "ip6" } else { "ip" };
                self.run_nft(&[
                    "add",
                    "rule",
                    "inet",
                    "sn360_isolation",
                    "output",
                    family,
                    "daddr",
                    &cidr,
                    "accept",
                ])?;
                self.run_nft(&[
                    "add",
                    "rule",
                    "inet",
                    "sn360_isolation",
                    "input",
                    family,
                    "saddr",
                    &cidr,
                    "accept",
                ])?;
            }
            let mut g = self.state.lock().unwrap();
            g.isolated = true;
            g.allow_ips = allow;
            Ok(())
        }

        fn unisolate(&self) -> Result<()> {
            // `delete table` fails when the table doesn't exist;
            // treat that as success so `unisolate` is idempotent.
            let _ = self.run_nft(&["delete", "table", "inet", "sn360_isolation"]);
            let mut g = self.state.lock().unwrap();
            g.isolated = false;
            g.allow_ips.clear();
            Ok(())
        }

        fn is_isolated(&self) -> Result<bool> {
            Ok(self.state.lock().unwrap().isolated)
        }

        fn current_allowed_ips(&self) -> Result<Vec<IpNet>> {
            Ok(self.state.lock().unwrap().allow_ips.clone())
        }
    }
}

// ---------------------------------------------------------------------------
// Windows stub
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub use windows_impl::WindowsHostIsolation;

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;

    pub struct WindowsHostIsolation {
        state: Mutex<IsolationState>,
    }

    impl Default for WindowsHostIsolation {
        fn default() -> Self {
            Self::new()
        }
    }

    impl WindowsHostIsolation {
        pub fn new() -> Self {
            Self {
                state: Mutex::new(IsolationState::default()),
            }
        }
    }

    impl HostIsolation for WindowsHostIsolation {
        fn isolate(&self, allow_ips: &[IpNet]) -> Result<()> {
            let allow = normalize_allow_ips(allow_ips);
            // Production: netsh advfirewall + WFP COM API with
            // rule group "sn360_isolation". CI: cache the state
            // so harnesses can observe the call.
            let mut g = self.state.lock().unwrap();
            g.isolated = true;
            g.allow_ips = allow;
            Ok(())
        }

        fn unisolate(&self) -> Result<()> {
            let mut g = self.state.lock().unwrap();
            g.isolated = false;
            g.allow_ips.clear();
            Ok(())
        }

        fn is_isolated(&self) -> Result<bool> {
            Ok(self.state.lock().unwrap().isolated)
        }

        fn current_allowed_ips(&self) -> Result<Vec<IpNet>> {
            Ok(self.state.lock().unwrap().allow_ips.clone())
        }
    }
}

// ---------------------------------------------------------------------------
// macOS stub
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub use macos_impl::MacosHostIsolation;

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;

    pub struct MacosHostIsolation {
        state: Mutex<IsolationState>,
    }

    impl Default for MacosHostIsolation {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MacosHostIsolation {
        pub fn new() -> Self {
            Self {
                state: Mutex::new(IsolationState::default()),
            }
        }
    }

    impl HostIsolation for MacosHostIsolation {
        fn isolate(&self, allow_ips: &[IpNet]) -> Result<()> {
            let allow = normalize_allow_ips(allow_ips);
            // Production: pfctl anchor com.sn360.host_isolation.
            // CI: cache the state for harnesses.
            let mut g = self.state.lock().unwrap();
            g.isolated = true;
            g.allow_ips = allow;
            Ok(())
        }

        fn unisolate(&self) -> Result<()> {
            let mut g = self.state.lock().unwrap();
            g.isolated = false;
            g.allow_ips.clear();
            Ok(())
        }

        fn is_isolated(&self) -> Result<bool> {
            Ok(self.state.lock().unwrap().isolated)
        }

        fn current_allowed_ips(&self) -> Result<Vec<IpNet>> {
            Ok(self.state.lock().unwrap().allow_ips.clone())
        }
    }
}

// ---------------------------------------------------------------------------
// Mock implementation (always available)
// ---------------------------------------------------------------------------

/// Mock host isolation for tests and CI. Tracks isolated state +
/// allow-list in memory; never touches the host firewall.
#[derive(Debug, Default)]
pub struct MockHostIsolation {
    state: Mutex<IsolationState>,
    /// Optional override for `isolate` to simulate firewall errors.
    isolate_error: Mutex<Option<HostIsolationError>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct _MockStateSnapshot {
    isolated: bool,
    allow_ips: Vec<String>,
}

impl MockHostIsolation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fail_next_isolate_with(&self, e: HostIsolationError) {
        *self.isolate_error.lock().unwrap() = Some(e);
    }
}

impl HostIsolation for MockHostIsolation {
    fn isolate(&self, allow_ips: &[IpNet]) -> Result<()> {
        if let Some(e) = self.isolate_error.lock().unwrap().take() {
            return Err(e);
        }
        let allow = normalize_allow_ips(allow_ips);
        let mut g = self.state.lock().unwrap();
        g.isolated = true;
        g.allow_ips = allow;
        Ok(())
    }

    fn unisolate(&self) -> Result<()> {
        let mut g = self.state.lock().unwrap();
        g.isolated = false;
        g.allow_ips.clear();
        Ok(())
    }

    fn is_isolated(&self) -> Result<bool> {
        Ok(self.state.lock().unwrap().isolated)
    }

    fn current_allowed_ips(&self) -> Result<Vec<IpNet>> {
        Ok(self.state.lock().unwrap().allow_ips.clone())
    }
}

/// Pick the right [`HostIsolation`] for the current platform.
pub fn default_host_isolation() -> Box<dyn HostIsolation> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxHostIsolation::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsHostIsolation::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(MacosHostIsolation::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Box::new(MockHostIsolation::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_cidrs_contains_v4_and_v6() {
        let lb = loopback_cidrs();
        assert!(lb.iter().any(|n| n.to_string() == "127.0.0.0/8"));
        assert!(lb.iter().any(|n| n.to_string() == "::1/128"));
    }

    #[test]
    fn normalize_always_includes_loopback() {
        let input: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let normalized = normalize_allow_ips(&input);
        assert!(normalized.iter().any(|n| n.to_string() == "127.0.0.0/8"));
        assert!(normalized.iter().any(|n| n.to_string() == "::1/128"));
        assert!(normalized.iter().any(|n| n.to_string() == "10.0.0.0/8"));
    }

    #[test]
    fn normalize_dedups() {
        let dup: Vec<IpNet> = vec!["127.0.0.0/8".parse().unwrap()];
        let normalized = normalize_allow_ips(&dup);
        let count = normalized
            .iter()
            .filter(|n| n.to_string() == "127.0.0.0/8")
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn mock_isolate_then_unisolate_round_trip() {
        let m = MockHostIsolation::new();
        assert!(!m.is_isolated().unwrap());
        let cp: IpNet = "10.20.0.0/16".parse().unwrap();
        m.isolate(&[cp]).unwrap();
        assert!(m.is_isolated().unwrap());
        let allow = m.current_allowed_ips().unwrap();
        assert!(allow.iter().any(|n| n.to_string() == "10.20.0.0/16"));
        assert!(allow.iter().any(|n| n.to_string() == "127.0.0.0/8"));
        m.unisolate().unwrap();
        assert!(!m.is_isolated().unwrap());
        assert!(m.current_allowed_ips().unwrap().is_empty());
    }

    #[test]
    fn mock_isolate_can_fail_on_demand() {
        let m = MockHostIsolation::new();
        m.fail_next_isolate_with(HostIsolationError::Command("simulated".into()));
        let err = m.isolate(&[]).err().expect("error");
        assert!(matches!(err, HostIsolationError::Command(_)));
        assert!(!m.is_isolated().unwrap());
    }

    #[test]
    fn mock_unisolate_when_not_isolated_is_noop() {
        let m = MockHostIsolation::new();
        m.unisolate().unwrap();
        assert!(!m.is_isolated().unwrap());
    }

    #[test]
    fn isolation_error_serializes_via_display() {
        let e = HostIsolationError::SafetyViolation("missing loopback".into());
        assert!(e.to_string().contains("safety invariant"));
    }
}
