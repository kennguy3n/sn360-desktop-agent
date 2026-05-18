//! Cross-platform DNS telemetry PAL trait.
//!
//! Backs the DNS half of the `sda-network-monitor` module
//! (Phase E3 of the EDR Parity workstream). See
//! `docs/architecture.md` § 4 (Platform abstraction layer) for the
//! trait spec and per-OS implementation matrix.
//!
//! Per-OS production implementations:
//!
//! - **Linux** (production): tap `journalctl -u systemd-resolved`
//!   for `QUESTIONS` / `ANSWERS` lines, or eBPF on `udp_sendmsg`
//!   for kernel ≥ 5.8. CI exercises the [`MockDnsMonitor`].
//! - **Windows** (production): ETW
//!   `Microsoft-Windows-DNS-Client`. Requires `SYSTEM`. CI uses
//!   [`MockDnsMonitor`].
//! - **macOS** (production): `NEDNSProxyProvider` or `dns_sd`.
//!   Requires the
//!   `com.apple.developer.networking.networkextension` (DNS proxy)
//!   entitlement. CI uses [`MockDnsMonitor`].

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// Errors produced by [`DnsMonitor`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum DnsMonitorError {
    #[error("dns monitor IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("dns monitor unsupported: {0}")]
    Unsupported(String),
    #[error("dns monitor already subscribed")]
    AlreadySubscribed,
}

pub type Result<T> = std::result::Result<T, DnsMonitorError>;

/// DNS RR-type subset surfaced by the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsQueryType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Ns,
    Ptr,
    Srv,
    Soa,
    Any,
    Other,
}

/// Options passed to [`DnsMonitor::subscribe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsMonitorOpts {
    /// Size of the bounded mpsc channel used for the event stream.
    pub channel_buffer: usize,
    /// Poll interval for journald / log-tail based fallbacks
    /// (milliseconds). Ignored by ETW / NEDNSProxyProvider /
    /// eBPF implementations.
    pub poll_interval_ms: u64,
}

impl Default for DnsMonitorOpts {
    fn default() -> Self {
        Self {
            channel_buffer: 4096,
            poll_interval_ms: 1000,
        }
    }
}

/// A single DNS query observation.
///
/// The shape mirrors the wire schema described in
/// `docs/edr.md` § 2.2 (Network telemetry) and serialised per
/// `docs/architecture.md` § 6 (Wire protocols).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsEvent {
    pub observed_at: DateTime<Utc>,
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub response_ips: Vec<IpAddr>,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

/// Async-ready receiver for DNS events.
pub struct DnsEventStream {
    rx: mpsc::Receiver<DnsEvent>,
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl DnsEventStream {
    pub fn from_parts(
        rx: mpsc::Receiver<DnsEvent>,
        dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        Self { rx, dropped }
    }

    pub async fn recv(&mut self) -> Option<DnsEvent> {
        self.rx.recv().await
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Cross-platform DNS monitor PAL trait.
pub trait DnsMonitor: Send + Sync {
    /// Begin emitting DNS observations to a new bounded channel.
    fn subscribe(&self, opts: &DnsMonitorOpts) -> Result<DnsEventStream>;
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub use linux::LinuxDnsMonitor;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    /// Stub for the production `journalctl -u systemd-resolved`
    /// tap / eBPF `udp_sendmsg` probe. Both backends require
    /// elevated privileges and a running resolver — neither is
    /// guaranteed in CI runners, so the supported behaviour here
    /// is to return `Unsupported` and let the owning module fall
    /// back to the [`super::MockDnsMonitor`] when configured.
    pub struct LinuxDnsMonitor;

    impl Default for LinuxDnsMonitor {
        fn default() -> Self {
            Self::new()
        }
    }

    impl LinuxDnsMonitor {
        pub fn new() -> Self {
            Self
        }
    }

    impl DnsMonitor for LinuxDnsMonitor {
        fn subscribe(&self, _opts: &DnsMonitorOpts) -> Result<DnsEventStream> {
            Err(DnsMonitorError::Unsupported(
                "Linux DnsMonitor requires journalctl/systemd-resolved or an eBPF \
                 probe; use MockDnsMonitor in CI"
                    .into(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Windows stub
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub use windows_impl::WindowsDnsMonitor;

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;

    pub struct WindowsDnsMonitor;

    impl Default for WindowsDnsMonitor {
        fn default() -> Self {
            Self::new()
        }
    }

    impl WindowsDnsMonitor {
        pub fn new() -> Self {
            Self
        }
    }

    impl DnsMonitor for WindowsDnsMonitor {
        fn subscribe(&self, _opts: &DnsMonitorOpts) -> Result<DnsEventStream> {
            Err(DnsMonitorError::Unsupported(
                "ETW DnsMonitor requires SYSTEM; use MockDnsMonitor in CI".into(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// macOS stub
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub use macos_impl::MacosDnsMonitor;

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;

    pub struct MacosDnsMonitor;

    impl Default for MacosDnsMonitor {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MacosDnsMonitor {
        pub fn new() -> Self {
            Self
        }
    }

    impl DnsMonitor for MacosDnsMonitor {
        fn subscribe(&self, _opts: &DnsMonitorOpts) -> Result<DnsEventStream> {
            Err(DnsMonitorError::Unsupported(
                "NEDNSProxyProvider DnsMonitor requires entitlement; use \
                 MockDnsMonitor in CI"
                    .into(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Mock implementation (always available)
// ---------------------------------------------------------------------------

/// Mock DNS monitor for tests and CI.
pub struct MockDnsMonitor {
    events: std::sync::Mutex<Vec<DnsEvent>>,
}

impl Default for MockDnsMonitor {
    fn default() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl MockDnsMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_events(events: Vec<DnsEvent>) -> Self {
        Self {
            events: std::sync::Mutex::new(events),
        }
    }

    pub fn push_event(&self, ev: DnsEvent) {
        self.events.lock().unwrap().push(ev);
    }
}

impl DnsMonitor for MockDnsMonitor {
    fn subscribe(&self, opts: &DnsMonitorOpts) -> Result<DnsEventStream> {
        let (tx, rx) = mpsc::channel(opts.channel_buffer);
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let dropped_clone = dropped.clone();
        let canned: Vec<DnsEvent> = {
            let g = self.events.lock().unwrap();
            g.clone()
        };
        tokio::spawn(async move {
            for ev in canned {
                if tx.send(ev).await.is_err() {
                    dropped_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
            }
        });
        Ok(DnsEventStream::from_parts(rx, dropped))
    }
}

/// Pick the right [`DnsMonitor`] for the current platform.
///
/// On every supported OS the production backend requires elevated
/// privileges, so the default constructor returns the platform
/// stub — owning modules can override with [`MockDnsMonitor`] for
/// tests and unprivileged operation.
pub fn default_dns_monitor() -> Box<dyn DnsMonitor> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxDnsMonitor::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsDnsMonitor::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(MacosDnsMonitor::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Box::new(MockDnsMonitor::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample_event(name: &str) -> DnsEvent {
        DnsEvent {
            observed_at: Utc::now(),
            query_name: name.to_string(),
            query_type: DnsQueryType::A,
            response_ips: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            pid: Some(4242),
            process_name: Some("curl".to_string()),
        }
    }

    #[test]
    fn dns_event_round_trips_via_serde_json() {
        let ev = sample_event("example.com");
        let s = serde_json::to_string(&ev).unwrap();
        let back: DnsEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn dns_query_type_serde_is_uppercase() {
        assert_eq!(serde_json::to_string(&DnsQueryType::A).unwrap(), "\"A\"");
        assert_eq!(
            serde_json::to_string(&DnsQueryType::Aaaa).unwrap(),
            "\"AAAA\""
        );
    }

    #[tokio::test]
    async fn mock_replays_events_in_order() {
        let events = vec![sample_event("a.example"), sample_event("b.example")];
        let mon = MockDnsMonitor::with_events(events.clone());
        let mut stream = mon.subscribe(&DnsMonitorOpts::default()).unwrap();
        for expected in events {
            let got = stream.recv().await.expect("event");
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn dns_monitor_opts_default_buffer_is_non_zero() {
        assert!(DnsMonitorOpts::default().channel_buffer > 0);
    }
}
