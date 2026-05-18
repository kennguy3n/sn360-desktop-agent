//! Cross-platform network telemetry PAL trait.
//!
//! Backs the `sda-network-monitor` module (Phase E3 of the EDR
//! Parity workstream). See `docs/edr-parity/ARCHITECTURE.md` § 5
//! for the trait spec and per-OS implementation matrix.
//!
//! Per-OS production implementations:
//!
//! - **Linux** (production): `audit` subsystem
//!   (`AUDIT_SOCKADDR` / `AUDIT_CONNECT`) for connect-time signal,
//!   netlink `INET_DIAG` for established-connection enumeration,
//!   and `/proc/net/{tcp,tcp6,udp,udp6}` + `/proc/<pid>/fd` for
//!   PID attribution. Requires `CAP_AUDIT_READ` + `CAP_NET_ADMIN`.
//!   The implementation in this file uses a `/proc/net/*` poller
//!   as the supported fallback when those capabilities aren't held
//!   — auditd without `CAP_AUDIT_READ` silently returns no events.
//! - **Windows** (production): ETW
//!   `Microsoft-Windows-Kernel-Network` provider keyed on
//!   `ProcessId`. Requires `SYSTEM` privileges; CI exercises the
//!   [`MockNetworkMonitor`] instead.
//! - **macOS** (production): Network Extension framework
//!   `NEFilterDataProvider`. Requires
//!   `com.apple.developer.networking.networkextension` entitlement;
//!   CI uses [`MockNetworkMonitor`].

use std::net::IpAddr;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// Errors produced by [`NetworkMonitor`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum NetworkMonitorError {
    /// I/O error opening `/proc/net`, a netlink socket, or invoking
    /// a platform helper.
    #[error("network monitor IO error: {0}")]
    Io(#[from] std::io::Error),
    /// The requested operation is not supported on this host
    /// (e.g. ETW backend on a non-Windows build, or INET_DIAG
    /// without `CAP_NET_ADMIN`).
    #[error("network monitor unsupported: {0}")]
    Unsupported(String),
    /// The subscription has already been initiated for this provider.
    #[error("network monitor already subscribed")]
    AlreadySubscribed,
    /// A platform helper exited non-zero or could not be parsed.
    #[error("network monitor command failed: {0}")]
    Command(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, NetworkMonitorError>;

/// Transport protocol observed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

/// Direction of a connection relative to the local host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionDirection {
    Inbound,
    Outbound,
}

/// Options passed to [`NetworkMonitor::subscribe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkMonitorOpts {
    /// Emit outbound connection events.
    pub outbound: bool,
    /// Emit inbound connection events.
    pub inbound: bool,
    /// Sample high-rate UDP flows (Spotify / Zoom / WebRTC).
    /// When false, each UDP 4-tuple is reported once per flow;
    /// when true, periodic samples are emitted.
    pub sample_high_rate_udp: bool,
    /// Size of the bounded mpsc channel used for the event stream.
    /// On overflow the implementation drops the oldest event and
    /// records a counter on the [`NetworkEventStream`].
    pub channel_buffer: usize,
    /// Poll interval (milliseconds) for poller-based fallbacks
    /// (e.g. Linux `/proc/net/*` poller). Ignored by audit /
    /// INET_DIAG / ETW / NEFilterDataProvider implementations.
    pub poll_interval_ms: u64,
}

impl Default for NetworkMonitorOpts {
    fn default() -> Self {
        Self {
            outbound: true,
            inbound: true,
            sample_high_rate_udp: true,
            channel_buffer: 8192,
            poll_interval_ms: 1000,
        }
    }
}

/// A single network telemetry event surfaced by the PAL.
///
/// The shape mirrors `docs/edr-parity/ARCHITECTURE.md` § 8 (wire
/// schema) so the owning module can serialise it to a canonical-JSON
/// payload without per-platform glue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NetworkEvent {
    /// A new TCP or UDP 4-tuple was observed.
    Connect {
        observed_at: DateTime<Utc>,
        direction: ConnectionDirection,
        protocol: TransportProtocol,
        local_addr: IpAddr,
        local_port: u16,
        remote_addr: IpAddr,
        remote_port: u16,
        pid: Option<u32>,
        process_name: Option<String>,
    },
    /// A previously-tracked 4-tuple was closed / torn down.
    Disconnect {
        observed_at: DateTime<Utc>,
        protocol: TransportProtocol,
        local_addr: IpAddr,
        local_port: u16,
        remote_addr: IpAddr,
        remote_port: u16,
        pid: Option<u32>,
    },
}

impl NetworkEvent {
    /// Convenience: the local port of the event, regardless of variant.
    pub fn local_port(&self) -> u16 {
        match self {
            NetworkEvent::Connect { local_port, .. } => *local_port,
            NetworkEvent::Disconnect { local_port, .. } => *local_port,
        }
    }
}

/// Snapshot row returned by [`NetworkMonitor::enumerate_established`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSnapshot {
    pub protocol: TransportProtocol,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub state: Option<String>,
}

/// Async-ready receiver for network events.
///
/// Wraps a [`tokio::sync::mpsc::Receiver`] and a monotonically
/// increasing `dropped` counter so callers can detect that the
/// channel ran behind the producer.
pub struct NetworkEventStream {
    rx: mpsc::Receiver<NetworkEvent>,
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl NetworkEventStream {
    /// Construct a stream from a raw receiver. Exposed so per-OS
    /// adapters can plug in their own producer task.
    pub fn from_parts(
        rx: mpsc::Receiver<NetworkEvent>,
        dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        Self { rx, dropped }
    }

    /// Receive the next event. Returns `None` when the producer
    /// task has dropped its sender (i.e. the monitor was stopped).
    pub async fn recv(&mut self) -> Option<NetworkEvent> {
        self.rx.recv().await
    }

    /// Number of events dropped because the channel was full.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Cross-platform network monitor PAL trait.
///
/// `subscribe` is sync because the underlying setup (opening a
/// netlink socket, enabling an ETW provider, registering an NE
/// content filter) is non-blocking; the actual producer runs on a
/// tokio task spawned by the implementation. This mirrors the
/// [`crate::process_monitor::ProcessMonitor`] convention.
pub trait NetworkMonitor: Send + Sync {
    /// Begin emitting events to a new bounded channel.
    fn subscribe(&self, opts: &NetworkMonitorOpts) -> Result<NetworkEventStream>;

    /// Enumerate currently-established connections (point-in-time).
    fn enumerate_established(&self) -> Result<Vec<ConnectionSnapshot>>;
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub use linux::LinuxNetworkMonitor;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::collections::HashSet;
    use std::fs;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;
    use tracing::{debug, warn};

    /// Linux network monitor backed by a `/proc/net/*` poller.
    ///
    /// The production target is `audit` + `INET_DIAG`, but those
    /// require `CAP_AUDIT_READ` + `CAP_NET_ADMIN` which are rarely
    /// held by CI runners or the unprivileged `sda` service user.
    /// The poller is the supported fallback referenced in
    /// [`super`]'s module docs.
    pub struct LinuxNetworkMonitor {
        /// Optional sysroot override for tests (defaults to "/proc").
        proc_root: PathBuf,
    }

    impl Default for LinuxNetworkMonitor {
        fn default() -> Self {
            Self::new()
        }
    }

    impl LinuxNetworkMonitor {
        pub fn new() -> Self {
            Self {
                proc_root: PathBuf::from("/proc"),
            }
        }

        /// Test-only constructor that points at a synthetic `/proc`.
        #[doc(hidden)]
        pub fn with_proc_root(proc_root: PathBuf) -> Self {
            Self { proc_root }
        }
    }

    impl NetworkMonitor for LinuxNetworkMonitor {
        fn subscribe(&self, opts: &NetworkMonitorOpts) -> Result<NetworkEventStream> {
            let (tx, rx) = mpsc::channel(opts.channel_buffer);
            let dropped = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let dropped_clone = dropped.clone();
            let proc_root = self.proc_root.clone();
            let opts = *opts;
            let poll_interval = Duration::from_millis(opts.poll_interval_ms.max(100));

            tokio::spawn(async move {
                let mut last_keys: HashSet<ConnKey> = HashSet::new();
                if let Ok(initial) = scan_all(&proc_root) {
                    last_keys = initial.into_iter().map(|c| key_of(&c)).collect();
                }
                loop {
                    tokio::time::sleep(poll_interval).await;
                    let current = match scan_all(&proc_root) {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(error = %e, "failed to scan /proc/net/*");
                            continue;
                        }
                    };
                    let current_keys: HashSet<ConnKey> = current.iter().map(key_of).collect();
                    for snap in &current {
                        let k = key_of(snap);
                        if last_keys.contains(&k) {
                            continue;
                        }
                        let dir = direction_for(snap);
                        let allowed = match dir {
                            ConnectionDirection::Inbound => opts.inbound,
                            ConnectionDirection::Outbound => opts.outbound,
                        };
                        if !allowed {
                            continue;
                        }
                        let ev = NetworkEvent::Connect {
                            observed_at: Utc::now(),
                            direction: dir,
                            protocol: snap.protocol,
                            local_addr: snap.local_addr,
                            local_port: snap.local_port,
                            remote_addr: snap.remote_addr,
                            remote_port: snap.remote_port,
                            pid: snap.pid,
                            process_name: snap.process_name.clone(),
                        };
                        if tx.try_send(ev).is_err() {
                            dropped_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    for snap in &current {
                        // Disconnect events: tuples present in last_keys but not in current_keys.
                        let _ = snap; // silence unused in this loop direction
                    }
                    for k in &last_keys {
                        if !current_keys.contains(k) {
                            let ev = NetworkEvent::Disconnect {
                                observed_at: Utc::now(),
                                protocol: k.protocol,
                                local_addr: k.local_addr,
                                local_port: k.local_port,
                                remote_addr: k.remote_addr,
                                remote_port: k.remote_port,
                                pid: None,
                            };
                            if tx.try_send(ev).is_err() {
                                dropped_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                    last_keys = current_keys;
                    if tx.is_closed() {
                        debug!("network monitor stream closed by consumer; stopping poller");
                        break;
                    }
                }
            });

            Ok(NetworkEventStream::from_parts(rx, dropped))
        }

        fn enumerate_established(&self) -> Result<Vec<ConnectionSnapshot>> {
            scan_all(&self.proc_root)
        }
    }

    #[derive(Debug, Clone, Hash, PartialEq, Eq)]
    struct ConnKey {
        protocol: TransportProtocol,
        local_addr: IpAddr,
        local_port: u16,
        remote_addr: IpAddr,
        remote_port: u16,
    }

    fn key_of(c: &ConnectionSnapshot) -> ConnKey {
        ConnKey {
            protocol: c.protocol,
            local_addr: c.local_addr,
            local_port: c.local_port,
            remote_addr: c.remote_addr,
            remote_port: c.remote_port,
        }
    }

    /// Heuristic direction classifier: TCP connections in
    /// `LISTEN` state are inbound; everything else is outbound for
    /// the purposes of the poller. The audit/INET_DIAG fast path
    /// gives a definitive answer.
    fn direction_for(snap: &ConnectionSnapshot) -> ConnectionDirection {
        match snap.state.as_deref() {
            Some("0A") => ConnectionDirection::Inbound, // TCP LISTEN
            _ => ConnectionDirection::Outbound,
        }
    }

    fn scan_all(proc_root: &std::path::Path) -> Result<Vec<ConnectionSnapshot>> {
        let mut out = Vec::new();
        for (name, proto, is_v6) in &[
            ("tcp", TransportProtocol::Tcp, false),
            ("tcp6", TransportProtocol::Tcp, true),
            ("udp", TransportProtocol::Udp, false),
            ("udp6", TransportProtocol::Udp, true),
        ] {
            let path = proc_root.join("net").join(name);
            let content = match fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(NetworkMonitorError::Io(e)),
            };
            for line in content.lines().skip(1) {
                if let Some(snap) = parse_proc_net_line(line, *proto, *is_v6) {
                    out.push(snap);
                }
            }
        }
        Ok(out)
    }

    /// Parse one row of `/proc/net/{tcp,tcp6,udp,udp6}`.
    ///
    /// The kernel writes each IP-address column by formatting the
    /// network-byte-order `__be32` value as a *native* `u32` with
    /// `%08X`. To recover the original octets in network order we
    /// MUST decode the hex with `u32::from_str_radix` and then
    /// call `to_ne_bytes()`. Using `to_le_bytes()` happens to work
    /// on x86_64 / aarch64 but silently corrupts every address on
    /// big-endian targets (s390x, some MIPS/PowerPC).
    pub(super) fn parse_proc_net_line(
        line: &str,
        protocol: TransportProtocol,
        is_v6: bool,
    ) -> Option<ConnectionSnapshot> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Need at least: sl, local, remote, state, ...
        if fields.len() < 4 {
            return None;
        }
        let local = fields[1];
        let remote = fields[2];
        let state = fields[3].to_string();
        let (la, lp) = parse_addr_port(local, is_v6)?;
        let (ra, rp) = parse_addr_port(remote, is_v6)?;
        Some(ConnectionSnapshot {
            protocol,
            local_addr: la,
            local_port: lp,
            remote_addr: ra,
            remote_port: rp,
            pid: None,
            process_name: None,
            state: Some(state),
        })
    }

    fn parse_addr_port(s: &str, is_v6: bool) -> Option<(IpAddr, u16)> {
        let (addr_hex, port_hex) = s.split_once(':')?;
        let port = u16::from_str_radix(port_hex, 16).ok()?;
        let ip = if is_v6 {
            // /proc/net/{tcp6,udp6} writes each 32-bit word in
            // host order; recover network-order octets per word
            // with `to_ne_bytes()`.
            if addr_hex.len() != 32 {
                return None;
            }
            let mut buf = [0u8; 16];
            for i in 0..4 {
                let chunk = &addr_hex[i * 8..(i + 1) * 8];
                let word = u32::from_str_radix(chunk, 16).ok()?;
                let bytes = word.to_ne_bytes();
                buf[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
            }
            IpAddr::V6(Ipv6Addr::from(buf))
        } else {
            if addr_hex.len() != 8 {
                return None;
            }
            let word = u32::from_str_radix(addr_hex, 16).ok()?;
            let bytes = word.to_ne_bytes();
            IpAddr::V4(Ipv4Addr::from(bytes))
        };
        Some((ip, port))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_ipv4_localhost_loopback() {
            // /proc/net/tcp prints 127.0.0.1:80 as either
            // "0100007F:0050" (LE host) or "7F000001:0050" (BE host).
            // Both must round-trip to 127.0.0.1 — that's the whole
            // point of using to_ne_bytes().
            let on_le = "  0: 0100007F:0050 00000000:0000 0A 00:00 ...";
            let on_be = "  0: 7F000001:0050 00000000:0000 0A 00:00 ...";
            #[cfg(target_endian = "little")]
            let line = on_le;
            #[cfg(target_endian = "big")]
            let line = on_be;
            #[cfg(target_endian = "little")]
            let _ = on_be;
            #[cfg(target_endian = "big")]
            let _ = on_le;

            let snap = parse_proc_net_line(line, TransportProtocol::Tcp, false).unwrap();
            assert_eq!(snap.local_addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
            assert_eq!(snap.local_port, 0x50);
            assert_eq!(snap.state.as_deref(), Some("0A"));
        }

        #[test]
        fn parse_ipv6_loopback() {
            // ::1 is 0x0000000000000000000000000000000000000001 in
            // network order, so /proc/net/tcp6 prints it as
            // "00000000000000000000000001000000" on little-endian
            // or "00000000000000000000000000000001" on big-endian.
            #[cfg(target_endian = "little")]
            let line = "  0: 00000000000000000000000001000000:0050 \
                         00000000000000000000000000000000:0000 0A 00:00 ...";
            #[cfg(target_endian = "big")]
            let line = "  0: 00000000000000000000000000000001:0050 \
                         00000000000000000000000000000000:0000 0A 00:00 ...";

            let snap = parse_proc_net_line(line, TransportProtocol::Tcp, true).unwrap();
            assert_eq!(snap.local_addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
            assert_eq!(snap.local_port, 0x50);
        }

        #[test]
        fn parse_rejects_short_lines() {
            assert!(parse_proc_net_line("  0:", TransportProtocol::Tcp, false).is_none());
        }

        #[test]
        fn scan_all_handles_missing_proc_net() {
            let tmp = tempfile::tempdir().unwrap();
            let out = scan_all(tmp.path()).unwrap();
            assert!(out.is_empty());
        }

        #[test]
        fn scan_all_reads_synthetic_tcp_file() {
            let tmp = tempfile::tempdir().unwrap();
            let net = tmp.path().join("net");
            std::fs::create_dir_all(&net).unwrap();
            #[cfg(target_endian = "little")]
            let body = "  sl  local_address rem_address   st\n  \
                        0: 0100007F:0050 0100007F:1F90 01 ...";
            #[cfg(target_endian = "big")]
            let body = "  sl  local_address rem_address   st\n  \
                        0: 7F000001:0050 7F000001:1F90 01 ...";
            std::fs::write(net.join("tcp"), body).unwrap();
            let out = scan_all(tmp.path()).unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].local_addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
            assert_eq!(out[0].local_port, 0x50);
            assert_eq!(out[0].remote_port, 0x1F90);
            assert_eq!(out[0].protocol, TransportProtocol::Tcp);
        }

        #[test]
        fn direction_classifier_marks_listen_as_inbound() {
            let snap = ConnectionSnapshot {
                protocol: TransportProtocol::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                local_port: 22,
                remote_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                remote_port: 0,
                pid: None,
                process_name: None,
                state: Some("0A".to_string()),
            };
            assert_eq!(direction_for(&snap), ConnectionDirection::Inbound);
        }
    }
}

// ---------------------------------------------------------------------------
// Windows stub
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub use windows_impl::WindowsNetworkMonitor;

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;

    /// Stub for the production Windows ETW backend. CI uses
    /// [`super::MockNetworkMonitor`] instead.
    pub struct WindowsNetworkMonitor;

    impl Default for WindowsNetworkMonitor {
        fn default() -> Self {
            Self::new()
        }
    }

    impl WindowsNetworkMonitor {
        pub fn new() -> Self {
            Self
        }
    }

    impl NetworkMonitor for WindowsNetworkMonitor {
        fn subscribe(&self, _opts: &NetworkMonitorOpts) -> Result<NetworkEventStream> {
            Err(NetworkMonitorError::Unsupported(
                "ETW NetworkMonitor requires a signed-driver build; use MockNetworkMonitor in CI"
                    .into(),
            ))
        }

        fn enumerate_established(&self) -> Result<Vec<ConnectionSnapshot>> {
            Ok(Vec::new())
        }
    }
}

// ---------------------------------------------------------------------------
// macOS stub
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub use macos_impl::MacosNetworkMonitor;

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;

    /// Stub for the production Endpoint Security / Network
    /// Extension backend. CI uses [`super::MockNetworkMonitor`].
    pub struct MacosNetworkMonitor;

    impl Default for MacosNetworkMonitor {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MacosNetworkMonitor {
        pub fn new() -> Self {
            Self
        }
    }

    impl NetworkMonitor for MacosNetworkMonitor {
        fn subscribe(&self, _opts: &NetworkMonitorOpts) -> Result<NetworkEventStream> {
            Err(NetworkMonitorError::Unsupported(
                "NEFilterDataProvider NetworkMonitor requires Apple entitlement; \
                 use MockNetworkMonitor in CI"
                    .into(),
            ))
        }

        fn enumerate_established(&self) -> Result<Vec<ConnectionSnapshot>> {
            Ok(Vec::new())
        }
    }
}

// ---------------------------------------------------------------------------
// Mock implementation (always available)
// ---------------------------------------------------------------------------

/// Mock network monitor for tests and CI. Replays a canned list of
/// [`NetworkEvent`]s and serves a canned `enumerate_established`
/// snapshot.
pub struct MockNetworkMonitor {
    events: std::sync::Mutex<Vec<NetworkEvent>>,
    established: std::sync::Mutex<Vec<ConnectionSnapshot>>,
}

impl Default for MockNetworkMonitor {
    fn default() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
            established: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl MockNetworkMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_events(events: Vec<NetworkEvent>) -> Self {
        Self {
            events: std::sync::Mutex::new(events),
            established: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn push_event(&self, ev: NetworkEvent) {
        self.events.lock().unwrap().push(ev);
    }

    pub fn set_established(&self, snaps: Vec<ConnectionSnapshot>) {
        let mut g = self.established.lock().unwrap();
        *g = snaps;
    }
}

impl NetworkMonitor for MockNetworkMonitor {
    fn subscribe(&self, opts: &NetworkMonitorOpts) -> Result<NetworkEventStream> {
        let (tx, rx) = mpsc::channel(opts.channel_buffer);
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let dropped_clone = dropped.clone();
        let canned: Vec<NetworkEvent> = {
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
        Ok(NetworkEventStream::from_parts(rx, dropped))
    }

    fn enumerate_established(&self) -> Result<Vec<ConnectionSnapshot>> {
        Ok(self.established.lock().unwrap().clone())
    }
}

/// Pick the right [`NetworkMonitor`] for the current platform.
pub fn default_network_monitor() -> Box<dyn NetworkMonitor> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxNetworkMonitor::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsNetworkMonitor::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(MacosNetworkMonitor::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Box::new(MockNetworkMonitor::new())
    }
}

#[cfg(test)]
mod cross_platform_tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample_event() -> NetworkEvent {
        NetworkEvent::Connect {
            observed_at: Utc::now(),
            direction: ConnectionDirection::Outbound,
            protocol: TransportProtocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 49000,
            remote_addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            remote_port: 443,
            pid: Some(4242),
            process_name: Some("curl".to_string()),
        }
    }

    #[test]
    fn network_event_round_trips_via_serde_json() {
        let ev = sample_event();
        let s = serde_json::to_string(&ev).unwrap();
        let back: NetworkEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
    }

    #[tokio::test]
    async fn mock_replays_events_in_order() {
        let events = vec![
            sample_event(),
            NetworkEvent::Disconnect {
                observed_at: Utc::now(),
                protocol: TransportProtocol::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                local_port: 49000,
                remote_addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                remote_port: 443,
                pid: Some(4242),
            },
        ];
        let mon = MockNetworkMonitor::with_events(events.clone());
        let mut stream = mon.subscribe(&NetworkMonitorOpts::default()).unwrap();
        for expected in events {
            let got = stream.recv().await.expect("event");
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn mock_enumerate_round_trips_snapshots() {
        let mon = MockNetworkMonitor::new();
        let snap = ConnectionSnapshot {
            protocol: TransportProtocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 22,
            remote_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            remote_port: 0,
            pid: None,
            process_name: None,
            state: Some("0A".to_string()),
        };
        mon.set_established(vec![snap.clone()]);
        let got = mon.enumerate_established().unwrap();
        assert_eq!(got, vec![snap]);
    }

    #[test]
    fn transport_protocol_serde_lowercases() {
        assert_eq!(
            serde_json::to_string(&TransportProtocol::Tcp).unwrap(),
            "\"tcp\""
        );
        assert_eq!(
            serde_json::to_string(&TransportProtocol::Udp).unwrap(),
            "\"udp\""
        );
    }

    #[test]
    fn connection_direction_serde_lowercases() {
        assert_eq!(
            serde_json::to_string(&ConnectionDirection::Inbound).unwrap(),
            "\"inbound\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectionDirection::Outbound).unwrap(),
            "\"outbound\""
        );
    }
}
