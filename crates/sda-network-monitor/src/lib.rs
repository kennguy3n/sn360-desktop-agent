//! Network + DNS telemetry module (Phase E3 of the EDR Parity workstream).
//!
//! Subscribes to the platform [`sda_pal::network_monitor::NetworkMonitor`]
//! and [`sda_pal::dns_monitor::DnsMonitor`] feeds, deduplicates the
//! cross-snapshot enumerate-established noise, samples high-rate
//! UDP flows, and publishes [`EventKind::NetworkConnection`] and
//! [`EventKind::DnsQuery`] on the shared event bus.
//!
//! Lifecycle mirrors `sda_process_monitor::ProcessMonitorModule`:
//! an `AtomicU8` status, a [`ModuleHandle`] returned from `start()`,
//! and a `tokio::select!` loop driven by a [`ShutdownSignal`].

use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use sda_core::config::{AgentConfig, DnsMonitorConfig, NetworkMonitorConfig};
use sda_core::module::{AgentModule, ModuleHandle, ModuleHealth, ModuleStatus};
use sda_core::signal::ShutdownSignal;
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use sda_pal::dns_monitor::{
    default_dns_monitor, DnsEvent, DnsMonitor, DnsMonitorOpts, DnsQueryType,
};
use sda_pal::network_monitor::{
    default_network_monitor, ConnectionDirection, NetworkEvent, NetworkMonitor, NetworkMonitorOpts,
    TransportProtocol,
};

const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// Module handle returned by [`NetworkMonitorModule::start`].
pub struct NetworkMonitorModule {
    status: Arc<AtomicU8>,
}

impl Default for NetworkMonitorModule {
    fn default() -> Self {
        Self {
            status: Arc::new(AtomicU8::new(STATUS_INITIALIZED)),
        }
    }
}

impl NetworkMonitorModule {
    /// Spawn the network run loop with default PAL implementations.
    pub fn start(config: &AgentConfig, bus: EventBus, shutdown: ShutdownSignal) -> ModuleHandle {
        let cfg = config.modules.network_monitor.clone();
        let mon: Arc<dyn NetworkMonitor> = Arc::from(default_network_monitor());
        Self::start_with_monitor(cfg, mon, bus, shutdown)
    }

    /// Spawn the network run loop with an injected monitor. Used by
    /// E2E tests to plug in
    /// [`sda_pal::network_monitor::MockNetworkMonitor`].
    pub fn start_with_monitor(
        cfg: NetworkMonitorConfig,
        monitor: Arc<dyn NetworkMonitor>,
        bus: EventBus,
        shutdown: ShutdownSignal,
    ) -> ModuleHandle {
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);
        let task = tokio::spawn(async move {
            if let Err(e) = run_network(cfg, monitor, bus, shutdown, task_status.clone()).await {
                error!(error = %e, "network monitor module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });
        ModuleHandle::new("network_monitor", task)
    }
}

impl AgentModule for NetworkMonitorModule {
    fn name(&self) -> &'static str {
        "network_monitor"
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
            STATUS_FAILED => ModuleHealth::Unhealthy,
            _ => ModuleHealth::Healthy,
        }
    }
}

// ---------------------------------------------------------------------------
// DNS monitor module
// ---------------------------------------------------------------------------

/// Module handle returned by [`DnsMonitorModule::start`].
///
/// Owns its own task because the network and DNS event streams are
/// independent — running them in separate tasks lets the module
/// recover gracefully when one PAL fails (e.g. systemd-resolved
/// isn't running but `/proc/net/tcp` parsing still works).
pub struct DnsMonitorModule {
    status: Arc<AtomicU8>,
}

impl Default for DnsMonitorModule {
    fn default() -> Self {
        Self {
            status: Arc::new(AtomicU8::new(STATUS_INITIALIZED)),
        }
    }
}

impl DnsMonitorModule {
    pub fn start(config: &AgentConfig, bus: EventBus, shutdown: ShutdownSignal) -> ModuleHandle {
        let cfg = config.modules.dns_monitor.clone();
        let mon: Arc<dyn DnsMonitor> = Arc::from(default_dns_monitor());
        Self::start_with_monitor(cfg, mon, bus, shutdown)
    }

    pub fn start_with_monitor(
        cfg: DnsMonitorConfig,
        monitor: Arc<dyn DnsMonitor>,
        bus: EventBus,
        shutdown: ShutdownSignal,
    ) -> ModuleHandle {
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);
        let task = tokio::spawn(async move {
            if let Err(e) = run_dns(cfg, monitor, bus, shutdown, task_status.clone()).await {
                error!(error = %e, "dns monitor module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });
        ModuleHandle::new("dns_monitor", task)
    }
}

impl AgentModule for DnsMonitorModule {
    fn name(&self) -> &'static str {
        "dns_monitor"
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
            STATUS_FAILED => ModuleHealth::Unhealthy,
            _ => ModuleHealth::Healthy,
        }
    }
}

// ---------------------------------------------------------------------------
// Wire payload shapes (mirrors `docs/edr.md` § 2.2 — Network telemetry)
// ---------------------------------------------------------------------------

/// Wire-shape of a `NetworkConnection` payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkConnectionPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    pub direction: String,
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub observed_at: String,
}

/// Wire-shape of a `DnsQuery` payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsQueryPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    pub query_name: String,
    pub query_type: String,
    #[serde(default)]
    pub response_ips: Vec<String>,
    pub observed_at: String,
}

// ---------------------------------------------------------------------------
// Internal helpers — dedup ring + sampler
// ---------------------------------------------------------------------------

/// Bounded LRU-ish dedup window. Same shape as the one in
/// `sda-process-monitor` so the agent gets uniform debounce
/// semantics across EDR modules.
#[derive(Debug)]
struct DedupRing {
    seen: VecDeque<u64>,
    capacity: usize,
}

impl DedupRing {
    fn new(capacity: usize) -> Self {
        Self {
            seen: VecDeque::with_capacity(capacity.max(1)),
            capacity: capacity.max(1),
        }
    }

    fn insert(&mut self, key: u64) -> bool {
        if self.seen.iter().any(|k| *k == key) {
            return false;
        }
        if self.seen.len() == self.capacity {
            self.seen.pop_front();
        }
        self.seen.push_back(key);
        true
    }
}

fn connection_dedup_key(ev: &NetworkEvent) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    match ev {
        NetworkEvent::Connect {
            protocol,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            observed_at,
            ..
        } => {
            0u8.hash(&mut hasher);
            protocol.hash(&mut hasher);
            local_addr.hash(&mut hasher);
            local_port.hash(&mut hasher);
            remote_addr.hash(&mut hasher);
            remote_port.hash(&mut hasher);
            (observed_at.timestamp_millis() / 100).hash(&mut hasher);
        }
        NetworkEvent::Disconnect {
            protocol,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            observed_at,
            ..
        } => {
            1u8.hash(&mut hasher);
            protocol.hash(&mut hasher);
            local_addr.hash(&mut hasher);
            local_port.hash(&mut hasher);
            remote_addr.hash(&mut hasher);
            remote_port.hash(&mut hasher);
            (observed_at.timestamp_millis() / 100).hash(&mut hasher);
        }
    }
    hasher.finish()
}

fn dns_dedup_key(ev: &DnsEvent) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    ev.query_name.hash(&mut hasher);
    ev.query_type.hash(&mut hasher);
    (ev.observed_at.timestamp_millis() / 100).hash(&mut hasher);
    hasher.finish()
}

/// High-rate UDP sampler. Tracks per-(local,remote) packet counts
/// per 1-second window and drops any sample beyond the first
/// [`UDP_SAMPLE_PER_SECOND`].
const UDP_SAMPLE_PER_SECOND: u32 = 4;

#[derive(Debug, Default)]
struct UdpSampler {
    /// `(local, remote, second-bucket) → count`. We keep the prior
    /// bucket so flows spanning the boundary still sample.
    buckets: std::collections::HashMap<(IpAddr, u16, IpAddr, u16, i64), u32>,
    seen: HashSet<i64>,
}

impl UdpSampler {
    fn should_sample(&mut self, ev: &NetworkEvent) -> bool {
        let (proto, la, lp, ra, rp, ts) = match ev {
            NetworkEvent::Connect {
                protocol,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                observed_at,
                ..
            } => (
                *protocol,
                *local_addr,
                *local_port,
                *remote_addr,
                *remote_port,
                observed_at.timestamp(),
            ),
            NetworkEvent::Disconnect { .. } => return true,
        };
        if !matches!(proto, TransportProtocol::Udp) {
            return true;
        }
        // Garbage-collect any bucket older than 5s so a long-running
        // module doesn't leak the hash map.
        if self.seen.insert(ts) {
            let cutoff = ts - 5;
            self.buckets.retain(|k, _| k.4 >= cutoff);
            self.seen.retain(|b| *b >= cutoff);
        }
        let key = (la, lp, ra, rp, ts);
        let counter = self.buckets.entry(key).or_insert(0);
        *counter += 1;
        *counter <= UDP_SAMPLE_PER_SECOND
    }
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct NetworkMonitorVitals {
    pub events_emitted: AtomicU64,
    pub duplicates_dropped: AtomicU64,
    pub udp_samples_dropped: AtomicU64,
    pub publish_failures: AtomicU64,
}

#[derive(Debug, Default)]
pub struct DnsMonitorVitals {
    pub events_emitted: AtomicU64,
    pub duplicates_dropped: AtomicU64,
    pub publish_failures: AtomicU64,
}

// ---------------------------------------------------------------------------
// Network run loop
// ---------------------------------------------------------------------------

async fn run_network(
    cfg: NetworkMonitorConfig,
    monitor: Arc<dyn NetworkMonitor>,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    if !cfg.enabled {
        info!("network monitor disabled; module is a no-op");
        status.store(STATUS_RUNNING, Ordering::Relaxed);
        shutdown.wait().await;
        status.store(STATUS_STOPPED, Ordering::Relaxed);
        return Ok(());
    }

    info!(
        outbound = cfg.direction_outbound,
        inbound = cfg.direction_inbound,
        sample_udp = cfg.sample_high_rate_udp,
        buf = cfg.event_buffer_size,
        "network monitor module starting"
    );

    let opts = NetworkMonitorOpts {
        outbound: cfg.direction_outbound,
        inbound: cfg.direction_inbound,
        sample_high_rate_udp: cfg.sample_high_rate_udp,
        channel_buffer: cfg.event_buffer_size,
        poll_interval_ms: 1000,
    };
    let mut stream = match monitor.subscribe(&opts) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "network monitor subscribe failed; module will remain idle");
            status.store(STATUS_FAILED, Ordering::Relaxed);
            shutdown.wait().await;
            return Ok(());
        }
    };

    let vitals = Arc::new(NetworkMonitorVitals::default());
    let mut dedup = DedupRing::new(2048);
    let mut sampler = UdpSampler::default();
    status.store(STATUS_RUNNING, Ordering::Relaxed);

    loop {
        tokio::select! {
            biased;
            _ = shutdown.wait() => {
                info!("network monitor received shutdown signal");
                break;
            }
            ev = stream.recv() => {
                let Some(ev) = ev else {
                    debug!("network monitor stream closed; idling until shutdown");
                    shutdown.wait().await;
                    break;
                };
                let key = connection_dedup_key(&ev);
                if !dedup.insert(key) {
                    vitals.duplicates_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if cfg.sample_high_rate_udp && !sampler.should_sample(&ev) {
                    vitals.udp_samples_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                emit_network_event(ev, &bus, &vitals).await;
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!(
        emitted = vitals.events_emitted.load(Ordering::Relaxed),
        dups = vitals.duplicates_dropped.load(Ordering::Relaxed),
        udp_samples = vitals.udp_samples_dropped.load(Ordering::Relaxed),
        publish_failures = vitals.publish_failures.load(Ordering::Relaxed),
        "network monitor module stopped"
    );
    Ok(())
}

async fn emit_network_event(ev: NetworkEvent, bus: &EventBus, vitals: &Arc<NetworkMonitorVitals>) {
    let (
        direction,
        protocol,
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        observed_at,
        pid,
        name,
    ) = match ev {
        NetworkEvent::Connect {
            direction,
            protocol,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            observed_at,
            pid,
            process_name,
        } => {
            let dir = match direction {
                ConnectionDirection::Inbound => "inbound",
                ConnectionDirection::Outbound => "outbound",
            };
            let proto = match protocol {
                TransportProtocol::Tcp => "tcp",
                TransportProtocol::Udp => "udp",
            };
            (
                dir,
                proto,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                observed_at,
                pid,
                process_name,
            )
        }
        NetworkEvent::Disconnect { .. } => {
            // Disconnect events are tracked internally for stream
            // hygiene but not published as their own NATS event;
            // the schema only carries a single
            // `NetworkConnection` shape.
            return;
        }
    };

    let payload = NetworkConnectionPayload {
        pid,
        process_name: name,
        direction: direction.to_string(),
        protocol: protocol.to_string(),
        local_addr: local_addr.to_string(),
        local_port,
        remote_addr: remote_addr.to_string(),
        remote_port,
        observed_at: observed_at.to_rfc3339(),
    };
    let Ok(payload_str) = serde_json::to_string(&payload) else {
        vitals.publish_failures.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let event = Event::new(
        "network_monitor",
        Priority::Normal,
        EventKind::NetworkConnection {
            payload: payload_str,
        },
    );
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, "network monitor server-bound publish failed");
        vitals.publish_failures.fetch_add(1, Ordering::Relaxed);
    } else {
        vitals.events_emitted.fetch_add(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// DNS run loop
// ---------------------------------------------------------------------------

async fn run_dns(
    cfg: DnsMonitorConfig,
    monitor: Arc<dyn DnsMonitor>,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    if !cfg.enabled {
        info!("dns monitor disabled; module is a no-op");
        status.store(STATUS_RUNNING, Ordering::Relaxed);
        shutdown.wait().await;
        status.store(STATUS_STOPPED, Ordering::Relaxed);
        return Ok(());
    }

    info!(source = %cfg.source, "dns monitor module starting");
    let opts = DnsMonitorOpts::default();
    let mut stream = match monitor.subscribe(&opts) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "dns monitor subscribe failed; module will remain idle");
            status.store(STATUS_FAILED, Ordering::Relaxed);
            shutdown.wait().await;
            return Ok(());
        }
    };

    let vitals = Arc::new(DnsMonitorVitals::default());
    let mut dedup = DedupRing::new(2048);
    status.store(STATUS_RUNNING, Ordering::Relaxed);

    loop {
        tokio::select! {
            biased;
            _ = shutdown.wait() => {
                info!("dns monitor received shutdown signal");
                break;
            }
            ev = stream.recv() => {
                let Some(ev) = ev else {
                    debug!("dns monitor stream closed; idling until shutdown");
                    shutdown.wait().await;
                    break;
                };
                let key = dns_dedup_key(&ev);
                if !dedup.insert(key) {
                    vitals.duplicates_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                emit_dns_event(ev, &bus, &vitals).await;
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!(
        emitted = vitals.events_emitted.load(Ordering::Relaxed),
        dups = vitals.duplicates_dropped.load(Ordering::Relaxed),
        publish_failures = vitals.publish_failures.load(Ordering::Relaxed),
        "dns monitor module stopped"
    );
    Ok(())
}

async fn emit_dns_event(ev: DnsEvent, bus: &EventBus, vitals: &Arc<DnsMonitorVitals>) {
    let qtype = match ev.query_type {
        DnsQueryType::A => "A",
        DnsQueryType::Aaaa => "AAAA",
        DnsQueryType::Cname => "CNAME",
        DnsQueryType::Mx => "MX",
        DnsQueryType::Txt => "TXT",
        DnsQueryType::Ns => "NS",
        DnsQueryType::Ptr => "PTR",
        DnsQueryType::Srv => "SRV",
        DnsQueryType::Soa => "SOA",
        DnsQueryType::Any => "ANY",
        DnsQueryType::Other => "OTHER",
    };
    let payload = DnsQueryPayload {
        pid: ev.pid,
        process_name: ev.process_name,
        query_name: ev.query_name,
        query_type: qtype.to_string(),
        response_ips: ev.response_ips.iter().map(|ip| ip.to_string()).collect(),
        observed_at: ev.observed_at.to_rfc3339(),
    };
    let Ok(payload_str) = serde_json::to_string(&payload) else {
        vitals.publish_failures.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let event = Event::new(
        "dns_monitor",
        Priority::Normal,
        EventKind::DnsQuery {
            payload: payload_str,
        },
    );
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, "dns monitor server-bound publish failed");
        vitals.publish_failures.fetch_add(1, Ordering::Relaxed);
    } else {
        vitals.events_emitted.fetch_add(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sda_core::signal::ShutdownController;
    use sda_pal::dns_monitor::MockDnsMonitor;
    use sda_pal::network_monitor::MockNetworkMonitor;
    use std::net::Ipv4Addr;

    fn enabled_net_cfg() -> NetworkMonitorConfig {
        NetworkMonitorConfig {
            enabled: true,
            direction_outbound: true,
            direction_inbound: true,
            sample_high_rate_udp: true,
            event_buffer_size: 64,
        }
    }

    fn enabled_dns_cfg() -> DnsMonitorConfig {
        DnsMonitorConfig {
            enabled: true,
            source: "auto".to_string(),
        }
    }

    fn connect_event(remote: &str, port: u16) -> NetworkEvent {
        NetworkEvent::Connect {
            observed_at: Utc::now(),
            direction: ConnectionDirection::Outbound,
            protocol: TransportProtocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 49000,
            remote_addr: remote.parse().unwrap(),
            remote_port: port,
            pid: Some(4242),
            process_name: Some("curl".into()),
        }
    }

    #[test]
    fn dedup_ring_drops_repeats() {
        let mut r = DedupRing::new(4);
        assert!(r.insert(1));
        assert!(!r.insert(1));
        assert!(r.insert(2));
    }

    #[test]
    fn connection_dedup_key_stable_within_bucket() {
        let a = connect_event("1.1.1.1", 443);
        let b = a.clone();
        assert_eq!(connection_dedup_key(&a), connection_dedup_key(&b));
    }

    #[test]
    fn network_monitor_config_defaults_match_phase_e3_spec() {
        let cfg = NetworkMonitorConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.direction_outbound);
        assert!(cfg.direction_inbound);
        assert!(cfg.sample_high_rate_udp);
        assert_eq!(cfg.event_buffer_size, 8192);
    }

    #[test]
    fn dns_monitor_config_defaults_match_phase_e3_spec() {
        let cfg = DnsMonitorConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.source, "auto");
    }

    #[tokio::test]
    async fn disabled_network_module_is_a_noop() {
        let mut cfg = enabled_net_cfg();
        cfg.enabled = false;
        let monitor = Arc::new(MockNetworkMonitor::new());
        let (bus, _server_rx) = EventBus::new(16, 16);
        let (controller, shutdown) = ShutdownController::new();
        let mut rx = bus.subscribe();
        let handle = NetworkMonitorModule::start_with_monitor(
            cfg,
            monitor as Arc<dyn NetworkMonitor>,
            bus,
            shutdown,
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        controller.shutdown();
        handle.task.await.unwrap().unwrap();
        while let Ok(Some(ev)) =
            tokio::time::timeout(std::time::Duration::from_millis(10), rx.recv()).await
        {
            assert!(
                !matches!(ev.kind, EventKind::NetworkConnection { .. }),
                "disabled module emitted a network event"
            );
        }
    }

    #[tokio::test]
    async fn connect_event_emits_network_connection_payload() {
        let monitor = Arc::new(MockNetworkMonitor::new());
        monitor.push_event(connect_event("1.1.1.1", 443));

        let (bus, _server_rx) = EventBus::new(16, 16);
        let mut rx = bus.subscribe();
        let (controller, shutdown) = ShutdownController::new();
        let handle = NetworkMonitorModule::start_with_monitor(
            enabled_net_cfg(),
            monitor as Arc<dyn NetworkMonitor>,
            bus,
            shutdown,
        );

        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("event within timeout")
            .expect("bus open");
        let EventKind::NetworkConnection { payload } = ev.kind else {
            panic!("expected NetworkConnection, got {:?}", ev.kind);
        };
        let p: NetworkConnectionPayload = serde_json::from_str(&payload).unwrap();
        assert_eq!(p.remote_addr, "1.1.1.1");
        assert_eq!(p.remote_port, 443);
        assert_eq!(p.direction, "outbound");
        assert_eq!(p.protocol, "tcp");
        assert_eq!(p.pid, Some(4242));
        controller.shutdown();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn duplicate_connect_events_are_collapsed() {
        let monitor = Arc::new(MockNetworkMonitor::new());
        let ev = connect_event("1.1.1.1", 443);
        monitor.push_event(ev.clone());
        monitor.push_event(ev);

        let (bus, _server_rx) = EventBus::new(16, 16);
        let mut rx = bus.subscribe();
        let (controller, shutdown) = ShutdownController::new();
        let handle = NetworkMonitorModule::start_with_monitor(
            enabled_net_cfg(),
            monitor as Arc<dyn NetworkMonitor>,
            bus,
            shutdown,
        );

        let _first = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("first event")
            .expect("bus open");
        // No second event should appear within 200ms.
        let res = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
        assert!(res.is_err(), "duplicate was emitted, expected dedup");
        controller.shutdown();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn dns_query_emits_payload_with_query_name() {
        let monitor = Arc::new(MockDnsMonitor::new());
        monitor.push_event(DnsEvent {
            observed_at: Utc::now(),
            query_name: "evil.example.com".into(),
            query_type: DnsQueryType::A,
            response_ips: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            pid: Some(7777),
            process_name: Some("curl".into()),
        });

        let (bus, _server_rx) = EventBus::new(16, 16);
        let mut rx = bus.subscribe();
        let (controller, shutdown) = ShutdownController::new();
        let handle = DnsMonitorModule::start_with_monitor(
            enabled_dns_cfg(),
            monitor as Arc<dyn DnsMonitor>,
            bus,
            shutdown,
        );

        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("event within timeout")
            .expect("bus open");
        let EventKind::DnsQuery { payload } = ev.kind else {
            panic!("expected DnsQuery, got {:?}", ev.kind);
        };
        let p: DnsQueryPayload = serde_json::from_str(&payload).unwrap();
        assert_eq!(p.query_name, "evil.example.com");
        assert_eq!(p.query_type, "A");
        assert_eq!(p.response_ips, vec!["1.2.3.4"]);
        assert_eq!(p.pid, Some(7777));
        controller.shutdown();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn udp_sampler_drops_burst_above_per_second_cap() {
        let mut sampler = UdpSampler::default();
        let ts = chrono::Utc::now();
        let ev = NetworkEvent::Connect {
            observed_at: ts,
            direction: ConnectionDirection::Outbound,
            protocol: TransportProtocol::Udp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 50000,
            remote_addr: "1.1.1.1".parse().unwrap(),
            remote_port: 5060,
            pid: None,
            process_name: None,
        };
        // First UDP_SAMPLE_PER_SECOND are accepted.
        for _ in 0..UDP_SAMPLE_PER_SECOND {
            assert!(sampler.should_sample(&ev));
        }
        // Past the cap, the same bucket starts dropping.
        assert!(!sampler.should_sample(&ev));
    }

    #[tokio::test]
    async fn udp_sampler_passes_tcp_unchanged() {
        let mut sampler = UdpSampler::default();
        let ev = connect_event("1.1.1.1", 443);
        for _ in 0..16 {
            assert!(sampler.should_sample(&ev));
        }
    }

    #[test]
    fn network_payload_round_trips_via_serde() {
        let p = NetworkConnectionPayload {
            pid: Some(1),
            process_name: Some("x".into()),
            direction: "outbound".into(),
            protocol: "tcp".into(),
            local_addr: "127.0.0.1".into(),
            local_port: 1,
            remote_addr: "1.1.1.1".into(),
            remote_port: 443,
            observed_at: "1970-01-01T00:00:00Z".into(),
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: NetworkConnectionPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(p, back);
    }
}
