//! Phase E3.12 — hermetic end-to-end coverage for the EDR network +
//! DNS telemetry pipeline.
//!
//! This suite stitches together:
//!
//! - `sda-pal::MockNetworkMonitor` / `MockDnsMonitor` (replays a
//!   canned sequence of `NetworkEvent` / `DnsEvent`s),
//! - `sda-network-monitor::NetworkMonitorModule` /
//!   `DnsMonitorModule` (the agent modules under test — performs
//!   dedup, UDP sampling, and publishes canonical-JSON wire
//!   payloads on the bus), and
//! - `sda-local-detection::LocalDetectionModule` (the LDE, which
//!   consumes the new `NetworkConnection` / `DnsQuery` arms in
//!   `handle_event` and surfaces `LocalDetectionAlert` events when
//!   IP / domain IOCs match).
//!
//! All scenarios run on the in-process `EventBus` and finish in tens
//! of milliseconds — `make e2e-network-telemetry` is safe to run on
//! every CI host without privileges.
//!
//! Coverage (≥ 9 tests per `docs/edr-parity/PHASES.md` § E3.12):
//!
//! 1. Network monitor disabled → no `NetworkConnection` events leak.
//! 2. DNS monitor disabled → no `DnsQuery` events leak.
//! 3. `Connect` event surfaces as `EventKind::NetworkConnection`
//!    with the canonical `NetworkConnectionPayload` JSON shape and
//!    PID attribution.
//! 4. Duplicate `Connect` events within the dedup window collapse
//!    to a single bus event.
//! 5. UDP burst above the per-second sampler cap is throttled.
//! 6. `DnsEvent` surfaces as `EventKind::DnsQuery` with the
//!    canonical `DnsQueryPayload` JSON shape.
//! 7. LDE IP IOC matches a `NetworkConnection.remote_addr` and
//!    publishes a `LocalDetectionAlert`.
//! 8. LDE string IOC matches a `DnsQuery.query_name` and publishes
//!    a `LocalDetectionAlert`.
//! 9. LDE does NOT fire when the remote address / query name is
//!    benign (regression for IOC false-positive bound).
//! 10. `NetworkConnectionPayload` survives a JSON round-trip
//!     without loss (regression for serde wire shape).
//! 11. `DnsQueryPayload` survives a JSON round-trip without loss.

#![cfg(unix)]

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use sda_core::config::{DnsMonitorConfig, LocalDetectionConfig, NetworkMonitorConfig};
use sda_core::signal::ShutdownController;
use sda_event_bus::{Event, EventBus, EventKind, EventReceiver};
use sda_local_detection::rule_store::{IocList, IpIoc, RuleBundle, StringIoc, SEV_HIGH};
use sda_local_detection::LocalDetectionModule;
use sda_network_monitor::{
    DnsMonitorModule, DnsQueryPayload, NetworkConnectionPayload, NetworkMonitorModule,
};
use sda_pal::dns_monitor::{DnsEvent, DnsMonitor, DnsQueryType, MockDnsMonitor};
use sda_pal::network_monitor::{
    ConnectionDirection, MockNetworkMonitor, NetworkEvent, NetworkMonitor, TransportProtocol,
};
use tempfile::TempDir;

// ------------------------------------------------------------------ helpers

async fn await_kind<F>(rx: &mut EventReceiver, budget: Duration, predicate: F) -> Option<Event>
where
    F: Fn(&EventKind) -> bool,
{
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(ev)) if predicate(&ev.kind) => return Some(ev),
            Ok(Some(_)) => continue,
            Ok(None) => return None,
            Err(_) => return None,
        }
    }
}

async fn count_kinds<F>(rx: &mut EventReceiver, window: Duration, predicate: F) -> usize
where
    F: Fn(&EventKind) -> bool,
{
    let deadline = tokio::time::Instant::now() + window;
    let mut count = 0;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return count;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(ev)) if predicate(&ev.kind) => count += 1,
            Ok(Some(_)) => continue,
            Ok(None) => return count,
            Err(_) => return count,
        }
    }
}

fn net_cfg(enabled: bool) -> NetworkMonitorConfig {
    NetworkMonitorConfig {
        enabled,
        direction_outbound: true,
        direction_inbound: true,
        sample_high_rate_udp: true,
        event_buffer_size: 64,
    }
}

fn dns_cfg(enabled: bool) -> DnsMonitorConfig {
    DnsMonitorConfig {
        enabled,
        source: "auto".to_string(),
    }
}

fn lde_cfg(tmp: &TempDir) -> LocalDetectionConfig {
    LocalDetectionConfig {
        enabled: true,
        rule_pull_interval: 3600,
        offline_queue_max: 1024,
        yara_scan_rate_limit: 0,
        yara_max_file_size_mb: 16,
        bloom_filter_fpr: 0.01,
        behavioral_max_window_sec: 600,
        behavioral_max_tracked_entities: 256,
        block_ip: false,
        kill_process: false,
        quarantine: false,
        rule_bundle_path: tmp.path().join("bundle.msgpack"),
        offline_queue_path: tmp.path().join("queue.sqlite"),
        quarantine_dir: tmp.path().join("quarantine"),
        offline_drain_interval: 3600,
        offline_drain_batch: 32,
        trds_endpoint: None,
        rule_bundle_signing_keys: Vec::new(),
        trds_pull_timeout_secs: 10,
    }
}

fn agent_config_with(lde: LocalDetectionConfig) -> sda_core::config::AgentConfig {
    let mut cfg = sda_core::config::AgentConfig::default();
    cfg.modules.local_detection = lde;
    cfg
}

fn outbound_tcp_connect(
    pid: Option<u32>,
    process: Option<&str>,
    remote: IpAddr,
    remote_port: u16,
) -> NetworkEvent {
    NetworkEvent::Connect {
        observed_at: Utc::now(),
        direction: ConnectionDirection::Outbound,
        protocol: TransportProtocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 49152,
        remote_addr: remote,
        remote_port,
        pid,
        process_name: process.map(|s| s.to_string()),
    }
}

fn udp_connect_for(remote: IpAddr, port: u16) -> NetworkEvent {
    NetworkEvent::Connect {
        observed_at: Utc::now(),
        direction: ConnectionDirection::Outbound,
        protocol: TransportProtocol::Udp,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 49152,
        remote_addr: remote,
        remote_port: port,
        pid: Some(2222),
        process_name: Some("noisy-udp".to_string()),
    }
}

fn dns_a_event(query_name: &str, response: Ipv4Addr) -> DnsEvent {
    DnsEvent {
        observed_at: Utc::now(),
        query_name: query_name.to_string(),
        query_type: DnsQueryType::A,
        response_ips: vec![IpAddr::V4(response)],
        pid: Some(4242),
        process_name: Some("curl".to_string()),
    }
}

fn save_bundle_with(tmp: &TempDir, iocs: IocList) -> PathBuf {
    let bundle = RuleBundle {
        version: 1,
        generated_at: "2026-05-17T00:00:00Z".into(),
        iocs,
        behavioral: Vec::new(),
        yara_paths: Vec::new(),
    };
    let path = tmp.path().join("bundle.msgpack");
    bundle.save(&path).expect("write bundle");
    path
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn t01_disabled_network_module_emits_no_network_events() {
    let monitor = Arc::new(MockNetworkMonitor::new());
    monitor.push_event(outbound_tcp_connect(
        Some(1),
        Some("leaked"),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        443,
    ));
    let (bus, _server_rx) = EventBus::new(16, 16);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = NetworkMonitorModule::start_with_monitor(
        net_cfg(false),
        monitor as Arc<dyn NetworkMonitor>,
        bus,
        shutdown,
    );

    let leaked = count_kinds(&mut rx, Duration::from_millis(150), |k| {
        matches!(k, EventKind::NetworkConnection { .. })
    })
    .await;
    assert_eq!(leaked, 0, "disabled module leaked {leaked} events");

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t02_disabled_dns_module_emits_no_dns_events() {
    let monitor = Arc::new(MockDnsMonitor::new());
    monitor.push_event(dns_a_event("leaked.example.com", Ipv4Addr::new(1, 1, 1, 1)));
    let (bus, _server_rx) = EventBus::new(16, 16);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = DnsMonitorModule::start_with_monitor(
        dns_cfg(false),
        monitor as Arc<dyn DnsMonitor>,
        bus,
        shutdown,
    );

    let leaked = count_kinds(&mut rx, Duration::from_millis(150), |k| {
        matches!(k, EventKind::DnsQuery { .. })
    })
    .await;
    assert_eq!(leaked, 0, "disabled DNS module leaked {leaked} events");

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t03_connect_event_surfaces_as_network_connection_kind() {
    let monitor = Arc::new(MockNetworkMonitor::new());
    monitor.push_event(outbound_tcp_connect(
        Some(4242),
        Some("curl"),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        443,
    ));
    let (bus, _server_rx) = EventBus::new(16, 16);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = NetworkMonitorModule::start_with_monitor(
        net_cfg(true),
        monitor as Arc<dyn NetworkMonitor>,
        bus,
        shutdown,
    );

    let ev = await_kind(&mut rx, Duration::from_secs(2), |k| {
        matches!(k, EventKind::NetworkConnection { .. })
    })
    .await
    .expect("NetworkConnection within 2s");
    let EventKind::NetworkConnection { payload } = ev.kind else {
        unreachable!()
    };
    let parsed: NetworkConnectionPayload = serde_json::from_str(&payload).unwrap();
    assert_eq!(parsed.pid, Some(4242));
    assert_eq!(parsed.process_name.as_deref(), Some("curl"));
    assert_eq!(parsed.remote_addr, "1.1.1.1");
    assert_eq!(parsed.remote_port, 443);
    assert_eq!(parsed.direction, "outbound");
    assert_eq!(parsed.protocol, "tcp");

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t04_duplicate_connect_events_are_deduplicated() {
    let monitor = Arc::new(MockNetworkMonitor::new());
    let remote = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    // Identical payload + timestamp bucket → dedup ring drops dupes.
    let ts = Utc::now();
    for _ in 0..3 {
        monitor.push_event(NetworkEvent::Connect {
            observed_at: ts,
            direction: ConnectionDirection::Outbound,
            protocol: TransportProtocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 49000,
            remote_addr: remote,
            remote_port: 443,
            pid: Some(7),
            process_name: Some("curl".to_string()),
        });
    }
    let (bus, _server_rx) = EventBus::new(16, 16);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = NetworkMonitorModule::start_with_monitor(
        net_cfg(true),
        monitor as Arc<dyn NetworkMonitor>,
        bus,
        shutdown,
    );

    let n = count_kinds(&mut rx, Duration::from_millis(250), |k| {
        matches!(k, EventKind::NetworkConnection { .. })
    })
    .await;
    assert_eq!(n, 1, "dedup ring should collapse 3 identical Connects to 1");

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t05_udp_burst_throttled_by_per_second_sampler() {
    let monitor = Arc::new(MockNetworkMonitor::new());
    // The sampler cap is 4 per second per (la,lp,ra,rp) tuple; push 8
    // UDP events all in the same second-bucket from the SAME flow and
    // assert at most 4 appear on the bus.  We vary `observed_at` by
    // nanoseconds so the dedup ring (which buckets on
    // `timestamp_millis()/100`) keeps each as a fresh event but the
    // sampler still treats them as one flow.
    let base = Utc::now();
    for i in 0..8 {
        monitor.push_event(NetworkEvent::Connect {
            observed_at: base + chrono::Duration::nanoseconds(i),
            direction: ConnectionDirection::Outbound,
            protocol: TransportProtocol::Udp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 53000,
            remote_addr: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            remote_port: 9999,
            pid: Some(7777),
            process_name: Some("voip".to_string()),
        });
    }
    let (bus, _server_rx) = EventBus::new(32, 32);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = NetworkMonitorModule::start_with_monitor(
        net_cfg(true),
        monitor as Arc<dyn NetworkMonitor>,
        bus,
        shutdown,
    );

    let n = count_kinds(&mut rx, Duration::from_millis(300), |k| {
        matches!(k, EventKind::NetworkConnection { .. })
    })
    .await;
    assert!(
        n <= 4,
        "UDP sampler should cap a single-flow burst at <= 4, saw {n}"
    );
    assert!(n >= 1, "sampler should still let at least one through");

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t06_dns_event_surfaces_as_dns_query_kind() {
    let monitor = Arc::new(MockDnsMonitor::new());
    monitor.push_event(dns_a_event("example.com", Ipv4Addr::new(93, 184, 216, 34)));
    let (bus, _server_rx) = EventBus::new(16, 16);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = DnsMonitorModule::start_with_monitor(
        dns_cfg(true),
        monitor as Arc<dyn DnsMonitor>,
        bus,
        shutdown,
    );

    let ev = await_kind(&mut rx, Duration::from_secs(2), |k| {
        matches!(k, EventKind::DnsQuery { .. })
    })
    .await
    .expect("DnsQuery within 2s");
    let EventKind::DnsQuery { payload } = ev.kind else {
        unreachable!()
    };
    let parsed: DnsQueryPayload = serde_json::from_str(&payload).unwrap();
    assert_eq!(parsed.query_name, "example.com");
    assert_eq!(parsed.query_type, "A");
    assert_eq!(parsed.response_ips, vec!["93.184.216.34".to_string()]);
    assert_eq!(parsed.pid, Some(4242));

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t07_lde_fires_ip_ioc_alert_on_network_connection() {
    let tmp = TempDir::new().unwrap();
    let bad_ip = "203.0.113.7";
    let bundle = IocList {
        strings: Vec::new(),
        hashes: Vec::new(),
        ips: vec![IpIoc {
            id: "ip-bad-c2".into(),
            ip: bad_ip.into(),
            severity: SEV_HIGH.into(),
            description: "Known C2".into(),
        }],
    };
    save_bundle_with(&tmp, bundle);
    let mut cfg = lde_cfg(&tmp);
    cfg.rule_bundle_path = tmp.path().join("bundle.msgpack");
    let agent_config = agent_config_with(cfg);
    let (bus, _server_rx) = EventBus::new(32, 32);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let _lde = LocalDetectionModule::start(&agent_config, bus.clone(), shutdown.clone());

    let monitor = Arc::new(MockNetworkMonitor::new());
    monitor.push_event(outbound_tcp_connect(
        Some(111),
        Some("bad.exe"),
        bad_ip.parse().unwrap(),
        4444,
    ));
    let nm_handle = NetworkMonitorModule::start_with_monitor(
        net_cfg(true),
        monitor as Arc<dyn NetworkMonitor>,
        bus,
        shutdown,
    );

    let alert = await_kind(&mut rx, Duration::from_secs(3), |k| {
        matches!(k, EventKind::LocalDetectionAlert { .. })
    })
    .await;
    assert!(
        alert.is_some(),
        "expected LocalDetectionAlert from IP IOC match"
    );

    controller.shutdown();
    nm_handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t08_lde_fires_string_ioc_alert_on_dns_query() {
    let tmp = TempDir::new().unwrap();
    let bad_domain = "evil.example.com";
    let bundle = IocList {
        strings: vec![StringIoc {
            id: "str-evil-domain".into(),
            value: bad_domain.into(),
            kind: "domain".into(),
            severity: SEV_HIGH.into(),
            description: "Known phishing".into(),
        }],
        hashes: Vec::new(),
        ips: Vec::new(),
    };
    save_bundle_with(&tmp, bundle);
    let mut cfg = lde_cfg(&tmp);
    cfg.rule_bundle_path = tmp.path().join("bundle.msgpack");
    let agent_config = agent_config_with(cfg);
    let (bus, _server_rx) = EventBus::new(32, 32);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let _lde = LocalDetectionModule::start(&agent_config, bus.clone(), shutdown.clone());

    let monitor = Arc::new(MockDnsMonitor::new());
    monitor.push_event(dns_a_event(bad_domain, Ipv4Addr::new(1, 2, 3, 4)));
    let dm_handle = DnsMonitorModule::start_with_monitor(
        dns_cfg(true),
        monitor as Arc<dyn DnsMonitor>,
        bus,
        shutdown,
    );

    let alert = await_kind(&mut rx, Duration::from_secs(3), |k| {
        matches!(k, EventKind::LocalDetectionAlert { .. })
    })
    .await;
    assert!(
        alert.is_some(),
        "expected LocalDetectionAlert from domain IOC match"
    );

    controller.shutdown();
    dm_handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t09_lde_does_not_fire_on_benign_network_or_dns_traffic() {
    let tmp = TempDir::new().unwrap();
    let bundle = IocList {
        strings: vec![StringIoc {
            id: "str-evil-domain".into(),
            value: "evil.example.com".into(),
            kind: "domain".into(),
            severity: SEV_HIGH.into(),
            description: "Known phishing".into(),
        }],
        hashes: Vec::new(),
        ips: vec![IpIoc {
            id: "ip-bad-c2".into(),
            ip: "203.0.113.7".into(),
            severity: SEV_HIGH.into(),
            description: "Known C2".into(),
        }],
    };
    save_bundle_with(&tmp, bundle);
    let mut cfg = lde_cfg(&tmp);
    cfg.rule_bundle_path = tmp.path().join("bundle.msgpack");
    let agent_config = agent_config_with(cfg);
    let (bus, _server_rx) = EventBus::new(32, 32);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let _lde = LocalDetectionModule::start(&agent_config, bus.clone(), shutdown.clone());

    let net = Arc::new(MockNetworkMonitor::new());
    net.push_event(outbound_tcp_connect(
        Some(33),
        Some("ok.exe"),
        // Cloudflare DNS — definitely NOT in the bundle.
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        443,
    ));
    let nm_handle = NetworkMonitorModule::start_with_monitor(
        net_cfg(true),
        net as Arc<dyn NetworkMonitor>,
        bus.clone(),
        shutdown.clone(),
    );

    let dns = Arc::new(MockDnsMonitor::new());
    dns.push_event(dns_a_event("good.example.com", Ipv4Addr::new(8, 8, 8, 8)));
    let dm_handle = DnsMonitorModule::start_with_monitor(
        dns_cfg(true),
        dns as Arc<dyn DnsMonitor>,
        bus,
        shutdown,
    );

    let alert = await_kind(&mut rx, Duration::from_millis(400), |k| {
        matches!(k, EventKind::LocalDetectionAlert { .. })
    })
    .await;
    assert!(
        alert.is_none(),
        "benign network/DNS traffic must not fire LDE alerts"
    );

    controller.shutdown();
    let _ = nm_handle.task.await;
    let _ = dm_handle.task.await;
}

#[tokio::test]
async fn t10_network_connection_payload_round_trips_via_json() {
    let p = NetworkConnectionPayload {
        pid: Some(101),
        process_name: Some("curl".into()),
        direction: "outbound".into(),
        protocol: "tcp".into(),
        local_addr: "127.0.0.1".into(),
        local_port: 49000,
        remote_addr: "1.1.1.1".into(),
        remote_port: 443,
        observed_at: "2026-05-17T00:00:00Z".into(),
    };
    let s = serde_json::to_string(&p).unwrap();
    let back: NetworkConnectionPayload = serde_json::from_str(&s).unwrap();
    assert_eq!(p, back);
}

#[tokio::test]
async fn t11_dns_query_payload_round_trips_via_json() {
    let p = DnsQueryPayload {
        pid: Some(202),
        process_name: Some("curl".into()),
        query_name: "example.com".into(),
        query_type: "A".into(),
        response_ips: vec!["93.184.216.34".into()],
        observed_at: "2026-05-17T00:00:00Z".into(),
    };
    let s = serde_json::to_string(&p).unwrap();
    let back: DnsQueryPayload = serde_json::from_str(&s).unwrap();
    assert_eq!(p, back);
}

#[allow(dead_code)]
fn _unused_keep_imports_in_use() {
    // Silence unused-import warnings on platforms that don't compile
    // every helper.
    let _ = udp_connect_for(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 0);
}
