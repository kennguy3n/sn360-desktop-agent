//! SN360 Desktop Agent — binary entry point.
//!
//! Orchestrates startup, enrollment, server connection, keepalive,
//! and graceful shutdown of the agent.
//!
//! The legacy SIEM (Wazuh-compatible) transport — enrollment,
//! connection, keepalive, event forwarding, server-receive, and the
//! shutdown message — is gated behind the `legacy-siem` Cargo
//! feature. When the feature is disabled the agent still starts all
//! local modules (FIM, LogCollector, Inventory, SCA, Rootcheck, LDE,
//! Enhanced Inventory, Active Response, Updater) but does not open
//! any outbound connection. A native SN360 transport will replace
//! the legacy path in a follow-up.

mod privilege;
mod tamper;

#[cfg(feature = "legacy-siem")]
use std::sync::Arc;
#[cfg(feature = "legacy-siem")]
use std::time::Duration;

use anyhow::{Context, Result};
#[cfg(feature = "legacy-siem")]
use tokio::sync::Mutex;
#[cfg(feature = "legacy-siem")]
use tracing::error;
use tracing::{info, warn};

#[cfg(feature = "legacy-siem")]
use sda_comms::connection::{ConnectionConfig, ConnectionManager, TransportProtocol};
#[cfg(feature = "legacy-siem")]
use sda_comms::crypto::WazuhCipher;
#[cfg(feature = "legacy-siem")]
use sda_comms::enrollment::{load_agent_key, save_agent_key, EnrollmentClient};
#[cfg(feature = "legacy-siem")]
use sda_comms::keepalive::run_keepalive_loop;
#[cfg(feature = "legacy-siem")]
use sda_comms::protocol::{MessageType, WazuhMessage};
use sda_core::config::AgentConfig;
use sda_core::power::{self, PowerProfile};
use sda_core::Agent;
#[cfg(feature = "legacy-siem")]
use sda_event_bus::{Event, EventKind, Priority};

#[tokio::main]
async fn main() -> Result<()> {
    // 0. Handle short-circuit CLI flags before any heavy init.
    //    `--version` is consumed by the self-update smoke test to
    //    confirm a freshly-installed binary runs.
    if let Some(code) = handle_short_flags(std::env::args()) {
        std::process::exit(code);
    }

    // 1. Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("wazuh desktop agent starting");

    // 2. Load configuration (from CLI arg or default path)
    let mut config = match first_positional_arg(std::env::args()) {
        Some(path) => AgentConfig::from_yaml_file(std::path::Path::new(&path))
            .context("failed to load config from provided path")?,
        None => AgentConfig::load_default().context("failed to load default config")?,
    };

    // 2a. Wire the enhanced-inventory -> device-control bridge.
    //     See `apply_device_control_bridge` for the rationale.
    apply_device_control_bridge(&mut config);

    // 2b. Startup tamper protection (P3.3): self-integrity check + best-effort
    // file immutability. Runs before any network I/O so a tampered binary
    // never gets a chance to enroll or connect.
    tamper::apply_startup_protections(&config.security.tamper)
        .context("tamper-protection startup check failed")?;

    // 3. Create the agent
    let mut agent = Agent::new(config.clone());

    // 4. Check for existing agent key; enroll if missing.
    //    Enrolment talks to the legacy SIEM `authd` protocol; when the
    //    `legacy-siem` feature is disabled we skip this entire phase.
    #[cfg(feature = "legacy-siem")]
    let (agent_key, _fresh_enrollment) = {
        let keys_file_override = config.enrollment.keys_file.as_deref();
        let mut fresh_enrollment = false;
        let agent_key = match load_agent_key(keys_file_override) {
            Some(key) => {
                info!(agent_id = %key.id, "loaded existing agent key");
                key
            }
            None => {
                info!("no agent key found, enrolling with server");
                let agent_name = config
                    .enrollment
                    .agent_name
                    .clone()
                    .unwrap_or_else(gethostname);

                let mut client = EnrollmentClient::new(
                    config.enrollment_address(),
                    config.enrollment.port,
                    &agent_name,
                );

                if let Some(ref password) = config.enrollment.key {
                    client = client.with_password(password);
                }
                if let Some(ref groups) = config.enrollment.groups {
                    client = client.with_groups(groups.clone());
                }

                let key = client.enroll().await.context("enrollment failed")?;

                // 5. Save the key
                save_agent_key(&key, keys_file_override).context("failed to save agent key")?;
                info!(agent_id = %key.id, "enrollment complete, key saved");
                fresh_enrollment = true;
                key
            }
        };

        agent.set_agent_id(agent_key.id.clone());
        agent.set_agent_key(agent_key.key.clone());

        // 5b. After fresh enrollment, wait for Wazuh remoted to reload
        //     client.keys.  Remoted detects the file change every ~10 s; if we
        //     connect before it reloads, our startup message is rejected with
        //     "Invalid ID" and the TCP connection is reset.
        if fresh_enrollment {
            info!("waiting 15 s for remoted to load new agent key");
            tokio::time::sleep(Duration::from_secs(15)).await;
        }

        (agent_key, fresh_enrollment)
    };

    #[cfg(not(feature = "legacy-siem"))]
    {
        info!("legacy-siem feature disabled: skipping enrolment and server transport");
        // Drop the server-bound receiver so publish_to_server() callers
        // get TrySendError::Closed immediately instead of buffering
        // 1024 events that nobody consumes.
        let _ = agent.take_server_rx();
    }

    // 5d. Cloud-config pull: fetch the full tier-appropriate module
    //     config from the Agent Gateway and merge it into local config.
    //     The bootstrap agent.yaml only has `tenant_gateway` +
    //     `bootstrap_token_file`; the cloud config provides every
    //     module toggle and platform endpoint URL.
    if let Some(ref gw) = config.agent.tenant_gateway {
        match pull_cloud_config(gw).await {
            Ok(cloud) => {
                // Store the enrolled identity so downstream modules
                // (host isolation, device control, MDM) can use it.
                if cloud.tenant_id.is_some() {
                    config.agent.tenant_id = cloud.tenant_id;
                }
                if cloud.device_id.is_some() {
                    config.agent.device_id = cloud.device_id;
                }
                if cloud.geolocation_url.is_some() {
                    config.agent.geolocation_url = cloud.geolocation_url;
                }
                config.merge_cloud_config(cloud.agent_config);
                agent.update_config(config.clone());
                info!("cloud config applied");
            }
            Err(e) => {
                warn!("cloud config pull failed, continuing with local config: {e}");
            }
        }
    }

    // 5c. Privilege separation (P3.2): drop root now that enrollment and
    // key persistence (both of which want to write to root-owned paths
    // under `/etc/sn360-desktop-agent/`) are done. Port 1514 is
    // unprivileged so the connection manager below still works fine
    // under the drop-to user.
    privilege::drop_privileges(&config.security).context("failed to drop privileges")?;

    // 6-10b. Legacy SIEM transport: ConnectionManager, startup frame,
    //        keepalive loop, event-forwarding loop, server-receive loop.
    //        Only compiled when the `legacy-siem` feature is on.
    #[cfg(feature = "legacy-siem")]
    let (conn, keepalive_handle, forward_handle, receive_handle) = {
        // 6. Create ConnectionManager and WazuhCipher from the agent key
        let protocol = match config.server.protocol.as_str() {
            "udp" => TransportProtocol::Udp,
            _ => TransportProtocol::Tcp,
        };

        let conn_config = ConnectionConfig {
            server_address: config.server.address.clone(),
            server_port: config.server.port,
            protocol,
            keepalive_interval: Duration::from_secs(config.server.keepalive_interval),
            ..ConnectionConfig::default()
        };

        let cipher = WazuhCipher::new(
            &agent_key.id,
            &agent_key.name,
            &agent_key.ip,
            &agent_key.key,
            sda_comms::crypto::CryptoMethod::default(),
        );
        let mut conn = ConnectionManager::new(conn_config);
        conn.set_cipher(cipher);

        // 7. Connect to server with retry
        info!("connecting to server");
        conn.connect_with_retry()
            .await
            .context("failed to connect to server")?;

        // 8. Send startup message
        let startup_msg = WazuhMessage::startup(&agent_key.id);
        conn.send(&startup_msg)
            .await
            .context("failed to send startup message")?;
        info!("startup message sent");

        // Wrap connection in Arc<Mutex> for shared access
        let conn = Arc::new(Mutex::new(conn));

        // 9. Spawn keepalive loop
        let keepalive_interval = Duration::from_secs(config.server.keepalive_interval);
        let keepalive_shutdown = agent.shutdown_signal();
        let keepalive_conn = Arc::clone(&conn);
        let keepalive_agent_id = agent_key.id.clone();

        let keepalive_handle = tokio::spawn(async move {
            run_keepalive_loop(
                keepalive_conn,
                keepalive_agent_id,
                keepalive_interval,
                keepalive_shutdown,
            )
            .await;
        });

        // 10. Spawn event forwarding loop
        let forward_conn = Arc::clone(&conn);
        let forward_agent_id = agent_key.id.clone();
        let mut forward_shutdown = agent.shutdown_signal();
        let mut server_rx = agent.take_server_rx().expect("server_rx already taken");

        let forward_handle = tokio::spawn(async move {
            info!("event forwarding loop started");
            loop {
                tokio::select! {
                    biased;

                    _ = forward_shutdown.wait() => {
                        info!("event forwarding loop shutting down");
                        break;
                    }

                    event = server_rx.recv() => {
                        let event = match event {
                            Some(ev) => ev,
                            None => {
                                info!("server event channel closed, stopping forward loop");
                                break;
                            }
                        };

                        let msg = match map_event_to_message(&forward_agent_id, &event.kind) {
                            Some(m) => m,
                            None => continue,
                        };

                        let mut guard = forward_conn.lock().await;
                        if let Err(e) = guard.send(&msg).await {
                            error!(error = %e, "failed to forward event to server");
                        }
                    }
                }
            }
            info!("event forwarding loop stopped");
        });

        // 10b. Spawn server message receive loop.
        //      Reads incoming frames from the Wazuh server, parses them, and
        //      publishes them as `EventKind::ServerCommand` events on the bus
        //      so modules like active_response can act on server-pushed
        //      commands.  The loop uses a short timeout on each receive so
        //      the connection mutex is released periodically, allowing the
        //      keepalive and forward tasks to send.
        let receive_conn = Arc::clone(&conn);
        let receive_bus = agent.event_bus();
        let mut receive_shutdown = agent.shutdown_signal();

        let receive_handle = tokio::spawn(async move {
            info!("server receive loop started");
            loop {
                tokio::select! {
                    biased;

                    _ = receive_shutdown.wait() => {
                        info!("server receive loop shutting down");
                        break;
                    }

                    result = async {
                        let mut guard = receive_conn.lock().await;
                        tokio::time::timeout(Duration::from_secs(1), guard.receive()).await
                    } => {
                        match result {
                            Ok(Ok(Some(data))) => {
                                let payload = match std::str::from_utf8(&data) {
                                    Ok(s) => s.to_string(),
                                    Err(_) => {
                                        warn!("received non-UTF8 server message, ignoring");
                                        continue;
                                    }
                                };
                                let (command, payload_body) = parse_server_command(&payload);
                                let event = Event::new(
                                    "comms",
                                    Priority::Critical,
                                    EventKind::ServerCommand {
                                        command,
                                        payload: payload_body,
                                    },
                                );
                                if let Err(e) = receive_bus.publish(event) {
                                    warn!(error = %e, "failed to publish server command");
                                }
                            }
                            Ok(Ok(None)) => {
                                // Peer sent a keep-open frame with no body.
                                // Not an error; release the connection mutex
                                // so other tasks can send.
                                tracing::debug!("received empty server frame");
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                            Ok(Err(e)) => {
                                warn!(error = %e, "failed to receive from server");
                                tokio::time::sleep(Duration::from_millis(500)).await;
                            }
                            Err(_) => {
                                // Timeout elapsed with no data; yield so other tasks
                                // (keepalive, forward) can acquire the connection.
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                        }
                    }
                }
            }
            info!("server receive loop stopped");
        });

        (conn, keepalive_handle, forward_handle, receive_handle)
    };

    // 10b. Spawn the shared power-profile watcher. The channel is
    // seeded with `PowerProfile::Normal` so modules started before the
    // first poll observe a sensible default; the background task will
    // reclassify on each poll interval and broadcast changes.
    let (power_tx, power_rx) = power::channel(PowerProfile::Normal);
    let _power_handle = power::spawn_power_profile_task(power_tx, agent.shutdown_signal());

    // 11. Start FIM module if enabled
    if config.modules.fim.enabled {
        info!("starting FIM module");
        let fim_handle = sda_fim::FimModule::start(
            &config,
            agent.event_bus(),
            agent.shutdown_signal(),
            power_rx.clone(),
        );
        agent.register_module(fim_handle);
    }

    // 12. Start LogCollector module if enabled
    if config.modules.logcollector.enabled {
        info!("starting logcollector module");
        let lc_handle = sda_logcollector::LogCollectorModule::start(
            &config,
            agent.event_bus(),
            agent.shutdown_signal(),
            power_rx.clone(),
        );
        agent.register_module(lc_handle);
    }

    // 12b. Start Inventory module if enabled
    if config.modules.inventory.enabled {
        info!("starting inventory module");
        let inv_handle = sda_inventory::InventoryModule::start(
            &config,
            agent.event_bus(),
            agent.shutdown_signal(),
            power_rx.clone(),
        );
        agent.register_module(inv_handle);
    }

    // 12c. Start Active Response module if enabled
    if config.modules.active_response.enabled {
        info!("starting active response module");
        let ar_handle = sda_active_response::ActiveResponseModule::start(
            &config,
            agent.event_bus(),
            agent.shutdown_signal(),
        );
        agent.register_module(ar_handle);
    }

    // 12d. Start SCA module if enabled
    if config.modules.sca.enabled {
        info!("starting SCA module");
        let sca_handle = sda_sca::ScaModule::start(
            &config,
            agent.event_bus(),
            agent.shutdown_signal(),
            power_rx.clone(),
        );
        agent.register_module(sca_handle);
    }

    // 12e. Start Rootcheck module if enabled
    if config.modules.rootcheck.enabled {
        info!("starting rootcheck module");
        let rc_handle = sda_rootcheck::RootcheckModule::start(
            &config,
            agent.event_bus(),
            agent.shutdown_signal(),
        );
        agent.register_module(rc_handle);
    }

    // 12f. Start Local Detection Engine (LDE) module if enabled
    if config.modules.local_detection.enabled {
        info!("starting local detection module");
        let lde_handle = sda_local_detection::LocalDetectionModule::start(
            &config,
            agent.event_bus(),
            agent.shutdown_signal(),
        );
        agent.register_module(lde_handle);
    }

    // 12f-bis. Start Process Monitor module (Phase E1) if enabled.
    //           Default is `false`; flipping `process_monitor.enabled`
    //           to `true` lights up cross-platform process telemetry
    //           (Created / Terminated / ImageLoaded) with parent-chain
    //           enrichment fed into the LDE for behavioural matching.
    if config.modules.process_monitor.enabled {
        info!("starting process monitor module");
        let pm_handle = sda_process_monitor::ProcessMonitorModule::start(
            &config,
            agent.event_bus(),
            agent.shutdown_signal(),
        );
        agent.register_module(pm_handle);
    }

    // 12f-ter. Network Monitor module (Phase E3) — Off by default.
    //          Flipping `network_monitor.enabled = true` lights up
    //          cross-platform TCP/UDP connection telemetry
    //          (`EventKind::NetworkConnection`) with PID
    //          attribution; the LDE feeds the `remote_addr` straight
    //          into the existing IP IOC bloom.
    if config.modules.network_monitor.enabled {
        info!("starting network monitor module");
        let nm_handle = sda_network_monitor::NetworkMonitorModule::start(
            &config,
            agent.event_bus(),
            agent.shutdown_signal(),
        );
        agent.register_module(nm_handle);
    }

    // 12f-quater. DNS Monitor module (Phase E3) — Off by default.
    //             Subscribes to the per-OS DNS source
    //             (systemd-resolved on Linux, ETW on Windows,
    //             NEDNSProxyProvider on macOS) and emits
    //             `EventKind::DnsQuery` events. The LDE feeds the
    //             `query_name` into the string IOC backend and the
    //             `response_ips` into the IP IOC bloom.
    if config.modules.dns_monitor.enabled {
        info!("starting dns monitor module");
        let dm_handle = sda_network_monitor::DnsMonitorModule::start(
            &config,
            agent.event_bus(),
            agent.shutdown_signal(),
        );
        agent.register_module(dm_handle);
    }

    // 12f-quinquies-bis. Memory Scanner module (Phase E4) — Off by
    //                    default. Flipping `memory_scanner.enabled =
    //                    true` lights up the periodic RWX-region
    //                    scanner that hands bounded byte slices to
    //                    the YARA matcher (`scan_bytes` from E4.5)
    //                    and the optional AMSI provider (Windows,
    //                    feature `amsi`). Self-pid exclusion is
    //                    enforced both at the PAL trait level
    //                    (`MemoryScanner::enumerate`) and at the
    //                    module's allow-list (`should_skip_pid`) —
    //                    see `docs/architecture.md` § 8.3 for the
    //                    safety model. CPU / battery gating respects the
    //                    same `PowerMonitor` the enhanced-inventory
    //                    sweep uses.
    if config.modules.memory_scanner.enabled {
        info!("starting memory scanner module");
        let ms_handle = sda_memory_scanner::MemoryScannerModule::start(
            &config,
            agent.event_bus(),
            agent.shutdown_signal(),
        );
        agent.register_module(ms_handle);
    }

    // 12f-quinquies-ter. Identity Monitor module (Phase E5) — Off by
    //                    default. Subscribes to FIM / process / ETW
    //                    feeds and emits `EventKind::IdentityAlert`
    //                    with MITRE ATT&CK technique IDs for
    //                    LSASS access (Windows T1003.001),
    //                    /etc/shadow + /proc/kcore access (Linux
    //                    T1003.008 / T1003), and keychain access
    //                    (macOS T1555.001). See E5 in
    //                    `docs/edr.md` § 5 (Identity attack
    //                    detection).
    if config.modules.identity_monitor.enabled {
        info!("starting identity monitor module");
        let im_handle = sda_identity_monitor::IdentityMonitorModule::start(
            &config,
            agent.event_bus(),
            agent.shutdown_signal(),
        );
        agent.register_module(im_handle);
    }

    // 12f-quinquies-quater. DLP module (Phase E5) — Off by
    //                       default. Subscribes to `FileCreated` /
    //                       `FileModified` from FIM and scans
    //                       bounded byte windows against the
    //                       regex pattern set (US SSN / UK NI /
    //                       PCI PAN+Luhn). Emits redaction-safe
    //                       findings via
    //                       `EventKind::LocalDetectionAlert` with
    //                       `rule_type = "dlp"` —
    //                       `docs/architecture.md` § 8.2 (Redaction
    //                       invariant) REQUIRES the matched bytes
    //                       MUST NOT appear in the payload.
    if config.modules.dlp.enabled {
        info!("starting DLP module");
        let dlp_handle =
            sda_dlp::DlpModule::start(&config, agent.event_bus(), agent.shutdown_signal());
        agent.register_module(dlp_handle);
    }

    // 12f-quinquies. Host Isolation module (Phase E3) — Off by
    //                default. Consumes `IsolateHost` /
    //                `UnisolateHost` `SignedActionJob`s once the
    //                Device Control router learns to forward them
    //                (parity with the MDM dispatcher; that wiring
    //                lands in a follow-up).
    //
    //                **Safety guard:** the router validates jobs
    //                against this agent's `(tenant_id, device_id)`
    //                pair, and the `Phase1Stub` hooks reject every
    //                signature with `UnknownKeyId` until the real
    //                KeyStore lands. Until the follow-up wires
    //                enrolled identity + a production key store
    //                into this call site, *every* inbound job
    //                would be silently refused. Rather than start
    //                a non-functional module that looks healthy to
    //                an operator, we log a `warn!` and skip
    //                registration when the identity is nil — this
    //                is the agent-side echo of `host_isolation`
    //                being a follow-up-gated feature.
    //
    //                The `submitter` is bound at the outer scope
    //                so the channel stays open for the lifetime of
    //                `main` even when the module is not started.
    let _host_isolation_submitter: Option<sda_host_isolation::HostIsolationSubmitter> =
        if config.modules.host_isolation.enabled {
            // Build the agent identity from the enrolled (tenant_id,
            // device_id) populated during cloud-config pull (WS2.1).
            let maybe_identity = config
                .agent
                .tenant_id
                .as_deref()
                .and_then(|t| t.parse::<uuid::Uuid>().ok())
                .and_then(|tid| {
                    config
                        .agent
                        .device_id
                        .as_deref()
                        .and_then(|d| d.parse::<uuid::Uuid>().ok())
                        .map(|did| (tid, did))
                })
                .filter(|(tid, did)| !tid.is_nil() && !did.is_nil());

            if let Some((tid, did)) = maybe_identity {
                let identity = sda_device_control::router::AgentIdentity {
                    tenant_id: tid,
                    device_id: did,
                };
                info!(
                    tenant_id = %identity.tenant_id,
                    device_id = %identity.device_id,
                    "starting host isolation module with enrolled identity"
                );
                let (hi_handle, submitter) = sda_host_isolation::HostIsolationModule::start(
                    &config,
                    identity,
                    agent.event_bus(),
                    agent.shutdown_signal(),
                );
                agent.register_module(hi_handle);
                Some(submitter)
            } else {
                warn!(
                    tenant_id = ?config.agent.tenant_id,
                    device_id = ?config.agent.device_id,
                    "host_isolation.enabled=true but enrolled identity is missing \
                     or invalid; skipping module start until enrollment completes."
                );
                None
            }
        } else {
            None
        };

    // 12g. Start Enhanced Inventory module if enabled
    if config.modules.enhanced_inventory.enabled {
        info!("starting enhanced inventory module");
        let ei_handle = sda_enhanced_inventory::EnhancedInventoryModule::start(
            &config,
            agent.event_bus(),
            agent.shutdown_signal(),
            power_rx.clone(),
        );
        agent.register_module(ei_handle);
    }

    // 12h. Start Updater module (P3.1) if enabled.
    //      Off by default; operators opt in and pin a verifying key.
    if config.modules.updater.enabled {
        info!("starting updater module");
        let up_handle = sda_updater::UpdaterModule::start(&config, agent.shutdown_signal());
        agent.register_module(up_handle);
    }

    // 12i. Device Control modules (Phase 1 scaffold).
    //      Off by default; flipping `device_control.enabled` to
    //      `true` lights up the Device Control router, which in
    //      Phase 1 only parks on the shutdown signal — the per-
    //      action executors land in Phase 2/3. Idle footprint is
    //      bit-for-bit identical to a pre-Device-Control build
    //      when this flag is `false`.
    if config.modules.device_control.enabled {
        info!("starting device control module");
        let dc_handle = sda_device_control::DeviceControlModule::start(
            &config,
            agent.event_bus(),
            agent.shutdown_signal(),
        );
        agent.register_module(dc_handle);

        // Phase D2: USB / removable-media policy enforcement is a
        // sub-module of Device Control gated by its own enable
        // flag so a tenant can flip it on independently of the
        // existing Phase 1 schemas.
        if config.modules.device_control.usb_policy.enabled {
            info!("starting USB-policy enforcement module");
            let usb_handle = sda_device_control::UsbPolicyModule::start(
                &config,
                agent.event_bus(),
                agent.shutdown_signal(),
            );
            agent.register_module(usb_handle);
        }
    }

    // 12i-bis. ShieldNet Desktop MDM module (Phase M1–M3).
    //           ON by default (`modules.mdm.enabled = true`).
    //           Spawns the auto-remediation supervisor, config-profile
    //           watcher, one-shot recovery-key escrow, and parks the
    //           wipe/lock/lost-mode/config-profile dispatch path until a
    //           SignedActionJob arrives from the Device Control router.
    //
    // The shared `LastKnownLocationStore` is built BEFORE both the MDM
    // module and the agent-vitals heartbeat (position 12m below) so the
    // two can rendezvous on the same instance: the lost-mode reporter
    // writes IP-geolocation readings into it, the heartbeat reads back
    // from it when assembling the next `AgentVitals` payload. Without
    // this rendezvous the heartbeat's `last_known_location` field would
    // always be `None` in production even while the reporter is
    // actively writing — the bug Devin Review flagged as #11.
    let mdm_location_store = sda_core::location::LastKnownLocationStore::new();
    if config.modules.mdm.enabled {
        info!("starting desktop MDM module");
        let mdm_provider: std::sync::Arc<dyn sda_pal::mdm::MdmProvider> =
            std::sync::Arc::from(sda_pal::mdm::default_mdm_provider());
        let mdm_power: sda_mdm::module::SharedPowerState = std::sync::Arc::new(
            sda_mdm::os_patch::WatchPowerStateProvider::new(power_rx.clone()),
        );
        let mdm_geolocator: std::sync::Arc<dyn sda_mdm::lost_mode::IpGeolocator> =
            if let Some(ref geo_url) = config.agent.geolocation_url {
                info!(url = %geo_url, "MDM geolocator: using HTTP backend");
                std::sync::Arc::new(HttpGeolocator::new(geo_url.clone()))
            } else {
                // Default to ip-api.com free-tier JSON endpoint when
                // the gateway does not provide a geolocation URL. The
                // free tier has a 45 req/min rate limit which is more
                // than enough for the 5-minute lost-mode interval.
                let default_url = "http://ip-api.com/json/?fields=lat,lon".to_string();
                info!(url = %default_url, "MDM geolocator: using default ip-api.com");
                std::sync::Arc::new(HttpGeolocator::new(default_url))
            };

        // Build the recovery-escrow identity from the enrolled
        // (tenant_id, device_id). The escrow seed is derived from
        // the device_id so it is deterministic across restarts.
        let recovery_identity = config
            .agent
            .tenant_id
            .as_deref()
            .and_then(|t| t.parse::<uuid::Uuid>().ok())
            .and_then(|tid| {
                config
                    .agent
                    .device_id
                    .as_deref()
                    .and_then(|d| d.parse::<uuid::Uuid>().ok())
                    .filter(|did| !did.is_nil())
                    .map(|did| (tid, did))
            })
            .filter(|(tid, _)| !tid.is_nil())
            .map(|(tid, did)| {
                use sha2::{Digest, Sha256};
                // Deterministic seed from device identity for stable
                // escrow key derivation across agent restarts.
                let mut hasher = Sha256::new();
                hasher.update(b"sn360-mdm-escrow-v1:");
                hasher.update(tid.as_bytes());
                hasher.update(did.as_bytes());
                let seed_bytes = hasher.finalize();
                let signing_key = ed25519_dalek::SigningKey::from_bytes(
                    seed_bytes
                        .as_slice()
                        .try_into()
                        .expect("SHA-256 is 32 bytes"),
                );
                let key_id = format!("device:{}", did);
                info!(tenant_id = %tid, device_id = %did, "MDM recovery escrow identity wired");
                sda_mdm::module::RecoveryEscrowIdentity {
                    tenant_id: tid,
                    device_id: did,
                    escrow_seed: seed_bytes.to_vec(),
                    signing_key: std::sync::Arc::new(signing_key),
                    key_id,
                }
            });

        let mdm_module = std::sync::Arc::new(sda_mdm::MdmModule::with_geolocator(
            config.modules.mdm.clone(),
            mdm_provider,
            agent.event_bus(),
            Vec::new(), // pinned profile signing keys — populated by TRDS bundle push
            mdm_power,
            recovery_identity,
            mdm_location_store.clone(),
            mdm_geolocator,
        ));
        // `start()` consumes one clone of the `Arc<MdmModule>` and
        // spawns an internal dispatcher task that holds its own
        // clone of the same `Arc` (the `dispatch_self` capture in
        // `sda_mdm::module`). That dispatcher-side `Arc` is what
        // keeps the module — and the `mpsc` sender / receiver pair
        // returned by `action_sender()` — alive for the lifetime
        // of the agent. The local `mdm_module` `Arc` here is
        // therefore free to drop at end of this scope; we do not
        // need a `let _keep_alive = mdm_module;` shim.
        //
        // Once the Device Control router learns to forward
        // MDM-flavour jobs to `MdmModule::dispatch`, the router
        // wiring will live here too: it'll need `mdm_module
        // .action_sender()` (or a wrapper that holds the sender
        // through the router's lifecycle). That code path is not
        // yet implemented — the inbound dispatch arms in
        // `MdmModule::dispatch` are reachable but not reached.
        let mdm_handle = mdm_module.start(agent.shutdown_signal());
        agent.register_module(mdm_handle);
    }

    // 12j. Query (osquery sidecar) module — Phase 1 MVP.
    //      Default is disabled. The supervisor probes the configured
    //      osquery binary, runs scheduled queries, and emits
    //      `EventKind::QueryResult` events on the bus.
    if config.modules.query.enabled {
        info!("starting query module");
        let q_handle =
            sda_query::QueryModule::start(&config, agent.event_bus(), agent.shutdown_signal());
        agent.register_module(q_handle);
    }

    // 12k. Posture module — periodic device-posture snapshots.
    //      Default is disabled. When enabled the supervisor takes
    //      a snapshot at `modules.posture.interval_secs` intervals
    //      and emits `EventKind::DevicePostureState` deltas.
    if config.modules.posture.enabled {
        info!("starting posture module");
        let p_handle = sda_posture::PostureModule::start(
            &config,
            agent.event_bus(),
            agent.shutdown_signal(),
            power_rx.clone(),
        );
        agent.register_module(p_handle);
    }

    // 12l. Software module (Phase 2.5 scaffold).
    //      Off by default. When enabled the supervisor refreshes the
    //      signed catalogue at `modules.software.refresh_interval_secs`
    //      and exposes install/update/uninstall actions through the
    //      `PackageManager` PAL trait. The Phase 2.5 scaffold parks
    //      until Phase 2.6 wires the live fetch loop.
    if config.modules.software.enabled {
        info!("starting software module");
        let sw_handle = sda_software::SoftwareModule::start(
            &config,
            agent.event_bus(),
            agent.shutdown_signal(),
        );
        agent.register_module(sw_handle);
    }

    // 12l-bis. Script runner (Phase 2.7).
    //          Off by default. Executes signed, allow-listed scripts
    //          with hard wall-clock and output-byte budgets, then
    //          emits `ScriptRunResult` + `EvidenceRecord` events.
    //          The supervisor handles the disabled / mis-configured
    //          cases internally (parks on shutdown), so we only need
    //          to spawn it unconditionally.
    let script_runner_work_dir = std::env::temp_dir().join("sn360-script-runner");
    let (script_runner_handle, _script_runner_sender) =
        sda_script_runner::ScriptRunnerModule::start(
            &config,
            agent.event_bus(),
            agent.shutdown_signal(),
            script_runner_work_dir,
        );
    agent.register_module(script_runner_handle);

    // 12l-ter. JIT admin module (Phase 3.2 / 3.3).
    //          Off by default. Owns the grant lifecycle state
    //          machine, on-disk grant ledger, and revocation
    //          watchdog (timer / heartbeat / power / boot-sweep).
    //          Always spawned: the supervisor itself parks on
    //          shutdown when `modules.jit_admin.enabled = false`,
    //          so idle CPU stays at zero and the bus only sees
    //          `JitAdmin*` events when grants are active.
    let jit_admin_work_dir = std::env::temp_dir().join("sn360-jit-admin");
    // The sender MUST stay alive for the lifetime of `main` —
    // dropping it closes the supervisor's request mpsc, which causes
    // its `tokio::select!` to break out on `rx.recv() = None` and
    // takes the watchdog `tick` branch with it. Bind at this outer
    // scope (not inside the `if let`) so the channel stays open
    // even before the device-control router that will eventually
    // consume the sender lands.
    let _jit_admin_sender: Option<sda_jit_admin::JitAdminSender> =
        if let Some(admin_box) = sda_pal::admin_manager::default_admin_manager() {
            let admin_arc: std::sync::Arc<dyn sda_pal::admin_manager::AdminManager> =
                std::sync::Arc::from(admin_box);
            let jit_admin_handle = sda_jit_admin::JitAdminModule::start(
                &config,
                agent.event_bus(),
                agent.shutdown_signal(),
                admin_arc,
                jit_admin_work_dir,
            );
            agent.register_module(jit_admin_handle.module);
            jit_admin_handle.sender
        } else {
            tracing::warn!(
                "jit_admin module disabled: no platform AdminManager available on this target"
            );
            None
        };

    // 12l-quater. Remote-support module (Phase 4.2).
    //              Off by default. `docs/device-control.md` § 9 mandates a
    //              consent banner on every session — the Phase-4
    //              default consent prompt is `StubConsentPrompt`,
    //              which denies every request. The agent therefore
    //              fails closed unless the operator wires a real
    //              prompt later. The module's `start()` parks on
    //              the request channel; dropping the sender ends
    //              the loop, so we keep it alive for the lifetime
    //              of `main`.
    let _remote_support_sender: Option<
        tokio::sync::mpsc::UnboundedSender<sda_remote_support::module::RemoteSupportRequest>,
    > = if config.modules.remote_support.enabled {
        match sda_remote_support::module::RemoteSupportModule::with_defaults(
            config.modules.remote_support.clone(),
            std::sync::Arc::new(agent.event_bus()),
        ) {
            Some(module) => {
                info!("starting remote-support module");
                let (tx, _handle) = module.start();
                Some(tx)
            }
            None => {
                tracing::warn!(
                    "remote_support module disabled: no platform RemoteSupportProvider available on this target"
                );
                None
            }
        }
    } else {
        None
    };

    // 12l-quinquies. App-control module (Phase 4.5).
    //                Off by default. Phase-4 acceptance criteria
    //                mandate `Monitor` mode by
    //                default; `Enforce` requires explicit tenant
    //                opt-in plus a trusted signing key configured
    //                via `modules.app_control.trusted_signing_key`.
    //                The supervisor short-circuits gracefully when
    //                the key is missing.
    let _app_control_sender: Option<
        tokio::sync::mpsc::UnboundedSender<sda_app_control::module::AppControlCommand>,
    > = if config.modules.app_control.enabled {
        match sda_app_control::module::AppControlModule::with_defaults(
            config.modules.app_control.clone(),
            std::sync::Arc::new(agent.event_bus()),
        ) {
            Some(module) => {
                info!("starting app-control module");
                let (tx, _handle) = module.start();
                Some(tx)
            }
            None => {
                tracing::warn!(
                    "app_control module disabled: no platform AppControlProvider available on this target"
                );
                None
            }
        }
    } else {
        None
    };

    // 12m. Agent-vitals heartbeat (Phase 1.12).
    //      Per `docs/architecture.md` § 3 (Event flow) the heartbeat
    //      is always-on when Device Control is enabled. The cadence
    //      defaults to 60s (`Priority::Low` per
    //      `docs/architecture.md` § 3.1); the module pauses entirely
    //      on `PowerProfile::CriticalBattery`.
    //      `modules.agent_vitals.enabled` lets operators force-enable
    //      the heartbeat without lighting up the rest of Device
    //      Control, which is useful for fleet-wide observability
    //      pilots.
    if config.modules.device_control.enabled || config.modules.agent_vitals.enabled {
        info!("starting agent vitals module");
        // Hand the heartbeat the same `LastKnownLocationStore` the
        // Desktop MDM module's lost-mode reporter writes into so the
        // `AgentVitals` payload carries the latest IP-geolocation
        // reading (per `docs/desktop-mdm.md` § 4.2 — Lost mode).
        // The store is created
        // unconditionally up top so the heartbeat can still read it
        // even when `modules.mdm.enabled = false` (in which case the
        // reading will be `None` until the MDM module is enabled).
        let av_handle = sda_agent_vitals::VitalsModule::start(
            config.modules.agent_vitals.interval_secs,
            sda_agent_vitals::VitalsCounters::new(),
            agent.event_bus(),
            agent.shutdown_signal(),
            power_rx.clone(),
            Some(mdm_location_store.clone()),
        );
        agent.register_module(av_handle);
    }

    // 12n. Tamper-protection watchdog (P3.3). Off unless
    // `security.tamper.watchdog_interval_secs` is non-zero AND
    // `$NOTIFY_SOCKET` is set by the service manager.
    let _watchdog_handle = tamper::spawn_watchdog(&config.security.tamper);

    // 12o. Local health-check HTTP endpoint (localhost:27015/healthz).
    //      The post-install health check polls this to confirm the
    //      agent enrolled, pulled cloud config, and started modules.
    let health_shutdown = agent.shutdown_signal();
    let _health_handle = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:27015").await {
            Ok(l) => l,
            Err(e) => {
                warn!("health endpoint: bind failed (port 27015 in use?): {e}");
                return;
            }
        };
        info!("health endpoint listening on 127.0.0.1:27015");
        let mut shutdown = health_shutdown;
        loop {
            tokio::select! {
                _ = shutdown.wait() => break,
                accept = listener.accept() => {
                    if let Ok((mut stream, _)) = accept {
                        let resp = "HTTP/1.1 200 OK\r\n\
                                    Content-Type: application/json\r\n\
                                    Content-Length: 15\r\n\
                                    Connection: close\r\n\r\n\
                                    {\"status\":\"ok\"}";
                        let _ = stream.write_all(resp.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    }
                }
            }
        }
    });

    // 13. Start agent and wait for shutdown signal
    agent.start().await;
    agent.wait_for_shutdown().await;

    // 14. Send shutdown message, disconnect, shut down agent.
    //     Only when the legacy SIEM transport is compiled in.
    #[cfg(feature = "legacy-siem")]
    {
        info!("sending shutdown message");
        {
            let shutdown_msg = WazuhMessage::new(
                &agent_key.id,
                sda_comms::protocol::MessageType::Shutdown,
                "#!-agent shutdown",
            );
            let mut guard = conn.lock().await;
            if let Err(e) = guard.send(&shutdown_msg).await {
                error!(error = %e, "failed to send shutdown message");
            }
            guard.disconnect().await;
        }

        // Wait for keepalive, forwarding, and receive tasks to finish
        let _ = keepalive_handle.await;
        let _ = forward_handle.await;
        let _ = receive_handle.await;
    }

    agent.shutdown().await;
    info!("wazuh desktop agent stopped");

    Ok(())
}

/// Map an `EventKind` to a `WazuhMessage` ready for server delivery.
///
/// Returns `None` for event kinds that should not be forwarded (e.g.
/// lifecycle events that are handled separately).
#[cfg(feature = "legacy-siem")]
fn map_event_to_message(agent_id: &str, kind: &EventKind) -> Option<WazuhMessage> {
    let (msg_type, payload) = match kind {
        EventKind::FileCreated {
            syscheck_payload, ..
        }
        | EventKind::FileModified {
            syscheck_payload, ..
        }
        | EventKind::FileDeleted {
            syscheck_payload, ..
        }
        | EventKind::FileMetadataChanged {
            syscheck_payload, ..
        } => {
            let json = syscheck_payload.clone().unwrap_or_else(|| {
                serde_json::to_string(kind).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e))
            });
            (MessageType::Syscheck, json)
        }
        EventKind::LogCollected {
            source, message, ..
        } => {
            let payload = format!("{}:{}", source, message);
            (MessageType::Log, payload)
        }
        EventKind::InventoryUpdate { data, .. } => {
            let payload = match data.as_str() {
                Some(s) => s.to_string(),
                None => serde_json::to_string(kind)
                    .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            };
            (MessageType::Syscollector, payload)
        }
        EventKind::EnhancedInventoryUpdate { category, data } => {
            // Wrap the module payload in a small envelope so the
            // manager can distinguish enhanced categories from the
            // base syscollector scans while still routing them to
            // the same `d:` queue.
            let envelope = serde_json::json!({
                "type": "enhanced_inventory",
                "category": category,
                "data": data,
            });
            let payload = serde_json::to_string(&envelope)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
            (MessageType::Syscollector, payload)
        }
        EventKind::ScaResult { .. } => {
            let json =
                serde_json::to_string(kind).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
            (MessageType::Sca, json)
        }
        EventKind::ActiveResponseResult { .. } => {
            let json =
                serde_json::to_string(kind).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
            (MessageType::ActiveResponse, json)
        }
        EventKind::RootcheckAlert { .. } => {
            let json =
                serde_json::to_string(kind).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
            (MessageType::Rootcheck, json)
        }
        EventKind::LocalDetectionAlert { .. } => {
            let json =
                serde_json::to_string(kind).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
            (MessageType::LocalDetection, json)
        }
        EventKind::ServerMessage { payload } => (MessageType::Generic, payload.clone()),

        // --- Device Control event mapping (Phase 1) ---
        //
        // Each Device Control `EventKind` carries an opaque pre-encoded
        // canonical-JSON `payload` produced by `sda-device-control`.
        // We forward it verbatim — the producing module is the single
        // source of truth for the wire encoding (RFC 8785 canonical
        // JSON, see `docs/wire-protocols/device-control.md` § 2).
        EventKind::DeviceControlFinding { payload } => {
            (MessageType::DeviceControlFinding, payload.clone())
        }
        EventKind::DeviceControlRecommendation { payload } => {
            (MessageType::DeviceControlRecommendation, payload.clone())
        }
        EventKind::DeviceControlActionResult { payload } => {
            (MessageType::DeviceControlActionResult, payload.clone())
        }
        EventKind::DevicePostureState { payload } => {
            (MessageType::DevicePostureState, payload.clone())
        }
        EventKind::SoftwareInventoryDelta { payload } => {
            (MessageType::SoftwareInventoryDelta, payload.clone())
        }
        EventKind::SoftwareJobResult { payload } => {
            (MessageType::SoftwareJobResult, payload.clone())
        }
        EventKind::JitAdminRequested { payload } => {
            (MessageType::JitAdminRequested, payload.clone())
        }
        EventKind::JitAdminGranted { payload } => (MessageType::JitAdminGranted, payload.clone()),
        EventKind::JitAdminRevoked { payload } => (MessageType::JitAdminRevoked, payload.clone()),
        EventKind::QueryResult { payload } => (MessageType::QueryResult, payload.clone()),
        EventKind::ScriptRunResult { payload } => (MessageType::ScriptRunResult, payload.clone()),
        EventKind::RemoteSupportSessionStarted { payload } => {
            (MessageType::RemoteSupportSessionStarted, payload.clone())
        }
        EventKind::RemoteSupportSessionEnded { payload } => {
            (MessageType::RemoteSupportSessionEnded, payload.clone())
        }
        EventKind::AgentVitals { payload } => (MessageType::AgentVitals, payload.clone()),
        EventKind::EvidenceRecord { payload } => (MessageType::EvidenceRecord, payload.clone()),
        EventKind::UsbDevicePolicyDecision { payload } => {
            (MessageType::UsbDevicePolicyDecision, payload.clone())
        }

        // --- Desktop MDM event mapping (Phase M1–M3) ---
        EventKind::MdmWipeResult { payload } => (MessageType::MdmWipeResult, payload.clone()),
        EventKind::MdmLockResult { payload } => (MessageType::MdmLockResult, payload.clone()),
        EventKind::MdmLostModeEntered { payload } => {
            (MessageType::MdmLostModeEntered, payload.clone())
        }
        EventKind::MdmLostModeExited { payload } => {
            (MessageType::MdmLostModeExited, payload.clone())
        }
        EventKind::MdmRecoveryKeyEscrowed { payload } => {
            (MessageType::MdmRecoveryKeyEscrowed, payload.clone())
        }
        EventKind::MdmOsUpdateResult { payload } => {
            (MessageType::MdmOsUpdateResult, payload.clone())
        }
        EventKind::MdmConfigProfileApplied { payload } => {
            (MessageType::MdmConfigProfileApplied, payload.clone())
        }
        EventKind::MdmAutoRemediationResult { payload } => {
            (MessageType::MdmAutoRemediationResult, payload.clone())
        }

        // --- EDR Parity event mapping (Phase E1-E3) ---
        EventKind::ProcessCreated { payload } => (MessageType::ProcessCreated, payload.clone()),
        EventKind::ProcessTerminated { payload } => {
            (MessageType::ProcessTerminated, payload.clone())
        }
        EventKind::ImageLoaded { payload } => (MessageType::ImageLoaded, payload.clone()),
        EventKind::NetworkConnection { payload } => {
            (MessageType::NetworkConnection, payload.clone())
        }
        EventKind::DnsQuery { payload } => (MessageType::DnsQuery, payload.clone()),
        EventKind::MemoryScanAlert { payload } => (MessageType::MemoryScanAlert, payload.clone()),
        EventKind::HostIsolationStateChanged { payload } => {
            (MessageType::HostIsolationStateChanged, payload.clone())
        }
        EventKind::IdentityAlert { payload } => (MessageType::IdentityAlert, payload.clone()),

        // Lifecycle / internal events are not forwarded.
        _ => return None,
    };

    Some(WazuhMessage::new(agent_id, msg_type, payload))
}

/// Classify a raw server payload into a command identifier and passthrough
/// body.  Wazuh server-pushed commands are typically prefixed with a magic
/// sentinel (e.g. `#!-execd` for the execution daemon).  The full payload
/// is preserved so downstream modules can perform their own parsing.
#[cfg(feature = "legacy-siem")]
fn parse_server_command(payload: &str) -> (String, String) {
    let trimmed = payload.trim_end_matches('\0').trim();
    let command = if trimmed.starts_with("#!-execd") {
        "execd"
    } else if trimmed.starts_with("#!-req") {
        "request"
    } else if trimmed.starts_with("#!-up_file") {
        "up_file"
    } else if trimmed.starts_with("#!-") {
        "internal"
    } else {
        "generic"
    };
    (command.to_string(), trimmed.to_string())
}

// ---- HttpGeolocator ---------------------------------------------------------
// Production IP-geolocation backend that queries a lightweight HTTP
// API (ip-api.com free tier, or a gateway-proxied equivalent). The
// trait `IpGeolocator::locate()` is synchronous, so we spawn the
// HTTP request on the current Tokio runtime via `block_on`.

struct HttpGeolocator {
    url: String,
    client: reqwest::Client,
}

impl HttpGeolocator {
    fn new(url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("build geolocator http client");
        Self { url, client }
    }
}

#[derive(serde::Deserialize)]
struct GeoApiResponse {
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
    #[serde(default)]
    accuracy: Option<f64>,
}

impl sda_mdm::lost_mode::IpGeolocator for HttpGeolocator {
    fn locate(&self) -> Option<sda_core::location::LastKnownLocation> {
        // The trait is synchronous; use a blocking spawn so we don't
        // deadlock the Tokio runtime. This is called infrequently
        // (every ~5 min during lost mode), so the overhead is fine.
        let url = self.url.clone();
        let client = self.client.clone();
        let handle = tokio::runtime::Handle::try_current().ok()?;
        let result = std::thread::spawn(move || {
            handle.block_on(async {
                let resp = client
                    .get(&url)
                    .header("User-Agent", "SN360-Desktop-Agent/1.0")
                    .send()
                    .await
                    .ok()?;
                if !resp.status().is_success() {
                    return None;
                }
                let body: GeoApiResponse = resp.json().await.ok()?;
                Some(sda_core::location::LastKnownLocation {
                    lat: body.lat?,
                    lon: body.lon?,
                    accuracy_m: body.accuracy.unwrap_or(5000.0),
                    reported_at: chrono::Utc::now(),
                })
            })
        })
        .join()
        .ok()?;
        result
    }
}

// ---- Cloud config pull types ------------------------------------------------
// Mirror the gateway's TierPreset JSON so we can deserialize the
// response and map it into the agent's own `AgentConfig`.

#[derive(serde::Deserialize)]
struct CloudTierPreset {
    #[serde(default)]
    tier: String,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    endpoints: CloudEndpoints,
    #[serde(default)]
    modules: CloudModules,
}

#[derive(serde::Deserialize, Default)]
struct CloudEndpoints {
    #[serde(default)]
    trds_url: Option<String>,
    #[serde(default)]
    iocfs_url: Option<String>,
    #[serde(default)]
    updater_manifest_url: Option<String>,
    #[serde(default)]
    software_catalogue_url: Option<String>,
    #[serde(default)]
    geolocation_url: Option<String>,
}

#[derive(serde::Deserialize, Default)]
struct CloudModules {
    #[serde(default)]
    fim: Option<CloudToggle>,
    #[serde(default)]
    logcollector: Option<CloudToggle>,
    #[serde(default)]
    inventory: Option<CloudToggle>,
    #[serde(default)]
    sca: Option<CloudToggle>,
    #[serde(default)]
    rootcheck: Option<CloudToggle>,
    #[serde(default)]
    active_response: Option<CloudToggle>,
    #[serde(default)]
    local_detection: Option<CloudToggle>,
    #[serde(default)]
    enhanced_inventory: Option<CloudToggle>,
    #[serde(default)]
    updater: Option<CloudUpdater>,
    #[serde(default)]
    device_control: Option<CloudToggle>,
    #[serde(default)]
    posture: Option<CloudToggle>,
    #[serde(default)]
    software: Option<CloudToggle>,
    #[serde(default)]
    jit_admin: Option<CloudToggle>,
    #[serde(default)]
    app_control: Option<CloudAppControl>,
    #[serde(default)]
    remote_support: Option<CloudToggle>,
    #[serde(default)]
    mdm: Option<CloudToggle>,
    #[serde(default)]
    process_monitor: Option<CloudToggle>,
    #[serde(default)]
    network_monitor: Option<CloudToggle>,
    #[serde(default)]
    dns_monitor: Option<CloudToggle>,
    #[serde(default)]
    host_isolation: Option<CloudToggle>,
    #[serde(default)]
    memory_scanner: Option<CloudToggle>,
    #[serde(default)]
    identity_monitor: Option<CloudToggle>,
    #[serde(default)]
    dlp: Option<CloudToggle>,
    #[serde(default)]
    query: Option<CloudToggle>,
    #[serde(default)]
    agent_vitals: Option<CloudToggle>,
    #[serde(default)]
    script_runner: Option<CloudToggle>,
}

#[derive(serde::Deserialize)]
struct CloudToggle {
    enabled: bool,
}

#[derive(serde::Deserialize)]
struct CloudUpdater {
    enabled: bool,
    #[serde(default)]
    manifest_url: Option<String>,
    #[serde(default)]
    public_key: Option<String>,
}

#[derive(serde::Deserialize)]
struct CloudAppControl {
    enabled: bool,
    #[serde(default)]
    mode: Option<String>,
}

/// Result of a successful cloud-config pull.
struct CloudConfig {
    /// The full agent config with cloud-provided module toggles.
    agent_config: AgentConfig,
    /// Tenant ID extracted from the gateway response (cert-derived).
    tenant_id: Option<String>,
    /// Device ID extracted from the gateway response (cert-derived).
    device_id: Option<String>,
    /// IP geolocation endpoint for MDM lost-mode location reports.
    geolocation_url: Option<String>,
}

/// Pull the cloud-provisioned agent config from the SN360 Agent
/// Gateway's `GET /api/v1/config` endpoint. The gateway returns a
/// TierPreset JSON scoped to the tenant's tier. We map it into an
/// `AgentConfig` for merging with the local config.
async fn pull_cloud_config(gateway_url: &str) -> Result<CloudConfig> {
    let url = format!("{}/api/v1/config", gateway_url.trim_end_matches('/'));
    info!(url = %url, "pulling cloud config from gateway");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build http client")?;

    let resp = client
        .get(&url)
        .header("User-Agent", "SN360-Desktop-Agent/1.0")
        .send()
        .await
        .context("cloud config request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("cloud config endpoint returned {status}: {body}");
    }

    let body = resp.text().await.context("read cloud config body")?;
    let preset: CloudTierPreset =
        serde_json::from_str(&body).context("parse cloud config response")?;

    info!(tier = %preset.tier, "received cloud config");

    // Map the preset into an AgentConfig so merge_cloud_config works.
    let mut cfg = AgentConfig::default();

    // Helper: apply a toggle to an enabled field.
    macro_rules! toggle {
        ($field:expr, $src:expr) => {
            if let Some(ref t) = $src {
                $field = t.enabled;
            }
        };
    }

    toggle!(cfg.modules.fim.enabled, preset.modules.fim);
    toggle!(
        cfg.modules.logcollector.enabled,
        preset.modules.logcollector
    );
    toggle!(cfg.modules.inventory.enabled, preset.modules.inventory);
    toggle!(cfg.modules.sca.enabled, preset.modules.sca);
    toggle!(cfg.modules.rootcheck.enabled, preset.modules.rootcheck);
    toggle!(
        cfg.modules.active_response.enabled,
        preset.modules.active_response
    );
    toggle!(
        cfg.modules.local_detection.enabled,
        preset.modules.local_detection
    );
    toggle!(
        cfg.modules.enhanced_inventory.enabled,
        preset.modules.enhanced_inventory
    );
    toggle!(
        cfg.modules.device_control.enabled,
        preset.modules.device_control
    );
    toggle!(cfg.modules.posture.enabled, preset.modules.posture);
    toggle!(cfg.modules.software.enabled, preset.modules.software);
    toggle!(cfg.modules.jit_admin.enabled, preset.modules.jit_admin);
    toggle!(
        cfg.modules.remote_support.enabled,
        preset.modules.remote_support
    );
    toggle!(cfg.modules.mdm.enabled, preset.modules.mdm);
    toggle!(
        cfg.modules.process_monitor.enabled,
        preset.modules.process_monitor
    );
    toggle!(
        cfg.modules.network_monitor.enabled,
        preset.modules.network_monitor
    );
    toggle!(cfg.modules.dns_monitor.enabled, preset.modules.dns_monitor);
    toggle!(
        cfg.modules.host_isolation.enabled,
        preset.modules.host_isolation
    );
    toggle!(
        cfg.modules.memory_scanner.enabled,
        preset.modules.memory_scanner
    );
    toggle!(
        cfg.modules.identity_monitor.enabled,
        preset.modules.identity_monitor
    );
    toggle!(cfg.modules.dlp.enabled, preset.modules.dlp);
    toggle!(cfg.modules.query.enabled, preset.modules.query);
    toggle!(
        cfg.modules.agent_vitals.enabled,
        preset.modules.agent_vitals
    );
    toggle!(
        cfg.modules.script_runner.enabled,
        preset.modules.script_runner
    );

    if let Some(ref u) = preset.modules.updater {
        cfg.modules.updater.enabled = u.enabled;
        if let Some(ref url) = u.manifest_url {
            cfg.modules.updater.server_url = url.clone();
        }
        if let Some(ref pk) = u.public_key {
            cfg.modules.updater.public_key = pk.clone();
        }
    }

    if let Some(ref ac) = preset.modules.app_control {
        cfg.modules.app_control.enabled = ac.enabled;
        if let Some(ref m) = ac.mode {
            cfg.modules.app_control.mode = m.clone();
        }
    }

    Ok(CloudConfig {
        agent_config: cfg,
        tenant_id: preset.tenant_id,
        device_id: preset.device_id,
        geolocation_url: preset.endpoints.geolocation_url,
    })
}

/// Get the system hostname as a fallback agent name.
#[cfg(feature = "legacy-siem")]
fn gethostname() -> String {
    ::gethostname::gethostname().to_string_lossy().into_owned()
}

/// Handle short-circuit CLI flags (`--version`, `-V`, `--help`, `-h`).
///
/// Returns `Some(exit_code)` if the flag was handled and the process
/// should exit immediately, or `None` to continue normal startup.
///
/// `--version` is used by the self-update smoke test in
/// [`sda_updater::installer`] — a freshly-installed binary that
/// cannot print its version within the smoke-test timeout is
/// considered broken and the install is rolled back. Keep this
/// handler minimal so it can succeed even if config or enrollment
/// would later fail.
fn handle_short_flags<I: IntoIterator<Item = String>>(args: I) -> Option<i32> {
    for arg in args.into_iter().skip(1) {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("sda-agent {}", env!("CARGO_PKG_VERSION"));
                return Some(0);
            }
            "--help" | "-h" => {
                println!(
                    "sda-agent {}\n\nUSAGE:\n    sda-agent [CONFIG_PATH]\n\nFLAGS:\n    -h, --help       Print this help\n    -V, --version    Print version and exit",
                    env!("CARGO_PKG_VERSION")
                );
                return Some(0);
            }
            _ => {}
        }
    }
    None
}

/// First positional (non-flag) argument, if any. Used to pull a
/// config path off the command line while still allowing flag-style
/// invocations.
fn first_positional_arg<I: IntoIterator<Item = String>>(args: I) -> Option<String> {
    args.into_iter().skip(1).find(|arg| !arg.starts_with('-'))
}

/// Wire the enhanced-inventory → device-control software-inventory
/// bridge (Task 1.10).
///
/// The `device_control_bridge_enabled` flag on
/// `EnhancedInventoryConfig` is `#[serde(default, skip)]` and is
/// intentionally not exposed in the YAML schema. Instead, it is
/// derived here from the two flags an operator already controls:
/// when both Device Control and the running-software inventory tick
/// are enabled, the enhanced-inventory module additionally publishes
/// `EventKind::SoftwareInventoryDelta` events alongside the existing
/// `EnhancedInventoryUpdate` (`docs/architecture.md` § 2.3 — EDR
/// modules). Disabling either
/// flag disables the bridge.
fn apply_device_control_bridge(config: &mut AgentConfig) {
    config
        .modules
        .enhanced_inventory
        .device_control_bridge_enabled = config.modules.device_control.enabled
        && config.modules.enhanced_inventory.running_software.enabled;
}

#[cfg(test)]
mod bridge_tests {
    use super::apply_device_control_bridge;
    use sda_core::config::AgentConfig;

    #[test]
    fn bridge_enabled_when_device_control_and_running_software_both_on() {
        let mut config = AgentConfig::default();
        config.modules.device_control.enabled = true;
        config.modules.enhanced_inventory.running_software.enabled = true;
        apply_device_control_bridge(&mut config);
        assert!(
            config
                .modules
                .enhanced_inventory
                .device_control_bridge_enabled
        );
    }

    #[test]
    fn bridge_disabled_when_device_control_off() {
        let mut config = AgentConfig::default();
        config.modules.device_control.enabled = false;
        config.modules.enhanced_inventory.running_software.enabled = true;
        apply_device_control_bridge(&mut config);
        assert!(
            !config
                .modules
                .enhanced_inventory
                .device_control_bridge_enabled
        );
    }

    #[test]
    fn bridge_disabled_when_running_software_off() {
        let mut config = AgentConfig::default();
        config.modules.device_control.enabled = true;
        config.modules.enhanced_inventory.running_software.enabled = false;
        apply_device_control_bridge(&mut config);
        assert!(
            !config
                .modules
                .enhanced_inventory
                .device_control_bridge_enabled
        );
    }

    #[test]
    fn bridge_clears_stale_true_when_either_flag_off() {
        // Defence in depth: even if a future config-load path
        // pre-sets the flag, the gating logic must still take
        // precedence. This is the regression case for the bot's
        // finding — without `apply_device_control_bridge`, the flag
        // would stay at whatever it was deserialised to.
        let mut config = AgentConfig::default();
        config.modules.device_control.enabled = false;
        config.modules.enhanced_inventory.running_software.enabled = true;
        config
            .modules
            .enhanced_inventory
            .device_control_bridge_enabled = true;
        apply_device_control_bridge(&mut config);
        assert!(
            !config
                .modules
                .enhanced_inventory
                .device_control_bridge_enabled
        );
    }
}

#[cfg(all(test, feature = "legacy-siem"))]
mod tests {
    use super::*;
    use sda_comms::protocol::MessageType;
    use sda_event_bus::{Event, EventKind, Priority};

    #[test]
    fn test_file_created_maps_to_syscheck_with_payload() {
        let syscheck_json = r#"{"type":"event","data":{"path":"/etc/passwd","mode":"realtime","type":"added","changed_attributes":[],"old_attributes":{},"new_attributes":{"size":1024}}}"#.to_string();
        let kind = EventKind::FileCreated {
            path: "/etc/passwd".to_string(),
            syscheck_payload: Some(syscheck_json.clone()),
        };
        let msg = map_event_to_message("001", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Syscheck);
        assert_eq!(msg.agent_id, "001");
        assert_eq!(msg.payload, syscheck_json);
    }

    #[test]
    fn test_file_created_without_syscheck_payload_falls_back() {
        let kind = EventKind::FileCreated {
            path: "/etc/passwd".to_string(),
            syscheck_payload: None,
        };
        let msg = map_event_to_message("001", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Syscheck);
        assert!(msg.payload.contains("/etc/passwd"));
    }

    #[test]
    fn test_file_modified_maps_to_syscheck_with_payload() {
        let syscheck_json = r#"{"type":"event","data":{"path":"/etc/shadow","mode":"realtime","type":"modified","changed_attributes":["sha256"],"old_attributes":{},"new_attributes":{}}}"#.to_string();
        let kind = EventKind::FileModified {
            path: "/etc/shadow".to_string(),
            syscheck_payload: Some(syscheck_json.clone()),
        };
        let msg = map_event_to_message("002", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Syscheck);
        assert_eq!(msg.payload, syscheck_json);
    }

    #[test]
    fn test_file_deleted_maps_to_syscheck_with_payload() {
        let syscheck_json = r#"{"type":"event","data":{"path":"/tmp/gone.txt","mode":"realtime","type":"deleted","changed_attributes":[],"old_attributes":{"size":100},"new_attributes":{}}}"#.to_string();
        let kind = EventKind::FileDeleted {
            path: "/tmp/gone.txt".to_string(),
            syscheck_payload: Some(syscheck_json.clone()),
        };
        let msg = map_event_to_message("003", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Syscheck);
        assert_eq!(msg.payload, syscheck_json);
    }

    #[test]
    fn test_file_metadata_changed_maps_to_syscheck_with_payload() {
        let syscheck_json = r#"{"type":"event","data":{"path":"/usr/bin/test","mode":"realtime","type":"modified","changed_attributes":["perm"],"old_attributes":{},"new_attributes":{}}}"#.to_string();
        let kind = EventKind::FileMetadataChanged {
            path: "/usr/bin/test".to_string(),
            syscheck_payload: Some(syscheck_json.clone()),
        };
        let msg = map_event_to_message("004", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Syscheck);
        assert_eq!(msg.payload, syscheck_json);
    }

    #[test]
    fn test_log_collected_maps_to_log_wire_format() {
        let kind = EventKind::LogCollected {
            source: "/var/log/auth.log".to_string(),
            message: "Failed password for root from 10.0.0.1 port 22 ssh2".to_string(),
            format: "syslog".to_string(),
        };
        let msg = map_event_to_message("005", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Log);
        assert_eq!(
            msg.payload,
            "/var/log/auth.log:Failed password for root from 10.0.0.1 port 22 ssh2"
        );
        let encoded = String::from_utf8(msg.encode()).unwrap();
        assert!(encoded.starts_with("005:log:"));
    }

    #[test]
    fn test_inventory_maps_to_syscollector() {
        let kind = EventKind::InventoryUpdate {
            category: "packages".to_string(),
            data: serde_json::json!({"name": "vim"}),
        };
        let msg = map_event_to_message("006", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Syscollector);
    }

    #[test]
    fn test_sca_maps_to_sca() {
        let kind = EventKind::ScaResult {
            policy_id: "cis_ubuntu".to_string(),
            check_id: "1001".to_string(),
            result: "passed".to_string(),
        };
        let msg = map_event_to_message("007", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Sca);
    }

    #[test]
    fn test_active_response_maps_to_active_response() {
        let kind = EventKind::ActiveResponseResult {
            action: "block_ip".to_string(),
            success: true,
            output: "blocked".to_string(),
        };
        let msg = map_event_to_message("008", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::ActiveResponse);
    }

    #[test]
    fn test_server_message_maps_to_generic() {
        let kind = EventKind::ServerMessage {
            payload: "raw payload".to_string(),
        };
        let msg = map_event_to_message("009", &kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Generic);
        assert_eq!(msg.payload, "raw payload");
    }

    #[test]
    fn test_keepalive_not_forwarded() {
        let kind = EventKind::Keepalive;
        assert!(map_event_to_message("010", &kind).is_none());
    }

    #[test]
    fn test_shutdown_not_forwarded() {
        let kind = EventKind::Shutdown;
        assert!(map_event_to_message("010", &kind).is_none());
    }

    #[test]
    fn test_config_reloaded_not_forwarded() {
        let kind = EventKind::ConfigReloaded;
        assert!(map_event_to_message("010", &kind).is_none());
    }

    #[test]
    fn test_parse_server_command_execd() {
        let payload = r#"#!-execd {"command":"firewall-drop0","parameters":{"ip":"10.0.0.1"}}"#;
        let (command, body) = parse_server_command(payload);
        assert_eq!(command, "execd");
        assert!(body.starts_with("#!-execd"));
        assert!(body.contains("firewall-drop0"));
    }

    #[test]
    fn test_parse_server_command_request() {
        let (command, body) = parse_server_command("#!-req 1234 getconfig");
        assert_eq!(command, "request");
        assert_eq!(body, "#!-req 1234 getconfig");
    }

    #[test]
    fn test_parse_server_command_generic() {
        let (command, body) = parse_server_command("hello world\n");
        assert_eq!(command, "generic");
        assert_eq!(body, "hello world");
    }

    #[test]
    fn test_parse_server_command_strips_trailing_nulls() {
        let payload = "#!-execd {\"command\":\"noop\"}\0\0\0";
        let (command, body) = parse_server_command(payload);
        assert_eq!(command, "execd");
        assert!(!body.ends_with('\0'));
    }

    #[tokio::test]
    async fn test_event_forwarding_via_bus() {
        let (bus, mut server_rx) = sda_event_bus::EventBus::new(64, 64);
        let syscheck_json = r#"{"type":"event","data":{"path":"/etc/test.conf","mode":"realtime","type":"added","changed_attributes":[],"old_attributes":{},"new_attributes":{"size":512}}}"#.to_string();

        let event = Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileCreated {
                path: "/etc/test.conf".to_string(),
                syscheck_payload: Some(syscheck_json.clone()),
            },
        );
        bus.publish_to_server(event).await.unwrap();

        let received = server_rx.recv().await.unwrap();
        let msg = map_event_to_message("001", &received.kind).unwrap();
        assert_eq!(msg.msg_type, MessageType::Syscheck);
        assert_eq!(msg.agent_id, "001");
        assert_eq!(msg.payload, syscheck_json);

        let encoded = String::from_utf8(msg.encode()).unwrap();
        assert!(encoded.starts_with("001:syscheck:"));
        assert!(encoded.contains(r#""type":"event""#));
    }
}
