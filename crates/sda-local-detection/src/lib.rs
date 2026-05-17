//! Local Detection Engine (LDE) for the SN360 Desktop Agent.
//!
//! Evaluates detection rules locally at the edge — IOC matching via
//! Aho-Corasick + bloom filters, behavioural rule state machines, and
//! YARA file scanning — without a server round-trip.  All findings are
//! republished on the shared event bus as
//! [`EventKind::LocalDetectionAlert`](sda_event_bus::EventKind::LocalDetectionAlert)
//! and, when the server is unreachable, spooled to the on-disk offline
//! queue.
//!
//! The module follows the same lifecycle pattern as
//! `sda_rootcheck::RootcheckModule`: an `AtomicU8` status, a
//! [`ModuleHandle`] returned from `start()`, and a `tokio::select!`
//! loop driven by a [`ShutdownSignal`].

pub mod behavioral;
pub mod default_bundle;
pub mod ioc_matcher;
pub mod offline_queue;
pub mod response;
pub mod rule_store;
pub mod trds_client;
pub mod yara_scanner;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;

use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use sda_core::config::{AgentConfig, LocalDetectionConfig};
use sda_core::module::{AgentModule, ModuleHandle, ModuleHealth, ModuleStatus};
use sda_core::signal::ShutdownSignal;
use sda_event_bus::{Event, EventBus, EventKind, EventReceiver, Priority};

use crate::behavioral::{BehavioralEngine, BehavioralEvent, BehavioralMatch, ProcessFields};
use crate::ioc_matcher::{IocMatch, IocMatcher};
use crate::offline_queue::OfflineQueue;
use crate::response::LocalResponder;
use crate::rule_store::{IocList, RuleBundle};
use crate::trds_client::{verify_envelope, SigningKey, TrdsClient, TrdsError};
use crate::yara_scanner::{YaraMatch, YaraScanner};

const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// Local Detection Engine module handle.
pub struct LocalDetectionModule {
    status: Arc<AtomicU8>,
}

impl LocalDetectionModule {
    /// Spawn the LDE run loop and return a [`ModuleHandle`].
    pub fn start(config: &AgentConfig, bus: EventBus, shutdown: ShutdownSignal) -> ModuleHandle {
        let lde_config = config.modules.local_detection.clone();
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);

        let task = tokio::spawn(async move {
            if let Err(e) = run(lde_config, bus, shutdown, task_status.clone()).await {
                error!(error = %e, "local detection module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });

        ModuleHandle::new("local_detection", task)
    }
}

impl Default for LocalDetectionModule {
    fn default() -> Self {
        Self {
            status: Arc::new(AtomicU8::new(STATUS_INITIALIZED)),
        }
    }
}

impl AgentModule for LocalDetectionModule {
    fn name(&self) -> &'static str {
        "local_detection"
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

/// The detection pipeline the run loop drives on every incoming event.
struct DetectionPipeline {
    iocs: IocMatcher,
    behavioral: Mutex<BehavioralEngine>,
    yara: YaraScanner,
    responder: LocalResponder,
    offline: OfflineQueue,
    bundle_version: u64,
}

impl DetectionPipeline {
    fn new(config: &LocalDetectionConfig, bundle: RuleBundle) -> anyhow::Result<Self> {
        let iocs = IocMatcher::build(&bundle.iocs, config.bloom_filter_fpr)?;
        let behavioral = Mutex::new(BehavioralEngine::new(
            bundle.behavioral.clone(),
            config.behavioral_max_tracked_entities,
            config.behavioral_max_window_sec,
        ));
        let yara = YaraScanner::new(
            &bundle.yara_paths,
            config.yara_scan_rate_limit,
            config.yara_max_file_size_mb,
        )
        .unwrap_or_else(|e| {
            warn!(error = %e, "falling back to empty YARA scanner");
            YaraScanner::empty(config.yara_scan_rate_limit, config.yara_max_file_size_mb)
        });
        let responder = LocalResponder::new(config.clone());
        let offline = OfflineQueue::open(&config.offline_queue_path, config.offline_queue_max)
            .unwrap_or_else(|e| {
                warn!(
                    path = %config.offline_queue_path.display(),
                    error = %e,
                    "falling back to in-memory offline queue"
                );
                OfflineQueue::in_memory(config.offline_queue_max)
                    .expect("in-memory sqlite creation")
            });
        Ok(Self {
            iocs,
            behavioral,
            yara,
            responder,
            offline,
            bundle_version: bundle.version,
        })
    }
}

/// Build the initial rule bundle from `config.rule_bundle_path`.  A
/// missing or unreadable bundle is *not* fatal — we degrade gracefully
/// to the embedded [`default_bundle`](crate::default_bundle::default_bundle)
/// so the run loop can still serve as a baseline detector while waiting
/// for the first TRDS pull (Phase E2.4).
fn load_initial_bundle(path: &std::path::Path) -> RuleBundle {
    match RuleBundle::load(path) {
        Ok(b) => {
            info!(
                path = %path.display(),
                version = b.version,
                strings = b.iocs.strings.len(),
                hashes = b.iocs.hashes.len(),
                ips = b.iocs.ips.len(),
                behavioral = b.behavioral.len(),
                yara = b.yara_paths.len(),
                "loaded LDE rule bundle"
            );
            b
        }
        Err(e) => {
            let b = default_bundle::default_bundle();
            warn!(
                path = %path.display(),
                error = %e,
                fallback_version = b.version,
                fallback_rules = b.behavioral.len(),
                "LDE rule bundle unavailable; falling back to embedded default baseline"
            );
            b
        }
    }
}

async fn publish_alert(bus: &EventBus, alert: &LocalAlert, offline: &OfflineQueue) {
    let kind = EventKind::LocalDetectionAlert {
        rule_id: alert.rule_id.clone(),
        rule_type: alert.rule_type.to_string(),
        severity: alert.severity.clone(),
        description: alert.description.clone(),
        matched_value: alert.matched_value.clone(),
    };
    let event = Event::new("local_detection", Priority::Normal, kind.clone());
    match bus.publish_to_server(event).await {
        Ok(()) => {}
        Err(e) => {
            warn!(error = %e, "server-bound publish failed; spooling to offline queue");
            if let Ok(payload) = serde_json::to_string(&kind) {
                if let Err(qe) = offline.enqueue(&payload) {
                    warn!(error = %qe, "offline queue enqueue failed");
                }
            }
        }
    }
}

/// Replay up to `batch` detection payloads from the offline queue back
/// to the server.  Uses `peek_batch` + `ack` rather than a destructive
/// `drain`: rows remain on disk with their original ids until a publish
/// succeeds, so a mid-batch failure leaves every unsent payload at the
/// head of the queue in its original order.  On the first publish error
/// we stop and return — the next tick retries from where this one left
/// off with strict FIFO semantics preserved across batches.
async fn drain_offline_queue(offline: &OfflineQueue, bus: &EventBus, batch: usize) {
    let items = match offline.peek_batch(batch) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "offline queue peek failed");
            return;
        }
    };
    if items.is_empty() {
        return;
    }
    let peeked = items.len();
    let mut replayed = 0usize;
    for item in items {
        let kind: EventKind = match serde_json::from_str(&item.payload) {
            Ok(k) => k,
            Err(e) => {
                warn!(error = %e, id = item.id, "discarding corrupt offline payload");
                if let Err(ae) = offline.ack(item.id) {
                    warn!(error = %ae, id = item.id, "offline queue ack failed");
                }
                continue;
            }
        };
        let event = Event::new("local_detection", Priority::Normal, kind);
        if let Err(e) = bus.publish_to_server(event).await {
            warn!(
                error = %e,
                unsent = peeked - replayed,
                "offline replay failed; leaving remaining batch on disk for the next tick"
            );
            break;
        }
        // Ack only after the publish succeeds.  If ack itself fails the
        // row stays on disk and will be replayed next tick (duplicate
        // delivery is strictly preferable to silent loss here).
        if let Err(ae) = offline.ack(item.id) {
            warn!(error = %ae, id = item.id, "offline queue ack failed after replay");
        }
        replayed += 1;
    }
    if replayed > 0 {
        debug!(peeked, replayed, "offline queue drain tick completed");
    }
}

/// A uniform alert shape shared by IOC, behavioural and YARA matches.
#[derive(Debug, Clone)]
struct LocalAlert {
    rule_id: String,
    rule_type: &'static str,
    severity: String,
    description: String,
    matched_value: String,
}

impl From<IocMatch> for LocalAlert {
    fn from(m: IocMatch) -> Self {
        Self {
            rule_id: m.rule_id,
            rule_type: m.rule_type,
            severity: m.severity,
            description: m.description,
            matched_value: m.matched_value,
        }
    }
}

impl From<BehavioralMatch> for LocalAlert {
    fn from(m: BehavioralMatch) -> Self {
        Self {
            rule_id: m.rule_id,
            rule_type: "behavioral",
            severity: m.severity,
            description: m.description,
            matched_value: m.entity,
        }
    }
}

impl LocalAlert {
    fn from_yara(path: &std::path::Path, m: YaraMatch, severity: &str) -> Self {
        Self {
            rule_id: m.rule_id.clone(),
            rule_type: "yara",
            severity: severity.to_string(),
            description: format!("YARA rule {} matched file", m.rule_id),
            matched_value: path.to_string_lossy().into_owned(),
        }
    }
}

/// Handle a single inbound event by running it through every rule
/// backend and firing alerts for each hit.
async fn handle_event(pipeline: &DetectionPipeline, bus: &EventBus, event: &Event) {
    // Per-event structured process metadata.  Set only by the
    // `ProcessCreated` arm below; the ProcessChain behavioural
    // matcher reads `parent_chain` and `leaf_name` from
    // `BehavioralEvent::process` rather than parsing the composite
    // `primary_text`.  Phase E3 review fix: lifting these out of the
    // free-form text avoids the `rfind(" > ")` ambiguity when a
    // cmdline contains a literal `>` (PowerShell `-Command`, shell
    // redirects, build scripts).
    let mut process_parent_chain: Option<String> = None;
    let mut process_leaf_name: Option<String> = None;

    // Extract the interesting fields from the event kind.
    let (source_tag, entity, primary_text, fim_path, sha256, ips): (
        &str,
        String,
        String,
        Option<PathBuf>,
        Option<String>,
        Vec<String>,
    ) = match &event.kind {
        EventKind::FileCreated {
            path,
            syscheck_payload,
        }
        | EventKind::FileModified {
            path,
            syscheck_payload,
        } => (
            "fim",
            path.clone(),
            path.clone(),
            Some(PathBuf::from(path)),
            extract_sha256_from_syscheck(syscheck_payload.as_deref()),
            Vec::new(),
        ),
        EventKind::FileDeleted {
            path,
            syscheck_payload,
        }
        | EventKind::FileMetadataChanged {
            path,
            syscheck_payload,
        } => (
            "fim",
            path.clone(),
            path.clone(),
            None,
            extract_sha256_from_syscheck(syscheck_payload.as_deref()),
            Vec::new(),
        ),
        EventKind::LogCollected {
            source, message, ..
        } => (
            "logcollector",
            source.clone(),
            message.clone(),
            None,
            None,
            extract_ipv4s(message),
        ),

        // --- EDR Parity event arms (Phase E1-E3) ---
        // Process create: feed `exe_path` as the entity and the
        // joined parent-chain text as primary_text so behavioural
        // rules can match against the full ancestor history.
        EventKind::ProcessCreated { payload } => {
            let parsed: serde_json::Value = serde_json::from_str(payload).unwrap_or_default();
            let name = parsed
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let exe_path = parsed
                .get("exe_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let entity = if !exe_path.is_empty() {
                exe_path
            } else {
                name.clone()
            };
            let cmdline = parsed
                .get("cmdline")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();
            let parent_chain = parsed
                .get("parent_chain")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.get("name").and_then(|n| n.as_str()))
                        .collect::<Vec<_>>()
                        .join(" > ")
                })
                .unwrap_or_default();
            let primary_text = if parent_chain.is_empty() {
                format!("{name} {cmdline}").trim().to_string()
            } else {
                format!("{parent_chain} > {name} {cmdline}")
                    .trim()
                    .to_string()
            };
            // Surface the structured process fields for the
            // ProcessChain behavioural matcher.  We keep
            // `primary_text` as the full composite string so the
            // string-IOC and Threshold/Sequence matchers continue
            // to see the chain + cmdline (their semantics are
            // unchanged), but ProcessChain now reads from
            // `BehavioralEvent::process` and is no longer sensitive
            // to a `" > "` substring inside cmdline.
            process_parent_chain = Some(parent_chain);
            process_leaf_name = Some(name);
            // Distinct source tags for each process event kind so
            // behavioural rules (notably ProcessChain) can pin
            // themselves to ProcessCreated explicitly — see Phase
            // E5 review note: ProcessChain rules must not fire on
            // ProcessTerminated / ImageLoaded payloads even though
            // they share the same underlying domain.
            (
                "process_created",
                entity,
                primary_text,
                None,
                None,
                Vec::new(),
            )
        }
        EventKind::ProcessTerminated { payload } => {
            let parsed: serde_json::Value = serde_json::from_str(payload).unwrap_or_default();
            let name = parsed
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let exit_code = parsed
                .get("exit_code")
                .and_then(|v| v.as_i64())
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into());
            (
                "process_terminated",
                name.clone(),
                format!("terminated exit_code={exit_code}"),
                None,
                None,
                Vec::new(),
            )
        }
        EventKind::ImageLoaded { payload } => {
            let parsed: serde_json::Value = serde_json::from_str(payload).unwrap_or_default();
            let image_path = parsed
                .get("image_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let image_hash = parsed
                .get("image_hash")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            (
                "process_image_loaded",
                image_path.clone(),
                image_path,
                None,
                image_hash,
                Vec::new(),
            )
        }
        EventKind::NetworkConnection { payload } => {
            let parsed: serde_json::Value = serde_json::from_str(payload).unwrap_or_default();
            let process_name = parsed
                .get("process_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let remote_addr = parsed
                .get("remote_addr")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let remote_port = parsed
                .get("remote_port")
                .and_then(|v| v.as_u64())
                .map(|p| p.to_string())
                .unwrap_or_else(|| "?".into());
            let ips = if !remote_addr.is_empty() {
                vec![remote_addr.clone()]
            } else {
                Vec::new()
            };
            (
                "network",
                process_name,
                format!("{remote_addr}:{remote_port}"),
                None,
                None,
                ips,
            )
        }
        EventKind::DnsQuery { payload } => {
            let parsed: serde_json::Value = serde_json::from_str(payload).unwrap_or_default();
            let query_name = parsed
                .get("query_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let process_name = parsed
                .get("process_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let response_ips = parsed
                .get("response_ips")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            ("dns", process_name, query_name, None, None, response_ips)
        }

        // Other event kinds pass through untouched.
        _ => return,
    };

    // --- IOC matching (string, hash, IP backends) ---
    let mut ioc_hits = pipeline
        .iocs
        .matches(&[&primary_text], sha256.as_deref(), None);
    // Probe every IP found in the log message against the IP bloom.
    for ip in &ips {
        if let Some(m) = pipeline.iocs.match_ip(ip) {
            ioc_hits.push(m);
        }
    }
    for hit in ioc_hits {
        let alert: LocalAlert = hit.into();
        maybe_respond(pipeline, &alert, fim_path.as_deref()).await;
        publish_alert(bus, &alert, &pipeline.offline).await;
    }

    // --- Behavioural rules ---
    let behavioral_hits = {
        let mut engine = pipeline.behavioral.lock().await;
        // ProcessChain matchers consume `parent_chain` and `leaf_name`
        // as separate fields so a literal `>` inside cmdline (shell
        // redirect, PowerShell `-Command`, build script) cannot
        // collide with the chain→leaf boundary parser that used to
        // live in `split_chain_and_leaf`.  Other rule kinds read
        // `text` as before.
        let process = match (
            process_parent_chain.as_deref(),
            process_leaf_name.as_deref(),
        ) {
            (Some(parent_chain), Some(leaf_name)) => Some(ProcessFields {
                parent_chain,
                leaf_name,
            }),
            _ => None,
        };
        engine.evaluate(&BehavioralEvent {
            source: source_tag,
            entity: &entity,
            text: &primary_text,
            process,
        })
    };
    for hit in behavioral_hits {
        let alert: LocalAlert = hit.into();
        maybe_respond(pipeline, &alert, fim_path.as_deref()).await;
        publish_alert(bus, &alert, &pipeline.offline).await;
    }

    // --- YARA on FIM-created/modified files ---
    if let Some(path) = fim_path {
        if pipeline.yara.has_rules() {
            match pipeline.yara.scan_file(&path).await {
                Ok(hits) => {
                    for m in hits {
                        let alert = LocalAlert::from_yara(&path, m, rule_store::SEV_HIGH);
                        maybe_respond(pipeline, &alert, Some(&path)).await;
                        publish_alert(bus, &alert, &pipeline.offline).await;
                    }
                }
                Err(e) => warn!(path = %path.display(), error = %e, "YARA scan failed"),
            }
        }
    }
}

/// Dispatch local responses for a finalised alert, when enabled by
/// configuration.
async fn maybe_respond(
    pipeline: &DetectionPipeline,
    alert: &LocalAlert,
    fim_path: Option<&std::path::Path>,
) {
    // IP-matched IOCs may warrant a block.
    if alert.rule_type == "ip" {
        let outcome = pipeline.responder.block_ip(&alert.matched_value).await;
        debug!(rule = %alert.rule_id, outcome = ?outcome, "block_ip response");
    }
    // YARA matches on a file path may warrant quarantine.
    if alert.rule_type == "yara" {
        if let Some(path) = fim_path {
            let outcome = pipeline.responder.quarantine(path).await;
            debug!(rule = %alert.rule_id, path = %path.display(), outcome = ?outcome, "quarantine response");
        }
    }
}

/// Atomic-swap container for the active [`DetectionPipeline`].
///
/// `handle_event` reads through a brief read-lock to clone the inner
/// `Arc<DetectionPipeline>` and then runs against that snapshot.
/// Hot-reload takes a write-lock just long enough to publish the new
/// `Arc` — in-flight evaluations always complete against the pipeline
/// they started with.  This mirrors the
/// `UsbPolicySupervisor::apply_bundle_slice` CAS pattern used by
/// `sda-device-control`.
type PipelineCell = StdRwLock<Arc<DetectionPipeline>>;

fn pipeline_load(cell: &PipelineCell) -> Arc<DetectionPipeline> {
    cell.read().expect("LDE pipeline RwLock poisoned").clone()
}

fn pipeline_store(cell: &PipelineCell, new: Arc<DetectionPipeline>) {
    *cell.write().expect("LDE pipeline RwLock poisoned") = new;
}

/// Parse the configured signing-key entries into [`SigningKey`]s.
///
/// Each input entry is one of:
///
/// 1. `"<key_id>:<hex>"` — explicit rotation id, e.g.
///    `"edr-2026-q2:5d3e…"`.  The first `:` separates the id from
///    the 64-character lower-case hex pubkey.  This is the form a
///    TRDS server publishes against, so production deployments
///    should always use it.
/// 2. `"<hex>"` — legacy bare-hex form.  The LDE assigns an
///    auto-generated id of `"rotation-{i}"` (i = position in the
///    list).  Envelopes from a TRDS server cannot match these
///    auto-ids, so this form is only useful for trust bootstrapping
///    when the rotation namespace is empty.
///
/// Bad entries are logged-and-dropped rather than fatal so a single
/// typo can't take the LDE offline.
fn build_signing_keys(entries: &[String]) -> Vec<SigningKey> {
    entries
        .iter()
        .enumerate()
        .filter_map(|(i, raw)| {
            let (key_id, public_hex) = match raw.split_once(':') {
                Some((id, hex)) if !id.is_empty() && !hex.is_empty() => {
                    (id.to_string(), hex.to_string())
                }
                _ => (format!("rotation-{i}"), raw.clone()),
            };
            let key = SigningKey { key_id, public_hex };
            match key.verifying_key() {
                Ok(_) => Some(key),
                Err(e) => {
                    warn!(error = %e, "skipping invalid LDE signing key");
                    None
                }
            }
        })
        .collect()
}

/// Attempt a single TRDS pull and atomic pipeline swap.  Returns the
/// version actually installed, or the unchanged `current_version` if
/// nothing changed / the pull failed.
///
/// On signature / key-id / version-substitution failures we emit a
/// High-severity `LocalDetectionAlert` so SIEM operators see the
/// rejection, but the live pipeline is preserved (last-known-good).
async fn pull_and_install(
    client: &TrdsClient,
    keys: &[SigningKey],
    config: &LocalDetectionConfig,
    bus: &EventBus,
    pipeline_cell: &Arc<PipelineCell>,
    current_version: u64,
) -> u64 {
    let envelope = match client.fetch_envelope(current_version).await {
        Ok(Some(env)) => env,
        Ok(None) => {
            debug!(current_version, "TRDS reports no newer bundle");
            return current_version;
        }
        Err(e) => {
            warn!(error = %e, "TRDS pull failed; keeping last-known-good pipeline");
            return current_version;
        }
    };

    if envelope.version <= current_version {
        debug!(
            envelope_version = envelope.version,
            current_version, "TRDS returned non-newer envelope; ignoring"
        );
        return current_version;
    }

    let verified = match verify_envelope(&envelope, keys) {
        Ok(v) => v,
        Err(e) => {
            let security = e.is_security_alert();
            warn!(error = %e, security, "TRDS bundle rejected; keeping last-known-good pipeline");
            if security {
                publish_bundle_security_alert(bus, &e).await;
            }
            return current_version;
        }
    };

    let new_pipeline = match DetectionPipeline::new(config, verified.bundle.clone()) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "failed to build pipeline from verified bundle");
            return current_version;
        }
    };
    let new_version = new_pipeline.bundle_version;
    let new_rule_count = new_pipeline.iocs.rule_count();
    // Emit one `LocalDetectionAlert` per behavioural rule the new
    // pipeline refused to load (invalid regex), then publish it so
    // the LDE keeps the rest of the bundle live.  We drain *before*
    // `pipeline_store` so subsequent `pipeline_load()` callers see a
    // freshly-drained engine (no stale `skipped_rules` queued for
    // re-publication on every event).
    publish_skipped_rule_alerts(bus, &new_pipeline, new_version).await;
    pipeline_store(pipeline_cell, Arc::new(new_pipeline));
    info!(
        version = new_version,
        rules = new_rule_count,
        key_id = %verified.key_id,
        "LDE pipeline hot-reloaded from TRDS"
    );
    publish_bundle_applied_alert(bus, new_version).await;
    new_version
}

async fn publish_bundle_applied_alert(bus: &EventBus, version: u64) {
    let kind = EventKind::LocalDetectionAlert {
        rule_id: "system.trds.applied".into(),
        rule_type: "system".into(),
        severity: "info".into(),
        description: format!("LDE rule bundle v{version} applied"),
        matched_value: version.to_string(),
    };
    let event = Event::new("local_detection", Priority::Low, kind);
    if let Err(e) = bus.publish_to_server(event).await {
        debug!(error = %e, "best-effort bundle-applied notice dropped");
    }
}

async fn publish_bundle_security_alert(bus: &EventBus, err: &TrdsError) {
    let kind = EventKind::LocalDetectionAlert {
        rule_id: "system.trds.rejected".into(),
        rule_type: "system".into(),
        severity: "high".into(),
        description: format!("LDE rejected TRDS bundle: {err}"),
        matched_value: format!("{err:?}"),
    };
    let event = Event::new("local_detection", Priority::High, kind);
    if let Err(e) = bus.publish_to_server(event).await {
        warn!(error = %e, "failed to publish TRDS rejection alert");
    }
}

/// Drain `behavioural_engine.take_skipped_rules()` and publish one
/// `LocalDetectionAlert` per permanently-disabled rule.
///
/// Without this, an operator would only see the startup `warn!`
/// trace line (easy to miss in a busy log) when a TRDS-pushed
/// regex fails to compile, and the rule would silently never fire.
/// Surfacing each skip as a `severity = "high"` system alert in the
/// SIEM matches the visibility we already provide for TRDS bundle
/// rejection (`publish_bundle_security_alert`).
async fn publish_skipped_rule_alerts(bus: &EventBus, pipeline: &DetectionPipeline, version: u64) {
    let skipped = pipeline.behavioral.lock().await.take_skipped_rules();
    if skipped.is_empty() {
        return;
    }
    warn!(
        count = skipped.len(),
        bundle_version = version,
        "LDE: behavioural rules permanently disabled at bundle load due to invalid regex"
    );
    for rule in skipped {
        let kind = EventKind::LocalDetectionAlert {
            rule_id: "system.lde.rule_disabled".into(),
            rule_type: "system".into(),
            severity: "high".into(),
            description: format!(
                "LDE rule {} permanently disabled at bundle v{version} load: {}",
                rule.rule_id, rule.reason,
            ),
            matched_value: rule.rule_id.clone(),
        };
        let event = Event::new("local_detection", Priority::High, kind);
        if let Err(e) = bus.publish_to_server(event).await {
            warn!(
                error = %e,
                rule = %rule.rule_id,
                "failed to publish behavioural-rule disabled alert"
            );
        }
    }
}

/// Main LDE run loop.
async fn run(
    config: LocalDetectionConfig,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    info!(
        rule_bundle = %config.rule_bundle_path.display(),
        offline_queue = %config.offline_queue_path.display(),
        trds_endpoint = ?config.trds_endpoint,
        signing_keys = config.rule_bundle_signing_keys.len(),
        block_ip = config.block_ip,
        kill_process = config.kill_process,
        quarantine = config.quarantine,
        "local detection module starting"
    );

    let bundle = load_initial_bundle(&config.rule_bundle_path);
    let initial_pipeline = DetectionPipeline::new(&config, bundle)?;
    info!(
        rules = initial_pipeline.iocs.rule_count(),
        yara_loaded = initial_pipeline.yara.has_rules(),
        version = initial_pipeline.bundle_version,
        "local detection engine ready"
    );

    // Surface any behavioural rules that the engine refused to load
    // due to invalid regexes — see `publish_skipped_rule_alerts` for
    // the rationale.  We drain *before* moving the pipeline into the
    // `Arc<PipelineCell>` so the per-rule alerts are emitted exactly
    // once per bundle load, not once per pipeline_load().
    let initial_version = initial_pipeline.bundle_version;
    publish_skipped_rule_alerts(&bus, &initial_pipeline, initial_version).await;

    let pipeline_cell: Arc<PipelineCell> = Arc::new(StdRwLock::new(Arc::new(initial_pipeline)));

    let signing_keys = build_signing_keys(&config.rule_bundle_signing_keys);
    let trds_client = match &config.trds_endpoint {
        Some(endpoint) => {
            match TrdsClient::new(
                endpoint.clone(),
                Duration::from_secs(config.trds_pull_timeout_secs.max(1)),
            ) {
                Ok(c) => {
                    info!(endpoint, "TRDS hot-reload client armed");
                    Some(c)
                }
                Err(e) => {
                    warn!(error = %e, "TRDS client construction failed; hot-reload disabled");
                    None
                }
            }
        }
        None => None,
    };

    let mut rx: EventReceiver = bus.subscribe();
    status.store(STATUS_RUNNING, Ordering::Relaxed);

    // The first tick of `tokio::time::interval` fires immediately
    // — we deliberately keep this so the LDE attempts a TRDS pull at
    // startup, surfacing the freshest rules without waiting a full
    // pull cycle.  Without an endpoint configured the arm in the
    // `select!` below is effectively a no-op aside from a debug log.
    //
    // The hard floor is 1 second so the e2e hot-reload suite can
    // converge quickly (`e2e_lde_hotreload.rs` configures
    // `rule_pull_interval: 1`).  We separately warn at startup when
    // the configured value drops below `RULE_PULL_INTERVAL_WARN_SECS`
    // so an operator who fat-fingers `1` in production sees that
    // the agent is about to hammer their TRDS endpoint.
    const RULE_PULL_INTERVAL_WARN_SECS: u64 = 10;
    if config.rule_pull_interval < RULE_PULL_INTERVAL_WARN_SECS {
        warn!(
            configured = config.rule_pull_interval,
            recommended_floor = RULE_PULL_INTERVAL_WARN_SECS,
            "modules.local_detection.rule_pull_interval is below the recommended \
             floor; the LDE will poll the TRDS endpoint very aggressively. This is \
             intentional for the e2e hot-reload suite but should not be used in \
             production. Consider setting rule_pull_interval >= 30."
        );
    }
    let mut rule_pull_timer =
        tokio::time::interval(Duration::from_secs(config.rule_pull_interval.max(1)));

    // Spool-drain timer — attempts to replay any detection payloads
    // that were parked in the offline queue while the server was
    // unreachable.  Cadence is deliberately shorter than the rule-pull
    // interval so recovery is snappy once the server is back.
    let mut drain_timer =
        tokio::time::interval(Duration::from_secs(config.offline_drain_interval.max(5)));
    drain_timer.tick().await;
    let drain_batch_size = config.offline_drain_batch.max(1);

    loop {
        tokio::select! {
            biased;

            _ = shutdown.wait() => {
                info!("local detection module received shutdown signal");
                break;
            }

            event = rx.recv() => {
                let event = match event {
                    Some(ev) => ev,
                    None => {
                        warn!("event bus closed, stopping local detection module");
                        break;
                    }
                };
                let snapshot = pipeline_load(&pipeline_cell);
                handle_event(&snapshot, &bus, &event).await;
            }

            _ = drain_timer.tick() => {
                let snapshot = pipeline_load(&pipeline_cell);
                drain_offline_queue(&snapshot.offline, &bus, drain_batch_size).await;
            }

            _ = rule_pull_timer.tick() => {
                if let Some(client) = trds_client.as_ref() {
                    let current_version = pipeline_load(&pipeline_cell).bundle_version;
                    pull_and_install(
                        client,
                        &signing_keys,
                        &config,
                        &bus,
                        &pipeline_cell,
                        current_version,
                    )
                    .await;
                } else {
                    debug!("LDE rule pull timer fired but no TRDS endpoint configured");
                }
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!("local detection module stopped");
    Ok(())
}

/// Helper for building empty IOC lists — used by tooling that wants a
/// minimal pipeline.
pub fn empty_ioc_list() -> IocList {
    IocList::default()
}

/// Extract the SHA-256 digest from a Wazuh-syscheck JSON payload.
///
/// The syscheck daemon emits events like
/// `{"type":"event","data":{"path":"...","hash_sha256":"...", ...}}`.
/// We accept a handful of common field names (`hash_sha256`, `sha256`,
/// `sha256sum`) and return the lower-cased 64-character hex string when
/// found.  Anything else yields `None`, letting the caller skip the
/// hash backend cleanly.
fn extract_sha256_from_syscheck(payload: Option<&str>) -> Option<String> {
    let raw = payload?;
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let keys = ["hash_sha256", "sha256", "sha256sum", "sha256_after"];
    fn find<'a>(v: &'a serde_json::Value, keys: &[&str]) -> Option<&'a str> {
        for k in keys {
            if let Some(s) = v.get(*k).and_then(|x| x.as_str()) {
                return Some(s);
            }
        }
        None
    }
    let found = find(&v, &keys)
        .or_else(|| v.get("data").and_then(|d| find(d, &keys)))
        .or_else(|| {
            v.get("data")
                .and_then(|d| d.get("attributes"))
                .and_then(|a| find(a, &keys))
        })?;
    let lower = found.to_ascii_lowercase();
    if lower.len() == 64 && lower.bytes().all(|c| c.is_ascii_hexdigit()) {
        Some(lower)
    } else {
        None
    }
}

/// Scan free-form text for dotted-quad IPv4 literals.
///
/// Deliberately avoids a regex dependency — syslog lines rarely contain
/// more than a handful of candidates and a linear scan is more than
/// fast enough.  IPv6 extraction is intentionally out of scope until we
/// have a concrete detection use case for it.
fn extract_ipv4s(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut octets = 0usize;
            let mut digits = 0usize;
            let mut valid = true;
            while i < bytes.len() && octets < 4 {
                if bytes[i].is_ascii_digit() {
                    digits += 1;
                    if digits > 3 {
                        valid = false;
                        break;
                    }
                    i += 1;
                } else if bytes[i] == b'.' && digits > 0 && octets < 3 {
                    octets += 1;
                    digits = 0;
                    i += 1;
                } else {
                    break;
                }
            }
            if valid && octets == 3 && digits > 0 {
                // Reject candidates that are actually a prefix of a longer
                // dotted sequence (e.g. "1.2.3.4.5") — those aren't IPv4.
                let followed_by_dot_digit =
                    i + 1 < bytes.len() && bytes[i] == b'.' && bytes[i + 1].is_ascii_digit();
                let candidate = &text[start..i];
                if !followed_by_dot_digit && candidate.split('.').all(|o| o.parse::<u8>().is_ok()) {
                    out.push(candidate.to_string());
                    continue;
                }
            }
            // Advance past the partial run to avoid re-scanning the
            // same prefix on the next iteration.
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_store::{
        BehavioralRule, BehavioralRuleKind, HashIoc, IpIoc, StringIoc, SEV_HIGH, SEV_MEDIUM,
    };
    use sda_core::config::{AgentConfig, ModulesConfig};
    use sda_core::signal::ShutdownController;
    use sda_event_bus::EventBus;

    fn test_config(tmp: &tempfile::TempDir) -> LocalDetectionConfig {
        LocalDetectionConfig {
            enabled: true,
            rule_pull_interval: 3600,
            offline_queue_max: 100,
            yara_scan_rate_limit: 10,
            yara_max_file_size_mb: 10,
            bloom_filter_fpr: 0.01,
            behavioral_max_window_sec: 60,
            behavioral_max_tracked_entities: 100,
            block_ip: false,
            kill_process: false,
            quarantine: false,
            rule_bundle_path: tmp.path().join("bundle.msgpack"),
            offline_queue_path: tmp.path().join("queue.db"),
            quarantine_dir: tmp.path().join("quarantine"),
            offline_drain_interval: 30,
            offline_drain_batch: 64,
            trds_endpoint: None,
            rule_bundle_signing_keys: Vec::new(),
            trds_pull_timeout_secs: 10,
        }
    }

    fn bundle_with_string_ioc(value: &str) -> RuleBundle {
        let mut b = RuleBundle {
            version: 1,
            ..Default::default()
        };
        b.iocs.strings.push(StringIoc {
            id: "test-ioc".into(),
            value: value.into(),
            kind: "path".into(),
            severity: SEV_HIGH.into(),
            description: "unit test IOC".into(),
        });
        b
    }

    #[tokio::test]
    async fn test_module_lifecycle_starts_and_stops() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(&tmp);
        let agent_config = AgentConfig {
            modules: ModulesConfig {
                local_detection: cfg,
                ..Default::default()
            },
            ..Default::default()
        };

        let (bus, _server_rx) = EventBus::new(16, 16);
        let (controller, signal) = ShutdownController::new();

        let handle = LocalDetectionModule::start(&agent_config, bus, signal);
        assert_eq!(handle.name, "local_detection");

        tokio::time::sleep(Duration::from_millis(50)).await;
        controller.shutdown();

        tokio::time::timeout(Duration::from_secs(2), handle.task)
            .await
            .expect("LDE task did not stop within 2s")
            .expect("join error")
            .expect("LDE run returned Err");
    }

    #[tokio::test]
    async fn test_string_ioc_match_publishes_alert() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(&tmp);
        let bundle = bundle_with_string_ioc("/tmp/suspicious.exe");
        bundle.save(&cfg.rule_bundle_path).unwrap();

        let (bus, mut server_rx) = EventBus::new(16, 16);
        let pipeline = DetectionPipeline::new(&cfg, bundle).unwrap();
        let fim_event = Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileCreated {
                path: "/tmp/suspicious.exe".into(),
                syscheck_payload: None,
            },
        );
        handle_event(&pipeline, &bus, &fim_event).await;

        let ev = tokio::time::timeout(Duration::from_millis(200), server_rx.recv())
            .await
            .expect("expected an LDE alert")
            .expect("server_rx closed");
        match ev.kind {
            EventKind::LocalDetectionAlert {
                rule_id, rule_type, ..
            } => {
                assert_eq!(rule_id, "test-ioc");
                assert_eq!(rule_type, "string");
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_log_event_does_not_trigger_yara_scan() {
        // Regression — YARA must only scan FIM file-created/modified
        // events, not logcollector payloads that happen to look like
        // paths.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(&tmp);
        let bundle = RuleBundle::default();
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let pipeline = DetectionPipeline::new(&cfg, bundle).unwrap();
        let log_event = Event::new(
            "logcollector",
            Priority::Normal,
            EventKind::LogCollected {
                source: "sshd".into(),
                message: "login".into(),
                format: "syslog".into(),
            },
        );
        handle_event(&pipeline, &bus, &log_event).await;
        let maybe = tokio::time::timeout(Duration::from_millis(100), server_rx.recv()).await;
        assert!(maybe.is_err(), "no alerts expected on benign log");
    }

    #[tokio::test]
    async fn test_behavioral_threshold_produces_alert() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(&tmp);
        let mut bundle = RuleBundle::default();
        bundle.behavioral.push(BehavioralRule {
            id: "brute-ssh".into(),
            severity: SEV_MEDIUM.into(),
            description: "ssh brute".into(),
            event_source: "logcollector".into(),
            kind: BehavioralRuleKind::Threshold {
                contains: "auth failure".into(),
                min_count: 2,
                window_secs: 60,
            },
        });

        let (bus, mut server_rx) = EventBus::new(16, 16);
        let pipeline = DetectionPipeline::new(&cfg, bundle).unwrap();

        for _ in 0..2 {
            let ev = Event::new(
                "logcollector",
                Priority::Normal,
                EventKind::LogCollected {
                    source: "sshd".into(),
                    message: "sshd: auth failure for root".into(),
                    format: "syslog".into(),
                },
            );
            handle_event(&pipeline, &bus, &ev).await;
        }

        let ev = tokio::time::timeout(Duration::from_millis(200), server_rx.recv())
            .await
            .expect("expected behavioural alert")
            .expect("server_rx closed");
        match ev.kind {
            EventKind::LocalDetectionAlert { rule_type, .. } => {
                assert_eq!(rule_type, "behavioral");
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn test_pipeline_with_empty_bundle_builds() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(&tmp);
        let pipeline = DetectionPipeline::new(&cfg, RuleBundle::default()).unwrap();
        assert_eq!(pipeline.iocs.rule_count(), 0);
        assert!(!pipeline.yara.has_rules());
        assert_eq!(pipeline.bundle_version, 0);
    }

    #[test]
    fn test_load_initial_bundle_missing_falls_back_to_default() {
        // Phase E2.4: a missing on-disk bundle must fall back to the
        // embedded default bundle so the default-ON LDE has rules to
        // evaluate immediately.
        let b = load_initial_bundle(std::path::Path::new("/nonexistent"));
        assert_eq!(b.version, default_bundle::DEFAULT_BUNDLE_VERSION);
        assert!(!b.iocs.strings.is_empty());
        assert!(b.behavioral.len() >= 3);
    }

    #[test]
    fn test_local_detection_default_is_enabled() {
        // Phase E2.3: LDE ships default-on.
        let cfg = LocalDetectionConfig::default();
        assert!(cfg.enabled, "LDE must be default-on after Phase E2.3");
    }

    #[test]
    fn test_local_detection_default_trds_fields() {
        // Phase E2.1: TRDS endpoint is absent by default; signing keys
        // are an empty rotation set; the pull timeout has a sane default.
        let cfg = LocalDetectionConfig::default();
        assert!(cfg.trds_endpoint.is_none());
        assert!(cfg.rule_bundle_signing_keys.is_empty());
        assert!(cfg.trds_pull_timeout_secs >= 1);
    }

    #[test]
    fn test_local_alert_from_yara_uses_file_path() {
        let alert = LocalAlert::from_yara(
            std::path::Path::new("/tmp/x.bin"),
            YaraMatch {
                rule_id: "R".into(),
                tags: vec![],
            },
            SEV_HIGH,
        );
        assert_eq!(alert.matched_value, "/tmp/x.bin");
        assert_eq!(alert.rule_type, "yara");
        assert_eq!(alert.severity, SEV_HIGH);
    }

    #[test]
    fn test_extract_sha256_from_syscheck_top_level() {
        let payload = serde_json::json!({ "sha256": "A".repeat(64) }).to_string();
        let got = extract_sha256_from_syscheck(Some(&payload)).unwrap();
        assert_eq!(got.len(), 64);
        assert!(got.chars().all(|c| c == 'a'));
    }

    #[test]
    fn test_extract_sha256_from_syscheck_nested() {
        let payload = serde_json::json!({
            "type": "event",
            "data": { "path": "/etc/passwd", "hash_sha256": "b".repeat(64) }
        })
        .to_string();
        let got = extract_sha256_from_syscheck(Some(&payload)).unwrap();
        assert_eq!(got, "b".repeat(64));
    }

    #[test]
    fn test_extract_sha256_rejects_wrong_length_or_garbage() {
        assert!(extract_sha256_from_syscheck(None).is_none());
        assert!(extract_sha256_from_syscheck(Some("not json")).is_none());
        let short = serde_json::json!({ "sha256": "abc" }).to_string();
        assert!(extract_sha256_from_syscheck(Some(&short)).is_none());
        let non_hex = serde_json::json!({ "sha256": "z".repeat(64) }).to_string();
        assert!(extract_sha256_from_syscheck(Some(&non_hex)).is_none());
    }

    #[test]
    fn test_extract_ipv4s_finds_all_dotted_quads() {
        let msg = "sshd: failed login from 203.0.113.9 port 22 (also seen via proxy 198.51.100.4)";
        let found = extract_ipv4s(msg);
        assert_eq!(found, vec!["203.0.113.9", "198.51.100.4"]);
    }

    #[test]
    fn test_extract_ipv4s_rejects_invalid_octets_and_malformed() {
        // 256 is out of range, 1.2.3 is too short, 1.2.3.4.5 has a trailing group.
        let msg = "bad 256.0.0.1 short 1.2.3 ok 10.0.0.1 trailing 1.2.3.4.5";
        let found = extract_ipv4s(msg);
        assert_eq!(found, vec!["10.0.0.1"]);
    }

    #[tokio::test]
    async fn test_hash_ioc_match_via_syscheck_payload() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(&tmp);
        let mut bundle = RuleBundle {
            version: 1,
            ..Default::default()
        };
        let bad_hash = "c".repeat(64);
        bundle.iocs.hashes.push(HashIoc {
            id: "bad-file".into(),
            sha256: bad_hash.clone(),
            severity: SEV_HIGH.into(),
            description: "known-bad".into(),
        });

        let (bus, mut server_rx) = EventBus::new(16, 16);
        let pipeline = DetectionPipeline::new(&cfg, bundle).unwrap();

        let payload = serde_json::json!({
            "type": "event",
            "data": { "path": "/tmp/clean-path", "sha256": bad_hash }
        })
        .to_string();
        let ev = Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileCreated {
                path: "/tmp/clean-path".into(),
                syscheck_payload: Some(payload),
            },
        );
        handle_event(&pipeline, &bus, &ev).await;

        let alert = tokio::time::timeout(Duration::from_millis(200), server_rx.recv())
            .await
            .expect("expected hash IOC alert")
            .expect("server_rx closed");
        match alert.kind {
            EventKind::LocalDetectionAlert {
                rule_type, rule_id, ..
            } => {
                assert_eq!(rule_type, "hash");
                assert_eq!(rule_id, "bad-file");
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_ip_ioc_match_via_log_message() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(&tmp);
        let mut bundle = RuleBundle {
            version: 1,
            ..Default::default()
        };
        bundle.iocs.ips.push(IpIoc {
            id: "c2".into(),
            ip: "203.0.113.9".into(),
            severity: SEV_MEDIUM.into(),
            description: "known C2".into(),
        });

        let (bus, mut server_rx) = EventBus::new(16, 16);
        let pipeline = DetectionPipeline::new(&cfg, bundle).unwrap();

        let ev = Event::new(
            "logcollector",
            Priority::Normal,
            EventKind::LogCollected {
                source: "sshd".into(),
                message: "Accepted publickey for root from 203.0.113.9 port 22".into(),
                format: "syslog".into(),
            },
        );
        handle_event(&pipeline, &bus, &ev).await;

        let alert = tokio::time::timeout(Duration::from_millis(200), server_rx.recv())
            .await
            .expect("expected IP IOC alert")
            .expect("server_rx closed");
        match alert.kind {
            EventKind::LocalDetectionAlert {
                rule_type, rule_id, ..
            } => {
                assert_eq!(rule_type, "ip");
                assert_eq!(rule_id, "c2");
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn test_hash_and_ip_ioc_build_ok() {
        // Ensure hash/IP bloom construction exercises the whole code path.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(&tmp);
        let mut bundle = RuleBundle::default();
        bundle.iocs.hashes.push(HashIoc {
            id: "h".into(),
            sha256: "a".repeat(64),
            severity: SEV_HIGH.into(),
            description: "".into(),
        });
        bundle.iocs.ips.push(IpIoc {
            id: "i".into(),
            ip: "203.0.113.9".into(),
            severity: SEV_MEDIUM.into(),
            description: "".into(),
        });
        let pipeline = DetectionPipeline::new(&cfg, bundle).unwrap();
        assert_eq!(pipeline.iocs.rule_count(), 2);
    }

    #[tokio::test]
    async fn test_drain_offline_queue_replays_to_server() {
        // Spool two detection payloads directly into the queue (simulating
        // a prior outage) then confirm `drain_offline_queue` replays them
        // to the server-bound channel in FIFO order and empties the queue.
        let q = OfflineQueue::in_memory(100).unwrap();
        let kind_a = EventKind::LocalDetectionAlert {
            rule_id: "spooled-a".into(),
            rule_type: "string".into(),
            severity: "high".into(),
            description: "".into(),
            matched_value: "a".into(),
        };
        let kind_b = EventKind::LocalDetectionAlert {
            rule_id: "spooled-b".into(),
            rule_type: "string".into(),
            severity: "high".into(),
            description: "".into(),
            matched_value: "b".into(),
        };
        q.enqueue(&serde_json::to_string(&kind_a).unwrap()).unwrap();
        q.enqueue(&serde_json::to_string(&kind_b).unwrap()).unwrap();
        assert_eq!(q.len().unwrap(), 2);

        let (bus, mut server_rx) = EventBus::new(16, 16);
        drain_offline_queue(&q, &bus, 10).await;

        let first = tokio::time::timeout(Duration::from_millis(200), server_rx.recv())
            .await
            .expect("drained alert should arrive")
            .expect("server_rx closed");
        let second = tokio::time::timeout(Duration::from_millis(200), server_rx.recv())
            .await
            .expect("second drained alert should arrive")
            .expect("server_rx closed");
        let ids: Vec<_> = [first, second]
            .into_iter()
            .map(|e| match e.kind {
                EventKind::LocalDetectionAlert { rule_id, .. } => rule_id,
                other => panic!("unexpected kind: {:?}", other),
            })
            .collect();
        assert_eq!(ids, vec!["spooled-a".to_string(), "spooled-b".to_string()]);
        assert!(q.is_empty().unwrap(), "queue should be empty after drain");
    }

    #[tokio::test]
    async fn test_drain_offline_queue_empty_is_noop() {
        let q = OfflineQueue::in_memory(10).unwrap();
        let (bus, mut server_rx) = EventBus::new(4, 4);
        drain_offline_queue(&q, &bus, 10).await;
        let nothing = tokio::time::timeout(Duration::from_millis(50), server_rx.recv()).await;
        assert!(nothing.is_err(), "no events expected from empty queue");
    }

    fn seed_alert(q: &OfflineQueue, id: &str) {
        let kind = EventKind::LocalDetectionAlert {
            rule_id: id.into(),
            rule_type: "string".into(),
            severity: "high".into(),
            description: "".into(),
            matched_value: id.into(),
        };
        q.enqueue(&serde_json::to_string(&kind).unwrap()).unwrap();
    }

    fn rule_ids_on_disk(q: &OfflineQueue) -> Vec<String> {
        q.peek_batch(usize::MAX)
            .unwrap()
            .into_iter()
            .map(|d| {
                let kind: EventKind = serde_json::from_str(&d.payload).unwrap();
                match kind {
                    EventKind::LocalDetectionAlert { rule_id, .. } => rule_id,
                    other => panic!("unexpected kind: {:?}", other),
                }
            })
            .collect()
    }

    #[tokio::test]
    async fn test_drain_offline_queue_preserves_batch_on_publish_failure() {
        // Regression — when the server-bound queue is saturated the drain
        // must leave every unsent payload on disk (at the head of the
        // queue, with original ids) so it's retried in order on the next
        // tick. We force failures by filling the server queue to capacity
        // with an undrained event, so subsequent `publish_to_server` calls
        // return `Err(ChannelFull)`.
        let q = OfflineQueue::in_memory(100).unwrap();
        for id in ["a", "b", "c"] {
            seed_alert(&q, id);
        }
        assert_eq!(q.len().unwrap(), 3);

        // Server queue capacity 1, keep the rx alive but never read from
        // it and pre-fill it so publish_to_server fails with Full.
        let (bus, _server_rx) = EventBus::new(4, 1);
        bus.publish_to_server(Event::new("seed", Priority::Normal, EventKind::Keepalive))
            .await
            .expect("seed the server queue");

        drain_offline_queue(&q, &bus, 10).await;

        assert_eq!(
            q.len().unwrap(),
            3,
            "all three payloads must stay on disk when publish fails"
        );
        assert_eq!(
            rule_ids_on_disk(&q),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    #[tokio::test]
    async fn test_drain_offline_queue_preserves_fifo_across_batches() {
        // Regression — with a bulk drain+re-enqueue strategy, items
        // beyond the batch could overtake items from inside the failing
        // batch (re-enqueued rows get fresh AUTOINCREMENT ids). We
        // verify that peek/ack keeps strict FIFO across batches: the
        // queue holds five items, we drain with batch=2 against a
        // saturated server queue, and every original item must still be
        // at its original position afterwards.
        let q = OfflineQueue::in_memory(100).unwrap();
        for id in ["a", "b", "c", "d", "e"] {
            seed_alert(&q, id);
        }

        let (bus, _server_rx) = EventBus::new(4, 1);
        bus.publish_to_server(Event::new("seed", Priority::Normal, EventKind::Keepalive))
            .await
            .expect("seed the server queue");

        drain_offline_queue(&q, &bus, 2).await;
        drain_offline_queue(&q, &bus, 2).await;
        drain_offline_queue(&q, &bus, 2).await;

        assert_eq!(q.len().unwrap(), 5);
        assert_eq!(
            rule_ids_on_disk(&q),
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
                "e".to_string()
            ],
            "FIFO order must be preserved across failed drain ticks"
        );
    }
}
