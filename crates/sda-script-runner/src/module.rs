//! Phase 2.7 script-runner supervisor task.
//!
//! The supervisor wires together [`ScriptRunner`] (the engine) with
//! the agent's [`EventBus`] (where outcomes are emitted) and an
//! [`mpsc`] request channel (where the device-control router pushes
//! verified [`RunScript`] jobs).
//!
//! In Phase 2.7 (MVP) the request channel is exposed via
//! [`ScriptRunnerHandle::sender`] so the wiring in
//! `crates/sda-agent/src/main.rs` can hand it to the
//! `sda-device-control` router. The router posts a
//! [`ScriptRequest`] when a `RunScript` `SignedActionJob` passes
//! validation, and the supervisor publishes
//! `EventKind::ScriptRunResult` and `EventKind::EvidenceRecord`
//! payloads back through the bus.
//!
//! When `modules.script_runner.enabled = false`, or when the pinned
//! key / allow-list is unset, the supervisor logs a single warning
//! and parks on the shutdown signal so the idle CPU footprint stays
//! at zero.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sda_core::config::AgentConfig;
use sda_core::module::ModuleHandle;
use sda_core::signal::ShutdownSignal;
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::runner::{ScriptOutcome, ScriptRequest, ScriptRunner, ScriptRunnerConfig};

/// How many in-flight requests can be queued before back-pressure is
/// applied to the producer (the device-control router). The runner
/// processes scripts serially, so the queue's only purpose is to
/// absorb bursts.
const REQUEST_QUEUE_DEPTH: usize = 16;

/// Phase 2.7 supervisor handle for the script-runner module.
pub struct ScriptRunnerModule;

/// Caller-side handle for the script-runner request queue.
///
/// Cloning is cheap — internally a [`mpsc::Sender`] — so the agent
/// supervisor hands a clone to whoever wants to dispatch script
/// runs.
#[derive(Debug, Clone)]
pub struct ScriptRunnerSender {
    tx: mpsc::Sender<ScriptRequest>,
}

impl ScriptRunnerSender {
    /// Try to enqueue `request` without blocking. Returns the
    /// request back when the queue is full.
    //
    // The `Err` variant carries the rejected `ScriptRequest` (which
    // includes the script body and the signature), so it is necessarily
    // large. Boxing here would force every caller to deal with an
    // extra heap indirection for the common success path; the
    // size-of-Err lint is an explicit non-goal for this API.
    #[allow(clippy::result_large_err)]
    pub fn try_send(
        &self,
        request: ScriptRequest,
    ) -> Result<(), mpsc::error::TrySendError<ScriptRequest>> {
        self.tx.try_send(request)
    }

    /// Enqueue `request`, waiting if the queue is at capacity.
    pub async fn send(
        &self,
        request: ScriptRequest,
    ) -> Result<(), mpsc::error::SendError<ScriptRequest>> {
        self.tx.send(request).await
    }
}

impl ScriptRunnerModule {
    /// Spawn the script-runner supervisor task.
    ///
    /// Behaviour matrix:
    ///
    /// - `modules.script_runner.enabled = false` → log "disabled"
    ///   and park on `shutdown` (idle CPU = 0).
    /// - `enabled = true && pinned_signing_key_hex.is_none()` → log
    ///   a warning and park; refuses to load without a pinned key.
    /// - `enabled = true && allowlist.is_empty()` → log a warning
    ///   and park; deny-by-default would reject every script anyway,
    ///   so we surface the misconfiguration loudly.
    /// - Otherwise → spawn the runner and process requests until
    ///   shutdown.
    ///
    /// Returns the [`ModuleHandle`] for the supervisor task and an
    /// optional [`ScriptRunnerSender`]. The sender is `None` when
    /// the module is disabled / parked, so callers branch cleanly
    /// rather than feeding requests into a black hole.
    pub fn start(
        config: &AgentConfig,
        bus: EventBus,
        mut shutdown: ShutdownSignal,
        work_dir: PathBuf,
    ) -> (ModuleHandle, Option<ScriptRunnerSender>) {
        let cfg = config.modules.script_runner.clone();

        if !cfg.enabled {
            info!("script_runner module disabled — parking on shutdown");
            let task = tokio::spawn(async move {
                shutdown.wait().await;
                Ok(())
            });
            return (ModuleHandle::new("script_runner", task), None);
        }

        let runner_config = match ScriptRunnerConfig::from_parts(
            cfg.pinned_signing_key_hex.as_deref(),
            cfg.allowlist.clone(),
            cfg.max_duration_secs,
            cfg.max_output_bytes,
        ) {
            Ok(c) => c,
            Err(err) => {
                warn!(
                    error = %err,
                    "script_runner enabled but configuration is invalid; parking"
                );
                let task = tokio::spawn(async move {
                    shutdown.wait().await;
                    Ok(())
                });
                return (ModuleHandle::new("script_runner", task), None);
            }
        };

        if runner_config.allowlist.is_empty() {
            warn!(
                "script_runner enabled but allowlist is empty (deny-by-default \
                 would reject every script); parking"
            );
            let task = tokio::spawn(async move {
                shutdown.wait().await;
                Ok(())
            });
            return (ModuleHandle::new("script_runner", task), None);
        }

        info!(
            allowlist_patterns = runner_config.allowlist.len(),
            max_duration_secs = runner_config.max_duration.as_secs(),
            max_output_bytes = runner_config.max_output_bytes,
            "script_runner module ready",
        );

        let (tx, mut rx) = mpsc::channel::<ScriptRequest>(REQUEST_QUEUE_DEPTH);
        let sender = ScriptRunnerSender { tx };
        let runner = Arc::new(ScriptRunner::new(runner_config, work_dir));

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.wait() => {
                        warn!("script_runner module shutting down");
                        break;
                    }
                    maybe_req = rx.recv() => {
                        let Some(req) = maybe_req else { break; };
                        let runner = runner.clone();
                        let bus = bus.clone();
                        // Spawn a child task so a slow script does
                        // not stall the supervisor's shutdown
                        // listener. The runner enforces its own
                        // wall-clock budget, so the join is
                        // guaranteed to complete.
                        tokio::spawn(async move {
                            handle_request(runner, bus, req).await;
                        });
                    }
                }
            }
            Ok(())
        });

        (ModuleHandle::new("script_runner", task), Some(sender))
    }
}

/// Audit projection of a single script run, emitted as
/// `EventKind::EvidenceRecord` alongside the
/// `EventKind::ScriptRunResult`.
///
/// This is intentionally minimal compared to the full
/// `sda_device_control::EvidenceRecord` — the script runner does not
/// own a Phase-1 chain, so we ship a self-contained payload that the
/// server can promote into the evidence chain. The Phase-3 work to
/// fold script runs into the device-wide evidence chain lands with
/// task 2.11.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScriptEvidence {
    schema_version: u16,
    job_id: String,
    canonical_name: String,
    exit_code: Option<i32>,
    timed_out: bool,
    output_truncated: bool,
    output_sha256: String,
    started_at: chrono::DateTime<chrono::Utc>,
    finished_at: chrono::DateTime<chrono::Utc>,
    /// SHA-256 of the canonical `ScriptOutcome` JSON. Lets a
    /// downstream chain verifier confirm the projection is
    /// faithful.
    outcome_sha256: String,
}

async fn handle_request(runner: Arc<ScriptRunner>, bus: EventBus, request: ScriptRequest) {
    let outcome = match runner.run(request.clone()).await {
        Ok(outcome) => outcome,
        Err(err) => {
            warn!(
                error = %err,
                job_id = %request.job_id,
                canonical_name = %request.canonical_name,
                "script_runner refused or failed to execute script",
            );
            // Synthesize a stub outcome so the server still gets
            // an audit projection. We use a sentinel exit_code of
            // None and an empty hash; the canonical name & job_id
            // are sufficient to correlate with the originating job.
            ScriptOutcome {
                job_id: request.job_id.clone(),
                canonical_name: request.canonical_name.clone(),
                exit_code: None,
                timed_out: false,
                output_truncated: false,
                truncation_reason: Some(format!("error:{err}")),
                stdout_truncated: String::new(),
                stderr_truncated: String::new(),
                output_sha256: String::new(),
                duration_secs: 0.0,
                started_at: chrono::Utc::now(),
                finished_at: chrono::Utc::now(),
            }
        }
    };

    let outcome_json = match serde_json::to_string(&outcome) {
        Ok(s) => s,
        Err(err) => {
            warn!(error = %err, "failed to serialize ScriptOutcome");
            return;
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(outcome_json.as_bytes());
    let outcome_sha256 = hex::encode(hasher.finalize());

    let evidence = ScriptEvidence {
        schema_version: 1,
        job_id: outcome.job_id.clone(),
        canonical_name: outcome.canonical_name.clone(),
        exit_code: outcome.exit_code,
        timed_out: outcome.timed_out,
        output_truncated: outcome.output_truncated,
        output_sha256: outcome.output_sha256.clone(),
        started_at: outcome.started_at,
        finished_at: outcome.finished_at,
        outcome_sha256,
    };
    let evidence_json = match serde_json::to_string(&evidence) {
        Ok(s) => s,
        Err(err) => {
            warn!(error = %err, "failed to serialize ScriptEvidence");
            return;
        }
    };

    let result_event = Event::new(
        "script_runner",
        Priority::High,
        EventKind::ScriptRunResult {
            payload: outcome_json,
        },
    );
    if let Err(err) = bus.publish_to_server(result_event).await {
        warn!(error = %err, "failed to publish ScriptRunResult to server queue");
    }

    let evidence_event = Event::new(
        "script_runner",
        Priority::High,
        EventKind::EvidenceRecord {
            payload: evidence_json,
        },
    );
    if let Err(err) = bus.publish_to_server(evidence_event).await {
        warn!(error = %err, "failed to publish EvidenceRecord to server queue");
    }
}

// `tokio::sync::mpsc::SendError` does not impl `Default`; use a
// short helper sleep for tests that need to wait briefly.
#[allow(dead_code)]
async fn yield_briefly() {
    tokio::time::sleep(Duration::from_millis(10)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use sda_core::config::ScriptRunnerConfig as AgentScriptRunnerConfig;
    use sda_core::signal::ShutdownController;
    use sda_event_bus::Event;
    use tempfile::TempDir;

    fn config_with(enabled: bool, key_hex: Option<String>, allow: Vec<String>) -> AgentConfig {
        let mut cfg = AgentConfig::default();
        cfg.modules.script_runner = AgentScriptRunnerConfig {
            enabled,
            pinned_signing_key_hex: key_hex,
            allowlist: allow,
            max_duration_secs: 5,
            max_output_bytes: 64 * 1024,
        };
        cfg
    }

    async fn drain_server(rx: &mut mpsc::Receiver<Event>) -> Vec<EventKind> {
        let mut out = Vec::new();
        while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            out.push(ev.kind);
        }
        out
    }

    #[tokio::test(flavor = "current_thread")]
    async fn parks_when_disabled() {
        let cfg = config_with(false, None, vec![]);
        let (bus, _server_rx) = EventBus::new(8, 8);
        let (controller, signal) = ShutdownController::new();
        let tmp = TempDir::new().unwrap();
        let (handle, sender) =
            ScriptRunnerModule::start(&cfg, bus, signal, tmp.path().to_path_buf());
        assert!(sender.is_none());
        controller.shutdown();
        handle.task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn parks_when_enabled_without_pinned_key() {
        let cfg = config_with(true, None, vec!["sn360.diagnostics.*".into()]);
        let (bus, _server_rx) = EventBus::new(8, 8);
        let (controller, signal) = ShutdownController::new();
        let tmp = TempDir::new().unwrap();
        let (handle, sender) =
            ScriptRunnerModule::start(&cfg, bus, signal, tmp.path().to_path_buf());
        assert!(sender.is_none());
        controller.shutdown();
        handle.task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn parks_when_allowlist_empty() {
        let key = SigningKey::generate(&mut OsRng);
        let key_hex = hex::encode(key.verifying_key().to_bytes());
        let cfg = config_with(true, Some(key_hex), vec![]);
        let (bus, _server_rx) = EventBus::new(8, 8);
        let (controller, signal) = ShutdownController::new();
        let tmp = TempDir::new().unwrap();
        let (handle, sender) =
            ScriptRunnerModule::start(&cfg, bus, signal, tmp.path().to_path_buf());
        assert!(sender.is_none());
        controller.shutdown();
        handle.task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn signed_request_emits_result_and_evidence() {
        let key = SigningKey::generate(&mut OsRng);
        let key_hex = hex::encode(key.verifying_key().to_bytes());
        let cfg = config_with(true, Some(key_hex), vec!["sn360.diagnostics.*".into()]);
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let (controller, signal) = ShutdownController::new();
        let tmp = TempDir::new().unwrap();
        let (handle, sender) =
            ScriptRunnerModule::start(&cfg, bus, signal, tmp.path().to_path_buf());
        let sender = sender.expect("module should be active");

        let body = b"#!/bin/sh\necho hello\n".to_vec();
        let signature = key.sign(&body);
        sender
            .send(ScriptRequest {
                job_id: "job-42".into(),
                canonical_name: "sn360.diagnostics.echo".into(),
                script_body: body,
                signature: signature.to_bytes().to_vec(),
                extension: Some("sh".into()),
                args: vec![],
            })
            .await
            .unwrap();

        // Wait briefly for the runner to drain.
        let kinds = drain_server(&mut server_rx).await;
        controller.shutdown();
        handle.task.await.unwrap().unwrap();

        let saw_result = kinds
            .iter()
            .any(|k| matches!(k, EventKind::ScriptRunResult { .. }));
        let saw_evidence = kinds
            .iter()
            .any(|k| matches!(k, EventKind::EvidenceRecord { .. }));
        assert!(
            saw_result,
            "expected at least one ScriptRunResult: {kinds:?}"
        );
        assert!(
            saw_evidence,
            "expected at least one EvidenceRecord: {kinds:?}"
        );
    }
}
