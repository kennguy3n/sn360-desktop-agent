//! Phase 3.2 / 3.3 supervisor task.
//!
//! Wires together
//! - [`crate::state_machine::StateMachine`],
//! - [`crate::store::GrantStore`], and
//! - [`crate::watchdog::RevocationWatchdog`]
//!
//! against an [`AdminManager`](sda_pal::admin_manager::AdminManager)
//! and the agent's [`EventBus`].
//!
//! The supervisor accepts [`JitAdminRequest`] messages from the
//! device-control router (Approve / Deny / Revoke). It then drives
//! the state machine, persists the result, calls the OS-level
//! grant/revoke through [`AdminManager`], and emits the matching
//! `EventKind::JitAdmin*` payloads.
//!
//! In addition to request-driven transitions, the supervisor runs a
//! periodic tick (`heartbeat_poll_secs`) that lets the watchdog fire
//! timer-, heartbeat-, and boot-sweep-based revocations. Power-state
//! revocations are handled by listening to the agent-wide power
//! profile broadcast.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sda_core::config::AgentConfig;
use sda_core::module::ModuleHandle;
use sda_core::signal::ShutdownSignal;
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use sda_pal::admin_manager::{AdminError, AdminManager, GrantHandle, UserRef};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

use crate::drift::{Drift, DriftDetector, DriftKind};
use crate::grant::{GrantRecord, GrantState};
use crate::state_machine::{StateMachine, StateTransition};
use crate::store::GrantStore;
use crate::watchdog::{RevocationReason, RevocationWatchdog, WatchdogConfig};

const REQUEST_QUEUE_DEPTH: usize = 32;

/// One request from the device-control router or operator into the
/// JIT-admin supervisor.
#[derive(Debug, Clone)]
pub enum JitAdminRequest {
    /// A new grant request arrived from the control plane. The
    /// supervisor records it as `Requested`.
    NewRequest {
        id: String,
        requested_by: String,
        user: UserRef,
        until: DateTime<Utc>,
    },
    /// Server approved the request. The supervisor moves it to
    /// `Approved` and immediately tries to grant.
    Approve { id: String, reason: Option<String> },
    /// Server denied the request — terminal.
    Deny { id: String, reason: Option<String> },
    /// Operator-initiated revoke; the supervisor pulls the OS-level
    /// privilege and moves the record to `Revoked`.
    Revoke {
        id: String,
        reason: Option<RevocationReason>,
    },
    /// Last-heartbeat indication from the comms loop. The supervisor
    /// tracks this so the watchdog's heartbeat-loss check has
    /// somewhere to read from.
    HeartbeatObserved { at: DateTime<Utc> },
    /// Power-state transition observed by the agent. The supervisor
    /// forwards it through the watchdog.
    PowerTransition { reason: RevocationReason },
}

/// Caller-side handle for the supervisor's request queue. Cheap to
/// clone (wraps an [`mpsc::Sender`]).
#[derive(Debug, Clone)]
pub struct JitAdminSender {
    tx: mpsc::Sender<JitAdminRequest>,
}

impl JitAdminSender {
    /// Best-effort enqueue; returns the request back when the queue
    /// is full.
    pub fn try_send(
        &self,
        request: JitAdminRequest,
    ) -> Result<(), mpsc::error::TrySendError<JitAdminRequest>> {
        self.tx.try_send(request)
    }

    /// Async enqueue; waits if the queue is at capacity.
    pub async fn send(
        &self,
        request: JitAdminRequest,
    ) -> Result<(), mpsc::error::SendError<JitAdminRequest>> {
        self.tx.send(request).await
    }
}

/// Bundle returned by [`JitAdminModule::start`].
pub struct JitAdminHandle {
    /// Supervisor task handle (suitable for `agent.register_module`).
    pub module: ModuleHandle,
    /// Sender for downstream producers; `None` when the module is
    /// disabled.
    pub sender: Option<JitAdminSender>,
}

/// Phase 3.2 / 3.3 supervisor handle.
pub struct JitAdminModule;

impl JitAdminModule {
    /// Spawn the JIT-admin supervisor task.
    ///
    /// Behaviour matrix:
    /// - `modules.jit_admin.enabled = false` → log "disabled" and
    ///   park on `shutdown` (idle CPU = 0).
    /// - `enabled = true` but `state_path = None` → fall back to
    ///   `<work_dir>/jit-admin-grants.json`.
    /// - Otherwise → spawn the supervisor and process requests.
    pub fn start(
        config: &AgentConfig,
        bus: EventBus,
        mut shutdown: ShutdownSignal,
        admin_manager: Arc<dyn AdminManager>,
        work_dir: PathBuf,
    ) -> JitAdminHandle {
        let cfg = config.modules.jit_admin.clone();
        if !cfg.enabled {
            info!("jit_admin module disabled — parking on shutdown");
            let task = tokio::spawn(async move {
                shutdown.wait().await;
                Ok(())
            });
            return JitAdminHandle {
                module: ModuleHandle::new("jit_admin", task),
                sender: None,
            };
        }

        let state_path = cfg
            .state_path
            .clone()
            .unwrap_or_else(|| work_dir.join("jit-admin-grants.json"));

        let store = match GrantStore::open(&state_path) {
            Ok(s) => s,
            Err(err) => {
                warn!(
                    error = %err,
                    path = %state_path.display(),
                    "jit_admin: failed to open grant store; parking",
                );
                let task = tokio::spawn(async move {
                    shutdown.wait().await;
                    Ok(())
                });
                return JitAdminHandle {
                    module: ModuleHandle::new("jit_admin", task),
                    sender: None,
                };
            }
        };

        let watchdog_cfg = WatchdogConfig::from_secs(cfg.heartbeat_loss_secs);
        // Drift-scan cadence is independent of the watchdog tick: it
        // runs on its own `tokio::time::interval` so a long
        // `AdminManager::list_admins` call cannot delay the watchdog
        // (which is the load-bearing path for time-boxed revocation).
        let drift_check_interval_secs = cfg.drift_check_interval_secs.max(1);
        info!(
            state_path = %state_path.display(),
            heartbeat_loss_secs = watchdog_cfg.heartbeat_loss_secs,
            heartbeat_poll_secs = watchdog_cfg.heartbeat_poll_secs,
            drift_check_interval_secs = drift_check_interval_secs,
            "jit_admin module ready",
        );

        let (tx, rx) = mpsc::channel::<JitAdminRequest>(REQUEST_QUEUE_DEPTH);
        let sender = JitAdminSender { tx };

        // Boot-time idempotent revoke before the supervisor starts
        // processing requests.
        let supervisor = Supervisor {
            store: Mutex::new(store),
            sm: StateMachine,
            wd: RevocationWatchdog,
            wd_cfg: watchdog_cfg,
            admin: admin_manager,
            bus,
            last_heartbeat: Mutex::new(None),
            drift_detector: DriftDetector::new(),
            drift_check_interval_secs,
        };
        let supervisor = Arc::new(supervisor);

        let task = {
            let supervisor = supervisor.clone();
            tokio::spawn(async move {
                supervisor.boot_sweep(Utc::now()).await;
                let mut rx = rx;
                let mut tick = tokio::time::interval(Duration::from_secs(
                    supervisor.wd_cfg.heartbeat_poll_secs,
                ));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                // Skip the immediate first tick (interval fires
                // straight away by default).
                let _ = tick.tick().await;

                let mut drift_tick = tokio::time::interval(Duration::from_secs(
                    supervisor.drift_check_interval_secs,
                ));
                drift_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let _ = drift_tick.tick().await;

                loop {
                    tokio::select! {
                        _ = shutdown.wait() => {
                            warn!("jit_admin module shutting down");
                            break;
                        }
                        maybe_req = rx.recv() => {
                            let Some(req) = maybe_req else { break };
                            supervisor.handle_request(req).await;
                        }
                        _ = tick.tick() => {
                            supervisor.watchdog_tick(Utc::now()).await;
                        }
                        _ = drift_tick.tick() => {
                            supervisor.do_drift_scan(Utc::now()).await;
                        }
                    }
                }
                Ok(())
            })
        };

        JitAdminHandle {
            module: ModuleHandle::new("jit_admin", task),
            sender: Some(sender),
        }
    }
}

/// Internal supervisor state shared between the request loop and the
/// watchdog tick.
struct Supervisor {
    store: Mutex<GrantStore>,
    sm: StateMachine,
    wd: RevocationWatchdog,
    wd_cfg: WatchdogConfig,
    admin: Arc<dyn AdminManager>,
    bus: EventBus,
    last_heartbeat: Mutex<Option<DateTime<Utc>>>,
    /// Phase 3.5 drift detector. Compares
    /// [`AdminManager::list_admins`] against the active grant ledger
    /// on `drift_check_interval_secs` cadence and emits a paired
    /// `DeviceControlFinding` + `EvidenceRecord` per discrepancy.
    drift_detector: DriftDetector,
    /// How often the drift scan runs, in seconds. Mirrors
    /// `JitAdminConfig::drift_check_interval_secs`.
    drift_check_interval_secs: u64,
}

impl Supervisor {
    async fn boot_sweep(&self, now: DateTime<Utc>) {
        // Snapshot (id, state) so we hold the lock briefly and then
        // dispatch each record through the right finalisation path.
        // Boot-sweep records can be in three non-terminal states:
        //   - Granted   → drop the OS-level privilege via `do_revoke`
        //                 (this also calls `AdminManager::revoke_admin`)
        //   - Approved  → no OS privilege ever activated; finalise
        //                 the ledger via `StateTransition::Expire`.
        //   - Requested → control plane never followed up; same
        //                 expiry path as `Approved`.
        let snapshots: Vec<(String, GrantState)> = {
            let store = self.store.lock().await;
            self.wd
                .boot_sweep(store.records(), now)
                .into_iter()
                .filter_map(|req| store.get(&req.grant_id).map(|r| (req.grant_id, r.state)))
                .collect()
        };
        for (id, state) in snapshots {
            match state {
                GrantState::Granted => {
                    self.do_revoke(&id, RevocationReason::BootSweep, now).await;
                }
                GrantState::Requested | GrantState::Approved => {
                    self.do_expire(&id, now).await;
                }
                // Terminal states are filtered out by
                // `RevocationWatchdog::boot_sweep`; this arm is only
                // here for exhaustiveness if a future state is added.
                GrantState::Denied
                | GrantState::Revoked
                | GrantState::Expired
                | GrantState::DriftDetected => {}
            }
        }
    }

    async fn watchdog_tick(&self, now: DateTime<Utc>) {
        let last_hb = *self.last_heartbeat.lock().await;
        let timer_reqs;
        let hb_reqs;
        {
            let store = self.store.lock().await;
            timer_reqs = self.wd.timer_revocations(store.records(), now);
            hb_reqs = self
                .wd
                .heartbeat_revocations(store.records(), last_hb, now, &self.wd_cfg);
        }
        for req in timer_reqs.into_iter().chain(hb_reqs) {
            self.do_revoke(&req.grant_id, req.reason, now).await;
        }
    }

    async fn handle_request(&self, request: JitAdminRequest) {
        let now = Utc::now();
        match request {
            JitAdminRequest::NewRequest {
                id,
                requested_by,
                user,
                until,
            } => {
                self.do_new_request(id, requested_by, user, until, now)
                    .await;
            }
            JitAdminRequest::Approve { id, reason } => {
                self.do_approve(&id, reason, now).await;
            }
            JitAdminRequest::Deny { id, reason } => {
                self.do_deny(&id, reason, now).await;
            }
            JitAdminRequest::Revoke { id, reason } => {
                self.do_revoke(&id, reason.unwrap_or(RevocationReason::Operator), now)
                    .await;
            }
            JitAdminRequest::HeartbeatObserved { at } => {
                let mut last = self.last_heartbeat.lock().await;
                *last = Some(at);
            }
            JitAdminRequest::PowerTransition { reason } => {
                let reqs = {
                    let store = self.store.lock().await;
                    self.wd.power_revocations(store.records(), reason)
                };
                for req in reqs {
                    self.do_revoke(&req.grant_id, req.reason, now).await;
                }
            }
        }
    }

    async fn do_new_request(
        &self,
        id: String,
        requested_by: String,
        user: UserRef,
        until: DateTime<Utc>,
        now: DateTime<Utc>,
    ) {
        let mut record = GrantRecord::new_requested(id.clone(), requested_by, user, until, now);
        // Phase 3.7 — build the transition evidence BEFORE the
        // persist so its id is appended to `record.evidence_ids`
        // and survives in the on-disk ledger. `request_received`
        // covers the entry into the grant lifecycle so the audit
        // chain has a record even if the control plane never
        // approves/denies the request.
        let evidence = Self::append_transition_evidence(&mut record, "request_received", None);
        let mut store = self.store.lock().await;
        if let Err(err) = store.upsert(record.clone()) {
            warn!(grant_id = %id, error = %err, "jit_admin: failed to persist new request");
            return;
        }
        drop(store);
        self.emit_event(EventKind::JitAdminRequested {
            payload: serde_json::to_string(&record).unwrap_or_default(),
        });
        self.emit_evidence(&evidence);
    }

    async fn do_approve(&self, id: &str, reason: Option<String>, now: DateTime<Utc>) {
        let record = {
            let store = self.store.lock().await;
            store.get(id).cloned()
        };
        let Some(record) = record else {
            warn!(grant_id = id, "jit_admin: approve for unknown grant");
            return;
        };

        let approved = match self.sm.apply(
            &record,
            StateTransition::Approve {
                reason: reason.clone(),
            },
            now,
        ) {
            Ok(r) => r,
            Err(err) => {
                warn!(grant_id = id, error = %err, "jit_admin: approve transition rejected");
                return;
            }
        };
        if let Err(err) = self.persist(&approved).await {
            warn!(grant_id = id, error = %err, "jit_admin: failed to persist approve");
            return;
        }

        // Immediately try to grant the OS-level privilege.
        match self.admin.grant_admin(&approved.user, approved.until) {
            Ok(handle) => {
                let mut granted = match self.sm.apply(
                    &approved,
                    StateTransition::Grant {
                        handle: handle.clone(),
                        reason,
                    },
                    Utc::now(),
                ) {
                    Ok(r) => r,
                    Err(err) => {
                        warn!(
                            grant_id = id,
                            error = %err,
                            "jit_admin: grant transition rejected after admin grant",
                        );
                        // Best-effort revoke to keep the device in
                        // sync with the ledger.
                        let _ = self.admin.revoke_admin(&handle);
                        return;
                    }
                };
                // Phase 3.7 — build evidence BEFORE the persist so
                // its id lands in `granted.evidence_ids` and the
                // on-disk ledger reflects the audit chain.
                let granted_reason = granted.last_reason.clone();
                let evidence = Self::append_transition_evidence(
                    &mut granted,
                    "granted",
                    granted_reason.as_deref(),
                );
                if let Err(err) = self.persist(&granted).await {
                    warn!(
                        grant_id = id,
                        error = %err,
                        "jit_admin: failed to persist grant; revoking orphan OS privilege",
                    );
                    // CRITICAL: the OS-level admin privilege is live
                    // on the device but the on-disk ledger is still
                    // in `Approved` (the earlier persist), so neither
                    // timer-revoke nor heartbeat-loss revoke nor
                    // power revoke will pick the orphan up — they
                    // all key off `is_active()`, which only fires
                    // for `Granted`. Best-effort revoke before we
                    // return so the device state matches the ledger.
                    // If the revoke also fails there is nothing more
                    // the supervisor can do here, but the emitted
                    // evidence record gives operators visibility.
                    let revoke_err = self
                        .admin
                        .revoke_admin(&handle)
                        .err()
                        .filter(|e| !is_already_revoked(e));
                    self.emit_event(EventKind::EvidenceRecord {
                        payload: serde_json::to_string(&AdminEvidence::failure(
                            &granted,
                            "persist_grant",
                            &AdminError::Command(err.to_string()),
                        ))
                        .unwrap_or_default(),
                    });
                    if let Some(rerr) = revoke_err {
                        warn!(
                            grant_id = id,
                            error = %rerr,
                            "jit_admin: orphan revoke also failed; admin privilege may be live until external cleanup",
                        );
                        self.emit_event(EventKind::EvidenceRecord {
                            payload: serde_json::to_string(&AdminEvidence::failure(
                                &granted,
                                "revoke_orphan",
                                &rerr,
                            ))
                            .unwrap_or_default(),
                        });
                    }
                    return;
                }
                self.emit_event(EventKind::JitAdminGranted {
                    payload: serde_json::to_string(&granted).unwrap_or_default(),
                });
                self.emit_evidence(&evidence);
            }
            Err(err) => {
                warn!(
                    grant_id = id,
                    error = %err,
                    "jit_admin: AdminManager::grant_admin failed; record stays Approved",
                );
                self.emit_event(EventKind::EvidenceRecord {
                    payload: serde_json::to_string(&AdminEvidence::failure(
                        &approved,
                        "grant_admin",
                        &err,
                    ))
                    .unwrap_or_default(),
                });
            }
        }
    }

    async fn do_deny(&self, id: &str, reason: Option<String>, now: DateTime<Utc>) {
        let record = {
            let store = self.store.lock().await;
            store.get(id).cloned()
        };
        let Some(record) = record else {
            warn!(grant_id = id, "jit_admin: deny for unknown grant");
            return;
        };
        let mut denied = match self
            .sm
            .apply(&record, StateTransition::Deny { reason }, now)
        {
            Ok(r) => r,
            Err(err) => {
                warn!(grant_id = id, error = %err, "jit_admin: deny transition rejected");
                return;
            }
        };
        // Phase 3.7 — build evidence BEFORE the persist so its id
        // lands in `denied.evidence_ids`.
        let denied_reason = denied.last_reason.clone();
        let evidence =
            Self::append_transition_evidence(&mut denied, "denied", denied_reason.as_deref());
        if let Err(err) = self.persist(&denied).await {
            warn!(grant_id = id, error = %err, "jit_admin: failed to persist deny");
            return;
        }
        // Denied records produce a JitAdminRevoked payload so the
        // server has a single terminal event regardless of the
        // intermediate state — see `docs/device-control.md` § 7.
        self.emit_event(EventKind::JitAdminRevoked {
            payload: serde_json::to_string(&denied).unwrap_or_default(),
        });
        self.emit_evidence(&evidence);
    }

    async fn do_revoke(&self, id: &str, reason: RevocationReason, now: DateTime<Utc>) {
        let record = {
            let store = self.store.lock().await;
            store.get(id).cloned()
        };
        let Some(record) = record else {
            debug!(
                grant_id = id,
                "jit_admin: revoke for unknown grant — ignored"
            );
            return;
        };

        if record.state.is_terminal() {
            debug!(
                grant_id = id,
                state = ?record.state,
                "jit_admin: revoke ignored (already terminal)",
            );
            return;
        }

        // Best-effort OS-level revoke when we have a live handle.
        // If the admin layer reports the privilege is *already* gone
        // (idempotent success), we proceed to finalise the ledger to
        // `Revoked`. Any other error means the OS-level privilege is
        // (or may still be) live — we MUST NOT mark the record
        // terminal, otherwise the watchdog (which only retries
        // non-terminal records) will silently leak the grant. Bail
        // out instead so the next watchdog tick re-attempts; the
        // emitted evidence record gives operators visibility while
        // the retry runs.
        if let Some(handle) = record.handle.clone() {
            if let Err(err) = self.admin.revoke_admin(&handle) {
                if !is_already_revoked(&err) {
                    warn!(
                        grant_id = id,
                        error = %err,
                        "jit_admin: AdminManager::revoke_admin failed; leaving record retryable",
                    );
                    self.emit_event(EventKind::EvidenceRecord {
                        payload: serde_json::to_string(&AdminEvidence::failure(
                            &record,
                            "revoke_admin",
                            &err,
                        ))
                        .unwrap_or_default(),
                    });
                    return;
                }
            }
        }

        let mut revoked = match self
            .sm
            .apply(&record, StateTransition::Revoke { reason }, now)
        {
            Ok(r) => r,
            Err(err) => {
                warn!(grant_id = id, error = %err, "jit_admin: revoke transition rejected");
                return;
            }
        };
        // Phase 3.7 — build evidence BEFORE the persist so its id
        // lands in `revoked.evidence_ids` (operator / timer /
        // heartbeat-loss / power / boot-sweep all funnel here).
        let revoked_reason = format!("{reason:?}");
        let evidence = Self::append_transition_evidence(
            &mut revoked,
            "revoked",
            Some(revoked_reason.as_str()),
        );
        if let Err(err) = self.persist(&revoked).await {
            warn!(grant_id = id, error = %err, "jit_admin: failed to persist revoke");
            return;
        }
        self.emit_event(EventKind::JitAdminRevoked {
            payload: serde_json::to_string(&revoked).unwrap_or_default(),
        });
        self.emit_evidence(&evidence);
    }

    /// Boot-sweep finaliser for records that were never grant-
    /// finalised — i.e. still in `Requested` or `Approved` when the
    /// agent restarted past their `until`. There is no OS-level
    /// privilege to drop, so we move the ledger to `Expired` and
    /// emit a single terminal `JitAdminRevoked` payload (mirroring
    /// `do_deny`'s convention so the server only has to subscribe
    /// to one terminal event kind).
    async fn do_expire(&self, id: &str, now: DateTime<Utc>) {
        let record = {
            let store = self.store.lock().await;
            store.get(id).cloned()
        };
        let Some(record) = record else {
            debug!(
                grant_id = id,
                "jit_admin: expire for unknown grant — ignored"
            );
            return;
        };
        if record.state.is_terminal() {
            debug!(
                grant_id = id,
                state = ?record.state,
                "jit_admin: expire ignored (already terminal)",
            );
            return;
        }
        let mut expired = match self.sm.apply(&record, StateTransition::Expire, now) {
            Ok(r) => r,
            Err(err) => {
                warn!(grant_id = id, error = %err, "jit_admin: expire transition rejected");
                return;
            }
        };
        // Phase 3.7 — build evidence BEFORE the persist so its id
        // lands in `expired.evidence_ids` (boot-sweep finalisation
        // of stale Requested/Approved records).
        let evidence = Self::append_transition_evidence(&mut expired, "expired", None);
        if let Err(err) = self.persist(&expired).await {
            warn!(grant_id = id, error = %err, "jit_admin: failed to persist expire");
            return;
        }
        self.emit_event(EventKind::JitAdminRevoked {
            payload: serde_json::to_string(&expired).unwrap_or_default(),
        });
        self.emit_evidence(&evidence);
    }

    /// Phase 3.5 drift scan. Calls
    /// [`AdminManager::list_admins`] and feeds the result into the
    /// pure-logic [`DriftDetector`]. For each [`Drift`] entry the
    /// supervisor publishes:
    ///
    /// 1. `EventKind::DeviceControlFinding` — canonical
    ///    [`Finding`](sda_device_control::finding::Finding) JSON
    ///    with [`FindingKind::AdminDrift`](sda_device_control::FindingKind::AdminDrift).
    /// 2. `EventKind::EvidenceRecord` — paired evidence so the audit
    ///    chain reflects the drift observation alongside the live
    ///    grant ledger.
    ///
    /// Failures from `list_admins()` are logged at WARN and skip the
    /// emit step; the next tick retries.
    async fn do_drift_scan(&self, now: DateTime<Utc>) {
        let records: Vec<GrantRecord> = {
            let store = self.store.lock().await;
            store.records().to_vec()
        };
        let drifts = match self.drift_detector.scan(self.admin.as_ref(), &records) {
            Ok(d) => d,
            Err(err) => {
                warn!(error = %err, "jit_admin: drift scan failed");
                return;
            }
        };
        for drift in drifts {
            self.emit_event(EventKind::DeviceControlFinding {
                payload: build_drift_finding_payload(&drift, now),
            });
            self.emit_event(EventKind::EvidenceRecord {
                payload: serde_json::to_string(&AdminEvidence::drift(&drift, now))
                    .unwrap_or_default(),
            });
        }
    }

    /// Phase 3.7 — build a transition evidence record AND wire
    /// its id into the grant's [`GrantRecord::evidence_ids`] audit
    /// chain. Callers MUST persist `record` after calling this so
    /// the appended id survives in the ledger; they then call
    /// [`Supervisor::emit_evidence`] once the persist returns OK so
    /// the wire and ledger views stay aligned.
    fn append_transition_evidence(
        record: &mut GrantRecord,
        operation: &str,
        reason: Option<&str>,
    ) -> AdminEvidence {
        let evidence = AdminEvidence::transition(record, operation, reason);
        record.evidence_ids.push(evidence.evidence_id.clone());
        evidence
    }

    /// Emit a pre-built [`AdminEvidence`] on the bus as an
    /// `EvidenceRecord`. Pairs with
    /// [`Supervisor::append_transition_evidence`] on the success
    /// paths and is invoked directly for failure / drift evidence.
    fn emit_evidence(&self, evidence: &AdminEvidence) {
        self.emit_event(EventKind::EvidenceRecord {
            payload: serde_json::to_string(evidence).unwrap_or_default(),
        });
    }

    async fn persist(&self, record: &GrantRecord) -> Result<(), crate::store::StoreError> {
        let mut store = self.store.lock().await;
        store.upsert(record.clone())
    }

    fn emit_event(&self, kind: EventKind) {
        let event = Event::new("jit_admin", Priority::High, kind);
        let bus = self.bus.clone();
        tokio::spawn(async move {
            if let Err(err) = bus.publish_to_server(event).await {
                warn!(error = %err, "jit_admin: failed to publish event to server queue");
            }
        });
    }
}

/// Decide whether an [`AdminError`] returned by `revoke_admin` is the
/// idempotent "this user is no longer in the admin group" case we
/// should silently swallow.
fn is_already_revoked(err: &AdminError) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("not a member") || msg.contains("not found")
}

/// Compact evidence payload for JIT-admin state transitions.
///
/// The supervisor emits these as `EventKind::EvidenceRecord` for
/// every transition (success or failure) so the audit chain mirrors
/// the lifecycle of every grant.
///
/// Three constructors cover the three classes of transition:
///
/// 1. [`AdminEvidence::transition`] — successful happy-path
///    transitions (request_received / granted / denied / revoked /
///    expired). `success = true`, `error = None`.
/// 2. [`AdminEvidence::failure`] — `AdminManager` (or persist) call
///    failed during a transition. `success = false`, `error =
///    Some(...)`.
/// 3. [`AdminEvidence::drift`] — drift detector observed a
///    discrepancy between the OS-level admin list and the active
///    grant ledger. Encoded as `operation = "drift_detected"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdminEvidence {
    /// Unique id for this evidence record. Generated fresh per
    /// emission so the audit chain (`GrantRecord::evidence_ids`)
    /// can reference each transition individually.
    evidence_id: String,
    schema_version: u16,
    grant_id: String,
    user: UserRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    handle_id: Option<String>,
    state: GrantState,
    operation: String,
    /// `true` on successful transitions; `false` when an OS-level
    /// or ledger persist failed.
    success: bool,
    /// Free-form reason text (deny reason, revoke reason, …) when
    /// the supervisor has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// Set only on failure transitions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// Drift kind label for `operation = "drift_detected"` records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    drift_kind: Option<String>,
    occurred_at: DateTime<Utc>,
}

impl AdminEvidence {
    fn transition(record: &GrantRecord, operation: &str, reason: Option<&str>) -> Self {
        Self {
            evidence_id: uuid::Uuid::new_v4().to_string(),
            schema_version: 1,
            grant_id: record.id.clone(),
            user: record.user.clone(),
            handle_id: record.handle.as_ref().map(|h: &GrantHandle| h.id.clone()),
            state: record.state,
            operation: operation.into(),
            success: true,
            reason: reason.map(|s| s.to_string()),
            error: None,
            drift_kind: None,
            occurred_at: Utc::now(),
        }
    }

    fn failure(record: &GrantRecord, operation: &str, error: &AdminError) -> Self {
        Self {
            evidence_id: uuid::Uuid::new_v4().to_string(),
            schema_version: 1,
            grant_id: record.id.clone(),
            user: record.user.clone(),
            handle_id: record.handle.as_ref().map(|h: &GrantHandle| h.id.clone()),
            state: record.state,
            operation: operation.into(),
            success: false,
            reason: None,
            error: Some(error.to_string()),
            drift_kind: None,
            occurred_at: Utc::now(),
        }
    }

    fn drift(drift: &Drift, now: DateTime<Utc>) -> Self {
        Self {
            evidence_id: uuid::Uuid::new_v4().to_string(),
            schema_version: 1,
            grant_id: drift.grant_id.clone().unwrap_or_default(),
            user: UserRef {
                username: drift.user.clone(),
                domain: None,
            },
            handle_id: None,
            // Drift records describe an OS-level state, not a
            // ledger transition — encode the drift kind as the
            // pseudo-state label so consumers can distinguish them
            // from regular grant evidence.
            state: GrantState::DriftDetected,
            operation: "drift_detected".into(),
            success: false,
            reason: drift.source.clone(),
            error: None,
            drift_kind: Some(drift.kind.as_str().to_string()),
            occurred_at: now,
        }
    }
}

/// Build the canonical [`sda_device_control::finding::Finding`] JSON
/// payload for a single drift observation. The agent does not yet
/// own its tenant_id / device_id at this layer — those are wired in
/// by the agent supervisor when it forwards the
/// `DeviceControlFinding` event onto the server queue. Until then we
/// emit the nil UUID and rely on the agent envelope to populate the
/// outer identity (matching the `build_recommendation_payload`
/// pattern in `sda-software::approval`).
fn build_drift_finding_payload(drift: &Drift, now: DateTime<Utc>) -> String {
    let evidence = serde_json::json!({
        "drift_kind": drift.kind.as_str(),
        "user": drift.user,
        "group": drift.group,
        "source": drift.source,
        "grant_id": drift.grant_id,
    });
    let plain_english = match drift.kind {
        DriftKind::UntrackedAdmin => format!(
            "{} has admin rights but no tracked JIT grant — possible drift.",
            drift.user
        ),
        DriftKind::MissingPrivilege => format!(
            "{} has a tracked grant but admin rights were externally removed.",
            drift.user
        ),
    };
    let value = serde_json::json!({
        "finding_id":     uuid::Uuid::new_v4(),
        "device_id":      uuid::Uuid::nil(),
        "tenant_id":      uuid::Uuid::nil(),
        "schema_version": 1u16,
        "kind":           "admin_drift",
        "severity":       "high",
        "plain_english":  plain_english,
        "evidence":       evidence,
        "observed_at":    now,
    });
    serde_json::to_string(&value).expect("serde_json::to_string of a Value is infallible")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::config::JitAdminConfig as AgentJitAdminConfig;
    use sda_core::signal::ShutdownController;
    use sda_pal::admin_manager::{AdminAccount, GrantHandle, OsCommandRunner};
    use std::sync::Mutex as StdMutex;
    use tempfile::TempDir;

    /// Test-only AdminManager implementation that records every call
    /// and lets the test inject canned responses.
    #[derive(Debug, Default)]
    struct FakeAdmin {
        next_grant_handle: StdMutex<Option<GrantHandle>>,
        grants: StdMutex<Vec<(UserRef, DateTime<Utc>)>>,
        revokes: StdMutex<Vec<GrantHandle>>,
        grant_should_fail: StdMutex<Option<AdminError>>,
        revoke_should_fail: StdMutex<Option<AdminError>>,
        /// Canned `list_admins` payload. When `None`, returns an
        /// empty list (the historical default that pre-3.5 tests
        /// expect). Drift tests overwrite this to inject untracked
        /// admins.
        admins: StdMutex<Option<Vec<AdminAccount>>>,
        /// Test-only mid-call hook: when set, the directory at the
        /// given path is recursively removed *during*
        /// [`grant_admin`], between the supervisor's `Approved`
        /// persist (which already happened) and the supervisor's
        /// `Granted` persist (which is about to happen). Used by
        /// `approve_persist_failure_revokes_orphaned_admin_grant` to
        /// simulate the disk-side state path disappearing while the
        /// OS-level privilege is live.
        grant_should_remove_dir: StdMutex<Option<PathBuf>>,
    }

    impl AdminManager for FakeAdmin {
        fn list_admins(&self) -> Result<Vec<AdminAccount>, AdminError> {
            Ok(self.admins.lock().unwrap().clone().unwrap_or_default())
        }

        fn grant_admin(
            &self,
            user: &UserRef,
            until: DateTime<Utc>,
        ) -> Result<GrantHandle, AdminError> {
            self.grants.lock().unwrap().push((user.clone(), until));
            if let Some(err) = self.grant_should_fail.lock().unwrap().take() {
                return Err(err);
            }
            // Mid-call hook (see field docstring). Fired *after* the
            // recorded grant so a successful grant_admin still
            // returns a usable handle even if the cleanup runs.
            if let Some(path) = self.grant_should_remove_dir.lock().unwrap().take() {
                let _ = std::fs::remove_dir_all(&path);
            }
            self.next_grant_handle
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| AdminError::Command("no grant handle queued".into()))
        }

        fn revoke_admin(&self, handle: &GrantHandle) -> Result<(), AdminError> {
            self.revokes.lock().unwrap().push(handle.clone());
            if let Some(err) = self.revoke_should_fail.lock().unwrap().take() {
                return Err(err);
            }
            Ok(())
        }

        fn observed_grants(&self) -> Result<Vec<GrantHandle>, AdminError> {
            Ok(Vec::new())
        }
    }

    fn cfg(enabled: bool, state_path: Option<PathBuf>) -> AgentConfig {
        let mut c = AgentConfig::default();
        c.modules.jit_admin = AgentJitAdminConfig {
            enabled,
            state_path,
            heartbeat_loss_secs: 4,
            // Long enough that the drift_tick never fires inside the
            // 200 ms `drain_server` window of the existing tests.
            // Drift-specific tests override this via `cfg_with_drift`.
            drift_check_interval_secs: 3600,
        };
        c
    }

    /// Like [`cfg`], but with a short drift-scan cadence so the
    /// supervisor's `drift_tick` fires inside the test's 200 ms
    /// `drain_server` window. The watchdog tick is unaffected.
    fn cfg_with_drift(
        enabled: bool,
        state_path: Option<PathBuf>,
        drift_check_interval_secs: u64,
    ) -> AgentConfig {
        let mut c = cfg(enabled, state_path);
        c.modules.jit_admin.drift_check_interval_secs = drift_check_interval_secs;
        c
    }

    fn user(name: &str) -> UserRef {
        UserRef {
            username: name.into(),
            domain: None,
        }
    }

    fn handle(id: &str, until: DateTime<Utc>) -> GrantHandle {
        GrantHandle {
            id: id.into(),
            user: user("alice"),
            until,
        }
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
        let cfg = cfg(false, None);
        let (bus, _server_rx) = EventBus::new(8, 8);
        let (controller, signal) = ShutdownController::new();
        let tmp = TempDir::new().unwrap();
        let admin = Arc::new(FakeAdmin::default());
        let h = JitAdminModule::start(&cfg, bus, signal, admin, tmp.path().to_path_buf());
        assert!(h.sender.is_none());
        controller.shutdown();
        h.module.task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn approve_drives_grant_and_emits_events() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg(true, Some(tmp.path().join("grants.json")));
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let (controller, signal) = ShutdownController::new();

        let admin = Arc::new(FakeAdmin::default());
        let until = Utc::now() + chrono::Duration::hours(1);
        *admin.next_grant_handle.lock().unwrap() = Some(handle("h-1", until));

        let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
        let sender = h.sender.expect("module should be active");

        sender
            .send(JitAdminRequest::NewRequest {
                id: "g-1".into(),
                requested_by: "ops".into(),
                user: user("alice"),
                until,
            })
            .await
            .unwrap();
        sender
            .send(JitAdminRequest::Approve {
                id: "g-1".into(),
                reason: Some("policy ok".into()),
            })
            .await
            .unwrap();

        let kinds = drain_server(&mut server_rx).await;
        controller.shutdown();
        h.module.task.await.unwrap().unwrap();

        // One Requested, one Granted (deny path is not used here).
        let saw_requested = kinds
            .iter()
            .any(|k| matches!(k, EventKind::JitAdminRequested { .. }));
        let saw_granted = kinds
            .iter()
            .any(|k| matches!(k, EventKind::JitAdminGranted { .. }));
        assert!(saw_requested, "expected JitAdminRequested in {kinds:?}");
        assert!(saw_granted, "expected JitAdminGranted in {kinds:?}");

        // FakeAdmin should have seen exactly one grant_admin call.
        assert_eq!(admin.grants.lock().unwrap().len(), 1);
        assert_eq!(admin.revokes.lock().unwrap().len(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deny_emits_terminal_revoked_event() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg(true, Some(tmp.path().join("grants.json")));
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let (controller, signal) = ShutdownController::new();
        let admin = Arc::new(FakeAdmin::default());
        let until = Utc::now() + chrono::Duration::hours(1);

        let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
        let sender = h.sender.expect("module should be active");

        sender
            .send(JitAdminRequest::NewRequest {
                id: "g-2".into(),
                requested_by: "ops".into(),
                user: user("alice"),
                until,
            })
            .await
            .unwrap();
        sender
            .send(JitAdminRequest::Deny {
                id: "g-2".into(),
                reason: Some("rate limited".into()),
            })
            .await
            .unwrap();

        let kinds = drain_server(&mut server_rx).await;
        controller.shutdown();
        h.module.task.await.unwrap().unwrap();

        let saw_requested = kinds
            .iter()
            .any(|k| matches!(k, EventKind::JitAdminRequested { .. }));
        let saw_revoked = kinds
            .iter()
            .any(|k| matches!(k, EventKind::JitAdminRevoked { .. }));
        assert!(saw_requested, "expected JitAdminRequested in {kinds:?}");
        assert!(saw_revoked, "expected JitAdminRevoked in {kinds:?}");
        assert!(admin.grants.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_revoke_drops_admin_privilege_and_persists() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("grants.json");
        let cfg = cfg(true, Some(path.clone()));
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let (controller, signal) = ShutdownController::new();

        let admin = Arc::new(FakeAdmin::default());
        let until = Utc::now() + chrono::Duration::hours(1);
        *admin.next_grant_handle.lock().unwrap() = Some(handle("h-1", until));

        let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
        let sender = h.sender.expect("module should be active");

        sender
            .send(JitAdminRequest::NewRequest {
                id: "g-3".into(),
                requested_by: "ops".into(),
                user: user("alice"),
                until,
            })
            .await
            .unwrap();
        sender
            .send(JitAdminRequest::Approve {
                id: "g-3".into(),
                reason: None,
            })
            .await
            .unwrap();
        sender
            .send(JitAdminRequest::Revoke {
                id: "g-3".into(),
                reason: Some(RevocationReason::Operator),
            })
            .await
            .unwrap();

        let _ = drain_server(&mut server_rx).await;
        controller.shutdown();
        h.module.task.await.unwrap().unwrap();

        // FakeAdmin should have seen 1 grant + 1 revoke.
        assert_eq!(admin.grants.lock().unwrap().len(), 1);
        assert_eq!(admin.revokes.lock().unwrap().len(), 1);
        assert_eq!(admin.revokes.lock().unwrap()[0].id, "h-1");

        // Reload the store and assert the record is terminal.
        let store = GrantStore::open(&path).unwrap();
        let r = store.get("g-3").expect("record persisted");
        assert_eq!(r.state, GrantState::Revoked);
        assert!(r.state.is_terminal());
    }

    /// Regression guard for the `do_revoke` early-return when the
    /// OS-level `revoke_admin` call fails non-idempotently. Pre-fix
    /// the supervisor logged a warning, emitted an `EvidenceRecord`,
    /// and then *fell through* to the state-machine `apply` call,
    /// transitioning the grant to terminal `Revoked` even though the
    /// OS-level privilege was still live. Because `Revoked` is
    /// terminal, no watchdog branch (timer, heartbeat-loss, power)
    /// would ever retry — silently leaking admin privilege. The fix
    /// is to bail out of `do_revoke` when the admin layer reports a
    /// non-`AlreadyRevoked` error so the watchdog picks the record
    /// up on the next tick.
    #[tokio::test(flavor = "current_thread")]
    async fn revoke_admin_failure_keeps_record_retryable() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("grants.json");
        let cfg = cfg(true, Some(path.clone()));
        let (bus, _server_rx) = EventBus::new(16, 16);
        let (controller, signal) = ShutdownController::new();

        let admin = Arc::new(FakeAdmin::default());
        let until = Utc::now() + chrono::Duration::hours(1);
        *admin.next_grant_handle.lock().unwrap() = Some(handle("h-retry", until));
        // Inject a non-idempotent failure on the upcoming revoke.
        // `is_already_revoked` keys on the substrings "not a member"
        // and "not found"; "io error" matches neither, so the
        // failure is treated as still-live.
        *admin.revoke_should_fail.lock().unwrap() =
            Some(AdminError::Command("io error: device not ready".into()));

        let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
        let sender = h.sender.expect("module should be active");

        sender
            .send(JitAdminRequest::NewRequest {
                id: "g-retry".into(),
                requested_by: "ops".into(),
                user: user("alice"),
                until,
            })
            .await
            .unwrap();
        sender
            .send(JitAdminRequest::Approve {
                id: "g-retry".into(),
                reason: None,
            })
            .await
            .unwrap();
        sender
            .send(JitAdminRequest::Revoke {
                id: "g-retry".into(),
                reason: Some(RevocationReason::Operator),
            })
            .await
            .unwrap();

        // Drain the bus so we know all in-flight messages have been
        // processed before we shut down.
        let _ = drain_server(&mut { _server_rx }).await;
        controller.shutdown();
        h.module.task.await.unwrap().unwrap();

        // The OS-level revoke was attempted exactly once.
        assert_eq!(admin.revokes.lock().unwrap().len(), 1);

        // Critically: the record must NOT be terminal, so the
        // watchdog can retry on the next tick.
        let store = GrantStore::open(&path).unwrap();
        let r = store.get("g-retry").expect("record persisted");
        assert_eq!(
            r.state,
            GrantState::Granted,
            "record must stay Granted so the watchdog can retry, was {:?}",
            r.state,
        );
        assert!(
            !r.state.is_terminal(),
            "record must not be terminal after a non-idempotent revoke failure",
        );
    }

    /// Regression guard for the orphaned-admin-grant bug in
    /// `do_approve` (Round 7). Pre-fix flow:
    /// 1. `Approve` transition → `persist(&approved)` succeeds
    ///    (ledger now `Approved`).
    /// 2. `AdminManager::grant_admin` succeeds → OS-level admin
    ///    privilege is now live on the device.
    /// 3. `Grant` transition → returns `granted` record.
    /// 4. `persist(&granted)` fails (e.g. cache dir disappeared,
    ///    disk unmounted, write quota exhausted) → the function
    ///    returns at the early-bail with NO revoke.
    ///
    /// Net effect pre-fix: the OS-level admin privilege stays live
    /// but the watchdog cannot pick the orphan up. `is_overdue()`
    /// requires `is_active()`, which only fires for `Granted` —
    /// since the persisted ledger is still `Approved`, none of the
    /// timer / heartbeat / power revocation paths see the record.
    /// On boot sweep when `until` elapses, the `Approved` record
    /// routes to `do_expire`, which deliberately does NOT call
    /// `revoke_admin` (it assumes no OS privilege ever activated
    /// from `Approved`) — the orphan persists until external
    /// cleanup. Same orphaning class as Round 5's revoke-path bug.
    ///
    /// This test simulates step 4 by removing the parent directory
    /// of the state file from inside the `FakeAdmin::grant_admin`
    /// hook (which fires after the `Approved` persist already
    /// landed). It then asserts the supervisor revokes the orphan
    /// before returning, emits an `EvidenceRecord` describing the
    /// persist failure, and never emits a `JitAdminGranted` event
    /// (because the grant never reached the durable ledger).
    #[tokio::test(flavor = "current_thread")]
    async fn approve_persist_failure_revokes_orphaned_admin_grant() {
        let tmp = TempDir::new().unwrap();
        // Place the state file inside a subdirectory we can wipe
        // mid-flow. The first two persists (Requested, Approved)
        // happen before the wipe, so they succeed.
        let sub_dir = tmp.path().join("state");
        std::fs::create_dir(&sub_dir).unwrap();
        let state_path = sub_dir.join("grants.json");
        let cfg = cfg(true, Some(state_path));
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let (controller, signal) = ShutdownController::new();

        let admin = Arc::new(FakeAdmin::default());
        let until = Utc::now() + chrono::Duration::hours(1);
        *admin.next_grant_handle.lock().unwrap() = Some(handle("h-orphan", until));
        // Mid-flow hook: when the supervisor calls grant_admin (the
        // OS-level privilege is now live on the device), the hook
        // wipes the state directory. The supervisor's subsequent
        // `persist(&granted)` will then fail because the tempfile
        // rename target's parent no longer exists. With the fix in
        // place this triggers the orphan revoke + evidence emit.
        *admin.grant_should_remove_dir.lock().unwrap() = Some(sub_dir.clone());

        let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
        let sender = h.sender.expect("module should be active");

        sender
            .send(JitAdminRequest::NewRequest {
                id: "g-orphan".into(),
                requested_by: "ops".into(),
                user: user("alice"),
                until,
            })
            .await
            .unwrap();
        sender
            .send(JitAdminRequest::Approve {
                id: "g-orphan".into(),
                reason: None,
            })
            .await
            .unwrap();

        let kinds = drain_server(&mut server_rx).await;
        controller.shutdown();
        h.module.task.await.unwrap().unwrap();

        // The OS-level privilege was granted exactly once...
        assert_eq!(admin.grants.lock().unwrap().len(), 1);
        // ...and immediately revoked because the Granted persist
        // failed. Pre-fix this would have been zero — the orphan
        // would have been left live on the device.
        let revokes = admin.revokes.lock().unwrap();
        assert_eq!(
            revokes.len(),
            1,
            "expected an orphan-revoke after persist failure; revokes = {revokes:?}",
        );
        assert_eq!(revokes[0].id, "h-orphan");
        drop(revokes);

        // Wire payload assertions:
        // - Requested event fired (early in the flow, before wipe).
        // - At least one EvidenceRecord describing the failure.
        // - NO JitAdminGranted event — the grant never reached the
        //   durable ledger and must not be claimed to operators.
        assert!(
            kinds
                .iter()
                .any(|k| matches!(k, EventKind::JitAdminRequested { .. })),
            "expected JitAdminRequested in {kinds:?}",
        );
        assert!(
            kinds
                .iter()
                .any(|k| matches!(k, EventKind::EvidenceRecord { .. })),
            "expected EvidenceRecord in {kinds:?}",
        );
        assert!(
            !kinds
                .iter()
                .any(|k| matches!(k, EventKind::JitAdminGranted { .. })),
            "must NOT claim Granted to the server when the ledger never made it past Approved: {kinds:?}",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unknown_revoke_is_silently_ignored() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg(true, Some(tmp.path().join("grants.json")));
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let (controller, signal) = ShutdownController::new();
        let admin = Arc::new(FakeAdmin::default());

        let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
        let sender = h.sender.expect("module should be active");

        sender
            .send(JitAdminRequest::Revoke {
                id: "no-such-id".into(),
                reason: None,
            })
            .await
            .unwrap();

        let kinds = drain_server(&mut server_rx).await;
        controller.shutdown();
        h.module.task.await.unwrap().unwrap();
        assert!(kinds.is_empty(), "no events expected: {kinds:?}");
        assert!(admin.revokes.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn power_transition_revokes_active_grants() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg(true, Some(tmp.path().join("grants.json")));
        let (bus, _server_rx) = EventBus::new(16, 16);
        let (controller, signal) = ShutdownController::new();

        let admin = Arc::new(FakeAdmin::default());
        let until = Utc::now() + chrono::Duration::hours(1);
        *admin.next_grant_handle.lock().unwrap() = Some(handle("h-2", until));

        let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
        let sender = h.sender.expect("module should be active");
        sender
            .send(JitAdminRequest::NewRequest {
                id: "g-4".into(),
                requested_by: "ops".into(),
                user: user("alice"),
                until,
            })
            .await
            .unwrap();
        sender
            .send(JitAdminRequest::Approve {
                id: "g-4".into(),
                reason: None,
            })
            .await
            .unwrap();
        sender
            .send(JitAdminRequest::PowerTransition {
                reason: RevocationReason::PowerSuspend,
            })
            .await
            .unwrap();

        // Drain a moment to let the supervisor process.
        tokio::time::sleep(Duration::from_millis(80)).await;
        controller.shutdown();
        h.module.task.await.unwrap().unwrap();
        assert_eq!(admin.revokes.lock().unwrap().len(), 1);
    }

    /// Pre-populate the ledger with three overdue, non-terminal
    /// records and confirm the supervisor's boot sweep finalises
    /// each one through the right path:
    ///
    /// - `Granted`   → `AdminManager::revoke_admin` is called and
    ///                 the record becomes `Revoked`.
    /// - `Approved`  → no admin call; record becomes `Expired`.
    /// - `Requested` → no admin call; record becomes `Expired`.
    ///
    /// Regression — the supervisor used to send
    /// `StateTransition::Revoke` for every state, which the state
    /// machine rejects from `Requested`/`Approved`, so those records
    /// stayed non-terminal forever and produced a warning log on
    /// every boot.
    #[tokio::test(flavor = "current_thread")]
    async fn boot_sweep_finalises_overdue_records_by_state() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("grants.json");
        let past = Utc::now() - chrono::Duration::hours(1);

        // Pre-populate the on-disk ledger.
        {
            let mut store = GrantStore::open(&path).unwrap();
            let mut requested =
                GrantRecord::new_requested("g-req", "ops", user("alice"), past, past);
            requested.state = GrantState::Requested;
            store.upsert(requested).unwrap();

            let mut approved =
                GrantRecord::new_requested("g-app", "ops", user("alice"), past, past);
            approved.state = GrantState::Approved;
            store.upsert(approved).unwrap();

            let mut granted = GrantRecord::new_requested("g-grn", "ops", user("alice"), past, past);
            granted.state = GrantState::Granted;
            granted.handle = Some(handle("h-grn", past));
            store.upsert(granted).unwrap();
        }

        let cfg = cfg(true, Some(path.clone()));
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let (controller, signal) = ShutdownController::new();
        let admin = Arc::new(FakeAdmin::default());

        let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());

        // Give the boot sweep time to run before draining.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = drain_server(&mut server_rx).await;
        controller.shutdown();
        h.module.task.await.unwrap().unwrap();

        // Only the Granted record produces an OS-level revoke call.
        let revokes = admin.revokes.lock().unwrap();
        assert_eq!(
            revokes.len(),
            1,
            "Granted should revoke once, others should not"
        );
        assert_eq!(revokes[0].id, "h-grn");
        assert!(
            admin.grants.lock().unwrap().is_empty(),
            "boot sweep must not call grant_admin",
        );

        // All three records are terminal on disk.
        let store = GrantStore::open(&path).unwrap();
        let req = store.get("g-req").expect("requested record persisted");
        let app = store.get("g-app").expect("approved record persisted");
        let grn = store.get("g-grn").expect("granted record persisted");
        assert_eq!(req.state, GrantState::Expired);
        assert_eq!(app.state, GrantState::Expired);
        assert_eq!(grn.state, GrantState::Revoked);
        assert!(req.state.is_terminal());
        assert!(app.state.is_terminal());
        assert!(grn.state.is_terminal());
    }

    /// Phase 3.5 — drift detector finds an externally-added admin
    /// (mock `AdminManager` returns a user not tracked by any
    /// grant). The supervisor must emit a `DeviceControlFinding`
    /// + paired `EvidenceRecord` on the next `drift_tick`.
    #[tokio::test(flavor = "current_thread")]
    async fn drift_scan_finds_externally_added_admin() {
        let tmp = TempDir::new().unwrap();
        // 1 second cadence is well below the 3 s drain window so
        // we are guaranteed at least one `drift_tick` firing.
        let cfg = cfg_with_drift(true, Some(tmp.path().join("grants.json")), 1);
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let (controller, signal) = ShutdownController::new();

        let admin = Arc::new(FakeAdmin::default());
        // Inject a single untracked admin ("mallory") with no
        // matching grant in the ledger.
        *admin.admins.lock().unwrap() = Some(vec![AdminAccount {
            username: "mallory".into(),
            source: "local".into(),
            since: None,
            group: Some("sudo".into()),
        }]);

        let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
        // Supervisor parks if disabled; here it must be active.
        assert!(h.sender.is_some(), "supervisor must be active");
        // Wait long enough for the `drift_tick` to fire at least
        // once. The first tick arrives `drift_check_interval_secs`
        // after the immediate-tick consume in `start`.
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let mut kinds = Vec::new();
        while let Ok(Some(ev)) =
            tokio::time::timeout(Duration::from_millis(200), server_rx.recv()).await
        {
            kinds.push(ev.kind);
        }
        controller.shutdown();
        h.module.task.await.unwrap().unwrap();

        // Expect at least one DeviceControlFinding + one
        // EvidenceRecord. The supervisor may have run multiple
        // ticks within the 1.5 s window so we accept >= 1.
        let finding_count = kinds
            .iter()
            .filter(|k| matches!(k, EventKind::DeviceControlFinding { .. }))
            .count();
        let evidence_count = kinds
            .iter()
            .filter(|k| matches!(k, EventKind::EvidenceRecord { .. }))
            .count();
        assert!(
            finding_count >= 1,
            "expected >=1 DeviceControlFinding, saw {finding_count} in {kinds:?}",
        );
        assert!(
            evidence_count >= 1,
            "expected >=1 EvidenceRecord, saw {evidence_count} in {kinds:?}",
        );

        // Validate the Finding payload shape: kind=admin_drift +
        // expected evidence keys.
        let finding_payload = kinds
            .iter()
            .find_map(|k| match k {
                EventKind::DeviceControlFinding { payload } => Some(payload.clone()),
                _ => None,
            })
            .expect("already asserted >=1 finding");
        let parsed: serde_json::Value =
            serde_json::from_str(&finding_payload).expect("Finding JSON must parse");
        assert_eq!(parsed["kind"], "admin_drift");
        assert_eq!(parsed["evidence"]["user"], "mallory");
        assert_eq!(parsed["evidence"]["drift_kind"], "untracked_admin");
    }

    /// Phase 3.5 — when `list_admins` returns only allow-listed
    /// users (root etc.), the drift scan must produce no findings.
    #[tokio::test(flavor = "current_thread")]
    async fn drift_scan_emits_nothing_when_ledger_matches_os() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg_with_drift(true, Some(tmp.path().join("grants.json")), 1);
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let (controller, signal) = ShutdownController::new();

        let admin = Arc::new(FakeAdmin::default());
        *admin.admins.lock().unwrap() = Some(vec![AdminAccount {
            username: "root".into(),
            source: "local".into(),
            since: None,
            group: Some("wheel".into()),
        }]);

        let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let mut kinds = Vec::new();
        while let Ok(Some(ev)) =
            tokio::time::timeout(Duration::from_millis(200), server_rx.recv()).await
        {
            kinds.push(ev.kind);
        }
        controller.shutdown();
        h.module.task.await.unwrap().unwrap();

        let drift_findings: Vec<_> = kinds
            .iter()
            .filter(|k| matches!(k, EventKind::DeviceControlFinding { .. }))
            .collect();
        assert!(
            drift_findings.is_empty(),
            "baseline allow-list must produce no drift findings; saw {drift_findings:?}",
        );
    }

    /// Phase 3.7 — every state transition must emit exactly one
    /// `EvidenceRecord`. Walks a grant through
    /// Requested → Granted → Revoked and verifies three transition
    /// records appear on the bus (one per transition).
    #[tokio::test(flavor = "current_thread")]
    async fn every_transition_emits_evidence_record() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg(true, Some(tmp.path().join("grants.json")));
        let (bus, mut server_rx) = EventBus::new(32, 32);
        let (controller, signal) = ShutdownController::new();

        let admin = Arc::new(FakeAdmin::default());
        let until = Utc::now() + chrono::Duration::hours(1);
        *admin.next_grant_handle.lock().unwrap() = Some(handle("h-3", until));

        let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
        let sender = h.sender.expect("module should be active");

        sender
            .send(JitAdminRequest::NewRequest {
                id: "g-3".into(),
                requested_by: "ops".into(),
                user: user("alice"),
                until,
            })
            .await
            .unwrap();
        sender
            .send(JitAdminRequest::Approve {
                id: "g-3".into(),
                reason: Some("policy ok".into()),
            })
            .await
            .unwrap();
        sender
            .send(JitAdminRequest::Revoke {
                id: "g-3".into(),
                reason: Some(RevocationReason::Operator),
            })
            .await
            .unwrap();

        let kinds = drain_server(&mut server_rx).await;
        controller.shutdown();
        h.module.task.await.unwrap().unwrap();

        // Decode every EvidenceRecord and bucket by `operation`.
        let mut ops: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        for kind in &kinds {
            if let EventKind::EvidenceRecord { payload } = kind {
                let v: serde_json::Value =
                    serde_json::from_str(payload).expect("evidence payload must be JSON");
                let op = v["operation"]
                    .as_str()
                    .expect("operation field must be a string")
                    .to_string();
                let entry = ops.entry(op).or_insert(0);
                *entry += 1;
            }
        }
        assert_eq!(
            ops.get("request_received").copied().unwrap_or(0),
            1,
            "expected exactly one request_received evidence; ops = {ops:?}",
        );
        assert_eq!(
            ops.get("granted").copied().unwrap_or(0),
            1,
            "expected exactly one granted evidence; ops = {ops:?}",
        );
        assert_eq!(
            ops.get("revoked").copied().unwrap_or(0),
            1,
            "expected exactly one revoked evidence; ops = {ops:?}",
        );
    }

    /// Phase 3.7 — the deny path produces exactly one transition
    /// evidence record (`operation = "denied"`).
    #[tokio::test(flavor = "current_thread")]
    async fn deny_path_emits_evidence_record() {
        let tmp = TempDir::new().unwrap();
        let cfg = cfg(true, Some(tmp.path().join("grants.json")));
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let (controller, signal) = ShutdownController::new();
        let admin = Arc::new(FakeAdmin::default());
        let until = Utc::now() + chrono::Duration::hours(1);

        let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
        let sender = h.sender.expect("module should be active");
        sender
            .send(JitAdminRequest::NewRequest {
                id: "g-4".into(),
                requested_by: "ops".into(),
                user: user("alice"),
                until,
            })
            .await
            .unwrap();
        sender
            .send(JitAdminRequest::Deny {
                id: "g-4".into(),
                reason: Some("after-hours".into()),
            })
            .await
            .unwrap();

        let kinds = drain_server(&mut server_rx).await;
        controller.shutdown();
        h.module.task.await.unwrap().unwrap();

        let denied_count = kinds
            .iter()
            .filter_map(|k| match k {
                EventKind::EvidenceRecord { payload } => Some(payload),
                _ => None,
            })
            .filter_map(|p| serde_json::from_str::<serde_json::Value>(p).ok())
            .filter(|v| v["operation"] == "denied")
            .count();
        assert_eq!(
            denied_count, 1,
            "expected exactly one `denied` evidence record in {kinds:?}",
        );
    }

    #[test]
    fn already_revoked_error_is_swallowed() {
        let err = AdminError::Command("user is not a member of admin group".into());
        assert!(is_already_revoked(&err));
        let err = AdminError::Command("net localgroup add returned 5".into());
        assert!(!is_already_revoked(&err));
    }

    /// Compile-time assurance: the supervisor accepts a real
    /// `AdminManager` via `Arc<dyn AdminManager>` so the wiring in
    /// `sda-agent/src/main.rs` does not need a special-case path.
    #[allow(dead_code)]
    fn _trait_object_compiles_ok() {
        let _: Arc<dyn AdminManager> = Arc::new(LinuxAdminManagerStub);
    }

    /// Empty stub used only to exercise the trait-object bound at
    /// compile time on hosts where the real Linux/macOS/Windows
    /// implementations are gated out.
    struct LinuxAdminManagerStub;
    impl AdminManager for LinuxAdminManagerStub {
        fn list_admins(&self) -> Result<Vec<AdminAccount>, AdminError> {
            Ok(Vec::new())
        }
        fn grant_admin(
            &self,
            _user: &UserRef,
            _until: DateTime<Utc>,
        ) -> Result<GrantHandle, AdminError> {
            Err(AdminError::NotImplemented)
        }
        fn revoke_admin(&self, _handle: &GrantHandle) -> Result<(), AdminError> {
            Err(AdminError::NotImplemented)
        }
        fn observed_grants(&self) -> Result<Vec<GrantHandle>, AdminError> {
            Err(AdminError::NotImplemented)
        }
    }

    #[test]
    fn os_command_runner_is_send_sync() {
        // Sanity: ensure the production runner can be passed across
        // tasks. (We don't actually use it in async tests because
        // the FakeAdmin keeps the supervisor hermetic.)
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<OsCommandRunner>();
    }
}
