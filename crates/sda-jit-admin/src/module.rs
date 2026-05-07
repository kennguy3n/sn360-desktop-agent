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
        info!(
            state_path = %state_path.display(),
            heartbeat_loss_secs = watchdog_cfg.heartbeat_loss_secs,
            heartbeat_poll_secs = watchdog_cfg.heartbeat_poll_secs,
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
        let record = GrantRecord::new_requested(id.clone(), requested_by, user, until, now);
        let mut store = self.store.lock().await;
        if let Err(err) = store.upsert(record.clone()) {
            warn!(grant_id = %id, error = %err, "jit_admin: failed to persist new request");
            return;
        }
        drop(store);
        self.emit_event(EventKind::JitAdminRequested {
            payload: serde_json::to_string(&record).unwrap_or_default(),
        });
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
                let granted = match self.sm.apply(
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
                if let Err(err) = self.persist(&granted).await {
                    warn!(grant_id = id, error = %err, "jit_admin: failed to persist grant");
                    return;
                }
                self.emit_event(EventKind::JitAdminGranted {
                    payload: serde_json::to_string(&granted).unwrap_or_default(),
                });
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
        let denied = match self
            .sm
            .apply(&record, StateTransition::Deny { reason }, now)
        {
            Ok(r) => r,
            Err(err) => {
                warn!(grant_id = id, error = %err, "jit_admin: deny transition rejected");
                return;
            }
        };
        if let Err(err) = self.persist(&denied).await {
            warn!(grant_id = id, error = %err, "jit_admin: failed to persist deny");
            return;
        }
        // Denied records produce a JitAdminRevoked payload so the
        // server has a single terminal event regardless of the
        // intermediate state — see PROPOSAL.md § 9.3.
        self.emit_event(EventKind::JitAdminRevoked {
            payload: serde_json::to_string(&denied).unwrap_or_default(),
        });
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

        let revoked = match self
            .sm
            .apply(&record, StateTransition::Revoke { reason }, now)
        {
            Ok(r) => r,
            Err(err) => {
                warn!(grant_id = id, error = %err, "jit_admin: revoke transition rejected");
                return;
            }
        };
        if let Err(err) = self.persist(&revoked).await {
            warn!(grant_id = id, error = %err, "jit_admin: failed to persist revoke");
            return;
        }
        self.emit_event(EventKind::JitAdminRevoked {
            payload: serde_json::to_string(&revoked).unwrap_or_default(),
        });
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
        let expired = match self.sm.apply(&record, StateTransition::Expire, now) {
            Ok(r) => r,
            Err(err) => {
                warn!(grant_id = id, error = %err, "jit_admin: expire transition rejected");
                return;
            }
        };
        if let Err(err) = self.persist(&expired).await {
            warn!(grant_id = id, error = %err, "jit_admin: failed to persist expire");
            return;
        }
        self.emit_event(EventKind::JitAdminRevoked {
            payload: serde_json::to_string(&expired).unwrap_or_default(),
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

/// Compact evidence payload for the cases where the AdminManager
/// fails. The supervisor emits these as
/// `EventKind::EvidenceRecord` so the audit chain reflects the
/// failure even when the state-machine record stays put.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdminEvidence {
    schema_version: u16,
    grant_id: String,
    user: UserRef,
    handle_id: Option<String>,
    state: GrantState,
    operation: String,
    error: String,
    occurred_at: DateTime<Utc>,
}

impl AdminEvidence {
    fn failure(record: &GrantRecord, operation: &str, error: &AdminError) -> Self {
        Self {
            schema_version: 1,
            grant_id: record.id.clone(),
            user: record.user.clone(),
            handle_id: record.handle.as_ref().map(|h: &GrantHandle| h.id.clone()),
            state: record.state,
            operation: operation.into(),
            error: error.to_string(),
            occurred_at: Utc::now(),
        }
    }
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
    }

    impl AdminManager for FakeAdmin {
        fn list_admins(&self) -> Result<Vec<AdminAccount>, AdminError> {
            Ok(Vec::new())
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
        };
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
