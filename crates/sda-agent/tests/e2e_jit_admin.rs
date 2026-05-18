//! Phase 3 JIT-admin end-to-end suite (task 3.8).
//!
//! Hermetic exercises of the JIT-admin lifecycle shipped in Phase 3
//! (grant request, approval, denial, time-boxed grant, automatic
//! revoke triggers, drift detection, evidence-chain continuity).
//! The harness reuses the in-process [`EventBus`] so every scenario
//! walks the same wire shape the supervisor publishes in
//! `sda-agent::main`.
//!
//! Coverage:
//!
//! 1. Grant request → approval → time-boxed admin → automatic timer
//!    revoke → evidence chain (`request_approve_revoke_chain`).
//! 2. Grant request → denial → evidence
//!    (`request_then_deny_emits_revoked_event`).
//! 3. Boot sweep revokes expired grants — simulate restart with
//!    overdue grants in the ledger
//!    (`boot_sweep_revokes_overdue_granted_record`,
//!    `boot_sweep_handles_grants_expired_during_long_shutdown`).
//! 4. Drift detection finds an externally-added admin (mock
//!    `AdminManager` returns extra user)
//!    (`drift_detection_finds_externally_added_admin`).
//! 5. Heartbeat-loss revocation — simulate no heartbeat for >
//!    `heartbeat_loss_secs` (`heartbeat_loss_revokes_active_grant`).
//! 6. Power-profile revocation — simulate `PowerSuspend` transition
//!    (`power_transition_revokes_active_grant`).
//! 7. Evidence chain continuity across the request → approve →
//!    revoke lifecycle (`evidence_chain_continuity_across_lifecycle`).
//!
//! All scenarios run on in-process state (mock [`AdminManager`],
//! tempdirs, in-process bus). `make e2e-jit-admin` runs in a few
//! seconds on every CI host.

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use sda_core::config::{AgentConfig, JitAdminConfig};
use sda_core::signal::ShutdownController;
use sda_event_bus::{Event, EventBus, EventKind};
use sda_jit_admin::{
    GrantRecord, GrantState, GrantStore, JitAdminModule, JitAdminRequest, RevocationReason,
};
use sda_pal::admin_manager::{AdminAccount, AdminError, AdminManager, GrantHandle, UserRef};
use tempfile::TempDir;
use tokio::sync::mpsc;

// ---------- Test harness ---------------------------------------------------

/// Mock [`AdminManager`] that records every call and lets the test
/// pre-program `list_admins`, `grant_admin`, and `revoke_admin`
/// outcomes per call.
///
/// This is a separate type from the `FakeAdmin` used in
/// `sda-jit-admin`'s in-tree tests because that one is gated behind
/// `#[cfg(test)] mod tests`. Integration tests cannot reach into
/// another crate's `mod tests`, so we ship an equivalent mock here.
#[derive(Debug, Default)]
struct MockAdmin {
    /// Canned `list_admins` payload. When `None`, returns an empty
    /// list (the historical default that pre-3.5 tests expect).
    /// Drift tests overwrite this to inject untracked admins.
    admins: Mutex<Option<Vec<AdminAccount>>>,
    /// Canned next [`GrantHandle`] returned by `grant_admin`. Set by
    /// tests that need a deterministic handle id.
    next_grant_handle: Mutex<Option<GrantHandle>>,
    /// Recorded `grant_admin` calls in invocation order.
    grants: Mutex<Vec<UserRef>>,
    /// Recorded `revoke_admin` calls in invocation order.
    revokes: Mutex<Vec<GrantHandle>>,
}

impl AdminManager for MockAdmin {
    fn list_admins(&self) -> Result<Vec<AdminAccount>, AdminError> {
        Ok(self.admins.lock().unwrap().clone().unwrap_or_default())
    }

    fn grant_admin(
        &self,
        user: &UserRef,
        until: chrono::DateTime<Utc>,
    ) -> Result<GrantHandle, AdminError> {
        self.grants.lock().unwrap().push(user.clone());
        Ok(self
            .next_grant_handle
            .lock()
            .unwrap()
            .take()
            .unwrap_or_else(|| GrantHandle {
                id: format!("h-{}", uuid::Uuid::new_v4()),
                user: user.clone(),
                until,
            }))
    }

    fn revoke_admin(&self, handle: &GrantHandle) -> Result<(), AdminError> {
        self.revokes.lock().unwrap().push(handle.clone());
        Ok(())
    }

    fn observed_grants(&self) -> Result<Vec<GrantHandle>, AdminError> {
        Ok(Vec::new())
    }
}

fn user(name: &str) -> UserRef {
    UserRef {
        username: name.into(),
        domain: None,
    }
}

fn handle(id: &str, until: chrono::DateTime<Utc>) -> GrantHandle {
    GrantHandle {
        id: id.into(),
        user: user("alice"),
        until,
    }
}

/// Build an [`AgentConfig`] with the JIT-admin module enabled and a
/// long drift cadence so the drift tick does NOT fire inside the
/// scenario's drain window. Drift-specific tests override this via
/// [`cfg_with_drift`].
fn cfg(state_path: PathBuf) -> AgentConfig {
    let mut c = AgentConfig::default();
    c.modules.jit_admin = JitAdminConfig {
        enabled: true,
        state_path: Some(state_path),
        heartbeat_loss_secs: 4,
        drift_check_interval_secs: 3600,
    };
    c
}

/// Like [`cfg`], but with a short drift-scan cadence so the
/// supervisor's `drift_tick` fires inside the test's drain window.
fn cfg_with_drift(state_path: PathBuf, drift_check_interval_secs: u64) -> AgentConfig {
    let mut c = cfg(state_path);
    c.modules.jit_admin.drift_check_interval_secs = drift_check_interval_secs;
    c
}

/// Like [`cfg`], but with a short heartbeat-loss budget so the
/// watchdog can fire inside the test's drain window.
fn cfg_with_heartbeat(state_path: PathBuf, heartbeat_loss_secs: u64) -> AgentConfig {
    let mut c = cfg(state_path);
    c.modules.jit_admin.heartbeat_loss_secs = heartbeat_loss_secs;
    c
}

/// Drain everything that has appeared on `server_rx` within
/// `budget` and return the captured `EventKind`s in arrival order.
async fn drain_for(rx: &mut mpsc::Receiver<Event>, budget: Duration) -> Vec<EventKind> {
    let mut out = Vec::new();
    while let Ok(Some(ev)) = tokio::time::timeout(budget, rx.recv()).await {
        out.push(ev.kind);
    }
    out
}

fn count<F: Fn(&EventKind) -> bool>(kinds: &[EventKind], pred: F) -> usize {
    kinds.iter().filter(|k| pred(k)).count()
}

// ---------- Scenario 1: request → approve → revoke chain -------------------

/// Request, approve, then explicit revoke.
///
/// Asserts the supervisor walks the full grant lifecycle:
/// `Requested` → `Approved` → `Granted` → `Revoked`, calling
/// `grant_admin` once and `revoke_admin` once, and emitting one
/// `JitAdminRequested`, one `JitAdminGranted`, and one
/// `JitAdminRevoked` event in that order.
#[tokio::test(flavor = "current_thread")]
async fn request_approve_revoke_chain() {
    let tmp = TempDir::new().unwrap();
    let cfg = cfg(tmp.path().join("grants.json"));
    let (bus, mut server_rx) = EventBus::new(64, 64);
    let (controller, signal) = ShutdownController::new();

    let admin = Arc::new(MockAdmin::default());
    let until = Utc::now() + chrono::Duration::hours(1);
    *admin.next_grant_handle.lock().unwrap() = Some(handle("h-1", until));

    let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
    let sender = h.sender.expect("module must be active when enabled");

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
            reason: Some("on-call paged".into()),
        })
        .await
        .unwrap();
    sender
        .send(JitAdminRequest::Revoke {
            id: "g-1".into(),
            reason: Some(RevocationReason::Operator),
        })
        .await
        .unwrap();

    let kinds = drain_for(&mut server_rx, Duration::from_millis(200)).await;
    controller.shutdown();
    h.module.task.await.unwrap().unwrap();

    assert_eq!(admin.grants.lock().unwrap().len(), 1, "grant_admin once");
    assert_eq!(admin.revokes.lock().unwrap().len(), 1, "revoke_admin once");

    // Three lifecycle events on the bus, in order.
    let lifecycle: Vec<&EventKind> = kinds
        .iter()
        .filter(|k| {
            matches!(
                k,
                EventKind::JitAdminRequested { .. }
                    | EventKind::JitAdminGranted { .. }
                    | EventKind::JitAdminRevoked { .. }
            )
        })
        .collect();
    assert!(
        matches!(
            lifecycle.as_slice(),
            [
                EventKind::JitAdminRequested { .. },
                EventKind::JitAdminGranted { .. },
                EventKind::JitAdminRevoked { .. },
            ]
        ),
        "expected Requested → Granted → Revoked, saw {lifecycle:?}",
    );

    // Final ledger state is `Revoked`.
    let store = GrantStore::open(tmp.path().join("grants.json")).unwrap();
    let r = store.get("g-1").expect("grant must persist");
    assert_eq!(r.state, GrantState::Revoked);
    assert!(r.state.is_terminal());
}

// ---------- Scenario 2: request → deny -------------------------------------

/// A denied request walks
/// `Requested` → `Denied` and emits `JitAdminRequested` +
/// `JitAdminRevoked` (the supervisor reuses the
/// `JitAdminRevoked` wire shape for terminal denials).
/// `grant_admin` MUST NOT be called.
#[tokio::test(flavor = "current_thread")]
async fn request_then_deny_emits_revoked_event() {
    let tmp = TempDir::new().unwrap();
    let cfg = cfg(tmp.path().join("grants.json"));
    let (bus, mut server_rx) = EventBus::new(64, 64);
    let (controller, signal) = ShutdownController::new();
    let admin = Arc::new(MockAdmin::default());

    let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
    let sender = h.sender.expect("module must be active");

    sender
        .send(JitAdminRequest::NewRequest {
            id: "g-deny".into(),
            requested_by: "ops".into(),
            user: user("bob"),
            until: Utc::now() + chrono::Duration::hours(1),
        })
        .await
        .unwrap();
    sender
        .send(JitAdminRequest::Deny {
            id: "g-deny".into(),
            reason: Some("policy violation".into()),
        })
        .await
        .unwrap();

    let kinds = drain_for(&mut server_rx, Duration::from_millis(200)).await;
    controller.shutdown();
    h.module.task.await.unwrap().unwrap();

    assert!(
        admin.grants.lock().unwrap().is_empty(),
        "grant_admin must not be called for denied requests",
    );
    assert!(
        admin.revokes.lock().unwrap().is_empty(),
        "revoke_admin must not be called for denied requests",
    );

    let saw_requested = count(&kinds, |k| matches!(k, EventKind::JitAdminRequested { .. }));
    let saw_revoked = count(&kinds, |k| matches!(k, EventKind::JitAdminRevoked { .. }));
    let saw_granted = count(&kinds, |k| matches!(k, EventKind::JitAdminGranted { .. }));
    assert_eq!(saw_requested, 1, "exactly one JitAdminRequested expected");
    assert_eq!(saw_revoked, 1, "exactly one JitAdminRevoked expected");
    assert_eq!(saw_granted, 0, "no JitAdminGranted on deny path");

    let store = GrantStore::open(tmp.path().join("grants.json")).unwrap();
    let r = store.get("g-deny").expect("grant must persist");
    assert_eq!(r.state, GrantState::Denied);
}

// ---------- Scenario 3: boot sweep on overdue grants -----------------------

/// Boot sweep revokes a `Granted` record
/// whose `until` is in the past at startup. The OS-level revoke
/// must be invoked exactly once and the on-disk record must be
/// terminal (`Revoked`) afterwards.
#[tokio::test(flavor = "current_thread")]
async fn boot_sweep_revokes_overdue_granted_record() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("grants.json");
    let past = Utc::now() - chrono::Duration::hours(1);

    {
        let mut store = GrantStore::open(&path).unwrap();
        let mut granted = GrantRecord::new_requested("g-overdue", "ops", user("alice"), past, past);
        granted.state = GrantState::Granted;
        granted.handle = Some(handle("h-overdue", past));
        store.upsert(granted).unwrap();
    }

    let cfg = cfg(path.clone());
    let (bus, mut server_rx) = EventBus::new(64, 64);
    let (controller, signal) = ShutdownController::new();
    let admin = Arc::new(MockAdmin::default());

    let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
    tokio::time::sleep(Duration::from_millis(150)).await;
    let _ = drain_for(&mut server_rx, Duration::from_millis(50)).await;
    controller.shutdown();
    h.module.task.await.unwrap().unwrap();

    let revokes = admin.revokes.lock().unwrap();
    assert_eq!(
        revokes.len(),
        1,
        "boot sweep must revoke the Granted record"
    );
    assert_eq!(revokes[0].id, "h-overdue");

    let store = GrantStore::open(&path).unwrap();
    let r = store.get("g-overdue").expect("record persisted");
    assert_eq!(r.state, GrantState::Revoked);
    assert!(r.state.is_terminal());
}

/// An edge case for the boot sweep: a grant
/// whose `until` was multiple days ago (simulating a long agent
/// outage) MUST still be force-revoked on the next boot. The sweep
/// is idempotent, so a second supervisor startup against the same
/// ledger MUST NOT call `revoke_admin` again — the record is
/// already terminal.
#[tokio::test(flavor = "current_thread")]
async fn boot_sweep_handles_grants_expired_during_long_shutdown() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("grants.json");
    let multi_day_past = Utc::now() - chrono::Duration::days(3);

    {
        let mut store = GrantStore::open(&path).unwrap();
        let mut stale = GrantRecord::new_requested(
            "g-stale",
            "ops",
            user("alice"),
            multi_day_past,
            multi_day_past,
        );
        stale.state = GrantState::Granted;
        stale.handle = Some(handle("h-stale", multi_day_past));
        store.upsert(stale).unwrap();
    }

    let cfg = cfg(path.clone());
    let admin = Arc::new(MockAdmin::default());

    // First boot: must revoke.
    {
        let (bus, mut server_rx) = EventBus::new(64, 64);
        let (controller, signal) = ShutdownController::new();
        let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = drain_for(&mut server_rx, Duration::from_millis(50)).await;
        controller.shutdown();
        h.module.task.await.unwrap().unwrap();
    }
    assert_eq!(
        admin.revokes.lock().unwrap().len(),
        1,
        "first boot must call revoke_admin exactly once",
    );

    // Second boot against the same on-disk ledger: the record is
    // already terminal, so `revoke_admin` MUST NOT be called again.
    {
        let (bus, mut server_rx) = EventBus::new(64, 64);
        let (controller, signal) = ShutdownController::new();
        let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = drain_for(&mut server_rx, Duration::from_millis(50)).await;
        controller.shutdown();
        h.module.task.await.unwrap().unwrap();
    }
    assert_eq!(
        admin.revokes.lock().unwrap().len(),
        1,
        "second boot must be idempotent: revoke_admin still only called once",
    );

    let store = GrantStore::open(&path).unwrap();
    assert_eq!(
        store.get("g-stale").unwrap().state,
        GrantState::Revoked,
        "record must remain terminal across boots",
    );
}

// ---------- Scenario 4: drift detection -----------------------------------

/// Drift detection finds an admin that the
/// agent did not grant (e.g. a user added to `sudo` outside SDA)
/// and emits a `DeviceControlFinding` paired with an
/// `EvidenceRecord`.
#[tokio::test(flavor = "current_thread")]
async fn drift_detection_finds_externally_added_admin() {
    let tmp = TempDir::new().unwrap();
    let cfg = cfg_with_drift(tmp.path().join("grants.json"), 1);
    let (bus, mut server_rx) = EventBus::new(64, 64);
    let (controller, signal) = ShutdownController::new();

    let admin = Arc::new(MockAdmin::default());
    *admin.admins.lock().unwrap() = Some(vec![AdminAccount {
        username: "mallory".into(),
        source: "local".into(),
        since: None,
        group: Some("sudo".into()),
    }]);

    let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
    assert!(h.sender.is_some(), "supervisor must be active");

    // Wait for at least one drift_tick. The first tick fires
    // `drift_check_interval_secs` after start.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let kinds = drain_for(&mut server_rx, Duration::from_millis(150)).await;
    controller.shutdown();
    h.module.task.await.unwrap().unwrap();

    let finding_count = count(&kinds, |k| {
        matches!(k, EventKind::DeviceControlFinding { .. })
    });
    let evidence_count = count(&kinds, |k| matches!(k, EventKind::EvidenceRecord { .. }));
    assert!(
        finding_count >= 1,
        "expected ≥1 DeviceControlFinding, saw {finding_count} in {kinds:?}",
    );
    assert!(
        evidence_count >= 1,
        "expected ≥1 EvidenceRecord, saw {evidence_count} in {kinds:?}",
    );

    let payload = kinds
        .iter()
        .find_map(|k| match k {
            EventKind::DeviceControlFinding { payload } => Some(payload.clone()),
            _ => None,
        })
        .expect("we already asserted ≥1 finding");
    let parsed: serde_json::Value =
        serde_json::from_str(&payload).expect("finding JSON must parse");
    assert_eq!(parsed["kind"], "admin_drift");
    assert_eq!(parsed["evidence"]["user"], "mallory");
    assert_eq!(parsed["evidence"]["drift_kind"], "untracked_admin");
}

// ---------- Scenario 5: heartbeat-loss revocation --------------------------

/// Heartbeat loss revokes an active grant.
/// We set `heartbeat_loss_secs = 1`, mark a heartbeat as observed
/// 10 seconds ago, approve a grant, and wait long enough for the
/// watchdog tick to detect the deadline crossing.
#[tokio::test(flavor = "current_thread")]
async fn heartbeat_loss_revokes_active_grant() {
    let tmp = TempDir::new().unwrap();
    let cfg = cfg_with_heartbeat(tmp.path().join("grants.json"), 1);
    let (bus, mut server_rx) = EventBus::new(64, 64);
    let (controller, signal) = ShutdownController::new();

    let admin = Arc::new(MockAdmin::default());
    let until = Utc::now() + chrono::Duration::hours(1);
    *admin.next_grant_handle.lock().unwrap() = Some(handle("h-hb", until));

    let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
    let sender = h.sender.expect("module must be active");

    // Plant a stale heartbeat so the watchdog has a deadline to
    // miss. Without this, `heartbeat_revocations` returns empty
    // because `last_heartbeat` is None at boot.
    sender
        .send(JitAdminRequest::HeartbeatObserved {
            at: Utc::now() - chrono::Duration::seconds(10),
        })
        .await
        .unwrap();
    sender
        .send(JitAdminRequest::NewRequest {
            id: "g-hb".into(),
            requested_by: "ops".into(),
            user: user("alice"),
            until,
        })
        .await
        .unwrap();
    sender
        .send(JitAdminRequest::Approve {
            id: "g-hb".into(),
            reason: None,
        })
        .await
        .unwrap();

    // Wait long enough for the watchdog tick to fire and revoke.
    // With heartbeat_loss_secs = 1, the poll cadence is also 1 s,
    // so 2.5 s is enough budget for at least two ticks.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let _ = drain_for(&mut server_rx, Duration::from_millis(100)).await;
    controller.shutdown();
    h.module.task.await.unwrap().unwrap();

    assert_eq!(
        admin.revokes.lock().unwrap().len(),
        1,
        "heartbeat-loss watchdog must revoke the active grant once",
    );
    let store = GrantStore::open(tmp.path().join("grants.json")).unwrap();
    let r = store.get("g-hb").expect("grant persists");
    assert_eq!(r.state, GrantState::Revoked);
    assert_eq!(
        r.last_reason.as_deref(),
        Some("heartbeat_loss"),
        "last_reason must reflect the watchdog trigger",
    );
}

// ---------- Scenario 6: power-profile revocation ---------------------------

/// A power transition (suspend / sleep /
/// lock) revokes any active grant immediately. We approve a grant
/// and feed in a `PowerSuspend` transition, then assert
/// `revoke_admin` was called once.
#[tokio::test(flavor = "current_thread")]
async fn power_transition_revokes_active_grant() {
    let tmp = TempDir::new().unwrap();
    let cfg = cfg(tmp.path().join("grants.json"));
    let (bus, mut server_rx) = EventBus::new(64, 64);
    let (controller, signal) = ShutdownController::new();

    let admin = Arc::new(MockAdmin::default());
    let until = Utc::now() + chrono::Duration::hours(1);
    *admin.next_grant_handle.lock().unwrap() = Some(handle("h-pwr", until));

    let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
    let sender = h.sender.expect("module must be active");

    sender
        .send(JitAdminRequest::NewRequest {
            id: "g-pwr".into(),
            requested_by: "ops".into(),
            user: user("alice"),
            until,
        })
        .await
        .unwrap();
    sender
        .send(JitAdminRequest::Approve {
            id: "g-pwr".into(),
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

    let kinds = drain_for(&mut server_rx, Duration::from_millis(200)).await;
    controller.shutdown();
    h.module.task.await.unwrap().unwrap();

    assert_eq!(admin.revokes.lock().unwrap().len(), 1);
    let saw_revoked = count(&kinds, |k| matches!(k, EventKind::JitAdminRevoked { .. }));
    assert_eq!(saw_revoked, 1, "exactly one JitAdminRevoked expected");

    let store = GrantStore::open(tmp.path().join("grants.json")).unwrap();
    let r = store.get("g-pwr").unwrap();
    assert_eq!(r.state, GrantState::Revoked);
    assert_eq!(r.last_reason.as_deref(), Some("power_suspend"));
}

// ---------- Scenario 7: evidence chain continuity --------------------------

/// Every JIT-admin transition emits exactly
/// one `EvidenceRecord` on the bus, so a request → approve → revoke
/// chain produces three records (one per transition). This is the
/// audit-trail invariant called out in `docs/device-control.md` § 7 ("evidence
/// at every transition").
#[tokio::test(flavor = "current_thread")]
async fn evidence_chain_continuity_across_lifecycle() {
    let tmp = TempDir::new().unwrap();
    let cfg = cfg(tmp.path().join("grants.json"));
    let (bus, mut server_rx) = EventBus::new(64, 64);
    let (controller, signal) = ShutdownController::new();

    let admin = Arc::new(MockAdmin::default());
    let until = Utc::now() + chrono::Duration::hours(1);
    *admin.next_grant_handle.lock().unwrap() = Some(handle("h-chain", until));

    let h = JitAdminModule::start(&cfg, bus, signal, admin.clone(), tmp.path().to_path_buf());
    let sender = h.sender.expect("module must be active");

    sender
        .send(JitAdminRequest::NewRequest {
            id: "g-chain".into(),
            requested_by: "ops".into(),
            user: user("alice"),
            until,
        })
        .await
        .unwrap();
    sender
        .send(JitAdminRequest::Approve {
            id: "g-chain".into(),
            reason: None,
        })
        .await
        .unwrap();
    sender
        .send(JitAdminRequest::Revoke {
            id: "g-chain".into(),
            reason: Some(RevocationReason::Operator),
        })
        .await
        .unwrap();

    let kinds = drain_for(&mut server_rx, Duration::from_millis(200)).await;
    controller.shutdown();
    h.module.task.await.unwrap().unwrap();

    let evidence_count = count(&kinds, |k| matches!(k, EventKind::EvidenceRecord { .. }));
    assert_eq!(
        evidence_count, 3,
        "expected exactly 3 EvidenceRecord events (request, granted, revoked), saw {kinds:?}",
    );

    // Record-id continuity: every evidence payload has a unique
    // `evidence_id` and the supervisor wired all three into the
    // grant's `evidence_ids` audit list.
    let mut evidence_ids: Vec<String> = Vec::new();
    for k in &kinds {
        if let EventKind::EvidenceRecord { payload } = k {
            let parsed: serde_json::Value = serde_json::from_str(payload).unwrap();
            evidence_ids.push(parsed["evidence_id"].as_str().unwrap().to_string());
        }
    }
    assert_eq!(evidence_ids.len(), 3);
    assert_eq!(
        evidence_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3,
        "evidence ids must be unique across the chain",
    );

    let store = GrantStore::open(tmp.path().join("grants.json")).unwrap();
    let r = store.get("g-chain").unwrap();
    assert_eq!(r.state, GrantState::Revoked);
    assert_eq!(
        r.evidence_ids.len(),
        3,
        "ledger must record three evidence ids (one per transition)",
    );
    assert_eq!(
        r.evidence_ids, evidence_ids,
        "ledger evidence ids must match the wire chain in order",
    );
}

// ---------- Smoke test: parks when disabled --------------------------------

/// Sanity smoke — when `modules.jit_admin.enabled = false`, the
/// supervisor must park (no sender) and emit nothing on the bus,
/// even with a populated ledger. Mirrors the behaviour of the
/// `parks_when_disabled` unit test but covers the integration
/// surface.
#[tokio::test(flavor = "current_thread")]
async fn supervisor_parks_when_disabled() {
    let tmp = TempDir::new().unwrap();
    let mut config = AgentConfig::default();
    config.modules.jit_admin = JitAdminConfig {
        enabled: false,
        state_path: Some(tmp.path().join("grants.json")),
        heartbeat_loss_secs: 4,
        drift_check_interval_secs: 3600,
    };
    let (bus, mut server_rx) = EventBus::new(64, 64);
    let (controller, signal) = ShutdownController::new();
    let admin = Arc::new(MockAdmin::default());

    let h = JitAdminModule::start(
        &config,
        bus,
        signal,
        admin.clone(),
        tmp.path().to_path_buf(),
    );
    assert!(
        h.sender.is_none(),
        "disabled supervisor must not return a sender"
    );
    let kinds = drain_for(&mut server_rx, Duration::from_millis(100)).await;
    controller.shutdown();
    h.module.task.await.unwrap().unwrap();
    assert!(kinds.is_empty(), "disabled supervisor must not emit events");
}
