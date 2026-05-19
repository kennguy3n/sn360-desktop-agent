//! Hermetic end-to-end coverage for the EDR host
//! isolation pipeline.
//!
//! This suite stitches together:
//!
//! - `sda-pal::MockHostIsolation` (in-memory firewall),
//! - `sda-host-isolation::HostIsolationModule` (the agent module
//!   under test — runs the 10-step signed-job validator, builds the
//!   allow-list, invokes the PAL, and publishes
//!   `EventKind::HostIsolationStateChanged`),
//! - the `HostIsolationSubmitter` mailbox shared with the
//!   device-control router in production wiring.
//!
//! Coverage (≥ 6 tests for `docs/edr.md` § 8.1 — Host isolation):
//!
//! 1. `IsolateHost` SignedActionJob → `HostIsolationStateChanged
//!    { isolated: true }` on the bus and the PAL is in the
//!    isolated state.
//! 2. Allow-list emitted on isolation includes the configured
//!    control-plane CIDRs plus loopback (PAL safety invariant).
//! 3. Followup `UnisolateHost` → `isolated: false` and PAL clears.
//! 4. Duplicate `IsolateHost` is a no-op (no second state-change
//!    event).
//! 5. Job rejected by the validator (`Phase1Stub` unknown key id)
//!    never touches the PAL and emits no state change.
//! 6. Disabled module ignores submitted jobs without touching the
//!    PAL.
//! 7. `HostIsolationStateChangedPayload` survives a JSON round-trip
//!    (regression for serde wire shape).

#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use sda_core::config::HostIsolationConfig;
use sda_core::signal::ShutdownController;
use sda_device_control::router::{AgentIdentity, JobValidationHooks, Phase1Stub};
use sda_device_control::signed_job::SignedActionJob;
use sda_device_control::types::{ActionKind, JobRefused};
use sda_event_bus::{Event, EventBus, EventKind, EventReceiver};
use sda_host_isolation::{HostIsolationModule, HostIsolationStateChangedPayload};
use sda_pal::host_isolation::{HostIsolation, MockHostIsolation};
use uuid::Uuid;

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

async fn assert_no_kind<F>(rx: &mut EventReceiver, window: Duration, predicate: F)
where
    F: Fn(&EventKind) -> bool,
{
    let res = await_kind(rx, window, predicate).await;
    assert!(
        res.is_none(),
        "expected no matching event in {:?}, got {:?}",
        window,
        res.map(|e| e.kind)
    );
}

fn identity() -> AgentIdentity {
    AgentIdentity {
        tenant_id: Uuid::nil(),
        device_id: Uuid::nil(),
    }
}

fn enabled_cfg() -> HostIsolationConfig {
    HostIsolationConfig {
        enabled: true,
        control_plane_cidrs: vec!["10.20.0.0/16".into(), "203.0.113.0/24".into()],
        always_allow_dns: true,
        always_allow_loopback: true,
    }
}

/// Validation hooks that accept every action / signature / window
/// so the test can focus on the module's state machine instead of
/// the (already-covered) router validator.
struct AcceptHooks;
impl JobValidationHooks for AcceptHooks {
    fn verify_signature(&self, _job: &SignedActionJob) -> Result<(), JobRefused> {
        Ok(())
    }
    fn action_permitted(&self, _a: ActionKind) -> bool {
        true
    }
    fn in_window(&self, _now: chrono::DateTime<Utc>) -> bool {
        true
    }
}

fn isolate_job(extras: Vec<String>, reason: Option<&str>) -> SignedActionJob {
    SignedActionJob {
        job_id: Uuid::new_v4(),
        tenant_id: Uuid::nil(),
        device_id: Uuid::nil(),
        schema_version: 1,
        recommendation_id: None,
        action: ActionKind::IsolateHost,
        args: serde_json::json!({
            "extra_allow_ips": extras,
            "reason": reason,
        }),
        not_before: Utc::now() - chrono::Duration::seconds(30),
        not_after: Utc::now() + chrono::Duration::hours(1),
        signature: vec![1, 2, 3, 4],
        key_id: "ctrl-plane:hex".into(),
        correlation_id: None,
        additional_signatures: Vec::new(),
    }
}

fn unisolate_job() -> SignedActionJob {
    SignedActionJob {
        job_id: Uuid::new_v4(),
        tenant_id: Uuid::nil(),
        device_id: Uuid::nil(),
        schema_version: 1,
        recommendation_id: None,
        action: ActionKind::UnisolateHost,
        args: serde_json::json!({"reason": "operator"}),
        not_before: Utc::now() - chrono::Duration::seconds(30),
        not_after: Utc::now() + chrono::Duration::hours(1),
        signature: vec![1, 2, 3, 4],
        key_id: "ctrl-plane:hex".into(),
        correlation_id: None,
        additional_signatures: Vec::new(),
    }
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn t01_isolate_host_emits_state_changed_and_isolates_pal() {
    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let pal: Arc<dyn HostIsolation> = Arc::new(MockHostIsolation::new());
    let hooks: Arc<dyn JobValidationHooks + Send + Sync> = Arc::new(AcceptHooks);
    let (controller, signal) = ShutdownController::new();
    let (handle, submitter) =
        HostIsolationModule::start_with(enabled_cfg(), identity(), pal.clone(), hooks, bus, signal);

    submitter
        .submit(isolate_job(vec![], Some("ir")))
        .await
        .unwrap();

    let ev = await_kind(&mut rx, Duration::from_secs(2), |k| {
        matches!(k, EventKind::HostIsolationStateChanged { .. })
    })
    .await
    .expect("HostIsolationStateChanged within 2s");
    let EventKind::HostIsolationStateChanged { payload } = ev.kind else {
        unreachable!()
    };
    let p: HostIsolationStateChangedPayload = serde_json::from_str(&payload).unwrap();
    assert!(p.isolated);
    assert_eq!(p.action, "isolate_host");
    assert_eq!(p.reason.as_deref(), Some("ir"));
    assert!(pal.is_isolated().unwrap());

    controller.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t02_isolate_allow_list_includes_control_plane_cidrs_and_loopback() {
    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let pal: Arc<dyn HostIsolation> = Arc::new(MockHostIsolation::new());
    let hooks: Arc<dyn JobValidationHooks + Send + Sync> = Arc::new(AcceptHooks);
    let (controller, signal) = ShutdownController::new();
    let (handle, submitter) =
        HostIsolationModule::start_with(enabled_cfg(), identity(), pal.clone(), hooks, bus, signal);

    submitter.submit(isolate_job(vec![], None)).await.unwrap();

    let ev = await_kind(&mut rx, Duration::from_secs(2), |k| {
        matches!(k, EventKind::HostIsolationStateChanged { .. })
    })
    .await
    .expect("state change");
    let EventKind::HostIsolationStateChanged { payload } = ev.kind else {
        unreachable!()
    };
    let p: HostIsolationStateChangedPayload = serde_json::from_str(&payload).unwrap();
    assert!(
        p.allowed_ips.iter().any(|s| s == "10.20.0.0/16"),
        "control-plane CIDR missing from allowed_ips: {:?}",
        p.allowed_ips
    );
    assert!(
        p.allowed_ips.iter().any(|s| s == "203.0.113.0/24"),
        "second control-plane CIDR missing: {:?}",
        p.allowed_ips
    );
    assert!(
        p.allowed_ips.iter().any(|s| s == "127.0.0.0/8"),
        "loopback safety invariant missing: {:?}",
        p.allowed_ips
    );
    assert!(
        p.allowed_ips.iter().any(|s| s == "::1/128"),
        "IPv6 loopback safety invariant missing: {:?}",
        p.allowed_ips
    );

    controller.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t03_unisolate_clears_pal_and_emits_state_changed_false() {
    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let pal: Arc<dyn HostIsolation> = Arc::new(MockHostIsolation::new());
    let hooks: Arc<dyn JobValidationHooks + Send + Sync> = Arc::new(AcceptHooks);
    let (controller, signal) = ShutdownController::new();
    let (handle, submitter) =
        HostIsolationModule::start_with(enabled_cfg(), identity(), pal.clone(), hooks, bus, signal);

    // First isolate.
    submitter.submit(isolate_job(vec![], None)).await.unwrap();
    let _first = await_kind(&mut rx, Duration::from_secs(2), |k| {
        matches!(k, EventKind::HostIsolationStateChanged { .. })
    })
    .await
    .expect("isolate");
    assert!(pal.is_isolated().unwrap());

    // Then unisolate.
    submitter.submit(unisolate_job()).await.unwrap();
    let second = await_kind(&mut rx, Duration::from_secs(2), |k| {
        matches!(k, EventKind::HostIsolationStateChanged { .. })
    })
    .await
    .expect("unisolate");
    let EventKind::HostIsolationStateChanged { payload } = second.kind else {
        unreachable!()
    };
    let p: HostIsolationStateChangedPayload = serde_json::from_str(&payload).unwrap();
    assert!(!p.isolated);
    assert_eq!(p.action, "unisolate_host");
    assert!(!pal.is_isolated().unwrap());

    controller.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t04_duplicate_isolate_does_not_re_emit_state_change() {
    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let pal: Arc<dyn HostIsolation> = Arc::new(MockHostIsolation::new());
    let hooks: Arc<dyn JobValidationHooks + Send + Sync> = Arc::new(AcceptHooks);
    let (controller, signal) = ShutdownController::new();
    let (handle, submitter) =
        HostIsolationModule::start_with(enabled_cfg(), identity(), pal.clone(), hooks, bus, signal);

    submitter.submit(isolate_job(vec![], None)).await.unwrap();
    let _first = await_kind(&mut rx, Duration::from_secs(2), |k| {
        matches!(k, EventKind::HostIsolationStateChanged { .. })
    })
    .await
    .expect("first isolate");

    submitter.submit(isolate_job(vec![], None)).await.unwrap();
    assert_no_kind(&mut rx, Duration::from_millis(250), |k| {
        matches!(k, EventKind::HostIsolationStateChanged { .. })
    })
    .await;

    controller.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t05_unsigned_job_is_refused_by_router_validator() {
    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let pal: Arc<dyn HostIsolation> = Arc::new(MockHostIsolation::new());
    // Phase1Stub rejects every signature with UnknownKeyId — proves
    // the validator gates the PAL.
    let hooks: Arc<dyn JobValidationHooks + Send + Sync> = Arc::new(Phase1Stub);
    let (controller, signal) = ShutdownController::new();
    let (handle, submitter) =
        HostIsolationModule::start_with(enabled_cfg(), identity(), pal.clone(), hooks, bus, signal);

    submitter.submit(isolate_job(vec![], None)).await.unwrap();
    assert_no_kind(&mut rx, Duration::from_millis(250), |k| {
        matches!(k, EventKind::HostIsolationStateChanged { .. })
    })
    .await;
    assert!(!pal.is_isolated().unwrap());

    controller.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t06_disabled_module_ignores_jobs_without_touching_pal() {
    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let pal: Arc<dyn HostIsolation> = Arc::new(MockHostIsolation::new());
    let hooks: Arc<dyn JobValidationHooks + Send + Sync> = Arc::new(AcceptHooks);
    let (controller, signal) = ShutdownController::new();
    let mut cfg = enabled_cfg();
    cfg.enabled = false;
    let (handle, submitter) =
        HostIsolationModule::start_with(cfg, identity(), pal.clone(), hooks, bus, signal);

    submitter.submit(isolate_job(vec![], None)).await.unwrap();
    assert_no_kind(&mut rx, Duration::from_millis(250), |k| {
        matches!(k, EventKind::HostIsolationStateChanged { .. })
    })
    .await;
    assert!(!pal.is_isolated().unwrap());

    controller.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t07_state_changed_payload_round_trips_via_json() {
    let p = HostIsolationStateChangedPayload {
        isolated: true,
        allowed_ips: vec!["127.0.0.0/8".into(), "10.20.0.0/16".into()],
        action: "isolate_host".into(),
        reason: Some("ir".into()),
        job_id: Uuid::new_v4().to_string(),
        observed_at: "2026-05-17T00:00:00Z".into(),
        schema_version: 1,
    };
    let s = serde_json::to_string(&p).unwrap();
    let back: HostIsolationStateChangedPayload = serde_json::from_str(&s).unwrap();
    assert_eq!(p, back);
}
