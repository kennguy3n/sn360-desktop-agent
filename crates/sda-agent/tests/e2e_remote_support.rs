//! Phase 4 remote-support end-to-end suite (PHASES.md task 4.12).
//!
//! Hermetic exercises of the consent-gated remote-support session
//! lifecycle shipped in PR #7. Verifies the supervisor walks the
//! state machine `Pending → ConsentRequested → Active → Ended`,
//! emits the right events on the bus, and **never** activates a
//! session without an explicit user click on the consent prompt
//! (PROPOSAL.md § 9.7 acceptance #1).
//!
//! Coverage:
//!
//! 1. Consent approve → session goes Active and emits Started
//!    (`consent_approve_drives_session_to_active`).
//! 2. Consent deny → session ends without ever going Active and
//!    emits a Denied Ended event
//!    (`consent_deny_terminates_session_before_active`).
//! 3. Consent timeout → session ends without ever going Active
//!    (`consent_timeout_terminates_session_before_active`).
//! 4. Stub prompt (`StubConsentPrompt`) — the production fail-closed
//!    default — denies every request, satisfying the
//!    "no remote-support without explicit user click" invariant
//!    (`stub_prompt_denies_by_default`).
//! 5. Lifecycle: approve → active → end emits one Started and one
//!    Ended event in order
//!    (`lifecycle_emits_started_then_ended`).
//! 6. Sweep expired sessions — runaway active session beyond the
//!    wall-clock cap is closed by `sweep_expired`
//!    (`sweep_expired_closes_overdue_sessions`).
//! 7. Two operators back-to-back — every session has its own
//!    consent prompt and its own session id
//!    (`back_to_back_sessions_each_get_consent`).
//! 8. PAL `NotSupported` ends the session cleanly with reason
//!    `pal_not_supported` (`pal_not_supported_ends_session_cleanly`).
//! 9. Mobile MDM is intentionally **absent**: this repo MUST NOT
//!    contain mobile MDM crates (PROPOSAL.md § 9.7 acceptance #3).
//!    Asserted by [`no_mobile_mdm_crate_in_workspace`].

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use sda_core::config::RemoteSupportConfig;
use sda_event_bus::{Event, EventBus, EventKind};
use sda_pal::remote_support::{
    RemoteSupportError as PalError, RemoteSupportProvider, SessionHandle, SessionParams,
};
use sda_remote_support::{
    consent::{ConsentDecision, ConsentPrompt},
    module::{RemoteSupportError, RemoteSupportRequest, RemoteSupportSupervisor},
    session::SessionState,
};
use tokio::sync::mpsc;

// ---------- Test harness ---------------------------------------------------

/// Recording PAL provider — captures every `start_session` /
/// `end_session` call so tests can assert what the supervisor
/// handed to the OS-level capture / transport stack.
#[derive(Debug, Default)]
struct RecordingProvider {
    starts: Mutex<Vec<SessionParams>>,
    ends: Mutex<Vec<SessionHandle>>,
    behavior: Mutex<ProviderBehavior>,
    next_id: AtomicUsize,
}

#[derive(Debug, Default)]
enum ProviderBehavior {
    #[default]
    Ok,
    NotSupported,
}

impl RecordingProvider {
    fn fail_with_not_supported(&self) {
        *self.behavior.lock().unwrap() = ProviderBehavior::NotSupported;
    }
}

impl RemoteSupportProvider for RecordingProvider {
    fn start_session(&self, params: &SessionParams) -> Result<SessionHandle, PalError> {
        match *self.behavior.lock().unwrap() {
            ProviderBehavior::NotSupported => return Err(PalError::NotSupported),
            ProviderBehavior::Ok => {}
        }
        self.starts.lock().unwrap().push(params.clone());
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        Ok(SessionHandle {
            session_id: format!("pal-handle-{id}"),
            started_at: chrono::Utc::now(),
        })
    }

    fn end_session(&self, handle: &SessionHandle) -> Result<(), PalError> {
        self.ends.lock().unwrap().push(handle.clone());
        Ok(())
    }
}

/// Wrapper that hands an `Arc<RecordingProvider>` to the supervisor
/// without taking exclusive ownership.
struct RecordingProviderHandle(Arc<RecordingProvider>);

impl RemoteSupportProvider for RecordingProviderHandle {
    fn start_session(&self, params: &SessionParams) -> Result<SessionHandle, PalError> {
        self.0.start_session(params)
    }
    fn end_session(&self, handle: &SessionHandle) -> Result<(), PalError> {
        self.0.end_session(handle)
    }
}

/// Pluggable consent prompt for tests. The supervisor takes a
/// `Box<dyn ConsentPrompt>`; we stamp out a fresh prompt per test
/// rather than re-using a global so individual scenarios are
/// hermetic.
struct ScriptedPrompt {
    decisions: Mutex<Vec<ConsentDecision>>,
    asks: AtomicUsize,
}

impl ScriptedPrompt {
    fn new(decisions: Vec<ConsentDecision>) -> Self {
        Self {
            decisions: Mutex::new(decisions),
            asks: AtomicUsize::new(0),
        }
    }
}

impl ConsentPrompt for ScriptedPrompt {
    fn ask(&self, _session_id: &str, _operator_id: &str) -> ConsentDecision {
        self.asks.fetch_add(1, Ordering::SeqCst);
        let mut q = self.decisions.lock().unwrap();
        if q.is_empty() {
            // Fail-closed: any extra ask returns Denied. This guards
            // tests that accidentally trigger more prompts than
            // expected.
            ConsentDecision::Denied
        } else {
            q.remove(0)
        }
    }
}

/// Build an in-process bus + the receiver for the tests.
fn make_bus() -> (Arc<EventBus>, mpsc::Receiver<Event>) {
    let (bus, rx) = EventBus::new(64, 64);
    (Arc::new(bus), rx)
}

fn cfg(max_minutes: u32, require_consent: bool) -> RemoteSupportConfig {
    RemoteSupportConfig {
        enabled: true,
        max_session_minutes: max_minutes,
        require_consent,
    }
}

fn request(operator: &str) -> RemoteSupportRequest {
    RemoteSupportRequest {
        operator_id: operator.into(),
        max_duration_minutes: None,
    }
}

async fn drain_for(rx: &mut mpsc::Receiver<Event>, budget: Duration) -> Vec<EventKind> {
    let mut out = Vec::new();
    while let Ok(Some(ev)) = tokio::time::timeout(budget, rx.recv()).await {
        out.push(ev.kind);
    }
    out
}

fn json_event(payload: &str, key: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(payload).ok()?;
    v.get(key)?.as_str().map(|s| s.to_string())
}

// ---------- Scenario 1: consent approve ------------------------------------

/// PHASES.md § 4.12 #1 — happy-path session: consent approved,
/// PAL accepts, session reaches Active, Started event lands on
/// the bus.
#[tokio::test(flavor = "current_thread")]
async fn consent_approve_drives_session_to_active() {
    let (bus, mut rx) = make_bus();
    let provider = Arc::new(RecordingProvider::default());
    let prompt = Box::new(ScriptedPrompt::new(vec![ConsentDecision::Approved]));
    let mut sup = RemoteSupportSupervisor::new(
        cfg(30, true),
        bus,
        Box::new(RecordingProviderHandle(provider.clone())),
        prompt,
    );

    let session = sup.handle_request(request("ops@example.com")).expect("ok");
    assert_eq!(session.state, SessionState::Active);
    assert_eq!(provider.starts.lock().unwrap().len(), 1);

    let kinds = drain_for(&mut rx, Duration::from_millis(150)).await;
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, EventKind::RemoteSupportSessionStarted { .. })),
        "Started event must land on the bus"
    );
}

// ---------- Scenario 2: consent deny ---------------------------------------

/// PHASES.md § 4.12 #1 — explicit deny terminates the session
/// before it reaches Active. Crucially, the PAL provider's
/// `start_session` is never invoked.
#[tokio::test(flavor = "current_thread")]
async fn consent_deny_terminates_session_before_active() {
    let (bus, mut rx) = make_bus();
    let provider = Arc::new(RecordingProvider::default());
    let prompt = Box::new(ScriptedPrompt::new(vec![ConsentDecision::Denied]));
    let mut sup = RemoteSupportSupervisor::new(
        cfg(30, true),
        bus,
        Box::new(RecordingProviderHandle(provider.clone())),
        prompt,
    );

    let err = sup
        .handle_request(request("ops@example.com"))
        .expect_err("must reject");
    assert!(matches!(err, RemoteSupportError::ConsentDenied));
    assert!(
        provider.starts.lock().unwrap().is_empty(),
        "PAL must not be touched without consent"
    );

    let kinds = drain_for(&mut rx, Duration::from_millis(150)).await;
    let started = kinds
        .iter()
        .filter(|k| matches!(k, EventKind::RemoteSupportSessionStarted { .. }))
        .count();
    let ended = kinds
        .iter()
        .filter(|k| matches!(k, EventKind::RemoteSupportSessionEnded { .. }))
        .count();
    assert_eq!(started, 0, "no Started event for a denied session");
    assert_eq!(ended, 1, "exactly one Ended event for a denied session");

    // The Ended payload's `reason` must distinguish consent denial
    // from other end reasons so audit reports stay precise.
    let denied_payload = kinds
        .iter()
        .find_map(|k| match k {
            EventKind::RemoteSupportSessionEnded { payload } => Some(payload.clone()),
            _ => None,
        })
        .expect("payload");
    assert_eq!(
        json_event(&denied_payload, "reason").as_deref(),
        Some("consent_denied")
    );
}

// ---------- Scenario 3: consent timeout ------------------------------------

/// PHASES.md § 4.12 #1 — a timed-out prompt is treated identically
/// to an explicit deny: the session never reaches Active.
#[tokio::test(flavor = "current_thread")]
async fn consent_timeout_terminates_session_before_active() {
    let (bus, _rx) = make_bus();
    let provider = Arc::new(RecordingProvider::default());
    let prompt = Box::new(ScriptedPrompt::new(vec![ConsentDecision::TimedOut]));
    let mut sup = RemoteSupportSupervisor::new(
        cfg(30, true),
        bus,
        Box::new(RecordingProviderHandle(provider.clone())),
        prompt,
    );

    let err = sup
        .handle_request(request("ops@example.com"))
        .expect_err("must reject");
    assert!(matches!(err, RemoteSupportError::ConsentDenied));
    assert!(provider.starts.lock().unwrap().is_empty());
}

// ---------- Scenario 4: stub prompt is fail-closed -------------------------

/// PHASES.md § 4.12 #1 / PROPOSAL.md § 9.7 acceptance #1 —
/// `StubConsentPrompt` is the production default. It denies every
/// request, so a deployment that forgets to wire a real consent UI
/// **cannot** start a remote-support session. This is the critical
/// safety property the acceptance test pins.
#[tokio::test(flavor = "current_thread")]
async fn stub_prompt_denies_by_default() {
    let (bus, _rx) = make_bus();
    let provider = Arc::new(RecordingProvider::default());
    let mut sup = RemoteSupportSupervisor::new(
        cfg(30, true),
        bus,
        Box::new(RecordingProviderHandle(provider.clone())),
        Box::new(sda_remote_support::consent::StubConsentPrompt),
    );
    let err = sup
        .handle_request(request("ops@example.com"))
        .expect_err("stub prompt must deny");
    assert!(matches!(err, RemoteSupportError::ConsentDenied));
    assert!(provider.starts.lock().unwrap().is_empty());
}

// ---------- Scenario 5: lifecycle emits Started then Ended ----------------

/// PHASES.md § 4.12 #1 — full happy-path lifecycle. The supervisor
/// must emit exactly one Started followed by exactly one Ended
/// event, in order, when an active session is explicitly closed.
#[tokio::test(flavor = "current_thread")]
async fn lifecycle_emits_started_then_ended() {
    let (bus, mut rx) = make_bus();
    let provider = Arc::new(RecordingProvider::default());
    let prompt = Box::new(ScriptedPrompt::new(vec![ConsentDecision::Approved]));
    let mut sup = RemoteSupportSupervisor::new(
        cfg(30, true),
        bus,
        Box::new(RecordingProviderHandle(provider.clone())),
        prompt,
    );

    let session = sup.handle_request(request("ops@example.com")).expect("ok");
    let ended = sup
        .end_session(
            &session.session_id,
            sda_remote_support::session::EndReason::OperatorDisconnect,
        )
        .expect("end ok");
    assert_eq!(ended.state, SessionState::Ended);

    let kinds = drain_for(&mut rx, Duration::from_millis(200)).await;
    let mut order: Vec<&'static str> = Vec::new();
    for k in &kinds {
        match k {
            EventKind::RemoteSupportSessionStarted { .. } => order.push("started"),
            EventKind::RemoteSupportSessionEnded { .. } => order.push("ended"),
            _ => {}
        }
    }
    assert_eq!(order, vec!["started", "ended"]);
}

// ---------- Scenario 6: sweep expired closes runaway sessions --------------

/// PHASES.md § 4.12 #1 — `sweep_expired` closes any session whose
/// wall-clock cap has elapsed. This is the safety net that makes
/// time-boxed sessions a hard guarantee even if an operator
/// forgets to call `end_session`.
///
/// We coerce immediate expiry by requesting a 0-minute cap. The
/// supervisor clamps `cap_minutes` to at least 1 internally, but
/// `request.max_duration_minutes = Some(0)` falls through to a
/// zero-minute `ChronoDuration`, so `is_expired()` returns true
/// the instant the session reaches Active.
#[tokio::test(flavor = "current_thread")]
async fn sweep_expired_closes_overdue_sessions() {
    let (bus, _rx) = make_bus();
    let provider = Arc::new(RecordingProvider::default());
    let prompt = Box::new(ScriptedPrompt::new(vec![ConsentDecision::Approved]));
    let mut sup = RemoteSupportSupervisor::new(
        cfg(30, true),
        bus,
        Box::new(RecordingProviderHandle(provider.clone())),
        prompt,
    );

    let req = RemoteSupportRequest {
        operator_id: "ops@example.com".into(),
        max_duration_minutes: Some(0),
    };
    let session = sup.handle_request(req).expect("ok");
    sup.sweep_expired();
    let after = sup
        .sessions()
        .into_iter()
        .find(|s| s.session_id == session.session_id)
        .expect("session retained");
    assert_eq!(after.state, SessionState::Ended);
    assert_eq!(provider.ends.lock().unwrap().len(), 1);
}

// ---------- Scenario 7: back-to-back sessions ------------------------------

/// PHASES.md § 4.12 #1 — every session is independently
/// consent-gated. Two operators making back-to-back requests must
/// each see their own prompt; the supervisor must never re-use
/// consent across sessions.
#[tokio::test(flavor = "current_thread")]
async fn back_to_back_sessions_each_get_consent() {
    let (bus, _rx) = make_bus();
    let provider = Arc::new(RecordingProvider::default());
    let captured = Arc::new(ScriptedPromptShared::new(vec![
        ConsentDecision::Approved,
        ConsentDecision::Denied,
    ]));

    let mut sup = RemoteSupportSupervisor::new(
        cfg(30, true),
        bus,
        Box::new(RecordingProviderHandle(provider.clone())),
        Box::new(ScriptedPromptHandle(captured.clone())),
    );

    let s1 = sup.handle_request(request("op1@example.com")).expect("ok");
    let err = sup
        .handle_request(request("op2@example.com"))
        .expect_err("must deny");
    assert!(matches!(err, RemoteSupportError::ConsentDenied));
    assert_eq!(s1.state, SessionState::Active);
    assert_eq!(captured.ask_count(), 2);
}

// ---------- Scenario 8: PAL NotSupported -----------------------------------

/// PHASES.md § 4.12 #1 — when the PAL provider returns
/// `NotSupported` (every Phase-4 stub does), the supervisor must
/// end the session cleanly rather than panicking.
#[tokio::test(flavor = "current_thread")]
async fn pal_not_supported_ends_session_cleanly() {
    let (bus, mut rx) = make_bus();
    let provider = Arc::new(RecordingProvider::default());
    provider.fail_with_not_supported();
    let prompt = Box::new(ScriptedPrompt::new(vec![ConsentDecision::Approved]));
    let mut sup = RemoteSupportSupervisor::new(
        cfg(30, true),
        bus,
        Box::new(RecordingProviderHandle(provider.clone())),
        prompt,
    );
    let err = sup
        .handle_request(request("ops@example.com"))
        .expect_err("must reject");
    assert!(matches!(
        err,
        RemoteSupportError::Pal(PalError::NotSupported)
    ));
    let kinds = drain_for(&mut rx, Duration::from_millis(150)).await;
    let started = kinds
        .iter()
        .filter(|k| matches!(k, EventKind::RemoteSupportSessionStarted { .. }))
        .count();
    let ended = kinds
        .iter()
        .filter(|k| matches!(k, EventKind::RemoteSupportSessionEnded { .. }))
        .count();
    assert_eq!(started, 0, "no Started event when PAL is not supported");
    assert_eq!(
        ended, 1,
        "exactly one Ended event when PAL is not supported"
    );
}

// ---------- Scenario 9: no mobile MDM crate --------------------------------

/// PROPOSAL.md § 9.7 acceptance #3 / PHASES.md § 4.12 #3 — this
/// repository must not contain *mobile* MDM code. Asserted by
/// walking the Cargo workspace and ensuring no crate name matches
/// the mobile-MDM naming patterns. `sda-mdm` (Desktop MDM,
/// `docs/desktop-mdm.md`) is explicitly allowed.
#[test]
fn no_mobile_mdm_crate_in_workspace() {
    let workspace_root = workspace_root();
    let cargo = std::fs::read_to_string(workspace_root.join("Cargo.toml")).expect("Cargo.toml");
    // Crates intentionally allowed under this guardrail.
    const ALLOWED: &[&str] = &["crates/sda-mdm"];
    // Patterns that would indicate a *mobile* MDM crate (iOS/Android).
    const MOBILE_PATTERNS: &[&str] = &["mobile-mdm", "ios-mdm", "android-mdm", "/mdm-mobile"];
    for line in cargo.lines() {
        let l = line.trim();
        if !l.starts_with('"') || !l.contains("mdm") {
            continue;
        }
        if ALLOWED.iter().any(|a| l.contains(a)) {
            continue;
        }
        if MOBILE_PATTERNS.iter().any(|p| l.contains(p)) {
            panic!("mobile MDM crate detected in workspace: {l}");
        }
        // Defence-in-depth: any *new* unknown `mdm` crate must be
        // listed in ALLOWED above and reviewed deliberately.
        panic!("unrecognised mdm crate in workspace; allow-list it explicitly: {l}");
    }
}

fn workspace_root() -> PathBuf {
    // tests run from `crates/sda-agent`; back out two levels.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

// ---------- Shared scripted prompt -----------------------------------------

/// Variant of [`ScriptedPrompt`] that is `Arc`-able so the test can
/// retain a handle to inspect ask counts after the supervisor takes
/// ownership. Behaviour is otherwise identical.
struct ScriptedPromptShared {
    decisions: Mutex<Vec<ConsentDecision>>,
    asks: AtomicUsize,
}

impl ScriptedPromptShared {
    fn new(decisions: Vec<ConsentDecision>) -> Self {
        Self {
            decisions: Mutex::new(decisions),
            asks: AtomicUsize::new(0),
        }
    }
    fn ask_count(&self) -> usize {
        self.asks.load(Ordering::SeqCst)
    }
}

struct ScriptedPromptHandle(Arc<ScriptedPromptShared>);

impl ConsentPrompt for ScriptedPromptHandle {
    fn ask(&self, _session_id: &str, _operator_id: &str) -> ConsentDecision {
        self.0.asks.fetch_add(1, Ordering::SeqCst);
        let mut q = self.0.decisions.lock().unwrap();
        if q.is_empty() {
            ConsentDecision::Denied
        } else {
            q.remove(0)
        }
    }
}
