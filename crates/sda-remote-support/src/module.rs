//! Top-level [`RemoteSupportModule`] — wires the supervisor into
//! the agent's `tokio::select!` loop.
//!
//! The module owns:
//!
//! * A [`RemoteSupportSupervisor`] state machine driving sessions
//!   through `Pending → ConsentRequested → Active → Ended`.
//! * A [`ConsentManager`] for the consent gate.
//! * A `Box<dyn RemoteSupportProvider>` for OS-level capture &
//!   transport.
//!
//! Higher-level events fired on the bus:
//!
//! * `EventKind::RemoteSupportSessionStarted` — the moment a
//!   session transitions to `Active`.
//! * `EventKind::RemoteSupportSessionEnded` — terminal transition.

use std::sync::Arc;

use chrono::{Duration as ChronoDuration, Utc};
use sda_core::config::RemoteSupportConfig;
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use sda_pal::remote_support::{
    default_remote_support_provider, RemoteSupportError as PalError, RemoteSupportProvider,
    SessionHandle, SessionParams,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};

use crate::consent::{ConsentDecision, ConsentManager, ConsentPrompt, StubConsentPrompt};
use crate::session::{EndReason, Session, SessionState};

/// Errors produced by the supervisor.
#[derive(Debug, thiserror::Error)]
pub enum RemoteSupportError {
    /// The PAL returned an error while starting / ending a session.
    #[error("pal error: {0}")]
    Pal(#[from] PalError),
    /// The user declined the consent prompt.
    #[error("consent denied")]
    ConsentDenied,
    /// The supervisor was asked to act on a session it has never
    /// seen.
    #[error("unknown session: {0}")]
    UnknownSession(String),
    /// Session-state-machine transition was illegal.
    #[error("invalid transition: {0}")]
    InvalidTransition(String),
}

/// Caller request directed at the supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteSupportRequest {
    /// Operator (helpdesk agent / automation) initiating the
    /// session.
    pub operator_id: String,
    /// Optional override for the wall-clock cap. `None` defers to
    /// the module config.
    pub max_duration_minutes: Option<u32>,
}

/// Notification emitted by the supervisor to the bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "event")]
pub enum RemoteSupportEvent {
    /// Session entered `Active`.
    Started {
        session_id: String,
        operator_id: String,
        started_at: chrono::DateTime<chrono::Utc>,
        max_duration_secs: i64,
    },
    /// Session entered `Ended`.
    Ended {
        session_id: String,
        operator_id: String,
        reason: String,
        active_duration_secs: i64,
    },
}

/// Supervisor responsible for the session lifecycle.
pub struct RemoteSupportSupervisor {
    config: RemoteSupportConfig,
    bus: Arc<EventBus>,
    provider: Box<dyn RemoteSupportProvider>,
    consent: ConsentManager,
    sessions: Vec<(Session, Option<SessionHandle>)>,
}

impl std::fmt::Debug for RemoteSupportSupervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteSupportSupervisor")
            .field("session_count", &self.sessions.len())
            .field("config", &self.config)
            .finish()
    }
}

impl RemoteSupportSupervisor {
    /// Build a supervisor with the platform-default provider and
    /// the deny-all stub consent prompt.
    pub fn with_defaults(config: RemoteSupportConfig, bus: Arc<EventBus>) -> Option<Self> {
        let provider = default_remote_support_provider()?;
        Some(Self::new(
            config,
            bus,
            provider,
            Box::new(StubConsentPrompt),
        ))
    }

    /// Build a supervisor with caller-supplied PAL provider and
    /// consent prompt. Used by unit tests and by the agent's
    /// production main when it wants to inject a non-stub prompt.
    pub fn new(
        config: RemoteSupportConfig,
        bus: Arc<EventBus>,
        provider: Box<dyn RemoteSupportProvider>,
        consent_prompt: Box<dyn ConsentPrompt>,
    ) -> Self {
        Self {
            config,
            bus,
            provider,
            consent: ConsentManager::new(consent_prompt),
            sessions: Vec::new(),
        }
    }

    /// Number of sessions tracked (active + ended).
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Read-only snapshot of every session record.
    pub fn sessions(&self) -> Vec<Session> {
        self.sessions.iter().map(|(s, _)| s.clone()).collect()
    }

    /// Resolve the wall-clock cap for a request, clamped to the
    /// configured maximum.
    fn resolve_max_duration(&self, request: &RemoteSupportRequest) -> ChronoDuration {
        let cap_minutes = self.config.max_session_minutes.max(1);
        let requested = request
            .max_duration_minutes
            .map(|m| m.min(cap_minutes))
            .unwrap_or(cap_minutes);
        ChronoDuration::minutes(i64::from(requested))
    }

    /// Drive a request through the full lifecycle.
    ///
    /// Returns the terminal session record. Errors short-circuit the
    /// state machine — the session is moved to `Ended` with the
    /// appropriate reason and the supervisor records the failure
    /// before returning.
    pub fn handle_request(
        &mut self,
        request: RemoteSupportRequest,
    ) -> Result<Session, RemoteSupportError> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let max_duration = self.resolve_max_duration(&request);
        let mut session = Session::new(
            session_id.clone(),
            request.operator_id.clone(),
            max_duration,
        );

        // Pending → ConsentRequested.
        session
            .request_consent()
            .map_err(|e| RemoteSupportError::InvalidTransition(e.to_string()))?;

        // Consent gate. PROPOSAL.md § 9.7 requires consent on every
        // session in production; honour the test-only override.
        let decision = if self.config.require_consent {
            self.consent.ask(&session_id, &request.operator_id)
        } else {
            ConsentDecision::Approved
        };
        if decision != ConsentDecision::Approved {
            session
                .end(EndReason::ConsentDenied)
                .map_err(|e| RemoteSupportError::InvalidTransition(e.to_string()))?;
            self.emit_ended(&session);
            self.sessions.push((session.clone(), None));
            return Err(RemoteSupportError::ConsentDenied);
        }

        // Ask the PAL to start the underlying capture session.
        let params = SessionParams {
            operator_id: request.operator_id.clone(),
            max_duration,
            consent_required: self.config.require_consent,
        };
        let pal_handle = match self.provider.start_session(&params) {
            Ok(h) => Some(h),
            Err(PalError::NotSupported) => {
                // PAL not available on this host — end the session
                // cleanly so callers see a deterministic state.
                session
                    .end(EndReason::Error("pal not supported".into()))
                    .map_err(|e| RemoteSupportError::InvalidTransition(e.to_string()))?;
                self.emit_ended(&session);
                self.sessions.push((session.clone(), None));
                return Err(RemoteSupportError::Pal(PalError::NotSupported));
            }
            Err(e) => {
                let msg = e.to_string();
                session
                    .end(EndReason::Error(msg.clone()))
                    .map_err(|e| RemoteSupportError::InvalidTransition(e.to_string()))?;
                self.emit_ended(&session);
                self.sessions.push((session.clone(), None));
                return Err(RemoteSupportError::Pal(e));
            }
        };

        // ConsentRequested → Active.
        session
            .activate()
            .map_err(|e| RemoteSupportError::InvalidTransition(e.to_string()))?;
        self.emit_started(&session);
        self.sessions.push((session.clone(), pal_handle));
        Ok(session)
    }

    /// Terminate a tracked session.
    pub fn end_session(
        &mut self,
        session_id: &str,
        reason: EndReason,
    ) -> Result<Session, RemoteSupportError> {
        let idx = self
            .sessions
            .iter()
            .position(|(s, _)| s.session_id == session_id)
            .ok_or_else(|| RemoteSupportError::UnknownSession(session_id.into()))?;
        // If the session is already terminal, just return a copy
        // — this keeps `end_session` idempotent for callers
        // (e.g. the sweep) that may race with a previous end.
        if self.sessions[idx].0.state == SessionState::Ended {
            return Ok(self.sessions[idx].0.clone());
        }
        // PAL end_session is idempotent by contract — log but do
        // not bail on errors. We hand the handle to the provider
        // before touching the session so the mutable borrow on
        // `self.sessions` only kicks in for the state transition.
        if let Some(h) = self.sessions[idx].1.as_ref() {
            if let Err(e) = self.provider.end_session(h) {
                tracing::warn!(error = %e, session_id, "remote-support PAL end_session failed");
            }
        }
        // Drive the session into Ended in a tightly-scoped mutable
        // borrow so the subsequent `self.emit_ended` call can
        // borrow `self` immutably without conflict.
        let session_snapshot = {
            let session = &mut self.sessions[idx].0;
            session
                .end(reason)
                .map_err(|e| RemoteSupportError::InvalidTransition(e.to_string()))?;
            session.clone()
        };
        self.emit_ended(&session_snapshot);
        Ok(session_snapshot)
    }

    /// Sweep expired sessions. Called by the agent supervisor on a
    /// timer (default 5s).
    pub fn sweep_expired(&mut self) -> Vec<Session> {
        let mut ended = Vec::new();
        let to_end: Vec<String> = self
            .sessions
            .iter()
            .filter(|(s, _)| s.state == SessionState::Active && s.is_expired())
            .map(|(s, _)| s.session_id.clone())
            .collect();
        for id in to_end {
            if let Ok(s) = self.end_session(&id, EndReason::Timeout) {
                ended.push(s);
            }
        }
        ended
    }

    fn emit_started(&self, session: &Session) {
        let payload = RemoteSupportEvent::Started {
            session_id: session.session_id.clone(),
            operator_id: session.operator_id.clone(),
            started_at: session.started_at.unwrap_or_else(Utc::now),
            max_duration_secs: session.max_duration.num_seconds(),
        };
        self.emit(EventKind::RemoteSupportSessionStarted {
            payload: serde_json::to_string(&payload).unwrap_or_default(),
        });
    }

    fn emit_ended(&self, session: &Session) {
        let reason = match &session.end_reason {
            Some(EndReason::ConsentDenied) => "consent_denied".to_string(),
            Some(EndReason::OperatorDisconnect) => "operator_disconnect".to_string(),
            Some(EndReason::Timeout) => "timeout".to_string(),
            Some(EndReason::Error(msg)) => format!("error: {msg}"),
            None => "unknown".to_string(),
        };
        let payload = RemoteSupportEvent::Ended {
            session_id: session.session_id.clone(),
            operator_id: session.operator_id.clone(),
            reason,
            active_duration_secs: session
                .active_duration()
                .map(|d| d.num_seconds())
                .unwrap_or(0),
        };
        self.emit(EventKind::RemoteSupportSessionEnded {
            payload: serde_json::to_string(&payload).unwrap_or_default(),
        });
    }

    fn emit(&self, kind: EventKind) {
        let event = Event::new("sda-remote-support", Priority::High, kind);
        let bus = self.bus.clone();
        // `publish_to_server` already broadcasts locally even when
        // the server-bound queue send fails (see vma_event_bus
        // double-broadcast note in our knowledge base). Do NOT add
        // a `bus.publish` fallback — that would double-broadcast.
        tokio::spawn(async move {
            if let Err(e) = bus.publish_to_server(event).await {
                tracing::debug!(error = %e, "remote-support publish_to_server failed");
            }
        });
    }
}

/// Top-level module wrapper. The agent's `main.rs` builds one of
/// these, calls [`RemoteSupportModule::start`], and sends requests
/// over the returned mpsc.
pub struct RemoteSupportModule {
    supervisor: Arc<Mutex<RemoteSupportSupervisor>>,
}

impl RemoteSupportModule {
    /// Build a module with the platform-default provider and the
    /// deny-all stub consent prompt. Returns `None` on unsupported
    /// hosts.
    pub fn with_defaults(config: RemoteSupportConfig, bus: Arc<EventBus>) -> Option<Self> {
        let supervisor = RemoteSupportSupervisor::with_defaults(config, bus)?;
        Some(Self {
            supervisor: Arc::new(Mutex::new(supervisor)),
        })
    }

    /// Build a module with caller-supplied dependencies. Used by
    /// unit tests.
    pub fn new(supervisor: RemoteSupportSupervisor) -> Self {
        Self {
            supervisor: Arc::new(Mutex::new(supervisor)),
        }
    }

    /// Spawn the module's main loop. Returns a sender for caller
    /// requests + a join handle.
    ///
    /// The loop terminates when the request channel closes.
    pub fn start(
        self,
    ) -> (
        mpsc::UnboundedSender<RemoteSupportRequest>,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, mut rx) = mpsc::unbounded_channel::<RemoteSupportRequest>();
        let supervisor = self.supervisor.clone();
        let handle = tokio::spawn(async move {
            let mut sweep_timer = tokio::time::interval(tokio::time::Duration::from_secs(5));
            loop {
                tokio::select! {
                    biased;
                    request = rx.recv() => match request {
                        Some(req) => {
                            let mut sup = supervisor.lock().await;
                            if let Err(e) = sup.handle_request(req) {
                                tracing::debug!(error = %e, "remote-support request failed");
                            }
                        }
                        None => break,
                    },
                    _ = sweep_timer.tick() => {
                        let mut sup = supervisor.lock().await;
                        let _ = sup.sweep_expired();
                    }
                }
            }
        });
        (tx, handle)
    }

    /// Borrow the supervisor — useful for tests.
    pub fn supervisor(&self) -> Arc<Mutex<RemoteSupportSupervisor>> {
        self.supervisor.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consent::{AutoApproveConsentPrompt, AutoDenyConsentPrompt};
    use sda_pal::remote_support::SessionHandle as PalSessionHandle;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Stub provider that always succeeds — used to exercise the
    /// happy path without depending on an OS capture backend.
    #[derive(Default)]
    struct OkProvider {
        starts: AtomicUsize,
        ends: AtomicUsize,
    }

    impl RemoteSupportProvider for OkProvider {
        fn start_session(&self, _params: &SessionParams) -> Result<PalSessionHandle, PalError> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            Ok(PalSessionHandle {
                session_id: "pal-handle".into(),
                started_at: Utc::now(),
            })
        }
        fn end_session(&self, _h: &PalSessionHandle) -> Result<(), PalError> {
            self.ends.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Stub provider that fails to start.
    struct FailProvider;

    impl RemoteSupportProvider for FailProvider {
        fn start_session(&self, _params: &SessionParams) -> Result<PalSessionHandle, PalError> {
            Err(PalError::NotSupported)
        }
        fn end_session(&self, _h: &PalSessionHandle) -> Result<(), PalError> {
            Ok(())
        }
    }

    fn make_bus() -> (Arc<EventBus>, tokio::sync::mpsc::Receiver<Event>) {
        let (bus, rx) = EventBus::new(64, 64);
        (Arc::new(bus), rx)
    }

    fn make_config(max_minutes: u32, require_consent: bool) -> RemoteSupportConfig {
        RemoteSupportConfig {
            enabled: true,
            max_session_minutes: max_minutes,
            require_consent,
        }
    }

    #[tokio::test]
    async fn happy_path_drives_session_to_active() {
        let (bus, _rx) = make_bus();
        let mut sup = RemoteSupportSupervisor::new(
            make_config(30, true),
            bus,
            Box::<OkProvider>::default(),
            Box::new(AutoApproveConsentPrompt),
        );
        let req = RemoteSupportRequest {
            operator_id: "ops@example.com".into(),
            max_duration_minutes: Some(15),
        };
        let session = sup.handle_request(req).expect("happy path");
        assert_eq!(session.state, SessionState::Active);
        assert!(session.started_at.is_some());
    }

    #[tokio::test]
    async fn deny_all_prompt_terminates_session() {
        let (bus, _rx) = make_bus();
        let mut sup = RemoteSupportSupervisor::new(
            make_config(30, true),
            bus,
            Box::<OkProvider>::default(),
            Box::new(AutoDenyConsentPrompt),
        );
        let req = RemoteSupportRequest {
            operator_id: "ops@example.com".into(),
            max_duration_minutes: None,
        };
        let err = sup.handle_request(req).expect_err("must fail");
        assert!(matches!(err, RemoteSupportError::ConsentDenied));
        let sessions = sup.sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].state, SessionState::Ended);
        assert_eq!(sessions[0].end_reason, Some(EndReason::ConsentDenied));
    }

    #[tokio::test]
    async fn pal_not_supported_ends_session_cleanly() {
        let (bus, _rx) = make_bus();
        let mut sup = RemoteSupportSupervisor::new(
            make_config(30, true),
            bus,
            Box::new(FailProvider),
            Box::new(AutoApproveConsentPrompt),
        );
        let err = sup
            .handle_request(RemoteSupportRequest {
                operator_id: "ops".into(),
                max_duration_minutes: None,
            })
            .err()
            .unwrap();
        assert!(matches!(
            err,
            RemoteSupportError::Pal(PalError::NotSupported)
        ));
        let sessions = sup.sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].state, SessionState::Ended);
    }

    #[tokio::test]
    async fn end_session_marks_session_ended() {
        let (bus, _rx) = make_bus();
        let mut sup = RemoteSupportSupervisor::new(
            make_config(30, true),
            bus,
            Box::<OkProvider>::default(),
            Box::new(AutoApproveConsentPrompt),
        );
        let session = sup
            .handle_request(RemoteSupportRequest {
                operator_id: "ops".into(),
                max_duration_minutes: None,
            })
            .unwrap();
        let ended = sup
            .end_session(&session.session_id, EndReason::OperatorDisconnect)
            .unwrap();
        assert_eq!(ended.state, SessionState::Ended);
        assert_eq!(ended.end_reason, Some(EndReason::OperatorDisconnect));
    }

    #[tokio::test]
    async fn end_session_unknown_id_returns_error() {
        let (bus, _rx) = make_bus();
        let mut sup = RemoteSupportSupervisor::new(
            make_config(30, true),
            bus,
            Box::<OkProvider>::default(),
            Box::new(AutoApproveConsentPrompt),
        );
        let err = sup
            .end_session("missing", EndReason::OperatorDisconnect)
            .err()
            .unwrap();
        assert!(matches!(err, RemoteSupportError::UnknownSession(_)));
    }

    #[tokio::test]
    async fn require_consent_false_skips_prompt() {
        let (bus, _rx) = make_bus();
        let mut sup = RemoteSupportSupervisor::new(
            make_config(30, false),
            bus,
            Box::<OkProvider>::default(),
            // Even with the deny-all prompt, we should bypass it.
            Box::new(AutoDenyConsentPrompt),
        );
        let s = sup
            .handle_request(RemoteSupportRequest {
                operator_id: "ops".into(),
                max_duration_minutes: None,
            })
            .expect("bypassed prompt");
        assert_eq!(s.state, SessionState::Active);
    }

    #[tokio::test]
    async fn resolve_max_duration_clamps_to_config() {
        let (bus, _rx) = make_bus();
        let sup = RemoteSupportSupervisor::new(
            make_config(10, true),
            bus,
            Box::<OkProvider>::default(),
            Box::new(AutoApproveConsentPrompt),
        );
        let req = RemoteSupportRequest {
            operator_id: "ops".into(),
            max_duration_minutes: Some(120),
        };
        assert_eq!(sup.resolve_max_duration(&req), ChronoDuration::minutes(10));
    }

    #[tokio::test]
    async fn started_event_lands_on_bus() {
        let (bus, mut rx) = make_bus();
        let mut sup = RemoteSupportSupervisor::new(
            make_config(30, true),
            bus,
            Box::<OkProvider>::default(),
            Box::new(AutoApproveConsentPrompt),
        );
        sup.handle_request(RemoteSupportRequest {
            operator_id: "ops".into(),
            max_duration_minutes: None,
        })
        .unwrap();
        let evt = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            evt.kind,
            EventKind::RemoteSupportSessionStarted { .. }
        ));
    }
}
