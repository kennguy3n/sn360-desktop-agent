//! `sda-query` — osquery sidecar wrapper for the SN360 Desktop
//! Agent (Phase 1 MVP).
//!
//! The Query module wraps an off-process [osquery] daemon (the
//! "sidecar") so the agent can run scheduled SQL queries against
//! the host without re-implementing the per-OS inventory logic
//! itself. Phase 1 lands the *scaffolding* — the supervisor task,
//! the [`scheduler::Scheduler`], the resource budget, and the
//! probe code that decides whether a sidecar can even be launched.
//!
//! Spawning the child process and connecting to its Thrift
//! extension socket is Phase 2 work and lives behind
//! [`client::UnavailableClient`] for now. See
//! `docs/device-control/PHASES.md` task 1.5 for the delivery plan.
//!
//! [osquery]: https://osquery.io/

pub mod client;
pub mod scheduler;
pub mod sidecar;

pub use client::{ClientError, OsqueryClient, QueryResultSet, QueryRow, UnavailableClient};
pub use scheduler::{ScheduledQuery, Scheduler, Tick};
pub use sidecar::{probe, ProbeResult, SidecarBudget};

use sda_core::config::AgentConfig;
use sda_core::module::ModuleHandle;
use sda_core::signal::ShutdownSignal;
use sda_event_bus::EventBus;
use tracing::{info, warn};

/// Phase 1 entry point.
///
/// In Phase 1 the supervisor task only logs its status and parks
/// on the shared shutdown signal. The real loop — probe sidecar,
/// spawn it, run scheduled queries, emit
/// `EventKind::QueryResult` events — lands in Phase 2 once the
/// extension-socket client is ready.
///
/// Crucially, when `modules.query.enabled = false` (the default),
/// this task is never spawned at all. The agent's idle footprint
/// is unchanged.
pub struct QueryModule;

impl QueryModule {
    pub fn start(
        _config: &AgentConfig,
        _bus: EventBus,
        mut shutdown: ShutdownSignal,
    ) -> ModuleHandle {
        info!(
            "query module starting (Phase 1 scaffold; \
             scheduler online, sidecar exec lands in Phase 2)"
        );
        let task = tokio::spawn(async move {
            shutdown.wait().await;
            warn!("query module shutting down");
            Ok(())
        });
        ModuleHandle::new("query", task)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn re_exports_compile() {
        // Smoke test that the module's public surface is reachable
        // through the crate root.
        let _ = SidecarBudget::default_phase1();
        let _ = probe(Some(Path::new("/nope")));
        let _ = UnavailableClient::default();
    }

    #[test]
    fn unavailable_path_is_handled_gracefully() {
        // Mirrors task 1.5's "module gracefully handles missing
        // osquery binary" requirement: probe + Unavailable client
        // both surface a structured error rather than a panic.
        let r = probe(Some(Path::new("/path/that/does/not/exist")));
        assert!(matches!(r, ProbeResult::Missing { .. }));

        let c = UnavailableClient::default();
        let err = c.execute("q", "SELECT 1").unwrap_err();
        assert!(matches!(err, ClientError::Unavailable(_)));
    }
}
