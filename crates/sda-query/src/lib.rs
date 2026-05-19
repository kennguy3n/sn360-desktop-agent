//! `sda-query` — osquery sidecar wrapper for the SN360 Desktop
//! Agent.
//!
//! The Query module wraps an off-process [osquery] daemon (the
//! "sidecar") so the agent can run scheduled SQL queries against
//! the host without re-implementing the per-OS inventory logic
//! itself.  This crate ships the supervisor task, the
//! [`scheduler::Scheduler`], the resource budget, and the probe
//! code that decides whether a sidecar can even be launched.
//!
//! Spawning the child process and connecting to its Thrift
//! extension socket is not yet wired; see
//! [`client::UnavailableClient`].  See `docs/device-control.md`
//! § 2 (Modules — `sda-query`) for the delivery plan.
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

/// Query module entry point.
///
/// Currently the supervisor task logs its status and parks on the
/// shared shutdown signal.  The real loop — probe sidecar, spawn
/// it, run scheduled queries, emit `EventKind::QueryResult`
/// events — will land once the extension-socket client is ready.
///
/// When `modules.query.enabled = false` (the default), this task
/// is never spawned at all.  The agent's idle footprint is
/// unchanged.
pub struct QueryModule;

impl QueryModule {
    pub fn start(
        _config: &AgentConfig,
        _bus: EventBus,
        mut shutdown: ShutdownSignal,
    ) -> ModuleHandle {
        info!(
            "query module starting (scaffold; \
             scheduler online, sidecar exec not yet wired)"
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
        // The module gracefully handles a missing osquery binary:
        // probe + Unavailable client both surface a structured
        // error rather than a panic.
        let r = probe(Some(Path::new("/path/that/does/not/exist")));
        assert!(matches!(r, ProbeResult::Missing { .. }));

        let c = UnavailableClient::default();
        let err = c.execute("q", "SELECT 1").unwrap_err();
        assert!(matches!(err, ClientError::Unavailable(_)));
    }
}
