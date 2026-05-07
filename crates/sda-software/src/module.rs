//! Phase 2 entry point for the approved-software module.
//!
//! Phase 2.5 (this PR) only ships the supervisor scaffold — it logs
//! its enabled / disabled state and parks on the shared shutdown
//! signal. The catalogue refresh loop (`catalogue_url` HTTPS fetch,
//! pinned-key signature verification through
//! [`crate::catalogue::CatalogueStore::verify_and_swap`], install /
//! update / uninstall action wiring through
//! [`sda_pal::package_manager::PackageManager`]) lands in Phase 2.6
//! once the catalogue authority key-management infrastructure is in
//! place and the action executors are unblocked.
//!
//! Keeping the supervisor minimal in Phase 1 / Phase 2.5 means
//! flipping `modules.software.enabled = false` (the default) keeps
//! the idle CPU footprint identical to a build without the crate.

use sda_core::config::AgentConfig;
use sda_core::module::ModuleHandle;
use sda_core::signal::ShutdownSignal;
use sda_event_bus::EventBus;
use tracing::{info, warn};

use crate::catalogue::CatalogueStore;

/// Phase 2 supervisor handle for the software module.
pub struct SoftwareModule;

impl SoftwareModule {
    /// Spawn the software-module supervisor task.
    ///
    /// Behaviour matrix:
    ///
    /// - `modules.software.enabled = false` → log "disabled" and park
    ///   on `shutdown` (idle CPU = 0).
    /// - `modules.software.enabled = true` &&
    ///   `catalogue_url.is_none()` → log a warning and park, so the
    ///   agent does not panic when an operator enables the module
    ///   without configuring a URL yet.
    /// - `modules.software.enabled = true` && `catalogue_url.is_some()`
    ///   → log "ready"; the live fetch / verify / refresh loop lands
    ///   in Phase 2.6.
    ///
    /// The returned [`ModuleHandle`] always carries the name
    /// `"software"` so the agent supervisor can wait on it
    /// uniformly.
    pub fn start(
        config: &AgentConfig,
        _bus: EventBus,
        mut shutdown: ShutdownSignal,
    ) -> ModuleHandle {
        let software = config.modules.software.clone();
        let store = CatalogueStore::new();
        if !software.enabled {
            info!("software module disabled — parking on shutdown");
        } else if software.catalogue_url.is_none() {
            warn!(
                "software module enabled but `catalogue_url` is unset; \
                 idling until configuration arrives"
            );
        } else if software.pinned_signing_key_hex.is_none() {
            warn!(
                "software module enabled but `pinned_signing_key_hex` is \
                 unset; refusing to fetch unsigned catalogues"
            );
        } else {
            info!(
                refresh_interval_secs = software.refresh_interval_secs,
                "software module ready (Phase 2.5 scaffold; \
                 fetch / verify loop lands in Phase 2.6)"
            );
        }
        let task = tokio::spawn(async move {
            // Keep the catalogue store alive on the supervisor's
            // stack so the Phase 2.6 fetch loop has somewhere to
            // swap in. Today nothing else holds a clone, so this is
            // simply a placeholder that documents the intended
            // ownership.
            let _store = store;
            shutdown.wait().await;
            warn!("software module shutting down");
            Ok(())
        });
        ModuleHandle::new("software", task)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::config::SoftwareConfig;
    use sda_core::signal::ShutdownController;

    #[tokio::test(flavor = "current_thread")]
    async fn module_parks_when_disabled() {
        let mut cfg = AgentConfig::default();
        cfg.modules.software = SoftwareConfig::default();
        let (bus, _server_rx) = EventBus::new(8, 8);
        let (controller, signal) = ShutdownController::new();
        let handle = SoftwareModule::start(&cfg, bus, signal);
        assert_eq!(handle.name, "software");
        controller.shutdown();
        let res = handle.task.await.unwrap();
        assert!(res.is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn module_parks_when_enabled_without_url() {
        let mut cfg = AgentConfig::default();
        cfg.modules.software = SoftwareConfig {
            enabled: true,
            catalogue_url: None,
            pinned_signing_key_hex: None,
            refresh_interval_secs: 3600,
        };
        let (bus, _server_rx) = EventBus::new(8, 8);
        let (controller, signal) = ShutdownController::new();
        let handle = SoftwareModule::start(&cfg, bus, signal);
        controller.shutdown();
        handle.task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn module_parks_when_enabled_without_pinned_key() {
        let mut cfg = AgentConfig::default();
        cfg.modules.software = SoftwareConfig {
            enabled: true,
            catalogue_url: Some("https://example.test/catalogue.json".into()),
            pinned_signing_key_hex: None,
            refresh_interval_secs: 3600,
        };
        let (bus, _server_rx) = EventBus::new(8, 8);
        let (controller, signal) = ShutdownController::new();
        let handle = SoftwareModule::start(&cfg, bus, signal);
        controller.shutdown();
        handle.task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn module_parks_when_fully_configured() {
        let mut cfg = AgentConfig::default();
        cfg.modules.software = SoftwareConfig {
            enabled: true,
            catalogue_url: Some("https://example.test/catalogue.json".into()),
            pinned_signing_key_hex: Some("00".repeat(32)),
            refresh_interval_secs: 600,
        };
        let (bus, _server_rx) = EventBus::new(8, 8);
        let (controller, signal) = ShutdownController::new();
        let handle = SoftwareModule::start(&cfg, bus, signal);
        controller.shutdown();
        handle.task.await.unwrap().unwrap();
    }
}
