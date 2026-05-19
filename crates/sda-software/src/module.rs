//! Software management module — periodic catalogue refresh and
//! package action execution.
//!
//! When enabled, the supervisor periodically fetches the signed
//! catalogue manifest from `catalogue_url`, verifies its Ed25519
//! signature against the pinned key(s), and atomically swaps the
//! in-memory [`CatalogueStore`]. Downstream action executors
//! (install/update/uninstall) read from the store.

use sda_core::config::AgentConfig;
use sda_core::module::ModuleHandle;
use sda_core::signal::ShutdownSignal;
use sda_event_bus::EventBus;
use tracing::{info, warn};

use crate::catalogue::CatalogueStore;

/// Software management module supervisor.
pub struct SoftwareModule;

impl SoftwareModule {
    /// Spawn the software-module supervisor task.
    ///
    /// Behaviour matrix:
    ///
    /// - `modules.software.enabled = false` → park on `shutdown`.
    /// - `modules.software.enabled = true` &&
    ///   `catalogue_url.is_none()` → warn and park.
    /// - `modules.software.enabled = true` &&
    ///   `pinned_signing_key_hex.is_none()` → warn and park.
    /// - Otherwise → run the periodic fetch-verify-swap loop.
    pub fn start(
        config: &AgentConfig,
        _bus: EventBus,
        mut shutdown: ShutdownSignal,
    ) -> ModuleHandle {
        let software = config.modules.software.clone();
        let store = CatalogueStore::new();

        if !software.enabled {
            info!("software module disabled — parking on shutdown");
            let task = tokio::spawn(async move {
                let _store = store;
                shutdown.wait().await;
                warn!("software module shutting down");
                Ok(())
            });
            return ModuleHandle::new("software", task);
        }

        let catalogue_url = match software.catalogue_url.clone() {
            Some(u) => u,
            None => {
                warn!(
                    "software module enabled but `catalogue_url` is unset; \
                     idling until configuration arrives"
                );
                let task = tokio::spawn(async move {
                    let _store = store;
                    shutdown.wait().await;
                    Ok(())
                });
                return ModuleHandle::new("software", task);
            }
        };

        let pinned_key = match software.pinned_signing_key_hex.clone() {
            Some(k) => k,
            None => {
                warn!(
                    "software module enabled but `pinned_signing_key_hex` is \
                     unset; refusing to fetch unsigned catalogues"
                );
                let task = tokio::spawn(async move {
                    let _store = store;
                    shutdown.wait().await;
                    Ok(())
                });
                return ModuleHandle::new("software", task);
            }
        };

        let refresh_secs = software.refresh_interval_secs.max(60);
        info!(
            refresh_interval_secs = refresh_secs,
            catalogue_url = %catalogue_url,
            "software module starting catalogue refresh loop"
        );

        let task = tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("build software http client");

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(refresh_secs));

            // First tick fires immediately so we fetch on startup.
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = shutdown.wait() => {
                        warn!("software module shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        match client
                            .get(&catalogue_url)
                            .header("User-Agent", "SN360-Desktop-Agent/1.0")
                            .send()
                            .await
                        {
                            Ok(resp) if resp.status().is_success() => {
                                match resp.bytes().await {
                                    Ok(bytes) => {
                                        match store.verify_and_swap(&bytes, &pinned_key) {
                                            Ok(rev) => {
                                                info!(
                                                    revision = rev,
                                                    "software catalogue refreshed"
                                                );
                                            }
                                            Err(e) => {
                                                warn!(
                                                    "software catalogue verification failed: {e}"
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("software catalogue body read failed: {e}");
                                    }
                                }
                            }
                            Ok(resp) => {
                                warn!(
                                    status = %resp.status(),
                                    "software catalogue fetch returned non-200"
                                );
                            }
                            Err(e) => {
                                warn!("software catalogue fetch failed: {e}");
                            }
                        }
                    }
                }
            }
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
            pinned_signing_keys: Vec::new(),
            manifest_max_age_secs: 7 * 24 * 3600,
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
            pinned_signing_keys: Vec::new(),
            manifest_max_age_secs: 7 * 24 * 3600,
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
            pinned_signing_keys: Vec::new(),
            manifest_max_age_secs: 7 * 24 * 3600,
            refresh_interval_secs: 600,
        };
        let (bus, _server_rx) = EventBus::new(8, 8);
        let (controller, signal) = ShutdownController::new();
        let handle = SoftwareModule::start(&cfg, bus, signal);
        controller.shutdown();
        handle.task.await.unwrap().unwrap();
    }
}
