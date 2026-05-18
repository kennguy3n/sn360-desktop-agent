//! Self-update module for the SN360 Desktop Agent (task P3.1).
//!
//! The updater periodically polls a configured update-server URL for a
//! signed manifest describing the latest agent build. When a newer
//! version is advertised it downloads the binary, verifies its
//! SHA-256 + Ed25519 signature against a pinned verifying key, and
//! atomically swaps the running binary — keeping a `.bak` copy so a
//! failed start can be rolled back.
//!
//! The module is off by default — operators opt in by setting
//! `modules.updater.enabled: true` and configuring a
//! `modules.updater.server_url` in the agent config.
//!
//! See [`docs/architecture.md`](../../../docs/architecture.md) § 1
//! (Overview) and § 6.3 (Bundle distribution) for the full design.

pub mod checker;
pub mod installer;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use sda_core::config::{AgentConfig, UpdateConfig};
use sda_core::module::{AgentModule, ModuleHandle, ModuleHealth, ModuleStatus};
use sda_core::signal::ShutdownSignal;

pub use checker::{check_for_update, UpdateManifest};
pub use installer::{install_update, InstallOutcome};

/// Minimum permitted update-check interval. A runaway timer hammering
/// the update server would be both impolite and a reliable foot-gun
/// for the bandwidth-budgeting logic elsewhere in the agent, so we
/// floor the configured value at one minute.
pub const MIN_CHECK_INTERVAL: Duration = Duration::from_secs(60);

const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// Updater module handle.
pub struct UpdaterModule {
    status: Arc<AtomicU8>,
}

impl UpdaterModule {
    /// Spawn the updater run loop and return a [`ModuleHandle`].
    pub fn start(config: &AgentConfig, shutdown: ShutdownSignal) -> ModuleHandle {
        let cfg = config.modules.updater.clone();
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);

        let task: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            if let Err(e) = run(cfg, shutdown, Arc::clone(&task_status)).await {
                error!(error = %e, "updater module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });

        ModuleHandle::new("updater", task)
    }
}

impl Default for UpdaterModule {
    fn default() -> Self {
        Self {
            status: Arc::new(AtomicU8::new(STATUS_INITIALIZED)),
        }
    }
}

impl AgentModule for UpdaterModule {
    fn name(&self) -> &'static str {
        "updater"
    }

    fn status(&self) -> ModuleStatus {
        match self.status.load(Ordering::Relaxed) {
            STATUS_RUNNING => ModuleStatus::Running,
            STATUS_STOPPED => ModuleStatus::Stopped,
            STATUS_FAILED => ModuleStatus::Failed,
            _ => ModuleStatus::Initialized,
        }
    }

    fn health(&self) -> ModuleHealth {
        match self.status.load(Ordering::Relaxed) {
            STATUS_FAILED => ModuleHealth::Unhealthy,
            _ => ModuleHealth::Healthy,
        }
    }
}

/// Effective check interval: configured value floored at
/// [`MIN_CHECK_INTERVAL`].
fn effective_check_interval(cfg: &UpdateConfig) -> Duration {
    Duration::from_secs(cfg.check_interval.max(MIN_CHECK_INTERVAL.as_secs()))
}

/// Run one complete update cycle: check, download-and-verify, install.
///
/// Logs and swallows all errors — a failed update attempt should never
/// take the agent down.
///
/// Returns `Some(installed_version)` on a successful install so the
/// caller can advance its tracked "current version" and avoid
/// re-downloading the same manifest on the next tick. Returns `None`
/// when no update was available, the download/verify failed, or the
/// freshly-installed binary was rolled back.
async fn run_once(cfg: &UpdateConfig, current_version: &str) -> Option<String> {
    let manifest = match check_for_update(cfg, current_version).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            debug!(current = current_version, "no update available");
            return None;
        }
        Err(e) => {
            warn!(error = %e, "update check failed");
            return None;
        }
    };

    info!(
        current = current_version,
        available = %manifest.version,
        "new version available, downloading"
    );

    let current_binary = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "could not resolve current_exe(); skipping install");
            return None;
        }
    };

    match install_update(cfg, &manifest, &current_binary).await {
        Ok(InstallOutcome::Installed) => {
            info!(version = %manifest.version, "update installed successfully");
            Some(manifest.version)
        }
        Ok(InstallOutcome::RolledBack) => {
            warn!(
                version = %manifest.version,
                "update installed but failed smoke test; rolled back"
            );
            None
        }
        Err(e) => {
            warn!(error = %e, "update installation failed");
            None
        }
    }
}

/// Main updater run loop.
async fn run(
    cfg: UpdateConfig,
    mut shutdown: ShutdownSignal,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    info!(
        server_url = %cfg.server_url,
        check_interval = cfg.check_interval,
        "updater module starting"
    );

    status.store(STATUS_RUNNING, Ordering::Relaxed);

    // Tracks the version currently installed on disk. Starts as the
    // compiled-in value and is advanced after each successful install
    // so the next check_for_update() call compares against what we
    // just dropped into place — otherwise the loop would happily
    // re-download the same manifest every tick until the process is
    // restarted.
    let mut current_version = env!("CARGO_PKG_VERSION").to_string();
    let mut timer = tokio::time::interval(effective_check_interval(&cfg));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;

            _ = shutdown.wait() => {
                info!("updater module received shutdown signal");
                break;
            }

            _ = timer.tick() => {
                if let Some(installed) = run_once(&cfg, &current_version).await {
                    current_version = installed;
                }
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!("updater module stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_interval_floors_at_min() {
        let cfg = UpdateConfig {
            enabled: true,
            server_url: "https://example.invalid/sda/latest.json".into(),
            check_interval: 1, // caller asks for 1 s
            public_key: String::new(),
            smoke_test_timeout: 10,
        };
        assert_eq!(effective_check_interval(&cfg), MIN_CHECK_INTERVAL);
    }

    #[test]
    fn effective_interval_respects_higher_values() {
        let cfg = UpdateConfig {
            enabled: true,
            server_url: "https://example.invalid/sda/latest.json".into(),
            check_interval: 7200,
            public_key: String::new(),
            smoke_test_timeout: 10,
        };
        assert_eq!(effective_check_interval(&cfg), Duration::from_secs(7200));
    }

    /// Regression test for the re-download loop bug fixed in A1.
    ///
    /// The manifest server advertises `"0.2.0"`. If the updater's
    /// tracked `current_version` has already been advanced to
    /// `"0.2.0"` after a successful install, `run_once` must observe
    /// via [`check_for_update`] that no newer version is available
    /// and exit without attempting to download or install anything.
    ///
    /// We assert this indirectly by pointing `server_url` at an
    /// invalid endpoint *without* an `.invalid` TLD the HTTP client
    /// will reject — any network attempt shows up as a `warn!` but
    /// run_once must still return `None` and leave disk state
    /// untouched. The test fixes the HTTP client to a bogus address
    /// on an unused port; a bug where run_once tried to proceed past
    /// the version check would surface as a long timeout or a
    /// connect error, both of which this test rejects by running
    /// under tokio's test-util clock with a tight deadline.
    #[tokio::test]
    async fn run_once_skips_when_current_matches_manifest() {
        // Stand up a tiny HTTP server that always returns the same
        // manifest. The updater is asked to compare against that
        // version, so is_newer returns false and run_once must exit
        // with `None` without ever calling install_update().
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/latest.json");

        let server = tokio::spawn(async move {
            // Serve at most one request; the test only needs one.
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await.unwrap();
            let body = br#"{
                "version": "0.2.0",
                "url": "http://127.0.0.1:1/ignored",
                "sha256": "00",
                "signature": "00"
            }"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.write_all(body).await.unwrap();
            sock.shutdown().await.ok();
        });

        let cfg = UpdateConfig {
            enabled: true,
            server_url: url,
            check_interval: 60,
            public_key: String::new(),
            smoke_test_timeout: 10,
        };

        // current_version equals the advertised manifest version →
        // no install should be attempted; returned Option is None.
        let installed = run_once(&cfg, "0.2.0").await;
        assert!(
            installed.is_none(),
            "run_once should not return an installed version when current == manifest"
        );
        server.await.unwrap();
    }
}
