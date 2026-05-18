//! Windows identity-attack provider (LSASS handle openings).
//!
//! In production, this binds to ETW via
//! `Microsoft-Windows-Threat-Intelligence`
//! (event ID 5: `Sensitive Handle Created`) and watches for
//! non-system PIDs opening `lsass.exe` with
//! `PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION`. Both the
//! ETW session and the corresponding access-mask interpretation
//! require `SeSystemProfilePrivilege` plus a SYSTEM-elevated host
//! agent, neither of which we can grant inside the standard CI
//! runners.
//!
//! Until the WDK minifilter from E6.1 is wired up, this module
//! ships an OS-aware *no-op* on Windows hosts and a mock-friendly
//! provider on every host so the module-level lifecycle code and
//! tests can still exercise the trait. The shape is identical to
//! the [`crate::linux::LinuxShadowAccessProvider`] so dropping in a
//! real backend is a single line in
//! [`crate::default_providers`].

use tokio::sync::mpsc;
use tracing::debug;

use sda_core::config::IdentityMonitorConfig;
use sda_core::signal::ShutdownSignal;

use crate::{IdentityProvider, IdentitySignal};

/// Default Windows LSASS-access provider.
///
/// On non-Windows hosts this is a no-op that immediately returns
/// from its background task. On Windows hosts it is currently a
/// stub waiting for the WDK minifilter from E6.1; see the crate-
/// level docs.
#[derive(Default)]
pub struct WindowsLsassAccessProvider {
    _private: (),
}

impl IdentityProvider for WindowsLsassAccessProvider {
    fn run(
        &self,
        cfg: IdentityMonitorConfig,
        _tx: mpsc::Sender<IdentitySignal>,
        shutdown: ShutdownSignal,
    ) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        let mut shutdown = shutdown;
        tokio::spawn(async move {
            if !cfg.lsass_access_windows {
                debug!("WindowsLsassAccessProvider: disabled by config");
                shutdown.wait().await;
                return Ok(());
            }
            #[cfg(target_os = "windows")]
            {
                debug!(
                    "WindowsLsassAccessProvider: production ETW backend lands \
                     in E6.1 (WDK minifilter). Idling until shutdown."
                );
            }
            #[cfg(not(target_os = "windows"))]
            {
                debug!(
                    "WindowsLsassAccessProvider: non-Windows host, idling \
                     until shutdown."
                );
            }
            shutdown.wait().await;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::signal::ShutdownController;
    use std::time::Duration;

    #[tokio::test]
    async fn windows_provider_exits_cleanly_on_shutdown() {
        let provider = WindowsLsassAccessProvider::default();
        let (tx, _rx) = mpsc::channel::<IdentitySignal>(16);
        let (ctrl, signal) = ShutdownController::new();
        let handle = provider.run(
            IdentityMonitorConfig::default(),
            tx,
            signal,
        );
        ctrl.shutdown();
        let res = tokio::time::timeout(Duration::from_millis(500), handle)
            .await
            .expect("join timeout")
            .expect("task panic");
        res.expect("provider returned error");
    }

    #[tokio::test]
    async fn windows_provider_disabled_still_idles_until_shutdown() {
        let provider = WindowsLsassAccessProvider::default();
        let (tx, _rx) = mpsc::channel::<IdentitySignal>(16);
        let (ctrl, signal) = ShutdownController::new();
        let cfg = IdentityMonitorConfig {
            enabled: true,
            lsass_access_windows: false,
            shadow_access_linux: true,
            keychain_access_macos: true,
        };
        let handle = provider.run(cfg, tx, signal);
        ctrl.shutdown();
        tokio::time::timeout(Duration::from_millis(500), handle)
            .await
            .expect("join timeout")
            .expect("task panic")
            .expect("provider returned error");
    }
}
