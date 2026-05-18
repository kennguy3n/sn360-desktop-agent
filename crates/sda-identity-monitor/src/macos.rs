//! macOS identity-attack provider (keychain DB opens).
//!
//! In production, this binds to the Endpoint Security framework
//! (`ES_EVENT_TYPE_NOTIFY_OPEN`) on the keychain DB paths
//! (`/Library/Keychains/*`, `~/Library/Keychains/*`) and emits an
//! [`crate::IdentitySignal`] whenever the opener is a non-Apple-
//! signed binary. Loading an ES client requires the
//! `com.apple.developer.endpoint-security.client` entitlement —
//! issued only to Apple Developer ID-signed bundles — and a
//! deployed `.systemextension` payload. None of these prerequisites
//! exist in CI, so the user-mode backend is mocked the same way the
//! Windows backend is. The production wiring lands in E6.3 as a
//! signed SystemExtension.
//!
//! ## Path matching
//!
//! [`is_keychain_path`] is exported so the mock provider in
//! `crate::mock` and any future Endpoint Security shim can share
//! the canonical predicate. The matcher recognises both the
//! system-wide and per-user keychain directories.

use tokio::sync::mpsc;
use tracing::debug;

use sda_core::config::IdentityMonitorConfig;
use sda_core::signal::ShutdownSignal;

use crate::{IdentityProvider, IdentitySignal};

/// Default macOS keychain-access provider. See module docs for the
/// production roadmap.
#[derive(Default)]
pub struct MacosKeychainAccessProvider {
    _private: (),
}

impl IdentityProvider for MacosKeychainAccessProvider {
    fn run(
        &self,
        cfg: IdentityMonitorConfig,
        _tx: mpsc::Sender<IdentitySignal>,
        shutdown: ShutdownSignal,
    ) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        let mut shutdown = shutdown;
        tokio::spawn(async move {
            if !cfg.keychain_access_macos {
                debug!("MacosKeychainAccessProvider: disabled by config");
                shutdown.wait().await;
                return Ok(());
            }
            #[cfg(target_os = "macos")]
            {
                debug!(
                    "MacosKeychainAccessProvider: production Endpoint Security \
                     backend lands in E6.3 (signed SystemExtension). Idling \
                     until shutdown."
                );
            }
            #[cfg(not(target_os = "macos"))]
            {
                debug!(
                    "MacosKeychainAccessProvider: non-macOS host, idling until \
                     shutdown."
                );
            }
            shutdown.wait().await;
            Ok(())
        })
    }
}

/// Returns `true` if `path` looks like one of the macOS keychain
/// database files. Used by the (future) Endpoint Security shim and
/// by the mock provider's synthetic events.
pub fn is_keychain_path(path: &str) -> bool {
    path.starts_with("/Library/Keychains/")
        || path.contains("/Library/Keychains/")
        || path.ends_with(".keychain-db")
        || path.ends_with("login.keychain")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::signal::ShutdownController;
    use std::time::Duration;

    #[tokio::test]
    async fn macos_provider_exits_cleanly_on_shutdown() {
        let provider = MacosKeychainAccessProvider::default();
        let (tx, _rx) = mpsc::channel::<IdentitySignal>(16);
        let (ctrl, signal) = ShutdownController::new();
        let handle = provider.run(IdentityMonitorConfig::default(), tx, signal);
        ctrl.shutdown();
        tokio::time::timeout(Duration::from_millis(500), handle)
            .await
            .expect("join timeout")
            .expect("task panic")
            .expect("provider returned error");
    }

    #[test]
    fn keychain_path_matcher_recognises_canonical_locations() {
        assert!(is_keychain_path("/Library/Keychains/System.keychain"));
        assert!(is_keychain_path(
            "/Users/alice/Library/Keychains/login.keychain-db"
        ));
        assert!(is_keychain_path("/tmp/foo.keychain-db"));
        assert!(!is_keychain_path("/etc/shadow"));
        assert!(!is_keychain_path("/Applications/Calculator.app"));
    }
}
