//! Local response dispatcher.
//!
//! The LDE can take three first-class local actions:
//!
//! * **`block_ip`** — delegates to the `firewall-drop` action in
//!   `sda-active-response`, which drives the platform-native firewall.
//! * **`kill_process`** — delegates to the `kill_process` action in
//!   `sda-active-response`.
//! * **`quarantine`** — moves a file out of the way into a
//!   dedicated quarantine directory with a random suffix to avoid
//!   collisions.  Implemented inline since no equivalent exists in
//!   `sda-active-response`.
//!
//! Each action is gated on a boolean in [`LocalDetectionConfig`].  An
//! action that is disabled returns [`ResponseOutcome::Skipped`].

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{debug, warn};

use sda_active_response::actions::{ActionParams, ActionRegistry};
use sda_core::config::LocalDetectionConfig;

/// Outcome of a single response action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseOutcome {
    /// Action completed successfully.  Attached text is action-specific.
    Executed(String),
    /// Action ran and reported a failure.
    Failed(String),
    /// Action was disabled in configuration and not attempted.
    Skipped,
}

impl ResponseOutcome {
    pub fn is_executed(&self) -> bool {
        matches!(self, ResponseOutcome::Executed(_))
    }
    pub fn is_skipped(&self) -> bool {
        matches!(self, ResponseOutcome::Skipped)
    }
}

/// Thin wrapper around the `sda-active-response` registry plus the
/// LDE-specific quarantine action.
pub struct LocalResponder {
    registry: ActionRegistry,
    config: LocalDetectionConfig,
    dispatch_timeout: Duration,
}

impl LocalResponder {
    /// Build a responder from the LDE config section.
    pub fn new(config: LocalDetectionConfig) -> Self {
        let mut allowed = Vec::new();
        if config.block_ip {
            allowed.push("block_ip".to_string());
        }
        if config.kill_process {
            allowed.push("kill_process".to_string());
        }
        let registry = ActionRegistry::new(&allowed);
        Self {
            registry,
            config,
            dispatch_timeout: Duration::from_secs(30),
        }
    }

    /// Block `ip` at the host firewall.
    pub async fn block_ip(&self, ip: &str) -> ResponseOutcome {
        if !self.config.block_ip {
            debug!(ip, "block_ip disabled by config");
            return ResponseOutcome::Skipped;
        }
        let params = ActionParams {
            ip: Some(ip.to_string()),
            pid: None,
            user: None,
            timeout: 0,
            extra: Default::default(),
        };
        let res = self
            .registry
            .dispatch("block_ip", &params, self.dispatch_timeout)
            .await;
        if res.success {
            ResponseOutcome::Executed(res.output)
        } else {
            ResponseOutcome::Failed(res.output)
        }
    }

    /// Terminate `pid`.
    pub async fn kill_process(&self, pid: u32) -> ResponseOutcome {
        if !self.config.kill_process {
            debug!(pid, "kill_process disabled by config");
            return ResponseOutcome::Skipped;
        }
        let params = ActionParams {
            ip: None,
            pid: Some(pid),
            user: None,
            timeout: 0,
            extra: Default::default(),
        };
        let res = self
            .registry
            .dispatch("kill_process", &params, self.dispatch_timeout)
            .await;
        if res.success {
            ResponseOutcome::Executed(res.output)
        } else {
            ResponseOutcome::Failed(res.output)
        }
    }

    /// Move `path` into the quarantine directory.  Idempotent; the
    /// destination filename embeds a nanosecond timestamp so repeated
    /// calls don't clobber prior files.
    pub async fn quarantine(&self, path: &Path) -> ResponseOutcome {
        if !self.config.quarantine {
            debug!(path = %path.display(), "quarantine disabled by config");
            return ResponseOutcome::Skipped;
        }
        let dir = self.config.quarantine_dir.clone();
        let src = path.to_path_buf();
        let result = tokio::task::spawn_blocking(move || quarantine_file(&src, &dir)).await;
        match result {
            Ok(Ok(dst)) => ResponseOutcome::Executed(format!("moved to {}", dst.display())),
            Ok(Err(e)) => ResponseOutcome::Failed(format!("{e}")),
            Err(e) => ResponseOutcome::Failed(format!("quarantine task panicked: {e}")),
        }
    }
}

fn quarantine_file(src: &Path, quarantine_dir: &Path) -> anyhow::Result<PathBuf> {
    if !src.exists() {
        anyhow::bail!("source file does not exist: {}", src.display());
    }
    std::fs::create_dir_all(quarantine_dir).map_err(|e| {
        anyhow::anyhow!(
            "failed to create quarantine dir {}: {}",
            quarantine_dir.display(),
            e
        )
    })?;
    let stem = src
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "quarantined".into());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dst = quarantine_dir.join(format!("{stem}.{nanos}.quar"));
    // Try a rename first; fall back to copy + remove across filesystems.
    match std::fs::rename(src, &dst) {
        Ok(()) => Ok(dst),
        Err(e) => {
            warn!(error = %e, "rename failed, falling back to copy+remove");
            std::fs::copy(src, &dst)
                .map_err(|e| anyhow::anyhow!("quarantine copy failed: {}", e))?;
            std::fs::remove_file(src)
                .map_err(|e| anyhow::anyhow!("quarantine remove failed: {}", e))?;
            Ok(dst)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(dir: &Path) -> LocalDetectionConfig {
        LocalDetectionConfig {
            enabled: true,
            block_ip: false,
            kill_process: false,
            quarantine: true,
            quarantine_dir: dir.to_path_buf(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_block_ip_disabled_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(dir.path());
        c.block_ip = false;
        let r = LocalResponder::new(c);
        assert!(r.block_ip("1.2.3.4").await.is_skipped());
    }

    #[tokio::test]
    async fn test_kill_process_disabled_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let r = LocalResponder::new(cfg(dir.path()));
        assert!(r.kill_process(1).await.is_skipped());
    }

    #[tokio::test]
    async fn test_quarantine_moves_file() {
        let dir = tempfile::tempdir().unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("malware.bin");
        std::fs::write(&src, b"bad bytes").unwrap();

        let r = LocalResponder::new(cfg(dir.path()));
        let outcome = r.quarantine(&src).await;
        assert!(outcome.is_executed(), "got {:?}", outcome);
        assert!(!src.exists(), "source should be moved");

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(entries.len(), 1);
        assert!(entries[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("malware.bin."));
    }

    #[tokio::test]
    async fn test_quarantine_disabled_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(dir.path());
        c.quarantine = false;
        let r = LocalResponder::new(c);
        let path = dir.path().join("whatever.bin");
        assert!(r.quarantine(&path).await.is_skipped());
    }

    #[tokio::test]
    async fn test_quarantine_missing_source_fails() {
        let dir = tempfile::tempdir().unwrap();
        let r = LocalResponder::new(cfg(dir.path()));
        let outcome = r.quarantine(Path::new("/nonexistent/does-not-exist")).await;
        assert!(matches!(outcome, ResponseOutcome::Failed(_)));
    }
}
