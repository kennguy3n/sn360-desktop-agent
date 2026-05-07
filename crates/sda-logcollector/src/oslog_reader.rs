//! macOS Unified Log (OSLog) collector.
//!
//! Spawns `/usr/bin/log stream` as a child process and reads events from
//! stdout, forwarding them to the event bus.
//!
//! Gated behind `#[cfg(target_os = "macos")]`.

#![cfg(target_os = "macos")]

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::{debug, error, info, warn};

use sda_core::signal::ShutdownSignal;
use sda_event_bus::{Event, EventKind, Priority};

use crate::batch::LogBatchSink;

/// Configuration for the macOS Unified Log reader.
#[derive(Debug, Clone)]
pub struct OsLogConfig {
    /// Predicate filter (e.g. `process == "sshd"`).
    pub predicate: Option<String>,
    /// Log level filter: "default", "info", "debug".
    pub level: Option<String>,
}

/// Reads events from the macOS Unified Log via `/usr/bin/log stream`.
pub struct OsLogReader {
    config: OsLogConfig,
    bus: LogBatchSink,
}

impl OsLogReader {
    pub fn new(config: OsLogConfig, bus: LogBatchSink) -> Self {
        Self { config, bus }
    }

    /// Run the OSLog reader until shutdown.
    pub async fn run(self, mut shutdown: ShutdownSignal) -> anyhow::Result<()> {
        info!("starting macOS Unified Log reader");

        let mut args = vec!["stream", "--style", "syslog"];

        let predicate_str;
        if let Some(ref predicate) = self.config.predicate {
            predicate_str = predicate.clone();
            args.push("--predicate");
            args.push(&predicate_str);
        }

        let level_str;
        if let Some(ref level) = self.config.level {
            level_str = format!("--level={}", level);
            args.push(&level_str);
        }

        let mut child = Command::new("/usr/bin/log")
            .args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to capture stdout from /usr/bin/log"))?;

        let mut reader = BufReader::new(stdout).lines();

        // Skip the header line output by `log stream`.
        let _header = reader.next_line().await;

        loop {
            tokio::select! {
                _ = shutdown.wait() => {
                    debug!("shutdown signal received, stopping OSLog reader");
                    child.kill().await.ok();
                    break;
                }
                line = reader.next_line() => {
                    match line {
                        Ok(Some(line)) => {
                            let line = line.trim().to_string();
                            if line.is_empty() {
                                continue;
                            }
                            let event = Event::new(
                                "logcollector",
                                Priority::Normal,
                                EventKind::LogCollected {
                                    source: "oslog".to_string(),
                                    message: line,
                                    format: "syslog".to_string(),
                                },
                            );
                            if let Err(e) = self.bus.publish_to_server(event).await {
                                warn!(error = %e, "failed to publish oslog event");
                            }
                        }
                        Ok(None) => {
                            warn!("OSLog stream ended unexpectedly");
                            break;
                        }
                        Err(e) => {
                            error!(error = %e, "error reading OSLog stream");
                            break;
                        }
                    }
                }
            }
        }

        info!("macOS Unified Log reader stopped");
        Ok(())
    }
}
