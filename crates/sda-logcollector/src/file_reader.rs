//! Async file reader with seek position tracking for log collection.

use std::path::{Path, PathBuf};

use notify::{Event as NotifyEvent, EventKind as NotifyEventKind, RecommendedWatcher, Watcher};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use sda_event_bus::{Event, EventKind, Priority};

use crate::batch::LogBatchSink;
use crate::state::SeekState;

/// Watches a set of log files for new content and publishes log events.
pub struct FileReader {
    /// Paths being watched.
    paths: Vec<PathBuf>,
    /// Format label for each path (parallel with `paths`).
    formats: Vec<String>,
    /// Seek state tracker.
    state: SeekState,
    /// Batching sink for publishing log events.
    bus: LogBatchSink,
}

impl FileReader {
    /// Create a new file reader.
    pub fn new(
        paths: Vec<PathBuf>,
        formats: Vec<String>,
        state: SeekState,
        bus: LogBatchSink,
    ) -> Self {
        Self {
            paths,
            formats,
            state,
            bus,
        }
    }

    /// Run the file reader loop until shutdown.
    pub async fn run(
        mut self,
        mut shutdown: sda_core::signal::ShutdownSignal,
    ) -> anyhow::Result<()> {
        if self.paths.is_empty() {
            info!("no log file sources configured, file reader idle");
            shutdown.wait().await;
            return Ok(());
        }

        // Seek to saved positions (or end of file for new files).
        let file_count = self.paths.len();
        for i in 0..file_count {
            let path = &self.paths[i];
            if !path.exists() {
                warn!(path = %path.display(), "log file does not exist yet, will watch for creation");
                continue;
            }
            let path_str = path.to_string_lossy().to_string();
            let saved_offset = self.state.get_offset(&path_str);
            if saved_offset == 0 {
                // New file: seek to end so we only collect new lines.
                match tokio::fs::metadata(path).await {
                    Ok(meta) => {
                        let end = meta.len();
                        self.state.set_offset(&path_str, end);
                        debug!(path = %path_str, offset = end, "seeking to end of new log file");
                    }
                    Err(e) => {
                        warn!(path = %path_str, error = %e, "failed to stat log file");
                    }
                }
            } else {
                debug!(path = %path_str, offset = saved_offset, "resuming from saved offset");
            }

            // Read any content that appeared since last offset.
            if let Err(e) = self.read_new_lines(i).await {
                warn!(path = %path_str, error = %e, "failed initial read of log file");
            }
        }

        // Set up a notify watcher to detect modifications.
        let (notify_tx, mut notify_rx) = mpsc::channel::<PathBuf>(256);

        let mut watcher: RecommendedWatcher = {
            let tx = notify_tx.clone();
            notify::recommended_watcher(move |res: Result<NotifyEvent, notify::Error>| {
                if let Ok(event) = res {
                    if matches!(
                        event.kind,
                        NotifyEventKind::Modify(_) | NotifyEventKind::Create(_)
                    ) {
                        for p in event.paths {
                            let _ = tx.blocking_send(p);
                        }
                    }
                }
            })?
        };

        // Watch parent directories of all log files.
        let mut watched_dirs = std::collections::HashSet::new();
        for path in &self.paths {
            if let Some(parent) = path.parent() {
                if watched_dirs.insert(parent.to_path_buf()) && parent.exists() {
                    if let Err(e) = watcher.watch(parent, notify::RecursiveMode::NonRecursive) {
                        warn!(path = %parent.display(), error = %e, "failed to watch log directory");
                    } else {
                        debug!(path = %parent.display(), "watching log directory");
                    }
                }
            }
        }

        info!(files = self.paths.len(), "file reader running");

        loop {
            tokio::select! {
                biased;

                _ = shutdown.wait() => {
                    info!("file reader received shutdown signal");
                    break;
                }

                changed_path = notify_rx.recv() => {
                    let changed_path = match changed_path {
                        Some(p) => p,
                        None => break,
                    };

                    // Find which of our tracked files was modified.
                    let matched: Vec<usize> = (0..self.paths.len())
                        .filter(|i| same_file(&changed_path, &self.paths[*i]))
                        .collect();
                    for i in matched {
                        if let Err(e) = self.read_new_lines(i).await {
                            warn!(
                                path = %self.paths[i].display(),
                                error = %e,
                                "failed to read new log lines"
                            );
                        }
                    }
                }
            }
        }

        // Save state on shutdown.
        if let Err(e) = self.state.save() {
            error!(error = %e, "failed to save seek state on shutdown");
        }

        info!("file reader stopped");
        Ok(())
    }

    /// Read new lines from the file at index `i` since the last offset.
    async fn read_new_lines(&mut self, i: usize) -> anyhow::Result<()> {
        let path = &self.paths[i];
        let format = &self.formats[i];
        let path_str = path.to_string_lossy().to_string();

        if !path.exists() {
            return Ok(());
        }

        let current_offset = self.state.get_offset(&path_str);

        let meta = tokio::fs::metadata(path).await?;
        let file_len = meta.len();

        // Handle file truncation / rotation.
        let seek_to = if file_len < current_offset {
            debug!(path = %path_str, "log file truncated/rotated, reading from beginning");
            0
        } else if file_len == current_offset {
            return Ok(());
        } else {
            current_offset
        };

        let file = File::open(path).await?;
        let mut reader = BufReader::new(file);
        reader.seek(std::io::SeekFrom::Start(seek_to)).await?;

        let mut line = String::new();
        let mut new_offset = seek_to;

        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).await?;
            if bytes_read == 0 {
                break;
            }
            new_offset += bytes_read as u64;

            let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
            if trimmed.is_empty() {
                continue;
            }

            let event = Event::new(
                "logcollector",
                Priority::Normal,
                EventKind::LogCollected {
                    source: path_str.clone(),
                    message: trimmed.to_string(),
                    format: format.clone(),
                },
            );

            if let Err(e) = self.bus.publish_to_server(event).await {
                warn!(error = %e, "failed to publish log event");
            }
        }

        self.state.set_offset(&path_str, new_offset);
        debug!(path = %path_str, offset = new_offset, "updated seek offset");

        Ok(())
    }
}

/// Check if two paths refer to the same file (handles symlinks, canonicalization).
fn same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SeekState;
    use sda_core::signal::ShutdownController;
    use sda_event_bus::EventBus;
    use std::io::Write;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_file_reader_detects_new_lines() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("test.log");

        // Create log file with initial content.
        {
            let mut f = std::fs::File::create(&log_path).unwrap();
            writeln!(f, "existing line 1").unwrap();
            writeln!(f, "existing line 2").unwrap();
        }

        let state_file = tmp.path().join("state.json");
        let state = SeekState::load(state_file);

        let (bus, mut server_rx) = EventBus::new(256, 256);
        let (controller, signal) = ShutdownController::new();

        let reader = FileReader::new(
            vec![log_path.clone()],
            vec!["syslog".to_string()],
            state,
            LogBatchSink::immediate(bus),
        );

        let handle = tokio::spawn(async move {
            reader.run(signal).await.unwrap();
        });

        // Wait for reader to start and seek to end.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Append new lines.
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&log_path)
                .unwrap();
            writeln!(f, "new line 1").unwrap();
            writeln!(f, "new line 2").unwrap();
        }

        // Wait for events.
        let event = tokio::time::timeout(std::time::Duration::from_secs(10), server_rx.recv())
            .await
            .expect("timed out waiting for log event")
            .expect("channel closed");

        match &event.kind {
            EventKind::LogCollected {
                source, message, ..
            } => {
                assert!(source.contains("test.log"));
                assert_eq!(message, "new line 1");
            }
            other => panic!("expected LogCollected, got: {other:?}"),
        }

        // Second line should also arrive.
        let event2 = tokio::time::timeout(std::time::Duration::from_secs(5), server_rx.recv())
            .await
            .expect("timed out waiting for second log event")
            .expect("channel closed");

        match &event2.kind {
            EventKind::LogCollected { message, .. } => {
                assert_eq!(message, "new line 2");
            }
            other => panic!("expected LogCollected, got: {other:?}"),
        }

        controller.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn test_file_reader_handles_file_rotation() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("rotated.log");

        // Create initial file with content.
        {
            let mut f = std::fs::File::create(&log_path).unwrap();
            writeln!(f, "old content that is longer than what comes next").unwrap();
        }

        let state_file = tmp.path().join("state.json");
        let state = SeekState::load(state_file);
        let (bus, mut server_rx) = EventBus::new(256, 256);
        let (controller, signal) = ShutdownController::new();

        let reader = FileReader::new(
            vec![log_path.clone()],
            vec!["plain".to_string()],
            state,
            LogBatchSink::immediate(bus),
        );

        let handle = tokio::spawn(async move {
            reader.run(signal).await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Simulate log rotation: truncate and write new content.
        std::fs::write(&log_path, "rotated line\n").unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(10), server_rx.recv())
            .await
            .expect("timed out waiting for rotated log event")
            .expect("channel closed");

        match &event.kind {
            EventKind::LogCollected { message, .. } => {
                assert_eq!(message, "rotated line");
            }
            other => panic!("expected LogCollected, got: {other:?}"),
        }

        controller.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }
}
