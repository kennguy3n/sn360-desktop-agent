//! Cross-platform filesystem watcher using the `notify` crate.
//!
//! Wraps OS-native filesystem notification APIs:
//! - Linux: inotify (with fanotify fallback planned)
//! - macOS: FSEvents
//! - Windows: ReadDirectoryChangesW

use std::path::{Path, PathBuf};

use notify::{
    Config, Event as NotifyEvent, EventKind as NotifyEventKind, RecommendedWatcher, RecursiveMode,
    Watcher,
};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::types::{FsEvent, FsEventKind};

/// Errors from the filesystem watcher.
#[derive(Debug, thiserror::Error)]
pub enum FsWatcherError {
    #[error("watcher initialization failed: {0}")]
    InitFailed(String),
    #[error("failed to watch path {path}: {source}")]
    WatchFailed {
        path: PathBuf,
        source: notify::Error,
    },
    #[error("watcher channel closed")]
    ChannelClosed,
}

/// Cross-platform filesystem watcher.
///
/// Uses OS-native APIs under the hood via the `notify` crate:
/// - Linux: inotify
/// - macOS: FSEvents
/// - Windows: ReadDirectoryChangesW
pub struct FsWatcher {
    watcher: RecommendedWatcher,
    event_rx: mpsc::Receiver<FsEvent>,
    watched_paths: Vec<PathBuf>,
}

impl FsWatcher {
    /// Create a new filesystem watcher.
    ///
    /// `buffer_size` controls how many events can be buffered before
    /// backpressure is applied to the OS watcher.
    pub fn new(buffer_size: usize) -> Result<Self, FsWatcherError> {
        let (tx, rx) = mpsc::channel(buffer_size);

        let watcher = RecommendedWatcher::new(
            move |result: Result<NotifyEvent, notify::Error>| match result {
                Ok(event) => {
                    if let Some(fs_event) = convert_event(&event) {
                        for ev in fs_event {
                            if tx.blocking_send(ev).is_err() {
                                warn!("fs watcher event channel full, dropping event");
                            }
                        }
                    }
                }
                Err(e) => {
                    error!(error = %e, "filesystem watcher error");
                }
            },
            Config::default(),
        )
        .map_err(|e| FsWatcherError::InitFailed(e.to_string()))?;

        info!("filesystem watcher initialized");

        Ok(Self {
            watcher,
            event_rx: rx,
            watched_paths: Vec::new(),
        })
    }

    /// Start watching a path for changes.
    pub fn watch(&mut self, path: &Path, recursive: bool) -> Result<(), FsWatcherError> {
        let mode = if recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };

        self.watcher
            .watch(path, mode)
            .map_err(|e| FsWatcherError::WatchFailed {
                path: path.to_path_buf(),
                source: e,
            })?;

        self.watched_paths.push(path.to_path_buf());
        debug!(path = %path.display(), recursive, "watching path for changes");
        Ok(())
    }

    /// Stop watching a path.
    pub fn unwatch(&mut self, path: &Path) -> Result<(), FsWatcherError> {
        self.watcher
            .unwatch(path)
            .map_err(|e| FsWatcherError::WatchFailed {
                path: path.to_path_buf(),
                source: e,
            })?;

        self.watched_paths.retain(|p| p != path);
        debug!(path = %path.display(), "stopped watching path");
        Ok(())
    }

    /// Receive the next filesystem event.
    ///
    /// Returns `None` if the watcher has been dropped.
    pub async fn recv(&mut self) -> Option<FsEvent> {
        self.event_rx.recv().await
    }

    /// Get the list of currently watched paths.
    pub fn watched_paths(&self) -> &[PathBuf] {
        &self.watched_paths
    }
}

/// Convert a `notify` event into our internal FsEvent(s).
fn convert_event(event: &NotifyEvent) -> Option<Vec<FsEvent>> {
    let kind = match &event.kind {
        NotifyEventKind::Create(_) => FsEventKind::Created,
        NotifyEventKind::Modify(modify_kind) => {
            use notify::event::ModifyKind;
            match modify_kind {
                ModifyKind::Metadata(_) => FsEventKind::MetadataChanged,
                ModifyKind::Name(_) => FsEventKind::Renamed,
                _ => FsEventKind::Modified,
            }
        }
        NotifyEventKind::Remove(_) => FsEventKind::Deleted,
        NotifyEventKind::Access(_) => return None, // Ignore access events
        NotifyEventKind::Other => return None,
        NotifyEventKind::Any => FsEventKind::Modified,
    };

    let events: Vec<FsEvent> = event
        .paths
        .iter()
        .map(|path| FsEvent {
            path: path.clone(),
            kind,
        })
        .collect();

    if events.is_empty() {
        None
    } else {
        Some(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn test_watcher_creation() {
        let watcher = FsWatcher::new(64);
        assert!(watcher.is_ok());
    }

    #[tokio::test]
    async fn test_watch_directory() {
        let dir = TempDir::new().unwrap();
        let mut watcher = FsWatcher::new(64).unwrap();

        let result = watcher.watch(dir.path(), true);
        assert!(result.is_ok());
        assert_eq!(watcher.watched_paths().len(), 1);
    }

    #[tokio::test]
    async fn test_detect_file_creation() {
        let dir = TempDir::new().unwrap();
        let mut watcher = FsWatcher::new(64).unwrap();
        watcher.watch(dir.path(), true).unwrap();

        // Give the watcher a moment to register
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Create a file
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "hello").unwrap();

        // Wait for the event (with timeout)
        let event = timeout(Duration::from_secs(5), watcher.recv()).await;
        assert!(event.is_ok(), "should receive an event within timeout");
        let event = event.unwrap();
        assert!(event.is_some(), "event should not be None");
    }

    #[tokio::test]
    async fn test_unwatch() {
        let dir = TempDir::new().unwrap();
        let mut watcher = FsWatcher::new(64).unwrap();

        watcher.watch(dir.path(), true).unwrap();
        assert_eq!(watcher.watched_paths().len(), 1);

        watcher.unwatch(dir.path()).unwrap();
        assert_eq!(watcher.watched_paths().len(), 0);
    }
}
