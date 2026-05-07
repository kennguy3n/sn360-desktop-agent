//! Debounced filesystem watcher wrapper.
//!
//! Wraps `sda_pal::fs_watcher::FsWatcher` and adds debounce logic:
//! events for the same path within a configurable window are collapsed
//! into a single event, keeping only the latest event kind.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use sda_pal::fs_watcher::FsWatcher;
use sda_pal::types::{FsEvent, FsEventKind};
use tokio::time::Instant;

/// A debounced filesystem watcher that collapses rapid events per path.
pub struct DebouncedWatcher {
    inner: FsWatcher,
    debounce_window: Duration,
    pending: HashMap<PathBuf, (FsEventKind, Instant)>,
    channel_closed: bool,
}

impl DebouncedWatcher {
    /// Create a new debounced watcher.
    ///
    /// `debounce_ms` is the debounce window in milliseconds.
    pub fn new(debounce_ms: u64) -> Result<Self, sda_pal::fs_watcher::FsWatcherError> {
        let inner = FsWatcher::new(1024)?;
        Ok(Self {
            inner,
            debounce_window: Duration::from_millis(debounce_ms),
            pending: HashMap::new(),
            channel_closed: false,
        })
    }

    /// Start watching a directory.
    pub fn watch(
        &mut self,
        path: &std::path::Path,
        recursive: bool,
    ) -> Result<(), sda_pal::fs_watcher::FsWatcherError> {
        self.inner.watch(path, recursive)
    }

    /// Return the next debounced event.
    ///
    /// Collects raw events within the debounce window, deduplicates
    /// by path (keeping the latest event kind), then yields them
    /// one at a time.
    pub async fn next_event(&mut self) -> Option<FsEvent> {
        loop {
            // First, flush any pending events whose debounce window has expired.
            let now = Instant::now();
            let ready: Vec<PathBuf> = self
                .pending
                .iter()
                .filter(|(_, (_, ts))| now.duration_since(*ts) >= self.debounce_window)
                .map(|(p, _)| p.clone())
                .collect();

            if let Some(path) = ready.into_iter().next() {
                let (kind, _) = self.pending.remove(&path).unwrap();
                return Some(FsEvent { path, kind });
            }

            // Calculate how long to wait for the next pending event to become ready.
            let sleep_dur = self
                .pending
                .values()
                .map(|(_, ts)| {
                    let elapsed = now.duration_since(*ts);
                    self.debounce_window.saturating_sub(elapsed)
                })
                .min();

            // Either wait for a new raw event or for the next pending timeout.
            match sleep_dur {
                Some(dur) if !dur.is_zero() => {
                    if self.channel_closed {
                        // Channel is closed; just sleep until the next pending event is ready.
                        tokio::time::sleep(dur).await;
                    } else {
                        tokio::select! {
                            raw = self.inner.recv() => {
                                match raw {
                                    Some(ev) => {
                                        self.pending.insert(ev.path, (ev.kind, Instant::now()));
                                    }
                                    None => {
                                        self.channel_closed = true;
                                        if self.pending.is_empty() {
                                            return None;
                                        }
                                    }
                                }
                            }
                            _ = tokio::time::sleep(dur) => {
                                // A pending event is now ready; loop back.
                            }
                        }
                    }
                }
                Some(_) => {
                    // dur is zero, loop back to flush.
                    continue;
                }
                None => {
                    if self.channel_closed {
                        return None;
                    }
                    // No pending events; just wait for new raw events.
                    match self.inner.recv().await {
                        Some(ev) => {
                            self.pending.insert(ev.path, (ev.kind, Instant::now()));
                        }
                        None => {
                            self.channel_closed = true;
                            return None;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_debounce_collapses_events() {
        let dir = TempDir::new().unwrap();
        let mut watcher = DebouncedWatcher::new(200).unwrap();
        watcher.watch(dir.path(), true).unwrap();

        // Wait for watcher to register.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let file_path = dir.path().join("test.txt");

        // Rapid writes to the same file.
        fs::write(&file_path, "v1").unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        fs::write(&file_path, "v2").unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        fs::write(&file_path, "v3").unwrap();

        // Wait for the debounce window to pass.
        tokio::time::sleep(Duration::from_millis(400)).await;

        // We should get at most a small number of events for the path
        // (possibly 1 create + 1 modify, but not 3+ separate modify events).
        let mut count = 0;
        while let Ok(Some(_)) = timeout(Duration::from_millis(300), watcher.next_event()).await {
            count += 1;
        }
        // The debouncer should have collapsed the rapid writes.
        // We expect fewer events than the 3+ raw events generated.
        assert!(count >= 1, "should receive at least one event");
        assert!(
            count <= 3,
            "debounce should collapse rapid events, got {count}"
        );
    }

    #[tokio::test]
    async fn test_watcher_detects_creation() {
        let dir = TempDir::new().unwrap();
        let mut watcher = DebouncedWatcher::new(50).unwrap();
        watcher.watch(dir.path(), true).unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let file_path = dir.path().join("created.txt");
        fs::write(&file_path, "new file").unwrap();

        let event = timeout(Duration::from_secs(5), watcher.next_event())
            .await
            .expect("should receive event within timeout");

        assert!(event.is_some());
    }
}
