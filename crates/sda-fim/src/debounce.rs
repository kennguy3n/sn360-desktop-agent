//! Debounce logic for filesystem events.
//!
//! Collects events per path within a configurable time window and collapses
//! them into a single event, keeping the latest event kind.  Uses a
//! `HashMap<PathBuf, Instant>` to track the last event time per path.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use sda_pal::types::FsEventKind;
use tokio::time::Instant;

/// Per-path pending event: the latest event kind and when it was last seen.
#[derive(Debug, Clone)]
struct PendingEvent {
    kind: FsEventKind,
    last_seen: Instant,
}

/// Debounce engine that collapses rapid filesystem events for the same path.
///
/// Events received within `window` of each other (for the same path) are
/// merged — only the latest event kind is retained.  Once the window
/// expires the event is considered "ready" and can be drained.
pub struct Debouncer {
    window: Duration,
    pending: HashMap<PathBuf, PendingEvent>,
}

impl Debouncer {
    /// Create a new debouncer with the given window in milliseconds.
    pub fn new(debounce_ms: u64) -> Self {
        Self {
            window: Duration::from_millis(debounce_ms),
            pending: HashMap::new(),
        }
    }

    /// Record a new raw event for `path`.
    ///
    /// If the path already has a pending event the kind is updated and the
    /// timer is reset.
    pub fn record(&mut self, path: PathBuf, kind: FsEventKind) {
        self.pending.insert(
            path,
            PendingEvent {
                kind,
                last_seen: Instant::now(),
            },
        );
    }

    /// Drain all events whose debounce window has expired.
    ///
    /// Returns a `Vec` of `(path, kind)` pairs that are ready.
    pub fn drain_ready(&mut self) -> Vec<(PathBuf, FsEventKind)> {
        let now = Instant::now();
        let ready_paths: Vec<PathBuf> = self
            .pending
            .iter()
            .filter(|(_, pe)| now.duration_since(pe.last_seen) >= self.window)
            .map(|(p, _)| p.clone())
            .collect();

        let mut result = Vec::with_capacity(ready_paths.len());
        for path in ready_paths {
            if let Some(pe) = self.pending.remove(&path) {
                result.push((path, pe.kind));
            }
        }
        result
    }

    /// Return the duration until the next pending event becomes ready,
    /// or `None` if there are no pending events.
    pub fn next_deadline(&self) -> Option<Duration> {
        let now = Instant::now();
        self.pending
            .values()
            .map(|pe| {
                let elapsed = now.duration_since(pe.last_seen);
                self.window.saturating_sub(elapsed)
            })
            .min()
    }

    /// Returns `true` when there are no pending events.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_events_within_window_collapse() {
        let mut d = Debouncer::new(200);

        let path = PathBuf::from("/etc/passwd");
        d.record(path.clone(), FsEventKind::Modified);
        // Immediately record another event for the same path.
        d.record(path.clone(), FsEventKind::Modified);
        d.record(path.clone(), FsEventKind::Modified);

        // Nothing should be ready yet (window has not expired).
        let ready = d.drain_ready();
        assert!(ready.is_empty(), "events should still be pending");

        // Wait for the debounce window to pass.
        tokio::time::sleep(Duration::from_millis(250)).await;

        let ready = d.drain_ready();
        assert_eq!(ready.len(), 1, "three rapid events should collapse to one");
        assert_eq!(ready[0].0, path);
    }

    #[tokio::test]
    async fn test_events_outside_window_are_separate() {
        let mut d = Debouncer::new(50);

        let path_a = PathBuf::from("/a");
        let path_b = PathBuf::from("/b");

        d.record(path_a.clone(), FsEventKind::Created);
        d.record(path_b.clone(), FsEventKind::Deleted);

        // Wait for window to expire.
        tokio::time::sleep(Duration::from_millis(80)).await;

        let ready = d.drain_ready();
        assert_eq!(
            ready.len(),
            2,
            "different paths should yield separate events"
        );
    }

    #[tokio::test]
    async fn test_latest_kind_wins() {
        let mut d = Debouncer::new(100);

        let path = PathBuf::from("/etc/shadow");
        d.record(path.clone(), FsEventKind::Created);
        d.record(path.clone(), FsEventKind::Modified);

        tokio::time::sleep(Duration::from_millis(150)).await;

        let ready = d.drain_ready();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].1, FsEventKind::Modified, "latest kind should win");
    }

    #[test]
    fn test_next_deadline_empty() {
        let d = Debouncer::new(100);
        assert!(d.next_deadline().is_none());
    }

    #[test]
    fn test_is_empty() {
        let mut d = Debouncer::new(100);
        assert!(d.is_empty());
        d.record(PathBuf::from("/x"), FsEventKind::Created);
        assert!(!d.is_empty());
    }

    #[tokio::test]
    async fn test_next_deadline_decreases() {
        let mut d = Debouncer::new(200);
        d.record(PathBuf::from("/test"), FsEventKind::Modified);

        let d1 = d.next_deadline().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let d2 = d.next_deadline().unwrap();

        assert!(d2 < d1, "deadline should decrease over time");
    }
}
