//! Event batching for the real-time FIM pipeline.
//!
//! Accumulates FIM events in a small buffer and flushes them to the
//! event bus as a burst when either the batch is full or the batch
//! timeout expires. Batching smooths out bursty workloads (e.g., a
//! thousand `create` events arriving back-to-back) and reduces the
//! per-event context-switch overhead of the broadcast/mpsc channels.

use std::time::Duration;

use tokio::time::Instant;
use tracing::warn;

use sda_event_bus::{Event, EventBus};

/// A tiny buffering layer in front of the event bus.
///
/// Events are added via [`EventBatcher::push`]. They stay in-memory
/// until either [`EventBatcher::is_full`] returns `true` or
/// [`EventBatcher::deadline`] expires, at which point the owner should
/// call [`EventBatcher::flush`] to drain them onto the bus.
pub struct EventBatcher {
    buffer: Vec<Event>,
    batch_size: usize,
    batch_timeout: Duration,
    last_flush: Instant,
}

impl EventBatcher {
    /// Create a new batcher with the given flush triggers.
    ///
    /// `batch_size == 0` is treated as `1` (flush immediately on push).
    /// `batch_timeout` of `Duration::ZERO` is likewise treated as
    /// "always flush on push".
    pub fn new(batch_size: usize, batch_timeout_ms: u64) -> Self {
        let batch_size = batch_size.max(1);
        Self {
            buffer: Vec::with_capacity(batch_size),
            batch_size,
            batch_timeout: Duration::from_millis(batch_timeout_ms),
            last_flush: Instant::now(),
        }
    }

    /// Append an event to the batch.
    pub fn push(&mut self, event: Event) {
        self.buffer.push(event);
    }

    /// Is there at least one event waiting to be published?
    pub fn has_pending(&self) -> bool {
        !self.buffer.is_empty()
    }

    /// Number of events currently queued.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Is the batch currently empty?
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Has the batch reached its size threshold?
    pub fn is_full(&self) -> bool {
        self.buffer.len() >= self.batch_size
    }

    /// The next time the batcher should be drained, or `None` when
    /// there are no pending events.
    pub fn deadline(&self) -> Option<Instant> {
        if self.buffer.is_empty() {
            None
        } else {
            Some(self.last_flush + self.batch_timeout)
        }
    }

    /// Drain all queued events to the event bus as a single burst.
    ///
    /// Individual `publish_to_server` failures are logged but do not
    /// stop the burst — the batcher always drains to empty.
    pub async fn flush(&mut self, bus: &EventBus) {
        if self.buffer.is_empty() {
            self.last_flush = Instant::now();
            return;
        }
        // Take ownership of the buffered events so we don't hold the
        // batcher borrowed across awaits.
        let drained = std::mem::take(&mut self.buffer);
        self.buffer.reserve(self.batch_size);
        self.last_flush = Instant::now();

        for event in drained {
            if let Err(e) = bus.publish_to_server(event).await {
                warn!(error = %e, "failed to publish FIM event (batched)");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_event_bus::{EventKind, Priority};

    fn sample_event() -> Event {
        Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileCreated {
                path: "/tmp/x".to_string(),
                syscheck_payload: None,
            },
        )
    }

    #[tokio::test]
    async fn test_is_full_triggers_at_threshold() {
        let mut b = EventBatcher::new(3, 1_000);
        assert!(!b.is_full());
        b.push(sample_event());
        assert!(!b.is_full());
        b.push(sample_event());
        assert!(!b.is_full());
        b.push(sample_event());
        assert!(b.is_full());
    }

    #[tokio::test]
    async fn test_flush_publishes_all_events_and_empties_buffer() {
        let (bus, mut server_rx) = EventBus::new(64, 64);
        let mut b = EventBatcher::new(10, 200);
        b.push(sample_event());
        b.push(sample_event());
        b.push(sample_event());

        b.flush(&bus).await;
        assert_eq!(b.len(), 0);

        let mut count = 0;
        while let Ok(Some(_)) =
            tokio::time::timeout(Duration::from_millis(100), server_rx.recv()).await
        {
            count += 1;
        }
        assert_eq!(count, 3, "flush should have published all three events");
    }

    #[tokio::test]
    async fn test_deadline_returns_none_when_empty() {
        let b = EventBatcher::new(10, 100);
        assert!(b.deadline().is_none());
    }

    #[tokio::test]
    async fn test_deadline_advances_after_push() {
        let mut b = EventBatcher::new(10, 100);
        let before = b.deadline();
        b.push(sample_event());
        let after = b.deadline();
        assert!(before.is_none());
        assert!(after.is_some());
    }

    #[tokio::test]
    async fn test_flush_on_empty_is_noop() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let mut b = EventBatcher::new(10, 100);
        b.flush(&bus).await;
        assert_eq!(b.len(), 0);
    }

    #[tokio::test]
    async fn test_zero_batch_size_flushes_each_push() {
        let mut b = EventBatcher::new(0, 200);
        b.push(sample_event());
        // 0 is clamped to 1, so a single push is "full".
        assert!(b.is_full());
    }
}
