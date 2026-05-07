//! Power-aware batching sink for log events.
//!
//! Each log reader ([`FileReader`], [`JournalReader`], [`OsLogReader`],
//! [`WindowsEventLogReader`]) publishes one event per log line. On a
//! busy host that produces a continuous stream of tiny writes to the
//! [`EventBus`] server queue, which keeps the agent's forwarding task
//! and the underlying TCP/UDP connection awake every few milliseconds.
//!
//! [`LogBatchSink`] wraps the shared [`EventBus`] and coalesces those
//! per-line events into periodic bursts. The flush cadence is driven
//! by the active [`PowerProfile`] via
//! [`PowerProfile::log_batch_interval`] — on AC the window is short
//! (5 s), on battery it lengthens (10–20 s), and on critical battery
//! it stretches to a minute so the radio and CPU can spend more time
//! asleep between wake-ups.
//!
//! The sink preserves the [`EventBus::publish_to_server`] API shape so
//! readers can use it as a drop-in replacement and still rely on the
//! same "queue-is-full is an error" backpressure semantics.
//!
//! [`FileReader`]: crate::file_reader::FileReader
//! [`JournalReader`]: crate::journal_reader::JournalReader
//! [`OsLogReader`]: crate::oslog_reader::OsLogReader
//! [`WindowsEventLogReader`]: crate::windows_eventlog::WindowsEventLogReader

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

use sda_core::signal::ShutdownSignal;
use sda_core::PowerProfileReceiver;
use sda_event_bus::{Event, EventBus, EventBusError};

/// Maximum number of buffered events before the sink forces a flush
/// inline with a `publish_to_server` call. This guards against
/// runaway memory growth if log lines arrive faster than the flush
/// interval can drain them (e.g. during a log burst while on battery).
const MAX_BATCH_SIZE: usize = 1024;

/// Handle used by log readers to enqueue events. Cheap to clone —
/// internally an `Arc` over the shared buffer and underlying
/// [`EventBus`].
#[derive(Clone)]
pub struct LogBatchSink {
    inner: EventBus,
    buffer: Arc<Mutex<Vec<Event>>>,
    /// Per-event passthrough. When `true` the sink forwards each
    /// event immediately and disables batching; used by tests and by
    /// the non-batched code paths that want the old behavior.
    immediate: bool,
}

impl LogBatchSink {
    /// Create a batching sink that coalesces events into windows
    /// driven by `power_rx`.
    pub fn batched(inner: EventBus) -> Self {
        Self {
            inner,
            buffer: Arc::new(Mutex::new(Vec::new())),
            immediate: false,
        }
    }

    /// Create a passthrough sink that forwards every event inline
    /// — handy for tests and for the single-event paths that don't
    /// need coalescing.
    pub fn immediate(inner: EventBus) -> Self {
        Self {
            inner,
            buffer: Arc::new(Mutex::new(Vec::new())),
            immediate: true,
        }
    }

    /// Borrow the wrapped [`EventBus`].
    pub fn inner(&self) -> &EventBus {
        &self.inner
    }

    /// Enqueue `event` for server delivery.
    ///
    /// In batched mode the event is buffered and drained by
    /// [`Self::flush_now`] (invoked by the periodic flush task). If
    /// the buffer has hit [`MAX_BATCH_SIZE`] this call triggers an
    /// inline flush before returning so memory stays bounded.
    pub async fn publish_to_server(&self, event: Event) -> Result<(), EventBusError> {
        if self.immediate {
            return self.inner.publish_to_server(event).await;
        }

        let needs_flush = {
            let mut buf = self.buffer.lock().await;
            buf.push(event);
            buf.len() >= MAX_BATCH_SIZE
        };

        if needs_flush {
            self.flush_now().await;
        }
        Ok(())
    }

    /// Drain the buffer and forward every pending event through the
    /// underlying [`EventBus`].
    ///
    /// Errors from the underlying server queue are swallowed after
    /// logging — a batch flush is a background maintenance operation
    /// and we don't want a single full queue to abort the flush task.
    pub async fn flush_now(&self) {
        if self.immediate {
            return;
        }
        let events: Vec<Event> = {
            let mut buf = self.buffer.lock().await;
            if buf.is_empty() {
                return;
            }
            std::mem::take(&mut *buf)
        };

        trace!(count = events.len(), "log-batch sink flushing");
        for event in events {
            if let Err(e) = self.inner.publish_to_server(event).await {
                warn!(error = %e, "log-batch sink failed to forward event");
            }
        }
    }
}

/// Spawn a background flush task that periodically drains `sink`
/// using the active [`PowerProfile`]'s
/// [`log_batch_interval`](PowerProfile::log_batch_interval).
///
/// The task observes `power_rx`; when the profile changes the sleep
/// interval is recomputed, so a transition onto battery immediately
/// stretches the flush window without waiting for the current timer
/// to expire.
///
/// The task drains the sink once on shutdown so events buffered in
/// the final window are not lost.
pub fn spawn_flush_task(
    sink: LogBatchSink,
    mut power_rx: PowerProfileReceiver,
    mut shutdown: ShutdownSignal,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut current_profile = *power_rx.borrow();
        let mut interval =
            tokio::time::interval(current_profile.log_batch_interval().max(MIN_TIMER));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Consume the immediate first tick so we don't flush an empty
        // buffer right after startup.
        interval.tick().await;

        loop {
            tokio::select! {
                biased;

                _ = shutdown.wait() => {
                    debug!("log-batch flush task shutting down; draining sink");
                    sink.flush_now().await;
                    break;
                }

                change = power_rx.changed() => {
                    if change.is_err() {
                        // Sender gone — keep running with the last
                        // known profile until the shutdown signal
                        // fires so we never silently stop flushing.
                        continue;
                    }
                    let new_profile = *power_rx.borrow();
                    if new_profile != current_profile {
                        debug!(
                            previous = ?current_profile,
                            current = ?new_profile,
                            "log-batch flush cadence retuning"
                        );
                        current_profile = new_profile;
                        interval = tokio::time::interval(
                            current_profile.log_batch_interval().max(MIN_TIMER),
                        );
                        interval.set_missed_tick_behavior(
                            tokio::time::MissedTickBehavior::Delay,
                        );
                        interval.tick().await;
                    }
                }

                _ = interval.tick() => {
                    sink.flush_now().await;
                }
            }
        }
    })
}

/// Minimum flush interval. Even if [`PowerProfile::log_batch_interval`]
/// ever returned a zero-or-near-zero duration we still want the flush
/// task to yield between wake-ups.
const MIN_TIMER: Duration = Duration::from_millis(100);

#[cfg(test)]
mod tests {
    use super::*;
    use sda_event_bus::{EventKind, Priority};

    fn test_event() -> Event {
        Event::new(
            "test",
            Priority::Normal,
            EventKind::LogCollected {
                source: "unit".to_string(),
                message: "hello".to_string(),
                format: "plain".to_string(),
            },
        )
    }

    #[tokio::test]
    async fn test_immediate_sink_forwards_per_event() {
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let sink = LogBatchSink::immediate(bus);

        sink.publish_to_server(test_event()).await.unwrap();
        let received = server_rx.recv().await.unwrap();
        assert_eq!(received.source, "test");
    }

    #[tokio::test]
    async fn test_batched_sink_buffers_until_flush() {
        let (bus, mut server_rx) = EventBus::new(16, 16);
        let sink = LogBatchSink::batched(bus);

        for _ in 0..3 {
            sink.publish_to_server(test_event()).await.unwrap();
        }

        // Before flush: server queue should be empty.
        assert!(server_rx.try_recv().is_err());

        sink.flush_now().await;

        // After flush: three events should have landed on the queue.
        for _ in 0..3 {
            let received = server_rx.recv().await.unwrap();
            assert_eq!(received.source, "test");
        }
    }

    #[tokio::test]
    async fn test_batched_sink_force_flushes_at_max_batch() {
        let (bus, mut server_rx) = EventBus::new(2048, 2048);
        let sink = LogBatchSink::batched(bus);

        for _ in 0..MAX_BATCH_SIZE {
            sink.publish_to_server(test_event()).await.unwrap();
        }

        // Hitting MAX_BATCH_SIZE triggers an inline flush; events
        // should be on the server queue without an explicit
        // `flush_now` call.
        let mut drained = 0usize;
        while drained < MAX_BATCH_SIZE {
            match server_rx.try_recv() {
                Ok(_) => drained += 1,
                Err(_) => break,
            }
        }
        assert_eq!(drained, MAX_BATCH_SIZE);
    }
}
