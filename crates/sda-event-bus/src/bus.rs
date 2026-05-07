use tokio::sync::{broadcast, mpsc};
use tracing::{debug, warn};

use crate::event::Event;

/// Errors from the event bus.
#[derive(Debug, thiserror::Error)]
pub enum EventBusError {
    #[error("event bus channel is full, dropping event")]
    ChannelFull,
    #[error("event bus has been shut down")]
    Closed,
}

/// A receiver handle for the event bus.
///
/// Each module gets its own receiver to consume events independently.
pub struct EventReceiver {
    broadcast_rx: broadcast::Receiver<Event>,
}

impl EventReceiver {
    /// Receive the next event from the bus.
    ///
    /// Returns `None` if the bus has been shut down and all pending events
    /// have been consumed.
    pub async fn recv(&mut self) -> Option<Event> {
        loop {
            match self.broadcast_rx.recv().await {
                Ok(event) => return Some(event),
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(skipped = n, "event receiver lagged, skipped events");
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

/// The central event bus that connects all agent modules.
///
/// Uses a broadcast channel so every subscriber sees every event.
/// The bus has a bounded capacity; if a slow consumer lags behind,
/// it will skip oldest events rather than block producers.
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<Event>,
    /// Dedicated channel for events that must be forwarded to the server.
    server_tx: mpsc::Sender<Event>,
    capacity: usize,
}

impl EventBus {
    /// Create a new event bus with the given capacity.
    ///
    /// `capacity` controls how many events can be buffered before slow
    /// consumers start lagging.
    /// `server_queue_size` controls the bounded queue for server-bound events.
    pub fn new(capacity: usize, server_queue_size: usize) -> (Self, mpsc::Receiver<Event>) {
        let (tx, _) = broadcast::channel(capacity);
        let (server_tx, server_rx) = mpsc::channel(server_queue_size);

        let bus = Self {
            tx,
            server_tx,
            capacity,
        };

        (bus, server_rx)
    }

    /// Subscribe to the event bus. Returns a receiver that will see all
    /// future events published after this call.
    pub fn subscribe(&self) -> EventReceiver {
        EventReceiver {
            broadcast_rx: self.tx.subscribe(),
        }
    }

    /// Publish an event to all subscribers.
    pub fn publish(&self, event: Event) -> Result<(), EventBusError> {
        // Try to send on broadcast channel
        match self.tx.send(event) {
            Ok(n) => {
                debug!(receivers = n, "event published to bus");
                Ok(())
            }
            Err(_) => {
                // No active receivers -- this is not an error, events are simply
                // dropped if nobody is listening.
                debug!("event published but no receivers active");
                Ok(())
            }
        }
    }

    /// Publish an event to local subscribers and also queue it for server
    /// delivery.
    ///
    /// Local broadcast is unconditional — subscribers always receive the
    /// event regardless of server-channel state. The returned `Result`
    /// reflects only the outcome relevant to callers that need to retry or
    /// spool on the server side:
    ///
    /// * `Ok(())` — event enqueued for server delivery, OR the server
    ///   receiver has been dropped (e.g. `legacy-siem` disabled). In both
    ///   cases the caller has nothing to retry.
    /// * `Err(EventBusError::ChannelFull)` — the server queue is
    ///   saturated; callers that persist data for later retry
    ///   (offline-queue replay, baseline/delta inventory publishers)
    ///   must observe this and keep their state to replay on the next
    ///   tick.
    pub async fn publish_to_server(&self, event: Event) -> Result<(), EventBusError> {
        let server_result = match self.server_tx.try_send(event.clone()) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Receiver was dropped (e.g. legacy-siem feature disabled).
                // Server delivery is intentionally disabled — not an error.
                debug!("server channel closed, skipping server delivery");
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("server event queue full, dropping server-bound copy");
                Err(EventBusError::ChannelFull)
            }
        };

        // Broadcast to local subscribers unconditionally so modules like
        // Active Response and the Local Detection Engine receive every
        // event regardless of server-channel state. A local broadcast
        // failure is propagated in preference to a server-queue failure
        // because it indicates the bus itself is in a worse state.
        self.publish(event)?;

        server_result
    }

    /// Get the configured capacity of the bus.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get the number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

// Ensure EventBus is cheaply cloneable (it's just Arc'd channels internally)
impl std::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBus")
            .field("capacity", &self.capacity)
            .field("subscribers", &self.tx.receiver_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, Priority};

    #[tokio::test]
    async fn test_publish_and_receive() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let mut rx = bus.subscribe();

        let event = Event::new("test", Priority::Normal, EventKind::Keepalive);
        bus.publish(event).unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv())
            .await
            .unwrap();

        assert!(received.is_some());
        let received = received.unwrap();
        assert_eq!(received.source, "test");
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        let event = Event::new("test", Priority::Normal, EventKind::Keepalive);
        bus.publish(event).unwrap();

        let r1 = rx1.recv().await.unwrap();
        let r2 = rx2.recv().await.unwrap();

        assert_eq!(r1.id, r2.id);
    }

    #[tokio::test]
    async fn test_server_queue() {
        let (bus, mut server_rx) = EventBus::new(64, 64);
        let _sub = bus.subscribe();

        let event = Event::new("test", Priority::Normal, EventKind::Keepalive);
        bus.publish_to_server(event).await.unwrap();

        let server_event = server_rx.recv().await.unwrap();
        assert_eq!(server_event.source, "test");
    }

    #[test]
    fn test_subscriber_count() {
        let (bus, _server_rx) = EventBus::new(64, 64);
        assert_eq!(bus.subscriber_count(), 0);

        let _rx1 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 1);

        let _rx2 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);
    }

    #[tokio::test]
    async fn test_publish_to_server_after_receiver_dropped() {
        let (bus, server_rx) = EventBus::new(64, 64);
        let mut local_sub = bus.subscribe();

        // Drop the server receiver to simulate legacy-siem disabled
        drop(server_rx);

        let event = Event::new("test", Priority::Normal, EventKind::Keepalive);
        // Must NOT return an error — local delivery must still work
        bus.publish_to_server(event).await.unwrap();

        let received =
            tokio::time::timeout(std::time::Duration::from_millis(100), local_sub.recv())
                .await
                .unwrap();
        assert!(received.is_some());
        assert_eq!(received.unwrap().source, "test");
    }

    #[tokio::test]
    async fn test_publish_to_server_when_queue_full_still_broadcasts_locally() {
        // Tiny server queue (capacity 1) that we never drain.
        let (bus, _server_rx) = EventBus::new(64, 1);
        let mut local_sub = bus.subscribe();

        // Fill the server queue.
        let event1 = Event::new("fill", Priority::Normal, EventKind::Keepalive);
        bus.publish_to_server(event1)
            .await
            .expect("first publish should succeed");

        // The second publish must report ChannelFull so callers with
        // spool/retry logic can preserve their state…
        let event2 = Event::new("overflow", Priority::Normal, EventKind::Keepalive);
        let err = bus
            .publish_to_server(event2)
            .await
            .expect_err("second publish should surface ChannelFull");
        assert!(matches!(err, EventBusError::ChannelFull));

        // …and both events must still have been broadcast locally.
        let r1 = tokio::time::timeout(std::time::Duration::from_millis(100), local_sub.recv())
            .await
            .unwrap();
        assert_eq!(r1.unwrap().source, "fill");

        let r2 = tokio::time::timeout(std::time::Duration::from_millis(100), local_sub.recv())
            .await
            .unwrap();
        assert_eq!(r2.unwrap().source, "overflow");
    }
}
