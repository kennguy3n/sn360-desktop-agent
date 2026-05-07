//! Cross-platform signal handling for graceful shutdown.

use std::sync::Arc;

use tokio::sync::watch;
use tracing::info;

/// Shutdown signal broadcaster.
///
/// Allows the agent core to notify all modules when a shutdown
/// has been requested (via SIGTERM, SIGINT, or Windows console event).
#[derive(Clone)]
pub struct ShutdownSignal {
    rx: watch::Receiver<bool>,
}

impl ShutdownSignal {
    /// Check if shutdown has been requested.
    pub fn is_shutdown(&self) -> bool {
        *self.rx.borrow()
    }

    /// Wait until shutdown is requested.
    pub async fn wait(&mut self) {
        // If already shut down, return immediately
        if *self.rx.borrow() {
            return;
        }
        // Wait for the value to change to true
        let _ = self.rx.changed().await;
    }
}

/// A cloneable, sendable handle that can trigger shutdown from any context.
///
/// Safe to move into spawned tasks (e.g. signal handlers) because it
/// holds an `Arc` to the underlying sender.
#[derive(Clone)]
pub struct ShutdownTrigger {
    tx: Arc<watch::Sender<bool>>,
}

impl ShutdownTrigger {
    /// Trigger shutdown, notifying all signal holders.
    pub fn shutdown(&self) {
        info!("shutdown triggered");
        let _ = self.tx.send(true);
    }
}

/// Controller that triggers shutdown.
pub struct ShutdownController {
    tx: Arc<watch::Sender<bool>>,
}

impl ShutdownController {
    /// Create a new shutdown controller and signal pair.
    pub fn new() -> (Self, ShutdownSignal) {
        let (tx, rx) = watch::channel(false);
        (Self { tx: Arc::new(tx) }, ShutdownSignal { rx })
    }

    /// Trigger shutdown, notifying all signal holders.
    pub fn shutdown(&self) {
        info!("shutdown signal sent");
        let _ = self.tx.send(true);
    }

    /// Get a new signal handle (for passing to modules).
    pub fn subscribe(&self) -> ShutdownSignal {
        ShutdownSignal {
            rx: self.tx.subscribe(),
        }
    }

    /// Get a cloneable trigger handle that can be moved into spawned tasks.
    pub fn trigger_handle(&self) -> ShutdownTrigger {
        ShutdownTrigger {
            tx: Arc::clone(&self.tx),
        }
    }
}

impl Default for ShutdownController {
    fn default() -> Self {
        Self::new().0
    }
}

/// Install platform-specific signal handlers that trigger shutdown.
///
/// On Unix: handles SIGTERM and SIGINT.
/// On Windows: handles Ctrl+C console event.
pub async fn install_signal_handlers(controller: &ShutdownController) {
    let trigger = controller.trigger_handle();

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");

        tokio::spawn(async move {
            tokio::select! {
                _ = sigterm.recv() => {
                    info!("received SIGTERM");
                }
                _ = sigint.recv() => {
                    info!("received SIGINT");
                }
            }
            trigger.shutdown();
        });
    }

    #[cfg(windows)]
    {
        tokio::spawn(async move {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install Ctrl+C handler");
            info!("received Ctrl+C");
            trigger.shutdown();
        });
    }
}
