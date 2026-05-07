//! Keepalive loop for maintaining server connection state.
//!
//! Sends periodic heartbeat messages to the Wazuh server to indicate
//! the agent is still alive and connected.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::connection::ConnectionManager;
use crate::protocol::WazuhMessage;

/// Run a keepalive loop that periodically sends heartbeat messages.
///
/// The loop uses `tokio::select!` to race between the keepalive timer
/// and the shutdown signal. On timer tick it sends a keepalive message
/// via the connection manager. On shutdown it breaks cleanly.
pub async fn run_keepalive_loop(
    conn: Arc<Mutex<ConnectionManager>>,
    agent_id: String,
    interval: Duration,
    mut shutdown: sda_core::ShutdownSignal,
) {
    info!(
        interval_secs = interval.as_secs(),
        "starting keepalive loop"
    );

    let mut ticker = tokio::time::interval(interval);
    // The first tick fires immediately; consume it so we don't send
    // a keepalive right at startup (the startup message covers that).
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let msg = WazuhMessage::keepalive(&agent_id);
                let mut guard = conn.lock().await;
                match guard.send(&msg).await {
                    Ok(()) => {
                        debug!(agent_id = %agent_id, "keepalive sent");
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to send keepalive");
                    }
                }
            }
            _ = shutdown.wait() => {
                info!("keepalive loop shutting down");
                break;
            }
        }
    }
}
