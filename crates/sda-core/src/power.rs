//! Shared power-profile broadcast channel.
//!
//! A single [`tokio::sync::watch`] channel carries the current
//! [`PowerProfile`] to every module that wants to adapt its scheduling
//! (scan interval, batch flush, pause behavior) based on the host's
//! power state and user idle status.
//!
//! The agent main loop owns the [`PowerProfileSender`] and spawns a
//! periodic poll task via [`spawn_power_profile_task`]. Each module
//! receives a clone of the [`PowerProfileReceiver`] at startup and
//! reads [`PowerProfile`] values via [`watch::Receiver::borrow`] at
//! the top of every scan/scheduling tick.

use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info};

pub use sda_pal::power::{PowerMonitor, PowerProfile};

use crate::signal::ShutdownSignal;

/// Sender handle for broadcasting power-profile changes.
pub type PowerProfileSender = watch::Sender<PowerProfile>;

/// Receiver handle for observing power-profile changes.
pub type PowerProfileReceiver = watch::Receiver<PowerProfile>;

/// How often [`spawn_power_profile_task`] polls the system's power
/// state and re-classifies the active [`PowerProfile`].
pub const POWER_PROFILE_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Idle threshold passed to [`PowerMonitor::is_user_idle`] when
/// deriving the active profile. Ten minutes mirrors the "screen saver
/// is probably on" heuristic common to desktop operating systems.
pub const POWER_PROFILE_IDLE_THRESHOLD: Duration = Duration::from_secs(10 * 60);

/// Create a watch channel pre-populated with `profile`.
///
/// The agent main loop calls this before any module starts so that
/// receivers cloned by each module always observe a valid initial
/// profile (typically [`PowerProfile::Normal`] on a fresh boot).
pub fn channel(profile: PowerProfile) -> (PowerProfileSender, PowerProfileReceiver) {
    watch::channel(profile)
}

/// Spawn a background task that periodically classifies the current
/// power state via [`PowerProfile::detect`] and broadcasts the result
/// on `tx`.
///
/// The task exits when `shutdown` fires, when every receiver has been
/// dropped (so sends would fail), or when the task is aborted.
pub fn spawn_power_profile_task(
    tx: PowerProfileSender,
    mut shutdown: ShutdownSignal,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(POWER_PROFILE_POLL_INTERVAL);
        // Consume the immediate first tick — the channel is already
        // seeded with an initial profile at creation time and we want
        // the first classification to fire after one poll window.
        ticker.tick().await;

        loop {
            tokio::select! {
                biased;

                _ = shutdown.wait() => {
                    debug!("power-profile poll task received shutdown");
                    break;
                }

                _ = ticker.tick() => {
                    // PowerProfile::detect() reads sysfs on Linux and
                    // shells out to `loginctl` to derive user-idle
                    // time; on macOS/Windows it calls into IOKit /
                    // Win32. Run it on the blocking pool so the
                    // async runtime never waits on a syscall or a
                    // subprocess.
                    let current = *tx.borrow();
                    let new_profile = match tokio::task::spawn_blocking(|| {
                        let monitor = PowerMonitor::new();
                        PowerProfile::detect(&monitor, POWER_PROFILE_IDLE_THRESHOLD)
                    })
                    .await
                    {
                        Ok(p) => p,
                        Err(e) => {
                            debug!(error = %e, "power-profile detect task panicked or was cancelled; keeping current profile");
                            current
                        }
                    };
                    if new_profile != current {
                        info!(
                            previous = ?current,
                            current = ?new_profile,
                            "power profile changed"
                        );
                    }
                    if tx.send(new_profile).is_err() {
                        debug!("power-profile receiver dropped; stopping poll task");
                        break;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_seeds_initial_profile() {
        let (tx, rx) = channel(PowerProfile::Normal);
        assert_eq!(*rx.borrow(), PowerProfile::Normal);
        tx.send(PowerProfile::BatteryActive).unwrap();
        assert_eq!(*rx.borrow(), PowerProfile::BatteryActive);
    }

    #[tokio::test]
    async fn test_receivers_observe_sender_updates() {
        let (tx, mut rx) = channel(PowerProfile::Normal);
        let handle = tokio::spawn(async move {
            rx.changed().await.unwrap();
            *rx.borrow()
        });
        tx.send(PowerProfile::CriticalBattery).unwrap();
        let observed = handle.await.unwrap();
        assert_eq!(observed, PowerProfile::CriticalBattery);
    }
}
