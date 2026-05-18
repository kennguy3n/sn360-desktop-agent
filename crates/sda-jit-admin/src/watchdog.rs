//! Revocation watchdog (Phase 3.3).
//!
//! See `docs/device-control.md` § 7 (Just-in-Time admin) — revocation triggers:
//!
//! 1. **Timer expiry** — a Tokio sleep until `grant.until`.
//! 2. **Heartbeat loss** — if the control plane has not been heard
//!    from for `heartbeat_loss_secs`, every active grant is
//!    revoked.
//! 3. **Power transition** — suspend / sleep / lock both revoke
//!    immediately (Phase 3 MVP only handles transitions delivered
//!    through [`PowerEvent`]; deeper OS-event subscription lands in
//!    Phase 4).
//! 4. **Boot-time idempotent revoke** — on agent startup, every
//!    grant whose `until` is already in the past is force-revoked.
//!
//! The watchdog is intentionally pure async — it owns no `tokio::spawn`
//! itself. The supervisor in [`crate::module::JitAdminModule`] drives
//! the loop so the cancellation behaviour matches the rest of the
//! agent's modules.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Why a grant was revoked.
///
/// Persisted into [`GrantRecord::last_reason`](crate::grant::GrantRecord)
/// so the audit trail can answer "who pulled the trigger" without
/// parsing free-form strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// `grant.until` was reached.
    Timer,
    /// Operator / control-plane explicit revoke.
    Operator,
    /// No heartbeat from the control plane within the configured
    /// window.
    HeartbeatLoss,
    /// Device went to sleep / suspended.
    PowerSuspend,
    /// Device went to a low-power state (e.g. battery saver).
    PowerSaver,
    /// User logged out of the elevated session.
    Logout,
    /// Boot-time sweep — grant was already past expiry on startup.
    BootSweep,
    /// Drift detection found unauthorised admin accounts.
    Drift,
}

impl RevocationReason {
    /// Lower-snake-case label suitable for evidence payloads / logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timer => "timer",
            Self::Operator => "operator",
            Self::HeartbeatLoss => "heartbeat_loss",
            Self::PowerSuspend => "power_suspend",
            Self::PowerSaver => "power_saver",
            Self::Logout => "logout",
            Self::BootSweep => "boot_sweep",
            Self::Drift => "drift",
        }
    }
}

/// Configuration knobs for the watchdog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchdogConfig {
    /// Revoke active grants when no heartbeat has been observed for
    /// this many seconds. Mirrors
    /// [`sda_core::config::JitAdminConfig::heartbeat_loss_secs`]
    /// (default 120 s).
    pub heartbeat_loss_secs: u64,
    /// How often the heartbeat watchdog wakes up to check whether
    /// the deadline has been crossed. Defaults to
    /// `heartbeat_loss_secs / 4` so a 120-second budget is sampled
    /// every 30 seconds (worst-case lateness 30 s).
    pub heartbeat_poll_secs: u64,
}

impl WatchdogConfig {
    /// Construct a config from the per-module
    /// [`sda_core::config::JitAdminConfig::heartbeat_loss_secs`]
    /// value. Bumps a zero-second budget to 1 s to keep test
    /// stability.
    pub fn from_secs(heartbeat_loss_secs: u64) -> Self {
        let bounded = heartbeat_loss_secs.max(1);
        let poll = (bounded / 4).max(1);
        Self {
            heartbeat_loss_secs: bounded,
            heartbeat_poll_secs: poll,
        }
    }

    /// Heartbeat loss budget as a [`Duration`].
    pub fn heartbeat_loss(&self) -> Duration {
        Duration::from_secs(self.heartbeat_loss_secs)
    }

    /// Heartbeat poll cadence as a [`Duration`].
    pub fn heartbeat_poll(&self) -> Duration {
        Duration::from_secs(self.heartbeat_poll_secs)
    }
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self::from_secs(120)
    }
}

/// One revocation request the watchdog wants the supervisor to
/// execute. The supervisor maps the reason onto a
/// [`StateTransition::Revoke`](crate::state_machine::StateTransition::Revoke)
/// and feeds it through the state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationRequest {
    /// The grant id whose underlying privilege should be dropped.
    pub grant_id: String,
    /// Why the watchdog is asking for the revoke.
    pub reason: RevocationReason,
}

/// Pure-logic helpers used by the supervisor's watchdog tick. The
/// real timers live in [`crate::module::JitAdminModule`].
#[derive(Debug, Default, Clone)]
pub struct RevocationWatchdog;

impl RevocationWatchdog {
    /// Return one revocation request per record that is past its
    /// `until` boundary or whose lifecycle has aged out.
    ///
    /// `now` is taken as a parameter so the policy is testable
    /// without `tokio::time::pause` / `Utc::now()` indirection.
    pub fn timer_revocations<'a>(
        &self,
        records: impl IntoIterator<Item = &'a crate::grant::GrantRecord>,
        now: DateTime<Utc>,
    ) -> Vec<RevocationRequest> {
        records
            .into_iter()
            .filter(|r| r.is_overdue(now))
            .map(|r| RevocationRequest {
                grant_id: r.id.clone(),
                reason: RevocationReason::Timer,
            })
            .collect()
    }

    /// Return one revocation request per active grant when the last
    /// heartbeat from the control plane is older than
    /// `cfg.heartbeat_loss_secs`.
    ///
    /// `last_heartbeat` is `None` until the agent receives its first
    /// heartbeat after startup; the watchdog treats that as
    /// "deadline not crossed yet" so the agent does not auto-revoke
    /// before the control plane has a chance to ping it.
    pub fn heartbeat_revocations<'a>(
        &self,
        records: impl IntoIterator<Item = &'a crate::grant::GrantRecord>,
        last_heartbeat: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
        cfg: &WatchdogConfig,
    ) -> Vec<RevocationRequest> {
        let Some(last) = last_heartbeat else {
            return Vec::new();
        };
        let elapsed = now - last;
        if elapsed.num_seconds() < cfg.heartbeat_loss_secs as i64 {
            return Vec::new();
        }
        records
            .into_iter()
            .filter(|r| r.state.is_active())
            .map(|r| RevocationRequest {
                grant_id: r.id.clone(),
                reason: RevocationReason::HeartbeatLoss,
            })
            .collect()
    }

    /// Return one revocation request per active grant when a
    /// power-state transition demands it.
    pub fn power_revocations<'a>(
        &self,
        records: impl IntoIterator<Item = &'a crate::grant::GrantRecord>,
        reason: RevocationReason,
    ) -> Vec<RevocationRequest> {
        debug_assert!(matches!(
            reason,
            RevocationReason::PowerSuspend
                | RevocationReason::PowerSaver
                | RevocationReason::Logout
        ));
        records
            .into_iter()
            .filter(|r| r.state.is_active())
            .map(|r| RevocationRequest {
                grant_id: r.id.clone(),
                reason,
            })
            .collect()
    }

    /// Boot-time idempotent sweep — revoke every grant whose
    /// `until` is already in the past, regardless of state. Active
    /// grants get [`RevocationReason::BootSweep`]; non-active
    /// records still in `Requested` / `Approved` are reported with
    /// `BootSweep` so the supervisor can finalise them via the
    /// [`StateTransition::Expire`](crate::state_machine::StateTransition::Expire)
    /// or `Deny` paths.
    pub fn boot_sweep<'a>(
        &self,
        records: impl IntoIterator<Item = &'a crate::grant::GrantRecord>,
        now: DateTime<Utc>,
    ) -> Vec<RevocationRequest> {
        records
            .into_iter()
            .filter(|r| !r.state.is_terminal() && now >= r.until)
            .map(|r| RevocationRequest {
                grant_id: r.id.clone(),
                reason: RevocationReason::BootSweep,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::{GrantRecord, GrantState};
    use sda_pal::admin_manager::UserRef;

    fn user(name: &str) -> UserRef {
        UserRef {
            username: name.into(),
            domain: None,
        }
    }

    fn record(id: &str, state: GrantState, until: DateTime<Utc>) -> GrantRecord {
        let now = Utc::now();
        let mut r = GrantRecord::new_requested(id, "ops", user("alice"), until, now);
        r.state = state;
        r
    }

    #[test]
    fn watchdog_config_clamps_zero_to_one_and_polls_quarter() {
        let cfg = WatchdogConfig::from_secs(0);
        assert_eq!(cfg.heartbeat_loss_secs, 1);
        assert_eq!(cfg.heartbeat_poll_secs, 1);

        let cfg = WatchdogConfig::from_secs(120);
        assert_eq!(cfg.heartbeat_loss_secs, 120);
        assert_eq!(cfg.heartbeat_poll_secs, 30);
    }

    #[test]
    fn timer_revocations_picks_only_overdue_active_grants() {
        let now = Utc::now();
        let active_due = record(
            "g-1",
            GrantState::Granted,
            now - chrono::Duration::seconds(1),
        );
        let active_future = record("g-2", GrantState::Granted, now + chrono::Duration::hours(1));
        let approved_due = record(
            "g-3",
            GrantState::Approved,
            now - chrono::Duration::hours(1),
        );
        let revoked = record("g-4", GrantState::Revoked, now - chrono::Duration::hours(1));

        let wd = RevocationWatchdog;
        let reqs =
            wd.timer_revocations([&active_due, &active_future, &approved_due, &revoked], now);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].grant_id, "g-1");
        assert_eq!(reqs[0].reason, RevocationReason::Timer);
    }

    #[test]
    fn heartbeat_revocations_quiet_until_deadline_crossed() {
        let now = Utc::now();
        let r = record("g-1", GrantState::Granted, now + chrono::Duration::hours(1));
        let cfg = WatchdogConfig::from_secs(120);
        let wd = RevocationWatchdog;

        // No heartbeat yet → no revocations.
        assert!(wd.heartbeat_revocations([&r], None, now, &cfg).is_empty());

        // Last heartbeat 30 s ago → still inside the budget.
        let last = now - chrono::Duration::seconds(30);
        assert!(wd
            .heartbeat_revocations([&r], Some(last), now, &cfg)
            .is_empty());

        // Last heartbeat 200 s ago → over budget.
        let last = now - chrono::Duration::seconds(200);
        let reqs = wd.heartbeat_revocations([&r], Some(last), now, &cfg);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].reason, RevocationReason::HeartbeatLoss);
    }

    #[test]
    fn heartbeat_revocations_only_pick_active() {
        let now = Utc::now();
        let active = record("g-1", GrantState::Granted, now + chrono::Duration::hours(1));
        let approved = record(
            "g-2",
            GrantState::Approved,
            now + chrono::Duration::hours(1),
        );
        let cfg = WatchdogConfig::from_secs(60);
        let last = now - chrono::Duration::seconds(120);
        let wd = RevocationWatchdog;
        let reqs = wd.heartbeat_revocations([&active, &approved], Some(last), now, &cfg);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].grant_id, "g-1");
    }

    #[test]
    fn power_revocations_target_active_grants() {
        let now = Utc::now();
        let active = record("g-1", GrantState::Granted, now + chrono::Duration::hours(1));
        let revoked = record("g-2", GrantState::Revoked, now - chrono::Duration::hours(1));
        let wd = RevocationWatchdog;
        let reqs = wd.power_revocations([&active, &revoked], RevocationReason::PowerSuspend);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].grant_id, "g-1");
        assert_eq!(reqs[0].reason, RevocationReason::PowerSuspend);
    }

    #[test]
    fn boot_sweep_targets_overdue_non_terminal_records() {
        let now = Utc::now();
        let active_old = record("g-1", GrantState::Granted, now - chrono::Duration::hours(2));
        let approved_old = record(
            "g-2",
            GrantState::Approved,
            now - chrono::Duration::hours(2),
        );
        let active_future = record("g-3", GrantState::Granted, now + chrono::Duration::hours(1));
        let revoked_old = record("g-4", GrantState::Revoked, now - chrono::Duration::hours(2));
        let wd = RevocationWatchdog;
        let reqs = wd.boot_sweep(
            [&active_old, &approved_old, &active_future, &revoked_old],
            now,
        );
        let ids: Vec<_> = reqs.iter().map(|r| r.grant_id.clone()).collect();
        assert!(ids.contains(&"g-1".to_string()));
        assert!(ids.contains(&"g-2".to_string()));
        assert!(!ids.contains(&"g-3".to_string()));
        assert!(!ids.contains(&"g-4".to_string()));
        for r in &reqs {
            assert_eq!(r.reason, RevocationReason::BootSweep);
        }
    }
}
