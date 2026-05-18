//! Maintenance window + quiet-hours policy evaluator (Phase 2.8).
//!
//! Mirrors `docs/device-control.md` § 4 (Signed-job lifecycle) and
//! step 9 of the validation pipeline in
//! `docs/wire-protocols/device-control.md` § 7.4.
//!
//! # Semantics
//!
//! * The **maintenance window** is an *allow* list: a job is only
//!   permitted to execute *inside* the configured window. Jobs that
//!   arrive outside the window are deferred (queued for later)
//!   rather than refused outright.
//! * **Quiet hours** are a *deny* list: even inside the maintenance
//!   window, jobs that arrive during quiet hours are deferred to
//!   suppress interactive prompts and noisy work.
//! * Both windows live in *local* time (relative to the agent's
//!   configured IANA timezone). The caller passes a UTC `now` and
//!   the policy converts.
//!
//! # Day-of-week parsing
//!
//! The configuration accepts a list of day strings, each of which
//! may be either a single day (`mon`, `tue`, …) or a closed range
//! (`mon-fri`). Days are case-insensitive. An empty list disables
//! the maintenance window entirely.
//!
//! # Time-range parsing
//!
//! Times are `HH:MM` in 24-hour notation. The end-of-window time
//! is *inclusive*. Windows that wrap around midnight are supported
//! (e.g. `start = "22:00"`, `end = "07:00"`).

use chrono::{DateTime, Datelike, NaiveTime, Timelike, Utc, Weekday};
use chrono_tz::Tz;
use sda_core::config::{MaintenanceWindow, QuietHours};
use thiserror::Error;

/// Outcome of [`MaintenanceWindowPolicy::should_execute`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowDecision {
    /// The job may execute now.
    Execute,
    /// The job should be queued and re-evaluated later (outside the
    /// maintenance window or inside quiet hours).
    Defer,
    /// The job is permanently refused — currently only emitted when
    /// the maintenance window is configured but contains zero
    /// allowed days, which means *no* execution will ever be
    /// possible.
    Refuse,
}

/// Errors returned when constructing or parsing a window policy.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WindowError {
    /// Configuration referenced an IANA timezone the chrono-tz
    /// database does not know about (e.g. a typo).
    #[error("unknown timezone: {0}")]
    UnknownTimezone(String),
    /// A `HH:MM` literal failed to parse.
    #[error("invalid time literal `{0}`: expected HH:MM (24-hour)")]
    InvalidTime(String),
    /// A day-of-week token failed to parse.
    #[error("invalid day-of-week token `{0}`: expected mon..sun or a range like mon-fri")]
    InvalidDay(String),
}

/// Compiled maintenance window + quiet-hours policy.
#[derive(Debug, Clone)]
pub struct MaintenanceWindowPolicy {
    timezone: Tz,
    maintenance: Option<CompiledWindow>,
    quiet_hours: Option<CompiledWindow>,
}

#[derive(Debug, Clone)]
struct CompiledWindow {
    start: NaiveTime,
    end: NaiveTime,
    /// Days the window applies on. `None` for quiet hours (which
    /// apply every day).
    days: Option<Vec<Weekday>>,
}

impl CompiledWindow {
    fn contains(&self, weekday: Weekday, time: NaiveTime) -> bool {
        if let Some(days) = self.days.as_ref() {
            if !days.contains(&weekday) {
                // Wrap-around: a window that starts on Friday at 22:00
                // and ends on Saturday at 07:00 is still active during
                // the Saturday morning hours even though Saturday is
                // not in the `days` list, *if* the matching wrap
                // anchor falls on the previous day. We handle this by
                // also checking `weekday.pred()` for windows that
                // wrap past midnight.
                // End-of-window is *inclusive* (see module docs §
                // "Time-range parsing"). Use `<=` so a job arriving
                // exactly at `self.end` on the wrap day is admitted,
                // matching the non-wrap branch below and the
                // documented contract.
                if self.wraps_midnight() && days.contains(&weekday.pred()) && time <= self.end {
                    return true;
                }
                return false;
            }
        }
        if self.wraps_midnight() {
            // Same inclusive boundary on the post-midnight half of a
            // wrap window — see the comment in the `days` branch.
            time >= self.start || time <= self.end
        } else {
            time >= self.start && time <= self.end
        }
    }

    fn wraps_midnight(&self) -> bool {
        // Strict `<` so that a degenerate `start == end` config falls
        // through to the non-wrap branch in [`CompiledWindow::contains`]
        // and matches *only* that exact minute. With `<=` the predicate
        // would hold for `start == end`, the non-wrap branch would
        // never run, and `time >= start || time <= end` would evaluate
        // to `true` for every clock value — silently turning a
        // single-minute window into a 24-hour blanket allow.
        self.end < self.start
    }
}

impl MaintenanceWindowPolicy {
    /// Build a policy from raw [`MaintenanceWindow`] /
    /// [`QuietHours`] config blocks plus an IANA timezone string
    /// (e.g. `"America/Los_Angeles"`). Use `"UTC"` if the operator
    /// has not configured a timezone.
    pub fn from_config(
        maintenance: &MaintenanceWindow,
        quiet_hours: &QuietHours,
        timezone: &str,
    ) -> Result<Self, WindowError> {
        let tz: Tz = timezone
            .parse()
            .map_err(|_| WindowError::UnknownTimezone(timezone.to_string()))?;

        let maintenance = if maintenance.enabled {
            Some(CompiledWindow {
                start: parse_hhmm(&maintenance.start)?,
                end: parse_hhmm(&maintenance.end)?,
                days: Some(parse_days(&maintenance.days)?),
            })
        } else {
            None
        };

        let quiet_hours = if quiet_hours.enabled {
            Some(CompiledWindow {
                start: parse_hhmm(&quiet_hours.start)?,
                end: parse_hhmm(&quiet_hours.end)?,
                days: None,
            })
        } else {
            None
        };

        Ok(Self {
            timezone: tz,
            maintenance,
            quiet_hours,
        })
    }

    /// Convenience constructor for a policy that always permits
    /// execution. Used by tests and by Phase 1 deployments that have
    /// not yet enabled either window.
    pub fn always_open() -> Self {
        Self {
            timezone: Tz::UTC,
            maintenance: None,
            quiet_hours: None,
        }
    }

    /// Whether `now` falls inside the configured maintenance window
    /// (interpreted in the supplied IANA timezone). Returns `true`
    /// when no maintenance window is configured (= "always
    /// permitted").
    pub fn is_in_maintenance_window(&self, now: DateTime<Utc>, timezone: &str) -> bool {
        match self.maintenance.as_ref() {
            Some(window) => match resolve_tz(timezone) {
                Ok(tz) => {
                    let local = now.with_timezone(&tz);
                    window.contains(local.weekday(), local_naive_time(local))
                }
                Err(_) => false,
            },
            None => true,
        }
    }

    /// Whether `now` falls inside the configured quiet hours
    /// (interpreted in the supplied IANA timezone). Returns `false`
    /// when no quiet hours are configured.
    pub fn is_in_quiet_hours(&self, now: DateTime<Utc>, timezone: &str) -> bool {
        match self.quiet_hours.as_ref() {
            Some(window) => match resolve_tz(timezone) {
                Ok(tz) => {
                    let local = now.with_timezone(&tz);
                    window.contains(local.weekday(), local_naive_time(local))
                }
                Err(_) => false,
            },
            None => false,
        }
    }

    /// 10-step pipeline integration entry point.
    ///
    /// Decides what to do with a job that has otherwise passed every
    /// other validation step.
    pub fn should_execute(&self, now: DateTime<Utc>) -> WindowDecision {
        if let Some(window) = self.maintenance.as_ref() {
            if window.days.as_ref().is_some_and(|d| d.is_empty()) {
                // The window is enabled but contains zero days, so no
                // execution will ever be permissible. Refuse rather
                // than defer to avoid a queue that grows forever.
                return WindowDecision::Refuse;
            }
        }
        let local = now.with_timezone(&self.timezone);
        let weekday = local.weekday();
        let time = local_naive_time(local);

        if let Some(window) = self.maintenance.as_ref() {
            if !window.contains(weekday, time) {
                return WindowDecision::Defer;
            }
        }

        if let Some(window) = self.quiet_hours.as_ref() {
            if window.contains(weekday, time) {
                return WindowDecision::Defer;
            }
        }

        WindowDecision::Execute
    }

    /// Returns the IANA timezone this policy was compiled for.
    pub fn timezone(&self) -> Tz {
        self.timezone
    }
}

fn local_naive_time<Tz: chrono::TimeZone>(dt: DateTime<Tz>) -> NaiveTime {
    NaiveTime::from_hms_opt(dt.hour(), dt.minute(), dt.second())
        .unwrap_or_else(|| NaiveTime::from_hms_opt(0, 0, 0).expect("midnight is valid"))
}

fn resolve_tz(timezone: &str) -> Result<Tz, WindowError> {
    timezone
        .parse()
        .map_err(|_| WindowError::UnknownTimezone(timezone.to_string()))
}

/// Parse a `HH:MM` literal into a [`NaiveTime`].
pub fn parse_hhmm(raw: &str) -> Result<NaiveTime, WindowError> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 2 {
        return Err(WindowError::InvalidTime(raw.to_string()));
    }
    let hour: u32 = parts[0]
        .parse()
        .map_err(|_| WindowError::InvalidTime(raw.to_string()))?;
    let minute: u32 = parts[1]
        .parse()
        .map_err(|_| WindowError::InvalidTime(raw.to_string()))?;
    if hour > 23 || minute > 59 {
        return Err(WindowError::InvalidTime(raw.to_string()));
    }
    NaiveTime::from_hms_opt(hour, minute, 0)
        .ok_or_else(|| WindowError::InvalidTime(raw.to_string()))
}

/// Parse a list of day-of-week tokens (`mon`, `mon-fri`) into a
/// flat list of [`Weekday`] values. Duplicates are kept (the
/// `contains` check is a linear scan over a list ≤7 entries) so
/// callers can preserve order if they care.
pub fn parse_days(raw: &[String]) -> Result<Vec<Weekday>, WindowError> {
    let mut out = Vec::with_capacity(7);
    for token in raw {
        for day in parse_day_token(token)? {
            if !out.contains(&day) {
                out.push(day);
            }
        }
    }
    Ok(out)
}

fn parse_day_token(token: &str) -> Result<Vec<Weekday>, WindowError> {
    let token = token.trim().to_ascii_lowercase();
    if let Some((lo, hi)) = token.split_once('-') {
        let lo = parse_day_name(lo)?;
        let hi = parse_day_name(hi)?;
        Ok(weekday_range(lo, hi))
    } else {
        Ok(vec![parse_day_name(&token)?])
    }
}

fn parse_day_name(name: &str) -> Result<Weekday, WindowError> {
    match name.trim().to_ascii_lowercase().as_str() {
        "mon" | "monday" => Ok(Weekday::Mon),
        "tue" | "tuesday" => Ok(Weekday::Tue),
        "wed" | "wednesday" => Ok(Weekday::Wed),
        "thu" | "thursday" => Ok(Weekday::Thu),
        "fri" | "friday" => Ok(Weekday::Fri),
        "sat" | "saturday" => Ok(Weekday::Sat),
        "sun" | "sunday" => Ok(Weekday::Sun),
        _ => Err(WindowError::InvalidDay(name.to_string())),
    }
}

fn weekday_range(start: Weekday, end: Weekday) -> Vec<Weekday> {
    let mut out = Vec::with_capacity(7);
    let mut cur = start;
    loop {
        out.push(cur);
        if cur == end {
            break;
        }
        cur = cur.succ();
        if out.len() > 7 {
            // The range wrapped all the way around — bail out.
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(year: i32, month: u32, day: u32, hour: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, min, 0)
            .unwrap()
    }

    fn maintenance(start: &str, end: &str, days: Vec<&str>) -> MaintenanceWindow {
        MaintenanceWindow {
            enabled: true,
            start: start.into(),
            end: end.into(),
            days: days.into_iter().map(String::from).collect(),
        }
    }

    fn quiet(start: &str, end: &str) -> QuietHours {
        QuietHours {
            enabled: true,
            start: start.into(),
            end: end.into(),
        }
    }

    #[test]
    fn parse_hhmm_accepts_valid_inputs() {
        assert_eq!(
            parse_hhmm("00:00").unwrap(),
            NaiveTime::from_hms_opt(0, 0, 0).unwrap()
        );
        assert_eq!(
            parse_hhmm("23:59").unwrap(),
            NaiveTime::from_hms_opt(23, 59, 0).unwrap()
        );
    }

    #[test]
    fn parse_hhmm_rejects_invalid_inputs() {
        assert_eq!(
            parse_hhmm("24:00").unwrap_err(),
            WindowError::InvalidTime("24:00".into())
        );
        assert_eq!(
            parse_hhmm("12:60").unwrap_err(),
            WindowError::InvalidTime("12:60".into())
        );
        assert_eq!(
            parse_hhmm("12-30").unwrap_err(),
            WindowError::InvalidTime("12-30".into())
        );
        assert_eq!(
            parse_hhmm("not a time").unwrap_err(),
            WindowError::InvalidTime("not a time".into())
        );
    }

    #[test]
    fn parse_days_handles_singles() {
        let parsed = parse_days(&["mon".into(), "wed".into(), "fri".into()]).unwrap();
        assert_eq!(parsed, vec![Weekday::Mon, Weekday::Wed, Weekday::Fri]);
    }

    #[test]
    fn parse_days_expands_ranges() {
        let parsed = parse_days(&["mon-fri".into()]).unwrap();
        assert_eq!(
            parsed,
            vec![
                Weekday::Mon,
                Weekday::Tue,
                Weekday::Wed,
                Weekday::Thu,
                Weekday::Fri,
            ]
        );
    }

    #[test]
    fn parse_days_handles_full_week_aliases() {
        let parsed = parse_days(&["monday".into(), "sunday".into()]).unwrap();
        assert_eq!(parsed, vec![Weekday::Mon, Weekday::Sun]);
    }

    #[test]
    fn parse_days_dedupes_overlapping_tokens() {
        let parsed = parse_days(&["mon-wed".into(), "tue".into(), "wed".into()]).unwrap();
        assert_eq!(parsed, vec![Weekday::Mon, Weekday::Tue, Weekday::Wed]);
    }

    #[test]
    fn parse_days_rejects_garbage() {
        assert!(matches!(
            parse_days(&["mon-funday".into()]),
            Err(WindowError::InvalidDay(_))
        ));
        assert!(matches!(
            parse_days(&["xyz".into()]),
            Err(WindowError::InvalidDay(_))
        ));
    }

    #[test]
    fn maintenance_window_simple_in_window() {
        let p = MaintenanceWindowPolicy::from_config(
            &maintenance("02:00", "05:00", vec!["mon-fri"]),
            &QuietHours::default(),
            "UTC",
        )
        .unwrap();
        // 2026-05-04 is a Monday.
        assert!(p.is_in_maintenance_window(utc(2026, 5, 4, 3, 0), "UTC"));
        assert_eq!(
            p.should_execute(utc(2026, 5, 4, 3, 0)),
            WindowDecision::Execute
        );
    }

    #[test]
    fn maintenance_window_outside_window_defers() {
        let p = MaintenanceWindowPolicy::from_config(
            &maintenance("02:00", "05:00", vec!["mon-fri"]),
            &QuietHours::default(),
            "UTC",
        )
        .unwrap();
        // Same Monday but at noon — outside the 02:00–05:00 window.
        assert!(!p.is_in_maintenance_window(utc(2026, 5, 4, 12, 0), "UTC"));
        assert_eq!(
            p.should_execute(utc(2026, 5, 4, 12, 0)),
            WindowDecision::Defer
        );
    }

    #[test]
    fn maintenance_window_disallowed_day_defers() {
        let p = MaintenanceWindowPolicy::from_config(
            &maintenance("02:00", "05:00", vec!["mon-fri"]),
            &QuietHours::default(),
            "UTC",
        )
        .unwrap();
        // 2026-05-09 is a Saturday.
        assert!(!p.is_in_maintenance_window(utc(2026, 5, 9, 3, 0), "UTC"));
        assert_eq!(
            p.should_execute(utc(2026, 5, 9, 3, 0)),
            WindowDecision::Defer
        );
    }

    #[test]
    fn maintenance_window_wraps_past_midnight() {
        let p = MaintenanceWindowPolicy::from_config(
            // Friday 22:00 → Saturday 07:00.
            &maintenance("22:00", "07:00", vec!["fri"]),
            &QuietHours::default(),
            "UTC",
        )
        .unwrap();
        // Friday 23:00 — inside.
        assert!(p.is_in_maintenance_window(utc(2026, 5, 8, 23, 0), "UTC"));
        // Saturday 02:00 — also inside (wrap-around).
        assert!(p.is_in_maintenance_window(utc(2026, 5, 9, 2, 0), "UTC"));
        // Saturday 09:00 — outside.
        assert!(!p.is_in_maintenance_window(utc(2026, 5, 9, 9, 0), "UTC"));
    }

    /// End-of-window is documented as **inclusive** (see module-doc
    /// "Time-range parsing"). Exercise both the non-wrap and the
    /// wrap-around branches at the exact boundary minute to lock in
    /// that contract.
    #[test]
    fn maintenance_window_end_time_is_inclusive_on_both_branches() {
        // Non-wrap window: 02:00 → 05:00 inclusive.
        let non_wrap = MaintenanceWindowPolicy::from_config(
            &maintenance("02:00", "05:00", vec!["mon-sun"]),
            &QuietHours::default(),
            "UTC",
        )
        .unwrap();
        // 05:00 exactly is inside.
        assert!(non_wrap.is_in_maintenance_window(utc(2026, 5, 4, 5, 0), "UTC"));
        // 05:01 is outside.
        assert!(!non_wrap.is_in_maintenance_window(utc(2026, 5, 4, 5, 1), "UTC"));

        // Wrap window: Friday 22:00 → Saturday 07:00 inclusive on
        // both halves — exercises both the `wraps_midnight()` arm of
        // `contains` (Saturday morning, day not in `days`) and the
        // post-midnight half of the same arm when the day *is* in
        // `days`.
        let wrap = MaintenanceWindowPolicy::from_config(
            &maintenance("22:00", "07:00", vec!["fri"]),
            &QuietHours::default(),
            "UTC",
        )
        .unwrap();
        // Friday 22:00 exactly — inside (start boundary).
        assert!(wrap.is_in_maintenance_window(utc(2026, 5, 8, 22, 0), "UTC"));
        // Saturday 07:00 exactly — inside (end boundary, wrap arm).
        // Pre-fix this returned false because the wrap branch used
        // `time < self.end` instead of `<=`.
        assert!(
            wrap.is_in_maintenance_window(utc(2026, 5, 9, 7, 0), "UTC"),
            "07:00 on the wrap day must be inside the inclusive end-boundary",
        );
        // Saturday 07:01 — outside.
        assert!(!wrap.is_in_maintenance_window(utc(2026, 5, 9, 7, 1), "UTC"));
    }

    /// Regression guard for the `wraps_midnight()` strict-`<` fix.
    /// A `start == end` config used to evaluate as wrap-around with
    /// `time >= start || time <= end` — true for every clock value,
    /// silently turning a "single-minute" window into a 24-hour
    /// blanket allow. Strict `<` now puts the degenerate config in
    /// the non-wrap branch so it matches *only* the exact minute.
    #[test]
    fn maintenance_window_with_equal_start_and_end_matches_only_that_minute() {
        let p = MaintenanceWindowPolicy::from_config(
            &maintenance("05:00", "05:00", vec!["mon-sun"]),
            &QuietHours::default(),
            "UTC",
        )
        .unwrap();
        // Exactly 05:00 — the one minute the window admits.
        assert!(p.is_in_maintenance_window(utc(2026, 5, 4, 5, 0), "UTC"));
        // 04:59 — outside.
        assert!(!p.is_in_maintenance_window(utc(2026, 5, 4, 4, 59), "UTC"));
        // 05:01 — outside.
        assert!(!p.is_in_maintenance_window(utc(2026, 5, 4, 5, 1), "UTC"));
        // Mid-day — outside (pre-fix this returned true).
        assert!(!p.is_in_maintenance_window(utc(2026, 5, 4, 12, 0), "UTC"));
        // Midnight — outside (pre-fix this returned true).
        assert!(!p.is_in_maintenance_window(utc(2026, 5, 4, 0, 0), "UTC"));
    }

    #[test]
    fn quiet_hours_block_inside_maintenance() {
        let p = MaintenanceWindowPolicy::from_config(
            &maintenance("00:00", "23:59", vec!["mon-sun"]),
            &quiet("22:00", "07:00"),
            "UTC",
        )
        .unwrap();
        // 03:00 on a Monday — inside maintenance, inside quiet hours.
        assert!(p.is_in_maintenance_window(utc(2026, 5, 4, 3, 0), "UTC"));
        assert!(p.is_in_quiet_hours(utc(2026, 5, 4, 3, 0), "UTC"));
        assert_eq!(
            p.should_execute(utc(2026, 5, 4, 3, 0)),
            WindowDecision::Defer
        );
    }

    #[test]
    fn quiet_hours_disabled_means_never_active() {
        let p = MaintenanceWindowPolicy::from_config(
            &maintenance("00:00", "23:59", vec!["mon-sun"]),
            &QuietHours::default(),
            "UTC",
        )
        .unwrap();
        assert!(!p.is_in_quiet_hours(utc(2026, 5, 4, 3, 0), "UTC"));
    }

    #[test]
    fn timezone_aware_window_handles_offset() {
        // 02:00–05:00 local in America/Los_Angeles = 09:00–12:00 UTC
        // (PST, no DST). At 10:00 UTC on a Monday, LA local is 02:00
        // on the same Monday, so we expect "in window".
        let p = MaintenanceWindowPolicy::from_config(
            &maintenance("02:00", "05:00", vec!["mon-fri"]),
            &QuietHours::default(),
            "America/Los_Angeles",
        )
        .unwrap();
        assert!(p.is_in_maintenance_window(utc(2026, 1, 5, 10, 0), "America/Los_Angeles"));
        // 02:00 UTC = 18:00 prior-day local → outside.
        assert!(!p.is_in_maintenance_window(utc(2026, 1, 5, 2, 0), "America/Los_Angeles"));
    }

    #[test]
    fn unknown_timezone_is_a_construction_error() {
        let err = MaintenanceWindowPolicy::from_config(
            &maintenance("02:00", "05:00", vec!["mon-fri"]),
            &QuietHours::default(),
            "Mars/Olympus_Mons",
        )
        .unwrap_err();
        assert_eq!(
            err,
            WindowError::UnknownTimezone("Mars/Olympus_Mons".into())
        );
    }

    #[test]
    fn maintenance_with_zero_days_refuses() {
        let p = MaintenanceWindowPolicy::from_config(
            &maintenance("02:00", "05:00", vec![]),
            &QuietHours::default(),
            "UTC",
        )
        .unwrap();
        assert_eq!(
            p.should_execute(utc(2026, 5, 4, 3, 0)),
            WindowDecision::Refuse
        );
    }

    #[test]
    fn always_open_policy_executes() {
        let p = MaintenanceWindowPolicy::always_open();
        assert_eq!(
            p.should_execute(utc(2026, 5, 4, 3, 0)),
            WindowDecision::Execute
        );
        assert!(p.is_in_maintenance_window(utc(2026, 5, 4, 3, 0), "UTC"));
        assert!(!p.is_in_quiet_hours(utc(2026, 5, 4, 3, 0), "UTC"));
    }

    #[test]
    fn weekday_range_is_inclusive() {
        let r = weekday_range(Weekday::Mon, Weekday::Fri);
        assert_eq!(
            r,
            vec![
                Weekday::Mon,
                Weekday::Tue,
                Weekday::Wed,
                Weekday::Thu,
                Weekday::Fri,
            ]
        );
        // Self-range is just the single day.
        assert_eq!(
            weekday_range(Weekday::Wed, Weekday::Wed),
            vec![Weekday::Wed]
        );
    }
}
