//! Date / time utilities shared by every SDA crate.
//!
//! The agent deliberately does not depend on `chrono`: it pulls in
//! ~1 MB of code and a parser we don't need. Every event payload that
//! needs a human-readable timestamp is RFC 3339 in UTC with a `Z`
//! suffix, and we build that directly from
//! [`std::time::SystemTime`] via the civil-from-days algorithm
//! described in Howard Hinnant's "chrono-Compatible Low-Level Date
//! Algorithms" (public domain).
//!
//! ## Why a single shared implementation
//!
//! There used to be two hand-rolled `civil_from_unix_secs`
//! implementations in the workspace — one in `sda-memory-scanner`
//! (correct for negative seconds via `div_euclid`/`rem_euclid`) and
//! one in `sda-identity-monitor` (slightly wrong: `secs / 86_400`
//! and `secs % 86_400` round toward zero in the rare negative-secs
//! path, and `year as u32` would wrap for negative years).
//! Both crates now call into this module so the algorithm exists
//! exactly once.
//!
//! Negative seconds aren't reachable from `SystemTime::now()` on a
//! sane clock, but the API still takes `i64` and handles them
//! correctly — the alternative would be a silent overflow that
//! depends on what callers do with the input.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Convert a Unix timestamp (seconds since 1970-01-01T00:00:00Z) into
/// a civil date/time tuple `(year, month, day, hour, minute, second)`
/// in UTC. Correct for negative seconds.
pub fn civil_from_unix_secs(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let day = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400) as u32;
    let hour = tod / 3600;
    let minute = (tod % 3600) / 60;
    let second = tod % 60;
    let z = day + 719_468;
    // Parentheses around the `if-else` are semantically redundant
    // (the `let` binding context already parses the conditional as a
    // single expression before the `/`), but make the operator
    // precedence unambiguous at a glance.
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i32 + (era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day_of_month = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    (year, month, day_of_month, hour, minute, second)
}

/// Format a [`SystemTime`] as an RFC 3339 UTC string with second
/// resolution (`YYYY-MM-DDTHH:MM:SSZ`). Times before the Unix epoch
/// return the epoch.
pub fn format_rfc3339_utc(at: SystemTime) -> String {
    let dur = at.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let (y, mo, d, h, mi, s) = civil_from_unix_secs(dur.as_secs() as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Format a [`SystemTime`] as an RFC 3339 UTC string with millisecond
/// resolution (`YYYY-MM-DDTHH:MM:SS.mmmZ`). Times before the Unix
/// epoch return the epoch.
pub fn format_rfc3339_utc_millis(at: SystemTime) -> String {
    let dur = at.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let (y, mo, d, h, mi, s) = civil_from_unix_secs(dur.as_secs() as i64);
    let millis = dur.subsec_millis();
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epoch_is_1970_01_01_midnight() {
        assert_eq!(civil_from_unix_secs(0), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn known_timestamp_2024_03_15_round_trips() {
        // 2024-03-15T12:34:56Z = 1710506096 (verified via
        // `date -u -d "2024-03-15T12:34:56Z" +%s`).
        assert_eq!(
            civil_from_unix_secs(1_710_506_096),
            (2024, 3, 15, 12, 34, 56)
        );
    }

    #[test]
    fn leap_day_2024_02_29_is_recognised() {
        // 2024-02-29T00:00:00Z = 1709164800.
        assert_eq!(civil_from_unix_secs(1_709_164_800), (2024, 2, 29, 0, 0, 0));
    }

    #[test]
    fn negative_seconds_yield_pre_epoch_dates() {
        // 1969-12-31T23:59:59Z = -1.
        assert_eq!(civil_from_unix_secs(-1), (1969, 12, 31, 23, 59, 59));
        // 1900-01-01T00:00:00Z = -2208988800.
        assert_eq!(civil_from_unix_secs(-2_208_988_800), (1900, 1, 1, 0, 0, 0));
    }

    #[test]
    fn format_rfc3339_utc_handles_epoch() {
        assert_eq!(format_rfc3339_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_rfc3339_utc_millis_zero_pads_subsecond() {
        let at = UNIX_EPOCH + Duration::from_millis(7);
        assert_eq!(format_rfc3339_utc_millis(at), "1970-01-01T00:00:00.007Z");
    }

    #[test]
    fn format_rfc3339_utc_returns_z_suffix() {
        let at = UNIX_EPOCH + Duration::from_secs(1_710_506_096);
        assert_eq!(format_rfc3339_utc(at), "2024-03-15T12:34:56Z");
    }
}
