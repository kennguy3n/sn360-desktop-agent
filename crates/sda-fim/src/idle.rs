//! Simple system idle detection for baseline scan scheduling.
//!
//! On Linux, checks `/proc/loadavg`.  On other platforms, always
//! returns `true` (idle) so scans proceed with throttling only.

use tracing::{debug, warn};

/// Default load-average threshold above which the system is considered busy.
const DEFAULT_LOAD_THRESHOLD: f64 = 2.0;

/// Check whether the system is currently idle enough to run a scan.
///
/// - **Linux**: reads `/proc/loadavg` and returns `true` if the 1-minute
///   load average is below `DEFAULT_LOAD_THRESHOLD`.
/// - **Other platforms**: always returns `true` (rely on per-file
///   throttling in the scanner instead).
pub fn is_system_idle() -> bool {
    is_system_idle_with_threshold(DEFAULT_LOAD_THRESHOLD)
}

/// Like [`is_system_idle`] but with a configurable threshold.
pub fn is_system_idle_with_threshold(threshold: f64) -> bool {
    #[cfg(target_os = "linux")]
    {
        match read_load_average() {
            Some(load) => {
                let idle = load < threshold;
                debug!(load_avg = load, threshold, idle, "idle check");
                idle
            }
            None => {
                warn!("could not read load average, assuming idle");
                true
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = threshold;
        debug!("idle detection not available on this platform, assuming idle");
        true
    }
}

/// Read the 1-minute load average from `/proc/loadavg`.
#[cfg(target_os = "linux")]
fn read_load_average() -> Option<f64> {
    let contents = std::fs::read_to_string("/proc/loadavg").ok()?;
    let first_field = contents.split_whitespace().next()?;
    first_field.parse::<f64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_system_idle_returns_bool() {
        // Just verify it runs without panicking.
        let _ = is_system_idle();
    }

    #[test]
    fn test_high_threshold_returns_idle() {
        // With a very high threshold, the system should always appear idle.
        assert!(is_system_idle_with_threshold(1000.0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_read_load_average() {
        let load = read_load_average();
        assert!(load.is_some(), "/proc/loadavg should be readable on Linux");
        assert!(load.unwrap() >= 0.0);
    }

    #[test]
    fn test_zero_threshold_returns_busy() {
        // With threshold 0.0, most systems will report busy.
        // On non-Linux this always returns true so skip the assertion.
        #[cfg(target_os = "linux")]
        {
            let idle = is_system_idle_with_threshold(0.0);
            // Load average is almost always > 0, so this should be false.
            assert!(!idle, "system should appear busy with threshold 0.0");
        }
    }
}
