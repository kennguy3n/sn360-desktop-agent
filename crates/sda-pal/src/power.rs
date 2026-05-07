//! Cross-platform power and idle status detection.

use crate::types::PowerState;
use std::time::Duration;

/// Power and idle status provider.
///
/// Detects battery state and user idle time to enable adaptive scheduling.
pub struct PowerMonitor;

impl PowerMonitor {
    pub fn new() -> Self {
        Self
    }

    /// Get the current power state (AC or battery).
    pub fn power_state(&self) -> PowerState {
        #[cfg(target_os = "linux")]
        {
            linux_power_state()
        }
        #[cfg(target_os = "macos")]
        {
            macos::power_state()
        }
        #[cfg(target_os = "windows")]
        {
            windows_imp::power_state()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            PowerState::Unknown
        }
    }

    /// Get the battery charge percentage, if available.
    pub fn battery_percentage(&self) -> Option<u8> {
        #[cfg(target_os = "linux")]
        {
            linux_battery_percentage()
        }
        #[cfg(target_os = "macos")]
        {
            macos::battery_percentage()
        }
        #[cfg(target_os = "windows")]
        {
            windows_imp::battery_percentage()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            None
        }
    }

    /// Check whether the user appears to be idle.
    pub fn is_user_idle(&self, idle_threshold: Duration) -> bool {
        self.user_idle_duration()
            .map(|d| d >= idle_threshold)
            .unwrap_or(false)
    }

    /// Get the user idle duration, if detectable.
    pub fn user_idle_duration(&self) -> Option<Duration> {
        #[cfg(target_os = "macos")]
        {
            return macos::user_idle_duration();
        }
        #[cfg(target_os = "windows")]
        {
            return windows_imp::user_idle_duration();
        }
        #[cfg(target_os = "linux")]
        {
            linux_user_idle_duration()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            None
        }
    }
}

impl Default for PowerMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
fn linux_power_state() -> PowerState {
    // Read /sys/class/power_supply/*/online or /sys/class/power_supply/*/status
    let ac_path = std::path::Path::new("/sys/class/power_supply/AC/online");
    if let Ok(contents) = std::fs::read_to_string(ac_path) {
        return match contents.trim() {
            "1" => PowerState::AC,
            "0" => PowerState::Battery,
            _ => PowerState::Unknown,
        };
    }

    // Try alternative paths
    if let Ok(entries) = std::fs::read_dir("/sys/class/power_supply/") {
        for entry in entries.flatten() {
            let online_path = entry.path().join("online");
            if let Ok(contents) = std::fs::read_to_string(&online_path) {
                match contents.trim() {
                    "1" => return PowerState::AC,
                    "0" => return PowerState::Battery,
                    _ => continue,
                }
            }
        }
    }

    PowerState::Unknown
}

#[cfg(target_os = "linux")]
fn linux_battery_percentage() -> Option<u8> {
    if let Ok(entries) = std::fs::read_dir("/sys/class/power_supply/") {
        for entry in entries.flatten() {
            let capacity_path = entry.path().join("capacity");
            if let Ok(contents) = std::fs::read_to_string(&capacity_path) {
                if let Ok(pct) = contents.trim().parse::<u8>() {
                    return Some(pct);
                }
            }
        }
    }
    None
}

/// Linux user-idle detection.
///
/// Queries `logind` via the standard `loginctl show-session self
/// --property=IdleSinceHint --value` command and interprets the
/// returned microseconds-since-UNIX-epoch timestamp. Returns:
///
/// * `Some(Duration::ZERO)` when logind reports the session as not
///   idle (`IdleSinceHint == 0`).
/// * `Some(elapsed)` when the session has been idle for `elapsed`.
/// * `None` when `loginctl` is missing, the current process has no
///   logind session (headless systems, non-systemd hosts, or inside
///   containers without `/run/systemd/sessions`), or the output
///   cannot be parsed.
///
/// This keeps adaptive scheduling correct on all mainstream systemd
/// distributions without adding a D-Bus dependency. Hosts without
/// logind fall through to `None`, which preserves the pre-existing
/// behaviour (`PowerProfile::IdleAC` / `BatteryIdle` not entered).
#[cfg(target_os = "linux")]
fn linux_user_idle_duration() -> Option<Duration> {
    let output = std::process::Command::new("loginctl")
        .args([
            "show-session",
            "self",
            "--property=IdleSinceHint",
            "--value",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = std::str::from_utf8(&output.stdout).ok()?;
    let now_usec = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    parse_idle_since_hint(raw, now_usec)
}

/// Parse the raw `IdleSinceHint` value returned by `loginctl` into
/// an idle [`Duration`].
///
/// Pure function split out so unit tests can exercise the full
/// matrix (not idle / idle / clock skew / garbage input) without
/// needing logind on the host.
#[cfg(target_os = "linux")]
fn parse_idle_since_hint(raw: &str, now_usec: u128) -> Option<Duration> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let idle_since_usec: u64 = trimmed.parse().ok()?;
    if idle_since_usec == 0 {
        // logind convention: 0 means "not currently idle".
        return Some(Duration::ZERO);
    }
    let idle_since = idle_since_usec as u128;
    if idle_since > now_usec {
        // Clock skew; don't fabricate a negative duration.
        return None;
    }
    let elapsed_usec = now_usec - idle_since;
    u64::try_from(elapsed_usec).ok().map(Duration::from_micros)
}

#[cfg(target_os = "macos")]
mod macos {
    use super::PowerState;
    use core_foundation::array::{CFArray, CFArrayRef};
    use core_foundation::base::{CFType, CFTypeRef, TCFType};
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use std::time::Duration;

    // IOKit Power Sources keys (see IOPSKeys.h).
    const K_IOPS_POWER_SOURCE_STATE_KEY: &str = "Power Source State";
    const K_IOPS_CURRENT_CAPACITY_KEY: &str = "Current Capacity";
    const K_IOPS_AC_POWER_VALUE: &str = "AC Power";
    const K_IOPS_BATTERY_POWER_VALUE: &str = "Battery Power";

    // CGEventSource state IDs and types (see CGEventSource.h / CGEventTypes.h).
    // `kCGEventSourceStateCombinedSessionState == 0` aggregates events across
    // the HID and session sources, matching what the user sees.
    const K_CG_EVENT_SOURCE_STATE_COMBINED: i32 = 0;
    // `kCGAnyInputEventType` is `(CGEventType)(~0)`; CGEventType is u32.
    const K_CG_ANY_INPUT_EVENT_TYPE: u32 = !0u32;

    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        fn IOPSCopyPowerSourcesInfo() -> CFTypeRef;
        fn IOPSCopyPowerSourcesList(blob: CFTypeRef) -> CFArrayRef;
        fn IOPSGetPowerSourceDescription(blob: CFTypeRef, ps: CFTypeRef) -> CFDictionaryRef;
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGEventSourceSecondsSinceLastEventType(state_id: i32, event_type: u32) -> f64;
    }

    /// Iterate power sources and apply `f` to each description dictionary.
    /// Returns the first `Some` value produced by `f`.
    fn with_power_sources<T>(
        mut f: impl FnMut(&CFDictionary<CFString, CFType>) -> Option<T>,
    ) -> Option<T> {
        // SAFETY: `IOPSCopyPowerSourcesInfo` / `IOPSCopyPowerSourcesList`
        // return retained CF objects that we own; `CFType::wrap_under_create_rule`
        // takes ownership and releases on drop.
        unsafe {
            let blob_ref = IOPSCopyPowerSourcesInfo();
            if blob_ref.is_null() {
                return None;
            }
            let blob = CFType::wrap_under_create_rule(blob_ref);

            let list_ref = IOPSCopyPowerSourcesList(blob.as_concrete_TypeRef());
            if list_ref.is_null() {
                return None;
            }
            let list: CFArray<CFType> = CFArray::wrap_under_create_rule(list_ref);

            for ps in list.iter() {
                let desc_ref =
                    IOPSGetPowerSourceDescription(blob.as_concrete_TypeRef(), ps.as_CFTypeRef());
                if desc_ref.is_null() {
                    continue;
                }
                // IOPSGetPowerSourceDescription follows the "get" rule: the
                // returned dictionary is owned by `blob` and must not be
                // released by us.
                let desc: CFDictionary<CFString, CFType> =
                    CFDictionary::wrap_under_get_rule(desc_ref);
                if let Some(value) = f(&desc) {
                    return Some(value);
                }
            }
            None
        }
    }

    fn dict_string(dict: &CFDictionary<CFString, CFType>, key: &str) -> Option<String> {
        let key = CFString::new(key);
        let value = dict.find(&key)?;
        let s = value.downcast::<CFString>()?;
        Some(s.to_string())
    }

    fn dict_i64(dict: &CFDictionary<CFString, CFType>, key: &str) -> Option<i64> {
        let key = CFString::new(key);
        let value = dict.find(&key)?;
        let num = value.downcast::<CFNumber>()?;
        num.to_i64()
    }

    pub fn power_state() -> PowerState {
        with_power_sources(|desc| {
            let state = dict_string(desc, K_IOPS_POWER_SOURCE_STATE_KEY)?;
            if state == K_IOPS_AC_POWER_VALUE {
                Some(PowerState::AC)
            } else if state == K_IOPS_BATTERY_POWER_VALUE {
                Some(PowerState::Battery)
            } else {
                None
            }
        })
        .unwrap_or(PowerState::Unknown)
    }

    pub fn battery_percentage() -> Option<u8> {
        with_power_sources(|desc| {
            let pct = dict_i64(desc, K_IOPS_CURRENT_CAPACITY_KEY)?;
            if (0..=100).contains(&pct) {
                Some(pct as u8)
            } else {
                None
            }
        })
    }

    pub fn user_idle_duration() -> Option<Duration> {
        // SAFETY: `CGEventSourceSecondsSinceLastEventType` has no preconditions
        // beyond the framework being linked.
        let seconds = unsafe {
            CGEventSourceSecondsSinceLastEventType(
                K_CG_EVENT_SOURCE_STATE_COMBINED,
                K_CG_ANY_INPUT_EVENT_TYPE,
            )
        };
        if seconds.is_finite() && seconds >= 0.0 {
            Some(Duration::from_secs_f64(seconds))
        } else {
            None
        }
    }
}

#[cfg(target_os = "windows")]
mod windows_imp {
    use super::PowerState;
    use std::time::Duration;
    use windows::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
    use windows::Win32::System::SystemInformation::GetTickCount;
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

    fn system_power_status() -> Option<SYSTEM_POWER_STATUS> {
        let mut status = SYSTEM_POWER_STATUS::default();
        // SAFETY: `status` is a valid writable `SYSTEM_POWER_STATUS`.
        unsafe { GetSystemPowerStatus(&mut status) }.ok()?;
        Some(status)
    }

    pub fn power_state() -> PowerState {
        match system_power_status() {
            Some(status) => match status.ACLineStatus {
                1 => PowerState::AC,
                0 => PowerState::Battery,
                _ => PowerState::Unknown,
            },
            None => PowerState::Unknown,
        }
    }

    pub fn battery_percentage() -> Option<u8> {
        let status = system_power_status()?;
        // 255 is the documented "status unknown" sentinel.
        if status.BatteryLifePercent == 255 {
            None
        } else {
            Some(status.BatteryLifePercent)
        }
    }

    pub fn user_idle_duration() -> Option<Duration> {
        let mut info = LASTINPUTINFO {
            cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        // SAFETY: `info.cbSize` is initialised and `info` is writable.
        let ok = unsafe { GetLastInputInfo(&mut info) };
        if !ok.as_bool() {
            return None;
        }
        // SAFETY: `GetTickCount` has no preconditions.
        let now = unsafe { GetTickCount() };
        // `GetTickCount` and `dwTime` are millisecond counters that wrap
        // every ~49.7 days; `wrapping_sub` yields the correct elapsed
        // delta across a wrap.
        let elapsed_ms = now.wrapping_sub(info.dwTime);
        Some(Duration::from_millis(elapsed_ms as u64))
    }
}

/// Power profile that determines agent behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerProfile {
    /// AC power, user active: normal operation.
    Normal,
    /// AC power, user idle: run deferred scans.
    IdleAC,
    /// Battery, user active: minimal scans, larger batches.
    BatteryActive,
    /// Battery, user idle: reduced scans, extended intervals.
    BatteryIdle,
    /// Critical battery (<10%): essential only.
    CriticalBattery,
}

impl PowerProfile {
    /// Determine the current power profile from system state.
    pub fn detect(monitor: &PowerMonitor, idle_threshold: Duration) -> Self {
        let power = monitor.power_state();
        let is_idle = monitor.is_user_idle(idle_threshold);
        let battery_pct = monitor.battery_percentage();

        Self::from_inputs(power, is_idle, battery_pct)
    }

    /// Classify a power profile from pre-collected inputs. Separated from
    /// [`PowerProfile::detect`] so the classification can be unit-tested
    /// on hosts where the platform APIs return `Unknown`.
    pub fn from_inputs(power: PowerState, is_idle: bool, battery_pct: Option<u8>) -> Self {
        match (power, is_idle, battery_pct) {
            (PowerState::Battery, _, Some(pct)) if pct < 10 => PowerProfile::CriticalBattery,
            (PowerState::Battery, true, _) => PowerProfile::BatteryIdle,
            (PowerState::Battery, false, _) => PowerProfile::BatteryActive,
            (_, true, _) => PowerProfile::IdleAC,
            _ => PowerProfile::Normal,
        }
    }

    /// Get the FIM scan rate multiplier for this profile.
    pub fn fim_scan_rate(&self) -> f64 {
        match self {
            PowerProfile::Normal => 1.0,
            PowerProfile::IdleAC => 2.0,
            PowerProfile::BatteryActive => 0.5,
            PowerProfile::BatteryIdle => 0.25,
            PowerProfile::CriticalBattery => 0.0, // Paused
        }
    }

    /// Get the log batch interval for this profile.
    pub fn log_batch_interval(&self) -> Duration {
        match self {
            PowerProfile::Normal => Duration::from_secs(5),
            PowerProfile::IdleAC => Duration::from_secs(5),
            PowerProfile::BatteryActive => Duration::from_secs(10),
            PowerProfile::BatteryIdle => Duration::from_secs(20),
            PowerProfile::CriticalBattery => Duration::from_secs(60),
        }
    }

    /// Get the inventory collection interval for this profile.
    pub fn inventory_interval(&self) -> Duration {
        match self {
            PowerProfile::Normal => Duration::from_secs(3600),
            PowerProfile::IdleAC => Duration::from_secs(3600),
            PowerProfile::BatteryActive => Duration::from_secs(14400),
            PowerProfile::BatteryIdle => Duration::from_secs(28800),
            PowerProfile::CriticalBattery => Duration::from_secs(86400),
        }
    }

    /// Whether SCA scans should run in this profile.
    pub fn sca_enabled(&self) -> bool {
        !matches!(self, PowerProfile::CriticalBattery)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_power_profile_detect_battery_critical() {
        // Battery with <10% charge always maps to CriticalBattery.
        assert_eq!(
            PowerProfile::from_inputs(PowerState::Battery, false, Some(5)),
            PowerProfile::CriticalBattery
        );
        assert_eq!(
            PowerProfile::from_inputs(PowerState::Battery, true, Some(9)),
            PowerProfile::CriticalBattery
        );

        // 10% is the boundary — not critical.
        assert_eq!(
            PowerProfile::from_inputs(PowerState::Battery, false, Some(10)),
            PowerProfile::BatteryActive
        );

        // Idle on non-critical battery.
        assert_eq!(
            PowerProfile::from_inputs(PowerState::Battery, true, Some(50)),
            PowerProfile::BatteryIdle
        );

        // Idle on AC.
        assert_eq!(
            PowerProfile::from_inputs(PowerState::AC, true, None),
            PowerProfile::IdleAC
        );

        // Active on AC.
        assert_eq!(
            PowerProfile::from_inputs(PowerState::AC, false, None),
            PowerProfile::Normal
        );

        // Unknown power state, active user.
        assert_eq!(
            PowerProfile::from_inputs(PowerState::Unknown, false, None),
            PowerProfile::Normal
        );

        // Critical battery pauses FIM and disables SCA.
        let critical = PowerProfile::CriticalBattery;
        assert_eq!(critical.fim_scan_rate(), 0.0);
        assert!(!critical.sca_enabled());
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires a real macOS host with a power source; CI VMs have no IOPowerSources and report Unknown. Run with `cargo test -- --ignored`."]
    fn test_macos_power_state_returns_known_value() {
        let monitor = PowerMonitor::new();
        let state = monitor.power_state();
        assert!(
            matches!(state, PowerState::AC | PowerState::Battery),
            "expected AC or Battery, got {:?}",
            state
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_user_idle_duration_is_some() {
        let monitor = PowerMonitor::new();
        assert!(monitor.user_idle_duration().is_some());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_power_state_returns_known_value() {
        let monitor = PowerMonitor::new();
        let state = monitor.power_state();
        assert!(
            matches!(state, PowerState::AC | PowerState::Battery),
            "expected AC or Battery, got {:?}",
            state
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_user_idle_duration_is_some() {
        let monitor = PowerMonitor::new();
        assert!(monitor.user_idle_duration().is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_idle_since_hint_not_idle() {
        // IdleSinceHint == 0 means logind considers the session active.
        let now = 1_700_000_000_000_000_u128;
        assert_eq!(parse_idle_since_hint("0\n", now), Some(Duration::ZERO));
        assert_eq!(parse_idle_since_hint("0", now), Some(Duration::ZERO));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_idle_since_hint_idle_for_30_seconds() {
        let now: u128 = 1_700_000_030_000_000;
        let thirty_s_ago: u64 = 1_700_000_000_000_000;
        let got = parse_idle_since_hint(&thirty_s_ago.to_string(), now);
        assert_eq!(got, Some(Duration::from_secs(30)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_idle_since_hint_rejects_future_timestamps() {
        let now: u128 = 1_000_000;
        let in_the_future: u64 = 2_000_000;
        assert_eq!(parse_idle_since_hint(&in_the_future.to_string(), now), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_idle_since_hint_rejects_garbage_and_empty() {
        let now = 1_700_000_000_000_000_u128;
        assert_eq!(parse_idle_since_hint("", now), None);
        assert_eq!(parse_idle_since_hint("   \n", now), None);
        assert_eq!(parse_idle_since_hint("not-a-number", now), None);
        assert_eq!(parse_idle_since_hint("-1", now), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_user_idle_duration_does_not_panic() {
        // Environments without logind (minimal containers, headless
        // CI runners) return `None`; with a session the value is
        // `Some(..)`. Either way the call must complete cleanly —
        // we only assert that nothing panics and the duration is
        // non-negative when present.
        let monitor = PowerMonitor::new();
        if let Some(d) = monitor.user_idle_duration() {
            // Duration is unsigned; the only guarantee we can make
            // without a real session is that we didn't observe
            // seconds-in-the-future nonsense.
            assert!(d.as_secs() < 60 * 60 * 24 * 365);
        }
    }
}
