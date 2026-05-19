//! Linux identity-attack provider.
//!
//! Subscribes to the in-process `EventBus` for FIM events on the
//! credential-bearing files we care about
//! (`/etc/shadow`, `/proc/kcore`) and lifts them into the typed
//! [`IdentitySignal`] stream consumed by the module.
//!
//! Reusing the existing FIM stream means we do **not** need
//! `CAP_AUDIT_CONTROL` or an extra inotify handle — the agent
//! already monitors `/etc/shadow` for integrity drift, and we just
//! observe the resulting events.
//!
//! ## What the Linux backend can and cannot see
//!
//! - **Detect**: any *write* to `/etc/shadow` (new mtime, perms,
//!   uid/gid change, deletion). FIM does not see pure read syscalls
//!   on Linux, but a credential exfiltration that copies the file
//!   typically modifies mtime via `atime` cascade or replaces it on
//!   subsequent edits. The signal we publish is therefore a
//!   "shadow write" event, which matches MITRE T1003.008 since the
//!   technique covers both reads and unauthorized modifications.
//! - **Detect**: any FIM event on `/proc/kcore`. The procfs entry is
//!   read-only, so an FIM hit here is almost always a probe of the
//!   live kernel image (MITRE T1003).
//! - **Cannot detect (yet)**: passive read-only access. Capturing
//!   that would require an eBPF kprobe on `do_sys_openat2` — that
//!   lands in E6.4 behind the `kernel-linux-ebpf` feature.

use std::sync::Arc;

use serde_json::Value;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use sda_core::config::IdentityMonitorConfig;
use sda_core::signal::ShutdownSignal;
use sda_event_bus::{EventBus, EventKind};

use crate::{IdentityAlertKind, IdentityProvider, IdentitySignal};

/// FIM-backed Linux identity provider.
///
/// Wraps a shared [`EventBus`] so we can plumb events through the
/// same in-process pub/sub the rest of the agent already uses.
pub struct LinuxShadowAccessProvider {
    bus: EventBus,
}

impl LinuxShadowAccessProvider {
    /// Build a new Linux provider bound to `bus`.
    pub fn new(bus: EventBus) -> Self {
        Self { bus }
    }
}

impl IdentityProvider for LinuxShadowAccessProvider {
    fn run(
        &self,
        cfg: IdentityMonitorConfig,
        tx: mpsc::Sender<IdentitySignal>,
        shutdown: ShutdownSignal,
    ) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        // Subscribe on the calling thread BEFORE spawning the
        // background task. If we subscribe inside the `tokio::spawn`
        // closure, the scheduler is free to delay the first poll
        // long enough for a publisher to race ahead and drop events
        // before the receiver exists. The DLP module and memory
        // scanner already follow this pattern.
        let mut rx = self.bus.subscribe();
        let mut shutdown = shutdown;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.wait() => {
                        debug!("LinuxShadowAccessProvider: shutdown");
                        return Ok(());
                    }
                    ev = rx.recv() => {
                        let Some(event) = ev else {
                            debug!("LinuxShadowAccessProvider: bus closed");
                            return Ok(());
                        };
                        let arc = Arc::new(event);
                        if let Some(signal) = classify(arc.as_ref(), &cfg) {
                            if tx.send(signal).await.is_err() {
                                debug!("LinuxShadowAccessProvider: consumer dropped");
                                return Ok(());
                            }
                        }
                    }
                }
            }
        })
    }
}

/// Inspect a single bus event and yield an [`IdentitySignal`] when
/// it matches a credential-bearing path the Linux provider cares
/// about. Returns `None` for everything else.
pub(crate) fn classify(
    event: &sda_event_bus::Event,
    cfg: &IdentityMonitorConfig,
) -> Option<IdentitySignal> {
    let (path, payload) = match &event.kind {
        EventKind::FileCreated {
            path,
            syscheck_payload,
        }
        | EventKind::FileModified {
            path,
            syscheck_payload,
        }
        | EventKind::FileMetadataChanged {
            path,
            syscheck_payload,
        }
        | EventKind::FileDeleted {
            path,
            syscheck_payload,
        } => (path.as_str(), syscheck_payload.as_deref()),
        _ => return None,
    };

    let category = if path == "/etc/shadow" && cfg.shadow_access_linux {
        IdentityAlertKind::ShadowAccess
    } else if path == "/proc/kcore" && cfg.shadow_access_linux {
        // Linux still uses the shadow_access_linux toggle — there
        // is no separate `kcore_access_linux` config knob in the
        // schema and the security model is the same.
        IdentityAlertKind::KcoreAccess
    } else {
        return None;
    };

    let user = payload.map(parse_user_from_syscheck).unwrap_or_default();
    Some(IdentitySignal {
        category,
        user,
        pid: 0,
        process: String::new(),
        image_path: String::new(),
        target: path.to_string(),
        description: format!(
            "FIM event on credential file {path} (category={})",
            category.as_wire()
        ),
    })
}

/// Extract a best-effort owning user (mapped from `uid`) out of a
/// Wazuh-shaped syscheck payload.
///
/// The payload always carries `attributes.uid` as a string; we map
/// 0 to `"root"` so the system-principal filter in the module
/// (`is_system_principal`) catches FIM hits that fire as root.
/// Returns an empty string when parsing fails — the module then
/// applies the default filter ('' counts as a system principal).
fn parse_user_from_syscheck(payload: &str) -> String {
    let Ok(v) = serde_json::from_str::<Value>(payload) else {
        warn!("identity_monitor: failed to parse syscheck payload");
        return String::new();
    };
    let uid_str = v
        .pointer("/data/attributes/uid")
        .and_then(Value::as_str)
        .unwrap_or("");
    match uid_str.parse::<u32>() {
        Ok(0) => "root".to_string(),
        Ok(uid) => format!("uid:{uid}"),
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_event_bus::{Event, Priority};

    fn payload(uid: u32) -> Option<String> {
        Some(format!(
            "{{\"type\":\"event\",\"data\":{{\"path\":\"/etc/shadow\",\"mode\":\"realtime\",\"type\":\"modified\",\"timestamp\":1700000000,\"changed_attributes\":[\"hash_sha256\"],\"attributes\":{{\"type\":\"file\",\"hash_sha256\":\"abc\",\"size\":1024,\"perm\":\"644\",\"uid\":\"{uid}\",\"gid\":\"0\",\"mtime\":1700000000,\"inode\":42}}}}}}"
        ))
    }

    fn cfg(enabled: bool) -> IdentityMonitorConfig {
        IdentityMonitorConfig {
            enabled: true,
            lsass_access_windows: true,
            shadow_access_linux: enabled,
            keychain_access_macos: true,
        }
    }

    #[test]
    fn shadow_modification_by_non_root_classifies_as_shadow_access() {
        let ev = Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileModified {
                path: "/etc/shadow".to_string(),
                syscheck_payload: payload(1000),
            },
        );
        let signal = classify(&ev, &cfg(true)).expect("expect classification");
        assert_eq!(signal.category, IdentityAlertKind::ShadowAccess);
        assert_eq!(signal.user, "uid:1000");
        assert_eq!(signal.target, "/etc/shadow");
        assert!(signal.description.contains("shadow_access"));
    }

    #[test]
    fn shadow_modification_by_root_emits_root_user() {
        let ev = Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileModified {
                path: "/etc/shadow".to_string(),
                syscheck_payload: payload(0),
            },
        );
        let signal = classify(&ev, &cfg(true)).expect("expect classification");
        assert_eq!(signal.user, "root");
        // Note: the module's publish boundary then drops this via
        // is_system_principal — verified in the module-level tests.
    }

    #[test]
    fn kcore_modification_classifies_as_kcore_access() {
        let ev = Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileMetadataChanged {
                path: "/proc/kcore".to_string(),
                syscheck_payload: payload(1000),
            },
        );
        let signal = classify(&ev, &cfg(true)).expect("expect classification");
        assert_eq!(signal.category, IdentityAlertKind::KcoreAccess);
        assert_eq!(signal.target, "/proc/kcore");
    }

    #[test]
    fn unrelated_path_yields_no_signal() {
        let ev = Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileModified {
                path: "/var/log/syslog".to_string(),
                syscheck_payload: payload(0),
            },
        );
        assert!(classify(&ev, &cfg(true)).is_none());
    }

    #[test]
    fn shadow_disabled_yields_no_signal() {
        let ev = Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileModified {
                path: "/etc/shadow".to_string(),
                syscheck_payload: payload(1000),
            },
        );
        assert!(classify(&ev, &cfg(false)).is_none());
    }

    #[test]
    fn non_fim_event_yields_no_signal() {
        let ev = Event::new(
            "other",
            Priority::Normal,
            EventKind::LogCollected {
                source: "test".to_string(),
                message: "msg".to_string(),
                format: "raw".to_string(),
            },
        );
        assert!(classify(&ev, &cfg(true)).is_none());
    }

    #[test]
    fn parse_user_handles_garbage_payload() {
        assert_eq!(parse_user_from_syscheck("not-json"), "");
        assert_eq!(parse_user_from_syscheck("{}"), "");
        assert_eq!(
            parse_user_from_syscheck("{\"data\":{\"attributes\":{\"uid\":\"0\"}}}"),
            "root"
        );
        assert_eq!(
            parse_user_from_syscheck("{\"data\":{\"attributes\":{\"uid\":\"1000\"}}}"),
            "uid:1000"
        );
    }
}
