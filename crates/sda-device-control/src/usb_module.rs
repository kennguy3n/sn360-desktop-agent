//! Top-level `UsbPolicyModule` — the supervisor + IPC server task
//! the agent's `main.rs` spawns when
//! `modules.device_control.usb_policy.enabled = true`.
//!
//! The module:
//!
//! * Owns a [`UsbPolicySupervisor`] (`Arc<...>` for shared access).
//! * Loads `policy/device-control/policies.json` from the agent's
//!   bundle staging directory at startup. The TRDS pull pipeline
//!   in `sda-updater` writes the verified bytes to that path; if
//!   the file is missing or malformed the supervisor stays in the
//!   closed-by-default boot sentinel until a future apply succeeds.
//! * Watches the bundle staging directory for replacements (D2.7:
//!   atomic CAS on every successful pull).
//! * Spawns the per-OS IPC server (Unix socket on Linux/macOS,
//!   named pipe on Windows) so the per-OS helpers can ask for
//!   decisions.
//! * Forwards every decision's audit envelope onto the agent's
//!   event bus as `EventKind::UsbDevicePolicyDecision`, where the
//!   gateway picks it up.
//!
//! The module signature mirrors the existing `sda-fim` /
//! `sda-rootcheck` / `sda-app-control` modules so the agent's
//! wiring code can call all modules through one shape.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sda_core::config::{AgentConfig, UsbPolicyConfig};
use sda_core::module::ModuleHandle;
use sda_core::signal::ShutdownSignal;
use sda_event_bus::{Event, EventBus, EventKind, Priority};
use tracing::{debug, info, warn};

use crate::canonicalize::canonicalize as canonicalize_json;
use crate::finding::Finding;
use crate::types::{FindingKind, Severity};
use crate::usb_policy::Action;
use crate::usb_supervisor::{UsbPolicySupervisor, UsbPolicySupervisorConfig};
use crate::version::FINDING_SCHEMA_VERSION;

/// Default bundle slice path. The TRDS pull pipeline writes the
/// verified `policy/device-control/policies.json` slice here.
pub const DEFAULT_BUNDLE_SLICE_PATH: &str =
    "/var/lib/sn360-desktop-agent/bundle/policy/device-control/policies.json";

/// Default bundle metadata path. Carries the
/// `device_control_status` sentinel introduced in D2.7 so a
/// tampered bundle that surgically removes the slice cannot
/// silently downgrade the agent to permissive.
pub const DEFAULT_BUNDLE_METADATA_PATH: &str = "/var/lib/sn360-desktop-agent/bundle/metadata.json";

/// How often the watcher rechecks the slice on disk. The TRDS
/// pull cadence is minutes-to-hours so we do not need a
/// sub-second poll; 5 s is well below any operator's worst-case
/// expectation and adds zero idle CPU when nothing changes
/// (mtime-based comparison).
pub const WATCHER_INTERVAL: Duration = Duration::from_secs(5);

/// Top-level Phase D2 module.
pub struct UsbPolicyModule;

impl UsbPolicyModule {
    /// Spawn the supervisor + IPC server + bundle-watcher. The
    /// returned [`ModuleHandle`] is registered into the agent's
    /// `lifecycle` so the agent can wait on it during graceful
    /// shutdown.
    pub fn start(config: &AgentConfig, bus: EventBus, shutdown: ShutdownSignal) -> ModuleHandle {
        let cfg = &config.modules.device_control.usb_policy;
        let supervisor = supervisor_from_config(cfg);
        let bundle_slice_path = PathBuf::from(DEFAULT_BUNDLE_SLICE_PATH);
        let bundle_metadata_path = PathBuf::from(DEFAULT_BUNDLE_METADATA_PATH);

        // Best-effort initial load. A failure here only logs; the
        // supervisor stays in the closed-by-default boot sentinel.
        let _ = try_apply_from_disk(&supervisor, &bundle_slice_path, &bundle_metadata_path, &bus);

        let ipc_path = if cfg.ipc_path.is_empty() {
            default_ipc_path()
        } else {
            cfg.ipc_path.clone()
        };

        let task = tokio::spawn(async move {
            run_loop(
                supervisor,
                bus,
                bundle_slice_path,
                bundle_metadata_path,
                ipc_path,
                shutdown,
            )
            .await;
            Ok(())
        });
        ModuleHandle::new("device-control-usb-policy", task)
    }
}

#[cfg(target_os = "linux")]
fn default_ipc_path() -> String {
    crate::usb_linux::DEFAULT_LINUX_SOCKET_PATH.to_string()
}

#[cfg(target_os = "macos")]
fn default_ipc_path() -> String {
    "/var/run/sn360-desktop-agent/usb-policy.sock".to_string()
}

#[cfg(target_os = "windows")]
fn default_ipc_path() -> String {
    r"\\.\pipe\sn360-usb-policy".to_string()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn default_ipc_path() -> String {
    "/run/sn360-desktop-agent/usb-policy.sock".to_string()
}

/// Build a supervisor from the agent's [`UsbPolicyConfig`].
pub fn supervisor_from_config(cfg: &UsbPolicyConfig) -> Arc<UsbPolicySupervisor> {
    let default_action = parse_action(&cfg.default_action).unwrap_or(Action::Audit);
    let fallback_action = parse_action(&cfg.fallback_action).unwrap_or(Action::Audit);
    UsbPolicySupervisor::new(&UsbPolicySupervisorConfig {
        // Tenant id is filled in by the bundle apply path once a
        // verified slice lands. Until then we stamp envelopes with
        // an empty string; the gateway treats that as "tenant
        // unknown — quarantine".
        tenant_id: String::new(),
        default_action,
        fallback_action,
    })
}

fn parse_action(s: &str) -> Option<Action> {
    match s.to_ascii_lowercase().as_str() {
        "block" => Some(Action::Block),
        "allow" => Some(Action::Allow),
        "audit" => Some(Action::Audit),
        _ => None,
    }
}

async fn run_loop(
    supervisor: Arc<UsbPolicySupervisor>,
    bus: EventBus,
    slice_path: PathBuf,
    metadata_path: PathBuf,
    ipc_path: String,
    mut shutdown: ShutdownSignal,
) {
    let mut last_mtime: Option<std::time::SystemTime> = None;
    info!(
        slice = %slice_path.display(),
        ipc = %ipc_path,
        "USB-policy module started; supervisor in closed-by-default boot sentinel"
    );

    // Spawn the per-OS IPC server so per-OS helpers can ask for
    // decisions. The bus is cloned into the audit callback so each
    // decision lands on the agent's event bus as a
    // `UsbDevicePolicyDecision` envelope. On macOS / Linux the
    // server is a `tokio::net::UnixListener`; on Windows it is a
    // named pipe. Other targets get a no-op server.
    spawn_ipc_server(supervisor.clone(), bus.clone(), ipc_path.clone());

    loop {
        tokio::select! {
            _ = tokio::time::sleep(WATCHER_INTERVAL) => {
                if let Some(new_mtime) = file_mtime(&slice_path) {
                    if last_mtime != Some(new_mtime) {
                        if let Err(e) = try_apply_from_disk(&supervisor, &slice_path, &metadata_path, &bus) {
                            warn!(error = %e, "USB-policy bundle slice apply failed");
                        }
                        last_mtime = Some(new_mtime);
                    }
                }
            }
            _ = shutdown.wait() => {
                info!("USB-policy module shutting down");
                return;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn spawn_ipc_server(supervisor: Arc<UsbPolicySupervisor>, bus: EventBus, ipc_path: String) {
    tokio::spawn(async move {
        let on_audit = move |payload: String| {
            let event = Event::new(
                "usb-policy",
                Priority::Normal,
                EventKind::UsbDevicePolicyDecision { payload },
            );
            // `publish_to_server` does the local broadcast AND
            // enqueues onto the server-bound mpsc; never pair it
            // with a follow-up `publish` (would double-broadcast).
            let bus = bus.clone();
            tokio::spawn(async move {
                if let Err(e) = bus.publish_to_server(event).await {
                    warn!(error = %e, "USB-policy decision publish failed");
                }
            });
        };
        if let Err(e) = crate::usb_linux::async_server::serve(&ipc_path, supervisor, on_audit).await
        {
            warn!(error = %e, "USB-policy Linux IPC server exited");
        }
    });
}

#[cfg(target_os = "macos")]
fn spawn_ipc_server(supervisor: Arc<UsbPolicySupervisor>, bus: EventBus, ipc_path: String) {
    tokio::spawn(async move {
        let on_audit = move |payload: String| {
            let event = Event::new(
                "usb-policy",
                Priority::Normal,
                EventKind::UsbDevicePolicyDecision { payload },
            );
            let bus = bus.clone();
            tokio::spawn(async move {
                if let Err(e) = bus.publish_to_server(event).await {
                    warn!(error = %e, "USB-policy decision publish failed");
                }
            });
        };
        if let Err(e) = crate::usb_macos::async_server::serve(&ipc_path, supervisor, on_audit).await
        {
            warn!(error = %e, "USB-policy macOS IPC server exited");
        }
    });
}

#[cfg(target_os = "windows")]
fn spawn_ipc_server(supervisor: Arc<UsbPolicySupervisor>, bus: EventBus, ipc_path: String) {
    tokio::spawn(async move {
        let on_audit = move |payload: String| {
            let event = Event::new(
                "usb-policy",
                Priority::Normal,
                EventKind::UsbDevicePolicyDecision { payload },
            );
            let bus = bus.clone();
            tokio::spawn(async move {
                if let Err(e) = bus.publish_to_server(event).await {
                    warn!(error = %e, "USB-policy decision publish failed");
                }
            });
        };
        if let Err(e) =
            crate::usb_windows::async_server::serve(&ipc_path, supervisor, on_audit).await
        {
            warn!(error = %e, "USB-policy Windows IPC server exited");
        }
    });
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn spawn_ipc_server(_supervisor: Arc<UsbPolicySupervisor>, _bus: EventBus, _ipc_path: String) {
    warn!("USB-policy IPC server not supported on this target; running supervisor without IPC");
}

/// Read the slice + metadata from disk and apply via the
/// supervisor. On verification-failure (missing metadata sentinel,
/// malformed slice) emits a `Finding` of severity `High` per D2.7
/// and keeps the previous policy set in place.
pub fn try_apply_from_disk(
    supervisor: &UsbPolicySupervisor,
    slice_path: &Path,
    metadata_path: &Path,
    bus: &EventBus,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Step 1: read the metadata sentinel. D2.7: a bundle that
    // ships a `device_control_status: "ok"` sentinel is a valid
    // empty-policy state; a bundle missing the sentinel is
    // assumed tampered and we keep last-known-good.
    let metadata: Metadata = match std::fs::read(metadata_path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Metadata::default(),
        Err(e) => return Err(Box::new(e)),
    };

    // Step 2: read the slice. Missing slice + verified metadata
    // means "tenant has zero policies"; missing slice + missing
    // metadata means "agent has not yet pulled a bundle".
    let slice = match std::fs::read(slice_path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(Box::new(e)),
    };

    if !metadata.tenant_id.is_empty() {
        supervisor.set_tenant_id(metadata.tenant_id.clone());
    }

    match (metadata.device_control_status.as_str(), slice.as_deref()) {
        ("ok", Some(bytes)) => match supervisor.apply_bundle_slice(bytes) {
            Ok(outcome) => {
                info!(
                    new_len = outcome.new_len,
                    previous_len = outcome.previous_len,
                    "USB-policy slice applied"
                );
            }
            Err(e) => {
                warn!(error = %e, "USB-policy slice malformed");
                emit_verification_finding(bus, supervisor, &format!("malformed slice: {e}"));
            }
        },
        ("ok", None) => {
            // Verified-empty state. Apply an explicit empty set so
            // the supervisor flips out of the boot sentinel.
            let _ = supervisor.apply_bundle_slice(b"[]");
            debug!("USB-policy slice not present; tenant has zero policies");
        }
        (_, _) => {
            // Missing or unrecognised sentinel — D2.7: keep
            // last-known-good and emit a high-severity finding.
            let err = supervisor.record_bundle_unverified(format!(
                "bundle metadata missing or invalid (status={:?})",
                metadata.device_control_status
            ));
            emit_verification_finding(bus, supervisor, &format!("{err}"));
        }
    }
    Ok(())
}

#[derive(Debug, Default, serde::Deserialize)]
struct Metadata {
    #[serde(default)]
    tenant_id: String,
    /// `"ok"` when the control plane explicitly signed off on the
    /// slice (even if it's empty); anything else is treated as
    /// missing.
    #[serde(default)]
    device_control_status: String,
}

fn emit_verification_finding(bus: &EventBus, supervisor: &UsbPolicySupervisor, reason: &str) {
    let tenant_id =
        uuid::Uuid::parse_str(&supervisor.tenant_id()).unwrap_or_else(|_| uuid::Uuid::nil());
    let device_id = std::env::var("SN360_DEVICE_ID")
        .ok()
        .and_then(|s| uuid::Uuid::parse_str(&s).ok())
        .unwrap_or_else(uuid::Uuid::nil);
    let f = Finding {
        finding_id: uuid::Uuid::new_v4(),
        device_id,
        tenant_id,
        schema_version: FINDING_SCHEMA_VERSION,
        kind: FindingKind::DeviceControlBundleVerificationFailure,
        observed_at: chrono::Utc::now(),
        severity: Severity::High,
        plain_english: format!("USB-policy bundle verification failed: {reason}"),
        evidence: serde_json::json!({ "reason": reason }),
        source_refs: None,
    };
    let value = match serde_json::to_value(&f) {
        Ok(v) => v,
        Err(_) => return,
    };
    let bytes = match canonicalize_json(&value) {
        Ok(b) => b,
        Err(_) => return,
    };
    let payload = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return,
    };
    let event = Event::new(
        "usb-policy",
        Priority::High,
        EventKind::DeviceControlFinding { payload },
    );
    // Bundle-verification failures must surface in the dashboard;
    // forward the Finding both onto the local bus and into the
    // server-bound mpsc. `publish_to_server` does both atomically;
    // never pair it with a follow-up `publish` (would
    // double-broadcast). When called from outside a tokio runtime
    // (e.g. eager unit tests) fall back to the synchronous local
    // broadcast — the agent's normal startup path is always inside
    // a runtime and therefore prefers the server-bound queue.
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let bus = bus.clone();
        handle.spawn(async move {
            if let Err(e) = bus.publish_to_server(event).await {
                tracing::warn!(error = %e, "USB-policy bundle-verification finding publish failed");
            }
        });
    } else {
        let _ = bus.publish(event);
    }
}

fn file_mtime(p: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_action_accepts_known_strings() {
        assert_eq!(parse_action("block"), Some(Action::Block));
        assert_eq!(parse_action("ALLOW"), Some(Action::Allow));
        assert_eq!(parse_action("Audit"), Some(Action::Audit));
        assert_eq!(parse_action("nuke"), None);
    }

    #[test]
    fn supervisor_from_config_uses_defaults_for_unknown_strings() {
        let cfg = UsbPolicyConfig {
            enabled: true,
            default_action: "nonsense".into(),
            fallback_action: "nonsense".into(),
            ipc_path: String::new(),
        };
        let sup = supervisor_from_config(&cfg);
        // Both defaults silently fall back to Audit so a typo
        // does not brick the agent.
        let cand = crate::DeviceCandidate::default();
        assert_eq!(sup.evaluate(&cand).action, Action::Audit);
    }
}
