//! Linux USB enforcement (D2.2).
//!
//! `systemd-udevd` matches the rule template shipped under
//! `packaging/linux/sn360-device-control.rules` (relative to the
//! repo root) and runs `sn360-device-control-helper` with the
//! device attributes in the helper's environment block. The helper
//! constructs a [`crate::DeviceCandidate`] from the udev
//! environment, talks to the supervisor over the agent's Unix
//! domain socket using [`crate::usb_ipc`], and either:
//!
//! * exits 0 (`Action::Allow` / `Action::Audit`) — udevd binds the
//!   device, OR
//! * exits 1 (`Action::Block`) — udevd leaves the device unbound
//!   so it cannot be mounted.
//!
//! Every decision (block / allow / audit) is also written to the
//! agent's event bus by the supervisor side of the IPC, where it
//! is forwarded to the gateway as a `connector_type:device-control`
//! envelope.
//!
//! The IPC server side and the helper-side parser are both kept
//! in this module so they share their wire types and unit tests.
//! The async IPC server is `cfg(target_os = "linux")` only because
//! it uses [`tokio::net::UnixListener`]; the parsers are portable
//! and exercised on every platform.

use std::collections::HashMap;
use std::sync::Arc;

use crate::usb_ipc::{
    decode_query_request, encode_query_response, UsbIpcQueryRequest, UsbIpcQueryResponse,
    USB_IPC_PROTOCOL_VERSION,
};
use crate::usb_policy::{DeviceCandidate, DeviceClass};
use crate::usb_supervisor::UsbPolicySupervisor;

/// Default Unix-domain socket path. The agent owns the socket; the
/// helper opens it as the device-controlling user (typically root,
/// since udev runs as root). The path lives under `/run` so it is
/// wiped on reboot.
pub const DEFAULT_LINUX_SOCKET_PATH: &str = "/run/sn360-desktop-agent/usb-policy.sock";

/// Errors specific to udev-environment parsing.
#[derive(Debug, thiserror::Error)]
pub enum UdevParseError {
    /// A field we accept was present but unparseable (e.g. a vendor
    /// id that is not 4 hex chars).
    #[error("malformed udev field {field}={value:?}")]
    Malformed { field: &'static str, value: String },
}

/// Parse a udev environment-block snapshot (the merged
/// `event.environment()` map a real udev consumer would build) into
/// a [`DeviceCandidate`]. Recognised keys:
///
/// | udev key            | DeviceCandidate field |
/// |---------------------|------------------------|
/// | `SUBSYSTEM`         | `device_class` mapping |
/// | `ID_USB_VENDOR_ID`  | `vendor_id`            |
/// | `ID_VENDOR_ID`      | `vendor_id` (fallback) |
/// | `ID_USB_MODEL_ID`   | `product_id`           |
/// | `ID_MODEL_ID`       | `product_id` (fallback)|
/// | `ID_SERIAL_SHORT`   | `serial`               |
/// | `ID_SERIAL`         | `serial` (fallback)    |
/// | `DEVPATH`           | `bus_path`             |
///
/// Unknown subsystems map to [`DeviceClass::Other`]. The helper
/// will then call the supervisor anyway so the agent can record an
/// audit envelope, but no policy will match.
pub fn parse_udev_environment(
    env: &HashMap<String, String>,
) -> Result<DeviceCandidate, UdevParseError> {
    let device_class = match env.get("SUBSYSTEM").map(String::as_str) {
        Some("usb") => DeviceClass::Usb,
        Some("block") => match env.get("ID_TYPE").map(String::as_str) {
            Some("disk") | Some("partition") => DeviceClass::Removable,
            _ => DeviceClass::Removable,
        },
        Some("bluetooth") => DeviceClass::Bluetooth,
        Some("sound") => DeviceClass::Audio,
        Some("net") => DeviceClass::NetworkTether,
        _ => DeviceClass::Other,
    };

    let vendor_id = env
        .get("ID_USB_VENDOR_ID")
        .or_else(|| env.get("ID_VENDOR_ID"))
        .map(|s| validate_hex16(s, "vendor_id"))
        .transpose()?;

    let product_id = env
        .get("ID_USB_MODEL_ID")
        .or_else(|| env.get("ID_MODEL_ID"))
        .map(|s| validate_hex16(s, "product_id"))
        .transpose()?;

    let serial = env
        .get("ID_SERIAL_SHORT")
        .or_else(|| env.get("ID_SERIAL"))
        .cloned()
        .filter(|s| !s.is_empty());

    let bus_path = env.get("DEVPATH").cloned().filter(|s| !s.is_empty());

    Ok(DeviceCandidate {
        device_class,
        vendor_id,
        product_id,
        serial,
        bus_path,
    })
}

fn validate_hex16(raw: &str, field: &'static str) -> Result<String, UdevParseError> {
    let s = raw.trim();
    if s.len() == 4 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(s.to_ascii_lowercase())
    } else {
        Err(UdevParseError::Malformed {
            field,
            value: raw.to_string(),
        })
    }
}

/// Build the helper-side IPC request from a parsed candidate. The
/// helper generates a transaction id from its PID + a process-local
/// monotonic counter. Both inputs are fine for correlation.
pub fn build_query_request(
    transaction_id: impl Into<String>,
    candidate: DeviceCandidate,
) -> UsbIpcQueryRequest {
    UsbIpcQueryRequest {
        v: USB_IPC_PROTOCOL_VERSION,
        transaction_id: transaction_id.into(),
        candidate,
    }
}

/// Service a single helper request against the supervisor.
///
/// Used by both the `tokio` async IPC server and the synchronous
/// e2e harness. Returns the raw bytes the server should write back
/// to the helper's socket (newline-terminated framed JSON) plus
/// the canonical-JSON audit envelope the supervisor wants emitted
/// onto the agent's event bus.
pub fn handle_query(
    supervisor: &UsbPolicySupervisor,
    req: UsbIpcQueryRequest,
) -> Result<(Vec<u8>, String), HandleError> {
    let candidate = req.candidate;
    let (decision, audit_payload) = supervisor
        .evaluate_with_payload(&candidate)
        .map_err(HandleError::Canonicalize)?;
    let resp = UsbIpcQueryResponse {
        v: USB_IPC_PROTOCOL_VERSION,
        transaction_id: req.transaction_id,
        default_action_used: decision.matched_policy_id.is_none(),
        decision,
    };
    let frame = encode_query_response(&resp).map_err(HandleError::Ipc)?;
    Ok((frame, audit_payload))
}

/// Errors returned by [`handle_query`].
#[derive(Debug, thiserror::Error)]
pub enum HandleError {
    #[error("canonicalize audit envelope: {0}")]
    Canonicalize(#[from] crate::CanonicalizeError),
    #[error("ipc encode: {0}")]
    Ipc(#[from] crate::UsbIpcError),
}

/// Decode a single newline-terminated request frame. Convenience
/// wrapper around [`decode_query_request`].
pub fn decode_helper_request(line: &[u8]) -> Result<UsbIpcQueryRequest, crate::UsbIpcError> {
    decode_query_request(line)
}

/// Async IPC server backed by [`tokio::net::UnixListener`].
///
/// Each accepted connection is expected to send exactly one
/// newline-terminated request, then wait for one newline-terminated
/// response, then close. The server tolerates client disconnects
/// at any point: if the helper goes away mid-frame we log and
/// move on.
#[cfg(target_os = "linux")]
pub mod async_server {
    use super::*;
    use std::path::Path;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;
    use tracing::{debug, error, info, warn};

    /// Bind a Unix-domain socket at `path` and start serving
    /// requests. Each request goes to `supervisor.evaluate` and
    /// the response is written back to the same socket.
    ///
    /// The function never returns; it loops forever until the
    /// process exits or the supervisor task is cancelled.
    pub async fn serve(
        path: impl AsRef<Path>,
        supervisor: Arc<UsbPolicySupervisor>,
        on_audit: impl Fn(String) + Send + Sync + 'static,
    ) -> std::io::Result<()> {
        let path = path.as_ref();
        // Best-effort cleanup of a stale socket from a crashed run.
        let _ = std::fs::remove_file(path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let listener = UnixListener::bind(path)?;
        info!(socket = %path.display(), "USB-policy IPC server bound");
        let on_audit = Arc::new(on_audit);
        loop {
            let (stream, _addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!(error = %e, "USB-policy IPC accept failed");
                    continue;
                }
            };
            let supervisor = supervisor.clone();
            let on_audit = on_audit.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                match reader.read_line(&mut line).await {
                    Ok(0) => return,
                    Ok(_) => {}
                    Err(e) => {
                        warn!(error = %e, "USB-policy helper read failed");
                        return;
                    }
                }
                let req = match decode_helper_request(line.as_bytes()) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(error = %e, "USB-policy helper sent malformed frame");
                        return;
                    }
                };
                debug!(transaction_id = %req.transaction_id, "USB-policy IPC query");
                let (frame, audit_payload) = match handle_query(&supervisor, req) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "USB-policy supervisor handle failed");
                        return;
                    }
                };
                let mut stream = reader.into_inner();
                if let Err(e) = stream.write_all(&frame).await {
                    warn!(error = %e, "USB-policy IPC response write failed");
                    return;
                }
                let _ = stream.flush().await;
                on_audit(audit_payload);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb_policy::{Action, DevicePolicy, PolicyMatch};
    use crate::usb_supervisor::UsbPolicySupervisorConfig;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn parses_typical_usb_mass_storage_event() {
        let e = env(&[
            ("ACTION", "add"),
            ("SUBSYSTEM", "usb"),
            ("ID_USB_VENDOR_ID", "05ac"),
            ("ID_USB_MODEL_ID", "0220"),
            ("ID_SERIAL_SHORT", "ABC123"),
            ("DEVPATH", "/devices/pci0000:00/0000:00:14.0/usb3/3-1"),
        ]);
        let cand = parse_udev_environment(&e).unwrap();
        assert_eq!(cand.device_class, DeviceClass::Usb);
        assert_eq!(cand.vendor_id.as_deref(), Some("05ac"));
        assert_eq!(cand.product_id.as_deref(), Some("0220"));
        assert_eq!(cand.serial.as_deref(), Some("ABC123"));
        assert_eq!(
            cand.bus_path.as_deref(),
            Some("/devices/pci0000:00/0000:00:14.0/usb3/3-1")
        );
    }

    #[test]
    fn unknown_subsystem_maps_to_other() {
        let e = env(&[("SUBSYSTEM", "iio")]);
        let cand = parse_udev_environment(&e).unwrap();
        assert_eq!(cand.device_class, DeviceClass::Other);
    }

    #[test]
    fn vendor_id_must_be_4_hex_chars() {
        let e = env(&[("SUBSYSTEM", "usb"), ("ID_USB_VENDOR_ID", "GGGG")]);
        let err = parse_udev_environment(&e).unwrap_err();
        assert!(matches!(
            err,
            UdevParseError::Malformed {
                field: "vendor_id",
                ..
            }
        ));
    }

    #[test]
    fn fallback_to_id_vendor_id_when_id_usb_vendor_id_absent() {
        let e = env(&[("SUBSYSTEM", "usb"), ("ID_VENDOR_ID", "abcd")]);
        let cand = parse_udev_environment(&e).unwrap();
        assert_eq!(cand.vendor_id.as_deref(), Some("abcd"));
    }

    #[test]
    fn handle_query_emits_audit_envelope_and_block_response() {
        let cfg = UsbPolicySupervisorConfig {
            tenant_id: "tenant-a".into(),
            default_action: Action::Audit,
            fallback_action: Action::Audit,
        };
        let sup = UsbPolicySupervisor::new(&cfg);
        let block = DevicePolicy {
            id: "00000000-0000-0000-0000-000000000001".into(),
            tenant_id: "tenant-a".into(),
            name: "block all usb".into(),
            enabled: true,
            device_class: DeviceClass::Usb,
            match_block: PolicyMatch::default(),
            action: Action::Block,
            priority: 100,
            severity: 7,
        };
        sup.apply_bundle_slice(&serde_json::to_vec(&[block]).unwrap())
            .unwrap();

        let req = build_query_request(
            "tx-1",
            DeviceCandidate {
                device_class: DeviceClass::Usb,
                vendor_id: Some("05ac".into()),
                product_id: Some("0220".into()),
                serial: None,
                bus_path: None,
            },
        );
        let (frame, audit) = handle_query(&sup, req).unwrap();
        let resp = crate::usb_ipc::decode_query_response(&frame).unwrap();
        assert!(resp.is_block());
        assert_eq!(resp.transaction_id, "tx-1");
        assert!(audit.contains(r#""decision":"block""#));
        assert!(audit.contains(r#""tenant_id":"tenant-a""#));
    }
}
