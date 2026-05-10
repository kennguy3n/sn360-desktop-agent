//! Windows USB enforcement (D2.3).
//!
//! The kernel-mode USB + class filter driver pair productionised
//! at GA time is intentionally **out of scope** for this module —
//! it lives in `packaging/windows/` alongside the existing FIM /
//! Active Response driver scaffolds. What this module ships is the
//! user-mode policy service half of the pair:
//!
//! * A canonical [`DeviceProperties`] parser that turns the raw
//!   `SP_DEVINFO_DATA` / `CM_Get_DevNode_Property` strings —
//!   "USB\\VID_05AC&PID_0220\\ABC123", `DEVPKEY_Device_Class`, etc.
//!   — into a [`crate::DeviceCandidate`].
//! * A named-pipe IPC server that mirrors the Linux UDS server
//!   line-protocol (so the kernel-mode filter and the WMI
//!   user-mode listener share one IPC contract with the agent).
//! * Synchronous parsers and a policy-evaluation helper used by
//!   the e2e harness.
//!
//! The named-pipe server uses [`tokio::net::windows::named_pipe`]
//! when compiled on Windows; the parser-only types are portable so
//! the linux CI machine can exercise them.

#[cfg(target_os = "windows")]
use std::sync::Arc;

use crate::usb_ipc::{
    decode_query_request, encode_query_response, UsbIpcQueryRequest, UsbIpcQueryResponse,
    USB_IPC_PROTOCOL_VERSION,
};
use crate::usb_policy::{DeviceCandidate, DeviceClass};
use crate::usb_supervisor::UsbPolicySupervisor;

/// Default named-pipe path. Mirrors the form `\\.\pipe\sn360-*`
/// already used by `sda-active-response`.
pub const DEFAULT_WINDOWS_PIPE_NAME: &str = r"\\.\pipe\sn360-usb-policy";

/// Errors specific to Windows device-property parsing.
#[derive(Debug, thiserror::Error)]
pub enum WindowsParseError {
    /// The hardware id was not the expected `USB\VID_xxxx&PID_xxxx[\…]` shape.
    #[error("malformed hardware id {0:?}")]
    MalformedHardwareId(String),
    /// The vendor or product id was present but not 4 hex characters.
    #[error("malformed {field} {value:?}")]
    MalformedHex { field: &'static str, value: String },
}

/// Subset of `SP_DEVINFO_DATA` / `CM_Get_DevNode_Property` strings
/// the user-mode service inspects. Mirrors what the WMI listener
/// (`Win32_PnPEntity` / `Win32_USBControllerDevice`) exposes.
#[derive(Debug, Clone, Default)]
pub struct DeviceProperties {
    /// The first element of the `HardwareID` multi-string, e.g.
    /// `USB\VID_05AC&PID_0220`.
    pub hardware_id: Option<String>,
    /// The `Device Instance Path`, e.g.
    /// `USB\VID_05AC&PID_0220\ABC123`. Used to recover the serial.
    pub instance_id: Option<String>,
    /// `DEVPKEY_Device_Class` GUID-friendly string, e.g. `USB`,
    /// `HIDClass`, `Bluetooth`, `MEDIA`, `Net`, `WPD`.
    pub device_class: Option<String>,
    /// `DEVPKEY_Device_LocationPaths` first entry; we use it as
    /// the `bus_path` for evidence correlation.
    pub location_path: Option<String>,
}

impl DeviceProperties {
    /// Build a [`DeviceCandidate`] from a property bag. Returns an
    /// error if mandatory fields are present but malformed; missing
    /// optional fields are fine.
    pub fn into_candidate(self) -> Result<DeviceCandidate, WindowsParseError> {
        let class = self
            .device_class
            .as_deref()
            .map(map_class)
            .unwrap_or(DeviceClass::Other);

        let (vendor_id, product_id) = if let Some(ref hwid) = self.hardware_id {
            parse_vid_pid(hwid)?
        } else if let Some(ref iid) = self.instance_id {
            parse_vid_pid(iid).unwrap_or((None, None))
        } else {
            (None, None)
        };

        let serial = self
            .instance_id
            .as_deref()
            .and_then(parse_serial_from_instance_id)
            .map(|s| s.to_string());

        Ok(DeviceCandidate {
            device_class: class,
            vendor_id,
            product_id,
            serial,
            bus_path: self.location_path,
        })
    }
}

fn map_class(s: &str) -> DeviceClass {
    match s.trim() {
        "USB" => DeviceClass::Usb,
        "DiskDrive" | "Volume" | "CDROM" | "FloppyDisk" => DeviceClass::Removable,
        "Bluetooth" | "BTHENUM" => DeviceClass::Bluetooth,
        "WPD" => DeviceClass::Wpd,
        "MTPDevice" => DeviceClass::Mtp,
        "Media" | "MEDIA" | "AudioEndpoint" => DeviceClass::Audio,
        "Net" => DeviceClass::NetworkTether,
        _ => DeviceClass::Other,
    }
}

fn parse_vid_pid(s: &str) -> Result<(Option<String>, Option<String>), WindowsParseError> {
    // Accept both `USB\VID_05AC&PID_0220` and the longer
    // `USB\VID_05AC&PID_0220\ABC123` instance-id forms.
    let upper = s.to_ascii_uppercase();
    let after_usb = upper
        .strip_prefix("USB\\")
        .or_else(|| upper.strip_prefix("USBSTOR\\"));
    let body = match after_usb {
        Some(b) => b,
        None => {
            // Some bus types (Bluetooth) carry no VID/PID at all.
            return Ok((None, None));
        }
    };
    let head = body.split('\\').next().unwrap_or(body);
    let vid = head
        .split('&')
        .find_map(|seg| seg.strip_prefix("VID_"))
        .map(|s| validate_hex16(s, "vendor_id"))
        .transpose()?;
    let pid = head
        .split('&')
        .find_map(|seg| seg.strip_prefix("PID_"))
        .map(|s| validate_hex16(s, "product_id"))
        .transpose()?;
    if vid.is_none() && pid.is_none() && head.starts_with("VID_") {
        return Err(WindowsParseError::MalformedHardwareId(s.to_string()));
    }
    Ok((vid, pid))
}

fn parse_serial_from_instance_id(iid: &str) -> Option<&str> {
    // e.g. `USB\VID_05AC&PID_0220\ABC123` → `ABC123`.
    iid.rsplit_once('\\')
        .map(|(_, tail)| tail)
        .filter(|s| !s.is_empty())
}

fn validate_hex16(raw: &str, field: &'static str) -> Result<String, WindowsParseError> {
    let s = raw.trim();
    if s.len() == 4 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(s.to_ascii_lowercase())
    } else {
        Err(WindowsParseError::MalformedHex {
            field,
            value: raw.to_string(),
        })
    }
}

/// Helper-side request constructor (mirrors the linux helper).
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

/// Service a single named-pipe request. Symmetrical with the linux
/// `handle_query`.
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

#[derive(Debug, thiserror::Error)]
pub enum HandleError {
    #[error("canonicalize: {0}")]
    Canonicalize(#[from] crate::CanonicalizeError),
    #[error("ipc: {0}")]
    Ipc(#[from] crate::UsbIpcError),
}

/// Decode a single newline-terminated frame.
pub fn decode_helper_request(line: &[u8]) -> Result<UsbIpcQueryRequest, crate::UsbIpcError> {
    decode_query_request(line)
}

/// Async named-pipe server. Compiled on Windows only.
#[cfg(target_os = "windows")]
pub mod async_server {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ServerOptions;
    use tracing::{debug, error, info, warn};

    /// Bind a named pipe at `pipe_name` and serve queries forever.
    pub async fn serve(
        pipe_name: &str,
        supervisor: Arc<UsbPolicySupervisor>,
        on_audit: impl Fn(String) + Send + Sync + 'static,
    ) -> std::io::Result<()> {
        info!(pipe = %pipe_name, "USB-policy IPC named-pipe server starting");
        let on_audit = Arc::new(on_audit);
        loop {
            let server = ServerOptions::new()
                .first_pipe_instance(false)
                .create(pipe_name)?;
            // Wait for a client to connect.
            if let Err(e) = server.connect().await {
                error!(error = %e, "USB-policy named-pipe accept failed");
                continue;
            }
            let supervisor = supervisor.clone();
            let on_audit = on_audit.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(server);
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

    #[test]
    fn parses_apple_keyboard_devnode() {
        let p = DeviceProperties {
            hardware_id: Some(r"USB\VID_05AC&PID_0220".into()),
            instance_id: Some(r"USB\VID_05AC&PID_0220\ABC123".into()),
            device_class: Some("USB".into()),
            location_path: Some(r"PCIROOT(0)#PCI(0014)#USBROOT(0)#USB(1)".into()),
        };
        let cand = p.into_candidate().unwrap();
        assert_eq!(cand.device_class, DeviceClass::Usb);
        assert_eq!(cand.vendor_id.as_deref(), Some("05ac"));
        assert_eq!(cand.product_id.as_deref(), Some("0220"));
        assert_eq!(cand.serial.as_deref(), Some("ABC123"));
        assert!(cand.bus_path.is_some());
    }

    #[test]
    fn parses_usbstor_disk_drive() {
        let p = DeviceProperties {
            hardware_id: Some(r"USBSTOR\VID_0951&PID_1666".into()),
            instance_id: Some(r"USBSTOR\VID_0951&PID_1666\AA00000000000389".into()),
            device_class: Some("DiskDrive".into()),
            location_path: None,
        };
        let cand = p.into_candidate().unwrap();
        assert_eq!(cand.device_class, DeviceClass::Removable);
        assert_eq!(cand.vendor_id.as_deref(), Some("0951"));
    }

    #[test]
    fn malformed_vid_is_rejected() {
        let p = DeviceProperties {
            hardware_id: Some(r"USB\VID_05A&PID_0220".into()),
            ..Default::default()
        };
        let err = p.into_candidate().unwrap_err();
        assert!(matches!(err, WindowsParseError::MalformedHex { .. }));
    }

    #[test]
    fn unknown_class_maps_to_other() {
        let p = DeviceProperties {
            device_class: Some("FuturePnP".into()),
            ..Default::default()
        };
        assert_eq!(p.into_candidate().unwrap().device_class, DeviceClass::Other);
    }

    #[test]
    fn handle_query_round_trip_with_block_policy() {
        let cfg = UsbPolicySupervisorConfig {
            tenant_id: "tenant-a".into(),
            ..Default::default()
        };
        let sup = UsbPolicySupervisor::new(&cfg);
        let block = DevicePolicy {
            id: "00000000-0000-0000-0000-000000000001".into(),
            tenant_id: "tenant-a".into(),
            name: "block usbstor".into(),
            enabled: true,
            device_class: DeviceClass::Removable,
            match_block: PolicyMatch::default(),
            action: Action::Block,
            priority: 100,
            severity: 7,
        };
        sup.apply_bundle_slice(&serde_json::to_vec(&[block]).unwrap())
            .unwrap();

        let cand = DeviceProperties {
            hardware_id: Some(r"USBSTOR\VID_0951&PID_1666".into()),
            instance_id: Some(r"USBSTOR\VID_0951&PID_1666\AA00".into()),
            device_class: Some("DiskDrive".into()),
            location_path: None,
        }
        .into_candidate()
        .unwrap();
        let req = build_query_request("tx-1", cand);
        let (frame, audit) = handle_query(&sup, req).unwrap();
        let resp = crate::usb_ipc::decode_query_response(&frame).unwrap();
        assert!(resp.is_block());
        assert!(audit.contains(r#""decision":"block""#));
    }
}
