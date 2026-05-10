//! macOS USB enforcement (D2.4).
//!
//! The signed SystemExtension + NetworkExtension pair productionised
//! at GA time is intentionally **out of scope** for this module —
//! it lives under `packaging/macos/` and ships through the existing
//! `sn360-desktop-agent.app` bundle. What this module ships is the
//! companion user-mode policy service:
//!
//! * An [`IokitProperties`] parser that turns the `IOService`
//!   property dictionary keys (`idVendor`, `idProduct`,
//!   `kUSBSerialNumberString`, `IOClass`, `IOObjectClass`) into a
//!   [`crate::DeviceCandidate`].
//! * A Unix-domain-socket IPC server (the SystemExtension talks to
//!   the agent via XPC, but the user-mode policy service uses the
//!   same UDS server we expose on Linux so the agent has a single
//!   IPC contract on POSIX hosts).
//! * Synchronous parser tests so the user-mode service can be
//!   exercised on the linux CI box.
//!
//! The async server is [`tokio::net::UnixListener`]-based on macOS;
//! the parser-only types are portable.

#[cfg(target_os = "macos")]
use std::sync::Arc;

use crate::usb_ipc::{
    decode_query_request, encode_query_response, UsbIpcQueryRequest, UsbIpcQueryResponse,
    USB_IPC_PROTOCOL_VERSION,
};
use crate::usb_policy::{DeviceCandidate, DeviceClass};
use crate::usb_supervisor::UsbPolicySupervisor;

/// Default IPC socket path on macOS. The agent runs as root via
/// `launchd`; the path lives under `/var/run` so it persists across
/// the agent restart but is wiped on reboot.
pub const DEFAULT_MACOS_SOCKET_PATH: &str = "/var/run/sn360-desktop-agent/usb-policy.sock";

/// Errors specific to IOKit dictionary parsing.
#[derive(Debug, thiserror::Error)]
pub enum IokitParseError {
    /// The vendor / product id was present but not parseable as a
    /// 16-bit number.
    #[error("malformed {field} {value:?}")]
    MalformedNumber { field: &'static str, value: String },
}

/// Subset of the IOKit `IOService` property dictionary the user-mode
/// service inspects. The companion fetches them via
/// `IORegistryEntryCreateCFProperties` and packs them into this
/// shape before crossing the IPC boundary.
#[derive(Debug, Clone, Default)]
pub struct IokitProperties {
    /// `idVendor` — 16-bit unsigned. CoreFoundation surfaces this
    /// as a [`u32`] so we accept the wider type and validate range.
    pub vendor_id: Option<u32>,
    /// `idProduct` — 16-bit unsigned, same caveat.
    pub product_id: Option<u32>,
    /// `kUSBSerialNumberString` — opaque.
    pub serial: Option<String>,
    /// `IOObjectClass` — e.g. `IOUSBHostInterface`, `IOBluetoothDevice`.
    pub io_object_class: Option<String>,
    /// Full IOService path used for evidence correlation, e.g.
    /// `IOService:/AppleACPIPlatformExpert/PCI0/.../USB2.0 Hub@01100000`.
    pub io_service_path: Option<String>,
}

impl IokitProperties {
    /// Convert the property bag to a [`DeviceCandidate`].
    pub fn into_candidate(self) -> Result<DeviceCandidate, IokitParseError> {
        let device_class = self
            .io_object_class
            .as_deref()
            .map(map_io_object_class)
            .unwrap_or(DeviceClass::Other);
        let vendor_id = self
            .vendor_id
            .map(|n| u16_hex(n, "vendor_id"))
            .transpose()?;
        let product_id = self
            .product_id
            .map(|n| u16_hex(n, "product_id"))
            .transpose()?;
        Ok(DeviceCandidate {
            device_class,
            vendor_id,
            product_id,
            serial: self.serial.filter(|s| !s.is_empty()),
            bus_path: self.io_service_path,
        })
    }
}

fn map_io_object_class(s: &str) -> DeviceClass {
    match s.trim() {
        "IOUSBHostInterface" | "IOUSBHostDevice" | "IOUSBDevice" | "IOUSBInterface" => {
            DeviceClass::Usb
        }
        "IOMedia" | "IOBlockStorageDevice" => DeviceClass::Removable,
        "IOBluetoothDevice" => DeviceClass::Bluetooth,
        "IOAudioEngine" | "IOAudioDevice" => DeviceClass::Audio,
        "IOEthernetInterface" | "IOPPPSerialDevice" => DeviceClass::NetworkTether,
        _ => DeviceClass::Other,
    }
}

fn u16_hex(n: u32, field: &'static str) -> Result<String, IokitParseError> {
    if n > u32::from(u16::MAX) {
        return Err(IokitParseError::MalformedNumber {
            field,
            value: format!("{n:#x}"),
        });
    }
    Ok(format!("{n:04x}"))
}

/// Helper-side request constructor. Mirrors the Linux + Windows
/// helpers.
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

/// Service a single helper request.
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

#[cfg(target_os = "macos")]
pub mod async_server {
    use super::*;
    use std::path::Path;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;
    use tracing::{debug, error, info, warn};

    /// Bind a Unix-domain socket at `path` and serve requests
    /// forever. Identical contract to the Linux server.
    pub async fn serve(
        path: impl AsRef<Path>,
        supervisor: Arc<UsbPolicySupervisor>,
        on_audit: impl Fn(String) + Send + Sync + 'static,
    ) -> std::io::Result<()> {
        let path = path.as_ref();
        let _ = std::fs::remove_file(path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let listener = UnixListener::bind(path)?;
        info!(socket = %path.display(), "USB-policy IPC server bound (macOS)");
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

    #[test]
    fn parses_iousbhostinterface_props() {
        let p = IokitProperties {
            vendor_id: Some(0x05ac),
            product_id: Some(0x0220),
            serial: Some("ABC123".into()),
            io_object_class: Some("IOUSBHostInterface".into()),
            io_service_path: Some(
                "IOService:/AppleACPIPlatformExpert/PCI0/USB0/IOUSBHostInterface@1".into(),
            ),
        };
        let cand = p.into_candidate().unwrap();
        assert_eq!(cand.device_class, DeviceClass::Usb);
        assert_eq!(cand.vendor_id.as_deref(), Some("05ac"));
        assert_eq!(cand.product_id.as_deref(), Some("0220"));
        assert_eq!(cand.serial.as_deref(), Some("ABC123"));
    }

    #[test]
    fn unknown_io_object_class_maps_to_other() {
        let p = IokitProperties {
            io_object_class: Some("IOFutureThing".into()),
            ..Default::default()
        };
        assert_eq!(p.into_candidate().unwrap().device_class, DeviceClass::Other);
    }

    #[test]
    fn iomedia_maps_to_removable() {
        let p = IokitProperties {
            io_object_class: Some("IOMedia".into()),
            ..Default::default()
        };
        assert_eq!(
            p.into_candidate().unwrap().device_class,
            DeviceClass::Removable
        );
    }

    #[test]
    fn vendor_id_out_of_u16_range_is_rejected() {
        let p = IokitProperties {
            vendor_id: Some(0xFFFFFF),
            ..Default::default()
        };
        let err = p.into_candidate().unwrap_err();
        assert!(matches!(err, IokitParseError::MalformedNumber { .. }));
    }

    #[test]
    fn handle_query_uses_supervisor_for_block() {
        let cfg = UsbPolicySupervisorConfig {
            tenant_id: "tenant-a".into(),
            ..Default::default()
        };
        let sup = UsbPolicySupervisor::new(&cfg);
        let block = DevicePolicy {
            id: "00000000-0000-0000-0000-000000000001".into(),
            tenant_id: "tenant-a".into(),
            name: "block usb".into(),
            enabled: true,
            device_class: DeviceClass::Usb,
            match_block: PolicyMatch::default(),
            action: Action::Block,
            priority: 100,
            severity: 7,
        };
        sup.apply_bundle_slice(&serde_json::to_vec(&[block]).unwrap())
            .unwrap();

        let cand = IokitProperties {
            vendor_id: Some(0x05ac),
            product_id: Some(0x0220),
            serial: None,
            io_object_class: Some("IOUSBHostInterface".into()),
            io_service_path: None,
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
