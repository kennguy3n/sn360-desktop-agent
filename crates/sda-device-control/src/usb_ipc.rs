//! Hermetic IPC wire format shared by every per-OS USB-policy
//! helper.
//!
//! The agent runs the [`crate::usb_supervisor::UsbPolicySupervisor`]
//! which owns the [`crate::DevicePolicyStore`]. The OS-specific
//! helpers (Linux `sn360-device-control-helper`, Windows class
//! filter user-mode service, macOS NetworkExtension companion) talk
//! to the supervisor over a platform-native byte stream — Unix
//! domain socket on Linux/macOS, named pipe on Windows.
//!
//! To keep the helpers small (they may be pulled out of `udev`
//! environments where dynamic-linker quirks matter), the wire
//! format is line-delimited JSON, ASCII-only, with a fixed
//! `\n` framing. The helper writes a [`UsbIpcQueryRequest`] line,
//! reads a [`UsbIpcQueryResponse`] line, and exits.
//!
//! The wire envelope is intentionally a different shape from the
//! audit envelope (see [`crate::UsbPolicyDecision::to_event_payload`]):
//! the IPC envelope is private to the agent and can evolve
//! independently of the audit decoder.

use serde::{Deserialize, Serialize};

use crate::usb_policy::{Action, Decision, DeviceCandidate};

/// Maximum size of a single IPC frame. Generously sized — even a
/// pathologically long bus path is well under this limit. Anything
/// larger is malformed and the supervisor rejects it.
pub const USB_IPC_FRAME_MAX_BYTES: usize = 64 * 1024;

/// Wire-stable protocol version. Bumped on incompatible changes
/// only; additive optional fields keep `v` at `1`.
pub const USB_IPC_PROTOCOL_VERSION: u32 = 1;

/// IPC errors returned by [`encode_query_request`] /
/// [`decode_query_request`] / [`encode_query_response`] /
/// [`decode_query_response`].
#[derive(Debug, thiserror::Error)]
pub enum UsbIpcError {
    /// Frame exceeded [`USB_IPC_FRAME_MAX_BYTES`].
    #[error("ipc frame {got} bytes exceeds limit of {limit} bytes")]
    FrameTooLarge { got: usize, limit: usize },
    /// JSON encode/decode failed.
    #[error("ipc frame is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Protocol version mismatch.
    #[error("ipc protocol version {got} not supported (this build understands {supported})")]
    UnsupportedVersion { got: u32, supported: u32 },
}

/// Request a policy decision for a device the OS just attached.
///
/// All fields except `device_class` are optional and map directly
/// onto [`DeviceCandidate`]. The `transaction_id` is opaque — the
/// helper echoes it in the response so it can correlate logs even
/// if the underlying socket multiplexes (it currently does not,
/// but the field future-proofs the wire).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsbIpcQueryRequest {
    /// Wire format version. Must equal [`USB_IPC_PROTOCOL_VERSION`].
    pub v: u32,
    /// Opaque correlation id chosen by the helper.
    pub transaction_id: String,
    /// Device candidate built from the OS attach event.
    pub candidate: DeviceCandidate,
}

/// Response from the supervisor. The helper uses `action` to
/// decide between exit code 0 (allow/audit) and exit code 1 (block).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsbIpcQueryResponse {
    /// Wire format version. Must equal [`USB_IPC_PROTOCOL_VERSION`].
    pub v: u32,
    /// Opaque correlation id, copied verbatim from the request.
    pub transaction_id: String,
    /// Decision payload.
    pub decision: Decision,
    /// `true` when the supervisor's policy set was empty/disabled
    /// (boot path or post-tampered-bundle path) and the decision
    /// fell back to the configured default. Helpers can log this
    /// to make it easy to spot agents that have not yet pulled a
    /// verified bundle.
    pub default_action_used: bool,
}

impl UsbIpcQueryResponse {
    /// `true` when the helper should refuse the OS attach.
    pub fn is_block(&self) -> bool {
        self.decision.action == Action::Block
    }
}

/// Encode a query request as a single newline-terminated frame.
pub fn encode_query_request(req: &UsbIpcQueryRequest) -> Result<Vec<u8>, UsbIpcError> {
    let mut buf = serde_json::to_vec(req)?;
    if buf.len() + 1 > USB_IPC_FRAME_MAX_BYTES {
        return Err(UsbIpcError::FrameTooLarge {
            got: buf.len() + 1,
            limit: USB_IPC_FRAME_MAX_BYTES,
        });
    }
    buf.push(b'\n');
    Ok(buf)
}

/// Decode a query request from a single line. Strips a trailing
/// newline if present so callers can pass either the raw line or
/// the framed line interchangeably.
pub fn decode_query_request(bytes: &[u8]) -> Result<UsbIpcQueryRequest, UsbIpcError> {
    if bytes.len() > USB_IPC_FRAME_MAX_BYTES {
        return Err(UsbIpcError::FrameTooLarge {
            got: bytes.len(),
            limit: USB_IPC_FRAME_MAX_BYTES,
        });
    }
    let trimmed = strip_trailing_newline(bytes);
    let req: UsbIpcQueryRequest = serde_json::from_slice(trimmed)?;
    if req.v != USB_IPC_PROTOCOL_VERSION {
        return Err(UsbIpcError::UnsupportedVersion {
            got: req.v,
            supported: USB_IPC_PROTOCOL_VERSION,
        });
    }
    Ok(req)
}

/// Encode a query response as a single newline-terminated frame.
pub fn encode_query_response(resp: &UsbIpcQueryResponse) -> Result<Vec<u8>, UsbIpcError> {
    let mut buf = serde_json::to_vec(resp)?;
    if buf.len() + 1 > USB_IPC_FRAME_MAX_BYTES {
        return Err(UsbIpcError::FrameTooLarge {
            got: buf.len() + 1,
            limit: USB_IPC_FRAME_MAX_BYTES,
        });
    }
    buf.push(b'\n');
    Ok(buf)
}

/// Decode a query response from a single line.
pub fn decode_query_response(bytes: &[u8]) -> Result<UsbIpcQueryResponse, UsbIpcError> {
    if bytes.len() > USB_IPC_FRAME_MAX_BYTES {
        return Err(UsbIpcError::FrameTooLarge {
            got: bytes.len(),
            limit: USB_IPC_FRAME_MAX_BYTES,
        });
    }
    let trimmed = strip_trailing_newline(bytes);
    let resp: UsbIpcQueryResponse = serde_json::from_slice(trimmed)?;
    if resp.v != USB_IPC_PROTOCOL_VERSION {
        return Err(UsbIpcError::UnsupportedVersion {
            got: resp.v,
            supported: USB_IPC_PROTOCOL_VERSION,
        });
    }
    Ok(resp)
}

fn strip_trailing_newline(b: &[u8]) -> &[u8] {
    if b.last().copied() == Some(b'\n') {
        &b[..b.len() - 1]
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb_policy::DeviceClass;

    fn req() -> UsbIpcQueryRequest {
        UsbIpcQueryRequest {
            v: USB_IPC_PROTOCOL_VERSION,
            transaction_id: "tx-1".into(),
            candidate: DeviceCandidate {
                device_class: DeviceClass::Usb,
                vendor_id: Some("05ac".into()),
                product_id: Some("0220".into()),
                serial: Some("ABC".into()),
                bus_path: Some("/sys/bus/usb/devices/3-1".into()),
            },
        }
    }

    fn resp() -> UsbIpcQueryResponse {
        UsbIpcQueryResponse {
            v: USB_IPC_PROTOCOL_VERSION,
            transaction_id: "tx-1".into(),
            decision: Decision {
                action: Action::Block,
                matched_policy_id: Some("p-1".into()),
                matched_policy_name: Some("block all usb".into()),
                severity: 7,
            },
            default_action_used: false,
        }
    }

    #[test]
    fn request_round_trip() {
        let line = encode_query_request(&req()).unwrap();
        assert_eq!(line.last().copied(), Some(b'\n'));
        let back = decode_query_request(&line).unwrap();
        assert_eq!(back, req());
    }

    #[test]
    fn response_round_trip() {
        let line = encode_query_response(&resp()).unwrap();
        let back = decode_query_response(&line).unwrap();
        assert_eq!(back, resp());
    }

    #[test]
    fn rejects_bad_version() {
        let bad = serde_json::to_vec(&serde_json::json!({
            "v": 99,
            "transaction_id": "x",
            "candidate": { "device_class": "usb" }
        }))
        .unwrap();
        let err = decode_query_request(&bad).unwrap_err();
        assert!(matches!(err, UsbIpcError::UnsupportedVersion { .. }));
    }

    #[test]
    fn rejects_oversize_frame() {
        let big = vec![b'x'; USB_IPC_FRAME_MAX_BYTES + 1];
        let err = decode_query_request(&big).unwrap_err();
        assert!(matches!(err, UsbIpcError::FrameTooLarge { .. }));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let bad =
            br#"{"v":1,"transaction_id":"x","candidate":{"device_class":"usb"},"unexpected":1}"#;
        let err = decode_query_request(bad).unwrap_err();
        assert!(matches!(err, UsbIpcError::Json(_)));
    }
}
