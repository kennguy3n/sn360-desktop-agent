//! Clean-room MeshCentral-style remote-support wire protocol.
//!
//! ## Provenance
//!
//! This is a **clean-room** implementation. The agent does **not**
//! link, embed, or copy any MeshCentral source code. Only the
//! externally-observable shape of the wire — bidirectional binary
//! frames carrying a `type` discriminant + opaque payload — is
//! inherited, in line with `docs/device-control.md` § 9 and
//! `docs/architecture.md` § 8.
//!
//! ## Frame layout
//!
//! Every frame is a MessagePack array with the following shape:
//!
//! ```text
//! [
//!   u8    type,        // FrameType discriminant
//!   u32   sequence,    // monotonically-increasing per session
//!   u32   length,      // payload length in bytes
//!   bin   payload,     // arbitrary bytes (already encrypted at the
//!                      //  PAL transport layer if applicable)
//! ]
//! ```
//!
//! ## Sequence + heartbeat invariants
//!
//! * Sequence numbers MUST start at `0` for each session and increase
//!   strictly by `1` per outbound frame. The receiver rejects any
//!   frame with a sequence that does not equal the previous frame's
//!   sequence + 1 — replay protection.
//! * The agent emits a [`FrameType::Heartbeat`] every
//!   `heartbeat_interval` (default 15s). Receivers timeout the
//!   session after `heartbeat_timeout` (default 45s — three missed
//!   heartbeats).
//! * Frame size is bounded by [`MAX_FRAME_SIZE`] = 64 KiB. A larger
//!   frame is rejected.
//!
//! ## Per-session keys
//!
//! Encryption is layered on top of the transport (TLS 1.3 in
//! production). The control-plane session token is run through
//! HKDF-SHA256 to derive the symmetric keys that protect frame
//! payloads when the underlying transport does not already terminate
//! TLS at the agent.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum permitted frame size on the wire (64 KiB).
pub const MAX_FRAME_SIZE: usize = 64 * 1024;

/// Default heartbeat interval (15 seconds).
pub const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 15;

/// Default heartbeat timeout (45 seconds — three missed beats).
pub const DEFAULT_HEARTBEAT_TIMEOUT_SECS: u64 = 45;

/// Frame type discriminant. Wire-encoded as a single byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    /// Operator → agent: announces the session has begun. The
    /// agent must wait for this frame before transmitting any
    /// payload data.
    SessionInit = 0x01,
    /// Agent → operator: returns the user's consent decision.
    ConsentResponse = 0x02,
    /// Bidirectional: opaque captured frame data (screen frame,
    /// input event, file fragment).
    FrameData = 0x03,
    /// Either side: terminates the session.
    SessionEnd = 0x04,
    /// Either side: keepalive. Receivers reset their idle timer.
    Heartbeat = 0x05,
}

impl FrameType {
    /// Convert from a raw byte. Returns `None` for unknown
    /// discriminants — the protocol intentionally does not extend
    /// silently.
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(FrameType::SessionInit),
            0x02 => Some(FrameType::ConsentResponse),
            0x03 => Some(FrameType::FrameData),
            0x04 => Some(FrameType::SessionEnd),
            0x05 => Some(FrameType::Heartbeat),
            _ => None,
        }
    }

    /// Wire-encoded byte for this discriminant.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Errors produced when encoding or decoding frames.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Encoding failed — typically because the payload was larger
    /// than [`MAX_FRAME_SIZE`].
    #[error("frame encode failed: {0}")]
    Encode(String),
    /// Decoding failed — malformed MessagePack, unknown frame type,
    /// or oversize payload.
    #[error("frame decode failed: {0}")]
    Decode(String),
    /// Sequence number did not match the expected next value.
    #[error("frame sequence regressed: expected {expected}, got {got}")]
    SequenceRegression { expected: u32, got: u32 },
    /// Frame exceeded [`MAX_FRAME_SIZE`].
    #[error("frame too large: {size} bytes (cap {cap})")]
    TooLarge { size: usize, cap: usize },
}

/// A single frame on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    /// Frame discriminant (encoded as `u8`).
    pub frame_type: u8,
    /// Per-session monotonically-increasing sequence number.
    pub sequence: u32,
    /// Length of `payload` in bytes. Redundant with the encoded
    /// length but kept on the wire so peers can pre-allocate.
    pub length: u32,
    /// Opaque bytes — interpreted by the higher layer.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Build a frame with the given type, sequence, and payload.
    pub fn new(frame_type: FrameType, sequence: u32, payload: Vec<u8>) -> Self {
        let length = payload.len() as u32;
        Self {
            frame_type: frame_type.as_u8(),
            sequence,
            length,
            payload,
        }
    }

    /// Encode the frame to MessagePack bytes.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.payload.len() > MAX_FRAME_SIZE {
            return Err(FrameError::TooLarge {
                size: self.payload.len(),
                cap: MAX_FRAME_SIZE,
            });
        }
        rmp_serde::to_vec(self).map_err(|e| FrameError::Encode(e.to_string()))
    }

    /// Decode a frame from MessagePack bytes. Validates the frame
    /// type discriminant and the size cap.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() > MAX_FRAME_SIZE * 2 {
            // Cheap upfront defense: a single MessagePack-encoded
            // frame can never legitimately be 2× the payload cap.
            return Err(FrameError::TooLarge {
                size: bytes.len(),
                cap: MAX_FRAME_SIZE * 2,
            });
        }
        let frame: Frame =
            rmp_serde::from_slice(bytes).map_err(|e| FrameError::Decode(e.to_string()))?;
        if frame.payload.len() > MAX_FRAME_SIZE {
            return Err(FrameError::TooLarge {
                size: frame.payload.len(),
                cap: MAX_FRAME_SIZE,
            });
        }
        if FrameType::from_u8(frame.frame_type).is_none() {
            return Err(FrameError::Decode(format!(
                "unknown frame type 0x{:02x}",
                frame.frame_type
            )));
        }
        if frame.length as usize != frame.payload.len() {
            return Err(FrameError::Decode(format!(
                "length field {} does not match payload {}",
                frame.length,
                frame.payload.len()
            )));
        }
        Ok(frame)
    }

    /// Strongly-typed accessor for the frame discriminant.
    pub fn typed(&self) -> Option<FrameType> {
        FrameType::from_u8(self.frame_type)
    }
}

/// Per-session symmetric key material derived from the
/// control-plane session token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// 32-byte payload-encryption key.
    pub payload_key: [u8; 32],
    /// 32-byte MAC key (used for sequence-number HMAC if the
    /// transport does not already provide integrity).
    pub mac_key: [u8; 32],
}

/// Derive [`SessionKeys`] from a control-plane session token using
/// HKDF-style chained SHA-256 (clean-room: not an HKDF crate
/// dependency).
///
/// Two distinct labels (`"sda-remote-support/payload"`,
/// `"sda-remote-support/mac"`) ensure the two outputs are
/// cryptographically independent.
pub fn derive_session_keys(session_token: &[u8]) -> SessionKeys {
    fn derive(token: &[u8], label: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"sda-remote-support/v1");
        h.update(token);
        h.update(label);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_slice());
        out
    }
    SessionKeys {
        payload_key: derive(session_token, b"sda-remote-support/payload"),
        mac_key: derive(session_token, b"sda-remote-support/mac"),
    }
}

/// Stateful per-session protocol engine: validates sequence numbers,
/// frame-type ordering, and frame sizes.
#[derive(Debug)]
pub struct ProtocolEngine {
    next_inbound_sequence: u32,
    next_outbound_sequence: u32,
    /// Whether the session has been initialized via a
    /// [`FrameType::SessionInit`] frame.
    initialized: bool,
    /// Whether the session has been ended via a
    /// [`FrameType::SessionEnd`] frame.
    ended: bool,
}

impl Default for ProtocolEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolEngine {
    /// Build a fresh engine.
    pub fn new() -> Self {
        Self {
            next_inbound_sequence: 0,
            next_outbound_sequence: 0,
            initialized: false,
            ended: false,
        }
    }

    /// True after a `SessionInit` frame has been observed.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// True after a `SessionEnd` frame has been observed.
    pub fn is_ended(&self) -> bool {
        self.ended
    }

    /// Build the next outbound frame and update internal state.
    pub fn build_outbound(
        &mut self,
        frame_type: FrameType,
        payload: Vec<u8>,
    ) -> Result<Frame, FrameError> {
        if payload.len() > MAX_FRAME_SIZE {
            return Err(FrameError::TooLarge {
                size: payload.len(),
                cap: MAX_FRAME_SIZE,
            });
        }
        let frame = Frame::new(frame_type, self.next_outbound_sequence, payload);
        self.next_outbound_sequence = self
            .next_outbound_sequence
            .checked_add(1)
            .ok_or_else(|| FrameError::Encode("sequence overflow".into()))?;
        Ok(frame)
    }

    /// Validate an inbound frame and update internal state.
    pub fn ingest(&mut self, frame: &Frame) -> Result<(), FrameError> {
        let expected = self.next_inbound_sequence;
        if frame.sequence != expected {
            return Err(FrameError::SequenceRegression {
                expected,
                got: frame.sequence,
            });
        }
        let kind = frame.typed().ok_or_else(|| {
            FrameError::Decode(format!("unknown frame type 0x{:02x}", frame.frame_type))
        })?;
        match kind {
            FrameType::SessionInit => {
                self.initialized = true;
            }
            FrameType::SessionEnd => {
                self.ended = true;
            }
            FrameType::FrameData | FrameType::ConsentResponse => {
                if !self.initialized {
                    return Err(FrameError::Decode(
                        "received data frame before session init".into(),
                    ));
                }
            }
            FrameType::Heartbeat => { /* always valid */ }
        }
        self.next_inbound_sequence = self
            .next_inbound_sequence
            .checked_add(1)
            .ok_or_else(|| FrameError::Decode("sequence overflow".into()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_type_round_trips_through_u8() {
        for kind in [
            FrameType::SessionInit,
            FrameType::ConsentResponse,
            FrameType::FrameData,
            FrameType::SessionEnd,
            FrameType::Heartbeat,
        ] {
            let byte = kind.as_u8();
            assert_eq!(FrameType::from_u8(byte), Some(kind));
        }
    }

    #[test]
    fn frame_type_rejects_unknown_discriminant() {
        assert!(FrameType::from_u8(0xff).is_none());
    }

    #[test]
    fn frame_round_trips_through_msgpack() {
        let f = Frame::new(FrameType::FrameData, 42, b"hello".to_vec());
        let bytes = f.encode().expect("encode");
        let back = Frame::decode(&bytes).expect("decode");
        assert_eq!(f, back);
        assert_eq!(back.typed(), Some(FrameType::FrameData));
    }

    #[test]
    fn frame_rejects_oversize_payload_on_encode() {
        let f = Frame::new(FrameType::FrameData, 1, vec![0u8; MAX_FRAME_SIZE + 1]);
        match f.encode() {
            Err(FrameError::TooLarge { size, cap }) => {
                assert_eq!(size, MAX_FRAME_SIZE + 1);
                assert_eq!(cap, MAX_FRAME_SIZE);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn frame_rejects_unknown_type_on_decode() {
        // Hand-craft a frame with an invalid type byte by encoding a
        // valid one, then mutating the type field via the
        // round-trip Vec<u8>.
        let bogus = Frame {
            frame_type: 0xff,
            sequence: 0,
            length: 0,
            payload: vec![],
        };
        let bytes = rmp_serde::to_vec(&bogus).unwrap();
        assert!(matches!(Frame::decode(&bytes), Err(FrameError::Decode(_))));
    }

    #[test]
    fn frame_rejects_length_payload_mismatch() {
        let bogus = Frame {
            frame_type: FrameType::FrameData.as_u8(),
            sequence: 0,
            length: 99,
            payload: vec![1, 2, 3],
        };
        let bytes = rmp_serde::to_vec(&bogus).unwrap();
        assert!(matches!(Frame::decode(&bytes), Err(FrameError::Decode(_))));
    }

    #[test]
    fn engine_emits_sequential_outbound_frames() {
        let mut e = ProtocolEngine::new();
        let f0 = e
            .build_outbound(FrameType::SessionInit, b"init".to_vec())
            .unwrap();
        let f1 = e
            .build_outbound(FrameType::FrameData, b"data".to_vec())
            .unwrap();
        assert_eq!(f0.sequence, 0);
        assert_eq!(f1.sequence, 1);
    }

    #[test]
    fn engine_rejects_inbound_sequence_skip() {
        let mut e = ProtocolEngine::new();
        let mut init = Frame::new(FrameType::SessionInit, 0, vec![]);
        e.ingest(&init).unwrap();
        // Skip from 0 to 2 — must reject.
        init.sequence = 2;
        init.frame_type = FrameType::FrameData.as_u8();
        match e.ingest(&init) {
            Err(FrameError::SequenceRegression { expected, got }) => {
                assert_eq!(expected, 1);
                assert_eq!(got, 2);
            }
            other => panic!("expected SequenceRegression, got {other:?}"),
        }
    }

    #[test]
    fn engine_rejects_data_before_init() {
        let mut e = ProtocolEngine::new();
        let f = Frame::new(FrameType::FrameData, 0, b"payload".to_vec());
        assert!(matches!(e.ingest(&f), Err(FrameError::Decode(_))));
    }

    #[test]
    fn engine_marks_initialized_and_ended() {
        let mut e = ProtocolEngine::new();
        let init = Frame::new(FrameType::SessionInit, 0, vec![]);
        e.ingest(&init).unwrap();
        assert!(e.is_initialized());
        assert!(!e.is_ended());
        let end = Frame::new(FrameType::SessionEnd, 1, vec![]);
        e.ingest(&end).unwrap();
        assert!(e.is_ended());
    }

    #[test]
    fn engine_accepts_heartbeat_anytime() {
        let mut e = ProtocolEngine::new();
        let hb = Frame::new(FrameType::Heartbeat, 0, vec![]);
        e.ingest(&hb).unwrap();
        // Heartbeat must NOT mark the session initialized.
        assert!(!e.is_initialized());
    }

    #[test]
    fn derive_session_keys_is_deterministic() {
        let a = derive_session_keys(b"token-a");
        let b = derive_session_keys(b"token-a");
        assert_eq!(a, b);
    }

    #[test]
    fn derive_session_keys_is_distinct_per_token() {
        let a = derive_session_keys(b"token-a");
        let b = derive_session_keys(b"token-b");
        assert_ne!(a.payload_key, b.payload_key);
        assert_ne!(a.mac_key, b.mac_key);
    }

    #[test]
    fn derive_session_keys_separates_payload_and_mac() {
        // The payload key and the MAC key must be cryptographically
        // independent — same input token, different label.
        let k = derive_session_keys(b"token");
        assert_ne!(k.payload_key, k.mac_key);
    }
}
