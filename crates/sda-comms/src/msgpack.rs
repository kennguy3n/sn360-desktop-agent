//! MessagePack event serialization (Phase 5.6 / proposal § 8.2).
//!
//! This module is the opt-in alternative to `serde_json` when talking
//! to an SDA-aware server. Wazuh 4.x servers do not understand
//! MessagePack, so callers must only switch to this serializer when
//! `config.server.enhanced.serialization == "msgpack"`.
//!
//! The wire format is the standard `rmp-serde` named-struct encoding:
//! each [`EventKind`] variant is serialized as a MessagePack map whose
//! keys are the field names (`path`, `source`, `category`, …). This
//! lines up with the JSON encoding so a server bridge can convert
//! between the two without schema drift.
//!
//! The round-trip tests at the bottom of this file are the contract
//! the server implementation is expected to honour — adding a new
//! [`EventKind`] variant without a matching test here is the bug this
//! module is designed to catch.

use sda_event_bus::{Event, EventKind};
use thiserror::Error;

/// Errors produced by the MessagePack serializer.
#[derive(Debug, Error)]
pub enum MsgPackError {
    /// Encoding failed (serde or I/O error from `rmp-serde`).
    #[error("msgpack encode failed: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    /// Decoding failed (malformed frame, type mismatch, …).
    #[error("msgpack decode failed: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
}

/// Stateless encoder/decoder for [`EventKind`] and [`Event`] payloads.
///
/// The wrapper is a unit struct rather than a free function pair so
/// future extensions (compression, size limits, schema versioning)
/// have an obvious place to live without breaking callers.
#[derive(Debug, Default, Clone, Copy)]
pub struct MessagePackSerializer;

impl MessagePackSerializer {
    /// Encode a single [`EventKind`] to a MessagePack byte vector.
    pub fn encode_kind(&self, kind: &EventKind) -> Result<Vec<u8>, MsgPackError> {
        Ok(rmp_serde::to_vec_named(kind)?)
    }

    /// Decode a [`EventKind`] from a MessagePack byte slice.
    pub fn decode_kind(&self, bytes: &[u8]) -> Result<EventKind, MsgPackError> {
        Ok(rmp_serde::from_slice(bytes)?)
    }

    /// Encode a full [`Event`] (id, timestamp, source, priority, kind).
    pub fn encode_event(&self, event: &Event) -> Result<Vec<u8>, MsgPackError> {
        Ok(rmp_serde::to_vec_named(event)?)
    }

    /// Decode a full [`Event`] from a MessagePack byte slice.
    pub fn decode_event(&self, bytes: &[u8]) -> Result<Event, MsgPackError> {
        Ok(rmp_serde::from_slice(bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_event_bus::{Event, EventKind, Priority};

    /// Every `EventKind` variant the agent currently emits must
    /// round-trip losslessly through MessagePack. Adding a new
    /// variant that breaks this test is intentional — extend the
    /// coverage below rather than skip the variant.
    #[test]
    fn all_event_kinds_round_trip() {
        let ser = MessagePackSerializer;
        let kinds = vec![
            EventKind::FileCreated {
                path: "/etc/passwd".into(),
                syscheck_payload: Some("{\"type\":\"added\"}".into()),
            },
            EventKind::FileModified {
                path: "/etc/passwd".into(),
                syscheck_payload: None,
            },
            EventKind::FileDeleted {
                path: "/etc/passwd".into(),
                syscheck_payload: None,
            },
            EventKind::FileMetadataChanged {
                path: "/etc/passwd".into(),
                syscheck_payload: None,
            },
            EventKind::LogCollected {
                source: "/var/log/auth.log".into(),
                message: "Accepted publickey for root".into(),
                format: "syslog".into(),
            },
            EventKind::InventoryUpdate {
                category: "packages".into(),
                data: serde_json::json!({ "name": "bash", "version": "5.2" }),
            },
            EventKind::EnhancedInventoryUpdate {
                category: "running_software".into(),
                data: serde_json::json!({ "pid": 1, "name": "systemd" }),
            },
            EventKind::ScaResult {
                policy_id: "cis_ubuntu_22_04".into(),
                check_id: "1.1.1".into(),
                result: "passed".into(),
            },
            EventKind::RootcheckAlert {
                category: "signature".into(),
                title: "Known rootkit path".into(),
                subject: "/dev/.udev".into(),
                description: "path matches signature #42".into(),
            },
            EventKind::LocalDetectionAlert {
                rule_id: "ioc-domain-1234".into(),
                rule_type: "ioc".into(),
                severity: "high".into(),
                description: "known C2 domain".into(),
                matched_value: "evil.example.com".into(),
            },
            EventKind::ActiveResponseRequest {
                action: "firewall-drop".into(),
                parameters: serde_json::json!({ "ip": "1.2.3.4" }),
            },
            EventKind::ActiveResponseResult {
                action: "firewall-drop".into(),
                success: true,
                output: String::new(),
            },
            EventKind::Keepalive,
            EventKind::Shutdown,
            EventKind::ConfigReloaded,
            EventKind::ServerMessage {
                payload: "hello".into(),
            },
            EventKind::ServerCommand {
                command: "syscheck:rescan".into(),
                payload: String::new(),
            },
            // Device Control variants — every variant added under the
            // Phase 0 wire-schema sign-off must round-trip through
            // MessagePack so the Agent Gateway can decode them on the
            // server side.
            EventKind::DeviceControlFinding {
                payload: r#"{"finding_id":"f1","kind":"permanent_admin"}"#.into(),
            },
            EventKind::DeviceControlRecommendation {
                payload: r#"{"recommendation_id":"r1"}"#.into(),
            },
            EventKind::DeviceControlActionResult {
                payload: r#"{"action_result_id":"ar1","status":"success"}"#.into(),
            },
            EventKind::DevicePostureState {
                payload: r#"{"disk_encryption":"on"}"#.into(),
            },
            EventKind::SoftwareInventoryDelta {
                payload: r#"{"added":[],"removed":[]}"#.into(),
            },
            EventKind::SoftwareJobResult {
                payload: r#"{"job_id":"j1","status":"success"}"#.into(),
            },
            EventKind::JitAdminRequested {
                payload: r#"{"user":"alice"}"#.into(),
            },
            EventKind::JitAdminGranted {
                payload: r#"{"user":"alice","until":"2026-05-08T00:00:00Z"}"#.into(),
            },
            EventKind::JitAdminRevoked {
                payload: r#"{"user":"alice"}"#.into(),
            },
            EventKind::QueryResult {
                payload: r#"{"query_id":"q1","rows":[]}"#.into(),
            },
            EventKind::ScriptRunResult {
                payload: r#"{"script_id":"s1","exit":0}"#.into(),
            },
            EventKind::RemoteSupportSessionStarted {
                payload: r#"{"session_id":"rs1"}"#.into(),
            },
            EventKind::RemoteSupportSessionEnded {
                payload: r#"{"session_id":"rs1"}"#.into(),
            },
            EventKind::AgentVitals {
                payload: r#"{"rss_mb":12,"cpu_percent":0.05}"#.into(),
            },
            EventKind::EvidenceRecord {
                payload: r#"{"record_id":"er1","prev_hash":""}"#.into(),
            },
        ];

        for kind in &kinds {
            let bytes = ser.encode_kind(kind).expect("encode");
            assert!(
                !bytes.is_empty(),
                "encoded payload for {kind:?} must be non-empty"
            );
            let decoded = ser.decode_kind(&bytes).expect("decode");
            // EventKind doesn't impl PartialEq, so compare by JSON
            // projection — cheap and good enough for a smoke test.
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                serde_json::to_value(&decoded).unwrap(),
            );
        }
    }

    #[test]
    fn full_event_round_trips() {
        let ser = MessagePackSerializer;
        let evt = Event::new(
            "fim",
            Priority::Normal,
            EventKind::FileCreated {
                path: "/tmp/new".into(),
                syscheck_payload: None,
            },
        );
        let bytes = ser.encode_event(&evt).unwrap();
        let back = ser.decode_event(&bytes).unwrap();
        assert_eq!(back.id, evt.id);
        assert_eq!(back.source, evt.source);
        assert_eq!(back.priority, evt.priority);
    }

    #[test]
    fn msgpack_payload_is_smaller_than_json_for_inventory() {
        // Sanity check on the "50-70% smaller than JSON" claim from
        // the proposal (§ 8.2). Not a strict regression gate — we
        // just want to flag if the encoding accidentally regresses
        // to larger-than-JSON output.
        let ser = MessagePackSerializer;
        let kind = EventKind::InventoryUpdate {
            category: "packages".into(),
            data: serde_json::json!({
                "packages": (0..50).map(|i| serde_json::json!({
                    "name": format!("pkg-{i}"),
                    "version": format!("1.{i}.0"),
                    "vendor": "vendor-{i}",
                })).collect::<Vec<_>>(),
            }),
        };
        let msgpack = ser.encode_kind(&kind).unwrap();
        let json = serde_json::to_vec(&kind).unwrap();
        assert!(
            msgpack.len() < json.len(),
            "msgpack ({} B) should be smaller than JSON ({} B)",
            msgpack.len(),
            json.len()
        );
    }

    #[test]
    fn decoding_garbage_returns_error_not_panic() {
        let ser = MessagePackSerializer;
        let err = ser.decode_kind(&[0xff, 0x00, 0xde, 0xad]).unwrap_err();
        assert!(
            matches!(err, MsgPackError::Decode(_)),
            "expected decode error, got {err:?}"
        );
    }
}
