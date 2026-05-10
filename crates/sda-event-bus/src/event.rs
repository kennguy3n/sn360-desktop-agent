use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Priority level for event processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Priority {
    /// Critical events that must never be deferred (active response, keepalive).
    Critical = 0,
    /// High-priority events that should run ahead of normal operational
    /// traffic but are not as time-critical as `Critical` (e.g. Device
    /// Control findings, signed-job action results, evidence records).
    High = 1,
    /// Normal operational events (real-time FIM, log collection).
    Normal = 2,
    /// Low-priority background events (baseline scans, inventory,
    /// posture snapshots, agent vitals).
    Low = 3,
}

/// The kind of event flowing through the bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventKind {
    // --- FIM events ---
    /// A file was created.
    FileCreated {
        path: String,
        /// Pre-formatted Wazuh syscheck JSON payload.
        syscheck_payload: Option<String>,
    },
    /// A file was modified.
    FileModified {
        path: String,
        /// Pre-formatted Wazuh syscheck JSON payload.
        syscheck_payload: Option<String>,
    },
    /// A file was deleted.
    FileDeleted {
        path: String,
        /// Pre-formatted Wazuh syscheck JSON payload.
        syscheck_payload: Option<String>,
    },
    /// A file's metadata (permissions, ownership) changed.
    FileMetadataChanged {
        path: String,
        /// Pre-formatted Wazuh syscheck JSON payload.
        syscheck_payload: Option<String>,
    },

    // --- Log events ---
    /// A new log line was collected.
    LogCollected {
        source: String,
        message: String,
        format: String,
    },

    // --- Inventory events ---
    /// System inventory was updated.
    InventoryUpdate {
        category: String,
        data: serde_json::Value,
    },

    // --- Enhanced inventory events ---
    /// Enhanced inventory snapshot or delta.
    ///
    /// `category` is one of `"running_software"`, `"browser_extensions"`,
    /// or `"sbom"` and `data` carries the module-specific payload
    /// (typically a JSON object matching the Wazuh syscollector schema
    /// so the manager can index it alongside the base inventory).
    EnhancedInventoryUpdate {
        category: String,
        data: serde_json::Value,
    },

    // --- SCA events ---
    /// SCA check result.
    ScaResult {
        policy_id: String,
        check_id: String,
        result: String,
    },

    // --- Rootcheck events ---
    /// A rootkit indicator or integrity violation was detected.
    RootcheckAlert {
        /// Category of the alert: "signature", "hidden_process", or "binary_integrity".
        category: String,
        /// Human-readable title of the alert.
        title: String,
        /// Path or subject of the alert (file path, PID, binary path).
        subject: String,
        /// Free-form description of what triggered the alert.
        description: String,
    },

    // --- Local Detection Engine (LDE) events ---
    /// A local detection rule (IOC, behavioral, or YARA) matched an event.
    LocalDetectionAlert {
        /// Identifier of the matched rule (e.g., "ioc-domain-1234", "behav-brute-ssh").
        rule_id: String,
        /// Type of rule that matched: "ioc", "behavioral", or "yara".
        rule_type: String,
        /// Severity: "info", "low", "medium", "high", "critical".
        severity: String,
        /// Human-readable description of the match.
        description: String,
        /// The value from the source event that triggered the match
        /// (path, domain, hash, PID, etc.).
        matched_value: String,
    },

    // --- Active Response events ---
    /// Request to execute an active response action.
    ActiveResponseRequest {
        action: String,
        parameters: serde_json::Value,
    },
    /// Active response execution result.
    ActiveResponseResult {
        action: String,
        success: bool,
        output: String,
    },

    // --- Agent lifecycle events ---
    /// Agent keepalive to server.
    Keepalive,
    /// Agent is shutting down.
    Shutdown,
    /// Configuration was reloaded.
    ConfigReloaded,

    // --- Communication events ---
    /// Message to be sent to the server.
    ServerMessage { payload: String },
    /// Message received from the server.
    ServerCommand { command: String, payload: String },

    // --- Device Control events (Phase 1) ---
    //
    // The agent encodes Device Control payloads as already-serialized
    // canonical JSON strings so the bus does not need to know the per-
    // schema type system. The full Rust definitions live in
    // `crates/sda-device-control` (see SCHEMAS.md § 5–9).
    /// A Device Control `Finding` was emitted (admin/posture/software
    /// observation). Payload: canonical JSON of `Finding`.
    DeviceControlFinding { payload: String },
    /// A Device Control `Recommendation` was received from the control
    /// plane (informational on the agent side). Payload: canonical JSON
    /// of `Recommendation`.
    DeviceControlRecommendation { payload: String },
    /// A Device Control `ActionResult` for a `SignedActionJob` the
    /// agent executed. Payload: canonical JSON of `ActionResult`.
    DeviceControlActionResult { payload: String },
    /// A device-posture snapshot delta (BitLocker / FileVault / LUKS,
    /// firewall, screen-lock, patch level, OS version). Payload:
    /// canonical JSON of `PostureSnapshot`.
    DevicePostureState { payload: String },
    /// A software-inventory delta from `sda-enhanced-inventory`
    /// re-shaped for Device Control consumers. Payload: canonical JSON
    /// matching the SoftwareInventoryDelta wire schema.
    SoftwareInventoryDelta { payload: String },
    /// Per-package outcome of a software job (install/update/uninstall).
    /// Payload: canonical JSON of the SoftwareJobResult wire schema.
    SoftwareJobResult { payload: String },
    /// A user-initiated JIT admin request reached the agent.
    /// Payload: canonical JSON of the JitAdminRequested wire schema.
    JitAdminRequested { payload: String },
    /// JIT admin grant succeeded; payload includes user, expiry,
    /// `GrantHandle`. Payload: canonical JSON.
    JitAdminGranted { payload: String },
    /// JIT admin grant was revoked (timer, watchdog, drift, or
    /// operator). Payload: canonical JSON.
    JitAdminRevoked { payload: String },
    /// Result of a scheduled or ad-hoc query (osquery, etc.).
    /// Payload: canonical JSON containing query id + rows.
    QueryResult { payload: String },
    /// Result of a `RunScript` action — exit code + truncated output
    /// + sha256 of the full output. Payload: canonical JSON.
    ScriptRunResult { payload: String },
    /// A remote-support session started (operator id, session id,
    /// consent state). Payload: canonical JSON.
    RemoteSupportSessionStarted { payload: String },
    /// A remote-support session ended (reason + duration). Payload:
    /// canonical JSON.
    RemoteSupportSessionEnded { payload: String },
    /// An app-control policy was applied (mode, rule count, signing
    /// key). Payload: canonical JSON.
    AppControlPolicyApplied { payload: String },
    /// An app-control enforcement decision (allow/deny + subject).
    /// Payload: canonical JSON.
    AppControlDecision { payload: String },
    /// Periodic agent vitals heartbeat — queue depth, watchdog faults,
    /// module health. Payload: canonical JSON of the AgentVitals wire
    /// schema.
    AgentVitals { payload: String },
    /// A signed Device Control evidence record produced as the audit
    /// projection of an `ActionResult`. Payload: canonical JSON of
    /// `EvidenceRecord`.
    EvidenceRecord { payload: String },

    /// A USB / removable-media policy decision (Phase D2). Emitted
    /// once per OS attach event the supervisor evaluates. Payload:
    /// RFC 8785 canonical JSON `{ "connector_type": "device-control",
    /// "tenant_id": ..., "decision": "block"|"allow"|"audit",
    /// "device": { ... }, "matched_policy": { ... } }` envelope
    /// produced by `sda_device_control::usb_policy::Decision::to_event_payload`.
    UsbDevicePolicyDecision { payload: String },
}

/// An event that flows through the event bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unique event identifier.
    pub id: u64,
    /// When the event was created.
    pub timestamp: DateTime<Utc>,
    /// Source module that generated this event.
    pub source: String,
    /// Priority level.
    pub priority: Priority,
    /// The event payload.
    pub kind: EventKind,
}

impl Event {
    /// Create a new event with auto-generated ID and timestamp.
    pub fn new(source: impl Into<String>, priority: Priority, kind: EventKind) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);

        Self {
            id: COUNTER.fetch_add(1, Ordering::Relaxed),
            timestamp: Utc::now(),
            source: source.into(),
            priority,
            kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_order_critical_high_normal_low() {
        // The ordering matters for the priority queue: Critical < High <
        // Normal < Low (smaller = higher priority).
        assert!(Priority::Critical < Priority::High);
        assert!(Priority::High < Priority::Normal);
        assert!(Priority::Normal < Priority::Low);
    }

    fn dc_event_kinds() -> Vec<EventKind> {
        let payload = r#"{"k":"v"}"#.to_string();
        vec![
            EventKind::DeviceControlFinding {
                payload: payload.clone(),
            },
            EventKind::DeviceControlRecommendation {
                payload: payload.clone(),
            },
            EventKind::DeviceControlActionResult {
                payload: payload.clone(),
            },
            EventKind::DevicePostureState {
                payload: payload.clone(),
            },
            EventKind::SoftwareInventoryDelta {
                payload: payload.clone(),
            },
            EventKind::SoftwareJobResult {
                payload: payload.clone(),
            },
            EventKind::JitAdminRequested {
                payload: payload.clone(),
            },
            EventKind::JitAdminGranted {
                payload: payload.clone(),
            },
            EventKind::JitAdminRevoked {
                payload: payload.clone(),
            },
            EventKind::QueryResult {
                payload: payload.clone(),
            },
            EventKind::ScriptRunResult {
                payload: payload.clone(),
            },
            EventKind::RemoteSupportSessionStarted {
                payload: payload.clone(),
            },
            EventKind::RemoteSupportSessionEnded {
                payload: payload.clone(),
            },
            EventKind::AppControlPolicyApplied {
                payload: payload.clone(),
            },
            EventKind::AppControlDecision {
                payload: payload.clone(),
            },
            EventKind::AgentVitals {
                payload: payload.clone(),
            },
            EventKind::EvidenceRecord { payload },
        ]
    }

    #[test]
    fn device_control_event_kinds_round_trip_via_serde_json() {
        for kind in dc_event_kinds() {
            let json = serde_json::to_string(&kind).expect("encode");
            let back: EventKind = serde_json::from_str(&json).expect("decode");
            // Round-trip through canonical JSON re-encode to compare,
            // because EventKind has no PartialEq.
            let again = serde_json::to_string(&back).expect("re-encode");
            assert_eq!(json, again, "DC event kind did not round-trip cleanly");
        }
    }

    #[test]
    fn device_control_event_kinds_preserve_payload() {
        let payload = r#"{"finding_id":"abc","kind":"permanent_admin"}"#;
        let kind = EventKind::DeviceControlFinding {
            payload: payload.to_string(),
        };
        let json = serde_json::to_string(&kind).expect("encode");
        // The payload string must be present verbatim in the JSON
        // representation of the variant.
        assert!(json.contains("permanent_admin"));
        assert!(json.contains("DeviceControlFinding"));
    }

    #[test]
    fn device_control_event_count_matches_phase0_signoff() {
        // Phase 0 task 0.12 froze the EventKind sign-off list at 15
        // Device Control variants. Phase 4 added 2 app-control
        // variants → 17. Any change requires a new ADR + a major
        // schema-version bump (SCHEMAS.md § 11).
        assert_eq!(dc_event_kinds().len(), 17);
    }
}
