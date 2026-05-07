use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Priority level for event processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Priority {
    /// Critical events that must never be deferred (active response, keepalive).
    Critical = 0,
    /// Normal operational events (real-time FIM, log collection).
    Normal = 1,
    /// Low-priority background events (baseline scans, inventory).
    Low = 2,
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
