//! Wazuh protocol message formatting.
//!
//! Implements the Wazuh wire protocol. Messages are encrypted with
//! Blowfish-CBC or AES-256-CBC. The agent ID is sent in the clear as a
//! routing prefix; only the message body is encrypted.
//!
//! On the wire (TCP): `4-byte-length | agent_id ":" encrypted_body`

use serde::{Deserialize, Serialize};

/// Wazuh protocol message types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Syscheck (FIM) event.
    Syscheck,
    /// Log collection event.
    Log,
    /// Rootcheck event.
    Rootcheck,
    /// SCA event.
    Sca,
    /// Syscollector (inventory) event.
    Syscollector,
    /// Agent keepalive.
    Keepalive,
    /// Active response result.
    ActiveResponse,
    /// Agent startup notification.
    Startup,
    /// Agent shutdown notification.
    Shutdown,
    /// Request from server.
    Request,
    /// Local Detection Engine alert (edge-generated detection).
    LocalDetection,

    // --- Device Control message types (Phase 1) ---
    //
    // Device Control traffic uses the SN360 native protocol path
    // (TLS 1.3 + MessagePack/JSON envelopes routed by the Agent
    // Gateway in `sn360-security-platform`). When the agent is
    // talking to a legacy Wazuh manager these frames are still
    // forwarded as logcollector messages with a `device-control:*`
    // source tag so that operators on the legacy console can at
    // least see them as raw JSON, but the canonical wire path is
    // the native one (see ARCHITECTURE.md § 4 and SCHEMAS.md § 4).
    /// Device Control `Finding` payload.
    DeviceControlFinding,
    /// Device Control `Recommendation` payload.
    DeviceControlRecommendation,
    /// Inbound `SignedActionJob` from the control plane (consumed by
    /// `sda-device-control::router` — this variant has no matching
    /// outbound `EventKind`).
    DeviceControlJob,
    /// Outbound `ActionResult` for an executed `SignedActionJob`.
    DeviceControlActionResult,
    /// Device-posture snapshot delta.
    DevicePostureState,
    /// Software-inventory delta.
    SoftwareInventoryDelta,
    /// Per-package outcome of a software job.
    SoftwareJobResult,
    /// JIT-admin grant request reached the agent.
    JitAdminRequested,
    /// JIT-admin grant succeeded.
    JitAdminGranted,
    /// JIT-admin grant revoked.
    JitAdminRevoked,
    /// Result of a scheduled or ad-hoc query (osquery, …).
    QueryResult,
    /// Result of a `RunScript` action.
    ScriptRunResult,
    /// A remote-support session started.
    RemoteSupportSessionStarted,
    /// A remote-support session ended.
    RemoteSupportSessionEnded,
    /// Periodic agent vitals heartbeat.
    AgentVitals,
    /// Signed Device Control evidence record.
    EvidenceRecord,
    /// USB / removable-media policy decision (Phase D2). One per
    /// OS attach event the supervisor evaluates.
    UsbDevicePolicyDecision,

    // --- Desktop MDM message types (Phase M1–M3) ---
    /// Result of a `RemoteWipe` action.
    MdmWipeResult,
    /// Result of a `RemoteLock` action.
    MdmLockResult,
    /// `EnterLostMode` action completed.
    MdmLostModeEntered,
    /// `ExitLostMode` action completed.
    MdmLostModeExited,
    /// Recovery key escrow envelope (encrypted via ChaCha20-Poly1305).
    MdmRecoveryKeyEscrowed,
    /// Result of an `InstallOsUpdate` action.
    MdmOsUpdateResult,
    /// A signed config profile was applied.
    MdmConfigProfileApplied,
    /// Auto-remediation supervisor finished a self-signed local job.
    MdmAutoRemediationResult,

    /// Generic message.
    Generic,
}

impl MessageType {
    /// Get the Wazuh protocol string for this message type.
    pub fn as_protocol_str(&self) -> &'static str {
        match self {
            MessageType::Syscheck => "syscheck",
            MessageType::Log => "log",
            MessageType::Rootcheck => "rootcheck",
            MessageType::Sca => "sca",
            MessageType::Syscollector => "syscollector",
            MessageType::Keepalive => "keep_alive",
            MessageType::ActiveResponse => "active-response",
            MessageType::Startup => "agent_start",
            MessageType::Shutdown => "agent_stop",
            MessageType::Request => "request",
            MessageType::LocalDetection => "local-detection",
            // Device Control protocol strings — kept stable; the Phase
            // 0 wire-schema sign-off freezes them as the canonical
            // names used by the Agent Gateway in
            // `sn360-security-platform`.
            MessageType::DeviceControlFinding => "device-control-finding",
            MessageType::DeviceControlRecommendation => "device-control-recommendation",
            MessageType::DeviceControlJob => "device-control-job",
            MessageType::DeviceControlActionResult => "device-control-action-result",
            MessageType::DevicePostureState => "device-posture-state",
            MessageType::SoftwareInventoryDelta => "software-inventory-delta",
            MessageType::SoftwareJobResult => "software-job-result",
            MessageType::JitAdminRequested => "jit-admin-requested",
            MessageType::JitAdminGranted => "jit-admin-granted",
            MessageType::JitAdminRevoked => "jit-admin-revoked",
            MessageType::QueryResult => "query-result",
            MessageType::ScriptRunResult => "script-run-result",
            MessageType::RemoteSupportSessionStarted => "remote-support-session-started",
            MessageType::RemoteSupportSessionEnded => "remote-support-session-ended",
            MessageType::AgentVitals => "agent-vitals",
            MessageType::EvidenceRecord => "evidence-record",
            MessageType::UsbDevicePolicyDecision => "usb-device-policy-decision",
            // Desktop MDM (Phase M1–M3). These wire strings are part
            // of the public contract — any change is a major schema
            // version bump (see SCHEMAS.md § 11).
            MessageType::MdmWipeResult => "mdm-wipe-result",
            MessageType::MdmLockResult => "mdm-lock-result",
            MessageType::MdmLostModeEntered => "mdm-lost-mode-entered",
            MessageType::MdmLostModeExited => "mdm-lost-mode-exited",
            MessageType::MdmRecoveryKeyEscrowed => "mdm-recovery-key-escrowed",
            MessageType::MdmOsUpdateResult => "mdm-os-update-result",
            MessageType::MdmConfigProfileApplied => "mdm-config-profile-applied",
            MessageType::MdmAutoRemediationResult => "mdm-auto-remediation-result",
            MessageType::Generic => "message",
        }
    }

    /// Parse a protocol string into a message type.
    pub fn from_protocol_str(s: &str) -> Self {
        match s {
            "syscheck" => MessageType::Syscheck,
            "log" => MessageType::Log,
            "rootcheck" => MessageType::Rootcheck,
            "sca" => MessageType::Sca,
            "syscollector" => MessageType::Syscollector,
            "keep_alive" => MessageType::Keepalive,
            "active-response" => MessageType::ActiveResponse,
            "agent_start" => MessageType::Startup,
            "agent_stop" => MessageType::Shutdown,
            "request" => MessageType::Request,
            "local-detection" => MessageType::LocalDetection,
            "device-control-finding" => MessageType::DeviceControlFinding,
            "device-control-recommendation" => MessageType::DeviceControlRecommendation,
            "device-control-job" => MessageType::DeviceControlJob,
            "device-control-action-result" => MessageType::DeviceControlActionResult,
            "device-posture-state" => MessageType::DevicePostureState,
            "software-inventory-delta" => MessageType::SoftwareInventoryDelta,
            "software-job-result" => MessageType::SoftwareJobResult,
            "jit-admin-requested" => MessageType::JitAdminRequested,
            "jit-admin-granted" => MessageType::JitAdminGranted,
            "jit-admin-revoked" => MessageType::JitAdminRevoked,
            "query-result" => MessageType::QueryResult,
            "script-run-result" => MessageType::ScriptRunResult,
            "remote-support-session-started" => MessageType::RemoteSupportSessionStarted,
            "remote-support-session-ended" => MessageType::RemoteSupportSessionEnded,
            "agent-vitals" => MessageType::AgentVitals,
            "evidence-record" => MessageType::EvidenceRecord,
            "usb-device-policy-decision" => MessageType::UsbDevicePolicyDecision,
            "mdm-wipe-result" => MessageType::MdmWipeResult,
            "mdm-lock-result" => MessageType::MdmLockResult,
            "mdm-lost-mode-entered" => MessageType::MdmLostModeEntered,
            "mdm-lost-mode-exited" => MessageType::MdmLostModeExited,
            "mdm-recovery-key-escrowed" => MessageType::MdmRecoveryKeyEscrowed,
            "mdm-os-update-result" => MessageType::MdmOsUpdateResult,
            "mdm-config-profile-applied" => MessageType::MdmConfigProfileApplied,
            "mdm-auto-remediation-result" => MessageType::MdmAutoRemediationResult,
            _ => MessageType::Generic,
        }
    }
}

/// A Wazuh protocol message ready for transmission.
#[derive(Debug, Clone)]
pub struct WazuhMessage {
    /// Agent ID (e.g., "001").
    pub agent_id: String,
    /// Message type.
    pub msg_type: MessageType,
    /// Message payload.
    pub payload: String,
    /// Whether to compress the payload.
    pub compress: bool,
}

impl WazuhMessage {
    /// Create a new message.
    pub fn new(
        agent_id: impl Into<String>,
        msg_type: MessageType,
        payload: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            msg_type,
            payload: payload.into(),
            compress: false,
        }
    }

    /// Enable compression for this message.
    pub fn with_compression(mut self) -> Self {
        self.compress = true;
        self
    }

    /// Encode the full wire-format message (legacy — includes agent_id).
    ///
    /// Format: `{agent_id}:{msg_type}:{payload}`
    ///
    /// Kept for backward compatibility with tests. Prefer `encode_body()`
    /// for the real protocol path.
    pub fn encode(&self) -> Vec<u8> {
        let wire = format!(
            "{}:{}:{}",
            self.agent_id,
            self.msg_type.as_protocol_str(),
            self.payload,
        );

        if self.compress {
            compress_payload(wire.as_bytes())
        } else {
            wire.into_bytes()
        }
    }

    /// Encode only the message body (the part that gets encrypted).
    ///
    /// The agent ID is NOT included — it is sent as a plaintext routing
    /// prefix by `ConnectionManager::send()`.
    pub fn encode_body(&self) -> Vec<u8> {
        // Queue byte prefixes match Wazuh's internal MQ types
        // (`src/headers/defs.h`): SYSCHECK_MQ='8', LOCALFILE_MQ='1',
        // SYSCOLLECTOR_MQ='d', ROOTCHECK_MQ='9', SCA_MQ='p'.  The
        // manager's `remoted` / `analysisd` route decrypted messages
        // on the leading byte; missing prefixes get silently dropped.
        let body = match self.msg_type {
            MessageType::Syscheck => format!("8:syscheck:{}", self.payload),
            MessageType::Log => format!("1:{}", self.payload),
            MessageType::Syscollector => format!("d:{}", self.payload),
            MessageType::Rootcheck => format!("9:{}", self.payload),
            MessageType::Sca => format!("p:{}", self.payload),
            // Active-response feedback from the agent is reported
            // through the logcollector queue with an "active-response"
            // source tag, mirroring Wazuh execd's
            // `SendMSG(..., "active-response", LOCALFILE_MQ)`.
            MessageType::ActiveResponse => format!("1:active-response:{}", self.payload),
            // Local Detection Engine alerts have no Wazuh-native queue
            // byte — the manager sees them as log events with a
            // "local-detection" source tag routed through LOCALFILE_MQ.
            // Analysisd then treats the payload as a JSON log record.
            MessageType::LocalDetection => format!("1:local-detection:{}", self.payload),
            // Device Control messages use the SN360 native protocol
            // path. When falling back to a legacy Wazuh manager they
            // are forwarded through LOCALFILE_MQ ('1') with a
            // `device-control:<kind>` source tag so analysisd treats
            // them as JSON log records and operators on the legacy
            // console can still see them. The Agent Gateway in
            // `sn360-security-platform` strips the prefix when
            // routing to the native NATS topology.
            MessageType::DeviceControlFinding => {
                format!("1:device-control:finding:{}", self.payload)
            }
            MessageType::DeviceControlRecommendation => {
                format!("1:device-control:recommendation:{}", self.payload)
            }
            MessageType::DeviceControlJob => {
                format!("1:device-control:job:{}", self.payload)
            }
            MessageType::DeviceControlActionResult => {
                format!("1:device-control:action-result:{}", self.payload)
            }
            MessageType::DevicePostureState => {
                format!("1:device-posture:{}", self.payload)
            }
            MessageType::SoftwareInventoryDelta => {
                format!("1:software-inventory:{}", self.payload)
            }
            MessageType::SoftwareJobResult => {
                format!("1:software-job:{}", self.payload)
            }
            MessageType::JitAdminRequested => {
                format!("1:jit-admin:requested:{}", self.payload)
            }
            MessageType::JitAdminGranted => {
                format!("1:jit-admin:granted:{}", self.payload)
            }
            MessageType::JitAdminRevoked => {
                format!("1:jit-admin:revoked:{}", self.payload)
            }
            MessageType::QueryResult => format!("1:query-result:{}", self.payload),
            MessageType::ScriptRunResult => format!("1:script-run:{}", self.payload),
            MessageType::RemoteSupportSessionStarted => {
                format!("1:remote-support:started:{}", self.payload)
            }
            MessageType::RemoteSupportSessionEnded => {
                format!("1:remote-support:ended:{}", self.payload)
            }
            MessageType::AgentVitals => format!("1:agent-vitals:{}", self.payload),
            MessageType::EvidenceRecord => format!("1:evidence-record:{}", self.payload),
            MessageType::UsbDevicePolicyDecision => {
                format!("1:device-control:usb-policy-decision:{}", self.payload)
            }
            // Desktop MDM events follow the same logcollector
            // queue + source-tag convention as Device Control so
            // legacy Wazuh consoles can still see them as raw JSON.
            MessageType::MdmWipeResult => format!("1:mdm:wipe-result:{}", self.payload),
            MessageType::MdmLockResult => format!("1:mdm:lock-result:{}", self.payload),
            MessageType::MdmLostModeEntered => {
                format!("1:mdm:lost-mode-entered:{}", self.payload)
            }
            MessageType::MdmLostModeExited => {
                format!("1:mdm:lost-mode-exited:{}", self.payload)
            }
            MessageType::MdmRecoveryKeyEscrowed => {
                format!("1:mdm:recovery-key-escrowed:{}", self.payload)
            }
            MessageType::MdmOsUpdateResult => {
                format!("1:mdm:os-update-result:{}", self.payload)
            }
            MessageType::MdmConfigProfileApplied => {
                format!("1:mdm:config-profile-applied:{}", self.payload)
            }
            MessageType::MdmAutoRemediationResult => {
                format!("1:mdm:auto-remediation-result:{}", self.payload)
            }
            // Control messages already carry the correct prefix.
            MessageType::Keepalive | MessageType::Startup | MessageType::Shutdown => {
                self.payload.clone()
            }
            MessageType::Request | MessageType::Generic => self.payload.clone(),
        };

        if self.compress {
            compress_payload(body.as_bytes())
        } else {
            body.into_bytes()
        }
    }

    /// Decode a message from the Wazuh wire format.
    pub fn decode(data: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(data).ok()?;
        let mut parts = text.splitn(3, ':');

        let agent_id = parts.next()?.to_string();
        let msg_type_str = parts.next()?;
        let payload = parts.next().unwrap_or("").to_string();

        Some(Self {
            agent_id,
            msg_type: MessageType::from_protocol_str(msg_type_str),
            payload,
            compress: false,
        })
    }

    /// Create a keepalive message.
    ///
    /// Wazuh's `run_notify()` in `notify.c` sends a multi-line control
    /// message.  The server's `save_controlmsg` looks for `\n` in the
    /// body; if none is found it logs "Invalid message from agent".
    ///
    /// Format accepted by remoted (mirrors what the upstream wazuh-agent
    /// sends so `save_controlmsg` populates agent.os/version/config_sum;
    /// without those fields populated, the manager's AR_Forward refuses
    /// to dispatch active-response commands to this agent):
    ///   `#!-<uname> [<distro>|<codename>] - Wazuh v<ver> / <cfg_md5>\n`
    ///   `<merged_md5> merged.mg\n`
    pub fn keepalive(agent_id: &str) -> Self {
        let uname = basic_uname();
        let distro = basic_distro();
        // The config hash and merged hash are placeholders here; the
        // manager re-computes/syncs `merged.mg` on its own and we don't
        // load any agent.conf-driven runtime config, so any stable hex
        // value is fine. AR dispatch only requires the keepalive to
        // *parse*, not to match.
        let body = format!(
            "#!-{} [{}] - Wazuh v4.13.1 / 11111111111111111111111111111111\n\
             22222222222222222222222222222222 merged.mg\n",
            uname, distro
        );
        Self::new(agent_id, MessageType::Keepalive, body)
    }

    /// Create an agent startup message.
    ///
    /// Wazuh's `agent_handshake_to_server` in `start_agent.c` sends:
    ///   `CONTROL_HEADER + HC_STARTUP + agent_info_json`
    /// where `HC_STARTUP` = `"agent startup "` (trailing space) and
    /// `agent_info_json` = `{"version":"..."}`.  The server parses
    /// the JSON to extract the version; if missing it responds with
    /// an error.
    pub fn startup(agent_id: &str) -> Self {
        // Match the Wazuh 4.x version string format.
        let body = "#!-agent startup {\"version\":\"v4.9.2\"}".to_string();
        Self::new(agent_id, MessageType::Startup, body)
    }
}

/// Compress data using zlib/deflate.
fn compress_payload(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).expect("compression failed");
    encoder.finish().expect("compression finalization failed")
}

/// Decompress zlib/deflate data.
pub fn decompress_payload(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    let mut decoder = ZlibDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).ok()?;
    Some(result)
}

/// Return the `<distro>|<codename>` field of the keepalive control
/// message. The Wazuh manager's `save_controlmsg` records this string
/// verbatim into `agent.os.platform`, so the value should reflect the
/// host's actual OS family rather than a hard-coded `Linux|generic`.
fn basic_distro() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "Linux|generic"
    }
    #[cfg(target_os = "macos")]
    {
        "Darwin|generic"
    }
    #[cfg(target_os = "windows")]
    {
        "Windows|generic"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "Unknown|generic"
    }
}

/// Return a minimal uname-style string for keepalive messages.
///
/// Wazuh's `run_notify()` calls `getuname()` which returns something
/// like `Linux myhost 5.15.0 #1 SMP x86_64 |Linux|x86_64`.  We
/// build a comparable string from the information available at
/// runtime.
fn basic_uname() -> String {
    #[cfg(target_os = "linux")]
    {
        let nodename = std::fs::read_to_string("/etc/hostname")
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();
        let machine = std::env::consts::ARCH;
        // Pipe-separated field layout matches what the upstream
        // wazuh-agent's `getuname()` emits (e.g. `Linux |host |5.15 |#1 SMP
        // ... |x86_64`). The manager's `save_controlmsg` parser walks the
        // string by `|` to populate the agent.os fields; without the
        // pipes it falls back to NULL and AR_Forward stops dispatching.
        format!(
            "Linux |{} |{} |#1 SMP {} |{}",
            nodename, release, machine, machine
        )
    }
    #[cfg(target_os = "macos")]
    {
        let machine = std::env::consts::ARCH;
        let nodename = run_cmd("hostname", &[]);
        let release = run_cmd("uname", &["-r"]);
        let version = run_cmd("uname", &["-v"]);
        format!(
            "Darwin {} {} {} |Darwin|{}",
            nodename, release, version, machine
        )
    }
    #[cfg(target_os = "windows")]
    {
        let machine = std::env::consts::ARCH;
        let nodename = run_cmd("hostname", &[]);
        let ver_output = run_cmd("cmd", &["/C", "ver"]);
        let version = ver_output
            .split("Version ")
            .nth(1)
            .unwrap_or("10.0")
            .trim_end_matches(']')
            .trim();
        format!(
            "Microsoft Windows {} {} |Windows|{}",
            version, nodename, machine
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "Unknown |Unknown|unknown".to_string()
    }
}

/// Run a command synchronously and return trimmed stdout, or a fallback.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn run_cmd(program: &str, args: &[&str]) -> String {
    std::process::Command::new(program)
        .args(args)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_encode() {
        let msg = WazuhMessage::new("001", MessageType::Keepalive, "#!-agent keep_alive");
        let encoded = msg.encode();
        let expected = b"001:keep_alive:#!-agent keep_alive";
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_message_decode() {
        let data = b"001:syscheck:{\"path\":\"/etc/passwd\"}";
        let msg = WazuhMessage::decode(data).unwrap();
        assert_eq!(msg.agent_id, "001");
        assert_eq!(msg.msg_type, MessageType::Syscheck);
        assert_eq!(msg.payload, "{\"path\":\"/etc/passwd\"}");
    }

    #[test]
    fn test_compress_decompress() {
        let data = b"hello world hello world hello world";
        let compressed = compress_payload(data);
        let decompressed = decompress_payload(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_keepalive_message() {
        let msg = WazuhMessage::keepalive("002");
        assert_eq!(msg.agent_id, "002");
        assert_eq!(msg.msg_type, MessageType::Keepalive);
        // Body must start with "#!-" and contain a newline (required by
        // Wazuh remoted's save_controlmsg).
        assert!(msg.payload.starts_with("#!-"));
        assert!(msg.payload.contains('\n'));
        assert!(msg.payload.contains("merged.mg"));
    }

    #[test]
    fn test_startup_message() {
        let msg = WazuhMessage::startup("001");
        assert_eq!(msg.agent_id, "001");
        assert_eq!(msg.msg_type, MessageType::Startup);
        // Must contain the control header, HC_STARTUP ("agent startup "),
        // and a JSON version object.
        assert!(msg.payload.starts_with("#!-agent startup "));
        assert!(msg.payload.contains("version"));
    }

    #[test]
    fn test_encode_body_syscheck_prefix() {
        let msg = WazuhMessage::new("001", MessageType::Syscheck, "{\"path\":\"/etc/passwd\"}");
        let body = String::from_utf8(msg.encode_body()).unwrap();
        assert!(
            body.starts_with("8:syscheck:"),
            "syscheck body missing queue prefix: {body}"
        );
    }

    #[test]
    fn test_encode_body_log_prefix() {
        let msg = WazuhMessage::new("001", MessageType::Log, "hello");
        let body = String::from_utf8(msg.encode_body()).unwrap();
        assert_eq!(body, "1:hello");
    }

    #[test]
    fn test_encode_body_syscollector_prefix() {
        let msg = WazuhMessage::new("001", MessageType::Syscollector, "{}");
        let body = String::from_utf8(msg.encode_body()).unwrap();
        assert_eq!(body, "d:{}");
    }

    #[test]
    fn test_encode_body_rootcheck_prefix() {
        let msg = WazuhMessage::new("001", MessageType::Rootcheck, "{}");
        let body = String::from_utf8(msg.encode_body()).unwrap();
        assert_eq!(body, "9:{}");
    }

    #[test]
    fn test_encode_body_sca_prefix() {
        // SCA_MQ = 'p' in Wazuh's internal queue table; analysisd will
        // silently drop messages without this byte.
        let msg = WazuhMessage::new("001", MessageType::Sca, "{\"check_id\":1}");
        let body = String::from_utf8(msg.encode_body()).unwrap();
        assert_eq!(body, "p:{\"check_id\":1}");
    }

    #[test]
    fn test_encode_body_active_response_prefix() {
        // Agent-originated active-response feedback goes through the
        // logcollector queue ('1') with an "active-response" source tag.
        let msg = WazuhMessage::new("001", MessageType::ActiveResponse, "{\"ok\":true}");
        let body = String::from_utf8(msg.encode_body()).unwrap();
        assert_eq!(body, "1:active-response:{\"ok\":true}");
    }

    #[test]
    fn test_encode_body_control_messages_pass_through() {
        // Keepalive / Startup / Shutdown already embed their own
        // Wazuh control header; encode_body must not prepend a queue
        // byte or the manager rejects them.
        for mt in [
            MessageType::Keepalive,
            MessageType::Startup,
            MessageType::Shutdown,
        ] {
            let msg = WazuhMessage::new("001", mt, "#!-agent payload");
            let body = String::from_utf8(msg.encode_body()).unwrap();
            assert_eq!(body, "#!-agent payload");
        }
    }

    #[test]
    fn test_encode_body_local_detection_prefix() {
        // LDE alerts are routed through the logcollector queue ('1')
        // with a "local-detection" source tag.  Missing the queue byte
        // would cause the manager to silently drop the payload.
        let msg = WazuhMessage::new(
            "001",
            MessageType::LocalDetection,
            "{\"rule_id\":\"ioc-1\"}",
        );
        let body = String::from_utf8(msg.encode_body()).unwrap();
        assert_eq!(body, "1:local-detection:{\"rule_id\":\"ioc-1\"}");
    }

    #[test]
    fn test_message_type_roundtrip() {
        let types = vec![
            MessageType::Syscheck,
            MessageType::Log,
            MessageType::Rootcheck,
            MessageType::Sca,
            MessageType::Syscollector,
            MessageType::Keepalive,
            MessageType::ActiveResponse,
            MessageType::Startup,
            MessageType::Shutdown,
            MessageType::Request,
            MessageType::LocalDetection,
            MessageType::DeviceControlFinding,
            MessageType::DeviceControlRecommendation,
            MessageType::DeviceControlJob,
            MessageType::DeviceControlActionResult,
            MessageType::DevicePostureState,
            MessageType::SoftwareInventoryDelta,
            MessageType::SoftwareJobResult,
            MessageType::JitAdminRequested,
            MessageType::JitAdminGranted,
            MessageType::JitAdminRevoked,
            MessageType::QueryResult,
            MessageType::ScriptRunResult,
            MessageType::RemoteSupportSessionStarted,
            MessageType::RemoteSupportSessionEnded,
            MessageType::AgentVitals,
            MessageType::EvidenceRecord,
            MessageType::UsbDevicePolicyDecision,
            MessageType::Generic,
        ];

        for mt in types {
            let s = mt.as_protocol_str();
            let parsed = MessageType::from_protocol_str(s);
            assert_eq!(mt, parsed);
        }
    }

    #[test]
    fn test_encode_body_device_control_prefixes() {
        // Each Device Control MessageType must prepend a stable
        // queue-byte prefix when forwarded to a legacy Wazuh manager.
        // Without the prefix, analysisd silently drops the payload —
        // the same failure mode that historically affected
        // Rootcheck/Sca/ActiveResponse.
        let cases = [
            (
                MessageType::DeviceControlFinding,
                "1:device-control:finding:",
            ),
            (
                MessageType::DeviceControlRecommendation,
                "1:device-control:recommendation:",
            ),
            (MessageType::DeviceControlJob, "1:device-control:job:"),
            (
                MessageType::DeviceControlActionResult,
                "1:device-control:action-result:",
            ),
            (MessageType::DevicePostureState, "1:device-posture:"),
            (MessageType::SoftwareInventoryDelta, "1:software-inventory:"),
            (MessageType::SoftwareJobResult, "1:software-job:"),
            (MessageType::JitAdminRequested, "1:jit-admin:requested:"),
            (MessageType::JitAdminGranted, "1:jit-admin:granted:"),
            (MessageType::JitAdminRevoked, "1:jit-admin:revoked:"),
            (MessageType::QueryResult, "1:query-result:"),
            (MessageType::ScriptRunResult, "1:script-run:"),
            (
                MessageType::RemoteSupportSessionStarted,
                "1:remote-support:started:",
            ),
            (
                MessageType::RemoteSupportSessionEnded,
                "1:remote-support:ended:",
            ),
            (MessageType::AgentVitals, "1:agent-vitals:"),
            (MessageType::EvidenceRecord, "1:evidence-record:"),
            (
                MessageType::UsbDevicePolicyDecision,
                "1:device-control:usb-policy-decision:",
            ),
        ];
        for (mt, prefix) in cases {
            let msg = WazuhMessage::new("001", mt.clone(), "{\"k\":\"v\"}");
            let body = String::from_utf8(msg.encode_body()).unwrap();
            assert!(
                body.starts_with(prefix),
                "{:?} encoded body {:?} did not start with {:?}",
                mt,
                body,
                prefix
            );
            assert!(body.ends_with("{\"k\":\"v\"}"));
        }
    }
}
