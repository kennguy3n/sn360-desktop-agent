//! Agent configuration loading and parsing.
//!
//! Supports YAML configuration files with backward-compatible XML reading.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::info;

/// Top-level agent configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentConfig {
    /// Server connection settings.
    #[serde(default)]
    pub server: ServerConfig,

    /// Enrollment settings.
    #[serde(default)]
    pub enrollment: EnrollmentConfig,

    /// Module-specific configuration.
    #[serde(default)]
    pub modules: ModulesConfig,

    /// Resource limit settings.
    #[serde(default)]
    pub resource_limits: ResourceLimits,

    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Security hardening: privilege separation (P3.2) and tamper
    /// protection (P3.3).
    #[serde(default)]
    pub security: SecurityConfig,
}

/// Security hardening settings: privilege separation (P3.2) and
/// tamper protection (P3.3).
///
/// The defaults are conservative — privilege dropping is off unless an
/// operator explicitly configures `run_as_user`, and tamper protection
/// is off unless explicitly enabled. This lets distro packagers
/// (`packaging/debian/postinst`, `packaging/rpm/sda-agent.spec`) turn
/// the hardening on via the default config they ship rather than
/// forcing every operator to opt in.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
    /// Unprivileged user to `setuid()` to after privileged
    /// initialization (enrollment, binding low ports, reading
    /// root-owned config). `None` disables privilege dropping — the
    /// agent continues running as whatever user systemd/launchd/SCM
    /// started it as.
    #[serde(default)]
    pub run_as_user: Option<String>,
    /// Unprivileged group to `setgid()` to. Defaults to `run_as_user`'s
    /// primary group when unset.
    #[serde(default)]
    pub run_as_group: Option<String>,
    /// Absolute path to a small setuid helper binary used by the
    /// active-response module to run privileged commands (e.g.
    /// `iptables`) after the main agent has dropped privileges.
    #[serde(default)]
    pub privilege_helper_path: Option<PathBuf>,
    /// Tamper-protection settings (see [`TamperConfig`]).
    #[serde(default)]
    pub tamper: TamperConfig,
}

/// Tamper-protection settings (P3.3).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TamperConfig {
    /// Master enable switch.
    #[serde(default)]
    pub enabled: bool,
    /// Expected lowercase-hex SHA-256 of the currently-running
    /// `sda-agent` binary, or `None` to skip the self-integrity check.
    ///
    /// Production deployments ship this value embedded in a signed
    /// manifest installed alongside the binary.
    #[serde(default)]
    pub expected_binary_sha256: Option<String>,
    /// Additional files that should be marked immutable on Linux
    /// (`chattr +i`) once the agent has settled. Non-existent paths
    /// are skipped with a warning rather than aborting startup so an
    /// incomplete install doesn't take the agent out.
    #[serde(default)]
    pub immutable_paths: Vec<PathBuf>,
    /// Systemd-style watchdog heartbeat interval, in seconds. The
    /// agent notifies the service manager at roughly half this
    /// interval; systemd will `SIGKILL` and restart the unit if
    /// heartbeats stop.
    ///
    /// A value of `0` disables the heartbeat. This must match the
    /// `WatchdogSec=` directive in the systemd unit — see
    /// `packaging/systemd/sda-agent.service`.
    #[serde(default)]
    pub watchdog_interval_secs: u64,
}

/// Server connection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server address (hostname or IP).
    #[serde(default = "default_server_address")]
    pub address: String,

    /// Server port.
    #[serde(default = "default_server_port")]
    pub port: u16,

    /// Transport protocol. `"tcp"` (the default) and `"udp"` use the
    /// stream / datagram transports on the standard agent port.
    /// `"http2"` selects the SN360 native HTTP/2 transport, which is
    /// only supported against the SN360 Agent Gateway.
    #[serde(default = "default_protocol")]
    pub protocol: String,

    /// Keepalive interval in seconds.
    #[serde(default = "default_keepalive")]
    pub keepalive_interval: u64,

    /// Optional SN360 native protocol toggles (TLS 1.3 + MessagePack +
    /// HTTP/2). All fields default **off** so an unmodified config
    /// keeps the stable agent protocol behavior; operators running
    /// against an SN360 Agent Gateway can flip them on.
    #[serde(default)]
    pub enhanced: EnhancedProtocolConfig,
}

/// Optional SN360 native protocol options.
///
/// These knobs opt the agent into the SN360 native protocol: TLS 1.3,
/// MessagePack event serialization, and HTTP/2 transport against the
/// SN360 Agent Gateway. All of them default **off** — turning them on
/// requires an SN360-aware server endpoint.
///
/// The actual transport / serializer implementations live in
/// `sda-comms` (see `transport::tls`, `transport::http2`) and
/// `sda-comms::msgpack` respectively.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedProtocolConfig {
    /// Wrap the stream transport in TLS 1.3 (via `rustls`). Has no
    /// effect when `protocol == "udp"` (TLS requires a stream
    /// transport) or when `protocol == "http2"` (HTTP/2 already
    /// negotiates TLS via ALPN). Defaults to `false`.
    #[serde(default)]
    pub tls: bool,

    /// Event serialization format. `"json"` (the default) is the
    /// standard agent event encoding; `"msgpack"` produces
    /// significantly smaller frames and is only understood by
    /// SN360-aware server endpoints.
    #[serde(default = "default_enhanced_serialization")]
    pub serialization: String,

    /// Expected SHA-256 fingerprint of the server's leaf certificate
    /// (lowercase hex, no colons). When set, the TLS client performs
    /// certificate pinning in addition to the standard chain
    /// validation. Leave empty to disable pinning.
    #[serde(default)]
    pub tls_pinned_sha256: Option<String>,

    /// Path to a PEM-encoded bundle of trust anchors used when
    /// `tls == true`. When `None`, the Mozilla `webpki-roots`
    /// bundle compiled into the agent binary is used (this is a
    /// static copy of the public-web CA list, NOT the host OS
    /// trust store). Operators running against a private CA MUST
    /// set this path — custom CAs added to the host trust store
    /// alone are NOT picked up.
    #[serde(default)]
    pub tls_ca_bundle_path: Option<PathBuf>,
}

impl Default for EnhancedProtocolConfig {
    fn default() -> Self {
        Self {
            tls: false,
            serialization: default_enhanced_serialization(),
            tls_pinned_sha256: None,
            tls_ca_bundle_path: None,
        }
    }
}

/// Enrollment configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentConfig {
    /// Enrollment server address (defaults to server address).
    pub server: Option<String>,

    /// Enrollment port.
    #[serde(default = "default_enrollment_port")]
    pub port: u16,

    /// Whether to auto-enroll on first start.
    #[serde(default = "default_true")]
    pub auto_enroll: bool,

    /// Pre-shared key for enrollment (optional).
    pub key: Option<String>,

    /// Agent name override.
    pub agent_name: Option<String>,

    /// Agent group assignment.
    pub groups: Option<Vec<String>>,

    /// Override for the `client.keys` file location. When unset the
    /// platform default is used (`/etc/sn360-desktop-agent/client.keys`
    /// on Unix, `C:\Program Files\SN360DesktopAgent\client.keys` on Windows).
    pub keys_file: Option<PathBuf>,
}

/// Module enable/disable configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModulesConfig {
    #[serde(default)]
    pub fim: FimConfig,
    #[serde(default)]
    pub logcollector: LogCollectorConfig,
    #[serde(default)]
    pub inventory: InventoryConfig,
    #[serde(default)]
    pub sca: ScaConfig,
    #[serde(default)]
    pub active_response: ActiveResponseConfig,
    #[serde(default)]
    pub rootcheck: RootcheckConfig,
    #[serde(default)]
    pub local_detection: LocalDetectionConfig,
    #[serde(default)]
    pub enhanced_inventory: EnhancedInventoryConfig,
    #[serde(default)]
    pub updater: UpdateConfig,

    // --- Device Control modules (Phase 1) ---
    //
    // All Device Control modules default to `enabled: false` per the
    // lazy-module-loading principle. With `device_control.enabled =
    // false` the agent's idle footprint is bit-for-bit identical to
    // the pre-Device-Control baseline.
    #[serde(default)]
    pub device_control: DeviceControlConfig,
    #[serde(default)]
    pub query: QueryConfig,
    #[serde(default)]
    pub posture: PostureConfig,
    #[serde(default)]
    pub software: SoftwareConfig,
    #[serde(default)]
    pub jit_admin: JitAdminConfig,
    #[serde(default)]
    pub script_runner: ScriptRunnerConfig,
    #[serde(default)]
    pub app_control: AppControlConfig,
    #[serde(default)]
    pub remote_support: RemoteSupportConfig,
    #[serde(default)]
    pub agent_vitals: AgentVitalsConfig,

    // --- Desktop MDM module (Phase M1–M3) ---
    //
    // Unlike every other Phase-1+ module, MDM defaults to `enabled =
    // true` per `docs/desktop-mdm.md` § 1 (Product loop) and the
    // Desktop MDM section of `docs/configuration-reference.md`.
    // Operators that need to disable it must explicitly set
    // `modules.mdm.enabled = false` in their config.
    #[serde(default)]
    pub mdm: MdmConfig,

    // --- EDR Parity modules (Phase E1-E3) ---
    //
    // Each EDR module defaults to `enabled: false` per the lazy
    // module-loading principle. See `docs/configuration-reference.md`
    // (Modules — EDR section) for the full schema.
    #[serde(default)]
    pub process_monitor: ProcessMonitorConfig,
    #[serde(default)]
    pub network_monitor: NetworkMonitorConfig,
    #[serde(default)]
    pub dns_monitor: DnsMonitorConfig,
    #[serde(default)]
    pub host_isolation: HostIsolationConfig,

    // --- EDR Parity modules (Phase E4) ---
    //
    // Memory scanning + fileless detection. Defaults to `enabled:
    // false` per the lazy module-loading principle; the agent process
    // is ALWAYS included in `allow_list_processes` (see
    // `docs/architecture.md` § 8.3 — Memory-scanner safety) even if
    // the operator omits or overrides this field.
    #[serde(default)]
    pub memory_scanner: MemoryScannerConfig,

    // --- EDR Parity modules (Phase E5) ---
    //
    // Identity attack detection (LSASS / shadow / keychain) and DLP
    // (PII / PCI on file writes + optional clipboard). Both default
    // to `enabled: false`.
    #[serde(default)]
    pub identity_monitor: IdentityMonitorConfig,
    #[serde(default)]
    pub dlp: DlpConfig,
}

/// FIM-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimConfig {
    /// Whether the FIM module is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Directories to monitor.
    #[serde(default = "default_fim_directories")]
    pub directories: Vec<FimDirectory>,
    /// Baseline scan interval in seconds (default 12h).
    #[serde(default = "default_fim_scan_interval")]
    pub scan_interval: u64,
    /// Debounce window in milliseconds (default 100).
    #[serde(default = "default_fim_debounce_ms")]
    pub debounce_ms: u64,
    /// Maximum SHA-256 hashes dispatched per second (default 100).
    ///
    /// Bounds CPU usage of the real-time FIM path under bursts. When
    /// the limit is reached the loop sleeps to the next second boundary
    /// before dispatching more hashes. Set to `0` to disable rate
    /// limiting.
    #[serde(default = "default_fim_max_hashes_per_sec")]
    pub max_hashes_per_sec: u32,
    /// Maximum number of events to accumulate before flushing to the
    /// event bus (default 50).
    #[serde(default = "default_fim_batch_size")]
    pub batch_size: usize,
    /// Maximum time to hold events before flushing (default 200 ms).
    #[serde(default = "default_fim_batch_timeout_ms")]
    pub batch_timeout_ms: u64,
}

/// A directory entry in FIM configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimDirectory {
    /// Path to monitor.
    pub path: String,
    /// Whether to watch recursively.
    #[serde(default = "default_true")]
    pub recursive: bool,
    /// Whether to enable real-time monitoring.
    #[serde(default = "default_true")]
    pub realtime: bool,
    /// Whether to compute SHA-256 hashes.
    #[serde(default = "default_true")]
    pub check_sha256: bool,
    /// Glob patterns to exclude.
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Log collector configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogCollectorConfig {
    /// Whether the log collector module is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Log sources to monitor.
    #[serde(default)]
    pub sources: Vec<LogSource>,
}

/// A log source entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    /// Source type: "file" or "journald".
    #[serde(default = "default_source_type")]
    pub source_type: String,
    /// Path to the log file (for file sources).
    #[serde(default)]
    pub path: Option<String>,
    /// Log format: "syslog", "json", or "plain".
    #[serde(default = "default_log_source_format")]
    pub format: String,
    /// Systemd unit filters (for journald sources).
    #[serde(default)]
    pub units: Vec<String>,
}

/// Inventory module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryConfig {
    /// Whether the inventory module is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Collection interval in seconds (default 3600).
    #[serde(default = "default_inventory_interval")]
    pub interval: u64,
    /// Categories to collect: "os", "network", "packages", "hardware".
    #[serde(default = "default_inventory_collect")]
    pub collect: Vec<String>,
}

/// Simple module enable/disable toggle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleToggle {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Rootcheck (rootkit detection) module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootcheckConfig {
    /// Whether the rootcheck module is enabled.
    ///
    /// Rootcheck is off by default — it runs privileged filesystem
    /// sweeps and PID scans, so operators opt in explicitly.
    #[serde(default)]
    pub enabled: bool,
    /// Interval in seconds between rootcheck sweeps (default 1h).
    #[serde(default = "default_rootcheck_scan_interval")]
    pub scan_interval_secs: u64,
    /// Additional file paths that should be flagged as rootkit
    /// indicators if present. The built-in signature list is always
    /// checked first; these are appended to it.
    #[serde(default)]
    pub signature_paths: Vec<String>,
    /// System binary paths whose SHA-256 is tracked for drift.
    ///
    /// When empty the platform-specific defaults from
    /// [`default_rootcheck_binary_paths`] are used.
    #[serde(default)]
    pub binary_paths: Vec<String>,
    /// Path to the on-disk baseline file that stores the initial
    /// SHA-256 hashes of each tracked binary. The file is created on
    /// first run and subsequent runs compare current hashes against
    /// the stored baseline.
    #[serde(default = "default_rootcheck_baseline_path")]
    pub baseline_path: PathBuf,
    /// Whether to run the hidden-process check.
    ///
    /// Only meaningful on Linux; no-op on other platforms.
    #[serde(default = "default_true")]
    pub hidden_process_check: bool,
    /// Whether to run the binary-integrity check.
    #[serde(default = "default_true")]
    pub binary_integrity_check: bool,
    /// Upper bound for PIDs to probe with `kill(pid, 0)` during the
    /// hidden-process sweep. Keep this conservative to cap CPU cost.
    #[serde(default = "default_rootcheck_max_pid")]
    pub max_pid: u32,
}

/// Local Detection Engine (LDE) module configuration.
///
/// The LDE evaluates detection rules locally at the edge — IOC matching
/// via Aho-Corasick + bloom filters, behavioral rule state machines,
/// and YARA file scanning — without a server round-trip. See
/// [`docs/edr.md`](../../../docs/edr.md) § 3 (Local Detection Engine).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalDetectionConfig {
    /// Whether the LDE is enabled.
    ///
    /// **Default**: `true` (since EDR Parity Phase E2.3 — see
    /// `docs/configuration-reference.md` and the CHANGELOG migration
    /// note).  Agents that omit this key now run the LDE against the
    /// embedded baseline bundle at startup; to preserve the previous
    /// default-off behaviour, set `modules.local_detection.enabled:
    /// false` explicitly.
    ///
    /// Uses `default_true` (not bare `#[serde(default)]`) so the
    /// default applies on the per-field serde path as well as the
    /// struct-level `LocalDetectionConfig::default()` path — i.e.
    /// when an operator provides a partial `local_detection:`
    /// section that omits the `enabled` key, the LDE still defaults
    /// on (matching the documented intent).  A bare
    /// `#[serde(default)]` would silently resolve to
    /// `bool::default() == false` on that path.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Interval in seconds between rule-bundle pulls from the Tenant
    /// Rule Distribution Service (TRDS).
    #[serde(default = "default_lde_rule_pull_interval")]
    pub rule_pull_interval: u64,
    /// Maximum number of detections buffered in the offline queue
    /// when the server is unreachable. Bounded FIFO — oldest entries
    /// are evicted when the queue is full.
    #[serde(default = "default_lde_offline_queue_max")]
    pub offline_queue_max: usize,
    /// Upper bound on YARA scans per second. The scanner sleeps to
    /// the next second boundary when the budget is exhausted.
    #[serde(default = "default_lde_yara_scan_rate_limit")]
    pub yara_scan_rate_limit: u32,
    /// Files larger than this (MB) are skipped by the YARA scanner.
    #[serde(default = "default_lde_yara_max_file_size_mb")]
    pub yara_max_file_size_mb: u64,
    /// Target false-positive rate for the hash/IP bloom filters.
    #[serde(default = "default_lde_bloom_filter_fpr")]
    pub bloom_filter_fpr: f64,
    /// Maximum sliding-window size (seconds) for behavioral rules.
    #[serde(default = "default_lde_behavioral_max_window_sec")]
    pub behavioral_max_window_sec: u64,
    /// Maximum number of distinct entities (subjects) tracked by the
    /// behavioral engine. Bounds memory use.
    #[serde(default = "default_lde_behavioral_max_tracked_entities")]
    pub behavioral_max_tracked_entities: usize,
    /// Whether `block_ip` local responses are allowed.
    #[serde(default)]
    pub block_ip: bool,
    /// Whether `kill_process` local responses are allowed.
    #[serde(default)]
    pub kill_process: bool,
    /// Whether `quarantine` local responses (move file aside) are allowed.
    #[serde(default)]
    pub quarantine: bool,
    /// Path to the MessagePack rule bundle on disk.
    #[serde(default = "default_lde_rule_bundle_path")]
    pub rule_bundle_path: PathBuf,
    /// Path to the SQLite offline-queue database.
    #[serde(default = "default_lde_offline_queue_path")]
    pub offline_queue_path: PathBuf,
    /// Directory where quarantined files are moved.
    #[serde(default = "default_lde_quarantine_dir")]
    pub quarantine_dir: PathBuf,
    /// Interval in seconds between attempts to replay detections from
    /// the offline queue back to the server. Floored to 5 s.
    #[serde(default = "default_lde_offline_drain_interval")]
    pub offline_drain_interval: u64,
    /// Maximum number of detections drained per replay tick.
    #[serde(default = "default_lde_offline_drain_batch")]
    pub offline_drain_batch: usize,
    /// Optional HTTPS endpoint of the Tenant Rule Distribution Service
    /// (TRDS).  When `None`, the LDE keeps the bundle loaded from
    /// `rule_bundle_path` (or the embedded default) and never attempts
    /// hot-reload (Phase E2.1).
    #[serde(default)]
    pub trds_endpoint: Option<String>,
    /// Ed25519 public keys (lower-case hex, 32-byte raw) that are
    /// permitted to sign TRDS bundles.  Bundles signed by keys outside
    /// this rotation set are rejected with a `LocalDetectionAlert` and
    /// the last-known-good pipeline is preserved (Phase E2.2).
    #[serde(default)]
    pub rule_bundle_signing_keys: Vec<String>,
    /// Connect / read timeout (seconds) for TRDS bundle pulls.
    #[serde(default = "default_lde_trds_timeout")]
    pub trds_pull_timeout_secs: u64,
}

/// Enhanced Inventory module configuration.
///
/// The enhanced inventory extends the base inventory with running
/// software monitoring (task 4.7), browser extension enumeration
/// (task 4.8), and CycloneDX SBOM generation (task 4.9). See
/// [`docs/architecture.md`](../../../docs/architecture.md) § 7
/// (Module reference) for design details.
///
/// The module is **off by default** — operators opt in explicitly
/// because running-software snapshots touch `/proc` on Linux and the
/// equivalent syscalls on macOS / Windows.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnhancedInventoryConfig {
    /// Whether the enhanced inventory module is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Running-software monitor settings.
    #[serde(default)]
    pub running_software: RunningSoftwareConfig,
    /// Browser-extension inventory settings.
    #[serde(default)]
    pub browser_extensions: BrowserExtensionsConfig,
    /// CycloneDX SBOM generator settings.
    #[serde(default)]
    pub sbom: SbomConfig,
    /// When `true`, the running-software monitor mirrors each
    /// snapshot/delta as an `EventKind::SoftwareInventoryDelta` event
    /// for Device Control consumers (task 1.10). The agent
    /// flips this on when `modules.device_control.enabled = true` and
    /// `modules.enhanced_inventory.running_software.enabled = true`.
    /// Not user-configurable from on-disk YAML — it is set internally
    /// by `sda-agent::main` after the full config is loaded so the
    /// disabled-by-default Device Control story stays single-knob.
    #[serde(default, skip)]
    pub device_control_bridge_enabled: bool,
}

/// Running-software monitor configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunningSoftwareConfig {
    /// Whether the running-software monitor is enabled when the
    /// enhanced inventory module itself is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Interval in seconds between process-list snapshots.
    #[serde(default = "default_running_software_interval")]
    pub interval: u64,
}

/// Browser-extension enumeration configuration.
///
/// Collects installed extensions for Chrome, Firefox, Edge, and
/// Safari. See [`sda_enhanced_inventory::browser_extensions`] for
/// platform-specific discovery paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserExtensionsConfig {
    /// Whether the browser-extensions scanner is enabled when the
    /// enhanced inventory module itself is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Interval in seconds between extension snapshots.
    #[serde(default = "default_browser_extensions_interval")]
    pub interval: u64,
}

/// CycloneDX SBOM generator configuration.
///
/// Produces a full Software Bill of Materials (CycloneDX 1.5 JSON)
/// covering installed OS packages, running processes, and browser
/// extensions. See [`sda_enhanced_inventory::sbom`] for the concrete
/// collection and serialization logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomConfig {
    /// Whether the SBOM generator is enabled when the enhanced
    /// inventory module itself is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Interval in seconds between full SBOM generations. Defaults to
    /// 86 400 (once per day) — the SBOM is comparatively expensive
    /// (shells out to `dpkg-query` / `rpm` / `brew`) and rarely
    /// changes more often than that.
    #[serde(default = "default_sbom_interval")]
    pub interval: u64,
    /// Whether to also honour explicit server-pushed requests for an
    /// immediate SBOM. When enabled, a `ServerCommand` whose payload
    /// contains `"sbom"` (case-insensitive) triggers an out-of-band
    /// generation independent of the periodic timer.
    #[serde(default = "default_true")]
    pub on_demand: bool,
}

/// SCA (Security Configuration Assessment) module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaConfig {
    /// Whether the SCA module is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Directory containing YAML policy files to load at startup.
    #[serde(default = "default_sca_policy_dir")]
    pub policy_dir: PathBuf,
    /// Interval in seconds between policy re-evaluations (default 12h).
    #[serde(default = "default_sca_scan_interval")]
    pub scan_interval: u64,
}

/// Self-update (P3.1) configuration.
///
/// The updater is disabled by default and must be explicitly enabled by
/// the operator — running without a configured `public_key` silently
/// skips installs so a bad deployment can never replace the agent with
/// an unsigned binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    /// Master enable switch.
    #[serde(default)]
    pub enabled: bool,
    /// HTTPS URL that returns the signed update manifest.
    #[serde(default = "default_update_server_url")]
    pub server_url: String,
    /// Poll interval, in seconds (floored at 60 s by the updater).
    #[serde(default = "default_update_check_interval")]
    pub check_interval: u64,
    /// Hex-encoded Ed25519 verifying key pinned at deploy time.
    ///
    /// An empty string is treated as "no key configured" and aborts
    /// any install attempt.
    #[serde(default)]
    pub public_key: String,
    /// Maximum number of seconds a newly-installed binary has to
    /// report a successful `--version` before it is rolled back.
    #[serde(default = "default_update_smoke_test_timeout")]
    pub smoke_test_timeout: u64,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_url: default_update_server_url(),
            check_interval: default_update_check_interval(),
            public_key: String::new(),
            smoke_test_timeout: default_update_smoke_test_timeout(),
        }
    }
}

fn default_update_server_url() -> String {
    "https://updates.example.com/sda/latest.json".to_string()
}

fn default_update_check_interval() -> u64 {
    3600
}

fn default_update_smoke_test_timeout() -> u64 {
    10
}

/// Active response module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveResponseConfig {
    /// Whether the active response module is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Command execution timeout in seconds.
    #[serde(default = "default_ar_timeout")]
    pub timeout: u64,
    /// Allowed response actions.
    #[serde(default = "default_ar_actions")]
    pub actions: Vec<String>,
}

/// Resource limit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum CPU usage percentage.
    #[serde(default = "default_max_cpu")]
    pub max_cpu_percent: u8,

    /// Maximum memory usage in MB.
    #[serde(default = "default_max_memory")]
    pub max_memory_mb: u32,

    /// Battery mode: "adaptive", "minimal", "normal".
    #[serde(default = "default_battery_mode")]
    pub battery_mode: String,

    /// Whether to detect user idle state.
    #[serde(default = "default_true")]
    pub idle_detection: bool,
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level: "trace", "debug", "info", "warn", "error".
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log output format: "text" or "json".
    #[serde(default = "default_log_format")]
    pub format: String,

    /// Log file path (optional; defaults to stderr).
    pub file: Option<PathBuf>,
}

// --- Default value functions ---

fn default_server_address() -> String {
    "localhost".to_string()
}
fn default_server_port() -> u16 {
    1514
}
fn default_protocol() -> String {
    "tcp".to_string()
}
fn default_enhanced_serialization() -> String {
    "json".to_string()
}
fn default_keepalive() -> u64 {
    600
}
fn default_enrollment_port() -> u16 {
    1515
}
fn default_true() -> bool {
    true
}
fn default_max_cpu() -> u8 {
    3
}
fn default_max_memory() -> u32 {
    50
}
fn default_battery_mode() -> String {
    "adaptive".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "text".to_string()
}
fn default_fim_scan_interval() -> u64 {
    43200 // 12 hours
}
fn default_fim_debounce_ms() -> u64 {
    100
}
fn default_fim_max_hashes_per_sec() -> u32 {
    100
}
fn default_fim_batch_size() -> usize {
    50
}
fn default_fim_batch_timeout_ms() -> u64 {
    200
}
fn default_source_type() -> String {
    "file".to_string()
}
fn default_log_source_format() -> String {
    "syslog".to_string()
}
fn default_inventory_interval() -> u64 {
    3600
}
fn default_inventory_collect() -> Vec<String> {
    vec![
        "os".to_string(),
        "network".to_string(),
        "packages".to_string(),
        "hardware".to_string(),
    ]
}
fn default_sca_policy_dir() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/etc/sn360-desktop-agent/sca")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\Program Files\SN360DesktopAgent\sca")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::new()
    }
}
fn default_sca_scan_interval() -> u64 {
    43200 // 12 hours
}
fn default_rootcheck_scan_interval() -> u64 {
    3600 // 1 hour
}
fn default_rootcheck_max_pid() -> u32 {
    32768
}
fn default_rootcheck_baseline_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/sn360-desktop-agent/rootcheck-baseline.json")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\SN360DesktopAgent\rootcheck-baseline.json")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::new()
    }
}
/// Platform-default list of critical system binary paths monitored for
/// SHA-256 drift by the rootcheck module.
pub fn default_rootcheck_binary_paths() -> Vec<String> {
    #[cfg(unix)]
    {
        vec![
            "/bin/ls".to_string(),
            "/bin/ps".to_string(),
            "/bin/login".to_string(),
            "/usr/bin/ssh".to_string(),
            "/usr/bin/sudo".to_string(),
            "/usr/bin/passwd".to_string(),
            "/usr/bin/su".to_string(),
            "/usr/sbin/sshd".to_string(),
        ]
    }
    #[cfg(windows)]
    {
        vec![
            r"C:\Windows\System32\cmd.exe".to_string(),
            r"C:\Windows\System32\svchost.exe".to_string(),
            r"C:\Windows\System32\lsass.exe".to_string(),
            r"C:\Windows\explorer.exe".to_string(),
        ]
    }
    #[cfg(not(any(unix, windows)))]
    {
        Vec::new()
    }
}
fn default_ar_timeout() -> u64 {
    30
}
fn default_running_software_interval() -> u64 {
    60
}
fn default_browser_extensions_interval() -> u64 {
    3600
}
fn default_sbom_interval() -> u64 {
    86_400 // once per day
}
fn default_lde_rule_pull_interval() -> u64 {
    300
}
fn default_lde_offline_queue_max() -> usize {
    10_000
}
fn default_lde_yara_scan_rate_limit() -> u32 {
    1
}
fn default_lde_yara_max_file_size_mb() -> u64 {
    50
}
fn default_lde_bloom_filter_fpr() -> f64 {
    0.01
}
fn default_lde_behavioral_max_window_sec() -> u64 {
    300
}
fn default_lde_behavioral_max_tracked_entities() -> usize {
    5_000
}
fn default_lde_rule_bundle_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/sn360-desktop-agent/lde-rules.msgpack")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\SN360DesktopAgent\lde-rules.msgpack")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::new()
    }
}
fn default_lde_offline_queue_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/sn360-desktop-agent/lde-offline-queue.db")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\SN360DesktopAgent\lde-offline-queue.db")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::new()
    }
}
fn default_lde_offline_drain_interval() -> u64 {
    30
}
fn default_lde_offline_drain_batch() -> usize {
    128
}
fn default_lde_trds_timeout() -> u64 {
    10
}
fn default_lde_quarantine_dir() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/sn360-desktop-agent/quarantine")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\SN360DesktopAgent\quarantine")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::new()
    }
}
fn default_ar_actions() -> Vec<String> {
    vec![
        "block_ip".to_string(),
        "kill_process".to_string(),
        "disable_account".to_string(),
    ]
}

// --- Trait implementations ---

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: default_server_address(),
            port: default_server_port(),
            protocol: default_protocol(),
            keepalive_interval: default_keepalive(),
            enhanced: EnhancedProtocolConfig::default(),
        }
    }
}

impl Default for EnrollmentConfig {
    fn default() -> Self {
        Self {
            server: None,
            port: default_enrollment_port(),
            auto_enroll: true,
            key: None,
            agent_name: None,
            groups: None,
            keys_file: None,
        }
    }
}

impl Default for InventoryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: default_inventory_interval(),
            collect: default_inventory_collect(),
        }
    }
}

impl Default for ModuleToggle {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Default for ScaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            policy_dir: default_sca_policy_dir(),
            scan_interval: default_sca_scan_interval(),
        }
    }
}

impl Default for RootcheckConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: default_rootcheck_scan_interval(),
            signature_paths: Vec::new(),
            binary_paths: Vec::new(),
            baseline_path: default_rootcheck_baseline_path(),
            hidden_process_check: true,
            binary_integrity_check: true,
            max_pid: default_rootcheck_max_pid(),
        }
    }
}

impl Default for LocalDetectionConfig {
    fn default() -> Self {
        Self {
            // Phase E2.3 — LDE is on by default once the embedded
            // bundle ships with baseline rules.
            enabled: true,
            rule_pull_interval: default_lde_rule_pull_interval(),
            offline_queue_max: default_lde_offline_queue_max(),
            yara_scan_rate_limit: default_lde_yara_scan_rate_limit(),
            yara_max_file_size_mb: default_lde_yara_max_file_size_mb(),
            bloom_filter_fpr: default_lde_bloom_filter_fpr(),
            behavioral_max_window_sec: default_lde_behavioral_max_window_sec(),
            behavioral_max_tracked_entities: default_lde_behavioral_max_tracked_entities(),
            block_ip: false,
            kill_process: false,
            quarantine: false,
            rule_bundle_path: default_lde_rule_bundle_path(),
            offline_queue_path: default_lde_offline_queue_path(),
            quarantine_dir: default_lde_quarantine_dir(),
            offline_drain_interval: default_lde_offline_drain_interval(),
            offline_drain_batch: default_lde_offline_drain_batch(),
            trds_endpoint: None,
            rule_bundle_signing_keys: Vec::new(),
            trds_pull_timeout_secs: default_lde_trds_timeout(),
        }
    }
}

impl Default for RunningSoftwareConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: default_running_software_interval(),
        }
    }
}

impl Default for BrowserExtensionsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: default_browser_extensions_interval(),
        }
    }
}

impl Default for SbomConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: default_sbom_interval(),
            on_demand: true,
        }
    }
}

impl Default for ActiveResponseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout: default_ar_timeout(),
            actions: default_ar_actions(),
        }
    }
}

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            directories: default_fim_directories(),
            scan_interval: default_fim_scan_interval(),
            debounce_ms: default_fim_debounce_ms(),
            max_hashes_per_sec: default_fim_max_hashes_per_sec(),
            batch_size: default_fim_batch_size(),
            batch_timeout_ms: default_fim_batch_timeout_ms(),
        }
    }
}

fn default_fim_directories() -> Vec<FimDirectory> {
    #[cfg(unix)]
    {
        vec![
            FimDirectory {
                path: "/etc".to_string(),
                recursive: true,
                realtime: true,
                check_sha256: true,
                exclude: Vec::new(),
            },
            FimDirectory {
                path: "/usr/bin".to_string(),
                recursive: false,
                realtime: true,
                check_sha256: true,
                exclude: Vec::new(),
            },
            FimDirectory {
                path: "/usr/sbin".to_string(),
                recursive: false,
                realtime: true,
                check_sha256: true,
                exclude: Vec::new(),
            },
            FimDirectory {
                path: "/boot".to_string(),
                recursive: true,
                realtime: true,
                check_sha256: true,
                exclude: Vec::new(),
            },
        ]
    }
    #[cfg(windows)]
    {
        vec![
            FimDirectory {
                path: r"C:\Windows\System32\drivers\etc".to_string(),
                recursive: true,
                realtime: true,
                check_sha256: true,
                exclude: Vec::new(),
            },
            FimDirectory {
                path: r"C:\Windows\System32".to_string(),
                recursive: false,
                realtime: true,
                check_sha256: true,
                exclude: Vec::new(),
            },
        ]
    }
    #[cfg(not(any(unix, windows)))]
    {
        Vec::new()
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_cpu_percent: default_max_cpu(),
            max_memory_mb: default_max_memory(),
            battery_mode: default_battery_mode(),
            idle_detection: true,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            file: None,
        }
    }
}

// =============================================================
// Device Control configuration sections (Phase 1)
// =============================================================
//
// All structs in this section default to `enabled: false`. The
// canonical source of truth for these knobs is
// `docs/configuration-reference.md` (Device Control section).

/// Device Control core configuration.
///
/// Controls the `sda-device-control` router (signed-job validation +
/// finding fan-out) and the cross-cutting policy knobs that bind every
/// Device Control action — maintenance window, quiet hours, and the
/// per-job resource budget.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceControlConfig {
    /// Master enable switch. Defaults to `false` per the
    /// lazy-module-loading principle.
    #[serde(default)]
    pub enabled: bool,

    /// Maintenance window when long-running Device Control jobs may
    /// run. Outside the window, jobs that opt into maintenance-window
    /// gating are queued.
    #[serde(default)]
    pub maintenance_window: MaintenanceWindow,

    /// Quiet hours when interactive prompts are suppressed and only
    /// `Critical` events fire.
    #[serde(default)]
    pub quiet_hours: QuietHours,

    /// Per-job resource budget. Jobs that exceed the budget are
    /// terminated and a `JobRefused::ResourceLimit` `ActionResult` is
    /// emitted.
    #[serde(default)]
    pub job_budget: JobBudget,

    /// USB / removable-media policy enforcement (Phase D2).
    /// Off by default; flipping `usb_policy.enabled` to `true` lights
    /// up the per-OS enforcement helper IPC server and wires the
    /// supervisor into the bundle apply path.
    #[serde(default)]
    pub usb_policy: UsbPolicyConfig,
}

/// USB / removable-media / peripheral device policy enforcement.
///
/// Maps directly onto
/// [`sda_device_control::usb_supervisor::UsbPolicySupervisorConfig`]
/// at module-startup time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbPolicyConfig {
    /// Master enable switch. Off by default.
    #[serde(default)]
    pub enabled: bool,

    /// Action used when no policy matches a candidate AND a
    /// verified policy set is loaded. Wire-format kebab-case:
    /// `block` / `allow` / `audit`. Defaults to `audit`.
    #[serde(default = "default_usb_policy_default_action")]
    pub default_action: String,

    /// Action used when no verified policy set is loaded yet
    /// (fresh boot, or last bundle was tampered). Operators that
    /// want closed-by-default flip this to `block`. Defaults to
    /// `audit` so a fresh agent records every attach event without
    /// changing OS behaviour.
    #[serde(default = "default_usb_policy_fallback_action")]
    pub fallback_action: String,

    /// Path to the IPC socket / named pipe used by the per-OS
    /// helper to query the supervisor. Defaults to the
    /// platform-native location (`/run/sn360-desktop-agent/usb-policy.sock`
    /// on Linux, `\\.\pipe\sn360-usb-policy` on Windows,
    /// `/var/run/sn360-desktop-agent/usb-policy.sock` on macOS).
    #[serde(default)]
    pub ipc_path: String,
}

fn default_usb_policy_default_action() -> String {
    "audit".to_string()
}

fn default_usb_policy_fallback_action() -> String {
    "audit".to_string()
}

impl Default for UsbPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_action: default_usb_policy_default_action(),
            fallback_action: default_usb_policy_fallback_action(),
            ipc_path: String::new(),
        }
    }
}

/// Maintenance window for batched Device Control work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceWindow {
    /// Whether the window is enabled. Disabled by default.
    #[serde(default)]
    pub enabled: bool,
    /// Start time in `HH:MM` (24h, local time).
    #[serde(default = "default_maintenance_window_start")]
    pub start: String,
    /// End time in `HH:MM` (24h, local time).
    #[serde(default = "default_maintenance_window_end")]
    pub end: String,
    /// Days of the week the window applies on (`mon`..`sun`).
    #[serde(default = "default_maintenance_window_days")]
    pub days: Vec<String>,
}

impl Default for MaintenanceWindow {
    fn default() -> Self {
        Self {
            enabled: false,
            start: default_maintenance_window_start(),
            end: default_maintenance_window_end(),
            days: default_maintenance_window_days(),
        }
    }
}

/// Quiet hours when interactive prompts and non-critical events are
/// suppressed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuietHours {
    /// Whether quiet hours are enforced. Disabled by default.
    #[serde(default)]
    pub enabled: bool,
    /// Start time in `HH:MM` (24h, local time).
    #[serde(default = "default_quiet_hours_start")]
    pub start: String,
    /// End time in `HH:MM` (24h, local time).
    #[serde(default = "default_quiet_hours_end")]
    pub end: String,
}

impl Default for QuietHours {
    fn default() -> Self {
        Self {
            enabled: false,
            start: default_quiet_hours_start(),
            end: default_quiet_hours_end(),
        }
    }
}

/// Per-job resource budget enforced by `sda-device-control::router`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobBudget {
    /// Maximum CPU percent the job is allowed to draw.
    #[serde(default = "default_job_max_cpu_percent")]
    pub max_cpu_percent: u8,
    /// Maximum RSS in MB.
    #[serde(default = "default_job_max_rss_mb")]
    pub max_rss_mb: u32,
    /// Maximum wall-clock duration in seconds.
    #[serde(default = "default_job_max_wall_secs")]
    pub max_wall_secs: u64,
}

impl Default for JobBudget {
    fn default() -> Self {
        Self {
            max_cpu_percent: default_job_max_cpu_percent(),
            max_rss_mb: default_job_max_rss_mb(),
            max_wall_secs: default_job_max_wall_secs(),
        }
    }
}

/// `sda-query` (osquery sidecar) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryConfig {
    /// Master enable switch.
    #[serde(default)]
    pub enabled: bool,
    /// Sidecar configuration for the osquery process the query module
    /// drives.
    #[serde(default)]
    pub osquery: OsqueryConfig,
    /// Interval in seconds between scheduled-query polls. Defaults to
    /// 300 (5 minutes).
    #[serde(default = "default_query_schedule_poll_secs")]
    pub schedule_poll_secs: u64,
}

impl Default for QueryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            osquery: OsqueryConfig::default(),
            schedule_poll_secs: default_query_schedule_poll_secs(),
        }
    }
}

/// osquery sidecar configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsqueryConfig {
    /// One of `"sidecar"` (agent spawns and supervises osquery),
    /// `"external"` (agent connects to an existing osquery socket), or
    /// `"disabled"`.
    #[serde(default = "default_osquery_mode")]
    pub mode: String,
    /// Path to the `osqueryd` (or `osqueryi`) binary on the host.
    #[serde(default = "default_osquery_binary_path")]
    pub binary_path: PathBuf,
    /// Path to the osquery extension socket.
    #[serde(default = "default_osquery_socket_path")]
    pub socket_path: PathBuf,
    /// Maximum RSS the sidecar is allowed to consume.
    #[serde(default = "default_osquery_max_rss_mb")]
    pub max_rss_mb: u32,
    /// Maximum CPU percent the sidecar is allowed to consume.
    #[serde(default = "default_osquery_max_cpu_percent")]
    pub max_cpu_percent: u8,
}

impl Default for OsqueryConfig {
    fn default() -> Self {
        Self {
            mode: default_osquery_mode(),
            binary_path: default_osquery_binary_path(),
            socket_path: default_osquery_socket_path(),
            max_rss_mb: default_osquery_max_rss_mb(),
            max_cpu_percent: default_osquery_max_cpu_percent(),
        }
    }
}

/// `sda-posture` (device-posture snapshots) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureConfig {
    /// Master enable switch.
    #[serde(default)]
    pub enabled: bool,
    /// Interval in seconds between posture snapshots. Defaults to
    /// 900 (15 minutes).
    #[serde(default = "default_posture_interval_secs")]
    pub interval_secs: u64,
    /// Whether to defer snapshots while on battery (power-aware
    /// scheduling). Defaults to `true`.
    #[serde(default = "default_true")]
    pub defer_on_battery: bool,
}

impl Default for PostureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: default_posture_interval_secs(),
            defer_on_battery: true,
        }
    }
}

/// Software management module configuration (Phase 2). Defaults to
/// disabled.
///
/// When `enabled = true` and `modules.device_control.enabled = true`,
/// the [`SoftwareModule`](../../../sda-software/index.html) refreshes
/// the signed catalogue manifest at `refresh_interval_secs` cadence
/// and gates every install / update / uninstall on a verified
/// Ed25519 signature against the configured pinned keys.
///
/// Phase 2.6 hardens this with key rotation
/// ([`Self::pinned_signing_keys`]) and manifest expiry
/// ([`Self::manifest_max_age_secs`]). The legacy
/// [`Self::pinned_signing_key_hex`] field is retained as a backward
/// compatible single-key shortcut and is treated as a pinned key
/// with `key_id = "default"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareConfig {
    /// Master enable switch.
    #[serde(default)]
    pub enabled: bool,
    /// HTTPS URL of the signed catalogue manifest. Optional so an
    /// SDA build with the module enabled but no URL configured will
    /// log a warning and idle rather than panicking. The agent only
    /// fetches when `enabled = true` AND `catalogue_url.is_some()`.
    #[serde(default)]
    pub catalogue_url: Option<String>,
    /// Legacy single-key fallback. Hex-encoded Ed25519 public key
    /// the manifest signature is verified against when no
    /// [`Self::pinned_signing_keys`] entries are configured. The
    /// control plane rotates this by pushing a new config; we never
    /// trust a manifest-embedded key.
    #[serde(default)]
    pub pinned_signing_key_hex: Option<String>,
    /// Multiple pinned signing keys for key rotation. Each entry
    /// pairs a stable `key_id` (matching the `key_id` field on the
    /// signed manifest) with the lowercase-hex Ed25519 public key
    /// bytes. When non-empty this list takes precedence over the
    /// legacy [`Self::pinned_signing_key_hex`] field.
    #[serde(default)]
    pub pinned_signing_keys: Vec<PinnedSigningKey>,
    /// Maximum age, in seconds, of a catalogue manifest before it
    /// is rejected as expired. The age is computed from the
    /// `signed_at` timestamp on the manifest. Defaults to 7 days.
    #[serde(default = "default_manifest_max_age_secs")]
    pub manifest_max_age_secs: u64,
    /// How often the agent re-pulls the manifest (default 1 h).
    /// Catalogue updates between fetches still respect maintenance
    /// windows on the action side.
    #[serde(default = "default_software_refresh_interval_secs")]
    pub refresh_interval_secs: u64,
}

/// Hex-encoded Ed25519 public key paired with the `key_id` it is
/// announced under in the catalogue manifest. Used for key rotation
/// (multiple pinned keys may be active simultaneously while the
/// control plane completes a rollover).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinnedSigningKey {
    /// Stable identifier matched against the manifest's `key_id`
    /// field. Producers must keep these unique across simultaneously
    /// pinned keys.
    pub key_id: String,
    /// Lowercase-hex Ed25519 public key (64 hex chars / 32 bytes).
    pub public_key_hex: String,
}

impl Default for SoftwareConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            catalogue_url: None,
            pinned_signing_key_hex: None,
            pinned_signing_keys: Vec::new(),
            manifest_max_age_secs: default_manifest_max_age_secs(),
            refresh_interval_secs: default_software_refresh_interval_secs(),
        }
    }
}

/// JIT-admin module configuration.
///
/// Phase 3.2 introduces the `sda-jit-admin` module which owns the
/// grant lifecycle state machine and revocation watchdog. Defaults
/// to disabled so an SDA built without jit-admin work configured
/// keeps idle CPU at zero.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitAdminConfig {
    /// Master enable switch.
    #[serde(default)]
    pub enabled: bool,
    /// Filesystem path where active grants are persisted across
    /// agent restarts. The directory must be writable by the agent
    /// service account; the file itself is created on first grant.
    #[serde(default)]
    pub state_path: Option<PathBuf>,
    /// Revoke an active grant when no heartbeat has been observed
    /// from the control plane for this many seconds. Defaults to
    /// 120 s per `docs/device-control.md` § 7 (Just-in-Time admin).
    #[serde(default = "default_jit_heartbeat_loss_secs")]
    pub heartbeat_loss_secs: u64,
    /// How often the JIT-admin supervisor runs a drift scan
    /// (`AdminManager::list_admins` vs the active grant ledger). The
    /// supervisor emits a `FindingKind::AdminDrift` payload + paired
    /// `EvidenceRecord` for each discrepancy. Defaults to 300 s
    /// (Phase 3.5 / `docs/device-control.md` § 7 — Just-in-Time admin).
    #[serde(default = "default_jit_drift_check_interval_secs")]
    pub drift_check_interval_secs: u64,
}

impl Default for JitAdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            state_path: None,
            heartbeat_loss_secs: default_jit_heartbeat_loss_secs(),
            drift_check_interval_secs: default_jit_drift_check_interval_secs(),
        }
    }
}

/// Script-runner module configuration.
///
/// Phase 2.7 introduces the `sda-script-runner` module which
/// executes signed scripts against an allow-list of canonical names.
/// Defaults to disabled so the surface area stays at zero on
/// builds that do not opt in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptRunnerConfig {
    /// Master enable switch.
    #[serde(default)]
    pub enabled: bool,
    /// Hex-encoded Ed25519 public key against which every script
    /// payload's signature is verified. Required when `enabled =
    /// true`; unset means no scripts may run even if jobs arrive.
    #[serde(default)]
    pub pinned_signing_key_hex: Option<String>,
    /// Glob patterns that a script's canonical name must match
    /// before it is allowed to run (e.g. `sn360.diagnostics.*`).
    /// Empty means deny-by-default.
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// Hard wall-clock limit, in seconds, for any single script run.
    /// Defaults to 90 s. Bounded by `RUN_SCRIPT_MAX_TIMEOUT_SECONDS`
    /// upstream in `sda-device-control`.
    #[serde(default = "default_script_max_duration_secs")]
    pub max_duration_secs: u64,
    /// Hard cap, in bytes, on combined stdout+stderr captured from
    /// a script run before truncation. Defaults to 1 MiB.
    #[serde(default = "default_script_max_output_bytes")]
    pub max_output_bytes: usize,
}

impl Default for ScriptRunnerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pinned_signing_key_hex: None,
            allowlist: Vec::new(),
            max_duration_secs: default_script_max_duration_secs(),
            max_output_bytes: default_script_max_output_bytes(),
        }
    }
}

/// Application-control module configuration (Phase 4).
///
/// Defaults to disabled. The Phase-4 default mode is `Monitor` per
/// `docs/device-control.md` § 8 (Application control) —
/// `Enforce` requires explicit tenant opt-in plus dual-control
/// rollback per the same section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppControlConfig {
    /// Master enable switch.
    #[serde(default)]
    pub enabled: bool,
    /// Operating mode: `"monitor"`, `"enforce"`, or `"disabled"`.
    /// Mapped onto `sda_pal::app_control::AppControlMode` at module
    /// startup. Defaults to `"monitor"` so a Phase-4 enable does
    /// not accidentally start blocking traffic.
    #[serde(default = "default_app_control_mode")]
    pub mode: String,
    /// Lowercase-hex Ed25519 public key the agent will trust when
    /// verifying signed policy bundles. `None` disables policy
    /// application entirely (the agent only reports
    /// `current_mode`).
    #[serde(default)]
    pub trusted_signing_key: Option<String>,
}

impl Default for AppControlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_app_control_mode(),
            trusted_signing_key: None,
        }
    }
}

/// Remote-support module configuration (Phase 4).
///
/// Defaults to disabled. When `enabled = true` the module shows a
/// consent prompt on every session per `docs/device-control.md` § 9 and
/// enforces `max_session_minutes` as a hard wall-clock cap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteSupportConfig {
    /// Master enable switch.
    #[serde(default)]
    pub enabled: bool,
    /// Hard wall-clock cap on a remote-support session, in minutes
    /// (default 30). Must be > 0; a zero value would let a
    /// malformed config short-circuit the consent flow.
    #[serde(default = "default_remote_support_max_session_minutes")]
    pub max_session_minutes: u32,
    /// Whether the agent must present a consent banner before
    /// transitioning a session into `Active`. Always `true` in
    /// production per `docs/device-control.md` § 9; the field exists so unit
    /// tests can construct sessions without a UI fixture.
    #[serde(default = "default_true")]
    pub require_consent: bool,
}

impl Default for RemoteSupportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_session_minutes: default_remote_support_max_session_minutes(),
            require_consent: true,
        }
    }
}

/// Agent-vitals heartbeat configuration (Phase 1, Task 1.12).
///
/// When `enabled = true`, the
/// [`VitalsModule`](../../../sda_agent_vitals/index.html) emits an
/// `EventKind::AgentVitals` event on every tick at a cadence of
/// `interval_secs` seconds (default 60s, matching
/// `docs/architecture.md` § 3.1 — `Priority::Low`).
///
/// The agent supervisor wires this on automatically when
/// `modules.device_control.enabled = true`, but operators can also
/// opt-in independently by flipping `enabled = true` here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentVitalsConfig {
    /// Master enable switch.
    #[serde(default)]
    pub enabled: bool,
    /// Heartbeat cadence in seconds. Defaults to 60s
    /// (`Priority::Low` per `docs/architecture.md` § 3.1).
    #[serde(default = "default_agent_vitals_interval_secs")]
    pub interval_secs: u64,
}

impl Default for AgentVitalsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: default_agent_vitals_interval_secs(),
        }
    }
}

// --- Device Control default value functions ---

fn default_maintenance_window_start() -> String {
    "02:00".to_string()
}

fn default_maintenance_window_end() -> String {
    "05:00".to_string()
}

fn default_maintenance_window_days() -> Vec<String> {
    vec![
        "mon".to_string(),
        "tue".to_string(),
        "wed".to_string(),
        "thu".to_string(),
        "fri".to_string(),
        "sat".to_string(),
        "sun".to_string(),
    ]
}

fn default_quiet_hours_start() -> String {
    "22:00".to_string()
}

fn default_quiet_hours_end() -> String {
    "07:00".to_string()
}

fn default_job_max_cpu_percent() -> u8 {
    20
}

fn default_job_max_rss_mb() -> u32 {
    256
}

fn default_job_max_wall_secs() -> u64 {
    900
}

fn default_query_schedule_poll_secs() -> u64 {
    300
}

fn default_osquery_mode() -> String {
    "sidecar".to_string()
}

fn default_osquery_binary_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/usr/bin/osqueryd")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/usr/local/bin/osqueryd")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\Program Files\osquery\osqueryd\osqueryd.exe")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        PathBuf::new()
    }
}

fn default_osquery_socket_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/sn360-desktop-agent/osquery.sock")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"\\.\pipe\sn360-osquery")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::new()
    }
}

fn default_osquery_max_rss_mb() -> u32 {
    60
}

fn default_osquery_max_cpu_percent() -> u8 {
    5
}

fn default_posture_interval_secs() -> u64 {
    900
}

fn default_software_refresh_interval_secs() -> u64 {
    3600
}

/// Default manifest expiry threshold — 7 days. Matches the
/// "manifest must be re-signed at least weekly" guidance in
/// `docs/device-control.md` § 6 (Approved software catalogue).
fn default_manifest_max_age_secs() -> u64 {
    7 * 24 * 3600
}

/// Default JIT-admin heartbeat-loss revoke window. Matches
/// `docs/device-control.md` § 7 (Just-in-Time admin) (120 s).
fn default_jit_heartbeat_loss_secs() -> u64 {
    120
}

/// Default JIT-admin drift-scan cadence. Matches `default_posture_interval_secs`
/// (300 s) so the drift detector runs on the same cadence as posture
/// snapshots without piling up on top of the watchdog tick. See
/// `docs/device-control.md` § 7 (Just-in-Time admin).
fn default_jit_drift_check_interval_secs() -> u64 {
    300
}

/// Default per-script wall-clock cap (90 s) per
/// `docs/device-control.md` § 2 (Modules — `sda-script-runner`).
fn default_script_max_duration_secs() -> u64 {
    90
}

/// Default per-script combined stdout+stderr cap (1 MiB) per
/// `docs/device-control.md` § 2 (Modules — `sda-script-runner`).
fn default_script_max_output_bytes() -> usize {
    1024 * 1024
}

fn default_agent_vitals_interval_secs() -> u64 {
    60
}

/// Default Phase-4 application-control mode. `docs/device-control.md` § 8
/// mandates `Monitor` so an accidental `enabled = true` does not start
/// blocking traffic.
fn default_app_control_mode() -> String {
    "monitor".to_string()
}

/// Default Phase-4 remote-support session cap (30 minutes).
/// `docs/device-control.md` § 9 specifies "≤30 min" as the typical bound; the
/// supervisor truncates anything longer.
fn default_remote_support_max_session_minutes() -> u32 {
    30
}

// -------------------------------------------------------------------------
// ShieldNet Desktop MDM (Phase M1–M3) — configuration schema.
//
// Mirrors the Desktop MDM section of `docs/configuration-reference.md`
// verbatim. The distinguishing property versus every other
// Phase-1+ module config
// is that `MdmConfig::default()` produces `enabled = true` with every
// `auto_remediate.*` flag also `true`. This is the documented
// "defaults-on" posture per `docs/desktop-mdm.md` § 1 (Product loop).
// -------------------------------------------------------------------------

/// Top-level Desktop MDM configuration. **Defaults to ON.**
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdmConfig {
    /// Master enable switch. Defaults to `true` — see the module
    /// docstring for the rationale.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Auto-remediation supervisor settings (Phase M1.2). Drives the
    /// posture-snapshot subscriber that self-signs local jobs when
    /// FDE / firewall / screen-lock are off.
    #[serde(default)]
    pub auto_remediate: AutoRemediateConfig,

    /// OS patch orchestration settings (Phase M1.4).
    #[serde(default)]
    pub os_patch: OsPatchConfig,

    /// Recovery-key escrow settings (Phase M1.3).
    #[serde(default)]
    pub recovery_key_escrow: RecoveryKeyEscrowConfig,

    /// Lost-mode settings (Phase M2.3).
    #[serde(default)]
    pub lost_mode: LostModeConfig,

    /// Declarative configuration profiles (Phase M3).
    #[serde(default)]
    pub config_profiles: ConfigProfilesConfig,

    /// Filesystem path of the TRDS-pushed signed config profile
    /// bundle. The Phase M3 watcher mounts a `notify` watcher here
    /// and re-applies the profile on every successful signature
    /// verification.
    #[serde(default = "default_mdm_bundle_path")]
    pub bundle_path: PathBuf,
}

impl Default for MdmConfig {
    /// MDM is the **only** Phase-1+ module whose default is
    /// `enabled = true` with every `auto_remediate.*` flag also
    /// `true`. This intentionally diverges from every sibling
    /// module (Device Control, Software, Posture, Query, JIT-admin,
    /// App Control, etc.), all of which default to `enabled =
    /// false`.
    ///
    /// **Rationale:** the three default-on remediations (disk
    /// encryption, host firewall, screen lock) are the
    /// industry-baseline posture controls that no production fleet
    /// should ship without. Defaulting them off would make
    /// "upgraded but mis-configured" fleets indistinguishable from
    /// "intentionally lax" ones, and the operator has no audit
    /// signal that the agent _could_ have remediated but did not.
    /// Per `docs/desktop-mdm.md` § 8 (Auto-remediation) the design
    /// requires a single explicit opt-out by tenants who do not
    /// want this behaviour.
    ///
    /// **Upgrade path:** existing deployments that upgrade to the
    /// build containing the MDM module will immediately begin
    /// auto-remediating FDE / firewall / screen-lock posture on
    /// every enrolled device. Tenants who do _not_ want this MUST
    /// add `modules.mdm.enabled = false` (or set individual
    /// `modules.mdm.auto_remediate.*` flags to `false`) to their
    /// rendered config **before** rolling the upgrade. The agent
    /// honours the YAML override on first load — there is no
    /// hidden gate beyond the standard config-merge path in
    /// `AgentConfig::from_yaml_file`.
    fn default() -> Self {
        Self {
            enabled: true,
            auto_remediate: AutoRemediateConfig::default(),
            os_patch: OsPatchConfig::default(),
            recovery_key_escrow: RecoveryKeyEscrowConfig::default(),
            lost_mode: LostModeConfig::default(),
            config_profiles: ConfigProfilesConfig::default(),
            bundle_path: default_mdm_bundle_path(),
        }
    }
}

/// Auto-remediation supervisor configuration. All three remediation
/// flags default to `true`; the debounce window defaults to 24 h.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoRemediateConfig {
    /// Auto-enable disk encryption when posture reports it as off.
    #[serde(default = "default_true")]
    pub disk_encryption: bool,
    /// Auto-enable the host firewall when posture reports it as off.
    #[serde(default = "default_true")]
    pub firewall: bool,
    /// Auto-enable screen-lock when posture reports it as off.
    #[serde(default = "default_true")]
    pub screen_lock: bool,
    /// Screen-lock idle timeout in seconds (default 300 s).
    #[serde(default = "default_screen_lock_timeout_secs")]
    pub screen_lock_timeout_secs: u32,
    /// Debounce window for repeated auto-remediation attempts of the
    /// same kind. Defaults to 86 400 s (24 h) per
    /// `docs/desktop-mdm.md` § 8 (Auto-remediation).
    #[serde(default = "default_remediation_debounce_secs")]
    pub remediation_debounce_secs: u64,
}

impl Default for AutoRemediateConfig {
    fn default() -> Self {
        Self {
            disk_encryption: true,
            firewall: true,
            screen_lock: true,
            screen_lock_timeout_secs: default_screen_lock_timeout_secs(),
            remediation_debounce_secs: default_remediation_debounce_secs(),
        }
    }
}

/// OS patch orchestration configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsPatchConfig {
    /// Master enable switch. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Auto-install security updates (default `true`).
    #[serde(default = "default_true")]
    pub auto_install_security: bool,
    /// Auto-install all updates including feature updates
    /// (default `false`).
    #[serde(default)]
    pub auto_install_all: bool,
    /// Defer patch jobs while on battery (default `true`).
    #[serde(default = "default_true")]
    pub defer_on_battery: bool,
}

impl Default for OsPatchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_install_security: true,
            auto_install_all: false,
            defer_on_battery: true,
        }
    }
}

/// Recovery-key escrow configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryKeyEscrowConfig {
    /// Master enable switch.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Escrow at most once per boot (default `true`). The agent
    /// re-runs the escrow only if the underlying recovery key
    /// rotates.
    #[serde(default = "default_true")]
    pub one_time_per_boot: bool,
}

impl Default for RecoveryKeyEscrowConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            one_time_per_boot: true,
        }
    }
}

/// Lost-mode configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LostModeConfig {
    /// Message shown on the locked screen while lost mode is active.
    /// Supports `{tenant_name}` / `{tenant_email}` substitutions at
    /// runtime.
    #[serde(default = "default_lost_mode_message")]
    pub message: String,
    /// Interval in seconds between background location reports.
    /// Defaults to 300 s.
    #[serde(default = "default_lost_mode_report_interval_secs")]
    pub report_location_interval_secs: u64,
}

impl Default for LostModeConfig {
    fn default() -> Self {
        Self {
            message: default_lost_mode_message(),
            report_location_interval_secs: default_lost_mode_report_interval_secs(),
        }
    }
}

/// Declarative configuration profile defaults. These are applied
/// when no signed profile has been pushed yet.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigProfilesConfig {
    /// Password policy (length, complexity, max age, lockout).
    #[serde(default)]
    pub password_policy: PasswordPolicyConfig,
    /// Screen-lock policy.
    #[serde(default)]
    pub screen_lock: ScreenLockPolicyConfig,
    /// Bluetooth policy. One of `"allow"`, `"audit"`, `"block"`.
    #[serde(default = "default_bluetooth_policy")]
    pub bluetooth: String,
    /// Camera policy. One of `"allow"`, `"audit"`, `"block"`.
    #[serde(default = "default_camera_policy")]
    pub camera: String,
    /// Wi-Fi policy.
    #[serde(default)]
    pub wifi: WifiPolicyConfig,
}

/// Password policy configuration applied via `pwpolicy` /
/// `pam_pwquality.conf` / `secedit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicyConfig {
    /// Minimum password length (default 8).
    #[serde(default = "default_password_min_length")]
    pub min_length: u8,
    /// Whether complex passwords (mixed case + digit + symbol) are
    /// required (default `true`).
    #[serde(default = "default_true")]
    pub require_complexity: bool,
    /// Maximum password age in days (default 90).
    #[serde(default = "default_password_max_age_days")]
    pub max_age_days: u32,
    /// Maximum failed attempts before lockout (default 5).
    #[serde(default = "default_password_max_attempts")]
    pub max_attempts: u8,
    /// Lockout duration in minutes (default 15).
    #[serde(default = "default_password_lockout_minutes")]
    pub lockout_minutes: u32,
}

impl Default for PasswordPolicyConfig {
    fn default() -> Self {
        Self {
            min_length: default_password_min_length(),
            require_complexity: true,
            max_age_days: default_password_max_age_days(),
            max_attempts: default_password_max_attempts(),
            lockout_minutes: default_password_lockout_minutes(),
        }
    }
}

/// Screen-lock policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenLockPolicyConfig {
    /// Idle timeout in seconds before the screen locks (default 300).
    #[serde(default = "default_screen_lock_timeout_secs_long")]
    pub timeout_secs: u32,
    /// Whether a password is required on resume (default `true`).
    #[serde(default = "default_true")]
    pub require_password_on_resume: bool,
}

impl Default for ScreenLockPolicyConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_screen_lock_timeout_secs_long(),
            require_password_on_resume: true,
        }
    }
}

/// Wi-Fi policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WifiPolicyConfig {
    /// List of allowed SSIDs. An empty list means no restriction.
    #[serde(default)]
    pub allowed_ssids: Vec<String>,
    /// Block open (unencrypted) networks regardless of SSID list.
    #[serde(default)]
    pub block_open_networks: bool,
}

// --- MDM default value helpers ---

fn default_screen_lock_timeout_secs() -> u32 {
    300
}

fn default_screen_lock_timeout_secs_long() -> u32 {
    300
}

fn default_remediation_debounce_secs() -> u64 {
    86_400
}

fn default_lost_mode_message() -> String {
    "This device belongs to {tenant_name}. Please contact {tenant_email}.".to_string()
}

fn default_lost_mode_report_interval_secs() -> u64 {
    300
}

fn default_bluetooth_policy() -> String {
    "audit".to_string()
}

fn default_camera_policy() -> String {
    "allow".to_string()
}

fn default_password_min_length() -> u8 {
    8
}

fn default_password_max_age_days() -> u32 {
    90
}

fn default_password_max_attempts() -> u8 {
    5
}

fn default_password_lockout_minutes() -> u32 {
    15
}

fn default_mdm_bundle_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/sn360-desktop-agent/bundle/policy/mdm/profile.json")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\SN360DesktopAgent\bundle\policy\mdm\profile.json")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::new()
    }
}

// ===========================================================================
// EDR Parity (Phase E1-E3) module configurations.
//
// All four EDR modules default to `enabled = false` per the lazy-
// module-loading principle — the agent's idle footprint is bit-for-
// bit identical to the pre-EDR baseline when every flag is left at
// its default. See `docs/configuration-reference.md` (Modules — EDR
// section).
// ===========================================================================

/// Process Telemetry (Phase E1) configuration.
///
/// Drives the `sda-process-monitor` crate which subscribes to the
/// platform process feed (Linux `cn_proc` + `/proc`, Windows ETW,
/// macOS Endpoint Security) and reconstructs parent chains on
/// each `Created` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMonitorConfig {
    /// Whether the process telemetry module is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Maximum number of ancestors walked on each `Created` event.
    #[serde(default = "default_process_monitor_parent_chain_depth")]
    pub parent_chain_depth: u32,
    /// Whether to emit `ImageLoaded` events for shared-library / DLL
    /// loads. Best-effort on Linux; native on Windows/macOS.
    #[serde(default = "default_true")]
    pub image_load_events: bool,
    /// Size of the bounded mpsc channel used by the PAL. On overflow
    /// the oldest event is dropped and a vitals counter is bumped.
    #[serde(default = "default_process_monitor_event_buffer_size")]
    pub event_buffer_size: usize,
    /// Poll interval (milliseconds) for the Linux `/proc` fallback.
    /// Ignored when the netlink / ETW / Endpoint Security backends
    /// are in use.
    #[serde(default = "default_process_monitor_poll_interval_ms")]
    pub poll_interval_ms: u64,
}

impl Default for ProcessMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            parent_chain_depth: default_process_monitor_parent_chain_depth(),
            image_load_events: true,
            event_buffer_size: default_process_monitor_event_buffer_size(),
            poll_interval_ms: default_process_monitor_poll_interval_ms(),
        }
    }
}

fn default_process_monitor_parent_chain_depth() -> u32 {
    8
}
fn default_process_monitor_event_buffer_size() -> usize {
    4096
}
fn default_process_monitor_poll_interval_ms() -> u64 {
    500
}

/// Network Telemetry (Phase E3) configuration.
///
/// Drives the `sda-network-monitor` crate which subscribes to the
/// platform network connection feed (Linux audit + `/proc/net`,
/// Windows ETW, macOS Network Extension).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitorConfig {
    /// Whether the network telemetry module is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Whether to surface outbound connections.
    #[serde(default = "default_true")]
    pub direction_outbound: bool,
    /// Whether to surface inbound connections (listeners + accepts).
    #[serde(default = "default_true")]
    pub direction_inbound: bool,
    /// Sample high-rate UDP flows to bound event volume.
    #[serde(default = "default_true")]
    pub sample_high_rate_udp: bool,
    /// Bounded mpsc channel size between the PAL and the module.
    #[serde(default = "default_network_monitor_event_buffer_size")]
    pub event_buffer_size: usize,
}

impl Default for NetworkMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            direction_outbound: true,
            direction_inbound: true,
            sample_high_rate_udp: true,
            event_buffer_size: default_network_monitor_event_buffer_size(),
        }
    }
}

fn default_network_monitor_event_buffer_size() -> usize {
    8192
}

/// DNS Telemetry (Phase E3) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsMonitorConfig {
    /// Whether the DNS telemetry module is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Source of DNS events. `"auto"` lets the PAL pick the best
    /// backend for the host (Linux: systemd-resolved tap, Windows:
    /// ETW DNS-Client, macOS: NEDNSProxyProvider).
    #[serde(default = "default_dns_monitor_source")]
    pub source: String,
}

impl Default for DnsMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            source: default_dns_monitor_source(),
        }
    }
}

fn default_dns_monitor_source() -> String {
    "auto".to_string()
}

/// Host Isolation (Phase E3) configuration.
///
/// Drives the `sda-host-isolation` crate which consumes
/// `IsolateHost` / `UnisolateHost` `SignedActionJob`s and flips the
/// per-OS firewall (nftables / Windows Firewall / pfctl) into a
/// default-drop posture with an allow-list anchored on the agent's
/// control-plane CIDRs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostIsolationConfig {
    /// Whether the host isolation module is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// CIDR ranges (IPv4 or IPv6) that MUST remain reachable while
    /// the host is isolated. Required when `enabled = true`; the
    /// agent refuses to isolate when this list is empty so the
    /// operator cannot accidentally cut the control-plane channel.
    #[serde(default)]
    pub control_plane_cidrs: Vec<String>,
    /// Always permit DNS to system resolvers while isolated. Recommended.
    #[serde(default = "default_true")]
    pub always_allow_dns: bool,
    /// Always permit loopback traffic while isolated. Recommended.
    #[serde(default = "default_true")]
    pub always_allow_loopback: bool,
}

impl Default for HostIsolationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            control_plane_cidrs: Vec::new(),
            always_allow_dns: true,
            always_allow_loopback: true,
        }
    }
}

/// Memory Scanner (Phase E4) configuration.
///
/// Drives the `sda-memory-scanner` crate which periodically enumerates
/// committed RWX / anonymous / JIT regions of running processes via
/// [`sda_pal::memory_scanner::MemoryScanner`] and feeds them through
/// the in-memory YARA matcher in `sda-local-detection`.
///
/// The agent process is ALWAYS excluded from scanning regardless of
/// the `allow_list_processes` field (see
/// `docs/architecture.md` § 8.3 — Memory-scanner safety).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScannerConfig {
    /// Whether the memory scanner module is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Interval between scan windows in seconds (default: 300).
    #[serde(default = "default_memory_scan_interval_secs")]
    pub scan_interval_secs: u64,
    /// Skip a scan window when system-wide CPU exceeds this percentage
    /// (default: 20). Set to `100` to disable idle gating.
    #[serde(default = "default_memory_only_when_idle_below_cpu_pct")]
    pub only_when_idle_below_cpu_pct: u32,
    /// Process names that MUST NOT be scanned. The agent process is
    /// always excluded in addition to this list.
    #[serde(default = "default_memory_allow_list_processes")]
    pub allow_list_processes: Vec<String>,
    /// Source of YARA rules (`"trds"` for the standard TRDS bundle
    /// pipeline; reserved for future override mechanisms).
    #[serde(default = "default_memory_yara_rule_source")]
    pub yara_rule_source: String,
    /// Defer scans when the host is on battery. Recommended.
    #[serde(default = "default_true")]
    pub defer_on_battery: bool,
    /// Maximum bytes read per region per scan. Bounds the agent
    /// memory footprint and the YARA scanning budget. 0 means
    /// "read the entire region" (not recommended).
    #[serde(default = "default_memory_max_region_bytes")]
    pub max_region_bytes: usize,
}

impl Default for MemoryScannerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: default_memory_scan_interval_secs(),
            only_when_idle_below_cpu_pct: default_memory_only_when_idle_below_cpu_pct(),
            allow_list_processes: default_memory_allow_list_processes(),
            yara_rule_source: default_memory_yara_rule_source(),
            defer_on_battery: true,
            max_region_bytes: default_memory_max_region_bytes(),
        }
    }
}

fn default_memory_scan_interval_secs() -> u64 {
    300
}
fn default_memory_only_when_idle_below_cpu_pct() -> u32 {
    20
}
fn default_memory_allow_list_processes() -> Vec<String> {
    vec!["sn360-desktop-agent".to_string()]
}
fn default_memory_yara_rule_source() -> String {
    "trds".to_string()
}
fn default_memory_max_region_bytes() -> usize {
    // 4 MiB per region. Matches the resource budget cap from
    // `docs/architecture.md` § 5.2 (memory scanner peak 4 MB / 1% CPU).
    4 * 1024 * 1024
}

/// Identity Monitor (Phase E5) configuration.
///
/// Drives the `sda-identity-monitor` crate which surfaces LSASS
/// access (Windows ETW), `/etc/shadow` + `/proc/kcore` reads (Linux,
/// reusing FIM), and keychain access (macOS Endpoint Security).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityMonitorConfig {
    /// Whether the identity monitor module is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Watch LSASS handle openings via ETW
    /// `Microsoft-Windows-Threat-Intelligence` on Windows.
    #[serde(default = "default_true")]
    pub lsass_access_windows: bool,
    /// Watch `/etc/shadow` and `/proc/kcore` reads on Linux.
    #[serde(default = "default_true")]
    pub shadow_access_linux: bool,
    /// Watch keychain DB access (`/Library/Keychains/*`,
    /// `~/Library/Keychains/*`) via Endpoint Security on macOS.
    #[serde(default = "default_true")]
    pub keychain_access_macos: bool,
}

impl Default for IdentityMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            lsass_access_windows: true,
            shadow_access_linux: true,
            keychain_access_macos: true,
        }
    }
}

/// DLP (Phase E5) configuration.
///
/// Drives the `sda-dlp` crate which scans file-write payloads (and
/// optionally clipboard contents) for PII / PCI patterns.
///
/// `mode = "enforce"` additionally quarantines the file via
/// `sda-active-response`. `mode = "monitor"` only emits findings.
/// Findings MUST NEVER contain the matched bytes — only the pattern
/// category, byte offset/length, and a Blake3 fingerprint of the
/// surrounding 32-byte window (see
/// `docs/architecture.md` § 8.2 — Redaction invariant).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpConfig {
    /// Whether the DLP module is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Operating mode: `"monitor"` (log + finding only) or
    /// `"enforce"` (additionally quarantine the file).
    #[serde(default = "default_dlp_mode")]
    pub mode: String,
    /// Active pattern categories. Each entry must match a pattern
    /// registered in `sda-dlp::patterns`. Defaults to the bundled
    /// SSN / UK-NI / PAN-Luhn set.
    #[serde(default = "default_dlp_patterns")]
    pub patterns: Vec<String>,
    /// Inspect content of files reported as Created / Modified by FIM.
    #[serde(default = "default_true")]
    pub inspect_file_writes: bool,
    /// Inspect clipboard content (requires the `dlp-clipboard`
    /// feature). Off by default.
    #[serde(default)]
    pub inspect_clipboard: bool,
    /// Maximum bytes read per file-write inspection. Bounds the
    /// agent's CPU and memory footprint when a process writes a
    /// very large file.
    #[serde(default = "default_dlp_max_bytes_per_file")]
    pub max_bytes_per_file: usize,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_dlp_mode(),
            patterns: default_dlp_patterns(),
            inspect_file_writes: true,
            inspect_clipboard: false,
            max_bytes_per_file: default_dlp_max_bytes_per_file(),
        }
    }
}

fn default_dlp_mode() -> String {
    "monitor".to_string()
}
fn default_dlp_patterns() -> Vec<String> {
    vec![
        "pii.ssn".to_string(),
        "pii.uk_ni".to_string(),
        "pci.pan_luhn".to_string(),
    ]
}
fn default_dlp_max_bytes_per_file() -> usize {
    // 2 MiB per file. Matches the resource budget cap from
    // `docs/architecture.md` § 5.2 (DLP peak 3 MB / 0.5% CPU).
    2 * 1024 * 1024
}

impl AgentConfig {
    /// Load configuration from a YAML file.
    pub fn from_yaml_file(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: AgentConfig = serde_yaml::from_str(&contents)?;
        info!(path = %path.display(), "loaded configuration");
        Ok(config)
    }

    /// Load configuration from a YAML string.
    pub fn from_yaml(yaml: &str) -> anyhow::Result<Self> {
        let config: AgentConfig = serde_yaml::from_str(yaml)?;
        Ok(config)
    }

    /// Try to load from the default config path for this platform.
    pub fn load_default() -> anyhow::Result<Self> {
        let path = Self::default_config_path();
        if path.exists() {
            Self::from_yaml_file(&path)
        } else {
            info!("no config file found, using defaults");
            Ok(Self::default())
        }
    }

    /// Get the default configuration file path for the current platform.
    pub fn default_config_path() -> PathBuf {
        #[cfg(unix)]
        {
            PathBuf::from("/etc/sn360-desktop-agent/config.yaml")
        }
        #[cfg(windows)]
        {
            PathBuf::from(r"C:\Program Files\SN360DesktopAgent\config.yaml")
        }
    }

    /// Get the enrollment server address (falls back to main server).
    pub fn enrollment_address(&self) -> &str {
        self.enrollment
            .server
            .as_deref()
            .unwrap_or(&self.server.address)
    }
}
