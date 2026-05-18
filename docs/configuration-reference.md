# SDA Configuration Reference

Canonical reference for every field understood by
`AgentConfig` in [`crates/sda-core/src/config.rs`](../crates/sda-core/src/config.rs).
Defaults shown here are what the agent uses when the field is
absent from `config.yaml`; see `tests/sda-test-config.yaml` for
an end-to-end working example.

---

## Top-level shape

```yaml
server:            # required — connection to the SN360 Control Plane
enrollment:        # required if auto-enrolling
modules:           # optional — per-module toggles, defaults enable all
updater:           # optional — self-update configuration
resource_limits:   # optional — per-host budget overrides
logging:           # optional — RUST_LOG-style filter override
```

## `server`

```yaml
server:
  address: "sn360.example.com"     # hostname or IP of the manager / Agent Gateway
  port: 1514                        # default: 1514
  protocol: "tcp"                   # "tcp" (default) | "udp" | "http2" (SN360 native)
  keepalive_interval: 600           # seconds, default: 600
  enhanced:                         # SN360 native protocol knobs (all default off)
    tls: false                       # opt in to TLS 1.3 transport, default: false
    serialization: "json"            # "json" (default) | "msgpack"
    tls_ca_bundle_path: null         # optional path to PEM bundle
    tls_pinned_sha256: null          # optional 64-char hex leaf fingerprint
```

- `enhanced.tls = true` opts into `rustls` with TLS 1.3 enforced
  (`rustls::version::TLS13`). Keep it off to preserve the stable
  agent stream protocol against existing SIEM managers.
- `enhanced.serialization = "msgpack"` serialises events with
  `rmp-serde` instead of JSON; 50–70 % smaller on inventory-heavy
  payloads. Requires an SN360-aware server endpoint — leave it at
  `"json"` for legacy SIEM managers.
- `protocol = "http2"` switches to the SN360 native HTTP/2
  transport. It requires `enhanced.tls = true` — HTTP/2 is only
  spoken over TLS with ALPN `h2`; plain-text h2c is not supported.
  `"tcp"` (default) and `"udp"` are the standard stream /
  datagram transports used against existing SIEM managers.

## `enrollment`

```yaml
enrollment:
  server: "sn360.example.com"     # manager enrolment host; defaults to server.address
  port: 1515                        # default: 1515
  password_file: "/etc/sn360-desktop-agent/enrollment.password"
  auto_enroll: true                 # default: true
  agent_name: null                  # defaults to hostname
  agent_groups: []                  # agent group tags
```

Enrolment talks to the manager's enrolment daemon on port 1515
and writes `client.keys` into the same directory as `config.yaml`.
The systemd unit's `ReadWritePaths=` must include this directory
or enrolment will fail with `EACCES`. When the SN360 native
protocol is selected (`server.protocol = "http2"` +
`enhanced.tls = true`), enrolment uses mTLS against the SN360
Agent Gateway and the native identity is persisted alongside the
config.

## `modules`

Each module has an `enabled: bool` and a module-specific subsection.
Omitting a module leaves it on with defaults.

### `modules.fim`

```yaml
modules:
  fim:
    enabled: true                   # default
    directories:
      - path: /etc
        recursive: true
        realtime: true
        check_sha256: true
      - path: /home
        recursive: true
        exclude: ["*.tmp", ".cache/**"]
    scan_interval: 43200             # seconds between idle baseline scans (12 h)
    batch_size: 500                  # max files per hash burst
```

### `modules.logcollector`

```yaml
modules:
  logcollector:
    enabled: true
    sources:
      - type: file                   # file | journald | eventlog | oslog
        path: /var/log/auth.log
        format: syslog
      - type: journald
        units: [sshd, sudo]
    max_lines_per_batch: 100
```

### `modules.inventory`

```yaml
modules:
  inventory:
    enabled: true
    collect: [packages, network, hardware, os, processes]
    interval: 3600                   # seconds between full refreshes
```

### `modules.sca`

```yaml
modules:
  sca:
    enabled: true
    policies:
      - /etc/sn360-desktop-agent/policies/cis_ubuntu_22_04.yaml
    scan_interval: 900
    scan_on_idle: true
```

### `modules.rootcheck`

```yaml
modules:
  rootcheck:
    enabled: true
    signature_paths: [/etc/rootcheck/signatures.json]
    scan_interval_secs: 86400
```

### `modules.active_response`

```yaml
modules:
  active_response:
    enabled: true
    allowed_commands: [block_ip, kill_process]
    command_timeout_secs: 30
```

### `modules.local_detection`

```yaml
modules:
  local_detection:
    enabled: true                       # default — see “Migration notes” below
    rule_bundle_path: /var/lib/sn360-desktop-agent/rules.mp
    yara_rules_dir: /var/lib/sn360-desktop-agent/yara
    offline_queue_capacity: 10000
    rule_pull_interval: 60              # seconds between TRDS pulls (default: 60)
    trds_endpoint: null                 # optional — when null, the embedded baseline bundle is used
    rule_bundle_signing_keys: []        # hex-encoded Ed25519 public keys for TRDS bundle verification
```

`enabled` defaults to `true` — agents that omit this section will
run the Local Detection Engine against the embedded baseline
bundle (three behavioural process-chain rules + a small set of
synthetic IOCs from `crates/sda-local-detection/src/default_bundle.rs`)
on startup. To opt out, explicitly set
`modules.local_detection.enabled: false`.

`rule_pull_interval` is enforced with a soft floor of 1 second so
the e2e hot-reload suite can converge quickly; in production we
recommend ≥ 30 seconds. The agent emits a `warn!` at startup when
the configured value is below the recommended floor.

### `modules.enhanced_inventory`

```yaml
modules:
  enhanced_inventory:
    running_software_enabled: true
    browser_extensions_enabled: true
    sbom_enabled: true
    scan_interval_secs: 10           # tick cadence per scanner
```

### `modules.host_isolation`

```yaml
modules:
  host_isolation:
    enabled: false                   # default — opt-in network containment
    control_plane_cidrs:             # required when enabled: agent refuses to isolate
      - 10.20.0.0/16                 # if this list is empty (would sever ctrl-plane)
      - 203.0.113.0/24
    always_allow_dns: true           # default: true — system DNS resolvers stay reachable
    always_allow_loopback: true      # informational — loopback is ALWAYS allowed by the PAL
```

> ⚠️ **Startup gate.** Setting `host_isolation.enabled: true` is
> a no-op until the agent has a real enrolled tenant + device
> identity wired through the Device Control router. The agent
> logs a `warn!` at startup explaining that host isolation is
> configured but inactive, and `IsolateHost` / `UnisolateHost`
> jobs from the control plane are refused at the router layer
> until the identity binding is in place. Operators can safely
> enable the flag ahead of the server rollout — the agent will
> pick up the live path automatically once the wiring is live.

`control_plane_cidrs` MUST be non-empty whenever `enabled: true`.
The host-isolation module refuses `IsolateHost` jobs (and bumps
`vitals.refused`) when the list is empty so the management
channel cannot be accidentally severed by an isolation job — see
[`empty_control_plane_cidrs_refuses_isolation_without_touching_pal`](../crates/sda-host-isolation/src/lib.rs)
for the regression test.  `UnisolateHost` is NOT blocked by this
guard so recovery from a misconfigured isolation is always
possible.

`always_allow_dns: true` (the default) instructs the agent to
discover the host's system DNS resolvers and union them into the
allow-list so name resolution survives isolation. On Linux this
parses `/etc/resolv.conf` (IPv6 scope ids stripped); on Windows
and macOS the platform helper is still maturing — operators
should pass DNS resolver IPs explicitly via the job's
`extra_allow_ips` or via `control_plane_cidrs` until then.

`always_allow_loopback` is informational only — `127.0.0.0/8`
and `::1/128` are appended to every allow-list by
`sda_pal::host_isolation::normalize_allow_ips` regardless of the
flag's value.  Leaving the flag at its `true` default makes that
guarantee visible in config; setting it to `false` does not
disable loopback access.

### `modules.memory_scanner`

```yaml
modules:
  memory_scanner:
    enabled: false                            # default — opt-in
    scan_interval_secs: 300                   # default: 300 (5 min between full sweeps)
    only_when_idle_below_cpu_pct: 20          # default: 20 — skip sweep when host CPU >= 20 %
    allow_list_processes:                     # processes excluded from scanning
      - sn360-desktop-agent                   # agent process always added at compile time
    yara_rule_source: "trds"                  # "trds" | "local" — where the in-memory YARA rules come from
```

> ⚠️ **Safety invariant.** The agent process is **always** in the
> allow-list at compile time (see
> [`docs/architecture.md`](./architecture.md#83-memory-scanner-safety)),
> even if the operator explicitly removes it from
> `allow_list_processes`. The PAL trait
> (`sda_pal::memory_scanner::MemoryScanner::enumerate`) enforces
> self-pid exclusion independently and the in-memory YARA rules
> are scoped to `pid != self_pid` at the rule-engine level — so a
> compromised config cannot make the agent scan itself.

> ⚠️ **Privilege requirements.** Region reads require elevated
> capabilities per platform: `CAP_SYS_PTRACE` on Linux for
> `/proc/<pid>/mem`, `SeDebugPrivilege` on Windows (granted to
> `SYSTEM`) for `ReadProcessMemory`, and the
> `com.apple.security.cs.debugger` entitlement (or `root`) on
> macOS for `task_for_pid`. Without these, the scanner logs a
> permission error per scan window and the LDE still sees
> `MemoryScanAlert` events from any AMSI matches on Windows.

`only_when_idle_below_cpu_pct` is enforced before each scan
window — the module reads the rolling host-CPU estimate from
`sda_pal::power::PowerMonitor::current_profile()` and skips the
sweep (without emitting an error) when the sample exceeds the
threshold. This keeps the scanner within the 1 %-of-scan-window
CPU budget documented in
[`docs/architecture.md`](./architecture.md#5-resource-budgets).

`yara_rule_source` controls where the in-memory YARA rules come
from. `"trds"` (the default) reuses the existing
`sda-local-detection` rule store (Ed25519-verified TRDS bundle
hot-reload + atomic `Arc<ArcSwap<DetectionPipeline>>` swap), so
the same signed bundle that drives file-path YARA scans also
covers in-memory matches without a new rule format. `"local"`
uses only the embedded baseline rules — useful for hermetic CI
or air-gapped deployments.

The optional `amsi` Cargo feature
(`#[cfg(feature = "amsi")] #[cfg(target_os = "windows")]`)
registers an `IAmsiStream` provider so PowerShell / VBScript
content scanned by AMSI feeds the same `MemoryScanAlert` path
with `alert_type: "amsi_match"`. Off by default.

### `modules.identity_monitor`

```yaml
modules:
  identity_monitor:
    enabled: false                  # default — opt-in
    lsass_access_windows: true      # ETW Microsoft-Windows-Threat-Intelligence + NtOpenProcess on lsass.exe — T1003.001
    shadow_access_linux: true       # FileMetadataChanged on /etc/shadow + audit on /proc/kcore — T1003.008 / T1003
    keychain_access_macos: true     # Endpoint Security ES_EVENT_TYPE_NOTIFY_OPEN on Keychain paths — T1555.001
```

The identity monitor emits `EventKind::IdentityAlert` with a
canonical-JSON payload that includes the MITRE ATT&CK technique
ID, the accessing user / process, and a human-readable
description. **System-principal events are filtered at the module
publish boundary** (not in providers) so the same provider can
feed both the IDS pipeline and audit logs; an access by
`NT AUTHORITY\SYSTEM`, `root`, or an Apple-signed binary does
not produce an `IdentityAlert`.

Each per-OS detector can be toggled independently. The Linux
backend reuses the existing FIM and audit primitives — no extra
privileges beyond what `sda-fim` already has. The Windows backend
requires `SYSTEM` (granted via the installer) for the
`Microsoft-Windows-Threat-Intelligence` ETW provider; the macOS
backend requires the `com.apple.developer.endpoint-security.client`
entitlement (production signing only; CI uses
`MockEndpointSecurity`).

### `modules.dlp`

```yaml
modules:
  dlp:
    enabled: false                       # default — opt-in
    mode: "monitor"                      # "monitor" (default) | "enforce"

    # Pattern selection. Empty == "every built-in pattern".
    # Each entry is either an exact category ID, a regional glob,
    # a category-tag glob, or the "*" / "all" wildcard. Unknown
    # selectors are dropped at startup with a warn-level log.
    patterns: []

    # Convenience shorthand. Set to one of "asia" | "gcc" |
    # "europe" | "global" | "all" to enable every pattern in
    # that region. Ignored when `patterns` is non-empty.
    region: null

    inspect_file_writes: true            # subscribe to FileCreated / FileModified
    inspect_clipboard: false             # feature-gated — requires `dlp-clipboard` Cargo feature
    max_bytes_per_file: 2097152          # 2 MiB read cap per file write
```

**Redaction invariant (mandatory).** DLP findings never carry the
matched bytes — the agent emits only the pattern category, byte
offset, length, and the Blake3 fingerprint of the surrounding
32-byte window (see
[`docs/architecture.md`](./architecture.md#82-redaction-invariant)).
Operators can correlate two findings as the same matched value
via fingerprint without ever reading the underlying PII / PCI
content. This is enforced at the scanner output type
(`DlpFinding`) — the matched bytes are never serialised into the
event payload.

- `mode: "monitor"` (default) — the DLP module publishes
  `EventKind::LocalDetectionAlert` with `rule_type: "dlp"` and
  `severity: "medium"`. No quarantine, no follow-up action.
- `mode: "enforce"` — the same finding is published with
  `severity: "high"` so the existing `sda-active-response` module
  can quarantine the offending file via its existing quarantine
  primitives. Nothing in the DLP code path writes to the
  filesystem directly.

**Pattern selectors.** `patterns` accepts any combination of:

- **Exact category** — `"pii.ssn"`, `"pci.pan_luhn"`, `"secrets.jwt"`, …
- **Regional glob** — `"asia.*"`, `"gcc.*"`, `"europe.*"`, `"global.*"`.
- **Category-tag glob** — `"pii.*"`, `"pci.*"`, `"secrets.*"`.
- **Wildcard** — `"*"` or `"all"`.

The full catalogue (≈ 50 patterns covering Asia, GCC, Europe, and
Global PII / PCI / secrets) is documented in
[`edr.md` § 6.1](./edr.md#61-pattern-set). Empty `patterns: []` —
the default — selects every built-in pattern.

`region` is a convenience shorthand: setting `region: "europe"` is
equivalent to `patterns: ["europe.*"]`. The shorthand is ignored
when an explicit `patterns` list is provided so explicit selection
always wins.

Examples:

```yaml
# Every Asian PII pattern + every PCI pattern.
patterns:
  - asia.*
  - pci.*
```

```yaml
# Just the singapore IDs + PAN.
patterns:
  - pii.sg_nric
  - pii.sg_uen
  - pci.pan_luhn
```

```yaml
# All Europe patterns via the shorthand.
region: europe
```

```yaml
# Everything (explicit wildcard).
patterns: ["*"]
```

`inspect_file_writes` is the default DLP input source —
subscribing to `EventKind::FileCreated` and `FileModified` and
performing a bounded read (`max_bytes_per_file`) on each event.
Files larger than the cap are skipped without an error.
`max_bytes_per_file` defaults to 2 MiB, matching the resource
budget in [`architecture.md`](./architecture.md) § 5.2.

`inspect_clipboard` requires the optional `dlp-clipboard` Cargo
feature (off by default) and a display server (X11 / Wayland on
Linux, a desktop session on macOS / Windows). Real clipboard
access is not available in headless CI, so the integration uses
`MockClipboardProvider` for tests.

## `updater`

```yaml
updater:
  enabled: false
  manifest_url: "https://updates.sn360.example.com/desktop-agent/manifest.json"
  public_key_pem: |
    -----BEGIN PUBLIC KEY-----
    ...
    -----END PUBLIC KEY-----
  poll_interval_secs: 21600           # 6 h
```

## `resource_limits`

```yaml
resource_limits:
  max_cpu_percent: 3
  max_memory_mb: 50
  battery_mode: adaptive             # adaptive | minimal | normal
  idle_detection: true
```

## `logging`

```yaml
logging:
  filter: "info,sda_fim=debug"
```

The filter string uses the `tracing-subscriber` env-filter grammar
and overrides `RUST_LOG` if both are set.

---

## `legacy_adapter` *(planned — not yet implemented)*

A `legacy_adapter` configuration section is planned for a future
release to allow explicit control over the legacy SIEM protocol
adapter when the `legacy-siem` Cargo feature is enabled. The
section has not yet been wired into [`AgentConfig`](../crates/sda-core/src/config.rs);
no `legacy_adapter:` key is parsed today. For the current release,
configure the legacy path through the existing `server:` and
`enrollment:` stanzas, and build with (or without)
`--no-default-features` on the `sda-agent` crate to toggle the
adapter at compile time. See [`licensing.md`](./licensing.md) for
the clean-room interoperability statement.

---

## Migration notes

- `server.protocol` replaces the legacy `server.transport` field.
- Old configs referencing `wazuh-desktop-agent` paths
  (`/etc/wazuh-desktop-agent/`) are read at startup and a warning
  is logged; move them to `/etc/sn360-desktop-agent/` before the
  next major release.
- The `server.enhanced` stanza is additive — omit it entirely to
  keep the stable stream protocol against an existing SIEM
  manager. Explicitly set its fields to `true` / `"msgpack"` and
  switch `server.protocol` to `"http2"` to opt into the SN360
  native protocol against an SN360 Agent Gateway.
