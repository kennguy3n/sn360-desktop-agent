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
    enabled: true
    rule_bundle_path: /var/lib/sn360-desktop-agent/rules.mp
    yara_rules_dir: /var/lib/sn360-desktop-agent/yara
    offline_queue_capacity: 10000
```

### `modules.enhanced_inventory`

```yaml
modules:
  enhanced_inventory:
    running_software_enabled: true
    browser_extensions_enabled: true
    sbom_enabled: true
    scan_interval_secs: 10           # tick cadence per scanner
```

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
adapter at compile time. See
[`proprietary-licensing-rationale.md`](./proprietary-licensing-rationale.md)
for the clean-room interoperability statement and the
[revised phase plan](./revised-phase-plan.md) for the timeline.

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
