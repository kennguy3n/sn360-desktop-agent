# ShieldNet EDR Parity — Architecture

> **Version:** 0.1 | **Date:** May 2026 | **Status:** Planning
> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)

This document is the architecture reference for the EDR Parity
workstream. It is intentionally narrower than
[PROPOSAL.md](./PROPOSAL.md) — that document captures the design
rationale; this one captures the target shape of the code as it will
be when Phases E0–E5 are merged. Kernel-mode productisation (Phase
E6) is tracked separately under
[`docs/device-control/PRODUCTISATION-WINDOWS.md`](../device-control/PRODUCTISATION-WINDOWS.md)
and
[`docs/device-control/PRODUCTISATION-MACOS.md`](../device-control/PRODUCTISATION-MACOS.md).

> **Scope note:** EDR Parity spans the agent (this repository) and
> the SN360 control plane
> ([`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)).
> Sections 1–9 below describe agent-side shape. Section 4's NATS
> subject hierarchy and the control-plane interaction surface are
> included for cross-reference; the corresponding code lives in
> `sn360-security-platform`, not here.

> **Phase identifier note:** EDR Parity uses **Phase E** identifiers
> (E0–E6) to avoid collision with the existing **Phase D**
> identifiers (D1–D4) for Device Control and the **Phase M**
> identifiers (M1–M4) for Desktop MDM.

---

## Table of contents

1. [Crate map](#1-crate-map)
2. [Event flow](#2-event-flow)
3. [Pipeline diagrams](#3-pipeline-diagrams)
4. [Protocol extension](#4-protocol-extension)
5. [PAL additions](#5-pal-additions)
6. [Configuration schema](#6-configuration-schema)
7. [Resource budgeting](#7-resource-budgeting)
8. [Wire schema overview](#8-wire-schema-overview)
9. [Security model](#9-security-model)
10. [Further reading](#10-further-reading)

---

## 1. Crate map

| Crate                    | Responsibility                                                                                                                                  |
|--------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| `sda-process-monitor`    | Subscribes to `sda-pal::ProcessMonitor`; reconstructs parent chain; emits `ProcessCreated` / `ProcessTerminated` / `ImageLoaded` on the bus.   |
| `sda-network-monitor`    | Subscribes to `sda-pal::NetworkMonitor` + `sda-pal::DnsMonitor`; debounces duplicates; emits `NetworkConnection` / `DnsQuery` on the bus.       |
| `sda-memory-scanner`     | Periodic RWX-region scan + in-memory YARA scan; emits `MemoryScanAlert` on detection.                                                          |
| `sda-host-isolation`     | Consumes `IsolateHost` / `UnisolateHost` `SignedActionJob`s; flips per-OS firewall state; emits `HostIsolationStateChanged`.                  |
| `sda-identity-monitor`   | Credential-theft detection — LSASS access on Windows, `/etc/shadow` + `/proc/kcore` on Linux, keychain access on macOS.                       |
| `sda-dlp`                | Regex-based PII / PCI scanner; inspects file writes via FIM events, optionally clipboard + outbound buffers.                                   |

The crate layering follows existing SDA conventions:
`sda-agent` depends on every EDR Parity crate; each EDR Parity crate
depends on `sda-core` / `sda-event-bus` / `sda-pal` / `sda-comms`;
no EDR Parity crate depends on any other EDR Parity crate except via
the event bus.

The existing `sda-local-detection` crate is **expanded** rather than
replaced — the LDE's `handle_event` match at
[`crates/sda-local-detection/src/lib.rs` lines 314–358](../../crates/sda-local-detection/src/lib.rs#L314-L358)
gets explicit arms for the new EventKind variants instead of falling
through to `_ => return,` at line 357. Phase E2 lifts the
hot-reload placeholder at lines 495–501 to a verified TRDS bundle
pull.

---

## 2. Event flow

```
+--------------------------------------------------------------------+
|                          sda-agent (bin)                            |
|                                                                     |
|  +-------------------------+    Event Bus (sda-event-bus)           |
|  | sda-process-monitor     |---+                                     |
|  +-------------------------+   |                                     |
|  | sda-network-monitor     |---+                                     |
|  +-------------------------+   |   +-----------------+   +---------+ |
|  | sda-memory-scanner      |---+==>| LDE             |   | Comms   | |
|  +-------------------------+   |   | (sda-local-     |   | (TLS    | |
|  | sda-identity-monitor    |---+   | detection)      |   |  +HTTP/2| |
|  +-------------------------+   |   |                 |   |  +Msg-  | |
|  | sda-dlp                 |---+   |  pipeline       |   |  pack)  | |
|  +-------------------------+   |   |  match_ip()     |   +---------+ |
|  | sda-host-isolation      |---+   |  match_str()    |        ^      |
|  +-------------------------+   |   |  yara_scan()    |        |      |
|  | existing modules:       |---+   |  behavioural    |        |      |
|  |  fim, logcollector,     |   |   |  rules          |        |      |
|  |  device-control, mdm,   |   |   +---------+-------+        |      |
|  |  agent-vitals, ...      |   |             |                |      |
|  +-------------------------+   |             v                |      |
|                                |   +-----------------+        |      |
|                                +==>| Router (main.rs)|========+      |
|                                    +-----------------+        |      |
|                                                               | inbound:
|                                                               | IsolateHost
|                                                               | UnisolateHost
|                                                               v      |
|                                                       +---------------+
|                                                       | SN360 Control |
|                                                       | Plane (Agent  |
|                                                       | Gateway, Risk |
|                                                       | Engine, SMI,  |
|                                                       | Dashboard,    |
|                                                       | Action Orch,  |
|                                                       | TRDS)         |
|                                                       +---------------+
+--------------------------------------------------------------------+
```

The LDE sits in the centre of the EDR data plane: every new
`EventKind` is consumed first by the LDE (for behavioural / IOC
matching against the live `DetectionPipeline`) and then forwarded to
comms.

### 2.1 New `EventKind` variants

`sda-core::EventKind` gains the following variants. Every variant is
produced by exactly one module and consumed by `sda-comms` (and, where
relevant, by `sda-local-detection`):

```rust
pub enum EventKind {
    // ... existing variants (FIM, logcollector, device-control, MDM,
    //     local-detection, agent-vitals, ...) ...

    /// E1 — A process was created. Carries the full parent chain up
    /// to the configured depth.
    ProcessCreated {
        pid: u32,
        ppid: u32,
        name: String,
        exe_path: PathBuf,
        cmdline: Vec<String>,
        user: String,
        parent_chain: Vec<ProcessAncestor>,
    },

    /// E1 — A process was terminated.
    ProcessTerminated {
        pid: u32,
        name: String,
        exit_code: i32,
    },

    /// E1 — An image (executable / DLL / dylib / .so) was loaded
    /// into a running process.
    ImageLoaded {
        pid: u32,
        image_path: PathBuf,
        image_hash: Option<Hash>,
    },

    /// E3 — A TCP or UDP connection was opened / observed.
    NetworkConnection {
        pid: u32,
        process_name: String,
        direction: NetDirection,
        protocol: NetProtocol,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        remote_port: u16,
    },

    /// E3 — A DNS query was issued by the local resolver.
    DnsQuery {
        pid: u32,
        process_name: String,
        query_name: String,
        query_type: DnsQueryType,
        response_ips: Vec<IpAddr>,
    },

    /// E4 — Memory scan flagged an RWX region or an in-memory YARA
    /// match in a non-allow-listed process.
    MemoryScanAlert {
        pid: u32,
        process_name: String,
        region_base: u64,
        region_size: u64,
        alert_type: MemoryAlertKind,
        description: String,
    },

    /// E3 — Host network containment state changed (e.g. isolated /
    /// unisolated). `allowed_ips` is the active control-plane CIDR
    /// allow-list.
    HostIsolationStateChanged {
        isolated: bool,
        allowed_ips: Vec<IpNet>,
    },

    /// E5 — Identity / credential-theft signal (LSASS access,
    /// shadow read, keychain access).
    IdentityAlert {
        category: IdentityAlertCategory,
        user: String,
        technique: MitreTechniqueId,
        description: String,
    },
}
```

Per the existing SDA comms invariant, every new `EventKind` variant
must also have an explicit arm in `WazuhMessage::encode_body()` (see
[`crates/sda-comms/src/protocol.rs`](../../crates/sda-comms/src/protocol.rs))
when the optional `legacy-siem` Cargo feature is on; fall-through to
the catch-all is forbidden.

### 2.2 LDE expansion: removing the catch-all

The current LDE drops every non-FIM, non-logcollector event at
[`crates/sda-local-detection/src/lib.rs` line 357](../../crates/sda-local-detection/src/lib.rs#L357):

```rust
match &event.kind {
    EventKind::FimChanged { /* ... */ } => { /* ... */ }
    EventKind::LogCollectorRecord { /* ... */ } => { /* ... */ }

    // The LDE only observes FIM and logcollector streams; other
    // event kinds pass through untouched.
    _ => return,
}
```

Phase E1, E3, E4, and E5 each replace this catch-all with explicit
arms. The replacement pattern is:

```rust
match &event.kind {
    EventKind::FimChanged { /* ... */ } => { /* ... */ }
    EventKind::LogCollectorRecord { /* ... */ } => { /* ... */ }

    // E1 — Phase E1.6
    EventKind::ProcessCreated { pid, name, exe_path, cmdline, user, parent_chain, .. } => {
        // Extract `(source_tag, entity, primary_text, fim_path, sha256, ips)`
        // tuple expected by the IOC matchers and the behavioural-rule
        // evaluator. `primary_text` is the joined cmdline; `entity` is
        // the exe_path; `fim_path` is None; `sha256` is None; `ips` is
        // empty.
    }
    EventKind::ProcessTerminated { /* ... */ } => { /* lightweight */ }
    EventKind::ImageLoaded { image_path, image_hash, .. } => { /* ... */ }

    // E3 — Phase E3.6 / E3.9
    EventKind::NetworkConnection { remote_addr, remote_port, process_name, .. } => {
        // Feed remote_addr into the existing IP IOC bloom; process_name
        // and remote_port available for behavioural rules.
    }
    EventKind::DnsQuery { query_name, response_ips, process_name, .. } => {
        // Feed query_name into the existing string IOC backend;
        // response_ips feed into the IP IOC bloom.
    }

    // E4 — Phase E4.5
    EventKind::MemoryScanAlert { /* ... */ } => { /* forward to comms */ }

    // E5 — Phase E5.4
    EventKind::IdentityAlert { /* ... */ } => { /* forward to comms */ }

    // E3 — Phase E3.10
    EventKind::HostIsolationStateChanged { /* ... */ } => { /* forward to comms */ }

    _ => return,
}
```

Phase E1.7 adds a `parent_chain` predicate to the LDE JSON DSL so a
TRDS bundle can ship rules of the form:

```json
{
  "id": "edr-process-chain-001",
  "match": {
    "kind": "ProcessCreated",
    "name_regex": "^powershell\\.exe$",
    "parent_chain_regex": ".*(winword|excel|outlook)\\.exe.*"
  },
  "finding": {
    "severity": "High",
    "category": "PROCESS_CHAIN_ANOMALY",
    "plain_english": "Office process spawned PowerShell — possible macro-borne attacker activity."
  }
}
```

---

## 3. Pipeline diagrams

### 3.1 Process telemetry pipeline

```
+----------------------------------------------+
|                  Per-OS source               |
|  Linux:   cn_proc (NETLINK_CONNECTOR /       |
|             CN_IDX_PROC) + /proc/<pid>/      |
|  Windows: ETW Microsoft-Windows-Kernel-      |
|             Process (PROCESS_START,          |
|             PROCESS_STOP, IMAGE_LOAD)        |
|  macOS:   Endpoint Security framework        |
|             (ES_EVENT_TYPE_NOTIFY_EXEC /     |
|             _FORK / _EXIT / _MMAP)           |
+----------------------+-----------------------+
                       |
                       | raw os event
                       v
+----------------------------------------------+
|             sda-pal::ProcessMonitor          |
|  - Normalises per-OS event shape into a      |
|    platform-agnostic ProcessEvent enum.      |
|  - Per-OS enrichment of cmdline / user /     |
|    cgroup / image_hash where available.      |
+----------------------+-----------------------+
                       |
                       | ProcessEvent
                       v
+----------------------------------------------+
|             sda-process-monitor              |
|  - Parent-chain reconstruction up to the     |
|    configured depth via per-OS lookup        |
|    helpers (Linux /proc/<pid>/stat, Windows  |
|    PROCESS_BASIC_INFORMATION, macOS          |
|    proc_listpidspath).                       |
|  - Debounces duplicate events.               |
|  - Backpressure: bounded mpsc channel; drops |
|    oldest event on overflow + emits          |
|    `agent_vitals` warning.                   |
+----------------------+-----------------------+
                       |
                       | EventKind::ProcessCreated /
                       | ProcessTerminated / ImageLoaded
                       v
+----------------------------------------------+
|             sda-event-bus (priority queue)    |
+----------------------+-----------------------+
                       |
        +--------------+-------------+
        |                            |
        v                            v
+----------------+        +----------------------+
| LDE            |        | Comms                |
| - parent_chain |        | - canonical-JSON     |
|   regex match  |        |   envelope per § 8   |
| - IOC bloom    |        | - encrypted to       |
|   (image hash) |        |   Agent Gateway      |
+----------------+        +----------------------+
```

### 3.2 Network telemetry pipeline

```
+----------------------------------------------+
|                  Per-OS source               |
|  Linux:   audit subsystem (AUDIT_SOCKADDR /  |
|             AUDIT_CONNECT) for connect-time  |
|             signal + netlink INET_DIAG for   |
|             established-connection           |
|             enumeration + /proc/net/* for    |
|             PID attribution.                  |
|  Windows: ETW Microsoft-Windows-Kernel-      |
|             Network (TCP connect/accept/     |
|             disconnect, UDP send/recv)       |
|             keyed on ProcessId.              |
|  macOS:   Network Extension framework        |
|             (NEFilterDataProvider) for       |
|             connection metadata.             |
+----------------------+-----------------------+
                       |
                       | raw os event
                       v
+----------------------------------------------+
|             sda-pal::NetworkMonitor          |
|             sda-pal::DnsMonitor              |
|  - Normalises into NetworkEvent / DnsEvent.  |
|  - Per-OS attribution (PID -> process name)  |
+----------------------+-----------------------+
                       |
                       v
+----------------------------------------------+
|             sda-network-monitor              |
|  - De-duplication of repeated established    |
|    connection enumerations.                  |
|  - Sampling for high-rate UDP flows (e.g.    |
|    Spotify / Zoom).                          |
+----------------------+-----------------------+
                       |
                       | EventKind::NetworkConnection /
                       | DnsQuery
                       v
+----------------------------------------------+
|             sda-event-bus (priority queue)    |
+----------------------+-----------------------+
                       |
        +--------------+-------------+
        |                            |
        v                            v
+-----------------+       +------------------------+
| LDE             |       | Comms                  |
| - IP IOC bloom  |       | - canonical-JSON       |
| - domain IOC    |       |   envelope per § 8     |
|   (DnsQuery)    |       | - encrypted to         |
| - rule match    |       |   Agent Gateway        |
+-----------------+       +------------------------+
```

### 3.3 Host isolation action flow

```
+----------------------------------------------+
| sn360-security-platform                       |
|  - Dashboard "Isolate host" button.            |
|  - Action Orchestrator builds an              |
|    IsolateHost SignedActionJob (Ed25519       |
|    signed by control-plane key).              |
+----------------------+-----------------------+
                       |
                       | mTLS / HTTP/2 / MessagePack
                       v
+----------------------------------------------+
|             sda-comms (inbound)              |
|  - Verifies TLS, decodes frame, hands off    |
|    to sda-host-isolation.                    |
+----------------------+-----------------------+
                       |
                       | SignedActionJob<IsolateHost>
                       v
+----------------------------------------------+
|             sda-host-isolation               |
|  - 10-step signed-job validation             |
|    (mirrors `sda-device-control::router`).   |
|  - Builds allow_ips list (control-plane      |
|    CIDRs + loopback + DNS allow-list).       |
|  - Invokes sda-pal::HostIsolation::isolate.  |
+----------------------+-----------------------+
                       |
                       | per-OS firewall write
                       v
+----------------------------------------------+
|             sda-pal::HostIsolation           |
|  Linux:   nftables table sn360_isolation;    |
|             default drop + accept allow_ips. |
|  Windows: netsh advfirewall + WFP COM API;   |
|             dedicated rule group.            |
|  macOS:   pfctl anchor sn360_isolation;      |
|             default drop + accept allow_ips. |
+----------------------+-----------------------+
                       |
                       | EventKind::HostIsolationStateChanged
                       v
+----------------------------------------------+
|             sda-event-bus -> Comms           |
+----------------------+-----------------------+
                       |
                       v
+----------------------------------------------+
| sn360-security-platform                       |
|  - Dashboard renders isolated state.          |
|  - Audit log appended.                        |
+----------------------------------------------+
```

### 3.4 Memory scanner pipeline

```
+----------------------------------------------+
|             sda-memory-scanner               |
|  - Periodic scan window (default: every      |
|    5 min during idle CPU < threshold).       |
|  - Per-process loop:                          |
|     1. Self-pid + allow-list filter.          |
|     2. sda-pal::MemoryScanner::enumerate     |
|        => Vec<MemoryRegion>.                 |
|     3. For each RWX / anonymous region:      |
|        a. sda-pal::MemoryScanner::read       |
|           (bounded byte slice).               |
|        b. Hand off to sda-local-detection's  |
|           in-memory YARA scanner.            |
|     4. On hit, emit MemoryScanAlert.         |
+----------------------+-----------------------+
                       |
                       | EventKind::MemoryScanAlert
                       v
+----------------------------------------------+
|             sda-event-bus -> LDE + Comms      |
+----------------------------------------------+
```

The in-memory YARA scanner reuses the existing `sda-local-detection`
YARA infrastructure — the rule store, signature verification, and
rotation handling are unchanged. Only the **input source** changes
from a file path to a byte slice (Phase E4.5).

---

## 4. Protocol extension

### 4.1 New `MessageType` variants

`sda-comms::MessageType` gains:

```rust
pub enum MessageType {
    // ... existing variants ...
    ProcessCreated,
    ProcessTerminated,
    ImageLoaded,
    NetworkConnection,
    DnsQuery,
    MemoryScanAlert,
    HostIsolationStateChanged,
    IdentityAlert,
}
```

Every variant has an explicit encoder arm in `protocol.rs` and a
corresponding mapping in `sda-agent::main::map_event_to_message`.

### 4.2 NATS subject hierarchy

The control plane consumes EDR Parity traffic on the `edr.*` tree:

```
edr.process_created.<tenant_id>.<device_id>
edr.process_terminated.<tenant_id>.<device_id>
edr.image_loaded.<tenant_id>.<device_id>
edr.network_connection.<tenant_id>.<device_id>
edr.dns_query.<tenant_id>.<device_id>
edr.memory_scan_alert.<tenant_id>.<device_id>
edr.host_isolation_state_changed.<tenant_id>.<device_id>
edr.identity_alert.<tenant_id>.<device_id>
```

The agent does not connect to NATS directly; the Agent Gateway (in
`sn360-security-platform`) translates between the agent's native
protocol frames and the NATS topology.

### 4.3 Signed-job validation (10-step checklist)

Host isolation reuses the **same** 10-step validation pipeline as
Device Control (see
[`docs/device-control/ARCHITECTURE.md` § 4.3](../device-control/ARCHITECTURE.md#43-signed-job-validation-10-step-checklist)).
The validator is implemented once in `sda-host-isolation::router`
and is the only entry point for host-isolation signed jobs into the
agent.

`IsolateHost` and `UnisolateHost` are added to the locally compiled
`ActionKind` allow-list at step 8; their `args` are validated
against the per-action strict struct at step 2 (deny unknown fields).

---

## 5. PAL additions

`sda-pal` exposes five new traits, with per-OS implementations
selected at compile time via `cfg`. The trait surface is:

```rust
pub trait ProcessMonitor: Send + Sync {
    async fn subscribe(&self, opts: &ProcessMonitorOpts) -> Result<ProcessEventStream>;
    fn lookup_ancestors(&self, pid: u32, max_depth: u32) -> Result<Vec<ProcessAncestor>>;
}

pub trait NetworkMonitor: Send + Sync {
    async fn subscribe(&self, opts: &NetworkMonitorOpts) -> Result<NetworkEventStream>;
    fn enumerate_established(&self) -> Result<Vec<ConnectionSnapshot>>;
}

pub trait DnsMonitor: Send + Sync {
    async fn subscribe(&self, opts: &DnsMonitorOpts) -> Result<DnsEventStream>;
}

pub trait MemoryScanner: Send + Sync {
    fn enumerate(&self, pid: u32) -> Result<Vec<MemoryRegion>>;
    fn read(&self, pid: u32, base: u64, len: usize, buf: &mut [u8]) -> Result<usize>;
}

pub trait HostIsolation: Send + Sync {
    fn isolate(&self, allow_ips: &[IpNet]) -> Result<()>;
    fn unisolate(&self) -> Result<()>;
    fn is_isolated(&self) -> Result<bool>;
    fn current_allowed_ips(&self) -> Result<Vec<IpNet>>;
}
```

### 5.1 Per-platform implementation matrix

| Trait              | Windows                                                                  | macOS                                                                          | Linux                                                                                          |
|--------------------|--------------------------------------------------------------------------|--------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| `ProcessMonitor`   | ETW `Microsoft-Windows-Kernel-Process` (PROCESS_START / STOP / IMAGE_LOAD). | Endpoint Security framework — `es_new_client` + `_NOTIFY_EXEC` / `_FORK` / `_EXIT` / `_MMAP`. | `cn_proc` netlink connector (`NETLINK_CONNECTOR` + `CN_IDX_PROC`) + `/proc/<pid>/` enrichment. |
| `NetworkMonitor`   | ETW `Microsoft-Windows-Kernel-Network` keyed on `ProcessId`.              | Network Extension framework — `NEFilterDataProvider`.                          | `audit` subsystem (`AUDIT_SOCKADDR` / `AUDIT_CONNECT`) + netlink `INET_DIAG` + `/proc/net/*`.  |
| `DnsMonitor`       | ETW `Microsoft-Windows-DNS-Client`.                                       | `NEDNSProxyProvider` or `dns_sd` API.                                          | Tap `journalctl -u systemd-resolved` or eBPF on `udp_sendmsg` (kernel ≥ 5.8).                  |
| `MemoryScanner`    | `VirtualQueryEx` + `ReadProcessMemory` over `PROCESS_QUERY_INFORMATION + PROCESS_VM_READ`. | `task_for_pid` (entitlement-gated) + `mach_vm_region` + `mach_vm_read_overwrite`. | `/proc/<pid>/maps` enumeration + `/proc/<pid>/mem` seek + bounded `pread`.                    |
| `HostIsolation`    | `netsh advfirewall` + WFP COM API; dedicated rule group `sn360_isolation`. | `pfctl` anchor `sn360_isolation`.                                              | `nftables` table `sn360_isolation`; default drop, accept allow-list.                          |

All providers run inside SDA's existing privilege-separated module
process boundary; no new privileged process is introduced by EDR
Parity beyond what is already required for FIM and device-control.

### 5.2 Per-OS entitlement / capability requirements

| Platform | Trait              | Capability / Entitlement                                                                                                                  |
|----------|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| Linux    | `ProcessMonitor`   | `CAP_NET_ADMIN` for cn_proc netlink; otherwise falls back to polling `/proc/`.                                                            |
| Linux    | `NetworkMonitor`   | `CAP_AUDIT_READ` for audit subsystem; `CAP_NET_ADMIN` for INET_DIAG.                                                                       |
| Linux    | `MemoryScanner`    | `CAP_SYS_PTRACE` to read `/proc/<pid>/mem` for processes outside the agent's UID.                                                          |
| Linux    | `HostIsolation`    | `CAP_NET_ADMIN` to write nftables rules.                                                                                                  |
| macOS    | `ProcessMonitor`   | `com.apple.developer.endpoint-security.client` entitlement; signed with Apple Developer ID; user must approve in System Settings.       |
| macOS    | `NetworkMonitor`   | `com.apple.developer.networking.networkextension` entitlement (content-filter provider type).                                            |
| macOS    | `DnsMonitor`       | `com.apple.developer.networking.networkextension` entitlement (DNS-proxy provider type).                                                  |
| macOS    | `MemoryScanner`    | `com.apple.security.cs.debugger` entitlement OR root for `task_for_pid`.                                                                  |
| macOS    | `HostIsolation`    | Root for `pfctl` modifications.                                                                                                            |
| Windows  | `ProcessMonitor`   | `SeSystemProfilePrivilege` (granted to `SYSTEM`); agent's Windows Service runs as `LOCAL SYSTEM`.                                         |
| Windows  | `NetworkMonitor`   | `SeSystemProfilePrivilege`.                                                                                                                |
| Windows  | `MemoryScanner`    | `SeDebugPrivilege` (granted to `SYSTEM`).                                                                                                  |
| Windows  | `HostIsolation`    | `SeNetworkConnectPrivilege` or higher; agent's Windows Service runs as `LOCAL SYSTEM`.                                                    |

---

## 6. Configuration schema

`AgentConfig` gains the following sections; **all default to off**
following the existing module pattern in `sda-core::config`. The one
exception is `local_detection.enabled`, which Phase E2.3 flips from
`false` to `true` in
[`crates/sda-core/src/config.rs` line 983](../../crates/sda-core/src/config.rs#L983).

```yaml
modules:
  process_monitor:
    enabled: false
    parent_chain_depth: 8
    image_load_events: true
    event_buffer_size: 4096

  network_monitor:
    enabled: false
    direction:
      outbound: true
      inbound: true     # set false to suppress server-side noise
    sample_high_rate_udp: true
    event_buffer_size: 8192

  dns_monitor:
    enabled: false
    source: "auto"      # auto | etw | network-extension | journald | ebpf

  memory_scanner:
    enabled: false
    scan_interval_secs: 300
    only_when_idle_below_cpu_pct: 20
    allow_list_processes:
      - "sn360-desktop-agent"
      - "explorer.exe"
    yara_rule_source: "trds"   # trds | local

  host_isolation:
    enabled: false
    control_plane_cidrs:
      - "203.0.113.0/24"
      - "198.51.100.0/24"
    always_allow_dns: true
    always_allow_loopback: true

  identity_monitor:
    enabled: false
    lsass_access_windows: true
    shadow_access_linux: true
    keychain_access_macos: true

  dlp:
    enabled: false
    mode: "monitor"      # monitor | enforce
    patterns:
      - "pii.ssn"
      - "pii.uk_ni"
      - "pci.pan_luhn"
    inspect_file_writes: true
    inspect_clipboard: false   # feature-gated via dlp-clipboard

local_detection:
  enabled: true            # Phase E2.3 — was false before EDR parity
  rule_pull_interval_secs: 300
  rule_bundle_max_bytes: 33554432  # 32 MiB
```

The full field reference is mirrored in
[`docs/configuration-reference.md`](../configuration-reference.md)
when the corresponding code lands.

---

## 7. Resource budgeting

### 7.1 Existing budgets are inviolable

| Metric                | Existing target | EDR Parity rule                                                                  |
|-----------------------|-----------------|----------------------------------------------------------------------------------|
| Idle RSS              | < 15 MB         | Disabled-by-default modules contribute zero idle RSS.                            |
| Idle CPU              | < 0.1 %         | No new periodic timers in idle when modules are disabled.                        |
| FIM scan peak CPU     | < 3 %           | EDR Parity uses `PowerMonitor::current_profile()` to defer heavy work.           |
| Binary size           | < 7 MB          | EDR Parity modules behind Cargo features where the size impact is non-trivial.   |

### 7.2 Per-module idle budgets (when enabled)

| Module                   | Max idle RSS | Max idle CPU | Notes                                                                  |
|--------------------------|--------------|--------------|------------------------------------------------------------------------|
| `sda-process-monitor`    | 5 MB         | 0.5 %        | Bounded mpsc; drops oldest event on overflow + emits vitals warning.   |
| `sda-network-monitor`    | 3 MB         | 0.3 %        | Sampling for high-rate UDP flows keeps CPU bounded.                    |
| `sda-pal::DnsMonitor`    | 2 MB         | 0.2 %        | DNS query volume is low on desktops; budget is generous.               |
| `sda-memory-scanner`     | 4 MB         | 1 % (scan window) / ~0 % (idle) | Scanner only runs in scheduled windows.                                |
| `sda-identity-monitor`   | 1 MB         | 0.1 %        | Mostly event-driven on existing FIM / audit / ES surfaces.             |
| `sda-host-isolation`     | < 0.5 MB     | ~0 %         | Pure action handler; no idle work outside an active job.               |
| `sda-dlp`                | 3 MB         | 0.5 %        | Pattern match cost bounded by FIM event volume.                        |

### 7.3 Combined idle budgets

| Configuration                                                                            | Idle RSS    | Idle CPU |
|------------------------------------------------------------------------------------------|-------------|----------|
| SDA baseline (no EDR modules)                                                            | < 15 MB     | < 0.1 %  |
| SDA + process + network + DNS monitors enabled                                           | < 25 MB     | < 1 %    |
| Full EDR slate (process + network + DNS + memory + identity + DLP)                        | < 32 MB     | < 2 %    |

The combined budgets are gated by the existing `make benchmark-ci`
pipeline, which already enforces idle RSS / idle CPU / FIM scan peak /
binary size. Phase E1.8 extends the gate with the per-module rows
from § 7.2.

### 7.4 Event priority assignments

| EventKind                              | Priority |
|----------------------------------------|----------|
| `ProcessCreated`                       | Normal   |
| `ProcessTerminated`                    | Low      |
| `ImageLoaded`                          | Low      |
| `NetworkConnection`                    | Normal   |
| `DnsQuery`                             | Normal   |
| `MemoryScanAlert`                      | High     |
| `HostIsolationStateChanged`            | High     |
| `IdentityAlert`                        | High     |

These priorities flow into `sda-event-bus`'s existing priority queue
without any new infrastructure.

---

## 8. Wire schema overview

Every new `EventKind` variant is serialised to a RFC 8785
canonical-JSON envelope and signed by the agent's evidence key.
The envelope shape mirrors the existing
[`docs/device-control/SCHEMAS.md`](../device-control/SCHEMAS.md)
pattern (and is governed by the same `schema_version` policy).

| EventKind                     | NATS subject suffix              | Payload fields (canonical-JSON)                                                                                                       |
|-------------------------------|----------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| `ProcessCreated`              | `edr.process_created`            | `{ tenant_id, device_id, observed_at, pid, ppid, name, exe_path, cmdline, user, parent_chain[], schema_version }`                     |
| `ProcessTerminated`           | `edr.process_terminated`         | `{ tenant_id, device_id, observed_at, pid, name, exit_code, schema_version }`                                                          |
| `ImageLoaded`                 | `edr.image_loaded`               | `{ tenant_id, device_id, observed_at, pid, image_path, image_hash, schema_version }`                                                   |
| `NetworkConnection`           | `edr.network_connection`         | `{ tenant_id, device_id, observed_at, pid, process_name, direction, protocol, local_addr, remote_addr, remote_port, schema_version }` |
| `DnsQuery`                    | `edr.dns_query`                  | `{ tenant_id, device_id, observed_at, pid, process_name, query_name, query_type, response_ips[], schema_version }`                    |
| `MemoryScanAlert`             | `edr.memory_scan_alert`          | `{ tenant_id, device_id, observed_at, pid, process_name, region_base, region_size, alert_type, description, schema_version }`         |
| `HostIsolationStateChanged`   | `edr.host_isolation_state_changed` | `{ tenant_id, device_id, observed_at, isolated, allowed_ips[], schema_version }`                                                       |
| `IdentityAlert`               | `edr.identity_alert`             | `{ tenant_id, device_id, observed_at, category, user, technique (MITRE ID), description, schema_version }`                            |

### 8.1 Redaction rules

The DLP module **never** writes matched content to the bus or to the
control plane. It writes only:

- The matched **pattern category** (e.g. `"pii.ssn"`,
  `"pci.pan_luhn"`).
- The **byte offset + length** of the match within the input.
- A **hash** of the surrounding 32-byte window (Blake3) for
  fingerprinting.

This mirrors the
[`pkg/privacy/`](https://github.com/kennguy3n/sn360-es/tree/main/pkg/privacy)
pseudonymisation pattern used elsewhere in the SN360 product family.

### 8.2 Wire schema sign-off

The eight `EventKind` variants + matching `MessageType` variants +
`edr.*` NATS subjects are signed off as part of **Phase E0.2–E0.4**.
Phase E0.5 records the sign-off in
[`PROGRESS.md`](./PROGRESS.md).

---

## 9. Security model

### 9.1 Threats and controls

| Threat                                                                            | Control                                                                                                                                            |
|-----------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| Compromised control-plane account issues malicious `IsolateHost` job              | Ed25519 signature + key rotation + dedicated approver tier + maintenance-window enforcement (mirrors device-control § 8.4).                       |
| Compromised agent forwards forged process / network telemetry                     | Existing mTLS enrolment + signed agent identity; control plane treats EDR telemetry as advisory until corroborated by other signals.              |
| Host isolation locks out the operator                                             | `allowed_ips` always includes SN360 control-plane CIDRs; loopback always allowed; DNS allow-list to control-plane resolvers; dedicated approver tier required. |
| TRDS hot-reload pushed a tampered rule bundle                                     | Ed25519 signature against locally pinned rotation set; rejected bundles never replace the live `DetectionPipeline`; high-severity `Finding` emitted. |
| Memory scanner triggers AV false-positive on the agent itself                     | Agent process pinned in scanner allow-list; YARA rules cleanly scoped to `pid != self_pid`.                                                       |
| DLP regex leaks matched content to the bus                                        | DLP module is hard-coded to never write match content; only pattern category, byte offset, and Blake3 hash leave the module.                       |
| Clean-room compliance for new PAL implementations                                  | License-audit gate (existing `cargo deny check licenses`) extended in Phase E0 to flag any reference-engine source-code import.                  |
| Multi-tenant data leakage (cross-tenant access to process / network telemetry)     | Existing Postgres RLS + per-tenant signing keys + agent-side `tenant_id` validation; control plane treats `edr.*` subjects as `tenant_id`-scoped. |
| Tampered agent binary disables EDR modules                                        | Existing tamper protection from Phase 5; EDR modules added behind the same checks. Kernel-mode tamper-protection deferred to Phase E6.            |
| Privilege escalation via PAL provider                                             | All PAL implementations run inside SDA's existing privilege-separated module process boundary; no new privileged process is introduced.            |

### 9.2 Clean-room license posture

All new PAL implementations under this slate are **clean-room**. No
CrowdStrike Falcon, SentinelOne, or Defender ATP source code is
referenced, vendored, or translated. The platform reference surfaces
(Linux `cn_proc` / netlink / audit / eBPF, Windows ETW providers,
macOS Endpoint Security framework, Network Extension framework) are
vendor-documented public APIs only.

Compliance is enforced via:

- The existing `cargo deny check licenses` gate, extended in Phase
  E0.5 to flag any reference-engine source-code import.
- A Phase E0 license-audit entry recorded in
  [`docs/security-audit.md`](../security-audit.md), mirroring the
  Phase 0 audit entries for Fleet / Munki / Santa / MeshCentral
  under
  [`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit).
- Per-PR license-review checklist requiring every new file to
  include the `SN360 Proprietary` header.

### 9.3 Host isolation safety

Host isolation is the single most dangerous action in the EDR
slate: a misfired `IsolateHost` job can take a device fully offline,
including from the operator. The agent enforces the following
guard-rails:

1. The `allowed_ips` list **must** include the SN360 control-plane
   CIDRs as configured under `modules.host_isolation.control_plane_cidrs`.
2. Loopback is **always** allowed.
3. DNS to control-plane resolvers is **always** allowed when
   `always_allow_dns: true`.
4. `IsolateHost` `SignedActionJob`s require a **dedicated approver
   tier** (configured at the control plane), not the standard
   approval-service tier used for software install / JIT admin.
5. The agent emits `HostIsolationStateChanged` immediately on
   isolation flip so the dashboard can flag a host that has just
   gone dark.

### 9.4 Memory scanner safety

1. The agent process itself (`sn360-desktop-agent`) is **always**
   pinned in the scanner allow-list at compile time.
2. The scanner respects the configured idle-CPU threshold; it
   pauses if system CPU exceeds the threshold.
3. The scanner reads at most `region_size` bytes per region; large
   regions are sampled (configurable) rather than read in full.
4. YARA rules are scoped to `pid != self_pid` at the rule-engine
   level so an accidental self-match is impossible.

---

## 10. Further reading

- [PROPOSAL.md](./PROPOSAL.md) — full technical proposal.
- [PHASES.md](./PHASES.md) — phased delivery plan + risk register.
- [PROGRESS.md](./PROGRESS.md) — delivery log.
- Parent [`docs/architecture.md`](../architecture.md) — current SDA
  crate map, event flow, and protocol details.
- Sibling
  [`docs/device-control/ARCHITECTURE.md`](../device-control/ARCHITECTURE.md) —
  Device Control architecture, including the signed-job validation
  pipeline reused by `sda-host-isolation`.
- Sibling
  [`docs/desktop-mdm/ARCHITECTURE.md`](../desktop-mdm/ARCHITECTURE.md) —
  Desktop MDM architecture (Phase M identifiers).
- Parent [`docs/revised-phase-plan.md`](../revised-phase-plan.md) —
  workspace phase plan; EDR Parity slots in as Phase 10.
- Productisation:
  [`docs/device-control/PRODUCTISATION-WINDOWS.md`](../device-control/PRODUCTISATION-WINDOWS.md)
  and
  [`docs/device-control/PRODUCTISATION-MACOS.md`](../device-control/PRODUCTISATION-MACOS.md) —
  the deferred-path roadmaps that Phase E6 mirrors.
