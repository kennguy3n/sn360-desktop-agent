# Technical Proposal: ShieldNet EDR Parity

> **Version:** 0.1 | **Date:** May 2026 | **Status:** Planning
> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)
> **Target Platforms:** Windows 10/11, macOS 12+, Linux (Ubuntu/Fedora/Arch)

> **Scope note:** ShieldNet EDR Parity spans both the agent
> (`sn360-desktop-agent`, this repository) and the SN360 control plane
> (`sn360-security-platform`). This proposal covers the design end to
> end so the two repositories can be built in lockstep, but only the
> *agent-side* sections (§§ 3, 4, 6, 7) are implemented in this
> repository. Control-plane sections (§ 5 and the ⚙️-tagged tasks in
> § 7) are implemented in
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).

---

## Table of Contents

1. [Motivation & competitive context](#1-motivation--competitive-context)
2. [Scope](#2-scope)
3. [Architecture](#3-architecture)
4. [Do-not-port / scope boundaries](#4-do-not-port--scope-boundaries)
5. [Server-side integration (sn360-security-platform)](#5-server-side-integration-sn360-security-platform)
6. [Risk register](#6-risk-register)
7. [Phasing](#7-phasing)

---

## 1. Motivation & competitive context

### 1.1 Where SDA stands today

The SN360 Desktop Agent (SDA) has shipped Phases 1–6, Phase D (Device
Control), and Phase M (Desktop MDM). Its observation surface is rich
in **integrity** and **inventory** signal — FIM, logcollector, SCA,
rootcheck, inventory deltas, posture snapshots, USB / removable-media
decisions — and the Local Detection Engine (LDE) already evaluates
IOC matches and YARA against those streams.

What SDA does *not* yet observe is the core EDR telemetry quartet
that every competing endpoint product treats as table stakes:
**process telemetry**, **network telemetry**, **DNS query
telemetry**, and **in-memory / fileless signal**. This is visible in
the LDE source today: the event-routing match in
[`crates/sda-local-detection/src/lib.rs`](../../crates/sda-local-detection/src/lib.rs)
extracts fields from `FileCreated` / `FileModified` /
`FileDeleted` / `FileMetadataChanged` / `LogCollected`, and falls
through to a literal `_ => return,` for every other `EventKind`
variant — see
[`crates/sda-local-detection/src/lib.rs` lines 355–358](../../crates/sda-local-detection/src/lib.rs#L355-L358):

```rust
// The LDE only observes FIM and logcollector streams; other
// event kinds pass through untouched.
_ => return,
```

In other words: the LDE pipeline is healthy, but the pipeline is fed
from a strict subset of what a full EDR observes.

### 1.2 What the competition ships

Across CrowdStrike Falcon, SentinelOne Singularity, and Microsoft
Defender for Endpoint, the **non-negotiable** floor for EDR parity is:

| Capability                                  | CrowdStrike | SentinelOne | Defender for Endpoint |
|---------------------------------------------|-------------|-------------|-----------------------|
| Kernel-mode process telemetry               | Yes         | Yes         | Yes (PPL + ETW-TI)    |
| Image-load / DLL-load telemetry             | Yes         | Yes         | Yes                   |
| Process-tree behavioural rules              | Yes         | Yes         | Yes                   |
| Network connection telemetry w/ PID attrib. | Yes         | Yes         | Yes                   |
| DNS query telemetry w/ PID attrib.          | Yes         | Yes         | Yes                   |
| Host network containment / isolation        | Yes         | Yes         | Yes                   |
| In-memory / RWX-region scanning             | Yes         | Yes         | Yes                   |
| AMSI in-memory script content               | Optional    | Optional    | Yes                   |
| Identity attack signal (LSASS, shadow)      | Yes         | Yes         | Yes                   |
| Outbound data / DLP content inspection      | Add-on      | Add-on      | Add-on                |

SDA's current event surface covers **none** of these. The architectural
foundation — the bounded priority event bus
([`crates/sda-event-bus`](../../crates/sda-event-bus/)), the per-OS
PAL trait pattern ([`crates/sda-pal`](../../crates/sda-pal/)), the
LDE pipeline
([`crates/sda-local-detection`](../../crates/sda-local-detection/)),
the SN360 native protocol with new `MessageType` and NATS subjects
added in Phase D / Phase M — was designed for this expansion. The
gap is in the **telemetry sources**, not in the runtime.

### 1.3 What this proposal commits to

Three workstreams (E, R, N — § 2 below) that close the user-mode
EDR-parity gap on Windows / macOS / Linux without breaking SDA's
existing resource budgets (idle RSS < 15 MB, idle CPU < 0.1 %, FIM
scan peak < 3 %, binary < 7 MB). Kernel-mode telemetry is
**explicitly deferred** to a productisation phase (§ 4) on the same
pattern as the deferred WDK driver and macOS SystemExtension already
documented under
[`docs/device-control/PRODUCTISATION-WINDOWS.md`](../device-control/PRODUCTISATION-WINDOWS.md)
and
[`docs/device-control/PRODUCTISATION-MACOS.md`](../device-control/PRODUCTISATION-MACOS.md).

Every new PAL implementation is **clean-room** — no CrowdStrike
Falcon agent source, no SentinelOne agent source, no Defender ATP
code reference. The platform reference surfaces we use (Linux
`cn_proc` / netlink / audit / eBPF, Windows ETW providers, macOS
Endpoint Security framework) are vendor-documented public APIs.

---

## 2. Scope

### 2.1 Workstreams

The work is organised into three workstreams. Workstream E is the
EDR-parity core; Workstream R matures the rule engine that consumes
the new telemetry; Workstream N adds the network / DNS / DLP surface
that completes the picture.

| Workstream | Theme                          | Crates / surfaces touched                                                                                  |
|------------|--------------------------------|------------------------------------------------------------------------------------------------------------|
| **E**      | EDR Parity                     | `sda-process-monitor`, `sda-network-monitor`, `sda-memory-scanner`, `sda-host-isolation`, `sda-identity-monitor` (new); `sda-pal` (5 new traits); `sda-event-bus::EventKind` (8 new variants). |
| **R**      | Rule Engine Maturity           | `sda-local-detection` (TRDS hot-reload, expanded event consumption, process-chain behavioural rules); `sda-core::config::LocalDetectionConfig` (default flip).                                |
| **N**      | Network & DLP                  | `sda-network-monitor` (DNS query logging, outbound monitoring); `sda-dlp` (new — pattern-based content inspection on file writes, clipboard, outbound data).                                  |

### 2.2 In scope for this proposal

- **Workstream E — EDR Parity.** Process telemetry (create /
  terminate / image load), network connection telemetry, host
  isolation, memory scanning (RWX + in-memory YARA), identity attack
  detection (LSASS / shadow / keychain).
- **Workstream R — Rule Engine Maturity.** LDE TRDS hot-reload (the
  placeholder at
  [`crates/sda-local-detection/src/lib.rs` lines 496–500](../../crates/sda-local-detection/src/lib.rs#L495-L501)
  is replaced with a verified bundle pull), LDE default-ON (the
  `enabled: false` at
  [`crates/sda-core/src/config.rs` line 983](../../crates/sda-core/src/config.rs#L983)
  flips to `true`), expanded LDE event consumption (the `_ => return,`
  at
  [`crates/sda-local-detection/src/lib.rs` line 357](../../crates/sda-local-detection/src/lib.rs#L357)
  is replaced with explicit arms for the new telemetry).
- **Workstream N — Network & DLP.** DNS query logging with process
  attribution, outbound connection monitoring, DLP content inspection
  via regex-based PII / PCI pattern matching on file-write events,
  clipboard, and outbound data buffers.

### 2.3 Phasing summary (detail in [`PHASES.md`](./PHASES.md))

| Phase | Theme                                              | Priority         | Duration   |
|-------|----------------------------------------------------|------------------|------------|
| E0    | Architecture & schema sign-off                     | P0 (gate)        | 2 weeks    |
| E1    | Process telemetry                                  | P0 — ship blocker | 8–10 weeks |
| E2    | LDE maturity + default-ON                          | P0 — ship blocker | 4–6 weeks  |
| E3    | Network telemetry + host isolation                 | P1 — core parity  | 8–10 weeks |
| E4    | Memory scanning + fileless detection               | P2 — differentiation | 6–8 weeks |
| E5    | Identity attack detection + DLP                    | P2 — differentiation | 6–8 weeks |
| E6    | Kernel driver productisation                       | P3 — nice to have | ongoing    |

---

## 3. Architecture

### 3.1 New PAL traits

Five new trait surfaces land in
[`crates/sda-pal/src/`](../../crates/sda-pal/src/). Each follows the
existing PAL convention: a `trait` in the OS-agnostic root module, a
per-OS implementation gated by `#[cfg(target_os = "...")]`, and a
test surface that exercises the trait through an in-memory fake.

#### 3.1.1 `process_monitor.rs` — `ProcessMonitor` trait

```rust
pub trait ProcessMonitor: Send + Sync {
    fn subscribe(&self) -> ProcessEventStream;
    fn enrich(&self, pid: Pid) -> Option<ProcessEnrichment>;
}
```

| Platform | Implementation                                                                                                       |
|----------|----------------------------------------------------------------------------------------------------------------------|
| Linux    | `cn_proc` netlink connector (`NETLINK_CONNECTOR` + `CN_IDX_PROC`) for process events; `/proc/<pid>/` for enrichment (exe path, cmdline, cgroup, namespaces, user). |
| Windows  | ETW `Microsoft-Windows-Kernel-Process` provider (`PROCESS_START`, `PROCESS_STOP`, `IMAGE_LOAD`) via the existing TraceLogging session in `sda-pal`. |
| macOS    | Endpoint Security framework — `es_new_client()` with `ES_EVENT_TYPE_NOTIFY_EXEC`, `ES_EVENT_TYPE_NOTIFY_FORK`, `ES_EVENT_TYPE_NOTIFY_EXIT`, `ES_EVENT_TYPE_NOTIFY_MMAP` for image loads. |

#### 3.1.2 `network_monitor.rs` — `NetworkMonitor` trait

```rust
pub trait NetworkMonitor: Send + Sync {
    fn subscribe(&self) -> NetworkEventStream;
    fn snapshot(&self) -> Vec<ConnectionEntry>;
}
```

| Platform | Implementation                                                                                                       |
|----------|----------------------------------------------------------------------------------------------------------------------|
| Linux    | `audit` subsystem (`AUDIT_SOCKADDR` / `AUDIT_CONNECT`) for connect-time signal; netlink `INET_DIAG` (NETLINK_INET_DIAG) for established-connection enumeration; process attribution via `/proc/net/{tcp,tcp6,udp,udp6}` and `/proc/<pid>/fd`. |
| Windows  | ETW `Microsoft-Windows-Kernel-Network` provider (TCP connect / accept / disconnect; UDP send / receive) keyed on `ProcessId`. |
| macOS    | Network Extension framework — `NEFilterDataProvider` registered as a content filter for connection metadata.         |

#### 3.1.3 `dns_monitor.rs` — `DnsMonitor` trait

```rust
pub trait DnsMonitor: Send + Sync {
    fn subscribe(&self) -> DnsEventStream;
}
```

| Platform | Implementation                                                                                                       |
|----------|----------------------------------------------------------------------------------------------------------------------|
| Linux    | Primary path: tap `/var/log/syslog` or `journalctl -u systemd-resolved` for dnsmasq / systemd-resolved query logs. Optional eBPF path: kprobe on `udp_sendmsg` for direct query interception (gated behind a Cargo feature). |
| Windows  | ETW `Microsoft-Windows-DNS-Client` provider (`DnsQueryExEvent`).                                                     |
| macOS    | `dns_sd` (`DNSServiceQueryRecord`) for ad-hoc resolves; `NEDNSProxyProvider` for system-wide query observation (DNS proxy mode). |

#### 3.1.4 `memory_scanner.rs` — `MemoryScanner` trait

```rust
pub trait MemoryScanner: Send + Sync {
    fn scan_pid(&self, pid: Pid) -> Result<Vec<MemoryRegion>, ScanError>;
    fn read_region(&self, pid: Pid, base: usize, len: usize) -> Result<Vec<u8>, ScanError>;
}
```

| Platform | Implementation                                                                                                       |
|----------|----------------------------------------------------------------------------------------------------------------------|
| Linux    | Parse `/proc/<pid>/maps` for region enumeration (filter RWX, anonymous regions, JIT-style regions); read via `/proc/<pid>/mem` with seek + bounded read. |
| Windows  | `VirtualQueryEx` over the target process handle (`PROCESS_QUERY_INFORMATION` + `PROCESS_VM_READ`); `ReadProcessMemory` for RWX page reads. |
| macOS    | `task_for_pid` (entitlement-gated) → `mach_vm_region` for enumeration; `mach_vm_read_overwrite` for region reads.    |

#### 3.1.5 `host_isolation.rs` — `HostIsolation` trait

```rust
pub trait HostIsolation: Send + Sync {
    fn isolate(&self, allowed_ips: &[IpAddr]) -> Result<(), IsolationError>;
    fn unisolate(&self) -> Result<(), IsolationError>;
    fn is_isolated(&self) -> bool;
}
```

| Platform | Implementation                                                                                                       |
|----------|----------------------------------------------------------------------------------------------------------------------|
| Linux    | `nftables` rules in a dedicated `sn360_isolation` table; allow only the configured SN360 control-plane IPs + loopback; block everything else. |
| Windows  | Windows Filtering Platform via the existing PowerShell `netsh advfirewall` shell-out path, mirroring the existing app-control conventions in [`crates/sda-app-control`](../../crates/sda-app-control/); WFP COM API for filter ordering. |
| macOS    | `pfctl` anchor (`com.sn360.host_isolation`) with a custom ruleset; reload via `pfctl -a com.sn360.host_isolation -f`. |

### 3.2 New `EventKind` variants

Eight new variants land in
[`crates/sda-event-bus/src/event.rs`](../../crates/sda-event-bus/src/event.rs)
(the file that currently owns the `EventKind` enum). Each variant
must have an explicit arm in `WazuhMessage::encode_body()` when the
`legacy-siem` feature is on, per the existing repo invariant
documented in
[`docs/device-control/ARCHITECTURE.md` § 2.1](../device-control/ARCHITECTURE.md#21-new-eventkind-variants).

```rust
pub enum EventKind {
    // ... existing variants ...

    /// A new process has been created. Carries the parent chain up
    /// to the configured depth so downstream behavioural rules can
    /// match on lineage.
    ProcessCreated {
        pid: u32,
        ppid: u32,
        name: String,
        exe_path: PathBuf,
        cmdline: Vec<String>,
        user: String,
        parent_chain: Vec<ProcessAncestor>,
    },

    /// A process has terminated.
    ProcessTerminated {
        pid: u32,
        name: String,
        exit_code: i32,
    },

    /// A DLL / dylib / shared object has been loaded into a process.
    ImageLoaded {
        pid: u32,
        image_path: PathBuf,
        image_hash: Option<[u8; 32]>,
    },

    /// A new network connection has been observed.
    NetworkConnection {
        pid: u32,
        process_name: String,
        direction: ConnectionDirection,
        protocol: TransportProtocol,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        remote_port: u16,
    },

    /// A DNS query has been observed (sent or seen by the resolver).
    DnsQuery {
        pid: u32,
        process_name: String,
        query_name: String,
        query_type: DnsRecordType,
        response_ips: Vec<IpAddr>,
    },

    /// The memory scanner has flagged a region of interest.
    MemoryScanAlert {
        pid: u32,
        process_name: String,
        region_base: u64,
        region_size: u64,
        alert_type: MemoryAlertKind,
        description: String,
    },

    /// Host isolation state has changed (operator-driven or by
    /// SignedActionJob).
    HostIsolationStateChanged {
        isolated: bool,
        allowed_ips: Vec<IpAddr>,
    },

    /// Credential theft / identity attack signal.
    IdentityAlert {
        category: IdentityAlertCategory,
        user: String,
        technique: String,           // MITRE ATT&CK technique ID.
        description: String,
    },
}
```

Wire schema specs for each variant land in
[`docs/edr-parity/PHASES.md` § Phase E0](./PHASES.md#phase-e0--architecture--schema-2-weeks)
(task E0.4) before any Phase E1 code merges.

### 3.3 New crates

Six new agent-side crates land under
[`crates/`](../../crates/). Each follows the existing SDA crate
convention: a `lib.rs` exporting a single `*Module` struct that
implements the existing module-lifecycle trait, a per-OS source file
(`linux.rs` / `macos.rs` / `windows.rs`), a `mod tests` block, and a
`Cargo.toml` that depends on `sda-core`, `sda-event-bus`,
`sda-pal`, and `sda-comms`.

| Crate                   | Purpose                                                                                                        | Workstream | Phase  |
|-------------------------|----------------------------------------------------------------------------------------------------------------|------------|--------|
| `sda-process-monitor`   | Process telemetry module. Subscribes to `sda-pal::ProcessMonitor`, enriches with parent chain, publishes `ProcessCreated` / `ProcessTerminated` / `ImageLoaded`. | E          | E1     |
| `sda-network-monitor`   | Network connection + DNS telemetry module. Subscribes to `sda-pal::NetworkMonitor` + `sda-pal::DnsMonitor`, publishes `NetworkConnection` / `DnsQuery`. | E + N      | E3     |
| `sda-memory-scanner`    | Periodic RWX-region scanner + in-memory YARA. Reuses the existing YARA scanner from `sda-local-detection`.     | E          | E4     |
| `sda-host-isolation`    | Host network containment via the new `HostIsolation` PAL trait. Activated by `SignedActionJob` from the control plane. | E          | E3     |
| `sda-identity-monitor`  | Credential theft detection (LSASS access on Windows, `/etc/shadow` + `/proc/kcore` access on Linux, keychain access on macOS). | E          | E5     |
| `sda-dlp`               | Data loss prevention content inspector — regex-based PII / PCI pattern matching on file writes, clipboard, and outbound data buffers. | N          | E5     |

### 3.4 LDE expansion in `sda-local-detection`

Two structural changes to
[`crates/sda-local-detection/src/lib.rs`](../../crates/sda-local-detection/src/lib.rs):

1. **Event consumption.** The `handle_event` match (around
   [`crates/sda-local-detection/src/lib.rs` line 314](../../crates/sda-local-detection/src/lib.rs#L314))
   currently extracts fields only from FIM and logcollector events,
   falling through to `_ => return,` at
   [line 357](../../crates/sda-local-detection/src/lib.rs#L357).
   Phase E1 adds explicit arms for `ProcessCreated`,
   `ProcessTerminated`, `ImageLoaded`; Phase E3 adds
   `NetworkConnection`, `DnsQuery`; Phase E4 adds `MemoryScanAlert`.
   Each new arm constructs the same `(source_tag, entity,
   primary_text, fim_path, sha256, ips)` tuple shape so the
   downstream IOC + behavioural-rule + YARA pipeline reuses without
   modification.

2. **Behavioural rules — process chain.** The existing
   `pipeline.behavioral` matcher gains process-chain rules that fire
   on parent-child anomalies: Word spawning PowerShell, `wmiprvse`
   spawning `rundll32`, `lsass.exe` being opened by a non-system
   process, etc. The rule schema is a small extension to the
   existing JSON DSL — a new optional `parent_chain` predicate that
   matches a regex against the joined parent-chain names.

3. **Network IOC matching.** The existing `pipeline.iocs` matcher
   already supports IP and domain backends. Phase E3 wires
   `NetworkConnection.remote_addr` and `DnsQuery.query_name` into
   the same backend, so a domain / IP IOC bundle pushed by TRDS
   matches against connection telemetry without new rule-engine
   code.

### 3.5 LDE hot-reload + default-ON

The TRDS rule-pull timer in
[`crates/sda-local-detection/src/lib.rs` lines 495–501](../../crates/sda-local-detection/src/lib.rs#L495-L501)
currently logs:

```rust
_ = rule_pull_timer.tick() => {
    // Placeholder for TRDS pull.  The real pull will reach
    // out to the Tenant Rule Distribution Service; for now
    // we simply log — operators can hot-swap by writing a
    // new bundle and restarting the module.
    debug!("LDE rule pull timer fired (hot-reload not yet implemented)");
}
```

Phase E2 replaces this with a verified bundle pull against the TRDS
endpoint registered in
[`sn360-security-platform/services/trds-api`](https://github.com/kennguy3n/sn360-security-platform).
The pull verifies the bundle's Ed25519 signature against the locally
pinned rotation set (mirroring the signed-job validation pattern in
[`docs/device-control/PROPOSAL.md` § 10.3](../device-control/PROPOSAL.md#103-signed-job-validation-10-step-checklist)),
hot-swaps the in-memory `DetectionPipeline` via an atomic CAS, and
emits a `RuleBundleApplied` event with the new bundle version.

The default at
[`crates/sda-core/src/config.rs` line 983](../../crates/sda-core/src/config.rs#L983)
flips from:

```rust
Self {
    enabled: false,                     // line 983 — flip to true
    rule_pull_interval: default_lde_rule_pull_interval(),
    // ...
}
```

to `enabled: true`, so a fresh install ships with baseline IOC +
behavioural detection on by default.

### 3.6 Config changes in `sda-core::config`

Seven new module-config structs land in
[`crates/sda-core/src/config.rs`](../../crates/sda-core/src/config.rs).
Each follows the existing `default: enabled = false` convention
(mirroring `DeviceControlConfig`, `UsbPolicyConfig`, etc.) so the
agent's idle footprint with EDR parity opt-in defaults remains the
same as today.

| Struct                    | Default `enabled` | Notes                                                                            |
|---------------------------|-------------------|----------------------------------------------------------------------------------|
| `ProcessMonitorConfig`    | `false`           | Process telemetry; budget < 5 MB RSS / < 0.5 % idle CPU.                         |
| `NetworkMonitorConfig`    | `false`           | Network connection telemetry; budget < 3 MB RSS / < 0.3 % idle CPU.              |
| `DnsMonitorConfig`        | `false`           | DNS query telemetry; budget < 2 MB RSS / < 0.2 % idle CPU.                       |
| `MemoryScannerConfig`     | `false`           | Periodic RWX scanner; budget < 4 MB RSS / < 1 % CPU during scan windows.         |
| `HostIsolationConfig`     | `false`           | Host containment; budget negligible (rules are evaluated by the kernel).         |
| `IdentityMonitorConfig`   | `false`           | LSASS / shadow / keychain; budget < 1 MB RSS / < 0.1 % idle CPU.                 |
| `DlpConfig`               | `false`           | PII / PCI pattern matching; budget < 3 MB RSS / < 0.5 % CPU during scan windows. |
| `LocalDetectionConfig`    | **`true`** (flip) | LDE default-ON — Phase E2 flips `enabled: false → true` at line 983.             |

---

## 4. Do-not-port / scope boundaries

The following capabilities are explicitly **out of scope** for the
EDR-parity slate and are not delivered in any form by Phases E0–E6:

- **No full packet capture / PCAP.** SDA observes connection metadata
  and DNS metadata, not payloads. Operators who need full PCAP run a
  dedicated network appliance.
- **No TLS interception / MITM proxy.** SDA does not terminate TLS
  for inspection. DLP on outbound data is scoped to plaintext buffers
  before they reach the TLS stack (clipboard, file writes,
  unencrypted protocols).
- **No full deep packet inspection (DPI).** DLP is pattern-matching
  only — regex-based PII / PCI patterns against plaintext content.
- **No kernel driver in this phase.** All Phase E1–E5 implementations
  are user-mode only. Kernel drivers (Windows WDK minifilter, macOS
  SystemExtension productisation, Linux eBPF programs) are tracked
  under Phase E6 as productisation work, on the same deferred-path
  pattern as the existing
  [`PRODUCTISATION-WINDOWS.md`](../device-control/PRODUCTISATION-WINDOWS.md)
  and
  [`PRODUCTISATION-MACOS.md`](../device-control/PRODUCTISATION-MACOS.md).
- **No source-code reference to commercial EDRs.** All new PAL
  implementations are **clean-room** — no CrowdStrike Falcon agent
  source, no SentinelOne agent source, no Defender ATP code
  reference. The platform reference surfaces (Linux `cn_proc` /
  netlink / audit / eBPF, Windows ETW providers, macOS Endpoint
  Security framework) are vendor-documented public APIs only.
- **No general-purpose remote shell.** Operator interaction stays on
  the existing `sda-remote-support` consent-banner-gated path
  delivered in Phase 4 of Device Control.

---

## 5. Server-side integration (sn360-security-platform)

Since we own the control plane, the following work must land in
[`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)
in lockstep with the agent-side phases. Each item is marked ⚙️ in
the per-phase task tables in [`PHASES.md`](./PHASES.md) and tracked
in the corresponding sibling progress doc in `sn360-security-platform`.

| Service                  | Required change                                                                                                                                                  | Phase  |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------|
| TRDS (`services/trds-api`) | Process-rule and network-rule bundle compilation; new bundle subtypes for behavioural-rule + IOC pairings; full rule CRUD + delta distribution.                  | E1, E2 |
| Agent Gateway            | New NATS subjects for process / network / DNS / memory / identity telemetry under the `edr.*` subject tree.                                                      | E1, E3 |
| Risk Engine              | New recommendation rules for process-chain anomalies, network IOC matches, and identity attack signal.                                                           | E1, E3, E5 |
| SMI Engine               | New `edr_coverage` sub-score that ingests `ProcessMonitor` / `NetworkMonitor` / `MemoryScanner` enablement + alert volume.                                       | E1, E3 |
| Dashboard                | Process-tree viewer, network-connection map, host-isolation button, identity-alert view, DLP-finding view.                                                       | E3, E5 |
| Action Orchestrator      | New action types `IsolateHost` / `UnisolateHost` dispatched as `SignedActionJob`s along the existing Phase 4 / Phase D2 signed-job pipeline.                     | E3     |

> All control-plane services in this section live in
> `sn360-security-platform`. No control-plane code is added to this
> repository under any circumstances. Per the user's standing
> preference, control-plane services are implemented in Go.

---

## 6. Risk register

The risk register shapes scope and sequencing for every phase in
[`PHASES.md`](./PHASES.md). This section is the authoritative source;
`PHASES.md § Risk register` is the phase-planner's quick reference.

| #  | Risk                                                                  | Severity   | Mitigation                                                                                                                                        |
|----|-----------------------------------------------------------------------|------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  | Process telemetry blows idle-RSS budget                                | High       | Per-OS resource budget gate (`make benchmark-ci`) — process monitor must add < 5 MB RSS / < 0.5 % idle CPU. Module disabled by default until E2.  |
| 2  | ETW / Endpoint Security framework instability                          | High       | Provider sessions wrapped in supervised tasks with restart-with-backoff; tracked under `sda-agent-vitals` heartbeat.                              |
| 3  | Host isolation locks operator out of agent                             | Critical   | `allowed_ips` always includes SN360 control-plane CIDRs; loopback always allowed; isolation `SignedActionJob`s require a dedicated approver tier. |
| 4  | False-positive process-chain rules in default bundle                   | High       | Default bundle ships only baseline, vendor-validated rules; operator-tunable false-positive feedback loop via TRDS.                              |
| 5  | Memory scanner triggers AV false-positives on the agent itself         | Medium     | Agent process pinned in scanner allow-list; YARA rules cleanly scoped to `pid != self_pid`.                                                       |
| 6  | macOS Endpoint Security entitlement gating                             | High       | Phase E1 ships with documented entitlement requirements; CI matrix runs on macOS 14 + 15 to catch entitlement regressions.                        |
| 7  | Clean-room compliance for new PAL implementations                      | Critical   | License audit gate (existing `cargo deny check licenses`) extended in Phase E0 to flag any reference-engine source-code import.                  |
| 8  | DLP regex false-positives swamp operator                               | High       | DLP rules ship in monitor mode by default; enforce mode opt-in per tenant; pattern false-positive rate tracked in `sda-agent-vitals`.            |
| 9  | LDE default-ON flip surprises existing operators                       | Medium     | Phase E2 ships a documented migration note; default bundle is conservative; operators can flip back via `LocalDetectionConfig.enabled = false`.   |
| 10 | TRDS hot-reload race with active rule evaluation                       | High       | Atomic CAS swap of `DetectionPipeline` (mirrors `UsbPolicySupervisor::apply_bundle_slice` from Phase D2); per-event evaluations finish on old set. |
| 11 | Cross-platform telemetry shape drift                                    | Medium     | `EventKind` variants are platform-agnostic; per-OS PAL implementations map to the same struct shape; CI matrix exercises all three.              |
| 12 | Kernel-mode deferral leaves tamper-protection gap                       | High       | Phase E6 explicitly tracks the productisation path; interim mitigation is the existing tamper-protection from Phase 5.3 + `sda-agent-vitals`.    |

---

## 7. Phasing

A summary of the seven phases (E0–E6) appears in § 2.3 above. The
detailed per-task ledger — task IDs, exit criteria per phase, test
surface requirements, cross-references, server-side ⚙️ markers —
lives in [`PHASES.md`](./PHASES.md). Live status is tracked in
[`PROGRESS.md`](./PROGRESS.md).

---

## Cross-references

- [`PHASES.md`](./PHASES.md) — phased delivery plan with per-task IDs (E0.1–E6.4) and exit criteria.
- [`PROGRESS.md`](./PROGRESS.md) — live progress tracker.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — diagram-first architecture companion.
- [`docs/device-control/PROPOSAL.md`](../device-control/PROPOSAL.md) — sibling Device Control proposal; reuses signed-job validator and evidence chain.
- [`docs/desktop-mdm/PROPOSAL.md`](../desktop-mdm/PROPOSAL.md) — sibling Desktop MDM proposal.
- [`docs/revised-phase-plan.md`](../revised-phase-plan.md) — workspace phase plan; EDR Parity slots in as Phase 10.
- [Phase E0 source line references](../../crates/sda-local-detection/src/lib.rs#L355-L358) — the `_ => return,` arm replaced in Phase E1.
- [Phase E2 source line references](../../crates/sda-core/src/config.rs#L983) — the `LocalDetectionConfig.enabled = false` flipped in Phase E2.
- Control-plane companion: [`sn360-security-platform/docs/edr-parity/`](https://github.com/kennguy3n/sn360-security-platform/tree/main/docs/edr-parity) (to be created in lockstep).
