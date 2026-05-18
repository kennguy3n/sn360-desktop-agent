# SN360 Desktop Agent — Architecture

This document is the canonical architecture reference for the SN360
Desktop Agent (SDA). It describes the shape of the agent as it ships
today: which crates exist, how events flow, which OS APIs each module
calls into, and which resource invariants are maintained.

For install and operations see the [user guide](./user-guide.md) and
[administrator guide](./admin-guide.md). For the YAML schema see the
[configuration reference](./configuration-reference.md). For
wire-protocol details see [docs/wire-protocols/](./wire-protocols/).

---

## Table of contents

1. [Overview](#1-overview)
2. [Crate map](#2-crate-map)
3. [Event flow](#3-event-flow)
4. [Platform abstraction layer (`sda-pal`)](#4-platform-abstraction-layer-sda-pal)
5. [Resource budgets](#5-resource-budgets)
6. [Wire protocols](#6-wire-protocols)
7. [Module reference](#7-module-reference)
8. [Security model](#8-security-model)
9. [Further reading](#9-further-reading)

---

## 1. Overview

SDA is a single static Rust binary that runs as a privileged service
on Windows, macOS, and Linux endpoints. It collects telemetry,
evaluates local detection rules, and acts on signed jobs delivered
from the SN360 Security Platform.

The agent is composed of ~30 crates in a single Cargo workspace.
Each crate owns one responsibility — a transport, a detection module,
an OS abstraction. Modules communicate exclusively over an in-process
event bus (`sda-event-bus`); none of them know about each other.

```
+---------------------------------------------------------------+
|                       sda-agent (bin)                         |
+---------------------------------------------------------------+
|  Detection / collection modules                               |
|  +-----------+ +-----------+ +-----------+ +----------------+ |
|  | fim       | | inventory | | sca       | | logcollector   | |
|  +-----------+ +-----------+ +-----------+ +----------------+ |
|  +------------------+ +------------+ +----------------------+ |
|  | local-detection  | | rootcheck  | | active-response      | |
|  +------------------+ +------------+ +----------------------+ |
|                                                               |
|  EDR modules                                                  |
|  +-----------------+ +----------------+ +-------------------+ |
|  | process-monitor | | network-monitor| | memory-scanner    | |
|  +-----------------+ +----------------+ +-------------------+ |
|  +-----------------+ +-----+ +-----------------------------+ |
|  | identity-monitor| | dlp | | host-isolation              | |
|  +-----------------+ +-----+ +-----------------------------+ |
|                                                               |
|  Device control / management                                  |
|  +----------------+ +---------+ +---------+ +---------------+ |
|  | device-control | | posture | | software| | jit-admin     | |
|  +----------------+ +---------+ +---------+ +---------------+ |
|  +-------+ +-------+ +-------------+ +--------------+         |
|  | query | | mdm   | | app-control | | script-runner|         |
|  +-------+ +-------+ +-------------+ +--------------+         |
|                                                               |
|              sda-event-bus  (priority queue)                  |
+---------------------------------------------------------------+
|              sda-comms (TLS 1.3 + HTTP/2 + MsgPack)           |
+---------------------------------------------------------------+
|              sda-pal  (per-OS traits + impls)                 |
+---------------------------------------------------------------+
                              ||
                              \/
            +-------------------------------------+
            |  SN360 Security Platform (separate  |
            |  repo): Agent Gateway, NATS, TRDS,  |
            |  IOCFS, SIS, Risk Engine, Approval, |
            |  Evidence Vault.                    |
            +-------------------------------------+
```

The dashed boundary at the bottom — the control plane — lives in
[`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
This repository contains only the on-device agent.

---

## 2. Crate map

### 2.1 Core infrastructure

| Crate | Responsibility |
|---|---|
| `sda-core` | Shared types: `EventKind`, `EventPriority`, config schema, time utilities, error types. |
| `sda-event-bus` | In-process broadcast event bus with priority queueing and back-pressure. |
| `sda-pal` | Platform Abstraction Layer — per-OS trait surface (see § 4). |
| `sda-comms` | Wire transport: TLS 1.3 + HTTP/2 + MessagePack native; optional `legacy-siem` adapter. |
| `sda-agent` | The binary itself: module wiring, signed-job router, comms handshake, vitals. |

### 2.2 Endpoint protection

| Crate | Responsibility |
|---|---|
| `sda-fim` | File integrity monitoring with `fanotify` / FSEvents / `ReadDirectoryChangesW` backends and idle-only baseline scans. |
| `sda-inventory` | Hardware, package, network-interface, and user inventory. |
| `sda-enhanced-inventory` | Running-software snapshot, browser-extension inventory, CycloneDX SBOM emission. |
| `sda-sca` | Security configuration assessment — checks against shipped policy bundles. |
| `sda-logcollector` | File / syslog / journald / Windows Event Log ingestion. |
| `sda-rootcheck` | Rootkit indicators: hidden processes, hidden ports, suid checks. |
| `sda-active-response` | Server-issued `block_ip` / `kill_process` actions with command allow-list. |
| `sda-local-detection` | On-device detection engine: Aho-Corasick, IOC bloom filters, YARA, behavioural state machine. |
| `sda-updater` | Signed self-update: manifest poll, signature verify, atomic binary swap, rollback sibling. |

### 2.3 EDR modules

| Crate | Responsibility |
|---|---|
| `sda-process-monitor` | Process create / terminate / image-load telemetry with parent-chain enrichment. |
| `sda-network-monitor` | Network connection + DNS query telemetry with bounded LRU dedup. |
| `sda-host-isolation` | Per-OS firewall isolation in response to signed jobs. |
| `sda-memory-scanner` | Periodic RWX-region scanner with in-memory YARA and self-PID exclusion. |
| `sda-identity-monitor` | Credential-access detection (LSASS, `/etc/shadow`, Keychain) with MITRE technique tagging. |
| `sda-dlp` | Pattern-based PII / PCI scanning over FIM events with redaction-safe output. |

### 2.4 Device management

| Crate | Responsibility |
|---|---|
| `sda-device-control` | Signed-job router and 10-step validator; fan-out to sub-modules. |
| `sda-posture` | Live posture snapshots: disk encryption, firewall, screen lock, OS patch level. |
| `sda-software` | Approved software catalogue — install / update / uninstall via `PackageManager`. |
| `sda-jit-admin` | Time-boxed local-admin / root elevation with watchdog and drift detection. |
| `sda-script-runner` | Signed-script executor with hard-coded allow-list and bounded execution. |
| `sda-query` | osquery-compatible declarative query engine (sidecar by default). |
| `sda-policy` | Evaluates query results + posture + inventory deltas into `Finding`s. |
| `sda-app-control` | Application control (monitor → enforce) wrapping WDAC, Santa, Linux equivalents. |
| `sda-remote-support` | Operator-initiated, user-consented remote support sessions. |
| `sda-agent-vitals` | Agent self-telemetry: heartbeat, queue depth, last-seen, watchdog faults. |
| `sda-mdm` | Desktop MDM: remote wipe / lock / lost mode, recovery key escrow, OS patch, config profiles, auto-remediation. |
| `sda-management-compat` | Library-only translation shim for Fleet GitOps YAML → SDA `AgentConfig`. |

### 2.5 Layering rules

- `sda-agent` depends on every module crate.
- Every module crate depends on `sda-core`, `sda-event-bus`,
  `sda-pal`, `sda-comms`.
- No module crate depends on another module crate. Cross-module
  communication is exclusively via the event bus.
- Per-OS code lives behind `cfg(target_os = ...)` inside `sda-pal`;
  module crates are OS-agnostic.

---

## 3. Event flow

Every module produces and / or consumes `EventKind` values on the
shared bus:

```
+------------------+    +------------------+    +------------------+
| collection       |    | detection /      |    | management       |
| modules          |    | enrichment       |    | modules          |
| (fim, process-   |    | (local-detection,|    | (mdm, device-    |
|  monitor, …)     |    |  policy, dlp)    |    |  control, …)     |
+--------+---------+    +--------+---------+    +--------+---------+
         |                       |                       |
         | EventKind::*          | EventKind::*          | EventKind::*
         v                       v                       v
+----------------------------------------------------------------+
|       sda-event-bus  (priority queue + back-pressure)          |
+--------------------------------+-------------------------------+
                                 |
                                 v
+----------------------------------------------------------------+
|      sda-agent::map_event_to_message  (event -> wire frame)    |
+--------------------------------+-------------------------------+
                                 |
                                 v
+----------------------------------------------------------------+
|              sda-comms  (TLS 1.3 + HTTP/2 + MsgPack)           |
+--------------------------------+-------------------------------+
                                 |
                                 v
                       SN360 Agent Gateway
                                 |
                                 v
                       NATS subject hierarchy
```

### 3.1 Event priorities

Each `EventKind` is assigned a priority, which drives placement on
the bus and ordering on the wire:

| Priority | Examples |
|---|---|
| `High` | `HostIsolationStateChanged`, `MemoryScanAlert`, `IdentityAlert`, `LocalDetectionAlert` |
| `Normal` | `ProcessCreated`, `NetworkConnection`, `DnsQuery`, `FileCreated`, `Finding`, `ActionResult` |
| `Low` | `ProcessTerminated`, `ImageLoaded`, `Heartbeat`, `AgentVitals` |

The `sda-event-bus` priority queue strictly drains `High` before
`Normal` and `Normal` before `Low`. Back-pressure drops the oldest
event in the lowest non-empty band and emits an `AgentVitals`
warning.

### 3.2 Signed-job ingress

Server-issued actions (device-control, MDM, host-isolation) enter
the agent as `SignedActionJob` frames over `sda-comms` and pass
through the **same** 10-step validation pipeline implemented in
`sda-device-control::router`:

1. Verify the message frame decoded successfully under TLS 1.3 +
   HTTP/2 + MessagePack.
2. Parse `SignedActionJob` strictly (deny unknown fields).
3. Look up `key_id` against the locally pinned rotation set.
4. Verify the Ed25519 signature over the canonical encoding.
5. Reject if `not_before` is in the future or `not_after` in the
   past (≤ 60 s clock-skew tolerance).
6. Reject if `tenant_id` does not match the agent's enrolled tenant.
7. Reject if `device_id` does not match the agent's local identity.
8. Reject if `action` is not in the locally compiled allow-list for
   the agent's current pricing tier.
9. Apply maintenance window / quiet hours configuration.
10. Hand off to the relevant sub-module with a deadline and a budget.

Steps 2–8 produce a `JobRefused` event with a structured reason on
failure; the operator-facing UI uses these reasons verbatim.

Special arms: `RemoteWipe` adds an extra step requiring two
distinct approver signatures with two distinct `key_id`s (see
[Desktop MDM](./desktop-mdm.md)).

---

## 4. Platform abstraction layer (`sda-pal`)

`sda-pal` is the single home for every OS-specific syscall, ioctl,
DLL import, framework binding, and FFI surface. The rest of the
agent talks only to its trait surface, so a new platform can be
added by writing one set of trait impls.

### 4.1 Trait surface

```rust
// Endpoint protection
pub trait FsWatcher          { /* fanotify / FSEvents / ReadDirectoryChangesW */ }
pub trait PackageInventory   { /* dpkg, rpm, pacman, pkgutil, winget */ }

// EDR
pub trait ProcessMonitor     { /* cn_proc, ETW, Endpoint Security */ }
pub trait NetworkMonitor     { /* /proc/net, ETW, Network Extension */ }
pub trait DnsMonitor         { /* journald/eBPF, ETW, NEDNSProxy */ }
pub trait MemoryScanner      { /* /proc/<pid>/mem, VirtualQueryEx, mach_vm_read */ }
pub trait HostIsolation      { /* nftables, netsh+WFP, pfctl */ }

// Device control / MDM
pub trait PackageManager        { /* apt/dnf/zypper, winget, local repo */ }
pub trait AdminManager          { /* wheel/sudoers, NetLocalGroup, Open Directory */ }
pub trait DevicePostureProvider { /* LUKS/BitLocker/FileVault, firewall, screen lock */ }
pub trait AppControlProvider    { /* WDAC + AppLocker, Santa, dm-verity */ }
pub trait RemoteSupportProvider { /* WGC, ScreenCaptureKit, PipeWire/XCB */ }
pub trait MdmProvider           { /* wipe, lock, recovery-key, OS patch, profile, lost-mode */ }
```

### 4.2 Per-OS implementation matrix

| Trait | Windows | macOS | Linux |
|---|---|---|---|
| `ProcessMonitor` | ETW `Microsoft-Windows-Kernel-Process` | Endpoint Security `_NOTIFY_EXEC` / `_FORK` / `_EXIT` | `cn_proc` netlink + `/proc/<pid>/` |
| `NetworkMonitor` | ETW `Microsoft-Windows-Kernel-Network` | Network Extension `NEFilterDataProvider` | `audit` + `INET_DIAG` + `/proc/net/*` |
| `DnsMonitor` | ETW `Microsoft-Windows-DNS-Client` | `NEDNSProxyProvider` | journald `systemd-resolved` or eBPF on `udp_sendmsg` (kernel ≥ 5.8) |
| `MemoryScanner` | `VirtualQueryEx` + `ReadProcessMemory` (`SeDebugPrivilege`) | `task_for_pid` + `mach_vm_region` + `mach_vm_read_overwrite` | `/proc/<pid>/maps` + `/proc/<pid>/mem` (`CAP_SYS_PTRACE`) |
| `HostIsolation` | `netsh advfirewall` + WFP COM API; rule group `sn360_isolation` | `pfctl` anchor `sn360_isolation` | `nftables` table `sn360_isolation` |
| `PackageManager` | `winget` CLI | Munki-style local repo (clean-room) | apt / dnf / yum / zypper auto-detect |
| `AdminManager` | `Administrators` group via `NetLocalGroup*` | `admin` group via Open Directory | `wheel` / `sudo` + time-boxed `sudoers.d` drop-in |
| `MdmProvider` | `manage-bde`, `LockWorkStation`, BitLocker key escrow, `Install-WindowsUpdate` | `fdesetup`, `CGSession`, FileVault key escrow, `softwareupdate` | `cryptsetup`, `loginctl lock-sessions`, LUKS keyslot escrow, `unattended-upgrades` |

### 4.3 Privilege / capability requirements

Provider implementations declare which privileges they need at
runtime; `sda-pal` returns `Unsupported` from a trait method if the
necessary capability is absent, and the calling module degrades
gracefully (typically by disabling its providing telemetry stream).

| Platform | Trait | Requirement |
|---|---|---|
| Linux | `ProcessMonitor` | `CAP_NET_ADMIN` for cn_proc; otherwise polls `/proc/` |
| Linux | `NetworkMonitor` | `CAP_AUDIT_READ` for audit; `CAP_NET_ADMIN` for INET_DIAG |
| Linux | `MemoryScanner` | `CAP_SYS_PTRACE` to read other processes' `/proc/<pid>/mem` |
| Linux | `HostIsolation` | `CAP_NET_ADMIN` for nftables |
| macOS | `ProcessMonitor` | `com.apple.developer.endpoint-security.client` entitlement |
| macOS | `NetworkMonitor` / `DnsMonitor` | `com.apple.developer.networking.networkextension` |
| macOS | `MemoryScanner` | `com.apple.security.cs.debugger` or root for `task_for_pid` |
| Windows | `ProcessMonitor` / `NetworkMonitor` | `SeSystemProfilePrivilege` (granted to `SYSTEM`) |
| Windows | `MemoryScanner` | `SeDebugPrivilege` (granted to `SYSTEM`) |

The packaged installer for each platform configures the service to
run with the necessary privilege set (see [packaging/](../packaging/)).

---

## 5. Resource budgets

The agent is benchmarked against a hard set of resource budgets
that gate every release.

### 5.1 Top-line invariants

| Metric | Budget |
|---|---|
| Idle RSS (single process) | < 15 MB |
| Idle CPU (60 s avg, communications) | < 0.1 % |
| FIM scan peak CPU (1 000-file burst) | < 3 % |
| Stripped binary size | < 7 MB |

These are enforced in CI by `tests/scripts/benchmark-regression.sh`
(invoked via `make benchmark-ci`). The script builds the release
binary, samples idle RSS / CPU via `pidstat`, measures binary size
from `ls`, runs a FIM burst against a temporary watched directory,
and exits non-zero on the first breach. See
[`docs/benchmarks.md`](./benchmarks.md) for the full numbers and
comparison against the reference SIEM agent.

### 5.2 Per-module idle budgets (when enabled)

| Module | Max idle RSS | Max idle CPU | Notes |
|---|---|---|---|
| `sda-process-monitor` | 5 MB | 0.5 % | Bounded mpsc; drop-oldest back-pressure + vitals warning |
| `sda-network-monitor` | 3 MB | 0.3 % | Sampler keeps high-rate UDP CPU bounded |
| `sda-memory-scanner` | 4 MB | 1 % during scan window / ~0 % idle | Only runs in scheduled windows |
| `sda-identity-monitor` | 1 MB | 0.1 % | Event-driven on FIM / audit / ES surfaces |
| `sda-host-isolation` | < 0.5 MB | ~0 % | Pure action handler |
| `sda-dlp` | 3 MB | 0.5 % | Pattern match bounded by FIM event volume |
| `sda-mdm` | 2 MB | < 0.1 % | Long-idle; auto-remediation runs at posture interval |

### 5.3 Combined idle budgets

| Configuration | Idle RSS | Idle CPU |
|---|---|---|
| Baseline (no EDR / MDM modules) | < 15 MB | < 0.1 % |
| Baseline + process + network + DNS monitors | < 25 MB | < 1 % |
| Full EDR slate (process + network + DNS + memory + identity + DLP) | < 32 MB | < 2 % |
| Full EDR + MDM + device control | < 40 MB | < 2 % |

---

## 6. Wire protocols

### 6.1 Native protocol (SN360 Agent Gateway)

The default and recommended transport. Wire format:

- **Transport.** TLS 1.3, ALPN `h2`, mTLS for both enrolment and
  steady-state. The agent verifies the Gateway certificate against
  a pinned root or a pinned SHA-256 of the leaf (configurable per
  fleet).
- **Framing.** HTTP/2 streams. One stream per logical event batch
  for telemetry; one stream per `SignedActionJob` for ingress.
- **Body.** MessagePack-encoded RFC 8785 canonical-JSON envelopes
  for events. Inbound jobs use the same envelope shape for the
  signature pre-image.
- **Subject hierarchy.** The Gateway translates between the wire
  protocol and a NATS subject tree (`edr.*`, `device_control.*`,
  `mdm.*`, `inventory.*`, …). The agent never speaks NATS directly.

### 6.2 Legacy SIEM adapter

Optional, enabled by the `legacy-siem` Cargo feature on `sda-comms`.
Implements a publicly documented agent wire protocol on TCP/UDP
1514 (events) and TCP 1515 (enrolment) with Blowfish/AES + counters.
See [licensing.md](./licensing.md) for the clean-room interoperability
statement.

A proprietary-only build that does not need legacy interop compiles
the adapter out:

```sh
cargo build --release -p sda-agent --no-default-features
```

### 6.3 Bundle distribution

Detection rule bundles (TRDS) and IOC packages (IOCFS) are pulled
over HTTPS from object storage published by the control plane.
Bundles are Ed25519-signed MessagePack and verified before
activation. See [docs/edr.md § rule distribution](./edr.md#7-rule-distribution).

### 6.4 Schema policy

Every payload carries a `schema_version` field. Backwards-compatible
additions bump the minor; breaking changes bump the major and
require a coordinated control-plane release.

The full wire schema for device-control envelopes (`Finding`,
`Recommendation`, `SignedActionJob`, `ActionResult`,
`EvidenceRecord`) lives in
[`docs/wire-protocols/device-control.md`](./wire-protocols/device-control.md).

---

## 7. Module reference

The module surface is documented per topic. Each topic doc covers
trait shape, configuration, telemetry, threat model, and per-OS
notes.

| Topic | Doc |
|---|---|
| EDR (process, network, memory, identity, DLP) | [`edr.md`](./edr.md) |
| Device Control (policy → finding → recommendation → signed job) | [`device-control.md`](./device-control.md) |
| Desktop MDM (wipe, lock, recovery key, OS patch, config profiles) | [`desktop-mdm.md`](./desktop-mdm.md) |
| Optional kernel drivers (Windows minifilter, macOS SystemExtension, Linux eBPF) | [`kernel-drivers.md`](./kernel-drivers.md) |

---

## 8. Security model

### 8.1 Threat model

SDA runs with elevated privileges on end-user devices, so every
byte that enters an agent process is an attacker-reachable input.
The threat model assumes:

- A determined attacker can run code on the endpoint as a non-root
  user.
- The control plane is trusted but the network is not — TLS 1.3 +
  certificate pinning is the integrity boundary.
- An attacker with code execution may attempt to disable or unload
  agent modules; the binary is tamper-watched and the service is
  configured to restart on unauthorised mutation.
- The DLP and memory-scanner modules must not themselves become
  data-exfiltration channels.

See [`docs/security.md`](./security.md) for the full threat model,
crypto inventory, fuzzing matrix, and dependency-audit posture.

### 8.2 Redaction invariant

The DLP module **never** writes matched content to the event bus
or to the control plane. It writes only:

- The matched **pattern category** (`pii.ssn`, `pii.uk_ni`,
  `pci.pan_luhn`, …).
- The **byte offset + length** of the match within the input.
- A **Blake3 fingerprint** of the surrounding 32-byte window.

This mirrors the pseudonymisation pattern used elsewhere in the
SN360 product family.

### 8.3 Memory-scanner safety

The memory scanner is the only agent component that intentionally
reads other processes' address spaces. Two invariants make it safe:

1. **Self-PID exclusion.** The scanner refuses to read from the
   agent's own PID at both the PAL trait and the rule-engine level.
2. **Bounded reads.** Every `MemoryScanner::read` call is capped by
   a per-region byte budget; oversize regions are truncated rather
   than streamed, so a hostile process cannot pin the scanner with
   a gigabyte-sized RWX region.

### 8.4 Signed-job model

Every server-issued side effect (install, uninstall, isolation,
wipe, lock, …) passes through the 10-step validation pipeline in
§ 3.2. Validation is implemented once in `sda-device-control::router`
and is the only entry point for actions into the agent.
`RemoteWipe` requires two distinct approver signatures with two
distinct `key_id`s.

### 8.5 Tamper protection

`sda-agent::tamper` watches the binary, config file, and
`client.keys` on disk. Unauthorised mutation triggers a service
restart and an `AgentVitals` warning. The watchdog runs on a
separate `tokio` task from the comms loop so a hung comms layer
does not silence it.

---

## 9. Further reading

- [User guide](./user-guide.md) — per-host install and operation
- [Administrator guide](./admin-guide.md) — fleet deployment and tuning
- [Configuration reference](./configuration-reference.md) — full YAML schema
- [Benchmarks](./benchmarks.md) — performance numbers
- [Security](./security.md) — threat model, crypto, dependency audit
- [Licensing](./licensing.md) — proprietary licence rationale, clean-room policy
- [Release process](./release-process.md) — signing, notarisation, publication
- [Integration](./integration.md) — control-plane integration paths
- [Wire protocols](./wire-protocols/) — canonical schemas
- [Platform testing](./platform-testing.md) — CI matrix and manual procedures
