# SDA Architecture

This document is the consolidated architecture reference for SDA.
It is intentionally narrower than the original
[`device-agent-proposal.md`](../device-agent-proposal.md) — that
document still captures the design rationale; this one captures
the shape of the code as shipped today.

---

## 1. Crate map

| Crate                          | Responsibility                                                                |
|--------------------------------|--------------------------------------------------------------------------------|
| `sda-agent`                    | Main binary. Wires modules to the event bus and owns the tokio runtime.        |
| `sda-core`                     | Config loading/validation (`AgentConfig`) and shutdown coordination.           |
| `sda-pal`                      | Platform Abstraction Layer: filesystem watcher, power monitor, system info.   |
| `sda-event-bus`                | Bounded async channels with priority queues and back-pressure.                 |
| `sda-comms`                    | Communication layer. SN360 native protocol (TLS 1.3 + HTTP/2 + MessagePack, default) and optional legacy SIEM protocol adapter (TCP/UDP + Blowfish/AES, behind the `legacy-siem` Cargo feature). |
| `sda-fim`                      | File integrity monitoring: real-time watcher, idle-aware baseline scan, SQLite state. |
| `sda-logcollector`             | Log collection: file tailers, journald (Linux), EvtSubscribe (Windows), OSLog (macOS). |
| `sda-inventory`                | Classic syscollector-compatible inventory.                                     |
| `sda-enhanced-inventory`       | Running-software, browser-extension, and SBOM (CycloneDX) scanners.            |
| `sda-sca`                      | Security configuration assessment engine (YAML policy evaluator).              |
| `sda-rootcheck`                | Rootkit signatures + hidden-process detection.                                 |
| `sda-local-detection`          | On-device rule engine: Aho-Corasick, IOC bloom filters, YARA, behavioural DSL. |
| `sda-active-response`          | Active response dispatcher (block IP, kill process, custom scripts).           |
| `sda-updater`                  | Signed self-update (manifest poll, download, atomic swap, rollback).           |

The crates form a layered workspace — `sda-agent` depends on
everything, the module crates depend on `sda-core` /
`sda-event-bus` / `sda-pal` / `sda-comms`, and those four form the
foundation layer with minimal coupling to each other.

## 2. Event flow

```
  +------------------------------------------------------------+
  |                        sda-agent                           |
  |                                                            |
  |   +-----------+     Event Bus (sda-event-bus)              |
  |   | FIM       |------+                                      |
  |   +-----------+      |                                      |
  |   | Inventory |------+       +----------+    +--------+    |
  |   +-----------+      |====>  | Router   |==> | Comms  |=====>  Manager
  |   | LogColl   |------+       | (main.rs)|    | Comms  |    |  (SN360 Control Plane)
  |   +-----------+      |       +----------+    +--------+    |
  |   | LDE       |------+                                      |
  |   +-----------+      |                                      |
  |   | SCA       |------+                                      |
  |   +-----------+      |                                      |
  |   | Rootcheck |------+                                      |
  |   +-----------+      |                                      |
  |   | AR        |<-----+  (server → agent control frames)    |
  |   +-----------+                                             |
  +------------------------------------------------------------+
```

> The "Manager (SN360 Control Plane)" box represents the server-side
> infrastructure implemented in
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
> This repository contains only the agent (left side of the diagram).

Every module publishes `EventKind` variants to the bus. The
router in `sda-agent::main::map_event_to_message` maps each
`EventKind` to a `MessageType` before handing it off to
`sda-comms`. On the SN360 native protocol path each `MessageType`
maps to a native event category; on the legacy adapter path each
`MessageType` is additionally prefixed with a legacy queue prefix
to match the publicly documented SIEM manager wire protocol.

Legacy SIEM queue prefixes are enforced in
[`crates/sda-comms/src/protocol.rs`
`WazuhMessage::encode_body`](../crates/sda-comms/src/protocol.rs)
and apply **only when the `legacy-siem` feature is active**:

| MessageType     | Legacy prefix       |
|-----------------|---------------------|
| `Log`           | `1:`                |
| `Syscheck`      | `8:syscheck:`       |
| `Rootcheck`     | `9:`                |
| `Syscollector`  | `d:`                |
| `Sca`           | `p:`                |
| `ActiveResponse`| `1:active-response:`|
| `LocalDetection`| `1:local-detection:`|
| control frames  | none (passthrough)  |

Adding a new `MessageType` without an explicit arm here causes the
legacy SIEM manager to silently drop the frame, so the protocol
tests in `protocol.rs` exhaustively assert the prefixes.

## 3. Communication layers

### 3.1 Stable stream protocol (default)

The default comms path is UDP or TCP on port 1514 against an
existing SIEM manager. This path is always compiled in and stays
on when the `legacy-siem` Cargo feature is enabled (see
[`proprietary-licensing-rationale.md`](./proprietary-licensing-rationale.md)
for the clean-room interoperability statement):

- UDP or TCP on port 1514.
- Payloads encrypted with Blowfish (and AES, depending on server
  negotiation). A single cipher is shared for the lifetime of a
  session so per-agent `(global, local)` counters in the manager's
  `remoted` stay monotonic.
- Enrolment uses the publicly documented `authd`-compatible
  endpoint on 1515 with password authentication and persists the
  issued agent identity to `client.keys`.

### 3.2 SN360 Native Protocol (opt-in)

Three orthogonal knobs under `server.enhanced`, all default
**off** today. Flip any of them on to move a deployment onto the
SN360 native protocol against an SN360 Agent Gateway:

| Option             | Crate surface                                   | Default |
|--------------------|-------------------------------------------------|---------|
| TLS 1.3            | `sda_comms::transport::tls` (`rustls`)          | off     |
| MessagePack events | `sda_comms::msgpack::MessagePackSerializer`     | off     |
| HTTP/2 transport   | `sda_comms::transport::http2` (requires TLS)    | off     |

ALPN identifiers: `b"h2"` for HTTP/2, `b"sda/1.0"` for native
TCP-over-TLS. Certificate pinning is SHA-256 leaf-fingerprint
based and configured via `server.enhanced.tls_pinned_sha256`.
Native enrolment is mTLS against the SN360 Agent Gateway
(implemented in [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)).
The [revised phase plan](./revised-phase-plan.md) tracks the work to
promote the native path to default-on in a future phase.

## 4. Platform Abstraction Layer

`sda-pal` exposes traits — `FileSystemWatcher`, `PowerMonitor`,
`ServiceManager`, `SystemInfo`, `LogSource` — with per-OS
implementations selected at compile time via `cfg`. The file
watcher prefers `fanotify` on Linux (when `CAP_SYS_ADMIN` is
available) and falls back to `inotify`. macOS uses `FSEvents`;
Windows uses `ReadDirectoryChangesW`.

## 5. Resource budgeting

All modules consult the power profile returned by
`PowerMonitor::current_profile()` before running heavy work. The
profile transitions between `Normal`, `IdleAC`, `BatteryActive`,
`BatteryIdle`, and `CriticalBattery` as described in § 9.4 of the
proposal. Hard budgets (idle RSS < 15 MB, idle CPU < 0.1 %, binary
< 7 MB, FIM burst peak < 3 %) are verified nightly by
`tests/scripts/benchmark-regression.sh`.

## 6. Testing layers

| Layer            | Command                  | Coverage                                                 |
|------------------|--------------------------|----------------------------------------------------------|
| Unit             | `cargo test --all`       | 400+ tests across all crates                             |
| Base E2E         | `make e2e`               | 14 assertions vs a reference SIEM manager (v4.9.2)       |
| Compat E2E       | `make e2e-compat`        | 14 assertions vs a reference SIEM manager (v4.7.5)       |
| Security E2E     | `make security-e2e`      | 10 attack scenarios (malware drop, brute force, etc.)    |
| Benchmark gate   | `make benchmark-ci`      | idle RSS / CPU / binary size / FIM burst hard thresholds |
| Fuzzing          | `cargo +nightly fuzz run` | Protocol, MessagePack, rule-store parsers                |

## 7. Further reading

- Roadmap and status: [`PROGRESS.md`](../PROGRESS.md)
- Original design rationale: [`device-agent-proposal.md`](../device-agent-proposal.md)
- YAML reference: [`configuration-reference.md`](./configuration-reference.md)
- Security audit + fuzzing: [`security-audit.md`](./security-audit.md)
- Platform matrix + manual tests: [`platform-testing.md`](./platform-testing.md)

## 8. Device Control (planned)

ShieldNet Device Control is the next major module family for SDA.
It is currently in **Phase 0 — Architecture, Legal, and Schema**
(documentation-only); no Device Control code exists on `main` yet.
Phase 0 ADR + license posture is recorded in
[`docs/device-control/ADR-001-functional-port.md`](./device-control/ADR-001-functional-port.md)
and the Phase 0 progress log lives in
[`docs/device-control/PROGRESS.md`](./device-control/PROGRESS.md).

The full architecture for Device Control lives in
[`docs/device-control/ARCHITECTURE.md`](./device-control/ARCHITECTURE.md).
This § 8 is intentionally a pointer — when Phase 1 code lands the
`§ 1 Crate map` table above will be expanded with the new crates;
until then, the planned crates are listed here only for context:

| Planned crate | Responsibility (planned — not yet on `main`) |
|---|---|
| `sda-device-control` | Signed-job dispatch, `JobRefused` plumbing, lifecycle for the Device Control surface. |
| `sda-query` | Declarative scheduled queries via osquery sidecar (Apache-2.0 osquery, integrated). |
| `sda-policy` | Boolean policy evaluator over `sda-query` results, posture, and inventory deltas. |
| `sda-posture` | Device posture snapshots (BitLocker / FileVault / LUKS, firewall, screen-lock, patch level). |
| `sda-software` | Approved package catalogue client + WinGet / `apt`-`dnf`-`zypper` / Munki-style local repo. |
| `sda-jit-admin` | Just-in-Time admin / root with watchdog + drift detection + idempotent revoke. |
| `sda-script-runner` | Signed, allow-listed, bounded script execution (not a generic shell). |
| `sda-app-control` | App control — Santa sidecar on macOS; clean-room WDAC + AppLocker on Windows; clean-room dm-verity-aware on Linux. |
| `sda-remote-support` | Operator-initiated, user-consented remote support (clean-room MeshCentral-style protocol). |
| `sda-agent-vitals` | Heartbeat + queue depth + watchdog faults. |
| `sda-management-compat` | Optional Phase 5 translation shim for Fleet-flavoured GitOps YAML. |

Engine policy (osquery, Santa, WinGet, Munki, MakeMeAdmin, SAP
Privileges, MeshCentral, Tactical RMM) is documented in
[`docs/device-control/ARCHITECTURE.md` § 9](./device-control/ARCHITECTURE.md#9-open-source-engine-policy);
per-engine licence posture is documented in
[`docs/security-audit.md` § Device Control License Audit](./security-audit.md#device-control-license-audit).
The capability mapping from Fleet concepts to SDA crates is in
[`docs/device-control/fleet-capability-mapping.md`](./device-control/fleet-capability-mapping.md).

> **No Device Control code exists on `main` yet.** Phase 1 code is
> gated on Phase 0 exit per
> [`docs/device-control/PHASES.md` § Phase 0](./device-control/PHASES.md#phase-0--architecture-legal-and-schema-2-weeks)
> exit criterion #4 ("No Phase 1 code may be merged before Phase 0
> exit").
