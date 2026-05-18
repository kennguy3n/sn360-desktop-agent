# ShieldNet EDR Parity — Phase Plan

> **Version:** 0.1 | **Date:** May 2026 | **Status:** Planning
> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)

This document defines the phased delivery plan for ShieldNet EDR
Parity. Progress is tracked in [`PROGRESS.md`](./PROGRESS.md); the
technical rationale lives in [`PROPOSAL.md`](./PROPOSAL.md); the
diagram-first architecture companion is
[`ARCHITECTURE.md`](./ARCHITECTURE.md).

> **Scope note:** Tasks marked ⚙️ are server-side and implemented in
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
> They are listed here for context and sequencing only and are **out
> of scope** for this repository, matching the convention used in
> [`docs/device-control/PHASES.md`](../device-control/PHASES.md) and
> [`docs/revised-phase-plan.md`](../revised-phase-plan.md).
>
> Status values follow the SDA convention: **Done**, **In Progress**,
> **Not Started**.

> **Phase identifier note:** EDR Parity uses **Phase E** identifiers
> (E0–E6) to avoid collision with the existing **Phase D**
> identifiers (D1–D4) for Device Control and the **Phase M**
> identifiers (M1–M4) for Desktop MDM. The three workstreams ship
> independently.

> **License posture:** all new PAL implementations under this slate
> are **clean-room**. No CrowdStrike Falcon, SentinelOne, or
> Defender ATP source code is referenced, vendored, or translated.
> The platform reference surfaces (Linux `cn_proc` / netlink /
> audit / eBPF, Windows ETW providers, macOS Endpoint Security
> framework) are vendor-documented public APIs only. Compliance is
> enforced via the existing `cargo deny check licenses` gate and the
> Phase E0 license-audit task (E0.5).

---

## Table of contents

1. [Risk register](#risk-register)
2. [Phase E0 — Architecture & schema](#phase-e0--architecture--schema-2-weeks)
3. [Phase E1 — Process telemetry](#phase-e1--process-telemetry-810-weeks-p0--ship-blocker)
4. [Phase E2 — LDE maturity + default-ON](#phase-e2--lde-maturity--default-on-46-weeks-p0--ship-blocker)
5. [Phase E3 — Network telemetry + host isolation](#phase-e3--network-telemetry--host-isolation-810-weeks-p1--core-edr-parity)
6. [Phase E4 — Memory scanning + fileless detection](#phase-e4--memory-scanning--fileless-detection-68-weeks-p2--differentiation)
7. [Phase E5 — Identity attack detection + DLP](#phase-e5--identity-attack-detection--dlp-68-weeks-p2--differentiation)
8. [Phase E6 — Kernel driver productisation](#phase-e6--kernel-driver-productisation-ongoing-p3--nice-to-have)

---

## Risk register

The risk register shapes scope and sequencing for every phase below.
[`PROPOSAL.md` § 6](./PROPOSAL.md#6-risk-register) is the
authoritative source; this section is the phase-planner's quick
reference.

| #  | Risk                                                           | Severity   | Mitigation                                                                                                                                        |
|----|----------------------------------------------------------------|------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  | Process telemetry blows idle-RSS budget                         | High       | Per-OS resource budget gate (`make benchmark-ci`) — process monitor must add < 5 MB RSS / < 0.5 % idle CPU. Module disabled by default until E2.  |
| 2  | ETW / Endpoint Security framework instability                   | High       | Provider sessions wrapped in supervised tasks with restart-with-backoff; tracked under `sda-agent-vitals` heartbeat.                              |
| 3  | Host isolation locks operator out of agent                      | Critical   | `allowed_ips` always includes SN360 control-plane CIDRs; loopback always allowed; isolation `SignedActionJob`s require a dedicated approver tier. |
| 4  | False-positive process-chain rules in default bundle            | High       | Default bundle ships only baseline, vendor-validated rules; operator-tunable false-positive feedback loop via TRDS.                              |
| 5  | Memory scanner triggers AV false-positives on the agent itself  | Medium     | Agent process pinned in scanner allow-list; YARA rules cleanly scoped to `pid != self_pid`.                                                       |
| 6  | macOS Endpoint Security entitlement gating                      | High       | Phase E1 ships with documented entitlement requirements; CI matrix runs on macOS 14 + 15 to catch entitlement regressions.                        |
| 7  | Clean-room compliance for new PAL implementations               | Critical   | License audit gate (existing `cargo deny check licenses`) extended in Phase E0 to flag any reference-engine source-code import.                  |
| 8  | DLP regex false-positives swamp operator                        | High       | DLP rules ship in monitor mode by default; enforce mode opt-in per tenant; pattern false-positive rate tracked in `sda-agent-vitals`.            |
| 9  | LDE default-ON flip surprises existing operators                | Medium     | Phase E2 ships a documented migration note; default bundle is conservative; operators can flip back via `LocalDetectionConfig.enabled = false`.   |
| 10 | TRDS hot-reload race with active rule evaluation                | High       | Atomic CAS swap of `DetectionPipeline` (mirrors `UsbPolicySupervisor::apply_bundle_slice` from Phase D2); per-event evaluations finish on old set. |
| 11 | Cross-platform telemetry shape drift                             | Medium     | `EventKind` variants are platform-agnostic; per-OS PAL implementations map to the same struct shape; CI matrix exercises all three.              |
| 12 | Kernel-mode deferral leaves tamper-protection gap                | High       | Phase E6 explicitly tracks the productisation path; interim mitigation is the existing tamper-protection from Phase 5.3 + `sda-agent-vitals`.    |

---

## Phase E0 — Architecture & schema (2 weeks)

**Goal:** lock the ADR, the wire schemas, and the clean-room license
posture before any Phase E1 code lands. This phase is intentionally
short and document-only, mirroring
[`docs/device-control/PHASES.md` Phase 0](../device-control/PHASES.md#phase-0--architecture-legal-and-schema-2-weeks).

### Deliverables

- ADR landed: user-mode telemetry-first, kernel deferred to Phase E6.
- Eight new `EventKind` variants signed off in
  [`crates/sda-event-bus/src/event.rs`](../../crates/sda-event-bus/src/event.rs):
  `ProcessCreated`, `ProcessTerminated`, `ImageLoaded`,
  `NetworkConnection`, `DnsQuery`, `MemoryScanAlert`,
  `HostIsolationStateChanged`, `IdentityAlert`.
- New `MessageType` variants + canonical encoder arms signed off in
  `sda-comms`, mirroring the
  [`docs/device-control/PROPOSAL.md` § 10.1](../device-control/PROPOSAL.md#101-new-messagetype-variants)
  pattern.
- New NATS subjects under the `edr.*` tree signed off with
  `sn360-security-platform` maintainers.
- Wire schema specs for `ProcessCreated`, `NetworkConnection`,
  `DnsQuery`, `MemoryScanAlert`, `HostIsolationStateChanged`,
  `IdentityAlert` landed under
  [`docs/edr-parity/ARCHITECTURE.md` § Wire schemas](./ARCHITECTURE.md).
- Phase E0 exit checklist recorded in
  [`PROGRESS.md`](./PROGRESS.md).
- License-audit extension: `cargo deny check licenses` gate updated
  to flag any reference-engine source-code import (CrowdStrike,
  SentinelOne, Defender) per
  [`PROPOSAL.md` § 4](./PROPOSAL.md#4-do-not-port--scope-boundaries).

### Tasks

| #     | Task                                                                                                                                                                                                                  | Description                                                                                                                                                                                                                                  | Status      |
|-------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------|
| E0.1  | ADR: user-mode telemetry-first, kernel deferred                                                                                                                                                                       | Lock the architectural decision that all Phase E1–E5 telemetry is user-mode (cn_proc / ETW / Endpoint Security framework); kernel-mode is deferred to Phase E6. ADR landed in [`PROPOSAL.md` § 1.3](./PROPOSAL.md#13-what-this-proposal-commits-to). | Done        |
| E0.2  | EventKind variant sign-off                                                                                                                                                                                            | Agree the eight new `EventKind` variants: `ProcessCreated`, `ProcessTerminated`, `ImageLoaded`, `NetworkConnection`, `DnsQuery`, `MemoryScanAlert`, `HostIsolationStateChanged`, `IdentityAlert`. Variants documented in [`PROPOSAL.md` § 3.2](./PROPOSAL.md#32-new-eventkind-variants). | Done        |
| E0.3  | MessageType + NATS subject sign-off                                                                                                                                                                                   | Agree the new `MessageType` variants and `edr.*` NATS subject hierarchy with `sn360-security-platform` maintainers; mirror the device-control pattern in [`docs/device-control/PROPOSAL.md` § 10](../device-control/PROPOSAL.md#10-native-protocol-extension). | Done        |
| E0.4  | Wire schema specs                                                                                                                                                                                                     | Land per-variant wire schemas (`ProcessCreated`, `NetworkConnection`, `DnsQuery`, `MemoryScanAlert`, `HostIsolationStateChanged`, `IdentityAlert`) in [`ARCHITECTURE.md` § 8](./ARCHITECTURE.md#8-wire-schema-overview); pin RFC 8785 canonical-JSON encoding. | Done        |
| E0.5  | Phase E0 exit checklist                                                                                                                                                                                               | Record exit criteria sign-off in [`PROGRESS.md`](./PROGRESS.md); extend the `cargo deny check licenses` gate to flag reference-engine source imports; clean-room license audit recorded in [`docs/security-audit.md`](../security-audit.md). | Done        |

### Exit criteria

1. [`PROPOSAL.md`](./PROPOSAL.md), [`PHASES.md`](./PHASES.md),
   [`PROGRESS.md`](./PROGRESS.md), and [`ARCHITECTURE.md`](./ARCHITECTURE.md)
   all merged to `main`.
2. Wire schema list (eight `EventKind` variants + matching
   `MessageType` variants + `edr.*` NATS subjects) agreed with
   [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)
   maintainers.
3. Clean-room license audit recorded in
   [`docs/security-audit.md`](../security-audit.md) — no
   CrowdStrike / SentinelOne / Defender source-code reference.
4. No Phase E1 code may be merged before Phase E0 exit.

---

## Phase E1 — Process telemetry (8–10 weeks) [P0 — Ship blocker]

**Goal:** light up process telemetry on all three platforms so the
LDE can match behavioural rules against process create / terminate /
image load events.

### Deliverables

- `sda-pal::ProcessMonitor` trait + per-OS implementations (Linux
  cn_proc, Windows ETW `Microsoft-Windows-Kernel-Process`, macOS
  Endpoint Security).
- `sda-process-monitor` crate scaffold with parent-chain enrichment.
- Three new `EventKind` variants — `ProcessCreated`,
  `ProcessTerminated`, `ImageLoaded` — produced by
  `sda-process-monitor` and consumed by `sda-comms`.
- LDE expansion: the `_ => return,` at
  [`crates/sda-local-detection/src/lib.rs` line 357](../../crates/sda-local-detection/src/lib.rs#L357)
  is replaced with explicit arms for `ProcessCreated`,
  `ProcessTerminated`, `ImageLoaded`.
- Process-chain behavioural rules in the LDE (parent-child anomaly
  detection — Word spawning PowerShell, `wmiprvse` spawning
  `rundll32`, etc.).
- Phase E1 E2E suite — `make e2e-process-telemetry`.
- ⚙️ TRDS process-rule bundle compilation in
  `sn360-security-platform/services/trds-api`.
- ⚙️ Agent Gateway NATS subjects for process telemetry under the
  `edr.*` tree.

### Tasks

| #      | Task                                                                                                                                                                                                                  | Description                                                                                                                                                                                                                                  | Status      |
|--------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------|
| E1.1   | `sda-pal::ProcessMonitor` trait + Linux `cn_proc` impl                                                                                                                                                                | Trait surface in `sda-pal::process_monitor`; Linux backend via `NETLINK_CONNECTOR` + `CN_IDX_PROC` netlink connector, with `/proc/<pid>/` enrichment for exe path / cmdline / cgroup / user.                                                | Done        |
| E1.2   | `sda-pal::ProcessMonitor` Windows ETW impl                                                                                                                                                                            | Windows backend via ETW `Microsoft-Windows-Kernel-Process` provider (`PROCESS_START`, `PROCESS_STOP`, `IMAGE_LOAD`) using the existing TraceLogging session in `sda-pal`.                                                                   | Done        |
| E1.3   | `sda-pal::ProcessMonitor` macOS Endpoint Security impl                                                                                                                                                                | macOS backend via Endpoint Security framework — `es_new_client()` subscribing to `ES_EVENT_TYPE_NOTIFY_EXEC`, `ES_EVENT_TYPE_NOTIFY_FORK`, `ES_EVENT_TYPE_NOTIFY_EXIT`, `ES_EVENT_TYPE_NOTIFY_MMAP`. Documents entitlement requirements.    | Done        |
| E1.4   | `sda-process-monitor` crate scaffold + parent-chain enrichment                                                                                                                                                        | New `crates/sda-process-monitor/` crate; subscribes to `sda-pal::ProcessMonitor`; reconstructs parent chain up to configured depth via per-OS lookup helpers; emits `EventKind::ProcessCreated` etc. on the bus.                            | Not Started |
| E1.5   | `EventKind::ProcessCreated` / `ProcessTerminated` / `ImageLoaded` variants                                                                                                                                            | Land variants in [`crates/sda-event-bus/src/event.rs`](../../crates/sda-event-bus/src/event.rs); add explicit encoder arms in `WazuhMessage::encode_body()` when `legacy-siem` feature is on; canonical-JSON envelope per Phase E0.4 schema. | Not Started |
| E1.6   | LDE expansion: process events consumed by `handle_event`                                                                                                                                                              | Replace the `_ => return,` at [`crates/sda-local-detection/src/lib.rs` line 357](../../crates/sda-local-detection/src/lib.rs#L357) with explicit arms that extract `(source_tag, entity, primary_text, fim_path, sha256, ips)` for the new variants. | Done        |
| E1.7   | Process-chain behavioural rules in LDE                                                                                                                                                                                | Extend the JSON DSL with an optional `parent_chain` predicate matching a regex against the joined parent-chain names; ship baseline rules for Word→PowerShell, wmiprvse→rundll32, lsass.exe-opened-by-non-system.                            | Done        |
| E1.8   | Phase E1 E2E suite (`make e2e-process-telemetry`)                                                                                                                                                                     | Hermetic suite in `crates/sda-agent/tests/e2e_process_telemetry.rs` — exec / fork / exit visibility on each OS; image-load visibility on each OS; parent-chain reconstruction; behavioural-rule firing on a Word→PowerShell synthetic event. | Done        |
| E1.9   | TRDS process-rule bundle compilation ⚙️                                                                                                                                                                              | `sn360-security-platform/services/trds-api` compiles process-rule bundles (behavioural-rule + IOC pairings) signed by the existing rotation-aware control-plane key.                                                                       | Not Started |
| E1.10  | Agent Gateway NATS subjects for process telemetry ⚙️                                                                                                                                                                 | `sn360-security-platform`: register `edr.process_created.<tenant_id>.<device_id>`, `edr.process_terminated.*`, `edr.image_loaded.*` under the existing Agent Gateway routing.                                                                | Not Started |

### Exit criteria

1. Agent reports full process tree with parent chain on Windows /
   macOS / Linux.
2. LDE can match behavioural rules against process creation events
   — at least one baseline rule fires in the hermetic E2E suite.
3. Idle RSS stays under the 20 MB budget with process monitor
   enabled (existing 15 MB + process monitor 5 MB budget).
4. `make e2e-process-telemetry` passes on all three platforms.
5. `cargo test --workspace` green; `cargo clippy --workspace -- -D warnings` clean.

---

## Phase E2 — LDE maturity + default-ON (4–6 weeks) [P0 — Ship blocker]

**Goal:** mature the Local Detection Engine from its current
placeholder hot-reload to a verified bundle-pull pipeline, then flip
the LDE default to enabled so fresh installs ship with baseline
detection on.

### Deliverables

- TRDS rule hot-reload implementation, replacing the placeholder at
  [`crates/sda-local-detection/src/lib.rs` lines 495–501](../../crates/sda-local-detection/src/lib.rs#L495-L501)
  with a verified bundle pull.
- Bundle signature verification for hot-reloaded rules (Ed25519
  against locally pinned rotation set; mirrors
  [`docs/device-control/PROPOSAL.md` § 10.3](../device-control/PROPOSAL.md#103-signed-job-validation-10-step-checklist)
  signed-job pattern).
- LDE default flip — `LocalDetectionConfig.enabled` flips from
  `false` to `true` at
  [`crates/sda-core/src/config.rs` line 983](../../crates/sda-core/src/config.rs#L983).
- Default rule bundle with baseline IOCs + behavioural rules.
- ⚙️ TRDS full rule CRUD + delta distribution in
  `sn360-security-platform` (extends existing `services/trds-api`).
- Phase E2 E2E suite — `make e2e-lde-hotreload`.

### Tasks

| #     | Task                                                                                                                                                                                                                  | Description                                                                                                                                                                                                                                  | Status      |
|-------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------|
| E2.1  | TRDS rule hot-reload in LDE                                                                                                                                                                                           | Replace the placeholder at [`crates/sda-local-detection/src/lib.rs` lines 495–501](../../crates/sda-local-detection/src/lib.rs#L495-L501) with a verified bundle pull against `services/trds-api`; atomic CAS swap of `DetectionPipeline`.   | Done        |
| E2.2  | Bundle signature verification for hot-reloaded rules                                                                                                                                                                  | Verify Ed25519 signature on the pulled bundle against the locally pinned rotation set; reject bundles whose `key_id` is not in the rotation set; emit a `Finding` of severity `High` on verification failure (mirrors Phase D2.7).         | Done        |
| E2.3  | Flip LDE default to `enabled = true`                                                                                                                                                                                  | Change [`crates/sda-core/src/config.rs` line 983](../../crates/sda-core/src/config.rs#L983) from `enabled: false,` to `enabled: true,`; update [`docs/configuration-reference.md`](../configuration-reference.md) and migration notes.       | Done        |
| E2.4  | Default rule bundle with baseline IOCs + behavioural rules                                                                                                                                                            | Ship a conservative default bundle covering known-bad IPs / domains from public threat-intel feeds, baseline behavioural rules (process-chain anomalies from E1.7), and a minimal YARA set for ransomware indicators.                       | Done        |
| E2.5  | TRDS full rule CRUD + delta distribution ⚙️                                                                                                                                                                          | Extend existing `services/trds-api` in `sn360-security-platform` with full rule CRUD (create / read / update / delete) and delta-only bundle distribution to minimise agent pull bandwidth.                                                | Not Started |
| E2.6  | Phase E2 E2E suite (`make e2e-lde-hotreload`)                                                                                                                                                                         | Hermetic suite in `crates/sda-agent/tests/e2e_lde_hotreload.rs` — push a new bundle to a fake TRDS endpoint, verify hot-reload within 30 s without restart, verify rejected-bundle path keeps last-known-good pipeline in force.            | Done        |

### Exit criteria

1. TRDS pushes a new rule bundle → agent hot-reloads within 30 s
   without restart.
2. LDE is ON by default in a fresh install; no operator configuration
   required for baseline detection.
3. Tampered / unsigned / mis-keyed bundles never replace the live
   `DetectionPipeline`; the agent keeps the last-known-good set and
   emits a `Finding` of severity `High`.
4. `make e2e-lde-hotreload` passes on all three platforms.
5. Existing benchmark gate (`make benchmark-ci`) shows no regression
   on idle RSS / idle CPU / FIM scan peak / binary size budgets.

---

## Phase E3 — Network telemetry + host isolation (8–10 weeks) [P1 — Core EDR parity]

**Goal:** light up network connection telemetry, DNS query
telemetry, and host isolation on all three platforms so the LDE can
match against connection metadata and the control plane can
quarantine a compromised host.

### Deliverables

- `sda-pal::NetworkMonitor` trait + per-OS implementations.
- `sda-network-monitor` crate scaffold.
- `EventKind::NetworkConnection` variant.
- `sda-pal::DnsMonitor` trait + per-OS implementations.
- `EventKind::DnsQuery` variant.
- `sda-pal::HostIsolation` trait + per-OS implementations.
- `sda-host-isolation` crate — `IsolateHost` / `UnisolateHost` via
  `SignedActionJob`.
- LDE expansion: network events consumed by `handle_event`.
- Network IOC matching in the LDE (domain + IP against connection
  telemetry).
- ⚙️ Agent Gateway NATS subjects for network / DNS telemetry.
- ⚙️ Dashboard host-isolation button.
- Phase E3 E2E suites — `make e2e-network-telemetry`,
  `make e2e-host-isolation`.

### Tasks

| #      | Task                                                                                                                                                                                                                  | Description                                                                                                                                                                                                                                  | Status      |
|--------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------|
| E3.1   | `sda-pal::NetworkMonitor` trait + Linux audit / netlink impl                                                                                                                                                          | Trait surface in `sda-pal::network_monitor`; Linux backend via `audit` subsystem (`AUDIT_SOCKADDR` / `AUDIT_CONNECT`) for connect-time signal, netlink `INET_DIAG` for established-connection enumeration, `/proc/net/*` for PID attribution. | Done        |
| E3.2   | `sda-pal::NetworkMonitor` Windows ETW impl                                                                                                                                                                            | Windows backend via ETW `Microsoft-Windows-Kernel-Network` provider (TCP connect / accept / disconnect; UDP send / receive) keyed on `ProcessId`.                                                                                           | Done        |
| E3.3   | `sda-pal::NetworkMonitor` macOS Network Extension impl                                                                                                                                                                | macOS backend via Network Extension framework — `NEFilterDataProvider` registered as a content filter for connection metadata. Documents entitlement requirements.                                                                          | Done        |
| E3.4   | `sda-network-monitor` crate scaffold                                                                                                                                                                                  | New `crates/sda-network-monitor/` crate; subscribes to `sda-pal::NetworkMonitor`; debounces duplicate events; emits `EventKind::NetworkConnection` on the bus.                                                                              | Done        |
| E3.5   | `EventKind::NetworkConnection` variant                                                                                                                                                                                | Land variant in [`crates/sda-event-bus/src/event.rs`](../../crates/sda-event-bus/src/event.rs); add encoder arm in `WazuhMessage::encode_body()` when `legacy-siem` feature is on; canonical-JSON envelope per Phase E0.4 schema.            | Done        |
| E3.6   | LDE expansion: network events consumed by `handle_event`                                                                                                                                                              | Add an explicit arm for `EventKind::NetworkConnection` to the `match &event.kind` block at [`crates/sda-local-detection/src/lib.rs` lines 314–358](../../crates/sda-local-detection/src/lib.rs#L314-L358) so connection IPs feed into the IOC bloom. | Done        |
| E3.7   | Network IOC matching in LDE                                                                                                                                                                                           | Wire `NetworkConnection.remote_addr` into the existing `pipeline.iocs.match_ip` backend; wire `DnsQuery.query_name` into the existing string-IOC backend so a TRDS domain bundle matches DNS queries without new rule-engine code.           | Done        |
| E3.8   | `sda-pal::DnsMonitor` trait + per-OS impls                                                                                                                                                                            | Trait surface in `sda-pal::dns_monitor`; Linux backend taps `/var/log/syslog` or `journalctl -u systemd-resolved`; Windows backend uses ETW `Microsoft-Windows-DNS-Client`; macOS backend uses `NEDNSProxyProvider`.                        | Done        |
| E3.9   | `EventKind::DnsQuery` variant                                                                                                                                                                                         | Land variant in [`crates/sda-event-bus/src/event.rs`](../../crates/sda-event-bus/src/event.rs); add encoder arm; canonical-JSON envelope per Phase E0.4 schema.                                                                              | Done        |
| E3.10  | `sda-pal::HostIsolation` trait + per-OS impls                                                                                                                                                                         | Trait surface in `sda-pal::host_isolation`; Linux backend via `nftables` in a dedicated `sn360_isolation` table; Windows backend via `netsh advfirewall` + WFP COM; macOS backend via `pfctl` anchor.                                       | Done        |
| E3.11  | `sda-host-isolation` crate — `IsolateHost` / `UnisolateHost` via `SignedActionJob`                                                                                                                                    | New `crates/sda-host-isolation/` crate; consumes `IsolateHost` / `UnisolateHost` `SignedActionJob` types dispatched via the existing Phase D / Phase M signed-job pipeline; emits `EventKind::HostIsolationStateChanged`.                    | Not Started |
| E3.12  | Phase E3 E2E suite (`make e2e-network-telemetry`, `make e2e-host-isolation`)                                                                                                                                          | Hermetic suites in `crates/sda-agent/tests/e2e_network_telemetry.rs` and `crates/sda-agent/tests/e2e_host_isolation.rs` — outbound TCP visibility, DNS query visibility, isolation blocks all non-allowed traffic within 5 s of dispatch.    | Not Started |
| E3.13  | Agent Gateway NATS subjects for network / DNS telemetry ⚙️                                                                                                                                                            | `sn360-security-platform`: register `edr.network_connection.*`, `edr.dns_query.*`, `edr.host_isolation_state_changed.*` under the existing Agent Gateway routing.                                                                            | Not Started |
| E3.14  | Dashboard host-isolation button ⚙️                                                                                                                                                                                    | `sn360-security-platform/sn360-dashboard-plugin/public/pages/Hosts/` — per-device isolation toggle that dispatches `IsolateHost` / `UnisolateHost` `SignedActionJob` through the Action Orchestrator with the dedicated approver tier.       | Not Started |

### Exit criteria

1. Agent reports outbound TCP connections with process attribution
   on Windows / macOS / Linux.
2. DNS queries are logged with process context on all three
   platforms.
3. Host isolation blocks all traffic except SN360 control-plane IPs
   within 5 s of action dispatch.
4. `make e2e-network-telemetry` and `make e2e-host-isolation` pass
   on all three platforms.
5. Idle RSS stays under the combined 25 MB budget with process +
   network monitor enabled (existing 15 MB + 5 MB process + 3 MB
   network + 2 MB DNS budget).

---

## Phase E4 — Memory scanning + fileless detection (6–8 weeks) [P2 — Differentiation]

**Goal:** detect fileless payloads — RWX memory regions in running
processes, in-memory YARA matches, AMSI script content on Windows.

### Deliverables

- `sda-pal::MemoryScanner` trait + per-OS implementations.
- `sda-memory-scanner` crate — periodic RWX-region scanner.
- In-memory YARA scanning by extending the existing
  `sda-local-detection` YARA scanner to operate on process memory
  regions.
- `EventKind::MemoryScanAlert` variant.
- Optional Windows AMSI integration (behind a Cargo feature flag).
- Phase E4 E2E suite — `make e2e-memory-scan`.

### Tasks

| #     | Task                                                                                                                                                                                                                  | Description                                                                                                                                                                                                                                  | Status      |
|-------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------|
| E4.1  | `sda-pal::MemoryScanner` trait + Linux `/proc/<pid>/maps` impl                                                                                                                                                        | Trait surface in `sda-pal::memory_scanner`; Linux backend parses `/proc/<pid>/maps` for region enumeration (filter RWX, anonymous, JIT-style), reads via `/proc/<pid>/mem` with seek + bounded read.                                        | Not Started |
| E4.2  | `sda-pal::MemoryScanner` Windows `VirtualQueryEx` impl                                                                                                                                                                | Windows backend via `VirtualQueryEx` over `PROCESS_QUERY_INFORMATION` + `PROCESS_VM_READ` handles; `ReadProcessMemory` for RWX page reads.                                                                                                  | Not Started |
| E4.3  | `sda-pal::MemoryScanner` macOS `mach_vm_region` impl                                                                                                                                                                  | macOS backend via `task_for_pid` (entitlement-gated) → `mach_vm_region` for enumeration; `mach_vm_read_overwrite` for region reads.                                                                                                          | Not Started |
| E4.4  | `sda-memory-scanner` crate — periodic RWX region scanner                                                                                                                                                              | New `crates/sda-memory-scanner/` crate; periodic scan loop respecting CPU budget; filters self-pid; emits `EventKind::MemoryScanAlert` on RWX-region detection in non-allow-listed processes.                                              | Not Started |
| E4.5  | In-memory YARA scanning                                                                                                                                                                                               | Extend the existing YARA scanner in [`crates/sda-local-detection/src/`](../../crates/sda-local-detection/src/) to accept a byte slice rather than a file path; scan flagged memory regions; emit `EventKind::MemoryScanAlert` on hits.       | Not Started |
| E4.6  | `EventKind::MemoryScanAlert` variant                                                                                                                                                                                  | Land variant in [`crates/sda-event-bus/src/event.rs`](../../crates/sda-event-bus/src/event.rs); add encoder arm; canonical-JSON envelope per Phase E0.4 schema.                                                                              | Not Started |
| E4.7  | Windows AMSI integration (optional, feature-gated)                                                                                                                                                                    | Optional feature `amsi` — register an AMSI provider via `IAmsiStream` so PowerShell / VBScript content scanned by AMSI is also visible to the LDE. Off by default; documents AMSI dependency.                                              | Not Started |
| E4.8  | Phase E4 E2E suite (`make e2e-memory-scan`)                                                                                                                                                                           | Hermetic suite in `crates/sda-agent/tests/e2e_memory_scan.rs` — synthetic RWX region in a fixture process, YARA rule against fixed string, fileless PowerShell payload trigger on Windows.                                                  | Not Started |

### Exit criteria

1. Agent detects RWX memory regions in running processes on all
   three platforms.
2. YARA rules can match in-memory patterns; in-memory match path
   reuses the existing rule store with no new rule format.
3. Fileless PowerShell payload (e.g. `[Reflection.Assembly]::Load(
   $bytes)`) triggers detection on Windows via the AMSI feature
   when enabled.
4. `make e2e-memory-scan` passes on all three platforms.
5. Memory scanner CPU stays under 1 % during scan windows; idle CPU
   under 0.1 % between scans.

---

## Phase E5 — Identity attack detection + DLP (6–8 weeks) [P2 — Differentiation]

**Goal:** detect credential-theft signal (LSASS access on Windows,
shadow / kcore access on Linux, keychain access on macOS) and add
DLP content inspection on file writes + clipboard + outbound data
buffers.

### Deliverables

- `sda-identity-monitor` crate — credential-theft detection.
- `EventKind::IdentityAlert` variant.
- `sda-dlp` crate scaffold — regex-based PII / PCI scanner.
- DLP file-write content inspection.
- Optional DLP clipboard monitoring.
- Phase E5 E2E suites — `make e2e-identity`, `make e2e-dlp`.

### Tasks

| #     | Task                                                                                                                                                                                                                  | Description                                                                                                                                                                                                                                  | Status      |
|-------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------|
| E5.1  | `sda-identity-monitor` crate — Windows LSASS access monitoring                                                                                                                                                        | New `crates/sda-identity-monitor/` crate; Windows backend uses ETW `Microsoft-Windows-Threat-Intelligence` (sensitive-handle creation) or `NtOpenProcess` instrumentation on lsass.exe PID; emits `EventKind::IdentityAlert` for non-system access. | Not Started |
| E5.2  | Linux `/etc/shadow` + `/proc/kcore` access detection                                                                                                                                                                  | Reuse the existing FIM and audit primitives — subscribe to `EventKind::FileMetadataChanged` on `/etc/shadow` and audit-rule on `/proc/kcore`; emit `EventKind::IdentityAlert` for non-system reads.                                          | Not Started |
| E5.3  | macOS keychain access detection                                                                                                                                                                                       | macOS backend uses Endpoint Security framework — `ES_EVENT_TYPE_NOTIFY_OPEN` on `/Library/Keychains/*` and `~/Library/Keychains/*` paths; emit `EventKind::IdentityAlert` for non-Apple-signed binaries.                                    | Not Started |
| E5.4  | `EventKind::IdentityAlert` variant                                                                                                                                                                                    | Land variant in [`crates/sda-event-bus/src/event.rs`](../../crates/sda-event-bus/src/event.rs); add encoder arm; canonical-JSON envelope per Phase E0.4 schema. MITRE ATT&CK technique ID in payload.                                       | Not Started |
| E5.5  | `sda-dlp` crate scaffold — regex-based PII / PCI scanner                                                                                                                                                              | New `crates/sda-dlp/` crate; ships baseline regex set for PII (SSN, NI numbers) and PCI (PAN with Luhn check); pluggable rule format reusing the LDE bundle pipeline.                                                                       | Not Started |
| E5.6  | DLP file-write content inspection                                                                                                                                                                                     | Subscribe to `EventKind::FileCreated` and `EventKind::FileModified`; on match, read the written bytes and scan against the DLP regex set; emit a DLP `Finding` with the matched pattern category but never the actual content.              | Not Started |
| E5.7  | DLP clipboard monitoring (optional, feature-gated)                                                                                                                                                                    | Optional feature `dlp-clipboard` — Linux X11 / Wayland clipboard tap, Windows clipboard chain hook, macOS NSPasteboard observer; off by default; emits a DLP `Finding` on match.                                                          | Not Started |
| E5.8  | Phase E5 E2E suite (`make e2e-identity`, `make e2e-dlp`)                                                                                                                                                              | Hermetic suites in `crates/sda-agent/tests/e2e_identity.rs` and `crates/sda-agent/tests/e2e_dlp.rs` — LSASS-access trigger on Windows synthetic, shadow-read trigger on Linux, keychain-access trigger on macOS, PII-pattern in file write.  | Not Started |

### Exit criteria

1. LSASS access by a non-system process triggers an
   `EventKind::IdentityAlert` on Windows.
2. `/etc/shadow` or `/proc/kcore` access by a non-system process
   triggers an `EventKind::IdentityAlert` on Linux.
3. Keychain access by a non-Apple-signed binary triggers an
   `EventKind::IdentityAlert` on macOS.
4. PII patterns in written files trigger a DLP `Finding` without
   leaking the matched content to the bus or to the control plane.
5. `make e2e-identity` and `make e2e-dlp` pass on all three
   platforms.
6. Idle RSS stays under the combined 28 MB budget with process +
   network + identity + DLP monitors enabled.

---

## Phase E6 — Kernel driver productisation (ongoing) [P3 — Nice to have]

**Goal:** lift the Phase E1–E3 user-mode telemetry to kernel-mode
where the platform supports it, providing tamper-resistance and
deeper visibility. This phase mirrors the deferred-path pattern in
[`docs/device-control/PRODUCTISATION-WINDOWS.md`](../device-control/PRODUCTISATION-WINDOWS.md)
and
[`docs/device-control/PRODUCTISATION-MACOS.md`](../device-control/PRODUCTISATION-MACOS.md).

### Deliverables

- Windows WDK minifilter driver for process / network callbacks +
  WHQL signing pipeline.
- macOS SystemExtension for Endpoint Security (production-signed
  with Apple Developer ID + entitlements).
- Linux eBPF programs for process / network as a kernel-resident
  alternative to cn_proc / audit.

### Tasks

| #     | Task                                                                                                                                                                                                                  | Description                                                                                                                                                                                                                                  | Status      |
|-------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------|
| E6.1  | Windows WDK minifilter driver for process / network callbacks                                                                                                                                                         | Productise the Phase E1 / Phase E3 telemetry as a WDK minifilter driver using `PsSetCreateProcessNotifyRoutineEx` for process callbacks and WFP callouts for network callbacks. Roadmap mirrors [`PRODUCTISATION-WINDOWS.md`](../device-control/PRODUCTISATION-WINDOWS.md). | Not Started |
| E6.2  | WHQL signing pipeline                                                                                                                                                                                                 | Submit the WDK driver through Windows Hardware Compatibility Program; pipeline mirrors the existing WHCP pipeline scoped for Phase D2.3-driver in [`PRODUCTISATION-WINDOWS.md`](../device-control/PRODUCTISATION-WINDOWS.md).                | Not Started |
| E6.3  | macOS SystemExtension for Endpoint Security (production signed)                                                                                                                                                       | Productise the Phase E1 Endpoint Security client as a signed SystemExtension with Apple Developer ID + entitlements; notarisation; MDM payload. Roadmap mirrors [`PRODUCTISATION-MACOS.md`](../device-control/PRODUCTISATION-MACOS.md).      | Not Started |
| E6.4  | Linux eBPF programs for process / network                                                                                                                                                                             | Productise the Phase E1 / Phase E3 telemetry as eBPF programs (kprobes on `sys_execve`, `tcp_v4_connect`, `udp_sendmsg`) using Aya; runs alongside or in place of cn_proc / audit depending on kernel version.                              | Not Started |

### Exit criteria

1. Kernel-mode telemetry on all three platforms — WHQL-signed
   Windows driver, signed macOS SystemExtension, production-grade
   Linux eBPF programs.
2. Tamper-protection coverage extended to kernel-mode — user-mode
   processes can no longer disable the telemetry source.
3. CI matrix exercises the kernel-mode path on every supported OS
   version.

---

## Cross-references

- [`PROPOSAL.md`](./PROPOSAL.md) — full technical proposal (motivation, scope, architecture).
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — diagram-first architecture companion.
- [`PROGRESS.md`](./PROGRESS.md) — live progress tracker.
- [`docs/device-control/PHASES.md`](../device-control/PHASES.md) — sibling Device Control phase plan (Phase D identifiers).
- [`docs/desktop-mdm/PROGRESS.md`](../desktop-mdm/PROGRESS.md) — sibling Desktop MDM progress tracker (Phase M identifiers).
- [`docs/revised-phase-plan.md`](../revised-phase-plan.md) — workspace phase plan; EDR Parity slots in as Phase 10.
- Control-plane companion: [`sn360-security-platform/docs/edr-parity/`](https://github.com/kennguy3n/sn360-security-platform/tree/main/docs/edr-parity) (to be created in lockstep).
