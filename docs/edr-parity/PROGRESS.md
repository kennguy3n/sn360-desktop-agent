# ShieldNet EDR Parity — Development Progress

> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)

Tracks the implementation status of ShieldNet EDR Parity against the
roadmap in [PHASES.md](./PHASES.md).

Status legend:

- **Done** — merged to `main` and covered by tests / benchmarks below.
- **In Progress** — branch exists, code is being written / reviewed.
- **Not Started** — no implementation work started yet.

> **Scope note:** Tasks marked ⚙️ are server-side and implemented in
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
> They are listed here for cross-reference only.

> **Phase identifier note:** EDR Parity uses **Phase E** identifiers
> (E0–E6) to avoid collision with the existing **Phase D**
> identifiers (D1–D4) for Device Control and the **Phase M**
> identifiers (M1–M4) for Desktop MDM.

## Current Status

EDR Parity is **shipped through Phase E3 (agent-side)**. The
technical proposal lives in [`PROPOSAL.md`](./PROPOSAL.md); the
phased delivery plan lives in [`PHASES.md`](./PHASES.md); the
diagram-first architecture companion lives in
[`ARCHITECTURE.md`](./ARCHITECTURE.md).

**Implementation status (2026-05-17):** Phase E0 (architecture &
schema sign-off) is **Done**. Phase E1 (process telemetry), Phase
E2 (LDE maturity + default-ON), and Phase E3 (network telemetry +
host isolation) are **Done on the agent side** — every agent-side
task in their tables ships in this PR. The server-side ⚙️ tasks
(E1.9, E1.10, E2.5, E3.13, E3.14) remain **Not Started** and are
tracked separately under
[`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
Phases E4–E6 (memory scanning, identity / DLP, kernel
productisation) remain **Not Started**.

The proposal closes the four EDR-parity gaps SDA has against
CrowdStrike Falcon, SentinelOne Singularity, and Defender for
Endpoint:

1. **Process telemetry** — the LDE today only sees FIM and
   logcollector events; every other `EventKind` variant hits the
   `_ => return,` arm at
   [`crates/sda-local-detection/src/lib.rs` line 357](../../crates/sda-local-detection/src/lib.rs#L357).
   Phase E1 adds process create / terminate / image-load telemetry
   on Windows / macOS / Linux and wires it into the LDE.
2. **Network telemetry + host isolation** — Phase E3 adds outbound
   connection telemetry with process attribution, DNS query
   telemetry, and host isolation via per-OS firewall primitives.
3. **In-memory / fileless signal** — Phase E4 adds RWX-region
   scanning + in-memory YARA + optional AMSI integration.
4. **Identity attack + DLP** — Phase E5 adds LSASS / shadow /
   keychain access detection plus regex-based PII / PCI content
   inspection on file writes, clipboard, and outbound buffers.

The plan **explicitly defers** kernel-mode drivers to Phase E6,
mirroring the deferred-path productisation pattern already
documented under
[`docs/device-control/PRODUCTISATION-WINDOWS.md`](../device-control/PRODUCTISATION-WINDOWS.md)
and
[`docs/device-control/PRODUCTISATION-MACOS.md`](../device-control/PRODUCTISATION-MACOS.md).

The existing SDA test surface — **433 unit tests, 14/14 base E2E,
10/10 security E2E** — remains green and must continue to pass as
EDR Parity crates are added.

---

## Phase summary

| Phase | Theme                                              | Priority             | Duration   | Status                                            |
|-------|----------------------------------------------------|----------------------|------------|---------------------------------------------------|
| E0    | Architecture & schema sign-off                     | P0 (gate)            | 2 weeks    | **Done**                                          |
| E1    | Process telemetry (all platforms)                  | P0 — ship blocker    | 8–10 weeks | **Done** (agent-side) · ⚙️ ~80% (E1.9, E1.10 remain) |
| E2    | LDE maturity + default-ON                          | P0 — ship blocker    | 4–6 weeks  | **Done** (agent-side) · ⚙️ ~83% (E2.5 remains)       |
| E3    | Network telemetry + host isolation                 | P1 — core EDR parity | 8–10 weeks | **Done** (agent-side) · ⚙️ ~86% (E3.13, E3.14 remain) |
| E4    | Memory scanning + fileless detection               | P2 — differentiation | 6–8 weeks  | Not Started                                       |
| E5    | Identity attack detection + DLP                    | P2 — differentiation | 6–8 weeks  | Not Started                                       |
| E6    | Kernel driver productisation                       | P3 — nice to have    | ongoing    | Not Started                                       |

---

## Phase E0 — Architecture & Schema (2 weeks)

| #    | Task                                                                  | Status |
|------|-----------------------------------------------------------------------|--------|
| E0.1 | ADR: user-mode telemetry-first, kernel deferred                       | Done   |
| E0.2 | EventKind variant sign-off (8 new variants)                           | Done   |
| E0.3 | MessageType + NATS subject sign-off for new telemetry                 | Done   |
| E0.4 | Wire schema specs (ProcessCreated, NetworkConnection, DnsQuery, MemoryScanAlert, HostIsolationStateChanged, IdentityAlert) | Done   |
| E0.5 | Phase E0 exit checklist + clean-room license audit                    | Done   |

---

## Phase E1 — Process Telemetry (8–10 weeks) [P0 — Ship blocker]

| #     | Task                                                                                      | Status      |
|-------|-------------------------------------------------------------------------------------------|-------------|
| E1.1  | `sda-pal::ProcessMonitor` trait + Linux `cn_proc` impl                                    | Done        |
| E1.2  | `sda-pal::ProcessMonitor` Windows ETW impl                                                | Done        |
| E1.3  | `sda-pal::ProcessMonitor` macOS Endpoint Security impl                                    | Done        |
| E1.4  | `sda-process-monitor` crate scaffold + parent-chain enrichment                            | Done        |
| E1.5  | `EventKind::ProcessCreated` / `ProcessTerminated` / `ImageLoaded` variants                | Done        |
| E1.6  | LDE expansion: process events consumed by `handle_event` (replaces `_ => return,` at lib.rs:357) | Done        |
| E1.7  | Process-chain behavioural rules in LDE (parent-child anomaly detection)                   | Done        |
| E1.8  | Phase E1 E2E suite (`make e2e-process-telemetry`)                                         | Done        |
| E1.9  | TRDS process-rule bundle compilation ⚙️                                                   | Not Started |
| E1.10 | Agent Gateway NATS subjects for process telemetry ⚙️                                      | Not Started |

---

## Phase E2 — LDE Maturity + Default-ON (4–6 weeks) [P0 — Ship blocker]

| #    | Task                                                                                      | Status      |
|------|-------------------------------------------------------------------------------------------|-------------|
| E2.1 | Implement TRDS rule hot-reload in LDE (replaces placeholder at lib.rs:495–501)            | Done        |
| E2.2 | Bundle signature verification for hot-reloaded rules                                      | Done        |
| E2.3 | Flip `LocalDetectionConfig.enabled` default to `true` (config.rs:983)                     | Done        |
| E2.4 | Ship a default rule bundle with baseline IOCs + behavioural rules                         | Done        |
| E2.5 | TRDS full rule CRUD + delta distribution ⚙️                                               | Not Started |
| E2.6 | Phase E2 E2E suite (`make e2e-lde-hotreload`)                                             | Done        |

---

## Phase E3 — Network Telemetry + Host Isolation (8–10 weeks) [P1 — Core EDR parity]

| #     | Task                                                                                      | Status      |
|-------|-------------------------------------------------------------------------------------------|-------------|
| E3.1  | `sda-pal::NetworkMonitor` trait + Linux audit / netlink impl                              | Done        |
| E3.2  | `sda-pal::NetworkMonitor` Windows ETW impl                                                | Done        |
| E3.3  | `sda-pal::NetworkMonitor` macOS Network Extension impl                                    | Done        |
| E3.4  | `sda-network-monitor` crate scaffold                                                      | Done        |
| E3.5  | `EventKind::NetworkConnection` variant                                                    | Done        |
| E3.6  | LDE expansion: network events consumed by `handle_event`                                  | Done        |
| E3.7  | Network IOC matching in LDE (domain + IP against connection telemetry)                    | Done        |
| E3.8  | `sda-pal::DnsMonitor` trait + per-OS impls                                                | Done        |
| E3.9  | `EventKind::DnsQuery` variant                                                             | Done        |
| E3.10 | `sda-pal::HostIsolation` trait + per-OS impls (nftables / pfctl / Windows Firewall)       | Done        |
| E3.11 | `sda-host-isolation` crate — `IsolateHost` / `UnisolateHost` via `SignedActionJob`        | Done        |
| E3.12 | Phase E3 E2E suite (`make e2e-network-telemetry`, `make e2e-host-isolation`)              | Done        |
| E3.13 | Agent Gateway NATS subjects for network / DNS telemetry ⚙️                                | Not Started |
| E3.14 | Dashboard host-isolation button ⚙️                                                        | Not Started |

---

## Phase E4 — Memory Scanning + Fileless Detection (6–8 weeks) [P2 — Differentiation]

| #    | Task                                                                                      | Status      |
|------|-------------------------------------------------------------------------------------------|-------------|
| E4.1 | `sda-pal::MemoryScanner` trait + Linux `/proc/<pid>/maps` impl                            | Not Started |
| E4.2 | `sda-pal::MemoryScanner` Windows `VirtualQueryEx` impl                                    | Not Started |
| E4.3 | `sda-pal::MemoryScanner` macOS `mach_vm_region` impl                                      | Not Started |
| E4.4 | `sda-memory-scanner` crate — periodic RWX-region scanner                                  | Not Started |
| E4.5 | In-memory YARA scanning (extend `sda-local-detection` YARA scanner)                       | Not Started |
| E4.6 | `EventKind::MemoryScanAlert` variant                                                      | Not Started |
| E4.7 | Windows AMSI integration (optional, feature-gated)                                        | Not Started |
| E4.8 | Phase E4 E2E suite (`make e2e-memory-scan`)                                               | Not Started |

---

## Phase E5 — Identity Attack Detection + DLP (6–8 weeks) [P2 — Differentiation]

| #    | Task                                                                                      | Status      |
|------|-------------------------------------------------------------------------------------------|-------------|
| E5.1 | `sda-identity-monitor` crate — Windows LSASS access monitoring                            | Not Started |
| E5.2 | Linux `/etc/shadow` + `/proc/kcore` access detection                                      | Not Started |
| E5.3 | macOS keychain access detection via Endpoint Security                                     | Not Started |
| E5.4 | `EventKind::IdentityAlert` variant                                                        | Not Started |
| E5.5 | `sda-dlp` crate scaffold — regex-based PII / PCI scanner                                  | Not Started |
| E5.6 | DLP file-write content inspection                                                         | Not Started |
| E5.7 | DLP clipboard monitoring (optional, feature-gated)                                        | Not Started |
| E5.8 | Phase E5 E2E suite (`make e2e-identity`, `make e2e-dlp`)                                  | Not Started |

---

## Phase E6 — Kernel Driver Productisation (ongoing) [P3 — Nice to have]

| #    | Task                                                                                      | Status      |
|------|-------------------------------------------------------------------------------------------|-------------|
| E6.1 | Windows WDK minifilter driver for process / network callbacks                             | Not Started |
| E6.2 | WHQL signing pipeline                                                                     | Not Started |
| E6.3 | macOS SystemExtension for Endpoint Security (production signed)                           | Not Started |
| E6.4 | Linux eBPF programs for process / network (alternative to cn_proc / audit)                | Not Started |

---

## Tests & Benchmarks

EDR Parity adds the following test surfaces. Live counts as of the
Phase E3 landing (2026-05-17) are recorded in **bold** alongside
the targets.

- **Process telemetry E2E** — `make e2e-process-telemetry`
  (target: ≥ 12 · **live: 13 tests passing**) covering exec / fork /
  exit / image-load, parent-chain reconstruction, deduplication,
  back-pressure / drop accounting, and synthetic behavioural-rule
  firings (Office→PowerShell, wmiprvse→rundll32, non-system
  lsass.exe access).
- **LDE hot-reload E2E** — `make e2e-lde-hotreload` (target: ≥ 6 ·
  **live: 10 tests passing**) covering happy-path hot-reload,
  signature failure → LKG preservation, unknown-key rejection,
  version-substitution rejection, atomic swap of a second valid
  bundle, default-bundle fallback, no-newer-bundle no-op, and stale
  envelope rejection.
- **Network telemetry E2E** — `make e2e-network-telemetry`
  (target: ≥ 9 · **live: 11 tests passing**) covering TCP connect
  attribution, DNS query attribution, dedup ring, UDP per-second
  sampler bound, LDE IP IOC + string IOC firings, benign-traffic
  false-positive bound, and wire-shape serde round-trips.
- **DNS telemetry E2E** — covered by `make e2e-network-telemetry`.
- **Host isolation E2E** — `make e2e-host-isolation` (target: ≥ 6 ·
  **live: 7 tests passing**) covering signed `IsolateHost` /
  `UnisolateHost` happy paths, control-plane CIDR + loopback safety
  invariants, idempotent dedup, unsigned-job rejection by the router
  validator, disabled-config short-circuit, and wire-shape serde
  round-trip.
- **Unit tests** — the EDR Parity crates add 130 PAL unit tests
  (`sda-pal`) + 18 process-monitor unit tests + 17 network-monitor
  unit tests + 13 host-isolation unit tests, all running on every
  `make test-unit` invocation.
- **Memory scan E2E** — `make e2e-memory-scan` (target: ≥ 6 tests
  for synthetic RWX region detection + in-memory YARA match on each
  platform).
- **Identity attack E2E** — `make e2e-identity` (target: ≥ 6 tests
  for LSASS access on Windows synthetic, shadow / kcore read on
  Linux, keychain access on macOS).
- **DLP E2E** — `make e2e-dlp` (target: ≥ 6 tests for PII / PCI
  pattern match on file writes + clipboard + redaction-on-emit).

Resource budgets (testable via the existing `make benchmark-ci`
gate, which already gates idle RSS / idle CPU / FIM scan peak /
binary size — the EDR Parity slate extends the gate with
per-monitor budgets):

| Metric                                                            | Budget         | Notes                                                                   |
|-------------------------------------------------------------------|----------------|--------------------------------------------------------------------------|
| Idle RSS with process + network monitor enabled                   | **< 25 MB**    | Existing 15 MB SDA budget + 5 MB process + 3 MB network + 2 MB DNS.      |
| Idle RSS with full EDR slate enabled (process + network + DNS + memory + identity + DLP) | **< 32 MB**    | 15 MB SDA + 5 MB process + 3 MB network + 2 MB DNS + 4 MB memory + 1 MB identity + 3 MB DLP.       |
| Idle CPU with process + network monitor enabled                   | **< 1 %**      | Existing 0.1 % SDA budget + 0.5 % process + 0.3 % network + 0.2 % DNS.   |
| Idle CPU with full EDR slate enabled                              | **< 2 %**      | Adds 1 % memory scanner during scan windows + 0.5 % DLP during inspect. |
| Memory scanner CPU during scan window                             | **< 1 %**      | Scanner allotted a periodic scan window; outside windows CPU is ~0 %.   |
| DLP file-write content scan CPU                                   | **< 0.5 %**    | Pattern matching is regex-based; bounded by FIM event volume.            |
| Binary size with full EDR slate compiled in                       | **< 10 MB**    | Existing 7 MB SDA budget + 3 MB headroom for the seven new crates.       |
| LDE hot-reload latency                                            | **< 30 s**     | TRDS push → live `DetectionPipeline` swap, end-to-end.                   |
| Host isolation activation latency                                  | **< 5 s**      | `SignedActionJob` receipt → all non-allowed traffic blocked.             |

Existing SDA budgets — idle RSS < 15 MB, idle CPU < 0.1 %, FIM scan
peak < 3 %, binary < 7 MB **with EDR modules disabled** — must remain
green; the benchmark gate (`make benchmark-ci`) covers regression.

---

## Known Risks

The full risk register lives in
[PHASES.md § Risk register](./PHASES.md#risk-register) (and
canonically in [PROPOSAL.md § 6](./PROPOSAL.md#6-risk-register)). Top
six highest-severity risks for delivery planning:

| # | Risk                                                  | Severity   | Mitigation summary                                                                                                                                |
|---|-------------------------------------------------------|------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | Process telemetry blows idle-RSS budget                | High       | Per-OS resource budget gate (`make benchmark-ci`); process monitor opt-in until Phase E2 default-ON. Budget < 5 MB RSS / < 0.5 % idle CPU.       |
| 2 | Host isolation locks operator out of agent             | Critical   | `allowed_ips` always includes SN360 control-plane CIDRs; loopback always allowed; isolation `SignedActionJob`s require a dedicated approver tier. |
| 3 | Clean-room compliance for new PAL implementations      | Critical   | License audit gate (existing `cargo deny check licenses`) extended in Phase E0 to flag any reference-engine source-code import.                  |
| 4 | False-positive process-chain rules in default bundle   | High       | Default bundle ships only baseline, vendor-validated rules; operator-tunable false-positive feedback loop via TRDS.                              |
| 5 | macOS Endpoint Security entitlement gating             | High       | Phase E1 ships with documented entitlement requirements; CI matrix runs on macOS 14 + 15 to catch entitlement regressions.                        |
| 6 | TRDS hot-reload race with active rule evaluation       | High       | Atomic CAS swap of `DetectionPipeline` (mirrors `UsbPolicySupervisor::apply_bundle_slice` from Phase D2); per-event evaluations finish on old set. |

---

## Known Gaps

No phase has started. Every gap below is a planning-stage gap; the
phase-level plan in [`PHASES.md`](./PHASES.md) closes each one in
the indicated phase.

1. **No process / network / DNS / memory / identity / DLP telemetry
   on the bus today.** The LDE pipeline is healthy, but
   [`crates/sda-local-detection/src/lib.rs` line 357](../../crates/sda-local-detection/src/lib.rs#L357)
   falls through (`_ => return,`) for every event that isn't FIM or
   logcollector. Closed by Phase E1 (process), Phase E3 (network /
   DNS), Phase E4 (memory), and Phase E5 (identity / DLP).
2. **LDE TRDS hot-reload is a placeholder.** The rule-pull timer at
   [`crates/sda-local-detection/src/lib.rs` lines 495–501](../../crates/sda-local-detection/src/lib.rs#L495-L501)
   currently logs `"LDE rule pull timer fired (hot-reload not yet
   implemented)"` and does not actually swap rules. Closed by
   Phase E2.
3. **LDE is off by default.** The default at
   [`crates/sda-core/src/config.rs` line 983](../../crates/sda-core/src/config.rs#L983)
   is `enabled: false`. Closed by Phase E2 (flips to `true`).
4. **No host isolation primitive.** No `HostIsolation` PAL trait;
   no `IsolateHost` / `UnisolateHost` `SignedActionJob`. Closed by
   Phase E3.
5. **No in-memory YARA path.** The existing YARA scanner in
   `sda-local-detection` only scans file paths from FIM events.
   Closed by Phase E4 (extends to byte slices for memory regions).
6. **No identity-attack signal.** No LSASS / shadow / keychain
   access detection. Closed by Phase E5.
7. **No DLP content inspection.** No `sda-dlp` crate; no PII / PCI
   pattern matching on file writes or clipboard. Closed by
   Phase E5.
8. **No kernel-mode telemetry.** All Phase E1–E5 telemetry is
   user-mode by design. Kernel-mode productisation is tracked
   separately in Phase E6, mirroring
   [`docs/device-control/PRODUCTISATION-WINDOWS.md`](../device-control/PRODUCTISATION-WINDOWS.md)
   and
   [`docs/device-control/PRODUCTISATION-MACOS.md`](../device-control/PRODUCTISATION-MACOS.md).

---

## Next Steps

1. **Land Phase E0 documentation** — this PR.
2. **Phase E0 sign-off** — ADR review with maintainers; wire schema
   sign-off with `sn360-security-platform` maintainers; clean-room
   license audit recorded in
   [`docs/security-audit.md`](../security-audit.md).
3. **Phase E1 kick-off** — once Phase E0 exits, open per-task PRs
   against E1.1–E1.10 in workstream order, gating each on the
   benchmark CI gate.

The phase ordering is intentionally:

- **E0 → E1 → E2** before any of E3 / E4 / E5 because Phase E2's
  LDE maturity + default-ON is what turns the new telemetry from
  Phase E1 into shipped detections.
- **E3 → E4 → E5** in priority order; each phase is independent of
  the others and can be parallelised across teams once Phase E2 has
  landed.
- **E6 (kernel productisation)** is **ongoing** and runs in parallel
  with E3–E5 once the user-mode PAL surfaces from E1 / E3 / E4 are
  stable. Productisation of any one platform is a self-contained
  workstream.

---

## Changelog

> Each entry is collapsed; click the date row to expand the full
> implementation notes for that PR.

<details>
<summary>2026-05-17 — EDR Parity Phases E0–E3 agent-side delivery</summary>


Implementation PR closing every agent-side task in Phases E0, E1,
E2, and E3 of the EDR Parity workstream. The remaining server-side
⚙️ tasks (E1.9, E1.10, E2.5, E3.13, E3.14) are tracked separately
in [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).

Phase E0 — Architecture & Schema (done):

- 8 new `EventKind` variants added to
  [`crates/sda-event-bus/src/event.rs`](../../crates/sda-event-bus/src/event.rs)
  (`ProcessCreated`, `ProcessTerminated`, `ImageLoaded`,
  `NetworkConnection`, `DnsQuery`, `MemoryScanAlert`,
  `HostIsolationStateChanged`, `IdentityAlert`) following the
  established `{ payload: String }` canonical-JSON pattern.
- Matching 8 `MessageType` variants + explicit encoder arms added
  to [`crates/sda-comms/src/protocol.rs`](../../crates/sda-comms/src/protocol.rs)
  under the `legacy-siem` feature gate.
- `deny.toml` annotated with the clean-room EDR posture (no
  CrowdStrike / SentinelOne / Defender source imports) and
  [`docs/security-audit.md`](../security-audit.md) extended with
  the "EDR Parity License Audit" section.

Phase E1 — Process Telemetry (agent-side done):

- New PAL trait `sda-pal::ProcessMonitor` (`crates/sda-pal/src/process_monitor.rs`)
  with Linux `cn_proc` netlink + `/proc` enrichment, Windows ETW
  `Microsoft-Windows-Kernel-Process`, macOS Endpoint Security
  framework, plus `MockProcessMonitor` for hermetic CI.
- New crate `sda-process-monitor` with standard module lifecycle:
  bounded mpsc + drop-oldest back-pressure, dedup ring, ancestor
  enrichment up to configurable depth, `ProcessCreated` /
  `ProcessTerminated` / `ImageLoaded` event emission.
- LDE `handle_event` expansion: `EventKind::ProcessCreated`,
  `ProcessTerminated`, and `ImageLoaded` now flow into the IOC and
  behavioural pipelines instead of being dropped by the
  `_ => return,` catch-all.
- Behavioural rule DSL extended with `parent_chain_regex` matcher;
  3 baseline rules ship in the default bundle
  (Office→PowerShell, wmiprvse→rundll32, non-system `lsass.exe`
  access).
- E2E suite: `make e2e-process-telemetry` — 13 tests, all green.

Phase E2 — LDE Maturity + Default-ON (agent-side done):

- Real TRDS hot-reload pipeline (`crates/sda-local-detection/src/trds_client.rs`):
  HTTP(S) pull → bundle envelope validation → Ed25519 signature
  verification against a pinned rotation set → atomic
  `Arc<ArcSwap<DetectionPipeline>>` swap. In-flight evaluations
  complete on the old pipeline; failed pulls preserve the
  last-known-good.
- Ed25519 verifier rejects tampered bundles, unknown `key_id`s,
  and stale `not_after` envelopes; every rejection emits a
  `LocalDetectionAlert` Finding at `severity: high`.
- `LocalDetectionConfig::default().enabled` flipped from `false`
  to `true` in [`crates/sda-core/src/config.rs`](../../crates/sda-core/src/config.rs);
  migration note added to [`CHANGELOG.md`](../../CHANGELOG.md).
- Default rule bundle embedded via `include_bytes!` in
  `crates/sda-local-detection/src/default_bundle.rs` containing
  the Phase E1 baseline behavioural rules plus a minimal IOC set;
  the LDE loads it on startup whenever a TRDS pull has not yet
  succeeded.
- E2E suite: `make e2e-lde-hotreload` — 10 tests, all green.

Phase E3 — Network Telemetry + Host Isolation (agent-side done):

- Three new PAL traits in `sda-pal`:
  - `NetworkMonitor` (`network_monitor.rs`) — Linux `/proc/net/*`
    poller with `to_ne_bytes()` endian-correct IP parsing,
    Windows ETW `Microsoft-Windows-Kernel-Network`, macOS Network
    Extension `NEFilterDataProvider`, plus `MockNetworkMonitor`.
  - `DnsMonitor` (`dns_monitor.rs`) — Linux journalctl /
    systemd-resolved tap, Windows ETW
    `Microsoft-Windows-DNS-Client`, macOS `NEDNSProxyProvider`,
    plus `MockDnsMonitor`.
  - `HostIsolation` (`host_isolation.rs`) — Linux nftables table
    `sn360_isolation`, Windows `netsh advfirewall` + WFP rule
    group, macOS `pfctl` anchor `com.sn360.host_isolation`, plus
    `MockHostIsolation`. Safety invariants enforced: loopback +
    control-plane CIDRs always in the allow-list; idempotent
    isolate / unisolate.
- New crate `sda-network-monitor` with bounded LRU-ish dedup ring,
  4-per-second UDP flow sampler, and standard module lifecycle.
  Publishes `EventKind::NetworkConnection` and `EventKind::DnsQuery`
  on the bus.
- New crate `sda-host-isolation` with the 10-step `SignedActionJob`
  validation pipeline (mirrors `sda-device-control`), allow-list
  construction (control-plane + loopback + DNS + extras),
  `IsolateHost` / `UnisolateHost` `ActionKind` variants, and
  `HostIsolationStateChanged` emission.
- LDE `handle_event` expansion: `EventKind::NetworkConnection` and
  `EventKind::DnsQuery` flow into the IP IOC and string IOC
  matchers respectively.
- E2E suites:
  - `make e2e-network-telemetry` — 11 tests, all green.
  - `make e2e-host-isolation` — 7 tests, all green.

Test surface delta:

- +130 `sda-pal` unit tests (new PAL traits + mocks).
- +18 `sda-process-monitor` unit tests.
- +17 `sda-network-monitor` unit tests.
- +13 `sda-host-isolation` unit tests.
- +41 new agent-side E2E tests across the four EDR Parity suites.

Idle-resource budgets remain enforced by `make benchmark-ci`. With
the new modules opted-in (via `process_monitor.enabled`,
`network_monitor.enabled`, `dns_monitor.enabled`, and
`host_isolation.enabled`), they live behind explicit config flags
and default-OFF except `local_detection` which now defaults to
`true` per Phase E2.3.

</details>

<details>
<summary>2026-05-17 — EDR Parity planning docs (Phase E0 documentation deliverable)</summary>


This PR is documentation-only — no source code is changed. It lands
the four EDR Parity planning documents under `docs/edr-parity/` and
threads cross-references through the workspace-level
[`PROGRESS.md`](../../PROGRESS.md) and
[`docs/revised-phase-plan.md`](../revised-phase-plan.md).

Doc landings:

- [`PROPOSAL.md`](./PROPOSAL.md) — full technical proposal covering
  motivation & competitive context vs CrowdStrike / SentinelOne /
  Defender, three workstreams (E / R / N), architecture (new PAL
  traits + new `EventKind` variants + six new agent-side crates +
  LDE expansion + config changes), do-not-port scope boundaries,
  server-side integration with `sn360-security-platform`, and the
  full risk register.
- [`PHASES.md`](./PHASES.md) — phased delivery plan with Phase E0
  through E6 task tables, per-task descriptions, exit criteria, and
  the phase-planner's risk-register quick reference. Uses Phase E
  identifiers (E0–E6) to avoid collision with existing Phase D
  (Device Control) and Phase M (Desktop MDM) identifiers.
- [`PROGRESS.md`](./PROGRESS.md) — this file. All tasks across
  Phases E0–E6 are marked **Not Started**.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — diagram-first
  architecture companion with crate map, event-flow diagram, per-OS
  PAL implementation notes, resource budgeting, and wire schema
  overview table.

Workspace-level cross-reference threading:

- [`PROGRESS.md`](../../PROGRESS.md) — adds **Priority 6 — EDR
  Parity (Process / Network / Memory / Identity)** section,
  listing the seven Phase E roll-ups (P6.1–P6.7).
- [`docs/revised-phase-plan.md`](../revised-phase-plan.md) — adds
  **Phase 10 — EDR Parity** after the existing Phase 9 (Legacy
  Deprecation), with a cross-reference to the new
  [`docs/edr-parity/PHASES.md`](./PHASES.md).

No code changes. No tests are added because there is nothing to
test yet. The existing SDA test surface (433 unit, 14/14 base E2E,
10/10 security E2E) remains green; the existing benchmark gate
(`make benchmark-ci`) continues to enforce idle RSS / idle CPU /
FIM scan peak / binary-size budgets with the LDE off (the default
until Phase E2 flips it on).

</details>
