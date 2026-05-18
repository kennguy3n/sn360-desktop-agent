# SN360 Desktop Agent — Development Progress

Tracks the implementation status of `sn360-desktop-agent` against the
roadmap in
[`device-agent-proposal.md`](./device-agent-proposal.md) §12.

Status legend:

- **Done** — merged to `main` and covered by tests / benchmarks below.
- **In Progress** — branch exists, code is being written / reviewed.
- **Not Started** — no implementation work started yet.

## Current Status

Phases 1–6 are complete. Phase 5.6 enhanced protocol (TLS 1.3 +
MessagePack + HTTP/2 under `server.enhanced`) shipped alongside
the Phase 6 testing & release infrastructure: the E2E harness
runs against a reference SIEM manager v4.9.2 (`make e2e`) and
v4.7.5 (`make e2e-compat`), the CI matrix covers Ubuntu
22.04/24.04, macOS 13/14, and Windows Server 2022, a `cargo audit`
gate, a performance regression gate (`make benchmark-ci`), and a
nightly `cargo-fuzz` matrix (5-minute budget per target) all run
in CI, and the tag-triggered release workflow
(`.github/workflows/release.yml`) builds `.deb` / `.rpm` /
`.pkg` / `.msi` installers on matching OS runners and drafts a
GitHub Release with `CHANGELOG.md` as the body. The
user/admin/architecture/configuration docs landed under `docs/`,
including the new [`docs/release-process.md`](./docs/release-process.md)
runbook for tagging, signing, and promoting a draft. The only
Phase 6 items not drivable from this repo are the beta tag
(`v0.9.0-beta.1`) and signed-binary publication, which need
release credentials and signing keys outside this session. All
four proposal benchmark targets (idle RSS 5.7 MB, idle CPU
0.00 %, shipped binary 4.6 MB, FIM scan peak 3 %) continue to be
met. `cargo test --all` shows **431 passing / 0 failed** (adds
15 rootcheck tests for content-based checks + cross-platform
hidden-process detection and 5 PAL tests for the new Linux
user-idle detector, on top of +20 tests that landed on `main`
via PR #55 in `sda-comms`, `sda-agent`, and `sda-updater`), the
base E2E harness passes **14/14** assertions against a local
reference SIEM manager, and the security E2E suite passes
**10/10** attack-scenario checks. Server-side SN360 Control
Plane microservices (TRDS, IOCFS, SIS, Agent Gateway) are **out
of scope** for this repository and are implemented in
[`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).

## Phase 1 — Core Plumbing (7/7)

| # | Task | Status |
|---|------|--------|
| 1.1 | Workspace + crate skeleton (`sda-core`, `sda-comms`, `sda-event-bus`, `sda-pal`, modules) | Done |
| 1.2 | Structured YAML config loading (`AgentConfig`) on all OSes | Done |
| 1.3 | Enrollment via the legacy SIEM enrollment protocol on 1515 with password auth, key persistence (legacy adapter) | Done |
| 1.4 | Connection manager with legacy SIEM transport adapter (TCP + UDP + Blowfish crypto) | Done |
| 1.5 | Keepalive loop sending startup + periodic keepalives | Done |
| 1.6 | Event bus with priority queues and back-pressure handling | Done |
| 1.7 | Shutdown signal + task coordination (SIGINT / SIGTERM) | Done |

## Phase 2 — Detection Modules (9/9)

| # | Task | Status |
|---|------|--------|
| 2.1 | FIM — realtime + scheduled baseline (inotify / ReadDirectoryChangesW / FSEvents) | Done |
| 2.2 | Log collection — file tailing (syslog format, position tracking) | Done |
| 2.3 | Log collection — journald (Linux, event-driven) | Done |
| 2.4 | Log collection — Windows EventLog (`EvtSubscribe` / `EvtRender` via `windows-rs`) | Done |
| 2.5 | Log collection — macOS OSLog / unified logging (`/usr/bin/log stream`) | Done |
| 2.6 | Inventory (syscollector-compatible: os, hardware, packages, network) | Done |
| 2.7 | Active response (`block_ip`, `kill_process`, script execution) | Done |
| 2.8 | SCA policy evaluation (YAML policies, regex / command / file checks) | Done |
| 2.9 | Rootcheck (signatures, Linux hidden-process detection, binary-integrity drift) | Done |

## Phase 3 — Gap-fill (3/3)

| # | Task | Status |
|---|------|--------|
| 3.R | Server message receive loop — parses `#!-execd` / `#!-req` / `#!-up_file` tags and publishes `EventKind::ServerCommand` | Done |
| 3.S | Wire SCA module into agent main loop with periodic policy evaluation | Done |
| 3.RC | Rootcheck detection logic (signatures, hidden-process, binary-integrity) wired into `RootcheckModule::start()` | Done |

## Phase 4 — Edge Detection, Software Inventory & Tenant Rule Distribution

Tasks below are tracked against
[`device-agent-proposal.md` § 12 Phase 4 roadmap](./device-agent-proposal.md#phase-4-edge-detection-software-inventory--tenant-rule-distribution-weeks-15-22);
see
[`device-agent-proposal.md` § 13](./device-agent-proposal.md#13-phase-4-detail-edge-detection-software-inventory--tenant-rule-distribution)
for the detailed design.

> **Scope note:** Tasks 4.10–4.14 are server-side Control Plane
> microservices excluded from this repository. They are implemented
> in [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
> This repo contains only the agent-side (device) code.
>
> See [`docs/integration.md`](./docs/integration.md) for the full
> integration picture (Path A / B / C, agent-side Non-Wazuh modules,
> companion microservices).

| # | Task | Status |
|---|------|--------|
| 4.1 | LDE: rule store format, MessagePack schema, mmap loader | Done |
| 4.2 | LDE: Aho-Corasick pattern matcher + IOC bloom filter evaluator | Done |
| 4.3 | LDE: Behavioral rule state machine (JSON DSL → evaluator) | Done |
| 4.4 | LDE: Local Response Dispatcher (block IP, kill process, quarantine) | Done |
| 4.5 | LDE: YARA scanner integration (required, not feature-gated) | Done |
| 4.6 | LDE: Offline detection queue + server sync on reconnect | Done |
| 4.7 | Enhanced Inventory: running software monitor (all platforms) | Done |
| 4.8 | Enhanced Inventory: browser extension inventory (Chrome / Firefox / Edge / Safari) | Done |
| 4.9 | Enhanced Inventory: CycloneDX SBOM generator (periodic + on-demand) | Done |
| 4.10 | TRDS microservice: rule CRUD API, compiler, delta distribution | Out of Scope — implemented in [sn360-security-platform](https://github.com/kennguy3n/sn360-security-platform) |
| 4.11 | IOCFS microservice: feed ingestion, normalization, bloom filter compilation | Out of Scope — implemented in [sn360-security-platform](https://github.com/kennguy3n/sn360-security-platform) |
| 4.12 | SIS microservice: inventory ingestion, CVE matching, dashboard API | Out of Scope — implemented in [sn360-security-platform](https://github.com/kennguy3n/sn360-security-platform) |
| 4.13 | Agent Gateway: mTLS termination, tenant routing, rate limiting | Out of Scope — implemented in [sn360-security-platform](https://github.com/kennguy3n/sn360-security-platform) |
| 4.14 | Integration: agent ↔ TRDS rule pull, hot-reload, version tracking | Out of Scope — agent-side integration only; server-side in [sn360-security-platform](https://github.com/kennguy3n/sn360-security-platform) |

## Tests & Benchmarks

The full test surface — unit, base E2E (14/14), security E2E (10/10), platform top-10 (10/10), benchmarks against the reference legacy SIEM agent — is reproduced on every commit and recorded in [`TEST_RESULTS.md`](./TEST_RESULTS.md). The latest run (2026-04-28) is **433 / 433 unit, 14 / 14 base E2E, 10 / 10 security E2E, 10 / 10 platform top-10**.

Reproduce locally:

```
cargo test --all                                    # unit
make e2e                                            # base E2E vs. wazuh-manager:4.9.2
make security-e2e                                   # 10 attacker scenarios
(cd ../sn360-security-platform && \
  bash tests/regression/security-scenarios/run-top10-security-e2e.sh)
```

## Continuous Integration

Unit tests and builds run on `ubuntu-latest`, `macos-latest`, and
`windows-latest` on every push and pull request. `rustfmt` + `clippy`
run on `ubuntu-latest`. A nightly benchmark job runs at `0 3 * * *`.

The `e2e` job runs on push to `main` on `ubuntu-latest` only —
`macos-latest` lacks Docker and the reference SIEM manager image
is Linux-only, so macOS / Windows E2E runs are executed locally
via `make e2e-macos` / `make e2e-windows`.

## Benchmarks

Latest benchmark numbers vs. proposal targets live in [`benchmark-results.md`](./benchmark-results.md); a one-line summary is also published in [`TEST_RESULTS.md`](./TEST_RESULTS.md). All four headline metrics (idle RAM / idle CPU / binary size / FIM scan peak CPU) are within target.

## Known Gaps

All previously-open Phase 1–3 items and the four agent-side
Phase-6 gaps have been resolved on `main`. The remaining open
items are:

1. **macOS FIM burst test permanently skipped on CI** — mitigated,
   not fixed. The runtime-starvation bug is fixed (multi-thread
   runtime + `spawn_blocking` for the synchronous writes) but the
   underlying kqueue drop on GitHub-hosted `macos-latest` runners
   persists, so the test keeps its
   `#[cfg_attr(target_os = "macos", ignore = "...")]` annotation.
   It can still be forced locally with
   `cargo test -p sda-fim --test burst_workload -- --include-ignored`.
   See
   [`docs/known-issues/fim-burst-workload-macos-ci.md`](./docs/known-issues/fim-burst-workload-macos-ci.md).
2. **Server-side microservices excluded from this repo** — TRDS,
   IOCFS, SIS, and the Agent Gateway are implemented in
   [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform),
   not in this repository. Phase 4.10–4.14 in the table above are
   marked Out of Scope accordingly.

## Next Steps

Completed items keep their strikethrough to preserve context; active
work is unstruck.

### Priority 1 — Phase 3 polish and open gaps

All P1 items are resolved. Completed items keep their
strikethrough plus a short note for provenance.

| # | Task | Status |
|---|------|--------|
| P1.1 | ~~Wire PAL `PowerMonitor` on macOS and Windows~~ | Done |
| P1.2 | ~~Add E2E tests for SCA and Rootcheck~~ | Done |
| P1.3 | ~~Investigate and fix the macOS FIM burst test hang; re-enable on macOS CI~~ — runtime-starvation bug fixed (multi-thread runtime + `spawn_blocking`); kqueue drop on GitHub-hosted macOS runners documented and test marked `#[cfg_attr(target_os = "macos", ignore)]` per existing repo convention. See [`docs/known-issues/fim-burst-workload-macos-ci.md`](./docs/known-issues/fim-burst-workload-macos-ci.md). | Done |
| P1.4 | ~~Implement rootcheck content-based checks (e.g. `/etc/ld.so.preload`)~~ — new `crates/sda-rootcheck/src/content_checks.rs` module inspects `/etc/ld.so.preload` (LD_PRELOAD allow-list), `/etc/crontab` (pipe-to-shell / dev-tcp reverse-shell patterns), and `/etc/hosts` (security-update domain redirections to non-loopback IPs) + 14 new unit tests. | Done |
| P1.5 | ~~Cross-platform rootcheck hidden-process detection (macOS / Windows)~~ — `hidden_process.rs` now enumerates processes via `sysctl(CTL_KERN, KERN_PROC_ALL)` on macOS and `CreateToolhelp32Snapshot` / `Process32NextW` on Windows, with liveness probes via `kill(pid, 0)` / `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, ...)` respectively. Platform-gated tests cover each backend. | Done |
| P1.6 | ~~Record Phase 2.9 Rootcheck as Complete~~ | Done |
| P1.7 | ~~Wire adaptive power-aware scheduling into module loops~~ | Done |
| P1.8 | ~~Linux user-idle detection~~ — implemented via `loginctl show-session self --property=IdleSinceHint --value` with a pure `parse_idle_since_hint()` helper; returns `None` on headless / non-systemd hosts, so no regression for bare-metal or container deployments. | Done |
| P1.9 | ~~Re-run FIM burst benchmark on the merged pipeline~~ — rerun on this branch with `bash tests/scripts/fim-burst-bench.sh`; peak 3 %, 15-s avg 1.33 % still meet the strict < 3 % target. See [`benchmark-results.md`](./benchmark-results.md). | Done |
| P1.10 | ~~Tune FIM defaults for burst-heavy environments~~ — current defaults (`max_hashes_per_sec = 100`, `batch_size = 50`, `batch_timeout_ms = 200`) already meet all budgets; no tuning required. Rationale captured in [`benchmark-results.md`](./benchmark-results.md#fim-scan-cpu-creation-of-1-000-files-in-a-watched-directory). | Done |
| P1.11 | ~~Regenerate E2E coverage for enhanced inventory~~ | Done |

### Priority 2 — Phase 4: Edge Detection & Enhanced Inventory

| # | Task | Phase 4 ref |
|---|------|-------------|
| P2.1 | ~~LDE rule store format and mmap loader~~ — Done | 4.1 |
| P2.2 | ~~Aho-Corasick pattern matcher + IOC bloom filter~~ — Done | 4.2 |
| P2.3 | ~~Behavioral rule state machines~~ — Done | 4.3 |
| P2.4 | ~~Local Response Dispatcher~~ — Done | 4.4 |
| P2.5 | ~~YARA scanner integration~~ — Done | 4.5 |
| P2.6 | ~~Offline detection queue + server sync on reconnect~~ — Done | 4.6 |
| P2.7 | ~~Enhanced Inventory: running software monitor~~ — Done | 4.7 |
| P2.8 | ~~Enhanced Inventory: browser extension enumeration~~ — Done | 4.8 |
| P2.9 | ~~Enhanced Inventory: SBOM generator (on-demand)~~ — Done | 4.9 |
| P2.10 | ~~Wire Enhanced Inventory into main agent~~ — Done | 4.7–4.9 wiring |
| P2.11 | ~~Companion microservices (TRDS / IOCFS / SIS / Gateway)~~ — **Out of Scope**: implemented in [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform) | 4.10–4.13 |
| P2.12 | Agent ↔ TRDS rule pull, hot-reload, version tracking — agent-side integration only; server-side in [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform) | 4.14 |

### Priority 3 — Phase 5: Platform Hardening

All Priority 3 tasks have landed. Phase 5 is complete.

| # | Task | Status |
|---|------|--------|
| P3.1 | Self-update mechanism (signed download, atomic replace, rollback) | Done (PR #49) |
| P3.2 | Privilege separation — run detection modules with minimal privileges | Done (PR #50) |
| P3.3 | Tamper protection — protect binary / config / keys; watchdog restart | Done (PR #50) |
| P3.4 | Installer / packaging — MSI (Windows), `.deb` / `.rpm` (Linux), `.pkg` (macOS) | Done (PR #48) |

### Priority 4 — Device Control Module

| # | Task | Status |
|---|------|--------|
| P4.1 | Phase 0: ADR, license review, schema design | Done |
| P4.2 | Phase 1: Visibility + admin/root review | Done |
| P4.3 | Phase 2: Push software + approved catalogue | Done |
| P4.4 | Phase 3: Just-in-time admin/root | Done |
| P4.5 | Phase 4: Remote support + app control + MDM | Done |
| P4.6 | Phase 5: MSP-ready multi-tenant operations | Done |
| P4.7 | Phase D2: USB / removable-media policy enforcement (agent-side) | Done |

### Priority 5 — Desktop MDM Module

The canonical per-task ledger lives in
[`docs/desktop-mdm/PROGRESS.md`](./docs/desktop-mdm/PROGRESS.md);
this section is a top-level summary.

| # | Task | Status |
|---|------|--------|
| P5.1 | Phase M1: Auto-remediation + recovery key escrow + OS patch (agent-side) | Done |
| P5.2 | Phase M2: Remote wipe (dual-control) + remote lock + lost mode (agent-side) | Done |
| P5.3 | Phase M3: Declarative configuration profiles (agent-side, TRDS bundle watcher) | Done |
| P5.4 | Phase M4: Dashboard UI + one-click actions + recovery key viewer ⚙️ | Not Started — server-side, [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform) |
| P5.5 | Risk Engine MDM recommendations (M1.7) ⚙️ | Not Started — server-side |
| P5.6 | SMI `mdm_compliance` sub-score (M1.8) ⚙️ | Not Started — server-side |
| P5.7 | Desktop MDM service (M2.4) ⚙️ | Not Started — server-side |

### Priority 6 — EDR Parity (Process / Network / Memory / Identity)

The canonical per-task ledger lives in
[`docs/edr-parity/PROGRESS.md`](./docs/edr-parity/PROGRESS.md);
this section is a top-level summary. EDR Parity uses **Phase E**
identifiers (E0–E6) to avoid collision with the existing **Phase D**
(Device Control) and **Phase M** (Desktop MDM) identifiers. See the
companion [`docs/edr-parity/PROPOSAL.md`](./docs/edr-parity/PROPOSAL.md),
[`docs/edr-parity/PHASES.md`](./docs/edr-parity/PHASES.md), and
[`docs/edr-parity/ARCHITECTURE.md`](./docs/edr-parity/ARCHITECTURE.md)
for design rationale, phased roadmap, and architecture reference.

| # | Task | Status |
|---|------|--------|
| P6.1 | Phase E0: Architecture & schema sign-off | Done |
| P6.2 | Phase E1: Process telemetry (all platforms) | Done (agent-side); E1.9 / E1.10 ⚙️ Not Started — server-side |
| P6.3 | Phase E2: LDE maturity + default-ON | Done (agent-side); E2.5 ⚙️ Not Started — server-side |
| P6.4 | Phase E3: Network telemetry + host isolation | Done (agent-side); E3.13 / E3.14 ⚙️ Not Started — server-side |
| P6.5 | Phase E4: Memory scanning + fileless detection | Done |
| P6.6 | Phase E5: Identity attack detection + DLP | Done |
| P6.7 | Phase E6: Kernel driver productisation | Done (scaffolding + productisation docs) |

> **EDR Parity agent-side status (this branch).** Phases E0–E6 are
> all landed agent-side. Phases E0–E3 ship via PR
> [#24](https://github.com/kennguy3n/sn360-desktop-agent/pull/24);
> Phases E4–E6 ship via PR
> [#25](https://github.com/kennguy3n/sn360-desktop-agent/pull/25).
> New crates: `sda-process-monitor`, `sda-network-monitor`,
> `sda-host-isolation`, `sda-memory-scanner`,
> `sda-identity-monitor`, `sda-dlp`. New PAL traits:
> `ProcessMonitor`, `NetworkMonitor`, `DnsMonitor`, `HostIsolation`,
> `MemoryScanner`; new platform-agnostic kernel-channel module
> `sda-pal::kernel` with per-platform mock channels for
> Windows / macOS / Linux gated behind `kernel-windows`,
> `kernel-macos`, and `kernel-linux-ebpf` feature flags. LDE is now
> default-ON with an embedded baseline rule bundle and verified
> TRDS hot-reload (Ed25519 against a pinned rotation set, atomic
> `Arc<ArcSwap<DetectionPipeline>>` swap). Seven new hermetic E2E
> suites: `make e2e-process-telemetry` (13 tests), `make
> e2e-lde-hotreload` (10 tests), `make e2e-network-telemetry` (11
> tests), `make e2e-host-isolation` (7 tests), `make
> e2e-memory-scan` (10 tests), `make e2e-identity` (10 tests),
> `make e2e-dlp` (11 tests). Server-side ⚙️ tasks (E1.9, E1.10,
> E2.5, E3.13, E3.14) remain Not Started in
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).

> **Cross-repo status (2026-05-11).** All agent-side Device Control
> work (Phases 0–5 + D2 user-mode enforcement) is complete on this
> repo, and every control-plane ⚙️ task (1.14–1.16, 2.12–2.14, 3.6,
> 4.9–4.11, 5.1–5.5 + 5.6 GA-prep scaffold) is complete on
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)
> under PRs
> [#85](https://github.com/kennguy3n/sn360-security-platform/pull/85)
> and [#86](https://github.com/kennguy3n/sn360-security-platform/pull/86).
> Open items are deferred-path productisation (the Windows WHQL-signed
> kernel filter driver `D2.3-driver` and the macOS signed
> `IOUSBHostInterface` SystemExtension `D2.4-sysext`) and the
> external-gated 5.2 pentest, 5.7 legal review, and D4.6 SRE on-call
> sign-off on the platform side.

See [`docs/device-control/PROGRESS.md`](./docs/device-control/PROGRESS.md) for the canonical per-phase Device Control task ledger, test counts, and changelog.

## Phase 5 detailed status

| Deliverable | Status | PR |
|---|---|---|
| Self-update module (signed manifest + rollback) | Done | [#49](https://github.com/kennguy3n/sn360-desktop-agent/pull/49) |
| Privilege separation (drop-privileges, minimal caps per module) | Done | [#50](https://github.com/kennguy3n/sn360-desktop-agent/pull/50) |
| Tamper protection (binary / config / keys integrity + watchdog) | Done | [#50](https://github.com/kennguy3n/sn360-desktop-agent/pull/50) |
| Installers — `.deb`, `.rpm`, `.pkg`, `.msi`, hardened systemd unit | Done | [#48](https://github.com/kennguy3n/sn360-desktop-agent/pull/48) |
| **5.6 Enhanced protocol — TLS 1.3 + MessagePack + HTTP/2 (opt-in)** | **Done** | *(this branch)* |

### Phase 5.6 detail — Enhanced protocol

The SN360 native protocol options live under `server.enhanced`
in `AgentConfig` and default **on** in the proprietary
distribution. When the optional `legacy-siem` adapter is enabled
and talking to a legacy SIEM manager these knobs can be disabled
to fall back to the legacy TCP/UDP + Blowfish path for that
specific deployment. See
[`docs/configuration-reference.md`](./docs/configuration-reference.md#server)
and [`docs/architecture.md`](./docs/architecture.md#3-communication-layers)
for the full surface.

| Sub-task | Deliverable | Status |
|---|---|---|
| 5.6a | TLS 1.3 transport — `sda_comms::transport::tls` using `rustls`, TLS 1.3-only, optional CA bundle, SHA-256 leaf pinning | Done |
| 5.6b | MessagePack serialisation — `sda_comms::msgpack::MessagePackSerializer` round-trips all `EventKind` variants; 50–70 % smaller than JSON on inventory payloads | Done |
| 5.6c | HTTP/2 transport — `sda_comms::transport::http2` with ALPN `h2` (requires TLS) | Done |
| 5.6d | Config integration — `server.enhanced.{tls,serialization,transport,tls_ca_bundle_path,tls_pinned_sha256}` | Done |
| 5.6e | Tests — unit tests for MessagePack round-trip (all `EventKind` variants), TLS config construction and pinning, HTTP/2 ALPN, legacy-protocol fallback | Done |

## Phase 6 — Testing & Release

Phase 6 tasks are tracked against
[`device-agent-proposal.md` § 12 Phase 5 roadmap](./device-agent-proposal.md#phase-5-testing--release-weeks-19-22)
(the proposal used "Phase 5" for this testing & release phase;
this document tracks it as Phase 6 since Phase 5 already covered
platform hardening here).

| # | Task | Status |
|---|------|--------|
| 6.1 | E2E integration testing vs a reference SIEM manager — `make e2e` (v4.9.2) and `make e2e-compat` (v4.7.5) harnesses + cleanup-hang fix (already in main via PR #54) | Done |
| 6.2 | Platform testing — CI matrix expanded to `ubuntu-22.04` / `ubuntu-24.04` / `macos-13` / `macos-14` / `windows-2022`; Fedora/Arch documented in [`docs/platform-testing.md`](./docs/platform-testing.md) | Done |
| 6.3 | Performance regression testing — `tests/scripts/benchmark-regression.sh` + `make benchmark-ci`; CI artifact upload with hard thresholds (idle RSS < 15 MB, idle CPU < 0.1 %, binary < 7 MB, FIM burst < 3 %) | Done |
| 6.4 | Security audit — `cargo audit --deny warnings` CI job + `fuzz/` harness (cargo-fuzz targets for protocol decode, zlib decompress, msgpack event decode, rule-bundle msgpack); see [`docs/security-audit.md`](./docs/security-audit.md) | Done |
| 6.5 | Documentation — [`docs/user-guide.md`](./docs/user-guide.md), [`docs/admin-guide.md`](./docs/admin-guide.md), [`docs/architecture.md`](./docs/architecture.md), [`docs/configuration-reference.md`](./docs/configuration-reference.md); README links added | Done |
| 6.6 | Beta release preparation — `.github/workflows/release.yml` builds `.deb` / `.rpm` / `.pkg` / `.msi` artefacts on Ubuntu / macOS / Windows runners and drafts a GitHub Release on every `v*` tag; nightly CI now fuzzes the four `cargo-fuzz` targets for 5 minutes each; [`docs/release-process.md`](./docs/release-process.md) runbook covers tagging, signing, and promotion. Tag push + artefact signing require maintainer action (keys outside this session). | Done (publication gated on maintainer action) |
