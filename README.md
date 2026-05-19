# SN360 Desktop Agent (SDA)

[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-lightgrey.svg)](./LICENSE)
[![CI](https://github.com/kennguy3n/sn360-desktop-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/kennguy3n/sn360-desktop-agent/actions/workflows/ci.yml)

A lightweight, cross-platform security and device-management agent
for desktops and laptops, built in Rust. SDA targets sub-15 MB
resident memory, sub-0.1 % idle CPU, and near-invisible operation
on end-user devices. It speaks the SN360 native protocol (TLS 1.3,
MessagePack, HTTP/2) and ships an optional adapter for legacy SIEM
manager protocols.

> Crates use the `sda-` prefix. Some legacy internal identifiers
> use the `wda-` prefix; these are code-only and the product is
> always referred to as SDA / SN360 Desktop Agent.

## Features

The agent is organised around five capability surfaces.

**Endpoint Detection & Response (EDR)** — file integrity
monitoring, process telemetry, network and DNS telemetry, host
isolation via per-OS firewall primitives, periodic memory scanning
with in-memory YARA, identity-attack detection (LSASS access on
Windows, `/etc/shadow` and `/proc/kcore` on Linux, keychain access
on macOS), and regex-based DLP scanning of file writes with
Blake3 fingerprinting. The local detection engine (LDE) does edge
IOC matching, behavioural rules, and YARA against live process
memory; rule bundles are Ed25519-signed and hot-swap atomically
over a `Arc<ArcSwap<DetectionPipeline>>`. See
[`docs/edr.md`](./docs/edr.md).

**Device Control** — atomic CAS-applied USB and removable-media
policy enforcement, signed-action-job ingestion with a 10-step
validation pipeline, append-only Ed25519-chained evidence records,
and an SME-targeted Finding / Recommendation / SignedActionJob /
ActionResult / EvidenceRecord schema set. See
[`docs/device-control.md`](./docs/device-control.md).

**Desktop MDM** — default-on auto-remediation supervisor (disk
encryption, firewall, screen lock), one-time-per-boot recovery key
escrow (BitLocker, FileVault, LUKS) with ChaCha20-Poly1305 +
Ed25519, OS patch orchestration with battery-aware deferral,
dual-control remote wipe, remote lock, lost mode with IP-based
geolocation, and Ed25519-signed declarative configuration
profiles. See [`docs/desktop-mdm.md`](./docs/desktop-mdm.md).

**Optional kernel-mode telemetry** — feature-gated backends for
tamper-resistant telemetry: Windows WDK minifilter, signed macOS
SystemExtension, and Aya-based Linux eBPF. User-mode telemetry is
the default everywhere; kernel backends are opt-in via Cargo
feature flags and packaging changes. See
[`docs/kernel-drivers.md`](./docs/kernel-drivers.md).

**Foundational endpoint hygiene** — log collection (file tailing,
systemd journal, Windows Event Log, macOS unified logging), system
inventory (packages, network interfaces, hardware, OS), enhanced
inventory (running software, browser extensions, CycloneDX SBOM),
security configuration assessment (SCA) with YAML policy
evaluation, active response (IP blocking, process termination,
script execution), rootkit detection, and posture snapshots (disk
encryption, firewall, screen lock, OS patch level). Adaptive
scheduling backs off scans on battery and during user activity.

## Installation

For most deployments, install from pre-built packages — no build
toolchain required.

| Platform | Package | Command |
|----------|---------|---------|
| **Windows** | `.msi` | `msiexec /i sn360-desktop-agent-x64.msi /qn` |
| **macOS** | `.pkg` | `sudo installer -pkg sn360-desktop-agent-arm64.pkg -target /` |
| **Debian / Ubuntu** | `.deb` | `sudo apt install ./sn360-desktop-agent_*_amd64.deb` |
| **RHEL / Fedora** | `.rpm` | `sudo dnf install ./sn360-desktop-agent-*.x86_64.rpm` |

Download the latest packages from the release page or your SN360
provider's distribution endpoint.

After installing, deploy a feature profile as the agent config.
Profile templates use `${SN360_GATEWAY_URL}` as a placeholder —
you **must** replace it with your actual gateway address before
starting the agent:

**Linux:**

```bash
# Download the profile from the release page (or copy from the source
# tree's configs/ directory if building from source):
curl -o /tmp/profile-standard.yaml \
  https://<release-server>/configs/profile-standard.yaml

sudo cp /tmp/profile-standard.yaml /etc/sn360-desktop-agent/config.yaml
sudo sed -i 's|${SN360_GATEWAY_URL}|wss://gateway.example.com|' \
  /etc/sn360-desktop-agent/config.yaml
sudo systemctl enable --now sn360-desktop-agent
```

**Windows (PowerShell):**

```powershell
Invoke-WebRequest -Uri "https://<release-server>/configs/profile-standard.yaml" `
  -OutFile "${env:ProgramFiles}\SN360DesktopAgent\config.yaml"
(Get-Content "${env:ProgramFiles}\SN360DesktopAgent\config.yaml") `
  -replace '\$\{SN360_GATEWAY_URL\}', 'wss://gateway.example.com' |
  Set-Content "${env:ProgramFiles}\SN360DesktopAgent\config.yaml"
Restart-Service sn360-desktop-agent
```

For mass deployment via GPO, MDM, or configuration management, see
[`docs/msp-deployment.md`](./docs/msp-deployment.md).

## Feature profiles

SDA ships three pre-configured profiles that control which modules
are active:

| Profile | What it includes | Memory |
|---------|-----------------|--------|
| **Basic** | FIM, log collection, inventory, SCA, TRDS, active response | ~8-12 MB |
| **Standard** | Basic + EDR + network telemetry | ~20-30 MB |
| **Advanced** | Standard + DLP, identity monitoring, memory scanning, device control, MDM, host isolation, rootcheck, enhanced inventory (running software, browser extensions, SBOM) | ~40-60 MB |

Profile configs are in [`configs/`](./configs/). See
[`docs/feature-profiles.md`](./docs/feature-profiles.md) for details.

## Development

### Prerequisites

- **Rust 1.75+** (install via [rustup](https://rustup.rs/))
- **Linux:** `pkg-config`, `libssl-dev`, `libyara-dev` (or the
  equivalents for your distro)
- **macOS:** Xcode Command Line Tools, `brew install yara`
- **Windows:** Visual Studio Build Tools (MSVC), a prebuilt YARA
  for Windows
- **Cross-compilation:** [`cross`](https://github.com/cross-rs/cross)
  (`cargo install cross`)

YARA is a **required** runtime dependency of the Local Detection
Engine. Build hosts must have YARA development headers available.

### Building from source

```bash
# Clone the repository
git clone https://github.com/kennguy3n/sn360-desktop-agent.git
cd sn360-desktop-agent

# Debug build
make build

# Run the agent against a test config
cargo run --bin sda-agent -- --config ./tests/sda-test-config.yaml

# Release build (optimised for size)
make release
```

## Testing

```bash
# PR gate — lint + unit tests only (fast; what CI runs on every PR)
make test-pr

# Unit tests only
make test-unit

# Unit + per-crate integration tests (no Device Control E2E)
make test-integration

# All workspace tests including sda-agent E2E (legacy / backward compat)
make test

# All hermetic Device Control and EDR E2E suites
make test-e2e-all

# Full suite — unit + integration + all E2E + shell E2E + benchmarks
make test-full

# Individual E2E suites (hermetic, no external server required)
make e2e-device-control      # USB / removable-media policy + signed jobs
make e2e-software            # signed software catalogue
make e2e-jit-admin           # just-in-time admin lifecycle
make e2e-app-control         # binary authorisation (Monitor / Enforce)
make e2e-remote-support      # operator remote-support sessions
make e2e-management-compat   # Fleet GitOps → SDA AgentConfig translation
make e2e-device-policy       # closed-by-default device policy fallback
make e2e-mdm                 # auto-remediation, recovery escrow, OS patch
make e2e-mdm-actions         # remote wipe / lock / lost-mode
make e2e-mdm-profile         # config profile push + enforcement
make e2e-process-telemetry   # process create / terminate / image-load
make e2e-lde-hotreload       # TRDS hot-reload + Ed25519 verification
make e2e-network-telemetry   # TCP / UDP connections + DNS + IOC matching
make e2e-host-isolation      # IsolateHost / UnisolateHost
make e2e-memory-scan         # RWX memory scanning + in-memory YARA
make e2e-identity            # LSASS / shadow / kcore / keychain
make e2e-dlp                 # PII / PCI regex on FileCreated / FileModified

# Shell-based E2E (requires Docker)
make e2e              # Linux E2E against local SIEM manager
make e2e-compat       # Same suite against legacy 4.x manager
make security-e2e     # Security-focused scenarios

# Platform-specific E2E
make e2e-macos
make e2e-windows

# Lint only
make lint
```

See [`tests/README.md`](./tests/README.md) for harness details and
[`docs/benchmarks.md`](./docs/benchmarks.md) for the performance
budgets and current numbers.

### CI tiers

| Trigger | What runs | Speed |
|---|---|---|
| Every PR (non-docs) | `make lint` + `make test-unit` | Fast (~2 min) |
| PR with `ci:full` label | Above + `make test-integration` + `make test-e2e-all` + `make benchmark-ci` | Slow |
| Push to `main` or `develop` | Above + `make test-integration` + `make test-e2e-all` + `make benchmark-ci` | Slow |
| Manual dispatch | Above (toggle `run_full_suite` / `run_benchmark`) | Slow |

Docs-only changes (`docs/**`, `*.md`, `LICENSE`) skip CI entirely.
By default every PR runs only the fast lane. To run the full suite
+ benchmark on a PR, add the `ci:full` label — remove and re-add
it to re-trigger. Pushes to `main` and `develop` always run the
full lane.

## Architecture

```
+-------------------------------------------------------------+
|                       sda-agent (bin)                       |
+-------------------------------------------------------------+
|                        sda-core                             |
|   lifecycle | config | signals | module manager | power     |
+-------------------------------------------------------------+
|                     sda-event-bus                           |
|     bounded broadcast + server-bound mpsc + priorities      |
+-------------------------------------------------------------+
|  sda-fim  | sda-logcollector | sda-inventory | sda-sca   |  |
|  sda-active-response | sda-rootcheck | sda-local-detection |
|  sda-enhanced-inventory | sda-device-control | sda-mdm     |
|  sda-process-monitor | sda-network-monitor                 |
|  sda-host-isolation  | sda-comms                           |
|  sda-memory-scanner  | sda-identity-monitor | sda-dlp      |
+-------------------------------------------------------------+
|                        sda-pal                              |
|   FS watcher | log source | sysinfo | service | firewall    |
|   process monitor | network monitor | dns monitor           |
|   host isolation  | power monitor   | memory scanner        |
|   kernel channels (windows / macos / linux-ebpf)            |
+-------------------------------------------------------------+
|     Linux (inotify, journald, nftables, netlink,            |
|            cn_proc, /proc/net/*, /proc/<pid>/maps,          |
|            /proc/<pid>/mem, optional Aya eBPF kprobes)      |
|     macOS (FSEvents, OSLog, pfctl, IOKit,                   |
|            Endpoint Security, Network Extension,            |
|            task_for_pid + mach_vm_region,                   |
|            optional signed SystemExtension)                 |
|     Windows (ReadDirectoryChangesW, Event Log, SCM,         |
|              ETW Kernel-Process / Kernel-Network /          |
|              Threat-Intelligence / DNS-Client, WFP,         |
|              VirtualQueryEx + ReadProcessMemory,            |
|              optional WDK minifilter, optional AMSI)        |
+-------------------------------------------------------------+
```

See [`docs/architecture.md`](./docs/architecture.md) for the full
crate map, event flow, PAL traits, configuration schema, resource
budgets, and security model.

## Workspace layout

| Crate | Responsibility |
|---|---|
| `sda-agent` | Main binary — entry point, module orchestration, wire-format mapping |
| `sda-core` | Shared types, YAML config loading, agent lifecycle, power broadcast |
| `sda-pal` | Platform Abstraction Layer (filesystem, power, service, firewall, process / network / DNS / memory / kernel channels) |
| `sda-event-bus` | Async event bus with priority queues and back-pressure |
| `sda-comms` | Communication layer — SN360 native protocol (TLS 1.3, MessagePack, HTTP/2) and optional legacy SIEM protocol adapter |
| `sda-fim` | File Integrity Monitoring module |
| `sda-logcollector` | Log collection module (file, journald, Event Log, OSLog) |
| `sda-inventory` | System inventory module (packages, network, hardware, OS) |
| `sda-sca` | Security Configuration Assessment module |
| `sda-active-response` | Active response module |
| `sda-rootcheck` | Rootkit detection module |
| `sda-local-detection` | Local Detection Engine (Aho-Corasick + IOC bloom + YARA + offline queue) |
| `sda-enhanced-inventory` | Running software, browser extensions, CycloneDX SBOM |
| `sda-updater` | Self-update — signed-manifest poll, Ed25519 + pinned SHA-256 verification, atomic binary swap with `.bak` rollback on smoke-test failure |
| `sda-device-control` | Device Control router — `SignedActionJob` validation, Finding / Recommendation / ActionResult / EvidenceRecord, maintenance + quiet hours, and the USB / removable-media policy supervisor |
| `sda-mdm` | Desktop MDM — auto-remediation, recovery key escrow, OS patch, remote wipe / lock / lost-mode, declarative config profiles |
| `sda-query` | osquery sidecar wrapper — scheduled host queries with a bounded resource budget |
| `sda-posture` | Cross-platform device-posture snapshots (disk encryption, firewall, screen-lock, OS patch level) with delta + power-aware scheduling |
| `sda-agent-vitals` | Agent vitals — heartbeat, queue depth, watchdog faults emitted as `AgentVitals` events |
| `sda-software` | Software lifecycle — signed catalogue manifest verifier, approval-state surfacing, rollback orchestrator, chain-linked evidence emission |
| `sda-script-runner` | Bounded script runner — Ed25519-verified scripts, glob allow-list canonical names, hard wall-clock + output ceilings, `ScriptRunResult` + `EvidenceRecord` emission |
| `sda-jit-admin` | Just-in-Time admin lifecycle — grant state machine, on-disk store, revocation watchdog (timer / power / heartbeat-loss), boot-sweep, drift detector |
| `sda-remote-support` | Operator remote-support sessions — `Pending → ConsentRequested → Active → Ended` state machine, pluggable consent prompt, clean-room MeshCentral-style protocol (MessagePack frames + HKDF-SHA256 per-session keys) |
| `sda-app-control` | Binary authorisation — Ed25519-signed policy verification, Monitor / Enforce with single-step `DualControlRollback`, Windows WDAC + AppLocker, Linux dm-verity-aware backend, macOS Santa wrapper |
| `sda-management-compat` | Fleet GitOps YAML → SDA `AgentConfig` translation shim. Library-only; zero runtime footprint |
| `sda-process-monitor` | Process telemetry — subscribes to `sda-pal::ProcessMonitor` (cn_proc / ETW / Endpoint Security), enriches each event with the parent chain, emits `ProcessCreated` / `ProcessTerminated` / `ImageLoaded` |
| `sda-network-monitor` | Network + DNS telemetry — subscribes to `sda-pal::NetworkMonitor` and `sda-pal::DnsMonitor`, runs a bounded dedup ring and a per-second UDP flow sampler, emits `NetworkConnection` and `DnsQuery` |
| `sda-host-isolation` | Network containment — consumes `IsolateHost` / `UnisolateHost` `SignedActionJob`s, builds the allow-list, invokes `sda-pal::HostIsolation`, emits `HostIsolationStateChanged` |
| `sda-memory-scanner` | Periodic RWX-region scanner — calls `sda-pal::MemoryScanner`, runs in-memory YARA, enforces self-pid exclusion, idle-CPU gates, optional Windows AMSI provider, emits `MemoryScanAlert` |
| `sda-identity-monitor` | Identity-attack detector — LSASS access (Windows, `T1003.001`), `/etc/shadow` and `/proc/kcore` (Linux, `T1003.008` / `T1003`), keychain access by non-Apple-signed binaries (macOS, `T1555.001`); system-principal filtering at the publish boundary; emits `IdentityAlert` |
| `sda-dlp` | DLP content inspector — regex PII (`pii.ssn`, `pii.uk_ni`) + PCI (`pci.pan_luhn`) scanner over `FileCreated` / `FileModified`; redaction-safe output (no matched bytes — only category, byte offset, length, Blake3 fingerprint); Monitor publishes `medium`, Enforce escalates to `high`; emits `LocalDetectionAlert` with `rule_type: "dlp"` |

## Cross-compilation

Build for all supported targets using `cross`:

```bash
make all-targets
```

| Target | Platform |
|---|---|
| `x86_64-unknown-linux-gnu` | Linux x86_64 (glibc) |
| `x86_64-unknown-linux-musl` | Linux x86_64 (static, musl) |
| `aarch64-unknown-linux-gnu` | Linux ARM64 |
| `x86_64-apple-darwin` | macOS Intel |
| `aarch64-apple-darwin` | macOS Apple Silicon |
| `x86_64-pc-windows-msvc` | Windows x86_64 |

## Configuration

SDA uses YAML configuration files. See the test configs for
working examples:

- [`tests/sda-test-config.yaml`](./tests/sda-test-config.yaml) — Linux
- [`tests/sda-test-config-macos.yaml`](./tests/sda-test-config-macos.yaml) — macOS
- [`tests/sda-test-config-windows.yaml`](./tests/sda-test-config-windows.yaml) — Windows

The full configuration schema lives in
[`docs/configuration-reference.md`](./docs/configuration-reference.md).

## Documentation

| Document | Purpose |
|---|---|
| [`docs/user-guide.md`](./docs/user-guide.md) | Per-host install, enrolment, troubleshooting |
| [`docs/admin-guide.md`](./docs/admin-guide.md) | Fleet deployment, module tuning, upgrades, legacy migration |
| [`docs/architecture.md`](./docs/architecture.md) | Crate map, event flow, PAL design, protocol details, resource budgets, security model |
| [`docs/configuration-reference.md`](./docs/configuration-reference.md) | Full YAML schema reference |
| [`docs/edr.md`](./docs/edr.md) | EDR module reference — FIM, process / network / DNS telemetry, host isolation, memory scanning, identity, DLP |
| [`docs/device-control.md`](./docs/device-control.md) | Device Control architecture and lifecycle |
| [`docs/desktop-mdm.md`](./docs/desktop-mdm.md) | Desktop MDM architecture and lifecycle |
| [`docs/kernel-drivers.md`](./docs/kernel-drivers.md) | Optional kernel-mode telemetry — WDK minifilter, SystemExtension, eBPF |
| [`docs/wire-protocols/device-control.md`](./docs/wire-protocols/device-control.md) | Canonical Device Control wire schemas |
| [`docs/security.md`](./docs/security.md) | Threat model, crypto posture, dependency audit, fuzzing, clean-room policy |
| [`docs/licensing.md`](./docs/licensing.md) | Licensing posture and clean-room interoperability statement |
| [`docs/integration.md`](./docs/integration.md) | Integration with the SN360 Security Platform |
| [`docs/platform-testing.md`](./docs/platform-testing.md) | CI matrix and manual procedures |
| [`docs/release-process.md`](./docs/release-process.md) | Release runbook |
| [`docs/benchmarks.md`](./docs/benchmarks.md) | Performance budgets and current numbers |
| [`docs/feature-profiles.md`](./docs/feature-profiles.md) | Tiered feature profiles (Basic / Standard / Advanced) |
| [`docs/msp-deployment.md`](./docs/msp-deployment.md) | MSP / MSSP mass deployment guide (GPO, SCCM, MDM, apt/yum) |
| [`docs/agent-shared-patterns.md`](./docs/agent-shared-patterns.md) | Cross-agent shared patterns and crate mapping |
| [`CHANGELOG.md`](./CHANGELOG.md) | Release notes |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | Branching, commits, tests, code review |
| [`SECURITY.md`](./SECURITY.md) | Reporting a vulnerability |

## Related repositories

| Repo | Purpose |
|---|---|
| [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform) | Multi-tenant control plane (Gateway, TRDS, IOCFS, SIS, alert-forwarder) |
| [`sn360-desktop-agent`](https://github.com/kennguy3n/sn360-desktop-agent) | Endpoint agent (Windows / Linux / macOS) — this repo |
| [`sn360-agent-vm`](https://github.com/kennguy3n/sn360-agent-vm) | Server / VM agent |
| [`sn360-agent-k8s`](https://github.com/kennguy3n/sn360-agent-k8s) | Kubernetes agent |

## License

SN360 Proprietary — see [`LICENSE`](./LICENSE) for the full
license terms. Copyright (c) 2026 SN360 Inc. All rights reserved.
For licensing inquiries, contact
[licensing@sn360.com](mailto:licensing@sn360.com). See
[`docs/licensing.md`](./docs/licensing.md) for the licensing
posture and clean-room interoperability statement.
