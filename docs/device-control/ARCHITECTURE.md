# ShieldNet Device Control — Architecture

> **Version:** 0.1 | **Date:** May 2026 | **Status:** Planning
> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)

This document is the architecture reference for the Device Control
module. It is intentionally narrower than [PROPOSAL.md](./PROPOSAL.md) —
that document captures the design rationale; this one captures the
target shape of the code as it will be when Phases 0–5 are merged.

> **Scope note:** Device Control spans the agent (this repository) and
> the SN360 control plane
> ([`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)).
> Sections 1–8, 10 below describe agent-side shape. Section 4's NATS
> subject hierarchy and the control-plane interaction surface are
> included for cross-reference; the corresponding code lives in
> `sn360-security-platform`, not here.

---

## Table of contents

1. [Crate map](#1-crate-map)
2. [Event flow](#2-event-flow)
3. [Data model](#3-data-model)
4. [Protocol extension](#4-protocol-extension)
5. [PAL additions](#5-pal-additions)
6. [Configuration schema](#6-configuration-schema)
7. [Resource budgeting](#7-resource-budgeting)
8. [Security model](#8-security-model)
9. [Open-source engine policy](#9-open-source-engine-policy)
10. [Module startup order](#10-module-startup-order)
11. [Further reading](#11-further-reading)

---

## 1. Crate map

| Crate                   | Responsibility                                                                                          |
|-------------------------|---------------------------------------------------------------------------------------------------------|
| `sda-device-control`    | Owns the Device Control event surface; receives signed jobs; publishes findings and action results.    |
| `sda-query`             | osquery-compatible declarative query engine. Sidecar-based by default, embedded later if budget allows. |
| `sda-policy`            | Evaluates query results + posture + inventory deltas into `Finding`s.                                   |
| `sda-posture`           | Live device-posture snapshots: disk encryption, firewall, screen lock, OS patch level.                  |
| `sda-software`          | Approved software catalogue client; install / update / uninstall via `PackageManager` PAL trait.        |
| `sda-jit-admin`         | Just-in-Time admin/root grant + revocation watchdog + drift detection.                                  |
| `sda-script-runner`     | Signed-script executor with hard-coded allow-list and bounded execution.                                |
| `sda-app-control`       | Application control (monitor → enforce) wrapping Santa, WDAC, Linux equivalents.                         |
| `sda-remote-support`    | Operator-initiated, user-consented remote support sessions; clean-room MeshCentral-style protocol.      |
| `sda-agent-vitals`      | Agent-self telemetry: heartbeat, queue depth, last-seen, watchdog faults.                                |
| `sda-management-compat` | Translation shim for Fleet-flavoured GitOps YAML so existing customers can adopt SDA.                   |

The crate layering is identical to existing SDA conventions:
`sda-agent` depends on every Device Control crate; each Device Control
crate depends on `sda-core` / `sda-event-bus` / `sda-pal` /
`sda-comms`; no Device Control crate depends on any other Device
Control crate except via the event bus.

---

## 2. Event flow

```
+--------------------------------------------------------------+
|                       sda-agent (bin)                        |
|                                                              |
|  +-------------------+    Event Bus (sda-event-bus)          |
|  | sda-query         |---+                                    |
|  +-------------------+   |                                    |
|  | sda-policy        |---+                                    |
|  +-------------------+   |   +----------+    +--------+       |
|  | sda-posture       |---+==>| Router   |==> | Comms  |======>  Manager
|  +-------------------+   |   | (main.rs)|    | (TLS+  |       |  (SN360 Control
|  | sda-software      |---+   +----------+    |  HTTP/2|       |   Plane: Risk
|  +-------------------+   |        ^          |  + Msg-|       |   Engine, SMI,
|  | sda-jit-admin     |---+        |          |  Pack) |       |   Action Orch,
|  +-------------------+   |        |          +--------+       |   Approval Svc,
|  | sda-script-runner |---+        |              ^            |   Package Catalog,
|  +-------------------+   |        |              |            |   Evidence Vault)
|  | sda-app-control   |---+        |              | inbound:   |
|  +-------------------+   |        |              | SignedJob  |
|  | sda-remote-support|---+        |              | DeviceCtrlJob
|  +-------------------+   |        |              v            |
|  | sda-agent-vitals  |---+   +-------------------------+      |
|  +-------------------+   |   | sda-device-control       |     |
|  | existing modules  |---+   | (signed-job validation,  |     |
|  | (fim, inv, sca,   |       |  fan-out to sub-modules) |     |
|  | lde, ar, ...)     |       +-------------------------+      |
|  +-------------------+                                         |
+--------------------------------------------------------------+
```

The `sda-device-control` crate sits at the boundary between the comms
inbound channel and the rest of the Device Control surface. Inbound
`DeviceControlJob` frames are validated (see § 4.3) once and only
once, then dispatched to the relevant sub-module on the bus.

### 2.1 New `EventKind` variants

`sda-core::EventKind` gains the following variants. Every variant is
produced by exactly one module and consumed by `sda-comms` (and, where
relevant, by `sda-active-response`):

```rust
pub enum EventKind {
    // ... existing variants ...
    DeviceControlFinding(Finding),
    DeviceControlRecommendation(Recommendation),
    DeviceControlActionResult(ActionResult),
    DevicePostureState(PostureSnapshot),
    SoftwareInventoryDelta(SoftwareInventoryDelta),
    SoftwareJobResult(SoftwareJobResult),
    JitAdminRequested(JitAdminRequested),
    JitAdminGranted(JitAdminGranted),
    JitAdminRevoked(JitAdminRevoked),
    QueryResult(QueryResult),
    ScriptRunResult(ScriptRunResult),
    RemoteSupportSessionStarted(RemoteSupportSessionStarted),
    RemoteSupportSessionEnded(RemoteSupportSessionEnded),
    AgentVitals(AgentVitals),
    EvidenceRecord(EvidenceRecord),
}
```

Per the existing repo invariant, every new `EventKind` variant must
also have an explicit arm in `WazuhMessage::encode_body()` (see
[`crates/sda-comms/src/protocol.rs`](../../crates/sda-comms/src/protocol.rs))
when the optional `legacy-siem` Cargo feature is on; fall-through to
the catch-all is forbidden.

---

## 3. Data model

### 3.1 `SignedActionJob`

```rust
pub struct SignedActionJob {
    pub job_id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub recommendation_id: Option<Uuid>,
    pub action: ActionKind,
    pub args: serde_json::Value,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub signature: Vec<u8>,   // Ed25519 over the canonical encoding.
    pub key_id: String,       // Rotation-aware key identifier.
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    InstallPackage,
    UpdatePackage,
    UninstallPackage,
    GrantJitAdmin,
    RevokeAdmin,
    RunScript,
    PushAppControlPolicy,
    StartRemoteSupport,
    EndRemoteSupport,
    QueryAdHoc,
}
```

The `args` field is `serde_json::Value` on the wire but is parsed
against an `ActionKind`-specific strict struct before any side effect
runs. Unknown fields are rejected.

### 3.2 `EvidenceRecord`

```rust
pub struct EvidenceRecord {
    pub evidence_id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub job_id: Uuid,
    pub recommendation_id: Option<Uuid>,
    pub action: ActionKind,
    pub args_canonical: String,   // Canonical JSON encoding of args.
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub status: ActionStatus,
    pub exit_code: Option<i32>,
    pub output_sha256: [u8; 32],
    pub platform: Platform,
    pub agent: AgentVersion,
    pub signature: Vec<u8>,       // Ed25519 by the agent's evidence key.
    pub key_id: String,
}
```

`output_sha256` is a hash of the bounded captured output; the raw
output bytes are streamed through `sda-comms` separately and stored
in the Evidence Vault under the same `evidence_id`.

### 3.3 `Finding` / `Recommendation` / `Result` schemas

```rust
pub struct Finding {
    pub finding_id: Uuid,
    pub device_id: Uuid,
    pub tenant_id: Uuid,
    pub kind: FindingKind,            // PermanentAdmin, OutdatedApp, ...
    pub severity: Severity,
    pub plain_english: String,
    pub evidence: serde_json::Value,
    pub observed_at: DateTime<Utc>,
}

pub struct Recommendation {
    pub recommendation_id: Uuid,
    pub tenant_id: Uuid,
    pub device_ids: Vec<Uuid>,
    pub finding_ids: Vec<Uuid>,
    pub action: ActionKind,
    pub plain_english: String,
    pub one_click: bool,
    pub created_at: DateTime<Utc>,
}

pub struct ActionResult {
    pub job_id: Uuid,
    pub device_id: Uuid,
    pub status: ActionStatus,         // Success, Failure, Refused, Skipped.
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub exit_code: Option<i32>,
    pub output: String,
    pub evidence_id: Uuid,
}
```

---

## 4. Protocol extension

### 4.1 New `MessageType` variants

`sda-comms::MessageType` gains:

```rust
pub enum MessageType {
    // ... existing variants ...
    DeviceControlFinding,
    DeviceControlRecommendation,
    DeviceControlJob,
    DeviceControlActionResult,
    DevicePostureState,
    SoftwareInventoryDelta,
    SoftwareJobResult,
    JitAdminRequested,
    JitAdminGranted,
    JitAdminRevoked,
    QueryResult,
    ScriptRunResult,
    RemoteSupportSessionStarted,
    RemoteSupportSessionEnded,
    AgentVitals,
    EvidenceRecord,
}
```

Every variant has an explicit encoder arm in `protocol.rs` and a
corresponding mapping in `sda-agent::main::map_event_to_message`.

### 4.2 NATS subject hierarchy

The control plane consumes Device Control traffic on the
`device_control.*` tree:

```
device_control.findings.<tenant_id>.<device_id>
device_control.recommendations.<tenant_id>
device_control.jobs.<tenant_id>.<device_id>
device_control.action_results.<tenant_id>.<device_id>
device_control.posture.<tenant_id>.<device_id>
device_control.software.delta.<tenant_id>.<device_id>
device_control.jit_admin.<tenant_id>.<device_id>
device_control.queries.<tenant_id>.<device_id>
device_control.scripts.<tenant_id>.<device_id>
device_control.remote_support.<tenant_id>.<device_id>
device_control.vitals.<tenant_id>.<device_id>
device_control.evidence.<tenant_id>.<device_id>
```

The agent does not connect to NATS directly; the Agent Gateway (in
`sn360-security-platform`) translates between the agent's native
protocol frames and the NATS topology.

### 4.3 Signed-job validation (10-step checklist)

Before any `SignedActionJob` produces a side effect, the agent runs:

1. Verify the message frame decoded successfully under TLS 1.3 +
   HTTP/2 + MessagePack.
2. Parse `SignedActionJob` strictly (deny unknown fields).
3. Look up `key_id` against the locally pinned rotation set.
4. Verify the Ed25519 signature over the canonical encoding.
5. Reject if `not_before` is in the future or `not_after` in the
   past, with ≤ 60 s clock-skew tolerance.
6. Reject if `tenant_id` does not match the agent's enrolled tenant.
7. Reject if `device_id` does not match the agent's local identity.
8. Reject if `action` is not in the locally compiled allow-list for
   the agent's current pricing tier.
9. Apply `modules.device_control.windows` (maintenance + quiet hours).
10. Hand off to the relevant sub-module with a deadline and a budget.

Steps 2–8 produce a `JobRefused` event with a structured reason on
failure; the user-facing UI uses these reasons verbatim.

---

## 5. PAL additions

`sda-pal` exposes five new traits, with per-OS implementations
selected at compile time via `cfg`. The trait surface is:

```rust
pub trait PackageManager: Send + Sync {
    fn list_installed(&self) -> Result<Vec<InstalledPackage>>;
    fn install(&self, package: &PackageRef, opts: &InstallOpts) -> Result<()>;
    fn update(&self, package: &PackageRef) -> Result<()>;
    fn uninstall(&self, package: &PackageRef) -> Result<()>;
}

pub trait AdminManager: Send + Sync {
    fn list_admins(&self) -> Result<Vec<AdminAccount>>;
    fn grant_admin(&self, user: &UserRef, until: DateTime<Utc>) -> Result<GrantHandle>;
    fn revoke_admin(&self, handle: &GrantHandle) -> Result<()>;
    fn observed_grants(&self) -> Result<Vec<GrantHandle>>;
}

pub trait DevicePostureProvider: Send + Sync {
    fn snapshot(&self) -> Result<PostureSnapshot>;
}

pub trait AppControlProvider: Send + Sync {
    fn current_mode(&self) -> Result<AppControlMode>;
    fn apply_policy(&self, policy: &SignedAppControlPolicy) -> Result<()>;
}

pub trait RemoteSupportProvider: Send + Sync {
    fn start_session(&self, params: &SessionParams) -> Result<SessionHandle>;
    fn end_session(&self, handle: &SessionHandle) -> Result<()>;
}
```

### 5.1 Per-platform implementation matrix

| Trait                    | Windows                                                        | macOS                                                         | Linux                                                                  |
|--------------------------|----------------------------------------------------------------|---------------------------------------------------------------|-------------------------------------------------------------------------|
| `PackageManager`         | `winget` CLI wrapper (Microsoft Store source).                 | Munki-style local repo (clean-room).                          | `apt` / `dnf` / `yum` / `zypper` auto-detect.                           |
| `AdminManager`           | `Administrators` group via `NetLocalGroup*` Win32 APIs.         | `admin` group via Open Directory APIs.                         | `wheel` / `sudo` group + time-boxed `sudoers.d` drop-in via `visudo`.   |
| `DevicePostureProvider`  | BitLocker, Defender Firewall, screen-lock policy, WSUS state.   | FileVault, Application Firewall, screen-lock, OS patch level. | LUKS, `firewalld` / `nftables`, screen-lock, package update freshness.  |
| `AppControlProvider`     | WDAC + AppLocker via PowerShell + signed policies.              | Santa / North Pole Santa.                                      | Clean-room dm-verity-aware enforcement (Phase 4).                       |
| `RemoteSupportProvider`  | Windows-side capture via WGC + DDA/PCoIP-style transport.       | macOS-side capture via ScreenCaptureKit-style API.             | Wayland / X11 capture via PipeWire / XCB; only with explicit consent.    |

All providers run inside SDA's existing privilege-separated module
process boundary; no new privileged process is introduced by Device
Control.

---

## 6. Configuration schema

`AgentConfig` gains the following sections; defaults are off so a
Device-Control-disabled agent has zero new behaviour:

```yaml
modules:
  device_control:
    enabled: true
    windows:
      maintenance:
        timezone: "America/Los_Angeles"
        allow:
          - { day: "tue", start: "02:00", end: "04:00" }
          - { day: "thu", start: "02:00", end: "04:00" }
      quiet_hours:
        deny:
          - { day: "mon-fri", start: "09:00", end: "17:00" }
    job_budget:
      max_concurrent: 1
      max_duration_secs: 600
      max_output_bytes: 1048576

  query:
    enabled: true
    osquery:
      mode: "sidecar"        # sidecar | embedded (Phase 1 = sidecar)
      socket: "/var/run/sda-osquery.sock"
      sidecar_budget:
        max_rss_mb: 60
        max_cpu_percent: 5
    schedule_poll_secs: 30

  posture:
    enabled: true
    interval_secs: 300

  software:
    enabled: true
    catalogue:
      url: "${sn360_gateway}/v1/catalogue"
      pinned_sha256: ["..."]
    package_manager:
      windows: "winget"
      macos:   "munki-style"
      linux:   "auto"        # auto | apt | dnf | yum | zypper
    cache_dir: "/var/cache/sn360-desktop-agent/software"

  jit_admin:
    enabled: false
    max_grant_minutes: 240
    revoke_on:
      - "logout"
      - "suspend"
      - "heartbeat_loss_secs:120"

  script_runner:
    enabled: true
    allow_only_signed: true
    max_duration_secs: 90
    allowlist:
      - "sn360.diagnostics.*"
      - "sn360.software.preflight.*"

  app_control:
    enabled: false
    mode: "monitor"          # monitor | enforce

  remote_support:
    enabled: false
    require_user_consent: true
    max_session_minutes: 30

updater:
  targets:
    agent:
      channel: "stable"
    osquery:
      channel: "stable"
    provider_bundles:
      channel: "stable"
```

The full field reference is mirrored in
[`docs/configuration-reference.md`](../configuration-reference.md)
when the corresponding code lands.

---

## 7. Resource budgeting

### 7.1 Existing budgets are inviolable

| Metric                | Existing target | Device Control rule                                                          |
|-----------------------|-----------------|------------------------------------------------------------------------------|
| Idle RSS              | < 15 MB         | Disabled-by-default modules contribute zero idle RSS.                         |
| Idle CPU              | < 0.1 %         | No new periodic timers in idle when modules are disabled.                     |
| FIM scan peak CPU     | < 3 %           | Device Control uses `PowerMonitor::current_profile()` to defer heavy work.    |
| Binary size           | < 7 MB          | Modules behind Cargo features where the size impact is non-trivial (Phase 4). |

### 7.2 Sidecar budget

| Sidecar                               | Max RSS | Max CPU (idle) | Notes                                                       |
|---------------------------------------|---------|----------------|-------------------------------------------------------------|
| `osquery` (Phase 1 default)           | 60 MB   | 5 %            | Spawned only when `modules.query.osquery.mode = "sidecar"`. |
| `winget` invocation (Windows)         | n/a     | n/a            | Short-lived; budget enforced via job timer.                  |
| `munki-style` invocation (macOS)      | n/a     | n/a            | Short-lived; budget enforced via job timer.                  |
| `apt` / `dnf` / `zypper` (Linux)      | n/a     | n/a            | Short-lived; budget enforced via job timer.                  |

### 7.3 Event priority assignments

| EventKind                              | Priority |
|----------------------------------------|----------|
| `DeviceControlFinding`                 | Normal   |
| `DeviceControlRecommendation`          | Normal   |
| `DeviceControlActionResult`            | High     |
| `DevicePostureState`                   | Low      |
| `SoftwareInventoryDelta`               | Low      |
| `SoftwareJobResult`                    | High     |
| `JitAdminRequested/Granted/Revoked`    | High     |
| `QueryResult`                          | Normal   |
| `ScriptRunResult`                      | High     |
| `RemoteSupportSessionStarted/Ended`    | High     |
| `AgentVitals`                          | Low      |
| `EvidenceRecord`                       | High     |

These priorities flow into `sda-event-bus`'s existing priority queue
without any new infrastructure.

---

## 8. Security model

### 8.1 Threats and controls

| Threat                                                        | Control                                                                                       |
|---------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| Compromised control-plane account issues malicious job        | Ed25519 signature + key rotation + per-action allow-list + maintenance-window enforcement.    |
| Compromised agent forwards forged Findings                    | Existing mTLS enrolment + signed agent identity; control plane treats Findings as advisory.   |
| Script runner used to execute arbitrary code                  | Hard-coded allow-list, signed-script requirement, exec budget.                                 |
| Package install used to install malware                       | Signed catalogue manifest, pinned SHA-256 per artefact, no out-of-catalogue installs.          |
| JIT admin not revoked                                         | Watchdog + drift detection + heartbeat-loss revoke + idempotent revoke on next boot.           |
| Remote support eavesdrops on user                             | User consent banner always visible; session time-bounded; clean-room protocol audited.         |
| App control false positives lock out user                     | Monitor mode default; enforce mode requires explicit tenant opt-in + dual-control rollback.    |
| Multi-tenant data leakage                                     | Existing Postgres RLS + per-tenant signing keys + agent-side `tenant_id` validation.           |
| Tampered agent binary                                         | Existing tamper protection (Phase 5); Device Control modules added behind the same checks.     |
| Privilege escalation via PAL provider                         | All PAL implementations run inside SDA's existing privilege-separated module process boundary. |

### 8.2 Script runner restrictions

- **Signed only.** Scripts not signed by a pinned key are rejected.
- **Allow-list namespace.** Only scripts whose canonical name matches
  `modules.script_runner.allowlist`.
- **Bounded execution.** Hard wall-clock, output-byte, and CPU
  limits.
- **No interactive shells.** No PTY, no stdin, no environment
  inheritance beyond an explicit allow-list.
- **Evidence-mandatory.** Every script run produces a
  `ScriptRunResult` and an `EvidenceRecord`.

### 8.3 Package installation restrictions

- **Catalogue-only.** Installs only from the signed catalogue.
- **Pinned SHA-256.** Mismatch ⇒ refuse + `JobRefused`.
- **Maintenance-window-gated.** Outside the window the job is queued.
- **Rollback path.** Updates record the previous version.
- **No silent uninstall.** Uninstalls require `one_click=false`
  unless the tenant has explicitly opted in.

### 8.4 Signed-job validation

See § 4.3 for the 10-step checklist. The validator is implemented
once in `sda-device-control::router` and is the only entry point
for signed jobs into the agent.

---

## 9. Open-source engine policy

This table directly governs which external engines each PAL
implementation targets. Implementation posture is captured per row so
engineers know whether to integrate, wrap, or clean-room re-implement
each engine.

| #  | Area                                  | Recommended engine                                                              | Implementation posture                                                                 |
|----|---------------------------------------|---------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| 1  | Declarative queries                   | osquery (Apache-2.0 / GPL-2.0 dual; we consume Apache-2.0)                      | Integrate as a sidecar; talk over the local Thrift/JSON socket.                         |
| 2  | Compliance / monitoring agent         | Wazuh                                                                            | Already integrated upstream of SDA; reuse via existing PAL.                             |
| 3  | Windows package management            | WinGet                                                                           | Wrap the `winget` CLI from `sda-software`; signed-job-gated.                            |
| 4  | macOS package management              | Munki-style approach                                                             | Clean-room re-implementation in `sda-software`; reference design only, no Munki code.    |
| 5  | Linux package management              | `apt` / `dnf` / `yum` / `zypper`                                                | Wrap native CLIs from `sda-software`; signed-job-gated.                                  |
| 6  | Just-in-Time admin (Windows)          | MakeMeAdmin-style flow (original is GPL — not redistributed)                    | Clean-room re-implementation in `sda-jit-admin`.                                         |
| 7  | Just-in-Time admin (macOS)            | SAP Privileges-style flow                                                        | Clean-room re-implementation in `sda-jit-admin`.                                         |
| 8  | App control                           | Santa / North Pole Santa (Apache-2.0)                                            | Integrate Santa on macOS; clean-room WDAC equivalent on Windows; clean-room on Linux.    |
| 9  | Remote support                        | MeshCentral-style protocol (original is Apache-2.0)                              | Clean-room re-implementation in `sda-remote-support`; no MeshCentral source vendored.    |
| 10 | Mobile management — Android           | Android Management API + Headwind reference                                     | Control-plane integration only; agent does not run on Android.                          |
| 11 | Mobile management — Apple             | Apple MDM / DDM + NanoMDM reference                                              | Control-plane integration only; agent does not run on iOS/macOS as MDM client.           |
| 12 | Mobile management — ChromeOS          | Chrome Policy / Chrome Management APIs                                           | Control-plane integration only.                                                          |
| 13 | RMM benchmarking                      | **Tactical RMM**                                                                 | **Benchmark only — do not use as base.** License restricts SaaS / commercial use.        |

---

## 10. Module startup order

The `sda-agent` binary brings up Device Control modules in the
following order. Each step is independently observable via
`AgentVitals` so a mis-ordered start fails loudly:

```
1.  sda-core: load AgentConfig, derive feature flags.
2.  sda-pal: select per-OS providers (PackageManager, AdminManager,
    DevicePostureProvider, AppControlProvider, RemoteSupportProvider).
3.  sda-event-bus: bring up bus with new priority assignments.
4.  sda-comms: open native protocol session and register Device
    Control MessageType arms.
5.  sda-agent-vitals: start heartbeat (low-priority, always on).
6.  sda-posture: subscribe to power profile, schedule snapshots.
7.  sda-query: start scheduler; spawn osquery sidecar if configured.
8.  sda-policy: subscribe to query results + posture + inventory.
9.  sda-device-control: subscribe to inbound jobs; wire signed-job
    validation pipeline.
10. sda-software / sda-jit-admin / sda-script-runner: lazy-init only
    after first inbound job they would handle (Phases 2–3).
11. sda-app-control / sda-remote-support: lazy-init under explicit
    enable + tenant authorisation (Phase 4).
```

---

## 11. Further reading

- [PROPOSAL.md](./PROPOSAL.md) — full technical proposal.
- [PHASES.md](./PHASES.md) — phased delivery plan + risk register.
- [PROGRESS.md](./PROGRESS.md) — delivery log.
- Parent [`docs/architecture.md`](../architecture.md) — current SDA
  crate map, event flow, and protocol details.
- Parent [`device-agent-proposal.md`](../../device-agent-proposal.md) —
  original SDA architecture & implementation proposal.
- Parent [`docs/revised-phase-plan.md`](../revised-phase-plan.md) —
  Phases 7–9 (native protocol promotion, full control plane, legacy
  deprecation).
