# Technical Proposal: ShieldNet Device Control

> **Version:** 0.1 | **Date:** May 2026 | **Status:** Planning
> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)
> **Target Platforms:** Windows 10/11, macOS 12+, Linux (Ubuntu/Fedora/Arch)

> **Scope note:** ShieldNet Device Control spans both the agent
> (`sn360-desktop-agent`, this repository) and the SN360 control plane
> (`sn360-security-platform`). This proposal covers the design end to
> end so the two repositories can be built in lockstep, but only the
> *agent-side* sections (§§ 5–6, 8, 10–12, 14–15, 18) are implemented in
> this repository. Control-plane sections (§ 7 and the ⚙️-tagged tasks
> in § 19) are implemented in
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).

---

## Table of Contents

1. [Executive decision](#1-executive-decision)
2. [Product scope](#2-product-scope)
3. [Existing repository fit](#3-existing-repository-fit)
4. [What to port from Fleet](#4-what-to-port-from-fleet)
5. [Target architecture](#5-target-architecture)
6. [New SDA crates](#6-new-sda-crates)
7. [Control-plane services](#7-control-plane-services)
8. [Data model](#8-data-model)
9. [Core capabilities](#9-core-capabilities)
10. [Native protocol extension](#10-native-protocol-extension)
11. [Agent configuration extension](#11-agent-configuration-extension)
12. [PAL additions](#12-pal-additions)
13. [SMI scoring model](#13-smi-scoring-model)
14. [Security model](#14-security-model)
15. [Performance and optimisation](#15-performance-and-optimisation)
16. [Evidence and audit model](#16-evidence-and-audit-model)
17. [MSP and pricing alignment](#17-msp-and-pricing-alignment)
18. [Repository implementation plan](#18-repository-implementation-plan)
19. [Roadmap](#19-roadmap)
20. [Open-source and platform engine policy](#20-open-source-and-platform-engine-policy)
21. [Risk register](#21-risk-register)
22. [Final recommendation](#22-final-recommendation)

---

## 1. Executive decision

ShieldNet 360 already ships an endpoint security agent (SDA) that does
file integrity monitoring, log collection, inventory, SCA, rootcheck,
on-device detection, active response, and CycloneDX SBOM generation.
What it does not do — and what every SME customer asks for next — is
**device management**: see who has admin, push approved software, fix
out-of-date apps, grant temporary admin rights, and prove the change
happened.

This proposal turns that into a first-class product surface called
**ShieldNet Device Control**. The decision is to deliver it as:

- **SDA-native Rust modules** for everything that runs on the
  endpoint, reusing SDA's PAL, event bus, comms, and updater.
- **SN360 control-plane services** (in
  [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform))
  for everything that runs server-side.
- **No Fleet code merge.** We port concepts, not source.
- **No GPL/AGPL/LGPL dependencies** in the agent; clean-room
  re-implementations for any reference design that is copyleft.
- **No full RMM/MDM scope.** MVP ships the *found → fix → evidence
  → SMI* loop and nothing else.

The product targets SDA's existing resource budgets — idle RSS
< 15 MB, idle CPU < 0.1 %, FIM scan peak < 3 % — without regression.
Anything that would break those budgets is implemented as a sidecar
under its own budget.

---

## 2. Product scope

### 2.1 Product promise

SME-first device management:

> Found issue → plain-English risk → one-click fix → audit evidence
> → SMI improvement.

If a candidate capability does not start at "found issue" and end at
"SMI improvement", it does not ship in MVP.

### 2.2 Customer-facing examples

| # | Example                  | Plain-English risk                                                       | One-click fix                                                  |
|---|--------------------------|--------------------------------------------------------------------------|----------------------------------------------------------------|
| 1 | **6 permanent admins**   | "6 users have permanent admin/root rights — risky on shared laptops."    | Demote to standard, enrol in JIT admin.                        |
| 2 | **12 outdated apps**     | "12 apps haven't been updated in over 60 days — known CVEs apply."       | Patch via the approved package catalogue during a window.      |
| 3 | **4 missing laptops**    | "4 laptops haven't checked in for 14+ days — possibly lost."             | Mark as missing; require remote support session on next check-in. |
| 4 | **Unknown software**     | "Software not on your approved list was installed on 3 devices."         | Flag, request approval, optionally uninstall.                  |
| 5 | **User needs admin**     | "User X is asking for admin access to install Tool Y."                   | Grant time-boxed JIT admin with auto-revocation + evidence.    |

### 2.3 Product boundary

**Build first**

- Device inventory (hardware / OS / patch / installed software).
- Local admin & root account inventory + plain-English findings.
- Software inventory + stale / unapproved / vulnerable flags.
- Approved package catalogue with one-click install / update /
  uninstall on Windows / macOS / Linux.
- Just-in-Time admin / root with approval workflow + auto-revocation.
- Evidence records for every action.
- SMI sub-scores fed by Device Control findings.

**Integrate later**

- App control (Santa-style allow / deny on macOS, WDAC on Windows).
- Remote support / screen sharing.
- Mobile MDM (Android Management API, Apple MDM/DDM, Chrome).
- Multi-tenant MSP-shaped operations.
- Generic ad-hoc script execution (signed-only, narrow scope).

**Avoid initially**

- Full RMM parity with Tactical RMM, NinjaOne, N-able.
- Full MDM parity with Jamf, Kandji, Intune, ABE.
- General-purpose remote shell.
- Cross-tenant data sharing.
- Any kernel extension on macOS we did not author.

---

## 3. Existing repository fit

### 3.1 Current SDA baseline

SDA today (Phases 1–6 complete) ships:

- A Rust workspace under `crates/sda-*` with the modules listed in
  [`docs/architecture.md`](../architecture.md#1-crate-map).
- A `tokio` async runtime, a bounded priority event bus
  (`sda-event-bus`), and the SN360 native protocol over TLS 1.3 +
  HTTP/2 + MessagePack (`sda-comms`).
- A YAML configuration model (`sda-core::config`).
- A platform abstraction layer (`sda-pal`) with per-OS
  implementations selected at compile time.
- A signed self-update mechanism (`sda-updater`).
- Privilege separation, tamper protection, and packaging on Windows /
  macOS / Linux.
- 433 / 433 unit tests, 14 / 14 base E2E, 10 / 10 security E2E.

### 3.2 Architectural correction / ADR

> **ShieldNet Device Control is a functional port of Fleet-like
> management capabilities, implemented as SDA-native Rust modules and
> SN360 control-plane services. It is not a line-by-line Fleet
> source-code port.**

We studied [Fleet](https://github.com/fleetdm/fleet) (Go + osquery)
and selected the *concepts* worth carrying forward — queries,
policies, scripts, software jobs, update channels, agent vitals,
GitOps workflows. The implementation is:

- Fresh Rust on the agent (every crate is `sda-*`, no Go on the
  endpoint).
- Fresh Go on the control plane (the existing
  [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)
  stack already speaks NATS / Postgres / OpenSearch).
- No use of Fleet Enterprise Edition (EE) code.
- No re-use of Fleet's Go server source.

This ADR is binding. Everything below — every crate name, every
struct, every protocol field — reflects it.

---

## 4. What to port from Fleet

### 4.1 Concepts to port

| Fleet concept             | SDA / SN360 equivalent                                  | Where it lives                                  |
|---------------------------|---------------------------------------------------------|-------------------------------------------------|
| osquery scheduled queries | `sda-query` declarative queries                         | Agent (this repo).                              |
| Policies (boolean SQL)    | `sda-policy` policy evaluator                           | Agent (this repo).                              |
| Software installers       | Approved Package Catalogue + `sda-software`             | Agent + control plane.                          |
| Scripts                   | Signed script jobs via `sda-script-runner`              | Agent (this repo).                              |
| Update channels           | `sda-updater` per-target channels                       | Agent (this repo).                              |
| Agent vitals              | `sda-agent-vitals`                                      | Agent (this repo).                              |
| Activities (audit log)    | EvidenceRecord stream → Evidence Vault                  | Control plane.                                  |
| GitOps YAML config        | `sda-management-compat` translation shim                | Optional — Phase 5.                             |
| Labels (host groups)      | Tag-based device groups in Device Registry              | Control plane.                                  |

### 4.2 Do-not-port list

The following Fleet capabilities are explicitly **out of scope** and
not ported in any form:

- Fleet's Go server source. We do not vendor or fork it.
- Fleet EE features under the Fleet EE license.
- Fleet's MySQL schema. SN360 already runs Postgres with row-level
  security; we use that.
- Fleet's `fleetd`/Orbit agent runtime. We use SDA.
- Fleet's MDM ADE/DEP/VPP integrations. We integrate Apple MDM via
  NanoMDM-style services if and only if we reach Phase 4.
- Fleet's Sails.js website, handbook-as-code, or DRI governance.

---

## 5. Target architecture

```
+--------------------------------------------------------------+
|                       sda-agent (bin)                        |
+--------------------------------------------------------------+
|   sda-device-control  | sda-query     | sda-policy           |
|   sda-posture         | sda-software  | sda-jit-admin        |
|   sda-script-runner   | sda-app-ctrl  | sda-remote-support   |
|   sda-agent-vitals    | sda-management-compat                |
+--------------------------------------------------------------+
|     existing modules: fim / inventory / sca / lde / ar       |
+--------------------------------------------------------------+
|          sda-event-bus  (priority queues + back-pressure)    |
+--------------------------------------------------------------+
|             sda-comms  (TLS 1.3 + HTTP/2 + MsgPack)          |
+--------------------------------------------------------------+
|     sda-pal: PackageManager | AdminManager | Posture         |
|              AppControlProvider | RemoteSupportProvider      |
+--------------------------------------------------------------+
|     Linux | macOS | Windows native APIs (per existing PAL)   |
+--------------------------------------------------------------+
                            ||  TLS 1.3 / HTTP/2 / MsgPack
                            \/
+--------------------------------------------------------------+
|              SN360 Control Plane (separate repo)             |
|                                                              |
|  Agent Gateway -> NATS -> {Device Registry, Risk Engine,     |
|                            SMI Engine, Action Orchestrator,  |
|                            Approval Service, Package         |
|                            Catalog, Evidence Vault, Vitals}  |
+--------------------------------------------------------------+
```

The arrow between agent and control plane is the existing SN360 native
protocol path — there is no new transport. Device Control adds new
`MessageType` variants and new NATS subjects, not new sockets.

---

## 6. New SDA crates

### 6.1 Agent-side new crates

| Crate                  | Purpose                                                                                          | MVP role                              |
|------------------------|--------------------------------------------------------------------------------------------------|---------------------------------------|
| `sda-device-control`   | Owns the Device Control event surface, signed-job intake, and result publishing.                 | Phase 1 — required.                   |
| `sda-query`            | osquery-compatible declarative query engine; runs scheduled and ad-hoc queries via PAL.          | Phase 1 — required.                   |
| `sda-policy`           | Policy evaluator: turns query results + posture + inventory deltas into Findings.                | Phase 1 — required.                   |
| `sda-posture`          | Live device-posture snapshots (disk encryption, firewall, screen lock, OS patch level).          | Phase 1 — required.                   |
| `sda-software`         | Approved software catalogue client + per-OS install / update / uninstall via PackageManager.     | Phase 2 — required.                   |
| `sda-jit-admin`        | Just-in-Time admin/root grant + revocation watchdog + drift detection.                           | Phase 3 — required.                   |
| `sda-script-runner`    | Signed-script executor with a hard allow-list and short execution budget.                        | Phase 2 — required (catalogue uses).  |
| `sda-app-control`      | Application control (monitor → enforce) wrapping Santa, WDAC, Linux equivalents.                 | Phase 4 — optional.                   |
| `sda-remote-support`   | Operator-initiated, user-consented remote support session (clean-room MeshCentral-style).        | Phase 4 — optional.                   |
| `sda-agent-vitals`     | Agent-self telemetry: heartbeat, queue depth, last-seen, watchdog faults.                        | Phase 1 — required.                   |
| `sda-management-compat`| Translation shim for Fleet-flavoured GitOps YAML so existing customers can adopt SDA.            | Phase 5 — optional.                   |

### 6.2 Existing crates to modify

| Crate                       | Required changes                                                                                                       |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------|
| `sda-core`                  | New `EventKind` variants, new `modules.device_control` / `modules.query` / etc. config sections, new event priorities. |
| `sda-event-bus`             | New priority assignments for Device Control events; no new infrastructure.                                             |
| `sda-comms`                 | New `MessageType` variants for signed jobs, results, evidence, vitals; `device_control.*` NATS subject hierarchy.      |
| `sda-pal`                   | New traits: `PackageManager`, `AdminManager`, `DevicePostureProvider`, `AppControlProvider`, `RemoteSupportProvider`.  |
| `sda-agent`                 | Lazy-load Device Control modules; wire signed-job validation into the router; add startup-order entries.               |
| `sda-updater`               | New per-target update channels (`agent`, `osquery`, `provider-bundles`); reuse existing signed manifest path.          |
| `sda-enhanced-inventory`    | Re-export software / browser-extension inventory into the Device Control event stream as `SoftwareInventoryDelta`.     |
| `sda-active-response`       | Receive `DeviceControlActionResult` and emit existing AR primitives when a job demands it.                             |

---

## 7. Control-plane services

> All services in this section live in
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform),
> not in this repository. They are listed for cross-reference only.

| Service              | Purpose                                                                                                |
|----------------------|--------------------------------------------------------------------------------------------------------|
| Device Registry      | Source of truth for tenant ↔ device ↔ user mappings; receives heartbeats from `sda-agent-vitals`.       |
| Risk Engine          | Consumes Findings + posture + software deltas; emits Recommendations.                                   |
| SMI Engine           | Maintains per-tenant Security Maturity Index sub-scores; ingests Findings and Action results.           |
| Action Orchestrator  | Issues `SignedActionJob`s, tracks state, enforces maintenance windows / quiet hours.                    |
| Approval Service     | Auto / human / per-tenant approval workflows for Recommendations.                                        |
| Package Catalog      | Tenant-scoped approved-software catalogue + signed package manifests.                                    |
| Evidence Vault       | Append-only, signed `EvidenceRecord` store; powers customer & MSP exports.                              |
| Agent Vitals Service | Heartbeat + missing-device tracking; produces "missing laptop" findings.                                |
| MSP Tenant Service   | Multi-tenant routing, approval splits, white-label rendering (Phase 5).                                 |

### 7.1 Control-plane rule

> All control-plane services are implemented in `sn360-security-platform`.
> No control-plane code is added to this repository under any
> circumstances. The agent ships only the agent-side surface.

---

## 8. Data model

The Device Control wire model is four core types. All four are
serialised with MessagePack on the wire (matching the existing native
protocol path) and JSON on disk for evidence.

```rust
/// A single observation produced by the agent that the control plane
/// should consider for risk scoring or recommendations.
pub struct Finding {
    pub finding_id: Uuid,
    pub device_id: Uuid,
    pub tenant_id: Uuid,
    pub kind: FindingKind,           // PermanentAdmin, OutdatedApp, ...
    pub severity: Severity,          // Info, Low, Medium, High, Critical
    pub plain_english: String,       // Human-readable, SME-targeted.
    pub evidence: serde_json::Value, // Compact structured detail.
    pub observed_at: DateTime<Utc>,
}

/// A control-plane suggestion attached to one or more Findings.
pub struct Recommendation {
    pub recommendation_id: Uuid,
    pub tenant_id: Uuid,
    pub device_ids: Vec<Uuid>,
    pub finding_ids: Vec<Uuid>,
    pub action: ActionKind,          // PatchApp, RevokeAdmin, GrantJit, ...
    pub plain_english: String,
    pub one_click: bool,             // Eligible for auto-execution at this tier.
    pub created_at: DateTime<Utc>,
}

/// A signed instruction the agent will execute. Verified against the
/// SN360 control-plane signing key before any side-effect runs.
pub struct SignedActionJob {
    pub job_id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub recommendation_id: Option<Uuid>,
    pub action: ActionKind,
    pub args: serde_json::Value,     // Action-shaped (e.g. package id + version).
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub signature: Vec<u8>,          // Ed25519 over the canonical encoding.
    pub key_id: String,              // Rotation-aware key identifier.
}

/// What happened when the job ran.
pub struct ActionResult {
    pub job_id: Uuid,
    pub device_id: Uuid,
    pub status: ActionStatus,        // Success, Failure, Refused, Skipped.
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub exit_code: Option<i32>,
    pub output: String,              // Bounded; truncated and hashed if larger.
    pub evidence_id: Uuid,           // Foreign key into the EvidenceRecord stream.
}
```

`EvidenceRecord` is documented in § 16; it is the audit projection of
`ActionResult` plus the `SignedActionJob` it executed.

---

## 9. Core capabilities

### 9.1 Device inventory

`sda-enhanced-inventory` already produces hardware / OS / installed
software / browser-extension data. Device Control re-exports the
running-software stream as `SoftwareInventoryDelta` and adds posture
fields via `sda-posture`. No new collection paths are introduced for
existing data.

### 9.2 Admin / root review

`sda-policy` runs scheduled queries through `sda-query` to enumerate
local admins (Windows: `Administrators` group; macOS: `admin` group;
Linux: `wheel` / `sudo` / non-`root` UID 0). Each admin not on the
tenant allow-list emits a `PermanentAdmin` Finding.

### 9.3 Just-in-Time admin

`sda-jit-admin` accepts a signed `GrantJitAdmin` job and:

1. Adds the user to the platform admin group via `AdminManager`.
2. Starts a watchdog that revokes the grant after the configured
   duration, on suspend, on logout, or on heartbeat loss.
3. Emits `JitAdminRequested` / `Granted` / `Revoked` events with
   evidence at every transition.

### 9.4 Approved software catalogue

`sda-software` reads a signed catalogue manifest, verifies the
signature against the rotation-aware control-plane key, and exposes
install / update / uninstall actions per `PackageManager`
implementation (Windows / macOS / Linux). All actions go through the
signed job path.

### 9.5 Patch control

`sda-software` flags installed apps not seen in the latest catalogue
manifest in the last 60 days as **stale**, apps with known CVEs
(matched against the control-plane's existing SIS/CVE pipeline) as
**vulnerable**, and apps absent from the tenant catalogue as
**unapproved**. Each becomes a Finding.

### 9.6 App control

`sda-app-control` ships in two modes: **monitor** (Phase 4 default —
log allow/deny decisions only) and **enforce** (block on deny).
Implementations wrap Santa on macOS, WDAC on Windows, and a
clean-room dm-verity-aware enforcement on Linux. Enforcement is
gated by tenant-level configuration and a separate signed policy
bundle.

### 9.7 Remote support

`sda-remote-support` is initiated only from the control plane *and*
acknowledged interactively by the device user (consent banner
visible at all times). The wire format is a clean-room
MeshCentral-style protocol; no MeshCentral code is vendored. Sessions
end on user revocation, on operator termination, on heartbeat loss,
or after the configured maximum duration.

### 9.8 Mobile MDM (later)

For mobile, SDA does not run on-device; control-plane services talk
to:

- **Android** — Google Android Management API; Headwind reference
  for self-hosted parity.
- **Apple** — Apple MDM / DDM via a NanoMDM-style service.
- **ChromeOS** — Chrome Policy / Chrome Management APIs.

This section is included for completeness; nothing in mobile MDM is
implemented in this repository.

---

## 10. Native protocol extension

### 10.1 New `MessageType` variants

`sda-comms::MessageType` gains the following variants. Each variant
is exhaustively prefixed and validated in the existing protocol
encoder (see [`crates/sda-comms/src/protocol.rs`](../../crates/sda-comms/src/protocol.rs)):

```rust
pub enum MessageType {
    // ... existing variants ...
    DeviceControlFinding,
    DeviceControlRecommendation,
    DeviceControlJob,           // Inbound (server -> agent)
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

### 10.2 NATS subject hierarchy

On the control-plane side, the existing NATS topology gains a
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

### 10.3 Signed job validation (10-step checklist)

Before any `SignedActionJob` produces a side effect, the agent runs:

1. Verify the message frame decoded successfully under the existing
   transport (TLS 1.3 + HTTP/2 + MessagePack).
2. Parse the `SignedActionJob` strictly (deny unknown fields).
3. Look up `key_id` against the locally pinned rotation set.
4. Verify the Ed25519 `signature` over the canonical encoding.
5. Reject if `not_before` is in the future or `not_after` is in the
   past, with a clock-skew tolerance of ≤ 60 s.
6. Reject if `tenant_id` does not match the agent's enrolled tenant.
7. Reject if `device_id` does not match the agent's local identity.
8. Reject if `action` is not in the locally compiled allow-list for
   the agent's current pricing tier.
9. Apply maintenance-window and quiet-hours policy from
   `modules.device_control.windows`.
10. Hand off to the relevant module (e.g. `sda-software`,
    `sda-jit-admin`) with a deadline and a budget.

Steps 2–8 produce a `JobRefused` event with a structured reason on
failure; the user-facing UI uses these reasons verbatim.

---

## 11. Agent configuration extension

`AgentConfig` gains `modules.device_control`, `modules.query`,
`modules.posture`, `modules.software`, `modules.jit_admin`,
`modules.script_runner`, `modules.app_control`,
`modules.remote_support`, and `updater.targets` sections. The full
schema reference lives in
[`docs/configuration-reference.md`](../configuration-reference.md);
this proposal documents the canonical example:

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
    enabled: false           # opt-in per tenant
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

All `enabled: false` defaults match SDA's "lazy module loading"
principle — the underlying crate is compiled in but does not subscribe
to events, allocate threads, or spawn sidecars unless turned on.

---

## 12. PAL additions

`sda-pal` exposes five new traits, each with per-OS implementations
selected at compile time via `cfg`:

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

The per-OS implementation matrix lives in
[ARCHITECTURE.md § 5](./ARCHITECTURE.md#5-pal-additions).

---

## 13. SMI scoring model

The Security Maturity Index already exists at the SN360 control-plane
tier. Device Control feeds it new sub-scores:

| Sub-score                  | Source                                                         | Move on...                                                |
|----------------------------|----------------------------------------------------------------|-----------------------------------------------------------|
| Admin hygiene              | `sda-policy` admin/root findings.                               | Permanent admins ≤ tenant allow-list size.                |
| Patch hygiene              | `sda-software` stale / vulnerable findings.                     | 0 vulnerable + ≥ 95 % apps patched within 30 days.        |
| Software allow-list        | `sda-software` unapproved findings.                             | 0 unapproved apps observed in last 7 days.                |
| Posture                    | `sda-posture` snapshots.                                         | Disk encryption + firewall + screen-lock all on.          |
| Vitals                     | `sda-agent-vitals` heartbeat + watchdog faults.                  | ≥ 95 % devices heartbeating in the last hour.             |
| Evidence completeness      | EvidenceRecord stream coverage of executed jobs.                | 100 % of jobs have a signed evidence record.              |

Worked example — finding to SMI:

```
Finding: PermanentAdmin (severity High)
  -> Recommendation: RevokeAdmin + GrantJit
  -> SignedActionJob (RevokeAdmin) executed -> ActionResult Success
  -> EvidenceRecord written
  -> SMI sub-score "Admin hygiene": move +1 step toward target.
```

---

## 14. Security model

### 14.1 Threats and controls

| Threat                                                        | Control                                                                                       |
|---------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| Compromised control-plane account issues malicious job        | Ed25519 signature + key rotation + per-action allow-list + maintenance-window enforcement.    |
| Compromised agent forwards forged Findings                    | Existing mTLS enrolment + signed agent identity; control plane treats Findings as advisory.   |
| Script runner used to execute arbitrary code                  | Hard-coded allow-list (`sn360.*` namespace), signed-script requirement, exec budget.           |
| Package install used to install malware                       | Signed catalogue manifest, pinned SHA-256 per artefact, no out-of-catalogue installs.          |
| JIT admin not revoked                                         | Watchdog + drift detection + heartbeat-loss revoke + idempotent revoke on next boot.           |
| Remote support eavesdrops on user                             | User consent banner always visible; session time-bounded; clean-room protocol audited.         |
| App control false positives lock out user                     | Monitor mode default; enforce mode requires explicit tenant opt-in + dual-control rollback.    |
| Multi-tenant data leakage                                     | Existing Postgres RLS + per-tenant signing keys + agent-side `tenant_id` validation.           |
| Tampered agent binary                                         | Existing tamper protection (Phase 5); Device Control modules added behind the same checks.     |
| Privilege escalation via PAL provider                         | All PAL implementations run inside SDA's existing privilege-separated module process boundary. |

### 14.2 Script runner restrictions

- **Signed only.** Scripts not signed by a pinned key are rejected.
- **Allow-list namespace.** Only scripts whose canonical name matches
  `modules.script_runner.allowlist` may run.
- **Bounded execution.** Hard wall-clock limit, hard output-byte
  limit, hard CPU-percent limit, killed on breach.
- **No interactive shells.** No PTY, no stdin, no environment
  inheritance beyond an explicit allow-list of variables.
- **Evidence-mandatory.** Every script run produces a
  `ScriptRunResult` and an `EvidenceRecord`.

### 14.3 Package installation restrictions

- **Catalogue-only.** Installs only from the signed Approved Package
  Catalogue manifest active for the tenant.
- **Pinned SHA-256.** Each artefact has a pinned hash; mismatch ⇒
  refuse + `JobRefused`.
- **Maintenance-window-gated.** Outside the window the job is queued,
  not executed.
- **Rollback path.** Updates must record the previous version so a
  failed update can be rolled back via the same signed-job path.
- **No silent uninstall.** Uninstall jobs require `one_click=false`
  unless the tenant has explicitly opted in.

---

## 15. Performance and optimisation

### 15.1 Rules

1. **No regression on existing budgets.** Idle RSS < 15 MB, idle CPU
   < 0.1 %, FIM scan peak < 3 %, binary < 7 MB. Device Control crates
   that would breach this run as sidecars under their own budget.
2. **Lazy module loading.** Disabled modules consume zero threads,
   zero subscriptions, zero allocations beyond their static struct.
3. **Adaptive resource budgeting.** Modules consult
   `PowerMonitor::current_profile()` before heavy work, exactly like
   FIM and the inventory scanners do today.
4. **Power-aware.** Battery + idle states defer non-urgent work.
5. **Bounded queues.** Device Control events flow through the
   existing priority queues; no new buffers are allocated.

### 15.2 Sidecar budget

| Sidecar                               | Max RSS  | Max CPU (idle) | Notes                                                       |
|---------------------------------------|----------|----------------|-------------------------------------------------------------|
| `osquery` (Phase 1 default)           | 60 MB    | 5 %            | Spawned only when `modules.query.osquery.mode = "sidecar"`. |
| `winget` invocation (Windows)         | n/a      | n/a            | Short-lived process; budget enforced via job timer.         |
| `munki-style` invocation (macOS)      | n/a      | n/a            | Short-lived process; budget enforced via job timer.         |
| `apt` / `dnf` / `zypper` (Linux)      | n/a      | n/a            | Short-lived process; budget enforced via job timer.         |
| `santa` / `wdac` policy push          | n/a      | n/a            | Native OS APIs; no sidecar.                                  |

### 15.3 Event priorities

| EventKind                       | Priority   | Rationale                                                         |
|---------------------------------|------------|-------------------------------------------------------------------|
| `DeviceControlFinding`          | Normal     | Advisory; not life-safety.                                         |
| `DeviceControlRecommendation`   | Normal     | Server-bound only.                                                 |
| `DeviceControlActionResult`     | High       | Closes a control-plane job; must not be lost.                      |
| `DevicePostureState`            | Low        | Coarse-grained; deltas only.                                        |
| `SoftwareInventoryDelta`        | Low        | High-volume; deltas, not snapshots.                                |
| `SoftwareJobResult`             | High       | Closes a control-plane job.                                        |
| `JitAdminRequested/Granted/Revoked` | High   | Security-sensitive lifecycle events.                                |
| `QueryResult`                   | Normal     | Backed by retries; can absorb transient drops.                     |
| `ScriptRunResult`               | High       | Closes a control-plane job.                                        |
| `RemoteSupportSessionStarted/Ended` | High   | User-visible; must not be lost.                                    |
| `AgentVitals`                   | Low        | Heartbeat + counters; rate-limited.                                |
| `EvidenceRecord`                | High       | Audit-critical; never dropped, only back-pressured.                |

---

## 16. Evidence and audit model

Every signed job produces an `EvidenceRecord`. The schema is:

```json
{
  "evidence_id": "01h…",
  "tenant_id": "01h…",
  "device_id": "01h…",
  "job_id": "01h…",
  "recommendation_id": "01h…",
  "action": "PatchApp",
  "args_canonical": "{...}",
  "started_at": "2026-05-07T05:43:00Z",
  "finished_at": "2026-05-07T05:43:14Z",
  "status": "Success",
  "exit_code": 0,
  "output_sha256": "…",
  "platform": {
    "os": "macos",
    "version": "14.4.1",
    "arch": "aarch64"
  },
  "agent": {
    "version": "0.10.0",
    "build_sha": "…"
  },
  "signature": "ed25519:…",
  "key_id": "sn360-evidence-2026-05"
}
```

Records are append-only. The Evidence Vault stores them as an Ed25519
chain (each record signs a prefix-hash over the previous record so
deletions are detectable).

Export formats:

- **Customer JSON** — one record per line; signed; importable into
  SIEMs.
- **Customer PDF** — human-readable per-device report; tenant-branded.
- **MSP CSV** — flattened for cross-tenant operational dashboards
  (Phase 5).

---

## 17. MSP and pricing alignment

| Tier      | Surface                                                                                                          |
|-----------|------------------------------------------------------------------------------------------------------------------|
| Free      | Inventory + admin/root review (read-only). Plain-English findings, no fixes.                                     |
| Pro       | Free + approved software catalogue, one-click patch / update / uninstall, JIT admin with manual approval, SMI.   |
| Ultimate  | Pro + auto-approval workflows, app control (monitor + enforce), remote support, mobile MDM connectors, MSP mode. |

The agent ships every capability and runs whatever the gateway
authorises; tier enforcement is a server-side concern.

---

## 18. Repository implementation plan

### 18.1 `Cargo.toml` changes

Add the following members, in alphabetical order, preserving the
existing `[workspace]` ordering convention:

```toml
[workspace]
members = [
    # ... existing ...
    "crates/sda-app-control",
    "crates/sda-agent-vitals",
    "crates/sda-device-control",
    "crates/sda-jit-admin",
    "crates/sda-management-compat",
    "crates/sda-policy",
    "crates/sda-posture",
    "crates/sda-query",
    "crates/sda-remote-support",
    "crates/sda-script-runner",
    "crates/sda-software",
]
```

`fuzz/` keeps its own `[workspace]` stanza unchanged.

### 18.2 Per-crate changes

| Crate                        | Change kind                       | Notes                                                                |
|------------------------------|-----------------------------------|----------------------------------------------------------------------|
| `sda-core`                   | Additive                          | New `EventKind` variants, new config sections, new event priorities. |
| `sda-event-bus`              | Additive                          | New priority lookups; no public API change.                          |
| `sda-comms`                  | Additive                          | New `MessageType` variants + canonical encoder arms.                 |
| `sda-pal`                    | Additive                          | Five new traits + per-OS implementations.                            |
| `sda-agent`                  | Additive                          | Lazy-load of new modules; signed-job validation in router.           |
| `sda-updater`                | Additive                          | New per-target update channels.                                       |
| `sda-enhanced-inventory`     | Additive                          | New `SoftwareInventoryDelta` event publisher.                         |
| `sda-active-response`        | Additive                          | New `DeviceControlActionResult` consumer arm.                         |
| `sda-device-control`         | New crate                         | See § 6.1.                                                           |
| `sda-query`                  | New crate                         | See § 6.1.                                                           |
| `sda-policy`                 | New crate                         | See § 6.1.                                                           |
| `sda-posture`                | New crate                         | See § 6.1.                                                           |
| `sda-software`               | New crate                         | See § 6.1.                                                           |
| `sda-jit-admin`              | New crate                         | See § 6.1.                                                           |
| `sda-script-runner`          | New crate                         | See § 6.1.                                                           |
| `sda-app-control`            | New crate                         | See § 6.1 (Phase 4).                                                  |
| `sda-remote-support`         | New crate                         | See § 6.1 (Phase 4).                                                  |
| `sda-agent-vitals`           | New crate                         | See § 6.1.                                                           |
| `sda-management-compat`      | New crate                         | See § 6.1 (Phase 5).                                                  |

### 18.3 Compatibility

Adding new `MessageType` variants and new `EventKind` variants is
backward-compatible at the wire level — older agents simply do not
emit them, and the control plane already tolerates unknown variants
on the legacy adapter path.

### 18.4 Module startup order

```
1.  sda-core: load AgentConfig, derive feature flags.
2.  sda-pal: select per-OS providers (PackageManager, AdminManager,
    DevicePostureProvider, AppControlProvider, RemoteSupportProvider).
3.  sda-event-bus: bring up bus with new priority assignments.
4.  sda-comms: open native protocol session (TLS 1.3 + HTTP/2 +
    MessagePack), register Device Control MessageType arms.
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

Each step is independently observable via `AgentVitals` so a
mis-ordered start fails loudly.

---

## 19. Roadmap

This section is the summary; the detailed phase plan with task tables
lives in [PHASES.md](./PHASES.md).

| Phase | Theme                                              | Window         | Key deliverables                                                        |
|-------|----------------------------------------------------|----------------|-------------------------------------------------------------------------|
| 0     | Architecture, Legal, Schema                        | 2 weeks        | ADR, Fleet capability map, license reviews, schema specs.               |
| 1     | Visibility + Admin/Root Review                     | 8–12 weeks     | `sda-device-control`, `sda-query`, `sda-posture`, admin/root findings.  |
| 2     | Push Software + Approved Catalogue                 | 12–20 weeks    | `sda-software`, signed catalogue, package wrappers, maintenance windows.|
| 3     | Just-in-Time Admin/Root                            | 20–32 weeks    | `sda-jit-admin`, approval workflow, watchdog, drift detection.          |
| 4     | Remote Support + App Control + MDM Connectors     | 32–48 weeks    | `sda-remote-support`, `sda-app-control`, mobile connectors.             |
| 5     | MSP-Ready Multi-Tenant Operations                  | 48+ weeks      | Tenant catalogues, approval routing, white-label exports, MSP dashboard.|

---

## 20. Open-source and platform engine policy

This section is the canonical reference for which engines and tools
each Device Control area targets. **Tactical RMM is benchmark-only —
do not use as base.**

| #  | Area                                  | Recommended engine                                                              | Implementation posture                                                                 |
|----|---------------------------------------|---------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| 1  | Declarative queries                   | osquery (Apache-2.0 / GPL-2.0 dual; we consume Apache-2.0)                      | Integrate as a sidecar; talk over the local Thrift/JSON socket.                         |
| 2  | Compliance / monitoring agent         | Wazuh                                                                            | Already integrated upstream of SDA on the SIEM side; reuse via existing PAL.            |
| 3  | Windows package management            | WinGet (Microsoft Store source)                                                  | Wrap the `winget` CLI from `sda-software`; signed-job-gated.                            |
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

## 21. Risk register

| #  | Risk                                                           | Severity   | Mitigation                                                                                                         |
|----|----------------------------------------------------------------|------------|---------------------------------------------------------------------------------------------------------------------|
| 1  | Scope creep into full RMM/MDM                                  | High       | Hard product boundary in § 2.3; every PR must point at a § 2.2 example or be rejected.                              |
| 2  | Fleet EE licensing contamination                                | Critical   | ADR (§ 3.2) bars Fleet EE source; Phase 0 license audit; CI license check.                                          |
| 3  | Script execution abuse                                          | Critical   | Signed-only + allow-list namespace + bounded execution; § 14.2.                                                     |
| 4  | Package supply-chain attack                                     | Critical   | Signed catalogue + pinned SHA-256 + maintenance-window gating; § 14.3.                                              |
| 5  | JIT admin not revoked                                           | High       | Watchdog + drift detection + heartbeat-loss revoke + idempotent revoke at boot; § 9.3.                              |
| 6  | osquery sidecar resource impact                                 | Medium     | Sidecar budget (60 MB / 5 % CPU); falls back to embedded mode only after Phase 1 evidence; § 15.2.                   |
| 7  | App control false positives                                     | High       | Monitor mode default; enforce mode requires opt-in + dual-control rollback; § 9.6.                                  |
| 8  | Remote support privacy concerns                                 | High       | User consent banner always visible; session time-bounded; clean-room protocol audited; § 9.7.                       |
| 9  | Multi-tenant MSP data leakage                                   | Critical   | Existing Postgres RLS + per-tenant signing keys + agent-side `tenant_id` validation; cross-tenant sharing blocked.   |
| 10 | Platform-specific inconsistency                                 | Medium     | PAL traits enforce a uniform contract; per-OS providers tested via `make e2e-{linux,macos,windows}`.                |

---

## 22. Final recommendation

> **Port Fleet's useful management concepts — queries, policies,
> scripts, software jobs, update channels, agent vitals, GitOps
> workflows — into SDA-native Rust modules and SN360 control-plane
> services. Do not merge Fleet wholesale. Do not depend on Fleet EE
> code. Do not start with full MDM/RMM.**

The MVP is the eight-step SME workflow:

1. **Inventory every device.**
2. **Show risky admins/root users.**
3. **Show outdated or unapproved software.**
4. **Recommend a plain-English fix.**
5. **Execute approved fixes safely.**
6. **Record evidence.**
7. **Improve SMI.**
8. **Make it MSP-ready.**

Steps 1–3 are Phase 1. Step 4 is Phase 1 (as plain-English text on
each Finding). Step 5 is Phase 2 (catalogue) and Phase 3 (JIT). Step
6 is wired in from Phase 1 onward. Step 7 lights up at the end of
Phase 1 and is continuously improved. Step 8 is Phase 5.

Anything outside this sequence — kernel extensions, full RMM agents,
arbitrary remote shells, ad-hoc cross-tenant sharing — is out of
scope for the first 32 weeks and re-evaluated only against the
boundary in § 2.3.
