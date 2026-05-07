# ShieldNet Device Control — Phase Plan

> **Version:** 0.1 | **Date:** May 2026 | **Status:** Planning
> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)

This document defines the phased delivery plan for ShieldNet Device
Control. Progress is tracked in [PROGRESS.md](./PROGRESS.md).

> **Scope note:** Tasks marked ⚙️ are server-side and implemented in
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
> They are listed here for context and sequencing only and are **out
> of scope** for this repository, matching the convention used in
> [`docs/revised-phase-plan.md`](../revised-phase-plan.md).
>
> Status values follow the SDA convention: **Done**, **In Progress**,
> **Not Started**. All Phase 0–5 items below start as **Not Started**
> until matching code merges to `main`.

---

## Table of contents

1. [Risk register](#risk-register)
2. [Phase 0 — Architecture, Legal, and Schema](#phase-0--architecture-legal-and-schema-2-weeks)
3. [Phase 1 — Visibility + Admin/Root Review](#phase-1--visibility--adminroot-review-812-weeks)
4. [Phase 2 — Push Software + Approved Catalogue](#phase-2--push-software--approved-catalogue-1220-weeks)
5. [Phase 3 — Just-in-Time Admin/Root](#phase-3--just-in-time-adminroot-2032-weeks)
6. [Phase 4 — Remote Support + App Control + MDM Connectors](#phase-4--remote-support--app-control--mdm-connectors-3248-weeks)
7. [Phase 5 — MSP-Ready Multi-Tenant Operations](#phase-5--msp-ready-multi-tenant-operations-48-weeks)

---

## Risk register

The risk register shapes scope and sequencing for every phase below.
PROPOSAL.md § 21 is the authoritative source; this section is the
phase-planner's quick reference.

| #  | Risk                                                           | Severity   | Mitigation                                                                                                         |
|----|----------------------------------------------------------------|------------|---------------------------------------------------------------------------------------------------------------------|
| 1  | Scope creep into full RMM/MDM                                  | High       | Hard product boundary in PROPOSAL.md § 2.3; every PR points at a § 2.2 example or is rejected.                      |
| 2  | Fleet EE licensing contamination                                | Critical   | ADR (PROPOSAL.md § 3.2) bars Fleet EE source; Phase 0 license audit; CI license check.                              |
| 3  | Script execution abuse                                          | Critical   | Signed-only + allow-list namespace + bounded execution; PROPOSAL.md § 14.2.                                         |
| 4  | Package supply-chain attack                                     | Critical   | Signed catalogue + pinned SHA-256 + maintenance-window gating; PROPOSAL.md § 14.3.                                  |
| 5  | JIT admin not revoked                                           | High       | Watchdog + drift detection + heartbeat-loss revoke + idempotent revoke at boot; PROPOSAL.md § 9.3.                  |
| 6  | osquery sidecar resource impact                                 | Medium     | Sidecar budget (60 MB / 5 % CPU); embedded mode only after Phase 1 evidence; PROPOSAL.md § 15.2.                     |
| 7  | App control false positives                                     | High       | Monitor mode default; enforce mode requires opt-in + dual-control rollback; PROPOSAL.md § 9.6.                      |
| 8  | Remote support privacy concerns                                 | High       | User consent banner always visible; session time-bounded; clean-room protocol audited; PROPOSAL.md § 9.7.           |
| 9  | Multi-tenant MSP data leakage                                   | Critical   | Existing Postgres RLS + per-tenant signing keys + agent-side `tenant_id` validation; cross-tenant sharing blocked.   |
| 10 | Platform-specific inconsistency                                 | Medium     | PAL traits enforce a uniform contract; per-OS providers tested via `make e2e-{linux,macos,windows}`.                |

---

## Phase 0 — Architecture, Legal, and Schema (2 weeks)

**Goal:** lock the architectural decision record, the license posture,
and the wire schemas before any code lands. This phase is
intentionally short and document-only.

### Deliverables

- ADR landed in PROPOSAL.md § 3.2 (functional port, not source port).
- Fleet capability mapping table landed in PROPOSAL.md § 4.
- License reviews for every reference engine: Fleet (MIT) and Fleet
  EE (proprietary, **excluded**); MakeMeAdmin (GPL, **excluded as
  source**, clean-room reference only); SAP Privileges (clean-room
  reference); Munki (Apache-2.0, clean-room reference); Santa /
  North Pole Santa (Apache-2.0); MeshCentral (Apache-2.0, clean-room
  reference); Tactical RMM (**benchmark-only, never base**).
- Schema specs for `Finding`, `Recommendation`, `SignedActionJob`,
  `ActionResult`, `EvidenceRecord` (PROPOSAL.md § 8 + ARCHITECTURE.md
  § 3) reviewed and stable.
- New `MessageType` and `EventKind` variant lists agreed
  (ARCHITECTURE.md § 2.1, § 4.1).
- Phase 0 exit-criteria document recorded in PROGRESS.md.

### Tasks

| # | Task | Description | Status |
|---|------|-------------|--------|
| 0.1 | Land ADR | Functional port, not Fleet source-code port; PROPOSAL.md § 3.2 + standalone [ADR-001-functional-port.md](./ADR-001-functional-port.md). | Done |
| 0.2 | Fleet capability mapping | Concepts-to-port table + do-not-port list; PROPOSAL.md § 4 + standalone [fleet-capability-mapping.md](./fleet-capability-mapping.md). | Done |
| 0.3 | License review — Fleet MIT | Confirm MIT-licensed Fleet code is not vendored; document in [`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit). | Done |
| 0.4 | License review — Fleet EE | Bar Fleet EE source from this repo; [`deny.toml`](../../deny.toml) `[bans]` entries cover it; CI `cargo deny check licenses` gate is wired in Phase 7.8. | Done |
| 0.5 | License review — MakeMeAdmin (GPL) | Reference-only; clean-room re-implementation in `sda-jit-admin`; documented in [`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit). | Done |
| 0.6 | License review — SAP Privileges | Reference-only; clean-room re-implementation in `sda-jit-admin`; documented in [`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit). | Done |
| 0.7 | License review — Munki | Apache-2.0 reference; clean-room re-implementation in `sda-software`; documented in [`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit). | Done |
| 0.8 | License review — Santa / North Pole Santa | Apache-2.0; integrate on macOS, clean-room equivalents elsewhere; documented in [`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit). | Done |
| 0.9 | License review — MeshCentral | Apache-2.0 reference; clean-room re-implementation in `sda-remote-support`; documented in [`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit). | Done |
| 0.10 | Tactical RMM exclusion | Document benchmark-only posture; no source dependency; covered by [`deny.toml`](../../deny.toml) `[bans]` and [`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit). | Done |
| 0.11 | Schema specs | Finalise `Finding`, `Recommendation`, `SignedActionJob`, `ActionResult`, `EvidenceRecord`. | Not Started |
| 0.12 | Wire schema sign-off | Agree `MessageType` + `EventKind` additions and NATS subjects. | Not Started |
| 0.13 | Phase 0 exit checklist | Record exit criteria + sign-off in PROGRESS.md. | Not Started |

### Exit criteria

1. PROPOSAL.md, ARCHITECTURE.md, PHASES.md, PROGRESS.md all merged to
   `main` (this PR).
2. All license reviews recorded in
   [`docs/security-audit.md`](../security-audit.md) under a new
   "Device Control license audit" subsection.
3. Wire schema lists (MessageType, EventKind, NATS subjects) agreed
   with the
   [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)
   maintainers.
4. No Phase 1 code may be merged before Phase 0 exit.

---

## Phase 1 — Visibility + Admin/Root Review (8–12 weeks)

**Goal:** light up steps 1–4 of the SME workflow (inventory + admin
review + outdated software + plain-English findings) with evidence
records flowing for every observation.

### Deliverables

- `sda-device-control` crate scaffolded; signed-job validation
  pipeline in place (returns `JobRefused: NotImplemented` for actions
  not yet supported).
- `sda-query` MVP: scheduled queries via osquery sidecar (Phase 1 is
  sidecar-only).
- `sda-posture` snapshots wired into the event bus and the SMI
  pipeline.
- Local admin / root inventory for Windows / macOS / Linux via the
  new `AdminManager` PAL trait.
- Software inventory delta stream re-exported from
  `sda-enhanced-inventory` as `SoftwareInventoryDelta`.
- Plain-English `Finding` text for the five canonical examples in
  PROPOSAL.md § 2.2.
- SMI sub-scores (Admin hygiene, Patch hygiene, Software allow-list,
  Posture, Vitals, Evidence completeness) wired up by the SN360 SMI
  Engine ⚙️.
- Evidence records for every action result, even no-op acks.
- Device Registry integration ⚙️.
- `sda-agent-vitals` shipping heartbeat + queue depth + watchdog
  faults.

### Tasks

| # | Task | Description | Status |
|---|------|-------------|--------|
| 1.1 | `sda-core` additions | New `EventKind` variants (Finding, Recommendation, ActionResult, PostureState, SoftwareInventoryDelta, AgentVitals, EvidenceRecord); event-priority assignments. | Not Started |
| 1.2 | `sda-comms` additions | New `MessageType` variants + canonical encoder arms. | Not Started |
| 1.3 | `sda-pal` traits | `AdminManager`, `DevicePostureProvider` trait surfaces + per-OS implementations. | Not Started |
| 1.4 | `sda-device-control` scaffold | Crate skeleton, signed-job validator, `JobRefused` plumbing. | Not Started |
| 1.5 | `sda-query` MVP | osquery sidecar wrapper, schedule loop, `QueryResult` event. | Not Started |
| 1.6 | `sda-posture` MVP | Snapshot loop using `DevicePostureProvider`; emit `DevicePostureState`. | Not Started |
| 1.7 | Admin/root inventory — Windows | Enumerate `Administrators` group via `NetLocalGroupGetMembers`. | Not Started |
| 1.8 | Admin/root inventory — macOS | Enumerate `admin` group via Open Directory. | Not Started |
| 1.9 | Admin/root inventory — Linux | Enumerate `wheel` / `sudo` / non-root UID 0. | Not Started |
| 1.10 | Software inventory bridge | Re-export `sda-enhanced-inventory` deltas as `SoftwareInventoryDelta`. | Not Started |
| 1.11 | Plain-English findings | Implement Finding text for the five PROPOSAL.md § 2.2 examples. | Not Started |
| 1.12 | `sda-agent-vitals` MVP | Heartbeat, queue depth, watchdog faults emitted as `AgentVitals`. | Not Started |
| 1.13 | Evidence record emission | `EvidenceRecord` published for every `ActionResult` (even no-ops). | Not Started |
| 1.14 | Device Registry integration ⚙️ | Heartbeat + enrollment flow against Device Registry. Implemented in `sn360-security-platform`. | Not Started |
| 1.15 | SMI sub-score wiring ⚙️ | SMI Engine consumes Findings + ActionResults. Implemented in `sn360-security-platform`. | Not Started |
| 1.16 | Risk Engine v0 ⚙️ | First-pass Recommendation generation from Findings. Implemented in `sn360-security-platform`. | Not Started |
| 1.17 | Phase 1 E2E suite | New `make e2e-device-control` harness covering the five canonical examples. | Not Started |

### Acceptance criteria

1. `make test` (existing 433 unit / 14/14 E2E / 10/10 security E2E)
   continues to pass.
2. New `make e2e-device-control` exercises all five examples from
   PROPOSAL.md § 2.2 end to end.
3. Idle RSS / idle CPU / FIM scan-peak budgets unchanged.
4. With `modules.device_control.enabled: false` the agent's idle
   footprint is bit-for-bit identical to today.
5. Every Phase 1 action that produces a side effect — even an ack —
   emits a signed `EvidenceRecord`.

---

## Phase 2 — Push Software + Approved Catalogue (12–20 weeks)

**Goal:** light up step 5 of the SME workflow (execute approved
fixes safely) for the software-management half of MVP.

### Deliverables

- `sda-software` crate live; signed catalogue manifest verification.
- Per-OS `PackageManager` PAL implementations:
  - Windows: WinGet wrapper.
  - macOS: clean-room Munki-style local repo.
  - Linux: `apt` / `dnf` / `yum` / `zypper` auto-detect.
- `sda-script-runner` live with hard allow-list + signed-only
  enforcement (used for catalogue pre-flight scripts).
- Maintenance-window and quiet-hour enforcement on every install /
  update / uninstall job.
- Package approval states (Approved, Pending, Denied, Recalled)
  surfaced as `Recommendation`s.
- Rollback path for failed updates.
- Evidence records for every install / update / uninstall + every
  rollback.
- Package Catalog control-plane service ⚙️.
- Action Orchestrator + Approval Service ⚙️ for software jobs.

### Tasks

| # | Task | Description | Status |
|---|------|-------------|--------|
| 2.1 | `sda-pal::PackageManager` trait | Trait surface in `sda-pal`. | Not Started |
| 2.2 | PackageManager — Windows | `winget` CLI wrapper with structured exit-code handling. | Not Started |
| 2.3 | PackageManager — macOS | Clean-room Munki-style implementation. | Not Started |
| 2.4 | PackageManager — Linux | `apt` / `dnf` / `yum` / `zypper` auto-detect + wrappers. | Not Started |
| 2.5 | `sda-software` scaffold | Crate skeleton + catalogue client + signed-manifest verifier. | Not Started |
| 2.6 | Catalogue manifest verification | Ed25519 signature + pinned SHA-256 per artefact. | Not Started |
| 2.7 | `sda-script-runner` MVP | Allow-list + signed-only + bounded execution. | Not Started |
| 2.8 | Maintenance windows | Enforce `modules.device_control.windows`. | Not Started |
| 2.9 | Approval-state surfacing | Approved / Pending / Denied / Recalled as `Recommendation`s. | Not Started |
| 2.10 | Rollback path | `UpdatePackage` records previous version; failure triggers `RollbackPackage`. | Not Started |
| 2.11 | Evidence on install/update/uninstall | `EvidenceRecord` per side effect, including rollbacks. | Not Started |
| 2.12 | Package Catalog service ⚙️ | Tenant-scoped catalogue API. Implemented in `sn360-security-platform`. | Not Started |
| 2.13 | Action Orchestrator ⚙️ | Job state machine, retries, dispatch. Implemented in `sn360-security-platform`. | Not Started |
| 2.14 | Approval Service ⚙️ | Auto + human approval workflows. Implemented in `sn360-security-platform`. | Not Started |
| 2.15 | Phase 2 E2E suite | Extends `make e2e-device-control` to cover install / update / uninstall + rollback. | Not Started |

### Acceptance criteria

1. The "12 outdated apps" example in PROPOSAL.md § 2.2 ends with a
   one-click patch + evidence + SMI delta on all three platforms.
2. Out-of-window jobs are deferred, never silently executed.
3. Catalogue signature failures produce `JobRefused: SignatureError`
   with structured detail in the evidence record.
4. Existing budgets unchanged.

---

## Phase 3 — Just-in-Time Admin/Root (20–32 weeks)

**Goal:** light up the "User needs admin" example end to end with
auto-revocation, evidence, and SMI feedback.

### Deliverables

- `sda-jit-admin` crate live; revocation watchdog operational.
- Per-OS temporary admin grant via `AdminManager`:
  - Windows: time-boxed group membership + scheduled revoke.
  - macOS: SAP Privileges-style flow (clean-room).
  - Linux: time-boxed `sudoers.d` drop-in via `visudo`.
- Auto-approval and human-approval workflows ⚙️.
- Revocation triggers: explicit revoke, time-out, logout, suspend,
  heartbeat loss, idempotent revoke on boot.
- Drift detection: out-of-band group changes flagged.
- Evidence record at every transition (Requested / Granted / Revoked
  / Drift).

### Tasks

| # | Task | Description | Status |
|---|------|-------------|--------|
| 3.1 | `sda-pal::AdminManager` impls — temporary | Time-boxed grant + revoke on each OS. | Not Started |
| 3.2 | `sda-jit-admin` scaffold | Crate skeleton + grant state machine. | Not Started |
| 3.3 | Revocation watchdog | Tokio task scheduling + multi-trigger revoke. | Not Started |
| 3.4 | Boot-time idempotent revoke | On startup, revoke any expired grants. | Not Started |
| 3.5 | Drift detection | Compare observed grants vs. tracked grants; emit Finding. | Not Started |
| 3.6 | Approval Service v1 ⚙️ | Auto + human + per-tenant policy. Implemented in `sn360-security-platform`. | Not Started |
| 3.7 | Evidence at every transition | Requested / Granted / Revoked / Drift each emit `EvidenceRecord`. | Not Started |
| 3.8 | Phase 3 E2E suite | Covers PROPOSAL.md § 2.2 example 5 end to end. | Not Started |

### Acceptance criteria

1. The "User needs admin" example completes the loop: signed-job
   grant → time-boxed admin → automatic revoke → evidence → SMI.
2. No grant outlives its TTL under any failure mode (process crash,
   reboot, network loss, sleep/wake).
3. Drift detection finds operator-side group changes within one
   posture-snapshot interval.

---

## Phase 4 — Remote Support + App Control + MDM Connectors (32–48 weeks)

**Goal:** broaden the surface to the "Integrate later" bucket from
PROPOSAL.md § 2.3.

### Deliverables

- `sda-remote-support` crate live with consent banner, time-bounded
  sessions, and clean-room MeshCentral-style protocol.
- `sda-app-control` crate live in **monitor** mode (default); enforce
  mode opt-in per tenant.
- macOS app control via Santa / North Pole Santa.
- Windows app control via WDAC + AppLocker via PowerShell + signed
  policies.
- Linux app control via clean-room dm-verity-aware enforcement.
- Mobile MDM connectors ⚙️:
  - Android: Google Android Management API + Headwind reference.
  - Apple: NanoMDM-style service.
  - ChromeOS: Chrome Policy / Chrome Management APIs.

### Tasks

| # | Task | Description | Status |
|---|------|-------------|--------|
| 4.1 | `sda-pal::RemoteSupportProvider` impls | Per-OS capture + transport. | Not Started |
| 4.2 | `sda-remote-support` scaffold | Consent banner, time-bound, protocol shim. | Not Started |
| 4.3 | Clean-room MeshCentral-style protocol | Specification + reference implementation. | Not Started |
| 4.4 | `sda-pal::AppControlProvider` impls | Per-OS app control providers. | Not Started |
| 4.5 | `sda-app-control` scaffold | Monitor mode default + signed policy push. | Not Started |
| 4.6 | Santa integration (macOS) | Wrap Santa's binauthorize / file-modification rules. | Not Started |
| 4.7 | WDAC + AppLocker (Windows) | Signed-policy push via PowerShell. | Not Started |
| 4.8 | Linux app control | Clean-room dm-verity-aware enforcement. | Not Started |
| 4.9 | Android MDM connector ⚙️ | Implemented in `sn360-security-platform`. | Not Started |
| 4.10 | Apple MDM/DDM connector ⚙️ | Implemented in `sn360-security-platform`. | Not Started |
| 4.11 | ChromeOS connector ⚙️ | Implemented in `sn360-security-platform`. | Not Started |
| 4.12 | Phase 4 E2E suite | Remote-support session, app-control monitor + enforce, evidence. | Not Started |

### Acceptance criteria

1. Remote support session cannot start without an explicit user
   click; banner is visible the entire session; ending the session
   removes all access.
2. App control monitor mode is the default; flipping to enforce
   requires per-tenant opt-in + dual-control + a documented rollback
   path.
3. Mobile MDM tasks are wired in `sn360-security-platform` only;
   nothing in this repository runs on Android/iOS.

---

## Phase 5 — MSP-Ready Multi-Tenant Operations (48+ weeks)

**Goal:** light up step 8 of the SME workflow ("Make it MSP-ready").

### Deliverables

- Tenant-scoped catalogues with shared templates ⚙️.
- Approval routing: per-tenant approver + MSP-tier approver chains ⚙️.
- White-label evidence exports (customer-branded PDF + JSON) ⚙️.
- MSP dashboard ⚙️.
- Cross-tenant templates with per-tenant override hooks ⚙️.
- `sda-management-compat` translation shim for Fleet-flavoured GitOps
  YAML so existing customers can adopt SDA.

### Tasks

| # | Task | Description | Status |
|---|------|-------------|--------|
| 5.1 | Tenant catalogues ⚙️ | Per-tenant + cross-tenant template catalogues. Implemented in `sn360-security-platform`. | Not Started |
| 5.2 | Approval routing ⚙️ | Per-tenant + MSP approver chains. Implemented in `sn360-security-platform`. | Not Started |
| 5.3 | White-label exports ⚙️ | Branded PDF + JSON evidence exports. Implemented in `sn360-security-platform`. | Not Started |
| 5.4 | MSP dashboard ⚙️ | Cross-tenant operational view. Implemented in `sn360-security-platform`. | Not Started |
| 5.5 | Cross-tenant templates ⚙️ | Shared templates + per-tenant overrides. Implemented in `sn360-security-platform`. | Not Started |
| 5.6 | `sda-management-compat` shim | Translate Fleet-flavoured GitOps YAML into SDA-native config. | Not Started |
| 5.7 | Phase 5 E2E suite | Cross-tenant scenario coverage. | Not Started |

### Acceptance criteria

1. No agent-side change is required to onboard an MSP tenant; the
   agent is unaware of MSP topology.
2. Cross-tenant data leakage is impossible by construction (existing
   Postgres RLS + per-tenant signing keys + agent-side `tenant_id`
   validation).
3. White-label exports never include another tenant's `tenant_id` or
   evidence.
