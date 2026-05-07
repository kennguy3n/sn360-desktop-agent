# ShieldNet Device Control — Development Progress

> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)

Tracks the implementation status of ShieldNet Device Control against
the roadmap in [PHASES.md](./PHASES.md).

Status legend:

- **Done** — merged to `main` and covered by tests / benchmarks below.
- **In Progress** — branch exists, code is being written / reviewed.
- **Not Started** — no implementation work started yet.

> **Scope note:** Tasks marked ⚙️ are server-side and implemented in
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
> They are listed here for cross-reference only.

## Current Status

Phase 0 not yet started. All Device Control work is in planning. The
docs landing in this PR (`docs/device-control/{README,PROPOSAL,ARCHITECTURE,PHASES,PROGRESS}.md`)
are the only artefacts on `main` related to Device Control. No new
crates, config sections, `EventKind` variants, or `MessageType`
variants exist yet.

The existing SDA test surface — **433 unit tests, 14/14 base E2E,
10/10 security E2E** — remains green and must continue to pass as
Device Control crates are added.

---

## Phase 0 — Architecture, Legal, and Schema (2 weeks)

| # | Task | Status |
|---|------|--------|
| 0.1 | Land ADR (functional port, not Fleet source-code port) | Not Started |
| 0.2 | Fleet capability mapping | Not Started |
| 0.3 | License review — Fleet MIT | Not Started |
| 0.4 | License review — Fleet EE (excluded) | Not Started |
| 0.5 | License review — MakeMeAdmin (GPL, reference only) | Not Started |
| 0.6 | License review — SAP Privileges (reference only) | Not Started |
| 0.7 | License review — Munki (Apache-2.0, reference only) | Not Started |
| 0.8 | License review — Santa / North Pole Santa (Apache-2.0) | Not Started |
| 0.9 | License review — MeshCentral (Apache-2.0, reference only) | Not Started |
| 0.10 | Tactical RMM exclusion — benchmark-only posture | Not Started |
| 0.11 | Schema specs — Finding / Recommendation / SignedActionJob / ActionResult / EvidenceRecord | Not Started |
| 0.12 | Wire schema sign-off — MessageType / EventKind / NATS subjects | Not Started |
| 0.13 | Phase 0 exit checklist | Not Started |

---

## Phase 1 — Visibility + Admin/Root Review (8–12 weeks)

| # | Task | Status |
|---|------|--------|
| 1.1 | `sda-core` additions (EventKind variants + priorities) | Not Started |
| 1.2 | `sda-comms` additions (MessageType variants + encoder arms) | Not Started |
| 1.3 | `sda-pal` traits — AdminManager, DevicePostureProvider | Not Started |
| 1.4 | `sda-device-control` scaffold + signed-job validator | Not Started |
| 1.5 | `sda-query` MVP (osquery sidecar) | Not Started |
| 1.6 | `sda-posture` MVP | Not Started |
| 1.7 | Admin/root inventory — Windows | Not Started |
| 1.8 | Admin/root inventory — macOS | Not Started |
| 1.9 | Admin/root inventory — Linux | Not Started |
| 1.10 | Software inventory bridge (SoftwareInventoryDelta) | Not Started |
| 1.11 | Plain-English findings for the five PROPOSAL.md § 2.2 examples | Not Started |
| 1.12 | `sda-agent-vitals` MVP | Not Started |
| 1.13 | Evidence record emission for every ActionResult | Not Started |
| 1.14 | Device Registry integration ⚙️ | Not Started |
| 1.15 | SMI sub-score wiring ⚙️ | Not Started |
| 1.16 | Risk Engine v0 ⚙️ | Not Started |
| 1.17 | Phase 1 E2E suite (`make e2e-device-control`) | Not Started |

---

## Phase 2 — Push Software + Approved Catalogue (12–20 weeks)

| # | Task | Status |
|---|------|--------|
| 2.1 | `sda-pal::PackageManager` trait | Not Started |
| 2.2 | PackageManager — Windows (WinGet) | Not Started |
| 2.3 | PackageManager — macOS (Munki-style, clean-room) | Not Started |
| 2.4 | PackageManager — Linux (apt / dnf / yum / zypper) | Not Started |
| 2.5 | `sda-software` scaffold + catalogue client | Not Started |
| 2.6 | Catalogue manifest verification (Ed25519 + pinned SHA-256) | Not Started |
| 2.7 | `sda-script-runner` MVP (allow-list + signed-only + bounded) | Not Started |
| 2.8 | Maintenance windows + quiet hours | Not Started |
| 2.9 | Approval-state surfacing (Approved / Pending / Denied / Recalled) | Not Started |
| 2.10 | Rollback path | Not Started |
| 2.11 | Evidence on install / update / uninstall + rollback | Not Started |
| 2.12 | Package Catalog service ⚙️ | Not Started |
| 2.13 | Action Orchestrator ⚙️ | Not Started |
| 2.14 | Approval Service ⚙️ | Not Started |
| 2.15 | Phase 2 E2E suite | Not Started |

---

## Phase 3 — Just-in-Time Admin/Root (20–32 weeks)

| # | Task | Status |
|---|------|--------|
| 3.1 | `sda-pal::AdminManager` impls — temporary grant + revoke | Not Started |
| 3.2 | `sda-jit-admin` scaffold + grant state machine | Not Started |
| 3.3 | Revocation watchdog | Not Started |
| 3.4 | Boot-time idempotent revoke | Not Started |
| 3.5 | Drift detection | Not Started |
| 3.6 | Approval Service v1 ⚙️ | Not Started |
| 3.7 | Evidence at every transition | Not Started |
| 3.8 | Phase 3 E2E suite | Not Started |

---

## Phase 4 — Remote Support + App Control + MDM Connectors (32–48 weeks)

| # | Task | Status |
|---|------|--------|
| 4.1 | `sda-pal::RemoteSupportProvider` impls | Not Started |
| 4.2 | `sda-remote-support` scaffold | Not Started |
| 4.3 | Clean-room MeshCentral-style protocol | Not Started |
| 4.4 | `sda-pal::AppControlProvider` impls | Not Started |
| 4.5 | `sda-app-control` scaffold | Not Started |
| 4.6 | Santa integration (macOS) | Not Started |
| 4.7 | WDAC + AppLocker (Windows) | Not Started |
| 4.8 | Linux app control (clean-room dm-verity-aware) | Not Started |
| 4.9 | Android MDM connector ⚙️ | Not Started |
| 4.10 | Apple MDM/DDM connector ⚙️ | Not Started |
| 4.11 | ChromeOS connector ⚙️ | Not Started |
| 4.12 | Phase 4 E2E suite | Not Started |

---

## Phase 5 — MSP-Ready Multi-Tenant Operations (48+ weeks)

| # | Task | Status |
|---|------|--------|
| 5.1 | Tenant catalogues ⚙️ | Not Started |
| 5.2 | Approval routing ⚙️ | Not Started |
| 5.3 | White-label exports ⚙️ | Not Started |
| 5.4 | MSP dashboard ⚙️ | Not Started |
| 5.5 | Cross-tenant templates ⚙️ | Not Started |
| 5.6 | `sda-management-compat` shim | Not Started |
| 5.7 | Phase 5 E2E suite | Not Started |

---

## Tests & Benchmarks

No Device Control tests exist yet. Existing SDA test surface
(433 unit, 14/14 E2E, 10/10 security E2E) must continue to pass as
Device Control crates are added. New tests will land alongside the
phases that introduce them:

- Phase 1 — `make e2e-device-control` covering the five PROPOSAL.md
  § 2.2 examples (admin review, outdated apps, missing laptops,
  unknown software, JIT-admin request flow up to the
  `JobRefused: NotImplemented` boundary).
- Phase 2 — software-installer install / update / uninstall +
  rollback E2E on Windows / macOS / Linux.
- Phase 3 — JIT admin grant → revoke E2E on Windows / macOS / Linux,
  including process-crash, reboot, and sleep/wake recovery.
- Phase 4 — remote-support session E2E + app-control monitor +
  enforce E2E.
- Phase 5 — cross-tenant isolation E2E.

Existing budgets — idle RSS < 15 MB, idle CPU < 0.1 %, FIM scan peak
< 3 %, binary < 7 MB — must remain green; the benchmark gate
(`make benchmark-ci`) covers regression.

---

## Known Risks

The full risk register lives in
[PHASES.md § Risk register](./PHASES.md#risk-register) (and
canonically in [PROPOSAL.md § 21](./PROPOSAL.md#21-risk-register)).
Top six highest-severity risks for delivery planning:

| # | Risk                                  | Severity   | Mitigation summary                                                                                              |
|---|---------------------------------------|------------|------------------------------------------------------------------------------------------------------------------|
| 1 | Scope creep into full RMM/MDM         | High       | Hard product boundary (PROPOSAL.md § 2.3); every PR points at a § 2.2 example.                                   |
| 2 | Fleet EE licensing contamination      | Critical   | ADR (PROPOSAL.md § 3.2) bars Fleet EE source; Phase 0 license audit; CI license check.                           |
| 3 | Script execution abuse                | Critical   | Signed-only + allow-list namespace + bounded execution.                                                          |
| 4 | Package supply-chain attack           | Critical   | Signed catalogue + pinned SHA-256 + maintenance-window gating.                                                   |
| 5 | JIT admin not revoked                 | High       | Watchdog + drift detection + heartbeat-loss revoke + idempotent revoke at boot.                                  |
| 6 | Multi-tenant MSP data leakage         | Critical   | Existing Postgres RLS + per-tenant signing keys + agent-side `tenant_id` validation; cross-tenant sharing blocked.|

---

## Known Gaps

All Device Control work is pending Phase 0 completion. Specifically:

- No new crates (`sda-device-control`, `sda-query`, `sda-policy`,
  `sda-posture`, `sda-software`, `sda-jit-admin`, `sda-script-runner`,
  `sda-app-control`, `sda-remote-support`, `sda-agent-vitals`,
  `sda-management-compat`) exist on `main`.
- No new `EventKind` or `MessageType` variants are defined.
- No new `modules.device_control` / `modules.query` /
  `modules.posture` / etc. configuration sections are defined.
- No new PAL traits (`PackageManager`, `AdminManager`,
  `DevicePostureProvider`, `AppControlProvider`,
  `RemoteSupportProvider`) are defined.
- No control-plane integrations exist; the
  [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)
  side has not yet absorbed the Device Registry / Risk Engine / SMI
  Engine / Action Orchestrator / Approval Service / Package Catalog /
  Evidence Vault / Vitals Service work.

## Next Steps

Begin Phase 0 — ADR, license review, schema design. The Phase 0
exit-criteria checklist in [PHASES.md § Phase 0](./PHASES.md#phase-0--architecture-legal-and-schema-2-weeks)
gates the start of any Phase 1 implementation work.
