# Fleet → ShieldNet Device Control — Capability Mapping

> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)
> **Status:** Phase 0 — Architecture, Legal, Schema | **Date:** May 2026
> **Companion to:**
> [`ADR-001-functional-port.md`](./ADR-001-functional-port.md),
> [`PROPOSAL.md` § 4](./PROPOSAL.md#4-what-to-port-from-fleet),
> [`ARCHITECTURE.md` § 9](./ARCHITECTURE.md#9-open-source-engine-policy)

---

This document is the canonical Phase 0 capability map between
[Fleet](https://github.com/fleetdm/fleet) (Go + osquery) and
ShieldNet Device Control. It exists to make the
[ADR-001 functional-port decision](./ADR-001-functional-port.md)
operational: every Fleet *concept* worth carrying forward is mapped
to a specific SDA crate or SN360 control-plane service, and the
Fleet code paths that are explicitly **not** ported are listed below
the line so an engineer or auditor can verify scope at a glance.

> **Restatement of ADR-001.** SDA Device Control is a **clean-room
> functional re-implementation** inspired by Fleet's *concepts*. No
> Fleet source code (MIT or EE) is vendored, copied, or translated.
> The implementation reuses SDA's existing Rust crate workspace,
> bounded priority event bus (`sda-event-bus`), SN360 native protocol
> (`sda-comms`), YAML configuration model (`sda-core::config`), and
> per-OS PAL traits (`sda-pal`). See
> [`ADR-001-functional-port.md`](./ADR-001-functional-port.md) for
> the full record.

---

## 1. Concepts to port

The Fleet concepts below are ported into SDA / SN360. The
*capabilities* are ported, not the *implementation* — every cell in
the **Implementation posture** column is one of *integrate*, *wrap*,
*clean-room*, or *control-plane only*.

| Fleet concept | SDA / SN360 equivalent | Where it lives | Implementation posture | Maps to canonical example (PROPOSAL.md § 2.2) |
|---|---|---|---|---|
| osquery scheduled queries | `sda-query` declarative queries (osquery sidecar) | Agent — this repo | Integrate (Apache-2.0 osquery as an out-of-process sidecar; talk over the local Thrift/JSON socket) | Examples 1–4 |
| Policies (boolean SQL) | `sda-policy` policy evaluator | Agent — this repo | Clean-room (Rust evaluator over `sda-query` results, posture, and inventory deltas) | Examples 1, 2, 4 |
| Software installers | Approved Package Catalogue + `sda-software` | Agent + control plane (`sn360-security-platform`) | Mixed — *wrap* OS package managers (WinGet on Windows; `apt` / `dnf` / `yum` / `zypper` on Linux); *clean-room* Munki-style approach on macOS | Example 2 |
| Scripts | Signed script jobs via `sda-script-runner` | Agent — this repo | Clean-room (allow-list namespace + Ed25519-signed jobs + bounded execution; not a generic shell) | Example 5 (and follow-ups) |
| Update channels | `sda-updater` per-target channels | Agent — this repo (already shipped Phase 5) | Reuse (existing signed-update mechanism, `client.tier` channel selection) | Example 2 |
| Agent vitals | `sda-agent-vitals` | Agent — this repo | Clean-room (heartbeat + queue depth + watchdog faults; emitted as `EventKind::AgentVitals`) | Example 3 |
| Activities (audit log) | `EvidenceRecord` stream → Evidence Vault | Agent emits, control plane stores | Clean-room (signed, append-only `EvidenceRecord`s flowing through `sda-comms`) | All five examples |
| GitOps YAML config | `sda-management-compat` translation shim | Agent — this repo (Phase 5, optional) | Clean-room translation shim (Fleet-flavoured YAML → signed-job format); no Fleet YAML schema vendored | (migration path — not an example) |
| Labels (host groups) | Tag-based device groups in the SN360 Device Registry | Control plane (`sn360-security-platform`) | Control-plane only (no agent change beyond `tenant_id` already in the heartbeat) | Examples 1, 3 |
| Software inventory | `sda-enhanced-inventory` re-export as `SoftwareInventoryDelta` | Agent — this repo (already shipped Phase 4) | Reuse + bridge (re-export existing CycloneDX SBOM + running-software stream as Device-Control-shaped deltas) | Examples 2, 4 |
| Posture / configuration assessment | `sda-posture` snapshots + existing `sda-sca` policy evaluator | Agent — this repo | Clean-room `sda-posture` (BitLocker / FileVault / LUKS / firewall / screen-lock / patch level via the new `DevicePostureProvider` PAL trait); reuses `sda-sca` for YAML policy eval | Example 1 (and follow-ups) |
| Just-in-time admin (Fleet "scripts to grant temporary admin" pattern) | `sda-jit-admin` | Agent — this repo (Phase 3) | Clean-room (Windows: re-implements MakeMeAdmin-style flow; macOS: SAP-Privileges-style flow; Linux: `sudoers.d` drop-in) | Example 5 |
| App control / allow-listing | `sda-app-control` | Agent — this repo (Phase 4) | Mixed — *integrate* Santa on macOS; *clean-room* WDAC + AppLocker on Windows; *clean-room* dm-verity-aware on Linux | (later phases) |
| Remote support / live shell | `sda-remote-support` | Agent — this repo (Phase 4, optional) | Clean-room (operator-initiated, user-consented; original wire format; only the high-level concept references MeshCentral) | Example 5 follow-up |
| Mobile MDM (Apple / Android / Chrome) | Control-plane connectors only | Control plane (`sn360-security-platform`) | Control-plane only (agent does not run on iOS / Android / ChromeOS) | (out of scope for Phases 0–3) |
| Vulnerability matching (Fleet's NVD lookups) | `sn360-security-platform` SIS (already shipped) | Control plane (`sn360-security-platform`) | Reuse (existing CycloneDX → CVE pipeline; Fleet's NVD-lookup code is not used) | Examples 2, 4 |
| RMM benchmarking | Reference-only against Tactical RMM | n/a — never ported | Exclude (benchmark only, never base; see § 2 below) | (none) |

---

## 2. Do not port

The Fleet capabilities below are explicitly **out of scope** and not
ported in any form. This list is the operationalisation of
[`PROPOSAL.md` § 4.2](./PROPOSAL.md#42-do-not-port-list) and is the
checklist a reviewer can run against any Device Control PR.

### 2.1 Fleet-specific code that must never appear in this repo

- **Fleet's Go server source.** No vendoring, no fork, no
  translation. Any file under `cmd/fleet/...`, `server/...`,
  `ee/server/...`, or any Fleet-derived header is rejected at
  review. The control plane is implemented in
  [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)
  on top of NATS + Postgres + OpenSearch.
- **Fleet Enterprise Edition (EE) features.** Anything under Fleet's
  EE licence is barred from both repositories regardless of
  intent. Examples include Fleet's EE-licensed scripts library, EE
  software installer signing flows, and EE MDM features. CI
  license-checks (`cargo deny check licenses` against
  [`deny.toml`](../../deny.toml)) flag any transitive crate that
  could pull EE-licensed code.
- **Fleet's MySQL schema.** SN360 already runs Postgres with
  per-tenant Row-Level Security (RLS); we use that. No Fleet `.sql`
  migrations or schema files are imported into
  [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
- **Fleet's `fleetd` / Orbit agent runtime.** The endpoint runtime
  is SDA. We do not ship `fleetd`, Orbit, or any Fleet-managed
  installer binary. Crate names stay `sda-*`; there is no Go on the
  endpoint.
- **Fleet's MDM ADE/DEP/VPP integrations.** Apple MDM / DDM is
  implemented as a control-plane connector only, in
  [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform),
  per [`PROPOSAL.md` § 9.8](./PROPOSAL.md#98-mobile-mdm-later) and
  Phase 4 in [`PHASES.md`](./PHASES.md).
- **Fleet's Sails.js website / handbook-as-code / DRI governance.**
  The SN360 control plane already has a UI and operations playbook.
  Fleet's website and governance model are not adopted.
- **Fleet web UI.** SDA / SN360 use the SN360 control plane UI in
  [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
  No part of Fleet's React UI is ported.
- **Fleet's Go-based architecture patterns.** Fleet's Go server
  patterns (kit-style services, gorilla/mux routing, Sails.js
  framework, ORM choice, MySQL-flavoured queries) are not adopted
  on the control plane. SN360 control-plane services are
  Go-on-NATS-on-Postgres with the existing tenant model.
- **Tactical RMM source / APIs / protocols.** Tactical RMM is used
  exclusively as a *feature benchmark* (i.e. "what RMM capabilities
  exist in the market") per
  [`ARCHITECTURE.md` § 9 row 13](./ARCHITECTURE.md#9-open-source-engine-policy)
  and the Tactical RMM subsection of
  [`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit).
  No Tactical RMM code, APIs, schemas, or wire protocols are used
  in SDA or in
  [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).

### 2.2 Out-of-scope capabilities (concept *and* code)

- **Generic ad-hoc remote shell.** `sda-script-runner` is
  signed-only, allow-listed, and bounded; it is not a fleetctl-style
  general-purpose shell. Generic shell access is out of scope per
  [`PROPOSAL.md` § 14.2](./PROPOSAL.md#142-script-execution).
- **Full RMM / MDM feature parity.** SDA Device Control delivers the
  *found → fix → evidence → SMI* loop for the
  [five canonical examples](./PROPOSAL.md#22-customer-facing-examples).
  Anything beyond that — kernel extensions we did not author,
  arbitrary remote shells, ad-hoc cross-tenant sharing, full-fat
  MDM — is explicitly out of scope per
  [`PROPOSAL.md` § 2.3](./PROPOSAL.md#23-product-boundary).

---

## 3. Cross-reference to canonical customer examples

Every concept in § 1 must — when shipped — exercise at least one of
the five customer-facing examples in
[`PROPOSAL.md` § 2.2](./PROPOSAL.md#22-customer-facing-examples).
The mapping below is the inverse of the right-most column of the § 1
table and is the test the Phase 1 E2E suite (`make e2e-device-control`
in [`PHASES.md` § Phase 1](./PHASES.md#phase-1--visibility--adminroot-review-812-weeks))
must pass.

| # | Canonical example (PROPOSAL.md § 2.2) | Concepts exercised (from § 1) |
|---|---|---|
| 1 | **6 permanent admins** — "6 users have permanent admin/root rights — risky on shared laptops." | Posture (`sda-posture`) + admin/root inventory (new `AdminManager` PAL trait) → `Finding` via `sda-policy` → JIT-admin enrolment via `sda-jit-admin` → `EvidenceRecord` |
| 2 | **12 outdated apps** — "12 apps haven't been updated in over 60 days — known CVEs apply." | `sda-query` (osquery installed-software) + `sda-enhanced-inventory` SBOM + control-plane SIS CVE matching → `Finding` → `sda-software` patch via approved catalogue → `EvidenceRecord` |
| 3 | **4 missing laptops** — "4 laptops haven't checked in for 14+ days — possibly lost." | `sda-agent-vitals` heartbeat → control-plane Device Registry "missing" state → `Finding` (gating remote support on next check-in) |
| 4 | **Unknown software** — "Software not on your approved list was installed on 3 devices." | `sda-enhanced-inventory` running-software delta → `sda-policy` allow-list eval → `Finding` (request approval, optionally uninstall via `sda-software`) → `EvidenceRecord` |
| 5 | **User needs admin** — "User X is asking for admin access to install Tool Y." | `sda-jit-admin` grant state machine + control-plane Approval Service → time-boxed grant → revocation watchdog → `EvidenceRecord` for grant + revoke |

> **Phase-0 acceptance.** A Device Control capability is *only*
> Phase-0-acceptable if it traces back to at least one of these five
> rows. The Phase 1 E2E suite asserts this by-name; PRs that cannot
> point at one of them are rejected per
> [`PROPOSAL.md` § 2.3](./PROPOSAL.md#23-product-boundary).

---

## 4. Authorities and audit trail

When in doubt, the order of precedence is:

1. **The proprietary licence** ([`../../LICENSE`](../../LICENSE)) and
   [`docs/proprietary-licensing-rationale.md`](../proprietary-licensing-rationale.md).
2. **[ADR-001-functional-port.md](./ADR-001-functional-port.md)**.
3. **[`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit)**
   — per-engine licence posture (Fleet MIT / Fleet EE / MakeMeAdmin /
   SAP Privileges / Munki / Santa / MeshCentral / Tactical RMM).
4. **[`PROPOSAL.md` § 4](./PROPOSAL.md#4-what-to-port-from-fleet)** —
   summary in the Device Control proposal.
5. **[`ARCHITECTURE.md` § 9](./ARCHITECTURE.md#9-open-source-engine-policy)**
   — engine policy table.
6. **This document** — operational mapping.
7. **[`deny.toml`](../../deny.toml)** at the workspace root —
   mechanically enforces the licence allow-list.

If any item below this list contradicts an item above it, the higher
item wins.
