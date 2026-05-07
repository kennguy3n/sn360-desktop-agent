# ShieldNet Device Control — Module Overview

> **Version:** 0.1 | **Date:** May 2026 | **Status:** Planning
> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)
> **Target Platforms:** Windows 10/11, macOS 12+, Linux (Ubuntu/Fedora/Arch)

> **Scope note:** This document covers the Device Control module within
> [`sn360-desktop-agent`](https://github.com/kennguy3n/sn360-desktop-agent).
> Control-plane services — Device Registry, Risk Engine, SMI Engine,
> Action Orchestrator, Approval Service, Package Catalog, Evidence
> Vault, MSP Tenant Service, etc. — are implemented in
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
> No server-side code lives in this repository.

---

## Table of contents

1. [Product promise](#product-promise)
2. [Customer-facing examples](#customer-facing-examples)
3. [Product boundary](#product-boundary)
4. [Architectural decision record (ADR)](#architectural-decision-record-adr)
5. [New SDA crate summary](#new-sda-crate-summary)
6. [Existing SDA crates to modify](#existing-sda-crates-to-modify)
7. [Open-source engine policy summary](#open-source-engine-policy-summary)
8. [Engineering directive](#engineering-directive)
9. [Core SME workflow](#core-sme-workflow)
10. [Pricing-tier alignment](#pricing-tier-alignment)
11. [Documentation map](#documentation-map)

---

## Product promise

ShieldNet Device Control is the SME-first device management surface of
ShieldNet 360 (SN360). It exists for a single, narrow audience: small
and medium-sized businesses with one or two part-time IT owners who
need to keep a fleet of laptops and desktops safe without learning
osquery SQL, MDM XML, or Fleet GitOps.

The product loop is:

1. **Found issue** — SDA continuously inventories the device.
2. **Plain-English risk** — the control plane translates raw findings
   into a sentence the SME owner can read.
3. **One-click fix** — a signed action job is dispatched to the agent.
4. **Audit evidence** — every action produces a tamper-evident record.
5. **SMI improvement** — the Security Maturity Index moves up after
   the fix lands.

Every feature in Device Control is judged against this loop. If a
capability does not start at "found issue" and end at "SMI moved",
it does not belong here.

---

## Customer-facing examples

These are the five canonical examples used to scope Phase 1 of the
roadmap. Each example exercises the full
*found → explain → fix → evidence → SMI* loop.

| # | Example                                          | Plain-English risk                                                       | One-click fix                                                  |
|---|--------------------------------------------------|--------------------------------------------------------------------------|----------------------------------------------------------------|
| 1 | **6 permanent admins**                           | "6 users have permanent admin/root rights — risky on shared laptops."    | Demote to standard, enrol in Just-in-Time admin (JIT).         |
| 2 | **12 outdated apps**                             | "12 apps haven't been updated in over 60 days — known CVEs apply."       | Patch via the approved package catalogue during a window.      |
| 3 | **4 missing laptops**                            | "4 laptops haven't checked in for 14+ days — possibly lost."             | Mark as missing; require remote support session on next check-in. |
| 4 | **Unknown software**                             | "Software not on your approved list was installed on 3 devices."         | Flag, request approval, optionally uninstall.                  |
| 5 | **User needs admin**                             | "User X is asking for admin access to install Tool Y."                   | Grant time-boxed JIT admin with auto-revocation + evidence.    |

---

## Product boundary

The proposal divides every candidate capability into three buckets.
Only the **Build first** column is in scope before MVP; the other two
columns are explicit non-goals for the first 32 weeks.

### Build first

- Device inventory, OS / hardware / installed software facts.
- Local admin and root account inventory + plain-English findings.
- Software inventory + stale / unapproved / vulnerable flags.
- Approved package catalogue with one-click install / update /
  uninstall on Windows, macOS, and Linux.
- Just-in-Time admin / root with approval workflow and auto-revocation.
- Evidence records for every action (signed, append-only).
- SMI sub-scores fed by Device Control findings.

### Integrate later

- App control (Santa-style allow / deny on macOS, WDAC on Windows).
- Remote support / screen sharing.
- Mobile MDM (Android Management API, Apple MDM/DDM, Chrome).
- Multi-tenant MSP-shaped operations (tenant catalogues, white-label).
- Generic ad-hoc script execution (signed-only, narrowly scoped).

### Avoid initially

- Full RMM (Remote Monitoring & Management) feature parity with
  Tactical RMM, NinjaOne, or N-able.
- Full MDM feature parity with Jamf, Kandji, Intune, or
  Apple Business Essentials.
- General-purpose "run any script anywhere" remote shell.
- Cross-tenant data sharing of any kind.
- Any feature that requires a kernel extension on macOS we did not
  already author.

---

## Architectural decision record (ADR)

> **ShieldNet Device Control is a functional port of Fleet-like
> management capabilities, implemented as SDA-native Rust modules and
> SN360 control-plane services. It is not a line-by-line Fleet
> source-code port.**

We studied [Fleet](https://github.com/fleetdm/fleet) (Go + osquery)
and selected the *concepts* worth carrying forward — queries,
policies, scripts, software jobs, update channels, agent vitals,
GitOps workflows. The implementation is fresh Rust on the agent and
fresh Go on the control plane. We do not depend on Fleet Enterprise
Edition (EE) code, which is not licensed for this use, and we do not
reuse Fleet's Go server source.

This ADR is the reason every new agent crate carries the `sda-`
prefix, lives under `crates/`, and matches SDA's resource budgets and
PAL conventions instead of inheriting Fleet's process model.

---

## New SDA crate summary

These are the new agent-side crates introduced by Device Control.
PROPOSAL.md § 6 describes each one in full; this table is the
quick reference.

| Crate                  | Purpose                                                                                          | MVP role                              |
|------------------------|--------------------------------------------------------------------------------------------------|---------------------------------------|
| `sda-device-control`   | Module that owns the Device Control event surface, signed-job intake, and result publishing.     | Phase 1 — required.                   |
| `sda-query`            | osquery-compatible declarative query engine; runs scheduled and ad-hoc queries via PAL providers.| Phase 1 — required.                   |
| `sda-policy`           | Policy evaluator: turns query results + posture + inventory deltas into Findings.                | Phase 1 — required.                   |
| `sda-posture`          | Live device-posture snapshots (disk encryption, firewall, screen lock, OS patch level).          | Phase 1 — required.                   |
| `sda-software`         | Approved software catalogue client + per-OS install / update / uninstall via PackageManager.     | Phase 2 — required.                   |
| `sda-jit-admin`        | Just-in-Time admin/root grant + revocation watchdog + drift detection.                            | Phase 3 — required.                   |
| `sda-script-runner`    | Signed-script executor with a hard allow-list and short execution budget.                         | Phase 2 — required (catalogue uses).  |
| `sda-app-control`      | Application control (monitor → enforce) wrapping Santa, WDAC, Linux dm-verity equivalents.       | Phase 4 — optional.                   |
| `sda-remote-support`   | Operator-initiated, user-consented remote support session (clean-room MeshCentral-style).         | Phase 4 — optional.                   |
| `sda-agent-vitals`     | Agent-self telemetry: heartbeat, queue depth, last-seen, watchdog faults.                         | Phase 1 — required.                   |
| `sda-management-compat`| Optional translation shim for Fleet-flavoured GitOps YAML so existing customers can adopt SDA.   | Phase 5 — optional.                   |

---

## Existing SDA crates to modify

These existing crates absorb small, surgical changes; nothing in the
existing module set is rewritten.

| Crate                       | Required changes                                                                                                    |
|-----------------------------|---------------------------------------------------------------------------------------------------------------------|
| `sda-core`                  | New `EventKind` variants, new `modules.device_control` / `modules.query` / etc. config sections, new event priorities. |
| `sda-event-bus`             | New priority assignments for Device Control events; no new infrastructure.                                          |
| `sda-comms`                 | New `MessageType` variants for signed jobs, results, evidence, vitals; `device_control.*` NATS subject hierarchy.   |
| `sda-pal`                   | New traits: `PackageManager`, `AdminManager`, `DevicePostureProvider`, `AppControlProvider`, `RemoteSupportProvider`.|
| `sda-agent`                 | Lazy-load Device Control modules; wire signed-job validation into the router; add startup-order entries.            |
| `sda-updater`               | New per-target update channels (`agent`, `osquery`, `provider-bundles`); reuse existing signed manifest path.       |
| `sda-enhanced-inventory`    | Re-export software / browser-extension inventory into the Device Control event stream as `SoftwareInventoryDelta`.  |
| `sda-active-response`       | Receive `DeviceControlActionResult` and emit existing AR primitives (block IP, kill process) when a job demands it. |

---

## Open-source engine policy summary

This is the agent and platform engine policy applied to Device
Control. The full table with implementation posture per row lives in
PROPOSAL.md § 20 and ARCHITECTURE.md § 9; this section is the quick
reference for contributors.

| Area                                  | Recommended engine                                                                       |
|---------------------------------------|------------------------------------------------------------------------------------------|
| Declarative queries                   | osquery (Apache-2.0 / GPL-2.0 dual)                                                      |
| Compliance / monitoring agent         | Wazuh (already integrated upstream of SDA on the SIEM side)                              |
| Windows package management            | WinGet (`winget` CLI / Microsoft Store source)                                           |
| macOS package management              | Munki-style approach (clean-room, Apache-2.0 reference) over local munkitools repo       |
| Linux package management              | Native: `apt` / `dnf` / `yum` / `zypper`                                                 |
| Just-in-Time admin (Windows)          | MakeMeAdmin-style flow (clean-room re-implementation; original is GPL — not redistributed)|
| Just-in-Time admin (macOS)            | SAP Privileges-style flow (clean-room re-implementation)                                  |
| Just-in-Time admin (Linux)            | Time-boxed `sudoers.d` drop-in + watchdog                                                 |
| App control (macOS)                   | Santa / North Pole Santa (Apache-2.0)                                                     |
| App control (Windows)                 | WDAC / AppLocker via PowerShell + signed policies                                         |
| Remote support                        | MeshCentral-style protocol (clean-room implementation; original is Apache-2.0)            |
| Mobile management — Android           | Google Android Management API + Headwind reference                                        |
| Mobile management — Apple             | Apple MDM / DDM + NanoMDM reference                                                       |
| Mobile management — ChromeOS          | Chrome Policy / Chrome Management APIs                                                    |

> **Note:** **Tactical RMM: benchmark only — do not use as base.**
> Its license restricts SaaS / commercial use, and we cannot inherit
> its server architecture. It is studied for feature parity and
> performance comparisons only.

See PROPOSAL.md § 20 and ARCHITECTURE.md § 9 for implementation
posture (integrate / wrap / clean-room) per engine.

---

## Engineering directive

> **Port Fleet's useful management concepts — queries, policies,
> scripts, software jobs, update channels, agent vitals, GitOps
> workflows — into SDA-native Rust modules and SN360 control-plane
> services. Do not merge Fleet wholesale. Do not depend on Fleet EE
> code. Do not start with full MDM/RMM.**

---

## Core SME workflow

The product loop above is realised as eight concrete steps. Every
Phase 1 deliverable is sized so the relevant step works end-to-end on
all three platforms (Windows / macOS / Linux):

1. **Inventory every device.** Hardware, OS, patch level, installed
   software, posture (disk encryption / firewall / screen lock).
2. **Show risky admins/root users.** Local admins and root-equivalent
   accounts surfaced with risk reasons.
3. **Show outdated or unapproved software.** Stale apps, apps not in
   the approved catalogue, apps with known CVEs.
4. **Recommend a plain-English fix.** Each finding produces a
   `Recommendation` an SME owner can read.
5. **Execute approved fixes safely.** Signed action jobs only; per-OS
   PAL implementations; respect maintenance windows and quiet hours.
6. **Record evidence.** Every action emits a signed, append-only
   `EvidenceRecord` to the control plane.
7. **Improve SMI.** Findings + actions move SMI sub-scores; the SMI
   delta is what the customer sees in their dashboard.
8. **Make it MSP-ready.** Phase 5 lifts the same surface into a
   multi-tenant, white-label shape for managed service providers.

---

## Pricing-tier alignment

Device Control surfaces are gated by SN360 plan. The control plane
enforces tiers; the agent does not — it ships every capability and
runs whatever the gateway authorises.

| Tier      | Device Control surface                                                                                          |
|-----------|------------------------------------------------------------------------------------------------------------------|
| Free      | Inventory + admin/root review (read-only). Plain-English findings, no fixes.                                     |
| Pro       | Free + approved software catalogue, one-click patch / update / uninstall, JIT admin with manual approval, SMI.   |
| Ultimate  | Pro + auto-approval workflows, app control (monitor + enforce), remote support, mobile MDM connectors, MSP mode. |

---

## Documentation map

### Sibling docs

- [PROPOSAL.md](./PROPOSAL.md) — full technical proposal, sections 1–22.
- [ARCHITECTURE.md](./ARCHITECTURE.md) — target shape of the code: crates, traits, events, protocol.
- [SCHEMAS.md](./SCHEMAS.md) — canonical, versioned wire spec for `Finding`, `Recommendation`, `SignedActionJob`, `ActionResult`, `EvidenceRecord`.
- [PHASES.md](./PHASES.md) — phased delivery plan and risk register.
- [PROGRESS.md](./PROGRESS.md) — delivery log against PHASES.md.
- [ADR-001-functional-port.md](./ADR-001-functional-port.md) — ADR-001 (binding): clean-room functional port; no Fleet source vendored.
- [fleet-capability-mapping.md](./fleet-capability-mapping.md) — Fleet → SDA / SN360 capability map and do-not-port list.

### Parent docs

- [`device-agent-proposal.md`](../../device-agent-proposal.md) — original SDA architecture & implementation proposal.
- [`docs/architecture.md`](../architecture.md) — current SDA crate map and event-flow reference.
- [`docs/revised-phase-plan.md`](../revised-phase-plan.md) — Phases 7–9 (native protocol promotion, full control plane, legacy deprecation).
- [`PROGRESS.md`](../../PROGRESS.md) — top-level SDA delivery log.
