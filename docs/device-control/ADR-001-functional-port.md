# ADR-001 — ShieldNet Device Control is a functional port, not a Fleet source-code port

> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)
> **Status:** Accepted | **Date:** May 2026
> **Deciders:** SN360 Desktop Agent maintainers
> **Scope:** [`sn360-desktop-agent`](https://github.com/kennguy3n/sn360-desktop-agent)
> + [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)

---

## Status

**Accepted.** Binding for every Device Control PR in
[`sn360-desktop-agent`](https://github.com/kennguy3n/sn360-desktop-agent).
The summary lives in
[`PROPOSAL.md` § 3.2](./PROPOSAL.md#32-architectural-correction--adr); this
file is the canonical, standalone record.

## Context

ShieldNet 360 (SN360) ships a Rust endpoint security agent —
SN360 Desktop Agent (SDA) — with file integrity monitoring, log
collection, inventory, security configuration assessment, rootkit
detection, on-device detection, active response, and CycloneDX SBOM
generation (Phases 1–6 complete, 433/433 unit tests, 14/14 base E2E,
10/10 security E2E).

ShieldNet Device Control is the next product surface: SME-first
device management — admin-rights review, approved software
catalogue, just-in-time admin, evidence records, and SMI sub-scores
fed into the SN360 control plane.

[Fleet](https://github.com/fleetdm/fleet) (Go + osquery) is the
closest functional reference for the capabilities we want to ship,
and a tempting starting point. It is also a project with three
serious complications for this repository:

1. **Mixed licensing.** Fleet ships under MIT (the open-source
   server) plus a separate **Fleet Enterprise Edition (EE)**
   proprietary licence for several enterprise features. Mixing EE
   code into a proprietary product is a non-starter.
2. **Wrong runtime.** Fleet's server is Go and its agent runtime is
   `fleetd` / Orbit. SDA is Rust; the SN360 control plane is Go but
   already speaks NATS / Postgres / OpenSearch via existing services.
   Bolting Fleet onto either side would duplicate infrastructure.
3. **Wrong protocol surface.** Fleet's MySQL schema, MDM ADE/DEP/VPP
   surfaces, Sails.js website, and DRI / handbook-as-code
   governance are out of scope for SN360 — but they ride alongside
   the parts we do want.

The cheap answer is to fork Fleet and bolt it on. The correct
answer — and the only one that keeps SDA's resource budgets, the
SN360 control plane, and the proprietary licence posture of this
repository defensible — is a clean-room functional port.

## Decision

ShieldNet Device Control is a **clean-room functional
re-implementation** inspired by Fleet's *concepts*. It is **not** a
line-by-line Fleet source-code port.

The decision rests on four binding commitments:

1. **Clean-room, concept-only port.** SDA Device Control is a
   clean-room functional re-implementation inspired by Fleet's
   *concepts* (declarative queries, software management,
   just-in-time admin, policies, software jobs, agent vitals, GitOps
   workflows, evidence-driven activities). The *capabilities* are
   ported; the *implementation* is original.
2. **No Fleet source code.** No Fleet source code — MIT or
   Enterprise Edition — is vendored, copied, or translated into
   this repository. Fleet's Go server source, `fleetd`/Orbit agent
   runtime, MySQL schema, MDM ADE/DEP/VPP integrations, and Sails.js
   website are explicitly barred (see
   [`PROPOSAL.md` § 4.2](./PROPOSAL.md#42-do-not-port-list)). No
   Fleet Go source code was consulted during the design of this
   work.
3. **SDA-native architecture.** The implementation reuses SDA's
   existing Rust crate workspace under `crates/sda-*`, the bounded
   priority event bus (`sda-event-bus`), the SN360 native protocol
   (`sda-comms` — TLS 1.3 + HTTP/2 + MessagePack), the YAML
   configuration model (`sda-core::config`), and the per-OS PAL
   patterns (`sda-pal`). Every new Device Control crate is `sda-*`
   Rust; there is no Go on the endpoint and no kernel extension SDA
   does not author.
4. **Reference engines per the engine policy.** Reference engines
   (osquery, Santa / North Pole Santa, WinGet, Munki, MakeMeAdmin,
   SAP Privileges, MeshCentral, Tactical RMM, etc.) are
   *integrated*, *wrapped*, or *clean-room re-implemented* per the
   engine policy in
   [`ARCHITECTURE.md` § 9 — Open-source engine policy](./ARCHITECTURE.md#9-open-source-engine-policy).
   The license posture for each is documented in
   [`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit).
   **Tactical RMM is benchmark-only — never base.**

## Consequences

### Positive

- **Licence posture is defensible.** The proprietary licence on
  this repository (see [`../../LICENSE`](../../LICENSE) and
  [`../proprietary-licensing-rationale.md`](../proprietary-licensing-rationale.md))
  is not weakened by GPL, AGPL, LGPL, SSPL, or BUSL exposure. The
  workspace allow-list (MIT / Apache-2.0 / BSD / ISC / MPL-2.0 / a
  small set of permissive variants) continues to apply.
- **Resource budgets remain achievable.** Idle RSS < 15 MB, idle
  CPU < 0.1 %, FIM scan peak < 3 %, binary < 7 MB stay enforceable
  because every Device Control crate is `sda-*` Rust under the same
  benchmark gate. We are not paying for a Go runtime, an MDM
  daemon, or a second event bus on the endpoint.
- **Existing investment compounds.** The event bus, the comms
  layer, the PAL, the updater, the privilege-separation and
  tamper-protection work from Phase 5 are all reused. Device
  Control is additive, not parallel.
- **Control-plane reuse.** The SN360 control plane already runs
  NATS, Postgres (with row-level security), and OpenSearch.
  Device-Control control-plane services land alongside TRDS / IOCFS
  / SIS in [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform),
  not in a parallel Fleet stack.
- **Audit trail is explicit.** ADR-001 + the per-engine license
  audit in [`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit)
  + the workspace `deny.toml` give an external auditor a single
  trail to follow when verifying that Fleet-EE / MakeMeAdmin /
  Tactical RMM source has not crept in.

### Negative

- **More implementation work.** Every Fleet capability we want has
  to be re-implemented from scratch in Rust. We can read Fleet's
  *documentation* and *protocol descriptions*, but not its Go
  source. Phases 1–4 in [`PHASES.md`](./PHASES.md) reflect that
  cost.
- **No Fleet community drop-in compatibility.** Operators familiar
  with `fleetctl`, the Fleet web UI, or the Fleet GitOps YAML
  schema do not get a drop-in agent. This is mitigated by the
  optional `sda-management-compat` shim in Phase 5 (see
  [`PROPOSAL.md` § 6](./PROPOSAL.md#6-new-sda-crates)), which
  translates Fleet-flavoured GitOps YAML into SDA's signed-job
  format — but only as a migration path, not a hard dependency.
- **Engine integrations are still constrained.** Even where we
  *integrate* an upstream engine (osquery, Santa), we are bound by
  that engine's licence terms (Apache-2.0 in both cases) and must
  treat the binary as an out-of-process sidecar with its own
  resource budget.
- **CI guardrails are now load-bearing.** The
  `cargo deny check licenses` job and `deny.toml` allow-list in
  this repository are the mechanical enforcement of this ADR; if
  the gate is removed or downgraded the ADR is much harder to
  verify after the fact.

### Risks tracked elsewhere

- **Fleet EE licensing contamination** — risk #2 in
  [`PHASES.md` § Risk register](./PHASES.md#risk-register) and
  [`PROPOSAL.md` § 21](./PROPOSAL.md#21-risk-register). Mitigation:
  this ADR + Phase 0 license audit + CI license check.
- **Tactical RMM exposure** — covered in
  [`ARCHITECTURE.md` § 9 row 13](./ARCHITECTURE.md#9-open-source-engine-policy)
  and the Tactical RMM subsection of
  [`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit).
- **Multi-tenant MSP data leakage** — risk #9; mitigated by
  existing Postgres RLS + per-tenant signing keys + agent-side
  `tenant_id` validation.

## Alternatives considered

### A. Fork Fleet and integrate as a sidecar

**Rejected.** Forking Fleet imports the entire MIT codebase plus
the EE licensing surface area. Even if we held the line at
"MIT-only", any future Fleet upstream that mixes EE code into a
shared file (a real risk in mono-repos) becomes a contamination
event. The agent runtime would also be `fleetd` rather than SDA,
duplicating the Phase 5 hardening work we have already done.

### B. Vendor Fleet's Go server source as inspiration only

**Rejected.** "Inspiration only" is not a defensible audit posture
once the code is in the tree. The proprietary licence on this
repository (see [`../proprietary-licensing-rationale.md`](../proprietary-licensing-rationale.md))
makes any vendoring of GPL/AGPL/LGPL adjacent code or MIT code
that ships side-by-side with EE code a needless legal risk for no
runtime benefit (we are not running Go on the endpoint).

### C. Build on Tactical RMM

**Rejected.** Tactical RMM's licence restricts SaaS / commercial
use; SN360 is a multi-tenant SaaS-shaped product. Tactical RMM is
useful as a *feature benchmark* (what RMM capabilities exist in
the market) and is treated as such throughout
[`ARCHITECTURE.md` § 9 row 13](./ARCHITECTURE.md#9-open-source-engine-policy)
and [`PROPOSAL.md` § 20](./PROPOSAL.md#20-open-source-and-platform-engine-policy).
No Tactical RMM source, APIs, or protocols are used.

### D. Build on MakeMeAdmin / SAP Privileges / Munki / MeshCentral source

**Rejected on a per-engine basis.**

- **MakeMeAdmin** is GPL — using its source would force the GPL
  onto SDA. We re-implement the temporary-admin elevation
  *concept* in `sda-jit-admin` clean-room.
- **SAP Privileges** is used as a conceptual reference for the
  macOS admin-elevation flow only. No source is vendored.
- **Munki** is Apache-2.0 (compatible) but is a Python codebase
  that wraps a different security model than SDA's signed-job
  pipeline. We re-implement the Munki-style local-repo approach in
  `sda-software` clean-room.
- **MeshCentral** is Apache-2.0 (compatible) but is a Node.js
  service. The `sda-remote-support` wire format is an original
  clean-room design; only the high-level *concept* (operator-
  initiated, user-consented remote support) is referenced.

The clean-room constraint avoids any "consulted-source"
contamination claim and keeps the licence audit trail simple: SDA
ships SDA-original code under the SDA proprietary licence, plus
permissively-licensed dependencies on the Rust ecosystem
allow-list.

### E. Use Santa / North Pole Santa source as a Rust port

**Partially adopted.** Santa (Apache-2.0) is *integrated* on macOS
as a sidecar (mirroring the osquery integration pattern). Its
public API/CLI is the integration surface; no Santa source is
vendored or translated into Rust. Windows app control is a
clean-room WDAC equivalent; Linux app control is clean-room
dm-verity-aware.

## Compliance & enforcement

- **Documentation.** This ADR + the per-engine license audit in
  [`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit)
  + the engine policy table in
  [`ARCHITECTURE.md` § 9](./ARCHITECTURE.md#9-open-source-engine-policy)
  are the canonical record.
- **Workspace.** [`deny.toml`](../../deny.toml) at the workspace
  root encodes the SDA Rust-crate licence allow-list and a denylist
  for any crate that could transitively pull Fleet EE source. Run
  `cargo deny check licenses` to verify.
- **CI.** A `cargo deny check licenses` gate is planned in
  `.github/workflows/ci.yml` (tracked by Phase 7.8 in
  [`../revised-phase-plan.md`](../revised-phase-plan.md)). When the
  gate lands it must read the same `deny.toml`.
- **Code review.** Every Device Control PR must point at a customer
  example in [`PROPOSAL.md` § 2.2](./PROPOSAL.md#22-customer-facing-examples)
  *and* keep its dependencies inside the `deny.toml` allow-list.
  PRs that introduce a Fleet-derived file, a GPL/AGPL/LGPL/SSPL
  dependency, a Tactical RMM source dependency, or a copy of Fleet
  Go source under any header are rejected at review.

## References

- [`PROPOSAL.md`](./PROPOSAL.md) — full Device Control technical
  proposal (§ 3.2 ADR summary, § 4 Fleet capability mapping,
  § 4.2 do-not-port list, § 20 engine policy).
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — Device Control
  architecture; § 9 open-source engine policy.
- [`PHASES.md`](./PHASES.md) — phased delivery plan; Phase 0 task
  table; risk register row 2 ("Fleet EE licensing contamination").
- [`PROGRESS.md`](./PROGRESS.md) — Device Control delivery log.
- [`fleet-capability-mapping.md`](./fleet-capability-mapping.md) —
  detailed Fleet → SDA / SN360 capability map and do-not-port list.
- [`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit) —
  per-engine license posture (Fleet MIT / Fleet EE / MakeMeAdmin /
  SAP Privileges / Munki / Santa / MeshCentral / Tactical RMM).
- [`docs/proprietary-licensing-rationale.md`](../proprietary-licensing-rationale.md) —
  why SDA ships under a proprietary licence and how the
  Rust-crate allow-list keeps that posture defensible.
- [`deny.toml`](../../deny.toml) — workspace-root licence and
  source policy enforced by `cargo deny check licenses`.
