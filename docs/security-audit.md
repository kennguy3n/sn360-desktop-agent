# Security Audit

SDA runs with elevated privileges on end-user devices, so every
byte that enters an agent process is an attacker-reachable input.
Phase 6 task 6.4 adds two continuous audit surfaces to the repo:

1. **Dependency auditing** via `cargo audit` in CI.
2. **Differential fuzzing** of the highest-risk parsers via
   `cargo-fuzz` + libFuzzer.

## `cargo audit`

A `cargo-audit` job in `.github/workflows/ci.yml` installs the
latest `cargo-audit` from crates.io and runs:

```sh
cargo audit --deny warnings
```

This fails CI on any unpatched advisory against a direct or
transitive dependency. Warnings-only advisories (e.g. unmaintained
crates) also fail so they cannot silently accumulate. To reproduce
locally:

```sh
cargo install --locked cargo-audit
cargo audit
```

If an advisory is acceptable (e.g. unreachable code path), document
the decision inline via `deny.toml` or the RustSec ignore key rather
than disabling the gate globally.

## Fuzzing harness

The `fuzz/` directory at the repo root is a standalone cargo-fuzz
crate (its own `[workspace]`) so it does not participate in the
main stable build. Setup:

```sh
rustup toolchain install nightly
cargo +nightly install --locked cargo-fuzz
```

Run a target for one minute:

```sh
cd fuzz
cargo +nightly fuzz run protocol_decode -- -max_total_time=60
```

### Targets

| Target                     | Function under fuzz                                              | Rationale                                                              |
|----------------------------|------------------------------------------------------------------|------------------------------------------------------------------------|
| `protocol_decode`          | `sda_comms::protocol::WazuhMessage::decode`                      | First parser on every TCP frame from `remoted`; a panic = crash loop.  |
| `protocol_decompress`      | `sda_comms::protocol::decompress_payload`                        | zlib payloads are attacker-controlled; must fail gracefully.            |
| `msgpack_event_decode`     | `sda_comms::msgpack::MessagePackSerializer::{decode_event,decode_kind}` | Phase 5.6 enhanced protocol decoder; rmp-serde panics on bad input.   |
| `rule_store_msgpack`       | `sda_local_detection::rule_store::RuleBundle::from_msgpack`      | TRDS bundle decoder runs before signature verification.                |

### Corpus management

Each target owns a corpus directory at `fuzz/corpus/<target>/`
and a crashes directory at `fuzz/artifacts/<target>/`. These are
git-ignored by default — regenerate the corpus after a parser
change so libFuzzer's mutation engine has diverse seeds to work
from. Seed corpora can be committed under
`fuzz/seeds/<target>/` for reproducibility.

### Coverage goals

The Phase 6 exit criteria for fuzzing are:

- Each target runs in CI nightly for at least 5 minutes with
  `-max_total_time=300` and 0 crashes.
- Coverage (`cargo +nightly fuzz coverage`) for each parser module
  is ≥ 80 % of lines.

Nightly CI wiring for the fuzz targets is tracked as a follow-up
(release infrastructure item) in PROGRESS.md § Phase 6 6.4.

## License audit

SDA is distributed under a proprietary license (see
[`../LICENSE`](../LICENSE) and
[`proprietary-licensing-rationale.md`](./proprietary-licensing-rationale.md)).
To keep that posture defensible the workspace is gated to
permissive Rust crate dependencies only.

### Audit procedure

The audit is run with `cargo-license` against the full workspace
including all features (so the legacy SIEM adapter is included):

```sh
cargo install --locked cargo-license
cargo license --all-features
```

Each third-party package's SPDX expression is inspected for
strong-copyleft or source-available clauses. The expected allow-list
is:

- MIT
- Apache-2.0 (including the dual MIT/Apache-2.0 pairing and the
  `Apache-2.0 WITH LLVM-exception` variant)
- BSD-2-Clause / BSD-3-Clause
- ISC
- Unicode-3.0 / Unicode-DFS-2016
- zlib / Zlib
- CC0-1.0 (public-domain dedication — permissive for proprietary
  distribution)
- CDLA-Permissive-2.0 (used by `webpki-roots`; permissive)
- MPL-2.0 (file-level copyleft; does not reach the combined work —
  acceptable)

Any dependency whose SPDX expression contains `GPL`, `AGPL`,
`LGPL`, `SSPL`, `BUSL`, or `CC-BY-NC` (and is not offered under an
alternative permissive license via `OR`) must be replaced or
feature-gated out of the default build.

### Current result

Last run: see `cargo license --all-features` output on the
`devin/…-proprietary-license-refactor` branch. Summary:

- **No direct or transitive dependency in the SDA workspace is
  licensed exclusively under GPL, AGPL, LGPL, SSPL, BUSL, or any
  other strong-copyleft or source-available license.**
- One crate (`r-efi`, used indirectly by `getrandom` on UEFI
  targets) offers a triple-license `Apache-2.0 OR LGPL-2.1-or-later
  OR MIT`. SDA consumes it under `Apache-2.0` / `MIT`; the LGPL
  option is not taken.
- The 14 `LicenseRef-Proprietary` entries in the output are SDA's
  own workspace crates (`sda-*`) and are the proprietary artifact
  itself, not a third-party import.

### CI enforcement (planned)

The audit currently runs on demand. Phase 7.8 in
[`revised-phase-plan.md`](./revised-phase-plan.md) adds a
`cargo deny check licenses` gate wired into `.github/workflows/ci.yml`
with a committed `deny.toml` that encodes the allow-list above, so
a PR introducing a copyleft dependency fails CI before it can
merge.

The `deny.toml` itself landed in the Device Control Phase 0 PR (see
[`docs/device-control/PROGRESS.md`](./device-control/PROGRESS.md))
and lives at the workspace root: [`deny.toml`](../deny.toml). It
encodes both the Rust-crate licence allow-list above and the
`[bans]` entries that mechanically enforce
[`docs/device-control/ADR-001-functional-port.md`](./device-control/ADR-001-functional-port.md)
(see § "Device Control License Audit" below). Run it locally with:

```sh
cargo install --locked cargo-deny
cargo deny check licenses
cargo deny check bans
cargo deny check sources
```

## Device Control License Audit

This section is the canonical Phase 0 license review for the
ShieldNet Device Control module
([`docs/device-control/`](./device-control/)). It satisfies the
Phase 0 exit criterion in
[`docs/device-control/PHASES.md`](./device-control/PHASES.md#phase-0--architecture-legal-and-schema-2-weeks)
that "all license reviews are recorded in
[`docs/security-audit.md`](./security-audit.md) under a new
'Device Control license audit' subsection".

The decision that frames every entry below is recorded in
[`docs/device-control/ADR-001-functional-port.md`](./device-control/ADR-001-functional-port.md)
(also summarised in
[`docs/device-control/PROPOSAL.md` § 3.2](./device-control/PROPOSAL.md#32-architectural-correction--adr)):

> **SDA Device Control is a clean-room functional re-implementation
> inspired by Fleet's *concepts*. No Fleet source code (MIT or EE) is
> vendored, copied, or translated. Reference engines are
> *integrated*, *wrapped*, or *clean-room re-implemented* per the
> engine policy in
> [`docs/device-control/ARCHITECTURE.md` § 9](./device-control/ARCHITECTURE.md#9-open-source-engine-policy).
> Tactical RMM is benchmark-only — never base.**

Every subsection below follows the same shape so an external auditor
or `cargo deny check licenses` reviewer can run a quick checklist:

- **Engine** — name and upstream link.
- **License** — SPDX expression as published upstream.
- **Posture** — *Integrate*, *Wrap*, *Clean-room*, *Reference only*,
  or *Excluded*. Mirrors the wording in
  [`docs/device-control/ARCHITECTURE.md` § 9](./device-control/ARCHITECTURE.md#9-open-source-engine-policy).
- **Rationale** — why this posture is safe under the SDA proprietary
  licence (see
  [`proprietary-licensing-rationale.md`](./proprietary-licensing-rationale.md)).

### Fleet (MIT)

- **Engine.** [Fleet](https://github.com/fleetdm/fleet) — Go +
  osquery device-management server and `fleetd`/Orbit agent
  runtime, MIT-licensed.
- **License.** MIT.
- **Posture.** **Excluded as source; reference only.**
- **Rationale.**
    - **Fleet's MIT-licensed components are NOT vendored in this
      repository.** No `cmd/fleet/...`, no `server/...`, no
      Fleet-derived header file, no Fleet-derived schema is
      vendored, copied, or translated into either
      [`sn360-desktop-agent`](https://github.com/kennguy3n/sn360-desktop-agent)
      or
      [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
    - **SDA Device Control is a clean-room functional
      re-implementation.** See
      [`docs/device-control/ADR-001-functional-port.md`](./device-control/ADR-001-functional-port.md)
      and
      [`docs/device-control/fleet-capability-mapping.md`](./device-control/fleet-capability-mapping.md)
      for the per-concept mapping.
    - **No Fleet Go source code was consulted during
      implementation.** The SDA agent is `sda-*` Rust on the
      endpoint; the SN360 control plane is the existing Go +
      NATS + Postgres stack in
      [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
      Neither side imports a line of Fleet source.
    - **The `cargo deny check licenses` CI job covers transitive
      dependencies.** The workspace-root
      [`deny.toml`](../deny.toml) encodes the SDA Rust-crate
      licence allow-list and a denylist that flags any crate that
      could transitively pull a Fleet-derived module. The job is
      planned for `.github/workflows/ci.yml` per Phase 7.8 in
      [`revised-phase-plan.md`](./revised-phase-plan.md); the
      `deny.toml` lands in this Phase 0 PR so the gate has
      something to enforce when it is wired in.

### Fleet EE (Proprietary — EXCLUDED)

- **Engine.** Fleet Enterprise Edition — Fleet's enterprise-only
  feature surface (e.g. EE software-installer signing flows, EE
  scripts library, EE MDM extensions).
- **License.** Fleet Enterprise Edition — proprietary, **not
  open-source**.
- **Posture.** **Excluded.** Barred from this repository per
  [`docs/device-control/ADR-001-functional-port.md`](./device-control/ADR-001-functional-port.md).
- **Rationale.**
    - **Fleet EE source is barred from this repository.** No file
      under any Fleet `ee/...` path is vendored, copied,
      translated, or referenced by line. ADR-001 is the binding
      decision; risk #2 in
      [`docs/device-control/PHASES.md` § Risk register](./device-control/PHASES.md#risk-register)
      ("Fleet EE licensing contamination") and
      [`docs/device-control/PROPOSAL.md` § 21](./device-control/PROPOSAL.md#21-risk-register)
      track the residual exposure.
    - **CI license check must flag any Fleet EE dependency.** The
      `cargo deny check licenses` gate (Phase 7.8 — see
      [`revised-phase-plan.md`](./revised-phase-plan.md)) reads
      [`deny.toml`](../deny.toml) at the workspace root. The
      `[bans]` section explicitly denies any crate name pattern
      that could plausibly transitively pull Fleet EE source
      (e.g. `fleetdm-*`, `fleet-ee-*`); the `[licenses]` section
      retains a permissive-only allow-list so a non-MIT /
      non-Apache-2.0 / non-BSD / non-ISC / non-MPL-2.0 dependency
      cannot land silently.
    - **deny.toml entry.** A workspace-root `deny.toml` is added in
      this Phase 0 PR if one does not already exist (see
      § "License audit" earlier in this document — the existing
      cargo-license + cargo-audit posture stays as-is and is
      complemented by `cargo-deny`). The `deny.toml` is the
      operational enforcement of this subsection.

### MakeMeAdmin (GPL — reference only)

- **Engine.** [MakeMeAdmin](https://github.com/pseymour/MakeMeAdmin) —
  Windows utility that grants temporary local-administrator
  membership for a fixed window.
- **License.** GPL (strong copyleft).
- **Posture.** **Excluded as source. Reference only.** Concept-only
  reference for the `sda-jit-admin` Windows implementation.
- **Rationale.**
    - **MakeMeAdmin is GPL-licensed; SDA does NOT redistribute,
      vendor, or link against MakeMeAdmin.** The SDA workspace
      allow-list excludes GPL / AGPL / LGPL crates (see § "License
      audit" earlier in this document and
      [`proprietary-licensing-rationale.md`](./proprietary-licensing-rationale.md));
      no MakeMeAdmin binary, source file, or library is shipped
      with SDA.
    - **`sda-jit-admin` is a clean-room re-implementation of the
      *concept* of temporary admin elevation.** The Windows
      implementation uses the documented `NetLocalGroupAddMembers`
      / `NetLocalGroupDelMember` Win32 surface and SDA's existing
      `sda-pal::AdminManager` trait (see
      [`docs/device-control/ARCHITECTURE.md` § 4](./device-control/ARCHITECTURE.md)),
      with a watchdog + drift detection + idempotent boot-time
      revoke per
      [`docs/device-control/PROPOSAL.md` § 9.3](./device-control/PROPOSAL.md#93-just-in-time-admin)
      and Phase 3 in
      [`docs/device-control/PHASES.md`](./device-control/PHASES.md#phase-3--just-in-time-adminroot-2032-weeks).
    - **No MakeMeAdmin source code was consulted.** The behaviour
      contract (grant → revoke → evidence) is derived from public
      Windows API documentation, not from MakeMeAdmin's GPL
      source.

### SAP Privileges (reference only)

- **Engine.** [SAP Privileges](https://github.com/SAP/macOS-enterprise-privileges) —
  macOS utility that toggles the current console user's
  administrator membership on demand.
- **License.** Apache-2.0 (compatible) — recorded here as a
  *concept-only* reference because the macOS implementation is
  clean-room and does not vendor SAP Privileges code.
- **Posture.** **Reference only — clean-room.** Concept-only
  reference for the `sda-jit-admin` macOS implementation.
- **Rationale.**
    - **SAP Privileges is used as a conceptual reference for the
      macOS admin-elevation flow.** The concept (toggle the
      current console user's `admin` membership for a
      time-boxed grant) is well-understood and documented in
      Apple's Open Directory APIs.
    - **`sda-jit-admin` macOS implementation is clean-room; no SAP
      Privileges source vendored.** The implementation lives in
      the agent's `sda-jit-admin` crate (Phase 3) on top of the
      `sda-pal::AdminManager` macOS provider, which uses Open
      Directory + `dscl` for `admin` group enumeration and
      mutation per
      [`docs/device-control/PROPOSAL.md` § 9.3](./device-control/PROPOSAL.md#93-just-in-time-admin).
    - **Defence-in-depth.** Even though SAP Privileges' Apache-2.0
      licence is permissive and would be compatible with SDA's
      Rust crate allow-list, treating it as concept-only avoids
      any "consulted-source" contamination claim and keeps the
      ADR-001 audit trail simple.

### Munki (Apache-2.0 — reference only)

- **Engine.** [Munki](https://github.com/munki/munki) — Python
  managed-software-installer for macOS; Apache-2.0.
- **License.** Apache-2.0 (compatible).
- **Posture.** **Reference only — clean-room.** Concept-only
  reference for the `sda-software` macOS implementation.
- **Rationale.**
    - **Munki is Apache-2.0 licensed; SDA does NOT vendor Munki
      code.** Although Apache-2.0 would be compatible with SDA's
      Rust-crate allow-list, the implementation is not a Python
      port — it is a Rust re-implementation of the *Munki-style
      local repository* approach.
    - **`sda-software` macOS implementation is a clean-room
      "Munki-style" local-repo approach.** The agent fetches a
      signed package catalogue (Ed25519-signed manifest + pinned
      SHA-256 per item) from the SN360 control plane and applies
      install / update / uninstall jobs through the `PackageManager`
      PAL trait. See
      [`docs/device-control/PROPOSAL.md` § 9.4–9.5](./device-control/PROPOSAL.md#94-approved-software-catalogue)
      and Phase 2 in
      [`docs/device-control/PHASES.md`](./device-control/PHASES.md#phase-2--push-software--approved-catalogue-1220-weeks).
    - **The design is inspired by Munki's architecture but no
      source code is copied.** The wire format, manifest schema,
      and on-disk repository layout are SDA-original and live in
      `sda-software` + the SN360 Package Catalog service.

### Santa / North Pole Santa (Apache-2.0)

- **Engine.** [Santa](https://github.com/northpolesec/santa) — macOS
  Endpoint Security app-control system (formerly Google Santa, now
  maintained by North Pole Security); Apache-2.0.
- **License.** Apache-2.0 (compatible).
- **Posture.** **Integrate (sidecar) on macOS; clean-room
  equivalents on Windows and Linux.**
- **Rationale.**
    - **Santa is Apache-2.0; `sda-app-control` on macOS will
      integrate with Santa as a sidecar (similar to the osquery
      integration pattern).** The integration surface is Santa's
      public API / CLI (`santactl`, the `com.northpolesec.santa`
      XPC service); Santa runs in its own process under its own
      resource budget per
      [`docs/device-control/ARCHITECTURE.md` § 4](./device-control/ARCHITECTURE.md)
      and
      [`docs/device-control/PROPOSAL.md` § 15.2](./device-control/PROPOSAL.md#152-resource-budgets).
    - **No Santa source code is vendored; integration is via
      Santa's public API/CLI.** SDA shells out to / talks XPC to
      Santa; we do not link against Santa's libraries or
      translate Santa code into Rust.
    - **Windows and Linux app control are clean-room
      implementations (WDAC + AppLocker on Windows; dm-verity-aware
      on Linux respectively).** See
      [`docs/device-control/PROPOSAL.md` § 9.6](./device-control/PROPOSAL.md#96-app-control)
      and Phase 4 in
      [`docs/device-control/PHASES.md`](./device-control/PHASES.md#phase-4--remote-support--app-control--mdm-connectors-3248-weeks).

### MeshCentral (Apache-2.0 — reference only)

- **Engine.** [MeshCentral](https://github.com/Ylianst/MeshCentral) —
  Node.js remote-management web server; Apache-2.0.
- **License.** Apache-2.0 (compatible).
- **Posture.** **Reference only — clean-room.** Concept-only
  reference for the `sda-remote-support` protocol.
- **Rationale.**
    - **MeshCentral is Apache-2.0; SDA does NOT vendor MeshCentral
      code.** Apache-2.0 is allow-listed, but MeshCentral is a
      Node.js stack and would not fit SDA's `sda-*` Rust runtime
      or the `sda-comms` native protocol surface.
    - **`sda-remote-support` is a clean-room re-implementation of a
      MeshCentral-style remote-support protocol.** The wire
      format, session lifecycle, and consent model are SDA-original
      and ride over the existing `sda-comms` TLS 1.3 + HTTP/2 +
      MessagePack stack. See
      [`docs/device-control/PROPOSAL.md` § 9.7](./device-control/PROPOSAL.md#97-remote-support)
      and Phase 4 in
      [`docs/device-control/PHASES.md`](./device-control/PHASES.md#phase-4--remote-support--app-control--mdm-connectors-3248-weeks).
    - **The protocol design is original; only the high-level concept
      (user-consented remote desktop) is referenced.** Risk #8 in
      [`docs/device-control/PROPOSAL.md` § 21](./device-control/PROPOSAL.md#21-risk-register)
      tracks the residual privacy exposure (consent banner always
      visible, session time-bounded, audited per session).

### Tactical RMM (BENCHMARK ONLY — never base)

- **Engine.** [Tactical RMM](https://github.com/amidaware/tacticalrmm) —
  Django + Go RMM agent and server.
- **License.** Tactical RMM Licence — restricts SaaS / commercial
  use. Not allow-listed for SDA / SN360 distribution.
- **Posture.** **Excluded — benchmark only, never base.**
- **Rationale.**
    - **Tactical RMM's license restricts SaaS / commercial use.**
      SN360 is a multi-tenant SaaS-shaped product, so adopting
      Tactical RMM as a code base would be a licence violation
      from day one.
    - **SDA uses Tactical RMM only as a feature benchmark
      reference.** It is consulted to enumerate the capability set
      a customer might expect from a generalist RMM ("what
      capabilities exist in the RMM space"); no Tactical RMM
      design becomes part of the
      [PROPOSAL.md § 2.2](./device-control/PROPOSAL.md#22-customer-facing-examples)
      example list, and no Tactical RMM behaviour ships in MVP per
      [`PROPOSAL.md` § 2.3](./device-control/PROPOSAL.md#23-product-boundary).
    - **No Tactical RMM source code, APIs, or protocols are used
      in SDA.** Neither the agent nor the SN360 control plane
      imports Tactical RMM code, schemas, or wire formats. The
      `cargo deny check licenses` gate covers any transitive
      crate that could change this posture.
    - **This is explicitly called out in
      [`docs/device-control/ARCHITECTURE.md` § 9 row 13](./device-control/ARCHITECTURE.md#9-open-source-engine-policy).**
      The engine-policy table in
      [`docs/device-control/PROPOSAL.md` § 20 row 13](./device-control/PROPOSAL.md#20-open-source-and-platform-engine-policy)
      carries the same posture; ARCHITECTURE.md § 9 is the
      canonical reference.

### Summary table

| Engine | License | Posture | Crate / module | ADR-001 contact point |
|---|---|---|---|---|
| Fleet (MIT) | MIT | Excluded as source; reference only | n/a (concept ported across `sda-query`, `sda-policy`, `sda-software`, `sda-jit-admin`, `sda-script-runner`, `sda-agent-vitals`, `sda-management-compat`) | [ADR-001 § Decision](./device-control/ADR-001-functional-port.md#decision) |
| Fleet EE | Proprietary (EE) | **Excluded** | none | [ADR-001 § Decision #2](./device-control/ADR-001-functional-port.md#decision) |
| MakeMeAdmin | GPL | Excluded as source; reference only | `sda-jit-admin` (Windows) | [ADR-001 § Alternatives D](./device-control/ADR-001-functional-port.md#alternatives-considered) |
| SAP Privileges | Apache-2.0 | Reference only — clean-room | `sda-jit-admin` (macOS) | [ADR-001 § Alternatives D](./device-control/ADR-001-functional-port.md#alternatives-considered) |
| Munki | Apache-2.0 | Reference only — clean-room | `sda-software` (macOS) | [ADR-001 § Alternatives D](./device-control/ADR-001-functional-port.md#alternatives-considered) |
| Santa / North Pole Santa | Apache-2.0 | Integrate (sidecar) on macOS; clean-room elsewhere | `sda-app-control` | [ADR-001 § Alternatives E](./device-control/ADR-001-functional-port.md#alternatives-considered) |
| MeshCentral | Apache-2.0 | Reference only — clean-room | `sda-remote-support` | [ADR-001 § Alternatives D](./device-control/ADR-001-functional-port.md#alternatives-considered) |
| Tactical RMM | Tactical RMM Licence (restricts SaaS / commercial) | **Excluded** — benchmark only, never base | none | [ADR-001 § Alternatives C](./device-control/ADR-001-functional-port.md#alternatives-considered) |

## EDR Parity License Audit

This section is the canonical Phase E0 license review for the
ShieldNet EDR Parity workstream
([`docs/edr-parity/`](./edr-parity/)). It satisfies the Phase E0
exit criterion in
[`docs/edr-parity/PHASES.md`](./edr-parity/PHASES.md#phase-e0--architecture--schema-2-weeks)
task E0.5 that "the clean-room license audit is recorded in
[`docs/security-audit.md`](./security-audit.md) under a new
'EDR Parity License Audit' subsection."

The decision that frames every entry below is recorded in
[`docs/edr-parity/PROPOSAL.md` § 4](./edr-parity/PROPOSAL.md):

> **SDA EDR Parity is a clean-room functional re-implementation
> inspired by EDR concepts. No CrowdStrike Falcon, SentinelOne
> Singularity, or Microsoft Defender for Endpoint source code is
> vendored, copied, or translated. All Phase E1–E5 PAL
> implementations use vendor-documented public APIs only: Linux
> `cn_proc` netlink connector, audit subsystem, eBPF; Windows ETW
> providers documented in the Windows Software Development Kit;
> macOS Endpoint Security framework documented in the macOS
> Platform SDK.**

The audit follows the same shape as the Device Control License
Audit subsection above.

### CrowdStrike Falcon (Proprietary — EXCLUDED)

- **Engine.** [CrowdStrike Falcon](https://www.crowdstrike.com/products/endpoint-security/falcon-platform/) —
  cloud-native EDR / XDR platform.
- **License.** CrowdStrike commercial — proprietary, **not
  open-source**.
- **Posture.** **Excluded.** Barred from this repository per
  [`docs/edr-parity/PROPOSAL.md` § 4](./edr-parity/PROPOSAL.md).
- **Rationale.**
    - **CrowdStrike Falcon is closed-source commercial software.**
      No CrowdStrike Falcon binary, source file, ETW manifest,
      decompiled artefact, or licensee-restricted SDK is vendored,
      copied, translated, or referenced by line in either
      [`sn360-desktop-agent`](https://github.com/kennguy3n/sn360-desktop-agent)
      or
      [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
    - **No CrowdStrike public documentation drove the SDA wire
      schema.** SDA's EDR event schema (eight new `EventKind`
      variants — `ProcessCreated`, `ProcessTerminated`,
      `ImageLoaded`, `NetworkConnection`, `DnsQuery`,
      `MemoryScanAlert`, `HostIsolationStateChanged`,
      `IdentityAlert`) is original; the field shapes are derived
      from the underlying OS APIs (Linux `proc_event`, Windows
      `Microsoft-Windows-Kernel-Process`, macOS Endpoint Security
      `es_message_t`), not from CrowdStrike's published telemetry.
    - **CI license check covers transitive crate exposure.** The
      `cargo deny check licenses` gate (Phase 7.8 — see
      [`revised-phase-plan.md`](./revised-phase-plan.md)) reads
      [`deny.toml`](../deny.toml) which retains a permissive-only
      Rust crate allow-list, so no proprietary EDR-vendor crate
      can land silently.

### SentinelOne Singularity (Proprietary — EXCLUDED)

- **Engine.** [SentinelOne Singularity](https://www.sentinelone.com/platform/singularity-platform/) —
  AI-driven EDR / XDR platform.
- **License.** SentinelOne commercial — proprietary, **not
  open-source**.
- **Posture.** **Excluded.** Same posture as CrowdStrike Falcon.
- **Rationale.**
    - **SentinelOne Singularity is closed-source commercial
      software.** No SentinelOne binary, source file, behavioural
      AI model, decompiled artefact, or licensee-restricted SDK
      is vendored or referenced.
    - **No SentinelOne public documentation drove the SDA
      behavioural rule DSL.** SDA's behavioural rule DSL (see
      [`crates/sda-local-detection/src/behavioral.rs`](../crates/sda-local-detection/src/behavioral.rs))
      is original; the `parent_chain` predicate and the
      threshold / sequence matchers are derived from the existing
      Phase D Device Control rule DSL, not from SentinelOne's
      published rule grammar.

### Microsoft Defender for Endpoint (Proprietary — EXCLUDED)

- **Engine.** [Microsoft Defender for Endpoint](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-endpoint) —
  Microsoft's enterprise EDR component of Microsoft 365 Defender.
- **License.** Microsoft commercial — proprietary, **not
  open-source**. The Defender ATP source code is Microsoft
  internal and not redistributable.
- **Posture.** **Excluded.** Same posture as CrowdStrike and
  SentinelOne.
- **Rationale.**
    - **Microsoft Defender for Endpoint is closed-source
      commercial software.** No Defender binary, source file,
      ATP detection rule, or licensee-restricted SDK is vendored,
      copied, translated, or referenced.
    - **SDA only consumes documented Windows public APIs.** The
      Windows ETW providers SDA subscribes to
      (`Microsoft-Windows-Kernel-Process`,
      `Microsoft-Windows-Kernel-Network`,
      `Microsoft-Windows-DNS-Client`) are documented in the
      Windows Software Development Kit and are part of the
      public ETW surface. ETW is a general-purpose Windows
      tracing facility, not a Defender-specific API. SDA does
      not import any Defender-specific binary, header, or
      protocol.
    - **AMSI integration (Phase E4.7, optional, feature-gated)
      uses the documented AMSI public API only.** The
      `IAntimalwareProvider` interface is part of the Windows
      Software Development Kit; SDA uses it as a documented
      consumer, not as a Defender source-code reference. See
      [`docs/edr-parity/PHASES.md` § E4.7](./edr-parity/PHASES.md).

### Reference OS APIs (vendor-documented public surface)

The Phase E1–E3 PAL implementations consume the following
vendor-documented public APIs. These are not engines under SDA's
clean-room policy — they are platform primitives.

- **Linux.** `NETLINK_CONNECTOR` + `CN_IDX_PROC` proc events
  (documented in `Documentation/admin-guide/cn_proc.rst` upstream);
  `AUDIT_SOCKADDR` / `AUDIT_CONNECT` audit subsystem (documented
  in `audit-userspace`); `INET_DIAG` netlink (documented in
  `linux/inet_diag.h`); `/proc/net/{tcp,tcp6,udp,udp6}` and
  `/proc/<pid>/fd` procfs (documented in `proc(5)`);
  `nftables` (documented in `man 8 nft`).
- **Windows.** ETW providers — `Microsoft-Windows-Kernel-Process`,
  `Microsoft-Windows-Kernel-Network`,
  `Microsoft-Windows-DNS-Client` (documented in the Windows
  Software Development Kit); Windows Filtering Platform (WFP)
  COM API (documented in the WDK); `netsh advfirewall`
  (documented in Microsoft Learn).
- **macOS.** Endpoint Security framework — `es_new_client`,
  `ES_EVENT_TYPE_NOTIFY_EXEC`, `ES_EVENT_TYPE_NOTIFY_FORK`,
  `ES_EVENT_TYPE_NOTIFY_EXIT`, `ES_EVENT_TYPE_NOTIFY_MMAP`
  (documented in the macOS Platform SDK); Network Extension
  framework — `NEFilterDataProvider`, `NEDNSProxyProvider`
  (documented in the macOS Platform SDK); `pfctl` anchor (BSD
  pf documented in `pfctl(8)`).

### Summary table (EDR Parity)

| Engine | License | Posture | Crate / module | EDR Parity contact point |
|---|---|---|---|---|
| CrowdStrike Falcon | Commercial proprietary | **Excluded** | none | [PROPOSAL.md § 4](./edr-parity/PROPOSAL.md) |
| SentinelOne Singularity | Commercial proprietary | **Excluded** | none | [PROPOSAL.md § 4](./edr-parity/PROPOSAL.md) |
| Microsoft Defender for Endpoint | Commercial proprietary | **Excluded** | none | [PROPOSAL.md § 4](./edr-parity/PROPOSAL.md) |
| Linux `cn_proc` / netlink / audit / eBPF | Vendor-documented public OS API | Consumed | `sda-pal::process_monitor`, `sda-pal::network_monitor` | [ARCHITECTURE.md § 5](./edr-parity/ARCHITECTURE.md) |
| Windows ETW (`Microsoft-Windows-Kernel-Process`, `…-Kernel-Network`, `…-DNS-Client`) | Vendor-documented public OS API | Consumed | `sda-pal::process_monitor`, `sda-pal::network_monitor`, `sda-pal::dns_monitor` | [ARCHITECTURE.md § 5](./edr-parity/ARCHITECTURE.md) |
| macOS Endpoint Security framework | Vendor-documented public OS API (entitlement gated) | Consumed | `sda-pal::process_monitor` | [ARCHITECTURE.md § 5](./edr-parity/ARCHITECTURE.md) |
| `nftables` / `pfctl` / Windows Firewall + WFP | Vendor-documented public OS API | Consumed | `sda-pal::host_isolation` | [ARCHITECTURE.md § 5](./edr-parity/ARCHITECTURE.md) |

## Reporting a vulnerability

Confirmed vulnerabilities should be emailed to
`security@uney.com` with `[sda]` in the subject line. Do **not**
open public GitHub issues for unpatched security reports.
