# Licensing

This document explains the licensing posture of the SN360 Desktop
Agent (SDA): the proprietary licence on SDA's own source, the
permissive licences SDA depends on, and the clean-room policy that
keeps the boundary clean.

It is intended for reviewers (legal, engineering, compliance) who
need a short, verifiable statement of how SDA relates to
third-party security-agent codebases.

The canonical licence text is in [`../LICENSE`](../LICENSE).

---

## Table of contents

1. [Independent development](#1-independent-development)
2. [Clean-room interoperability](#2-clean-room-interoperability)
3. [Protocol architecture](#3-protocol-architecture)
4. [Dependency licensing](#4-dependency-licensing)
5. [Distribution rights](#5-distribution-rights)
6. [Verification checklist](#6-verification-checklist)
7. [Reference engines: per-engine policy](#7-reference-engines-per-engine-policy)

---

## 1. Independent development

SDA is an **independently developed** security agent written from
scratch in Rust:

- No third-party SIEM agent source code (Wazuh, OSSEC, or
  otherwise) was copied, translated, re-typed, or used as a
  template during the design or implementation of SDA.
- The SDA architecture, module boundaries, data model, resource
  budgeting strategy, and build system were authored inside this
  repository. The shipped shape of the code is documented in
  [`architecture.md`](./architecture.md).
- All crate-level code lives under `crates/sda-*` and is original
  work. The workspace depends only on third-party Rust crates
  whose licences are compatible with proprietary redistribution
  (see § 4).

Historical note: earlier internal drafts used the `wda-*` prefix
for crate and binary names. Those identifiers remain as code
tokens to avoid churn, but they do **not** imply derivation from a
third-party "Wazuh Desktop Agent" codebase — no such upstream
codebase exists, and the product is named SDA in all human-readable
prose.

---

## 2. Clean-room interoperability

SDA supports interoperability with existing SIEM managers through
a **clean-room implementation** of publicly documented wire
protocols. This is the same pattern used by mature interoperability
projects such as:

- Samba implementing SMB without reusing Microsoft's server code.
- Postfix implementing SMTP without reusing Sendmail's internals.
- Wine implementing the Win32 API from publicly documented
  behaviour.

The legacy SIEM protocol adapter in SDA was implemented against
publicly available references:

- The published Wazuh / OSSEC manager-agent wire protocol
  documentation.
- Public packet captures against a reference SIEM manager running
  in Docker (`wazuh/wazuh-manager:4.x`, which is publicly
  redistributable as a binary image).
- Public specifications for the underlying building blocks
  (Blowfish/AES-CBC, zlib, TLS 1.3, MessagePack, HTTP/2, ALPN).

No third-party agent or manager source code was consulted in the
process. The resulting adapter is an **interoperability layer**,
not a derivative work of any existing agent codebase.

---

## 3. Protocol architecture

SDA speaks two protocols. Both are implemented in the `sda-comms`
crate under `crates/sda-comms`, and the protocol used for a given
deployment is selected per-config:

- **SN360 native protocol.** TLS 1.3 + HTTP/2 + MessagePack, with
  mTLS enrolment against the SN360 Agent Gateway. Enabled by
  setting `server.protocol: http2` and flipping
  `server.enhanced.tls` and `server.enhanced.serialization: msgpack`
  on in `AgentConfig`.
- **Legacy SIEM protocol adapter.** Compiled in when the
  `legacy-siem` Cargo feature is enabled on the `sda-comms` crate
  (which is the shipped default). Implements a publicly documented
  agent wire protocol (TCP/UDP + Blowfish/AES, `authd`-compatible
  enrolment on port 1515) so the same binary can feed events into
  an existing SIEM manager while customers migrate to the SN360
  control plane.

A proprietary-only build of SDA that does not need legacy
interoperability can compile out the legacy adapter entirely:

```sh
cargo build --release -p sda-agent --no-default-features
```

With the `legacy-siem` feature off, the legacy transport,
enrolment, and encryption code are excluded from the final binary.
The only code that ships is original SN360 work plus permissively
licensed Rust crates.

---

## 4. Dependency licensing

The SDA workspace depends exclusively on third-party Rust crates
whose licences are compatible with proprietary redistribution.
Every direct and transitive dependency is licensed under one or
more of:

- MIT
- Apache-2.0 (including the dual MIT/Apache-2.0 pairing)
- BSD-2-Clause / BSD-3-Clause
- ISC
- Unicode-DFS-2016
- zlib
- MPL-2.0 (file-level copyleft; does not extend to the combined
  work and is therefore acceptable in a proprietary binary)

**No direct or transitive dependency in the SDA workspace is
licensed under GPL, AGPL, LGPL, SSPL, BUSL, or any other
strong-copyleft or source-available licence that would contaminate
a proprietary distribution.**

The dependency tree is audited via `cargo deny check licenses` on
every push (see [`security.md` § 5](./security.md#5-license-audit)
and the CI matrix). The allow-list and deny-list are defined in
[`../deny.toml`](../deny.toml); any new dependency that introduces
a copyleft licence fails CI before the PR can merge.

Notable crates that are sometimes assumed to be copyleft but are
actually permissive here:

| Crate | Licence | Notes |
|---|---|---|
| `yara` / `yara-sys` | BSD-3-Clause | The YARA engine itself is BSD; the Rust bindings inherit |
| `rusqlite` / `libsqlite3-sys` | MIT + Public Domain | SQLite core is public domain; Rust wrapper is MIT |
| `ring` | ISC + OpenSSL + MIT | Cryptographic primitives used by `rustls` |
| `rustls` | Apache-2.0 / ISC / MIT | TLS implementation used for the native protocol |
| `nix` | MIT | Safe Unix syscall wrappers |
| `windows-rs` | MIT / Apache-2.0 | Official Microsoft Windows API bindings |
| `tokio`, `serde`, `rmp-serde`, `chrono`, `bytes`, `flate2`, `sha2`, `md-5`, `socket2` | MIT / Apache-2.0 | Foundation async / serialisation / crypto utilities |

---

## 5. Distribution rights

Given the above:

1. SDA binaries may be redistributed under the SN360 proprietary
   licence (see [`../LICENSE`](../LICENSE)) with no copyleft
   obligations back to any upstream project.
2. The legacy SIEM protocol adapter, when shipped, remains an
   independent interoperability implementation; shipping it does
   not create a derivative-work relationship with any third-party
   SIEM codebase.
3. Source-code release, dual-licensing, or re-licensing decisions
   are at SN360 Inc.'s sole discretion, subject only to the
   permissive third-party crate licences (which require
   attribution but impose no source-release obligations).

---

## 6. Verification checklist

A reviewer can independently verify the claims above by running:

```sh
# No third-party SIEM agent source present in the workspace.
rg -n 'src/client-agent|src/syscheckd|src/logcollector|src/rootcheck|src/wazuh_modules' \
   -g '!docs/**' -g '!*.md'

# Dependency licences — expect only MIT / Apache-2.0 / BSD / ISC /
# Unicode-DFS / zlib / MPL-2.0. No GPL / AGPL / LGPL / SSPL / BUSL.
cargo deny --all-features check licenses

# Legacy adapter can be compiled out.
cargo build --release -p sda-agent --no-default-features
```

The expected results of these commands are captured in
[`security.md` § 5](./security.md#5-license-audit).

---

## 7. Reference engines: per-engine policy

SDA borrows *concepts* from a number of open-source and
proprietary endpoint-security projects without vendoring their
source. The policy is binding; `cargo deny check bans` enforces the
boundary mechanically.

### 7.1 Summary

| Engine | Licence | Posture | Crate / module |
|---|---|---|---|
| **EDR — excluded as source** | | | |
| CrowdStrike Falcon | Commercial proprietary | Excluded | n/a |
| SentinelOne Singularity | Commercial proprietary | Excluded | n/a |
| Microsoft Defender for Endpoint | Commercial proprietary | Excluded | n/a |
| **EDR — consumed via documented OS APIs** | | | |
| Linux `cn_proc` / netlink / audit / eBPF | Vendor-documented public OS API | Consumed | `sda-pal::process_monitor`, `sda-pal::network_monitor` |
| Windows ETW (`Microsoft-Windows-Kernel-Process`, `…-Kernel-Network`, `…-DNS-Client`) | Vendor-documented public OS API | Consumed | `sda-pal::process_monitor`, `sda-pal::network_monitor`, `sda-pal::dns_monitor` |
| macOS Endpoint Security framework | Vendor-documented public OS API (entitlement gated) | Consumed | `sda-pal::process_monitor` |
| Windows AMSI public API | Vendor-documented public OS API | Consumed (optional, feature-gated) | `sda-memory-scanner` |
| **Device Control — clean-room re-implementations** | | | |
| Fleet (MIT) | MIT | Excluded as source; reference only | concept ported across `sda-query`, `sda-policy`, `sda-software`, `sda-jit-admin`, `sda-script-runner`, `sda-agent-vitals`, `sda-management-compat` |
| Fleet EE | Proprietary (EE) | **Excluded** | none |
| MakeMeAdmin | GPL | Excluded as source; reference only | `sda-jit-admin` (Windows) |
| SAP Privileges | Apache-2.0 | Reference only — clean-room | `sda-jit-admin` (macOS) |
| Munki | Apache-2.0 | Reference only — clean-room | `sda-software` (macOS) |
| Santa / North Pole Santa | Apache-2.0 | Integrate (sidecar) on macOS; clean-room elsewhere | `sda-app-control` |
| MeshCentral | Apache-2.0 | Reference only — clean-room | `sda-remote-support` |
| Tactical RMM | Tactical RMM Licence (restricts SaaS/commercial) | **Excluded** — benchmark only, never base | none |

### 7.2 EDR — clean-room rationale

No CrowdStrike Falcon, SentinelOne Singularity, or Microsoft
Defender for Endpoint binary, source file, ETW manifest, decompiled
artefact, or licensee-restricted SDK is vendored, copied,
translated, or referenced in this repository.

SDA's EDR event schema (eight `EventKind` variants —
`ProcessCreated`, `ProcessTerminated`, `ImageLoaded`,
`NetworkConnection`, `DnsQuery`, `MemoryScanAlert`,
`HostIsolationStateChanged`, `IdentityAlert`) is original. Field
shapes are derived from the underlying OS APIs (Linux
`proc_event`, Windows `Microsoft-Windows-Kernel-Process`, macOS
Endpoint Security `es_message_t`), not from any commercial EDR
vendor's published telemetry.

SDA's behavioural-rule DSL (see
[`crates/sda-local-detection/src/behavioral.rs`](../crates/sda-local-detection/src/behavioral.rs))
is original; the `parent_chain` predicate and the threshold /
sequence matchers are derived from the Device Control rule DSL,
not from any vendor's published rule grammar.

### 7.3 Device Control — clean-room rationale

SDA Device Control is a clean-room functional re-implementation
inspired by Fleet's *concepts*. No Fleet source code (MIT or EE) is
vendored, copied, or translated. Reference engines are integrated,
wrapped, or clean-room re-implemented per the engine policy in
[`device-control.md` § 11](./device-control.md#11-clean-room-engine-policy).

Per-engine details:

- **Fleet (MIT).** MIT-licensed components are not vendored. The
  SDA agent is `sda-*` Rust on the endpoint; the SN360 control
  plane is a separate Go + NATS + Postgres stack. Neither side
  imports a line of Fleet source. The `cargo deny check licenses`
  CI job covers transitive crate exposure.
- **Fleet EE.** Fleet's enterprise-only source is barred from this
  repository. The `cargo deny` ban list explicitly denies crate
  name patterns that could transitively pull Fleet EE source.
- **MakeMeAdmin (GPL).** GPL-licensed; `sda-jit-admin` is a
  clean-room re-implementation of the concept of temporary admin
  elevation. The Windows implementation uses the documented
  `NetLocalGroupAddMembers` / `NetLocalGroupDelMember` Win32 surface
  and SDA's existing `sda-pal::AdminManager` trait, with a
  watchdog + drift detection + idempotent boot-time revoke. No
  MakeMeAdmin source code was consulted.
- **SAP Privileges (Apache-2.0).** Used as conceptual reference
  only for the macOS admin-elevation flow; the implementation is
  clean-room on top of Open Directory + `dscl`.
- **Munki (Apache-2.0).** Used as conceptual reference only for
  the macOS approved-software flow. `sda-software` is a Rust
  re-implementation of the "Munki-style local repository" approach
  (signed catalogue + pinned SHA-256 per item), not a Python port.
- **Santa / North Pole Santa (Apache-2.0).** Integrated as a
  sidecar on macOS via the public XPC service and `santactl`
  CLI; no Santa source is vendored. Windows app control
  (WDAC + AppLocker) and Linux app control (dm-verity-aware) are
  clean-room implementations.
- **MeshCentral (Apache-2.0).** Used as conceptual reference only
  for a user-consented remote-support protocol. `sda-remote-support`
  is a clean-room re-implementation riding over the SN360 native
  `sda-comms` TLS 1.3 + HTTP/2 + MessagePack stack.
- **Tactical RMM.** Tactical RMM's licence restricts SaaS /
  commercial use. SDA uses it only as a feature benchmark
  reference; no Tactical RMM source code, APIs, or protocols are
  used.

---

*Licensing inquiries: `licensing@sn360.com`.*
