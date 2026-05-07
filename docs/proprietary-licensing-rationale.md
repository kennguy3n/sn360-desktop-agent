# SDA Proprietary Licensing Rationale

This document explains the licensing posture of the SN360 Desktop
Agent (SDA) and, specifically, why SDA can be shipped as a
proprietary product despite providing interoperability with
publicly documented SIEM manager protocols.

It is intended for reviewers (legal, engineering, compliance) who
need a short, verifiable statement of how SDA relates to
third-party security-agent codebases.

---

## 1. Independent development

SDA is an **independently developed** security agent written from
scratch in Rust. Concretely:

- No third-party SIEM agent source code (Wazuh, OSSEC, or
  otherwise) was copied, translated, re-typed, or used as a
  template during the design or implementation of SDA.
- The SDA architecture, module boundaries, data model, resource
  budgeting strategy, and build system were authored inside this
  repository. The design rationale is captured in
  [`device-agent-proposal.md`](../device-agent-proposal.md) and the
  shipped shape of the code is documented in
  [`docs/architecture.md`](./architecture.md).
- All crate-level code lives under `crates/sda-*` and is original
  work. The workspace depends only on third-party Rust crates
  whose licenses are compatible with proprietary redistribution
  (see § 4 below).

Historical note: earlier internal drafts used the `wda-*` prefix
for crate and binary names. Those identifiers remain as code
tokens to avoid churn, but they do **not** imply any derivation
from a third-party "Wazuh Desktop Agent" codebase — no such
upstream codebase exists, and the product is named SDA in all
human-readable prose.

## 2. Clean-room interoperability

SDA supports interoperability with existing SIEM managers through
a **clean-room implementation** of publicly documented wire
protocols. This is the same pattern used by mature interoperability
projects such as:

- Samba implementing SMB without reusing Microsoft's server code.
- Postfix implementing SMTP without reusing Sendmail's internals.
- Wine implementing the Win32 API from publicly documented
  behavior.

Specifically, the optional legacy SIEM protocol adapter in SDA
(see § 3) was implemented against publicly available references:

- The published Wazuh / OSSEC manager-agent wire protocol
  documentation and RFC-style descriptions.
- Public packet captures against a reference SIEM manager running
  in Docker (`wazuh/wazuh-manager:4.x`, which is publicly
  redistributable as a binary image).
- Publicly available protocol specifications for the underlying
  building blocks (Blowfish/AES-CBC, zlib, TLS 1.3, MessagePack,
  HTTP/2, ALPN).

No third-party agent or manager source code was consulted in the
process. The resulting adapter is an **interoperability layer**,
not a derivative work of any existing agent codebase.

## 3. Protocol architecture — native opt-in, legacy adapter default

SDA speaks two protocols. Both are implemented in the
`sda-comms` crate under `crates/sda-comms`, and the protocol used
for a given deployment is selected per-config:

- **SN360 native protocol (opt-in today, default on the roadmap).**
  TLS 1.3 + HTTP/2 + MessagePack, with mTLS enrolment against the
  SN360 Agent Gateway. Enabled by setting `server.protocol:
  http2` and flipping `server.enhanced.tls` and
  `server.enhanced.serialization: msgpack` on in `AgentConfig`.
  The [revised phase plan](./revised-phase-plan.md) tracks
  promoting this path to default-on once the SN360 Agent Gateway
  is generally available.
- **Legacy SIEM protocol adapter (default today, feature-gated).**
  Compiled in when the `legacy-siem` Cargo feature is enabled on
  the `sda-comms` crate (which is the shipped default). Implements
  a publicly documented agent wire protocol (TCP/UDP +
  Blowfish/AES, `authd`-compatible enrolment on port 1515) so the
  same binary can feed events into an existing SIEM manager while
  customers migrate to the SN360 Control Plane.

A proprietary-only build of SDA that does not need legacy
interoperability can compile out the legacy adapter entirely:

```
cargo build --release -p sda-agent --no-default-features
```

With the `legacy-siem` feature off, the legacy transport,
enrolment, and encryption code are excluded from the final
binary. The only code that ships is original SN360 work plus
permissively licensed Rust crates (see § 4).

## 4. Dependency licensing

The SDA workspace depends exclusively on third-party Rust crates
whose licenses are compatible with proprietary redistribution.
Concretely, every direct and transitive dependency in the
workspace is licensed under one or more of:

- MIT
- Apache-2.0 (including the common dual MIT/Apache-2.0 pairing)
- BSD-2-Clause / BSD-3-Clause
- ISC
- Unicode-DFS-2016
- zlib
- MPL-2.0 (file-level copyleft; does not extend to the combined
  work and is therefore acceptable in a proprietary binary)

**No direct or transitive dependency in the SDA workspace is
licensed under GPL, AGPL, LGPL, SSPL, BUSL, or any other
strong-copyleft or source-available license that would
contaminate a proprietary distribution.**

The dependency tree is audited via `cargo deny check licenses`
on every push (see [`security-audit.md`](./security-audit.md) and
the CI matrix). The allow-list and deny-list are defined in
`deny.toml`; any new dependency that introduces a copyleft
license fails CI before the PR can merge.

Notable crates that are sometimes assumed to be copyleft but are
actually permissive here:

| Crate               | License             | Notes                                                     |
|---------------------|---------------------|-----------------------------------------------------------|
| `yara` / `yara-sys` | BSD-3-Clause        | The YARA engine itself is BSD; the Rust bindings inherit. |
| `rusqlite` / `libsqlite3-sys` | MIT + Public Domain | SQLite core is public domain; Rust wrapper is MIT. |
| `ring`              | ISC + OpenSSL + MIT | Cryptographic primitives used by `rustls`.                |
| `rustls`            | Apache-2.0 / ISC / MIT | TLS implementation used for the native protocol.       |
| `nix`               | MIT                 | Safe Unix syscall wrappers.                               |
| `windows-rs`        | MIT / Apache-2.0    | Official Microsoft Windows API bindings.                  |
| `tokio`, `serde`, `rmp-serde`, `chrono`, `bytes`, `flate2`, `sha2`, `md-5`, `socket2` | MIT / Apache-2.0 | Foundation async / serialization / crypto utilities. |

## 5. What this means for distribution

Given the above:

1. SDA binaries may be redistributed under the SN360 proprietary
   license (see [`../LICENSE`](../LICENSE)) with no copyleft
   obligations back to any upstream project.
2. The legacy SIEM protocol adapter, when shipped, remains an
   independent interoperability implementation; shipping it does
   not create a derivative-work relationship with any third-party
   SIEM codebase.
3. Source-code release, dual-licensing, or re-licensing decisions
   are at SN360 Inc.'s sole discretion, subject only to the
   permissive third-party crate licenses (which require attribution
   but impose no source-release obligations).

## 6. Verification checklist

A reviewer can independently verify the claims above by running:

```sh
# No third-party SIEM agent source present in the workspace.
rg -n 'src/client-agent|src/syscheckd|src/logcollector|src/rootcheck|src/wazuh_modules' -g '!docs/**' -g '!*.md'

# Dependency licenses — expect only MIT / Apache-2.0 / BSD / ISC /
# Unicode-DFS / zlib / MPL-2.0. No GPL / AGPL / LGPL / SSPL / BUSL.
cargo deny --all-features check licenses

# Legacy adapter can be compiled out.
cargo build --release -p sda-agent --no-default-features
```

The expected results of these commands are captured in the
[dependency audit section](./security-audit.md#license-audit)
of the security audit document.

---

*Licensing inquiries: `licensing@sn360.com`.*
