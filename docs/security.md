# Security Model

This document describes SDA's security posture: the threat model
the agent is designed against, the cryptographic and dependency
controls applied on every change, the clean-room policy for
reference engines, and the audit surfaces operators can rely on.

For per-module invariants (memory-scanner self-PID exclusion, DLP
redaction, signed-job validation, tamper protection) see
[`architecture.md` § 8](./architecture.md#8-security-model).
For licence-by-licence audit details see
[`licensing.md`](./licensing.md).

---

## Table of contents

1. [Threat model](#1-threat-model)
2. [Cryptographic posture](#2-cryptographic-posture)
3. [Dependency audit](#3-dependency-audit)
4. [Differential fuzzing](#4-differential-fuzzing)
5. [License audit](#5-license-audit)
6. [Clean-room implementation policy](#6-clean-room-implementation-policy)
7. [Reporting a vulnerability](#7-reporting-a-vulnerability)

---

## 1. Threat model

SDA runs with elevated privileges on end-user devices, so every
byte that enters an agent process is an attacker-reachable input.
The threat model has four assumed adversaries:

| Adversary | Capability | What the agent must do |
|---|---|---|
| **Untrusted network** | Can intercept, drop, replay, or forge frames between the agent and the control plane | Verify TLS 1.3 + pinned roots; require Ed25519-signed jobs; clock-bound `not_before` / `not_after` |
| **Privileged local user** | Can read agent files, attempt to inject DLLs, attempt to terminate the agent process | Tamper protection on agent binary, config, key file; signed installer; protected services |
| **Hostile peer process** | Runs as the same or higher privilege; can attempt to attach to or read the agent's memory | Memory scanner self-PID exclusion; never read other agent memory; bounded reads on `/proc/<pid>/mem`, `ReadProcessMemory`, `mach_vm_read_overwrite` |
| **Compromised dependency** | A direct or transitive Rust crate ships malicious code | `cargo audit` + `cargo deny` on every push; permissive-only license allow-list; differential fuzzing of the highest-risk parsers |

What the threat model is **not** designed to defeat:

- A motivated attacker with full kernel-mode root before the agent
  starts. The agent's tamper protection assumes the OS boot chain
  is intact.
- Side-channel attacks against the platform's crypto primitives
  (e.g., Spectre-class CPU bugs). These are out of scope for an
  endpoint agent.
- An attacker who controls the SN360 control plane signing keys.
  Key rotation policy is the privacy team's responsibility — see
  [`admin-guide.md`](./admin-guide.md).

---

## 2. Cryptographic posture

| Surface | Primitive | Library |
|---|---|---|
| Transport (agent ↔ control plane) | TLS 1.3 with pinned roots | `rustls` (Apache-2.0 / ISC / MIT) |
| Signed jobs and TRDS bundles | Ed25519 detached signatures | `ed25519-dalek` (Apache-2.0 / MIT) |
| Canonical JSON / MessagePack hashing | SHA-256 for general use, BLAKE3 for DLP fingerprints | `sha2`, `blake3` (Apache-2.0 / MIT) |
| Legacy SIEM adapter | Blowfish/AES-CBC + zlib | `block-modes`, `blowfish`, `flate2` (MIT / Apache-2.0) |
| Random number generation | `getrandom` (OS RNG) | `getrandom` (MIT / Apache-2.0) |

All signing keys are pinned at build time as the `key_id` rotation
set. The agent rejects any signed job whose `key_id` is not in the
pinned set; rotation is a control-plane operation that ships a new
SN360 release.

### 2.1 Validation pipeline (10-step)

Every server-issued action passes through the 10-step pipeline
described in
[`architecture.md` § 3.2](./architecture.md#32-signed-job-ingress)
and [`device-control.md` § 4](./device-control.md#4-signed-job-lifecycle).
The pipeline is implemented once, in `sda-device-control::router`,
so authorisation policy lives in one place.

### 2.2 Dual-control invariant

Two actions are dual-control by construction:

- `RemoteWipe` requires two distinct approver Ed25519 signatures
  with two distinct `key_id`s. See
  [`desktop-mdm.md` § 9](./desktop-mdm.md#9-security-model).
- `RemoteSupport` requires an approver signature **and** local
  user consent via a count-down banner. See
  [`device-control.md` § 9](./device-control.md#9-remote-support).

---

## 3. Dependency audit

A `cargo-audit` job runs on every PR and on every push to `main`:

```sh
cargo audit --deny warnings
```

The gate fails on any unpatched advisory against a direct or
transitive dependency. Warnings-only advisories (e.g. unmaintained
crates) also fail so they cannot silently accumulate. To reproduce
locally:

```sh
cargo install --locked cargo-audit
cargo audit
```

If a single advisory must be ignored (e.g. unreachable code path),
the decision is documented inline in `deny.toml` or via the RustSec
ignore key, **not** by disabling the gate globally.

---

## 4. Differential fuzzing

The `fuzz/` directory is a standalone `cargo-fuzz` crate (its own
`[workspace]`) so it does not participate in the main stable build.

```sh
rustup toolchain install nightly
cargo +nightly install --locked cargo-fuzz

cd fuzz
cargo +nightly fuzz run protocol_decode -- -max_total_time=60
```

### 4.1 Targets

| Target | Function under fuzz | Why |
|---|---|---|
| `protocol_decode` | `sda_comms::protocol::WazuhMessage::decode` | First parser on every legacy SIEM frame; a panic here is a crash loop |
| `protocol_decompress` | `sda_comms::protocol::decompress_payload` | zlib payloads are attacker-controlled; must fail gracefully |
| `msgpack_event_decode` | `sda_comms::msgpack::MessagePackSerializer::{decode_event,decode_kind}` | SN360 native protocol decoder; `rmp-serde` panics on malformed input must be caught |
| `rule_store_msgpack` | `sda_local_detection::rule_store::RuleBundle::from_msgpack` | TRDS bundle decoder runs before signature verification — a panic before signature check is a denial of service vector |

### 4.2 Corpus management

Each target owns a corpus directory at `fuzz/corpus/<target>/` and
a crashes directory at `fuzz/artifacts/<target>/`. These are
git-ignored by default — regenerate the corpus after a parser
change so libFuzzer's mutation engine has diverse seeds. Seed
corpora can be committed under `fuzz/seeds/<target>/` for
reproducibility.

### 4.3 Coverage goals

- Each target runs in nightly CI for at least 5 minutes with
  `-max_total_time=300` and 0 crashes.
- Coverage (`cargo +nightly fuzz coverage`) for each parser module
  is ≥ 80 % of lines.

---

## 5. License audit

SDA is distributed under a proprietary licence
(see [`LICENSE`](../LICENSE) and [`licensing.md`](./licensing.md)).
To keep that posture defensible the workspace is gated to
permissive Rust crate dependencies only.

### 5.1 Allow-list

The expected SPDX expressions, encoded in `deny.toml`:

- MIT
- Apache-2.0 (including the dual MIT/Apache-2.0 pairing and the
  `Apache-2.0 WITH LLVM-exception` variant)
- BSD-2-Clause / BSD-3-Clause
- ISC
- Unicode-3.0 / Unicode-DFS-2016
- zlib / Zlib
- CC0-1.0
- CDLA-Permissive-2.0
- MPL-2.0 (file-level copyleft; does not reach the combined work)

Any dependency whose SPDX expression contains `GPL`, `AGPL`,
`LGPL`, `SSPL`, `BUSL`, or `CC-BY-NC` (and is not offered under an
alternative permissive licence via `OR`) must be replaced or
feature-gated out of the default build.

### 5.2 Enforcement

```sh
cargo install --locked cargo-deny
cargo deny check licenses
cargo deny check bans
cargo deny check sources
```

The audit runs on every PR via `.github/workflows/ci.yml`. A PR
introducing a copyleft dependency fails CI before it can merge.
The `deny.toml` at the workspace root also encodes ban patterns
that mechanically enforce the clean-room policy in § 6 (e.g.
`fleetdm-*`, `fleet-ee-*` crate-name patterns are denied).

### 5.3 Current result

The last full workspace audit (`cargo license --all-features`)
confirms:

- **No direct or transitive dependency in the SDA workspace is
  licensed exclusively under GPL, AGPL, LGPL, SSPL, BUSL, or any
  other strong-copyleft or source-available licence.**
- One crate (`r-efi`, used indirectly by `getrandom` on UEFI
  targets) offers a triple-licence `Apache-2.0 OR LGPL-2.1-or-later
  OR MIT`. SDA consumes it under `Apache-2.0` / `MIT`; the LGPL
  option is not taken.
- The 14 `LicenseRef-Proprietary` entries are SDA's own workspace
  crates (`sda-*`) and are the proprietary artefact itself, not a
  third-party import.

---

## 6. Clean-room implementation policy

SDA's design borrows *concepts* from a number of open-source and
proprietary endpoint-security projects, but it does not vendor or
translate their source. The policy is binding and the
`cargo deny check bans` job enforces the surface mechanically.

### 6.1 EDR

| Project | Licence | Posture |
|---|---|---|
| CrowdStrike Falcon | Commercial proprietary | **Excluded** |
| SentinelOne Singularity | Commercial proprietary | **Excluded** |
| Microsoft Defender for Endpoint | Commercial proprietary | **Excluded** |
| Linux `cn_proc` / netlink / audit / eBPF | Vendor-documented public OS API | Consumed |
| Windows ETW (`Microsoft-Windows-Kernel-Process`, `…-Kernel-Network`, `…-DNS-Client`) | Vendor-documented public OS API | Consumed |
| macOS Endpoint Security framework | Vendor-documented public OS API (entitlement gated) | Consumed |
| Windows AMSI public API | Vendor-documented public OS API | Consumed (optional, feature-gated) |

No CrowdStrike Falcon, SentinelOne Singularity, or Microsoft
Defender for Endpoint source code, binary, ETW manifest, decompiled
artefact, or licensee-restricted SDK is vendored, copied,
translated, or referenced in this repository. SDA's EDR event
schema and behavioural-rule DSL are original; the per-OS PAL
implementations consume documented public APIs only.

### 6.2 Device Control

| Project | Licence | Posture |
|---|---|---|
| Fleet (MIT) | MIT | Excluded as source; reference only |
| Fleet EE | Proprietary (EE) | **Excluded** |
| MakeMeAdmin | GPL | Excluded as source; reference only |
| SAP Privileges | Apache-2.0 | Reference only — clean-room |
| Munki | Apache-2.0 | Reference only — clean-room |
| Santa / North Pole Santa | Apache-2.0 | Integrate (sidecar) on macOS; clean-room elsewhere |
| MeshCentral | Apache-2.0 | Reference only — clean-room |
| Tactical RMM | Tactical RMM Licence (restricts SaaS/commercial) | **Excluded** — benchmark only, never base |

The full per-engine rationale is in [`licensing.md`](./licensing.md).

### 6.3 SIEM interoperability

The optional legacy SIEM protocol adapter
(`sda-comms`, `legacy-siem` feature) is a clean-room
implementation of the publicly documented Wazuh / OSSEC manager-agent
wire protocol. It was implemented against:

- Published Wazuh / OSSEC wire-protocol documentation.
- Public packet captures against a reference SIEM manager running
  in Docker (`wazuh/wazuh-manager:4.x`, which is publicly
  redistributable as a binary image).
- Public specifications for the underlying building blocks
  (Blowfish/AES-CBC, zlib, TLS 1.3).

No third-party agent or manager source code was consulted. The
adapter is an interoperability layer, not a derivative work. A
proprietary-only build without the adapter is supported:

```sh
cargo build --release -p sda-agent --no-default-features
```

---

## 7. Reporting a vulnerability

Security reports are handled out of band. See
[`SECURITY.md`](../SECURITY.md) at the repository root for the
canonical disclosure policy, contact addresses, and PGP keys.

Do not file vulnerabilities as public GitHub issues. We acknowledge
reports within five business days and aim to ship a fix or a
documented mitigation within thirty days.
