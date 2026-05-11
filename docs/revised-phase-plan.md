# SDA Revised Phase Plan — Phases 7–9

This document supersedes the late-phase entries in
[`device-agent-proposal.md` §12](../device-agent-proposal.md#12-implementation-roadmap)
for the post-beta work. It describes how SDA evolves from its
current shape (legacy SIEM protocol as the transport used in CI,
SN360 native protocol shipped but opt-in) to the target shape
required for the proprietary release:

- **SN360 native protocol is the default** and the only path
  enabled in the default proprietary distribution.
- **Legacy SIEM protocol adapter is optional**, compiled in only
  when the `legacy-siem` Cargo feature is enabled.
- **SN360 Control Plane MVP** (Agent Gateway + TRDS) exists and is
  integration-tested against SDA.
- **All documentation and licensing** are consistent with the
  proprietary posture described in
  [`proprietary-licensing-rationale.md`](./proprietary-licensing-rationale.md).

Phases 1–6 remain as described in `PROGRESS.md` and
`device-agent-proposal.md`; this document picks up at Phase 7.

> **Scope:** This repository (`sn360-desktop-agent`) contains only the
> agent-side (on-device) code. All server-side Control Plane components
> — Agent Gateway, TRDS, IOCFS, SIS — are implemented in
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
> Tasks below that describe server-side work are included for context
> only and are marked with ⚙️ to indicate they belong to the other repository.

---

## Phase 7 — SN360 Native Protocol Promotion & Control Plane MVP

Goal: make the SN360 native protocol the default end-to-end path
for SDA. Unblock a proprietary-only release by standing up the
minimum Control Plane surface area the agent needs.

| #   | Task                                             | Description                                                                                                                                                                      |
|-----|--------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 7.1 | Promote SN360 native protocol to default         | Flip config defaults so `server.protocol = "http2"`, `server.enhanced.tls = true`, `server.enhanced.serialization = "msgpack"`. Legacy adapter moves behind the `legacy-siem` Cargo feature. |
| 7.2 | Native enrolment                                 | Implement mTLS-based enrolment against the SN360 Agent Gateway in `sda-comms::enrollment::native` (replacing `authd`-style enrolment as the default path).                       |
| 7.3 | Agent Gateway MVP ⚙️                             | Minimal Agent Gateway that terminates mTLS, authenticates the agent's client certificate, and routes native-protocol frames to internal backends. Accelerated from Phase 4.13. Implemented in `sn360-security-platform`, not this repo. |
| 7.4 | TRDS MVP ⚙️                                      | Minimal rule-distribution service so LDE (on-device rule engine) has a native rule source. Accelerated from Phase 4.10. Implemented in `sn360-security-platform`, not this repo.                                                        |
| 7.5 | Refactor `sda-comms`                             | Split the crate into native protocol modules (default) and a legacy adapter module (feature-gated). See § "sda-comms target layout" below.                                       |
| 7.6 | Update E2E tests                                 | Create an E2E suite that runs against the SN360 Agent Gateway instead of a legacy SIEM manager. Keep the legacy E2E as `make e2e-legacy` for regression coverage.                |
| 7.7 | Documentation sweep                              | Apply all document rewrites required to align the repo with the proprietary posture (LICENSE, README, proposal, architecture, admin/user guides, config reference, PROGRESS).    |
| 7.8 | License audit                                    | Run `cargo deny check licenses` (and/or `cargo license`) to confirm no GPL/AGPL/LGPL/SSPL/BUSL dependency exists. Document results in `docs/security-audit.md` under "License audit". |

**Milestone 7:** Agent enrols with SN360 Agent Gateway over mTLS,
pulls at least one rule bundle from TRDS, and forwards FIM +
syscheck events end-to-end using MessagePack over HTTP/2. The
legacy adapter still compiles and CI still runs it, but neither is
required for a default release build.

### sda-comms target layout (task 7.5)

```
crates/sda-comms/src/
  lib.rs                    # Public API; re-exports native + (cfg) legacy
  msgpack.rs                # SN360 native serialization (always compiled)
  transport/
    tls.rs                  # SN360 native (always compiled)
    http2.rs                # SN360 native (always compiled)
    legacy_tcp.rs           # Legacy SIEM adapter (cfg feature = "legacy-siem")
    legacy_udp.rs           # Legacy SIEM adapter (cfg feature = "legacy-siem")
  enrollment/
    native.rs               # mTLS enrolment against Agent Gateway
    legacy.rs               # authd-compatible enrolment (feature-gated)
  legacy_adapter/
    protocol.rs             # Legacy wire framing (feature-gated)
    crypto.rs               # Blowfish/AES-CBC (feature-gated)
```

The feature flag already exists on the crate (`legacy-siem`); task
7.5 moves the legacy modules under `#[cfg(feature = "legacy-siem")]`
and collapses the native path into the hot code path.

---

## Phase 8 — Full Control Plane

Goal: promote the Phase 7 Control Plane MVP to production quality.
This phase replaces the old Phase 4.10 – 4.14 line items.

> **Note:** All Phase 8 tasks are server-side and implemented in
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
> They are listed here for cross-reference only.

| #   | Task                                                           |
|-----|----------------------------------------------------------------|
| 8.1 | TRDS full implementation — rule CRUD API, rule compiler, delta distribution ⚙️ (sn360-security-platform) |
| 8.2 | IOCFS — feed ingestion, normalization, bloom filter compilation ⚙️ (sn360-security-platform) |
| 8.3 | SIS — inventory ingestion, CVE matching, dashboard API ⚙️ (sn360-security-platform) |
| 8.4 | Agent Gateway production hardening — rate limiting, multi-tenant routing, HA ⚙️ (sn360-security-platform) |
| 8.5 | Agent ↔ TRDS rule pull, hot-reload, version tracking ⚙️ (sn360-security-platform) |

**Milestone 8:** A fleet of SDA agents can enrol, pull rules, ship
inventory and detections, and be managed through the SN360
Control Plane without any legacy SIEM manager in the loop.

---

## Phase 9 — Legacy Deprecation

Goal: move customers off the legacy SIEM adapter and shrink the
default binary by removing the adapter from default builds.

| #   | Task                                                                  |
|-----|-----------------------------------------------------------------------|
| 9.1 | Deprecation notices in legacy adapter code (log once per session, docs cross-links) |
| 9.2 | Migration guide — legacy SIEM manager → SN360 Control Plane            |
| 9.3 | Feature-gate the legacy adapter compile-time flag default to **off**  |

At the end of Phase 9 the default proprietary build has zero
legacy-SIEM code compiled in. The `legacy-siem` feature remains in
the source tree so enterprises with outstanding migrations can opt
back in, but the shipped artefact is native-only.

---

## Relationship to earlier phases

- **Phase 5.6** (opt-in enhanced protocol) is the *engineering*
  ancestor of Phase 7.1. Phase 7.1 is the configuration + default
  flip, not new protocol code — the TLS 1.3 / HTTP/2 / MessagePack
  implementation already landed in Phase 5.6.
- **Phase 4.10 – 4.14** (server-side microservices) are absorbed by
  Phases 7.3 – 7.4 (MVP) and Phase 8 (production hardening). All
  server-side work is implemented in the
  [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)
  repository and is **out of scope** for `sn360-desktop-agent`.

## Tracking

Progress against this plan should be mirrored into `PROGRESS.md`
under a new "Phase 7" section once Phase 7 work actually starts in
the code; this file is the design reference, `PROGRESS.md` is the
delivery log.
