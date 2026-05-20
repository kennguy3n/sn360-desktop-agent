# SDA Integration with the SN360 Security Platform

This document is the device-side integration reference for the SN360
Desktop Agent (SDA). It explains the three integration paths SDA uses
to talk to the SN360 control plane, and how SDA's "Non-Wazuh" modules
(enhanced inventory, local detection) plug into the platform.

The canonical platform-side companion to this document is
[`docs/architecture/integration-architecture.md`](https://github.com/kennguy3n/sn360-security-platform/blob/main/docs/architecture/integration-architecture.md)
in `sn360-security-platform`. Where this file says "see platform §X",
that's the section to read.

---

## 1. Integration Paths

SDA connects to the SN360 Security Platform over three paths. The
canonical wire-level documentation lives in the platform repo's
[`docs/architecture/integration-architecture.md`](https://github.com/kennguy3n/sn360-security-platform/blob/main/docs/architecture/integration-architecture.md)
§2 ("Integration Paths"). This section is the device-side summary.

| Path | Endpoint | Wire format | Used by |
|---|---|---|---|
| **A — Native** | `sda-comms` → mTLS Agent Gateway → NATS → `analysisd` | mTLS 1.3 + msgpack frames | Default for new fleets; opt-in via `comms.protocol: native` |
| **B — Legacy SIEM** | `sda-comms` (`legacy-siem` Cargo feature) → `wazuh-manager:1514` | Wazuh 4.x agent protocol (Blowfish/AES + counters) | Brownfield deployments; the `make e2e` and `make security-e2e` test suites |
| **C — Bundles** | TRDS / IOCFS → S3 → `sda-updater` / `sda-local-detection` | Ed25519-signed msgpack bundles + bloom/AC IOC packages | LDE rule + IOC distribution; pulled on a poll interval |

- Path B is what the agent's own E2E harness exercises today
  (`tests/scripts/run-e2e.sh` boots a stock Wazuh manager via
  `tests/docker-compose.yml` and points `sda-agent` at it on `localhost:1514`).
- Path A is exercised end-to-end by the platform repo's regression
  harness ([`tests/regression/harness/sn360/docker-compose-up.sh`](https://github.com/kennguy3n/sn360-security-platform/blob/main/tests/regression/harness/sn360/docker-compose-up.sh)).
- Path C is independent of A vs. B — bundle distribution is purely a
  pull from S3 over HTTPS; the agent verifies Ed25519 signatures
  before activating a bundle.

For the per-path counter / cipher invariants (Wazuh `remoted`
monotonicity, `WazuhCipher` lifecycle), see the protocol notes in
[`crates/sda-comms/src/protocol.rs`](../crates/sda-comms/src/protocol.rs).

---

## 2. Non-Wazuh Components (Agent-Side)

The following SDA modules have **no Wazuh equivalent**. Their
server-side counterparts are documented in the platform repo's
[`ARCHITECTURE.md`](https://github.com/kennguy3n/sn360-security-platform/blob/main/ARCHITECTURE.md)
and the per-service trees under
[`services/`](https://github.com/kennguy3n/sn360-security-platform/tree/main/services).
This section captures only what changes on the agent.

### 2.1 Enhanced Inventory (`sda-enhanced-inventory`)

- Three scanners — running software, browser extensions, and CycloneDX
  SBOMs — emit `EventKind::EnhancedInventoryUpdate` events on the
  agent event bus.
- Server-side these are processed by SIS over NATS subject
  `sn360.inventory.*`; SIS persists them in PostgreSQL
  (`software_inventory_entries`, `sboms`) and S3.
- Wazuh's `analysisd` syscollector decoder rejects the
  `enhanced_inventory` envelope (it only matches `dbsync_*`
  variants) so the data path is fully outside `analysisd`. The
  E2E suite documents this in
  [`tests/scripts/run-e2e.sh` (lines 481-488)](../tests/scripts/run-e2e.sh#L481-L488)
  and the agent-log oracles for assertions 12–14 follow from that.
- Crate layout:
  [`crates/sda-enhanced-inventory/`](../crates/sda-enhanced-inventory/).

### 2.2 Local Detection Engine (`sda-local-detection`)

- On-device rule evaluation: Aho-Corasick string matchers, IOC bloom
  filters, YARA scanning, and a behavioural-rule state machine.
- Rule bundles and IOC packages are pulled by `sda-updater` from S3
  (Path C) — never via Wazuh's `agent.conf`. Bundles are Ed25519-
  signed msgpack and decoded by the shared
  [`shared/sn360-bundle/`](https://github.com/kennguy3n/sn360-security-platform/tree/main/shared/sn360-bundle)
  crate.
- Detection is **local** — alerts hit the agent event bus and the
  platform via Path A or Path B; nothing round-trips to `analysisd`
  for evaluation.
- Crate layout:
  [`crates/sda-local-detection/`](../crates/sda-local-detection/).
  56 unit tests cover the rule engines + bundle decode path; the
  bundle decoder is also fuzzed.

---

## 3. Companion Microservices (Out of Scope for This Repo)

These services live entirely in
[`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform);
the agent only sees them through the integration paths in §1. They
are listed here so an agent contributor knows what each event /
bundle / NATS subject ultimately lands in.

| Service | Purpose | Agent-side touchpoint |
|---|---|---|
| **Agent Gateway** | mTLS 1.3 edge; tenant routing; native protocol bridge | `sda-comms` Path A target |
| **TRDS API + Compiler** | Tenant rule CRUD, Ed25519-signed bundle compilation | `sda-updater` polls S3 bundle URLs published by TRDS |
| **IOCFS + IOCFS Compiler** | IOC feed aggregation, bloom-filter / Aho-Corasick package compilation | `sda-updater` pulls IOC packages alongside TRDS bundles |
| **SIS** | Inventory ingest, CVE matching, SBOM store | Consumes `EnhancedInventoryUpdate` events from NATS |
| **alert-forwarder** / **remoted-bridge** / **execd-bridge** | Path-A alert egress + legacy-protocol bridges | Transparent to the agent — same wire formats either way |

For the per-service detail, see the platform repo's
[`ARCHITECTURE.md`](https://github.com/kennguy3n/sn360-security-platform/blob/main/ARCHITECTURE.md)
and the individual `services/<name>/README.md` trees.

---

## 4. Testing the Integration

| Suite | Command | What it exercises |
|---|---|---|
| Unit + integration | `cargo test --all` | All 34 SDA test binaries |
| Base E2E | `make e2e` | Path B against a local Wazuh 4.9.2 manager (14 assertions, including three agent-log oracles for enhanced inventory) |
| Security E2E | `make security-e2e` | Path B, top-10 attack scenarios (REG-054..063 device-side) |
| Platform regression | `cd ../sn360-security-platform && make regression` | Path A + Path C end-to-end (89 cases) |
| Top-10 security on platform | `cd ../sn360-security-platform && tests/regression/security-scenarios/run-top10-security-e2e.sh` | Top-10 against the SN360 stack with a stock Wazuh agent sidecar |

Enhanced-inventory assertions use agent-log oracles rather than
`analysisd` decoder hits because Wazuh's `syscollector` decoder
rejects the `enhanced_inventory` envelope outright. The E2E harness
([`tests/scripts/run-e2e.sh`](../tests/scripts/run-e2e.sh)) documents
this at lines 481–488 and the three matching agent-log assertions
follow from that contract.

---

## 5. Cross-Repo References

- Canonical agent ↔ platform integration map:
  [`sn360-security-platform/docs/architecture/integration-architecture.md`](https://github.com/kennguy3n/sn360-security-platform/blob/main/docs/architecture/integration-architecture.md).
- Canonical platform architecture overview (covers the non-Wazuh
  SN360-original services):
  [`sn360-security-platform/ARCHITECTURE.md`](https://github.com/kennguy3n/sn360-security-platform/blob/main/ARCHITECTURE.md).
- Device-side architecture and PAL design:
  [`architecture.md`](./architecture.md).
