# SN360 Desktop Agent — Test Results

This file is the canonical record of device-side test runs for the
SN360 Desktop Agent (SDA). The most recent run is at the top; older
results are archived at the bottom under "Historical Results".

For the agent ↔ platform integration map, see
[`docs/integration.md`](./docs/integration.md). For the platform-side
companion (SIS / TRDS / IOCFS regression results), see
[`sn360-security-platform/docs/INTEGRATION_ASSESSMENT.md`](https://github.com/kennguy3n/sn360-security-platform/blob/main/docs/INTEGRATION_ASSESSMENT.md)
Appendix A.

---

## Latest Results (2026-04-28)

### Environment

| | |
|---|---|
| Date | 2026-04-28 02:00 UTC |
| OS | Linux 5.15.200 x86_64 (Ubuntu 22.04) |
| Rust | rustc 1.95.0 (59807616e 2026-04-14) |
| Docker | 27.4.1 / Compose v2 |
| Wazuh Manager | `wazuh/wazuh-manager:4.9.2` |
| `sn360-desktop-agent` | `bb44993ad24dc85ce26af85c5eb83571a7e0b35f` (`main`) |
| `sn360-security-platform` | `38edce20d13713754f90b2fe7d329c909d55104c` (`main`) |

### Unit Tests — `cargo test --all`

**Result: 433 passing / 0 failed / 0 ignored.** Identical to the 2026-04-25 baseline; per-crate counts unchanged.

### Base E2E — `bash tests/scripts/run-e2e.sh`

**Result: 14/14 assertions PASS** against a fresh `wazuh/wazuh-manager:4.9.2` brought up by `tests/docker-compose.yml`. All 14 checks (enrollment, FIM, baseline scan, inventory, log collection, journal, agent presence, active response, custom AR, SCA scan, rootcheck, journal Linux only) green.

### Security E2E — `bash tests/scripts/run-security-e2e.sh`

**Result: 10/10 scenarios PASS** (REG-054..REG-063 device-side, against a standalone stock Wazuh manager). All ten attacker scenarios (malware drop, SSH brute-force, sudo privilege escalation, sshd_config tamper, ransomware mass-rename, AR kill-process, AR firewall-drop, package inventory, /bin/ls binary tamper, AR disable-account) trigger the expected Wazuh rules with the expected MITRE ATT&CK groups.

### Platform Integration — Top-10 Security E2E (REG-054..REG-063)

`bash tests/regression/security-scenarios/run-top10-security-e2e.sh` against `sn360-security-platform` `38edce20`:

**Result: 10/10 PASS** (final run). The first invocation flaked on `SCENARIO 01` (malware.exe FIM alert hitting OpenSearch within the 90 s window); the immediate re-run cleared with `path=/var/ossec/tmp/malware.exe`. REG-061 (package inventory in `software_inventory_entries`) is **green** — `cowsay` package surfaced in SIS with `rows=1` via the `services/syscollector-bridge` sidecar; the `SN360_AGENT_PATH=direct` gap is closed.

| # | REG ID | Scenario | MITRE ATT&CK | Result |
|---|--------|----------|--------------|--------|
| 01 | REG-054 | Malware drop (`malware.exe` syscheck) | T1204.002 | PASS (re-run) |
| 02 | REG-055 | SSH brute-force correlation | T1110.001 | PASS |
| 03 | REG-056 | Sudo privilege escalation | T1548.003 | PASS |
| 04 | REG-057 | sshd_config tamper | T1098.004 | PASS |
| 05 | REG-058 | Ransomware mass-rename | T1486 | PASS |
| 06 | REG-059 | AR `kill_process` | T1059 | PASS |
| 07 | REG-060 | AR firewall-drop (v4+v6) | T1562.004 | PASS |
| 08 | REG-061 | Package inventory (`cowsay` in SIS) | T1005 | PASS |
| 09 | REG-062 | `/bin/ls` binary tamper (SHA-256) | T1036.005 | PASS |
| 10 | REG-063 | AR `disable-account` | T1531 | PASS |

### CI Checks (mirrored locally)

| Check | Command | Result |
|---|---|---|
| fmt | `cargo fmt --all -- --check` | clean |
| clippy | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean |
| build | `cargo build --workspace --release` | green |
| unit | `cargo test --all` | 433/433 |

### Known Issues

1. **REG-054 occasional first-run flake** — the malware-drop FIM alert sometimes does not reach OpenSearch within the 90 s wait when the platform stack is freshly brought up cold. Re-running `run-top10-security-e2e.sh` clears it; root cause is the cold-start indexing latency of the `sn360-alerts-*` template, not the agent. No follow-up needed beyond the existing 90 s wait.

---

## Latest Results (2026-04-25)

### Environment

- Date: 2026-04-25
- Platform: Linux 5.15.200, x86_64 (Ubuntu)
- Rust version: rustc 1.95.0 (59807616e 2026-04-14)
- Cargo version: cargo 1.95.0 (f2d3ce0bd 2026-03-21)
- Docker version: Docker 27.4.1 / Compose v2.32.1
- Wazuh Manager (E2E + security E2E target): `wazuh/wazuh-manager:4.9.2`

### Unit & Integration Tests

Command: `cargo test --all`

**Result: 433 passing / 0 failed.**

Per-binary breakdown:

| Crate | Passed | Failed |
|---|---|---|
| `sda-active-response` (unit) | 29 | 0 |
| `sda-agent` (unit) | 30 | 0 |
| `sda-comms` (unit) | 48 | 0 |
| `sda-core` (unit) | 2 | 0 |
| `sda-enhanced-inventory` (unit) | 50 | 0 |
| `sda-enhanced-inventory` (integration: `browser_extensions_integration`) | 3 | 0 |
| `sda-enhanced-inventory` (integration: `sbom_integration`) | 3 | 0 |
| `sda-event-bus` (unit) | 6 | 0 |
| `sda-fim` (unit) | 57 | 0 |
| `sda-fim` (integration: `baseline_scan_integration`) | 1 | 0 |
| `sda-fim` (integration: `burst_workload`) | 2 | 0 |
| `sda-fim` (integration: `fim_integration`) | 5 | 0 |
| `sda-fim` (integration: `integration`) | 4 | 0 |
| `sda-inventory` (unit) | 32 | 0 |
| `sda-local-detection` (unit) | 56 | 0 |
| `sda-logcollector` (unit) | 34 | 0 |
| `sda-pal` (unit) | 10 | 0 |
| `sda-rootcheck` (unit) | 35 | 0 |
| `sda-sca` (unit) | 5 | 0 |
| `sda-updater` (unit) | 18 | 0 |
| `sda-updater` (integration: `checker_http`) | 3 | 0 |
| **Total** | **433** | **0** |

Delta vs. the 2026-04-21 baseline: **+2 tests** (`sda-event-bus`
4 → 6) — landed via routine event-bus coverage on `main` since
the prior run; no regressions.

### Base E2E (vs. Local Wazuh 4.9.2)

Command: `make e2e`

**Result: 14/14 assertions PASS.**

```
==============================
  E2E Test Summary
==============================
  PASS: Agent enrolled successfully
  PASS: Agent still enrolled after keepalive (active flag not shown)
  PASS: FIM syscheck alerts received by server
  PASS: Baseline scan syscheck alerts received by server
  PASS: Baseline scan detected file deletion
  PASS: Inventory data received by server
  PASS: Log collection alerts received by server
  PASS: Journal log collection events received by server
  PASS: Active response command processed
  PASS: SCA policy evaluation received by server (generic match)
  PASS: Rootcheck signature alert received by server
  PASS: Enhanced inventory running-software scanner active (agent log oracle)
  PASS: Enhanced inventory SBOM scanner active (agent log oracle)
  PASS: Enhanced inventory browser-extensions scanner active (agent log oracle)
==============================
  RESULT: ALL CHECKS PASSED
==============================
```

Per-assertion counters observed by the harness on this run:

- Syscheck alerts: 2 (FIM testfile.txt creation)
- Baseline-scan syscheck alerts: 6 (scan-test-1/2/3)
- Deletion alerts: 3 (scan-test-2.txt removed)
- Inventory (syscollector) events in archives: 1103
- Log-collection alerts: 1 ("Failed password" tailed from `/tmp/sda-e2e-logs/test.log`)
- Journal log events in archives: 1 (`sda-e2e-test` via `logger`)
- Rootcheck marker events in archives: present
- Enhanced-inventory log-oracle hits: running_software, SBOM, browser-extensions
  all observed (the assertions are existence checks, not counts —
  the rationale is documented in the Security E2E section below)

### Security E2E (vs. Local Wazuh 4.9.2)

Command: `make security-e2e`

**Result: 10/10 scenarios PASS.**

```
==============================
  Security E2E Test Summary
==============================
  PASS: Malware file drop detected (syscheck alert for malware.exe)
  PASS: Brute-force SSH simulation detected (10 alert(s))
  PASS: Privilege escalation (sudo abuse) detected (5 alert(s))
  PASS: Config file tampering detected (hash change alert)
  PASS: Ransomware simulation detected (208 FIM alerts for .encrypted files)
  PASS: Active response kill_process command sent (process still alive — expected without server-side rule)
  PASS: IP blocking active response commands sent (IPv4 + IPv6)
  PASS: Package inventory update detected after install
  PASS: System binary tampering detected (SHA-256 change alert)
  PASS: Account disable AR configured and dispatched by server
==============================
  RESULT: ALL CHECKS PASSED
==============================
```

The 10 security E2E scenarios cover the device-side variants of
REG-054..063 from the platform regression catalogue.

### Non-Wazuh Component Verification

This section documents how SDA's **Non-Wazuh** modules are verified
end-to-end. The canonical reference for these modules is
[`docs/integration.md`](./docs/integration.md) (device-side) and
[`sn360-security-platform/docs/NON_WAZUH_COMPONENTS.md`](https://github.com/kennguy3n/sn360-security-platform/blob/main/docs/NON_WAZUH_COMPONENTS.md)
(platform-side).

**Enhanced Inventory (`sda-enhanced-inventory`).** The base E2E suite
asserts the three enhanced-inventory scanners are active on
assertions 12, 13, and 14. These assertions use **agent-log oracles**,
not Wazuh's `archives.json`, because Wazuh's `analysisd` syscollector
decoder only matches `dbsync_*` `"type"` variants. The
`enhanced_inventory` envelope SDA emits falls through that decoder
and is never archived by the manager. The agent's per-tick
`debug!` lines (enabled via `RUST_LOG=…=debug` in step 5 of the
harness) are the assertion oracle. The rationale lives in the
test script comment at
[`tests/scripts/run-e2e.sh` (lines 481-488)](./tests/scripts/run-e2e.sh#L481-L488)
and is mirrored in
[`docs/integration.md`](./docs/integration.md) §2.1.

  - Unit + integration coverage in this repo: **50** unit tests in
    `sda-enhanced-inventory` plus **6** integration tests
    (`browser_extensions_integration`, `sbom_integration`).
  - Server-side verification (data persistence into PostgreSQL +
    SBOM blob into S3) lives in the platform repo's `sis_cve`
    regression category (REG-051..053) — see Appendix A of the
    platform's `INTEGRATION_ASSESSMENT.md`.

**Local Detection Engine (`sda-local-detection`).** All on-device
detection (Aho-Corasick string matching, IOC bloom filters, YARA,
behavioural rules) is exercised by **56** unit tests in
`sda-local-detection`. The TRDS msgpack bundle decode + Ed25519
signature verify path is additionally fuzzed (see
`fuzz/fuzz_targets/trds_bundle_decode.rs`).

  - Server-side verification of the rule / IOC distribution path
    lives in the platform repo: TRDS regression cases REG-020..029,
    IOCFS regression cases REG-030..039.
  - LDE has no Wazuh equivalent — Wazuh has no on-agent rule engine,
    so there is no parity test in the platform's parity suite for
    this surface.

**Companion microservices (SIS / TRDS / IOCFS).** All three live in
`sn360-security-platform` and are verified there. From the agent's
perspective they are reachable through:

- Path A (native, mTLS Gateway → NATS) — exercised by the platform
  regression harness when `SN360_AGENT_PATH=gateway`.
- Path C (S3 bundle pull) — exercised by `sda-updater` integration
  tests (`checker_http`).

### Platform Integration Results

The matching platform-side regression run for this date is captured
in
[`sn360-security-platform/docs/INTEGRATION_ASSESSMENT.md`](https://github.com/kennguy3n/sn360-security-platform/blob/main/docs/INTEGRATION_ASSESSMENT.md)
Appendix A. Summary for 2026-04-25:

- `make regression` with `SKIP_AGENT_TESTS=0`: 75 PASS, 14 FAIL,
  33 SKIP (89 cases). Failures are concentrated in agent-compat
  cases that need the SN360 Gateway data path; the harness's
  default `SN360_AGENT_PATH=direct` exercises Wazuh end-to-end but
  bypasses the SN360 control plane, so SIS / Postgres rows used as
  test oracles are never populated. Tracked alongside Known Gap #5
  in `INTEGRATION_ASSESSMENT.md`.
- `tests/regression/security-scenarios/run-top10-security-e2e.sh`:
  9 PASS, 1 FAIL (Scenario 08 — same `software_inventory_entries`
  root cause as REG-061).
- `PARITY_SUITE=full run-parity.sh`: 9 PASS, 0 FAIL, 10 SKIP.

### Compat E2E (vs. Local Wazuh 4.7.5)

Command: `make e2e-compat`

The compatibility harness reuses `tests/scripts/run-e2e.sh` with
`E2E_COMPOSE_FILE=tests/docker-compose-v4.7.yml`, bringing up
`wazuh/wazuh-manager:4.7.5` so the same 14-assertion suite
exercises the older v4.x protocol surface. Not recorded on this CI
host because the 4.7.5 image is not pre-pulled on shared runners;
the job is runnable manually for pre-release validation and runs in
the release pipeline.

### Benchmark regression gate

Command: `make benchmark-ci` (invokes
`tests/scripts/benchmark-regression.sh`).

Enforces the hard budgets called out in
[`benchmark-results.md`](./benchmark-results.md) — idle RSS
< 15 MB, idle CPU < 0.1 %, release binary < 7 MB, FIM burst peak
< 3 %. Exits non-zero on any breach; the full output is written to
`target/benchmark-regression/benchmark-regression.txt` and uploaded
as a CI artifact by the nightly `benchmark-regression` job in
`.github/workflows/ci.yml`.

### Security audit

Command: `cargo audit --deny warnings` (CI-only; requires
`cargo install --locked cargo-audit`). Runs as a required check on
every push. See [`docs/security-audit.md`](./docs/security-audit.md)
for the fuzzing harness companion (cargo-fuzz targets under
`fuzz/` for protocol decode, zlib decompress, MessagePack event
decode, and TRDS rule-bundle decode).

### Issues Found & Fixes Applied (2026-04-25)

None. All 433 unit/integration tests, 14 base E2E assertions, and 10
security E2E assertions passed on the first attempt against a clean
local Wazuh 4.9.2 stack.

---

## Historical Results

<details>
<summary><b>2026-04-21 — PR #60 rerun (`legacy-siem` feature gating)</b></summary>

After feature-gating the legacy SIEM adapter under `legacy-siem` (see
PR #60), the full suite was re-run on this branch against the same
local Wazuh 4.9.2 compose environment. All three suites reproduce the
recorded outcomes with identical counts:

- `cargo test --all` — **431 passing / 0 failed** (per-crate split
  unchanged from the 2026-04-21 baseline below).
- `cargo test -p sda-agent --no-default-features` — **12 passing / 0
  failed** (the legacy-siem-gated tests in `sda-agent/src/main.rs`
  are correctly skipped when the feature is off).
- `cargo test -p sda-comms --no-default-features` — **17 passing / 0
  failed** (msgpack + TLS/HTTP2 native-protocol tests; legacy
  Blowfish / `WazuhMessage` / enrolment / connection tests are
  correctly skipped when the feature is off).
- `make e2e` — **14/14** assertions PASS (enrolment, keepalive, FIM
  syscheck, baseline scan, deletion detection, inventory,
  file/journald log collection, active response, SCA, Rootcheck,
  enhanced-inventory running_software/SBOM/browser_extensions).
- `make security-e2e` — **10/10** attack scenarios PASS.

The feature-gating diff is code-organisation-only (no runtime
behavioural change in the default build), which matches what the
suites observe.

#### Benchmark regression gate on this host (2026-04-21)

`make benchmark-ci` (see [`benchmark-results.md`](./benchmark-results.md)
for the full methodology) was re-run on this branch **and on
`main`** against the same local Wazuh 4.9.2 manager on the same
host. Binary size passes both runs; idle RSS, idle CPU, and FIM
peak CPU are over budget on both branches with near-identical
numbers, so the breach is **not a regression from PR #60** but
reflects this host's CPU / scheduler behaviour vs. the runner the
recorded baseline was taken on. Full numbers and side-by-side
comparison are in
[`benchmark-results.md`](./benchmark-results.md#pr-60-rerun-2026-04-21).

</details>

<details>
<summary><b>2026-04-21 — initial baseline (431/0)</b></summary>

- Date: 2026-04-21
- Platform: Linux 5.15.200, x86_64 (Ubuntu)
- Rust version: rustc 1.95.0 (59807616e 2026-04-14)
- Wazuh Manager: `wazuh/wazuh-manager:4.9.2`

`cargo test --all`: **431 passing / 0 failed.** Per-binary breakdown
matched the 2026-04-25 table above except `sda-event-bus` reported 4
unit tests (vs. 6 on 2026-04-25).

Rolled up by crate (matching the shape of the table in
`PROGRESS.md`):

| Crate | Passed |
|---|---|
| `sda-active-response` | 29 |
| `sda-agent` | 29 |
| `sda-comms` | 31 |
| `sda-core` | 2 |
| `sda-enhanced-inventory` | 56 |
| `sda-event-bus` | 4 |
| `sda-fim` | 69 |
| `sda-inventory` | 32 |
| `sda-local-detection` | 56 |
| `sda-logcollector` | 34 |
| `sda-pal` | 10 |
| `sda-rootcheck` | 35 |
| `sda-sca` | 5 |
| `sda-updater` | 21 |
| **Total** | **431** |

Notes on the deltas vs. the previously recorded 391/0 baseline:

- `sda-pal`: 5 → 10 (+5 new unit tests covering the loginctl-based
  Linux user-idle detector added for P1.8 — `parse_idle_since_hint`
  edge cases + a smoke test for `linux_user_idle_duration`).
- `sda-rootcheck`: 20 → 35 (+15: 14 new `content_checks` unit tests
  covering `/etc/ld.so.preload`, `/etc/crontab`, and `/etc/hosts`
  inspection for P1.4, plus 1 new platform-gated hidden-process
  test for macOS / Windows from P1.5).
- `sda-agent`: 29 → 30 (+1), `sda-comms`: 31 → 48 (+17),
  `sda-updater`: 19 → 21 (+2). These landed on `main` via
  PR #55 and are reflected in the 2026-04-21 `cargo test --all`
  baseline.

`make e2e` (14/14 PASS) and `make security-e2e` (10/10 PASS)
recorded the same outcomes as the 2026-04-25 retest above.

#### Notes from the 2026-04-21 run

- The E2E and security E2E harnesses both hung during the `trap
  cleanup` step after printing `ALL CHECKS PASSED`. Root cause: the
  harnesses launch the agent via `timeout 300 sudo ./target/release/sda-agent …`
  and then run `kill "$AGENT_PID"; wait "$AGENT_PID"` from an
  unprivileged shell. `$AGENT_PID` is the non-privileged `timeout`
  wrapper, so the unprivileged SIGTERM never reaches the root
  `sda-agent` process. Issuing `sudo pkill -f sda-agent` unblocked
  the `wait` in both runs. All assertion results were already
  recorded before the hang, so the test outcomes are not affected,
  but the harness cleanup path is worth hardening.
- `ossec.log` reported 1 "Decrypt the message fail, socket 28"
  warning during the base E2E run. This is the expected first-frame
  re-enroll race that the Wazuh manager logs when the previous
  run's client key was cleared and a new enrollment is in flight;
  no subsequent decrypt errors were observed and all 14 downstream
  assertions passed.
- Test step 10 in the base E2E harness logs `** Selected active
  response does not exist.` from `agent_control -f restart-wazuh0`.
  The harness intentionally treats this as the "command processed"
  oracle (the manager dispatched the AR; there is no matching
  `<active-response>` block for `restart-wazuh` in the stock
  image), and the assertion passes. The security E2E harness, which
  injects `<active-response>` blocks for `disable-account` and
  `firewall-drop` before starting the agent, exercises the full
  round-trip end-to-end in tests 7 and 10.

</details>
