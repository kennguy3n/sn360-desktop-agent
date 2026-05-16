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

## Latest Results (2026-05-16)

### Environment

| | |
|---|---|
| Date | 2026-05-16 09:00 UTC |
| OS | Linux 6.x x86_64 (Ubuntu 24.04) |
| Rust | rustc 1.95.0 |
| Docker | 28.x / Compose v2 |
| Wazuh Manager (standalone) | `wazuh/wazuh-manager:4.9.2` |
| Wazuh Manager (platform stack) | `sn360/wazuh-manager:regression` (FROM `wazuh/wazuh-manager:4.13.1`) |
| `sn360-desktop-agent` | `ef3b20c8418929672ede36987b46a48dc333d919` (`main`) |
| `sn360-security-platform` | `a13d568961a377646355707f92a1c972010d2e2c` (`main`) |

### Unit Tests — `cargo test --all`

**Result: 1075 passing / 0 failed / 0 ignored** across 62 test binaries (sda-agent, sda-comms, sda-core, sda-device-control, sda-event-bus, sda-fim, sda-jit-admin, sda-local-detection, sda-pal, sda-software, plus integration-test binaries). Up from 433 in the 2026-04-28 baseline as new crates and per-module tests landed.

### Build — `cargo build --release`

**Result: clean** — full workspace builds in 1m 22s with no warnings or errors.

### Base E2E — `bash tests/scripts/run-e2e.sh`

**Result: 14/14 assertions PASS** against a fresh `wazuh/wazuh-manager:4.9.2` brought up by `tests/docker-compose.yml`. All 14 checks (enrollment, FIM, baseline scan, inventory, log collection, journal, agent presence, active response, custom AR, SCA scan, rootcheck, journal Linux only) green.

### Platform Integration — Top-10 Security E2E (REG-054..REG-063)

`bash tests/regression/security-scenarios/run-top10-security-e2e.sh` against `sn360-security-platform` `a13d5689` on the full platform stack (`tests/regression/harness/sn360/docker-compose-up.sh`):

**Result: 10/10 PASS** on the first attempt (no flakes this run). REG-054 cleared on the initial pass without a re-run; the SCA timing window held end-to-end. REG-061 package inventory remains green via the `services/syscollector-bridge` sidecar (`rows=1` for `cowsay`).

| # | REG ID | Scenario | MITRE ATT&CK | Result |
|---|--------|----------|--------------|--------|
| 01 | REG-054 | Malware drop (`malware.exe` syscheck) | T1204.002 | PASS |
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
| build | `cargo build --workspace --release` | green |
| unit | `cargo test --all` | 1075/1075 |

### Known Issues

1. **Platform stack regression-harness blockers (now fixed upstream)** — On a clean snapshot, `sn360-security-platform/tests/regression/harness/sn360/docker-compose-up.sh` failed for four independent reasons (Dockerfile missing `COPY` for two `go.work` nested modules and for `connectors/`; `apply-migrations.sh` not creating the `sn360_service` role that migrations 021+ GRANT to; `mock-vendor` healthcheck resolving `localhost` to IPv6 while the server only listens on IPv4). All four are fixed in kennguy3n/sn360-security-platform#137; once that lands, the platform stack boots cleanly and this run reproduces deterministically.

---

## Historical Results

Earlier runs (Wazuh integration, scale benchmarks, security E2E
suite) are exercised on every PR through the
[CI workflows](./.github/workflows/) and the
[release workflow](./.github/workflows/release.yml). Per-run output
lives in the GitHub Actions run history rather than being inlined
here.
