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

## Historical Results

Earlier runs (Wazuh integration, scale benchmarks, security E2E
suite) are exercised on every PR through the
[CI workflows](./.github/workflows/) and the
[release workflow](./.github/workflows/release.yml). Per-run output
lives in the GitHub Actions run history rather than being inlined
here.
