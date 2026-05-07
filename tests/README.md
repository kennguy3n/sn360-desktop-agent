# SN360 Desktop Agent — Tests

End-to-end tests and fixtures for `sn360-agent-device`. Unit tests
live alongside each crate under `crates/*/src` and are exercised with
`cargo test --all`; this directory contains only the **integration /
E2E** harness, which drives the agent against a real Wazuh 4.9.2
manager running in Docker.

## Prerequisites

- **Docker + Compose v2** — `docker` and `docker compose` on `PATH`.
- **Rust 1.75+** — the harness builds `./target/release/sda-agent`
  on first run (and reuses any prebuilt binary on subsequent runs).
- **`sudo`** — the agent writes its enrollment keys under
  `/etc/sn360-desktop-agent/` and its baseline databases under
  `/var/lib/sn360-desktop-agent/`.
- **Linux host** — `run-e2e.sh` uses `inotify`, `journald`, `logger`,
  and Docker-for-Linux specifics. macOS / Windows have their own
  platform-specific entry points (`run-e2e-macos.sh`,
  `run-e2e-windows.ps1`).

## Running the suite

All entry points are wrapped by the repository `Makefile` targets:

```bash
make e2e            # Linux — base 14-assertion suite
make security-e2e   # Linux — 10 security-focused attack scenarios
make e2e-macos      # macOS — platform-specific coverage
make e2e-windows    # Windows — platform-specific coverage
```

Each script brings up `wazuh/wazuh-manager:4.9.2` via
[`docker-compose.yml`](./docker-compose.yml), patches in any extra
server config it needs (enrollment password, `<active-response>`
blocks for the security suite), builds and enrols the agent, exercises
each module, verifies alerts / inventory rows on the manager, and
then tears everything down in the `trap cleanup EXIT` handler.

Exit codes:
- `0` — all checks passed.
- non-zero — at least one assertion failed; the summary block at the
  bottom of stdout lists each `PASS:` / `FAIL:` line.

## Layout

| Path | Purpose |
|---|---|
| `docker-compose.yml` | Wazuh 4.9.2 manager used by every E2E entry point |
| `sda-test-config.yaml` | Linux agent config — enables every module the harness asserts on |
| `sda-test-config-macos.yaml` | macOS agent config |
| `sda-test-config-windows.yaml` | Windows agent config |
| `scripts/run-e2e.sh` | Base Linux E2E harness (14 assertions) |
| `scripts/run-security-e2e.sh` | Linux security E2E harness (10 attack scenarios, injects `<active-response>` blocks) |
| `scripts/run-e2e-macos.sh` | macOS E2E harness |
| `scripts/run-e2e-windows.ps1` | Windows E2E harness |
| `scripts/fim-burst-bench.sh` | FIM scan CPU benchmark (reproduces the numbers in `benchmark-results.md`) |

## What each suite validates

- **Base E2E** (`make e2e`) — enrollment, keepalive, FIM realtime +
  baseline + deletion, inventory, file-tail and journald log
  collection, active response, SCA policy result, rootcheck signature
  hit, and enhanced-inventory scanner liveness (running software,
  SBOM, browser extensions).
- **Security E2E** (`make security-e2e`) — malware file drop,
  brute-force SSH, sudo abuse, config tampering, ransomware
  simulation, active response `kill_process`, `firewall-drop` for
  IPv4 + IPv6, unauthorized package install, system-binary tampering,
  and account-disable AR.

See [`PROGRESS.md`](../PROGRESS.md) for the current pass counts and
known gaps (including the macOS FIM burst test that is currently
skipped on CI).

## Troubleshooting

- **`ERROR: Docker daemon not reachable`** — make sure `docker info`
  succeeds as the user running the script; rootless Docker requires
  `DOCKER_HOST` to be exported before `sudo` chains.
- **`Wazuh manager did not become ready within timeout`** — the
  manager sometimes needs longer than 90 × 2 s on slow hosts. Rerun
  after pulling the image once (`docker compose -f
  tests/docker-compose.yml pull`).
- **Stale `client.keys`** — the `cleanup` trap wipes
  `/etc/sn360-desktop-agent/client.keys` and any previously-enrolled
  agents from the manager; if a run is killed with `SIGKILL` you may
  need to remove these by hand before the next run.
- **Agent log** — each run tails `/tmp/sda-agent-e2e.log` into the
  final summary; this is the first place to look when a check fails.
