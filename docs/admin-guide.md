# SDA Administrator Guide

Audience: SREs, security engineers, and packaging owners who
deploy SDA to fleets of devices and integrate it with the SN360
Control Plane (or, when the optional legacy adapter is enabled,
an existing legacy SIEM manager).

For per-host install instructions see the
[user guide](./user-guide.md); for module-level YAML see the
[configuration reference](./configuration-reference.md).

---

## 1. Deployment topology

SDA is a single static binary with two supported back ends:

- **Existing SIEM manager (default today).** The binary speaks a
  publicly documented legacy agent wire protocol on TCP/UDP port
  1514 with enrolment on port 1515. Interoperability with
  reference manager versions 4.7.x – 4.9.x is validated in CI via
  `make e2e` (v4.9.2) and `make e2e-compat` (v4.7.5). See
  [`proprietary-licensing-rationale.md`](./proprietary-licensing-rationale.md)
  for the clean-room interoperability statement.
- **SN360 Control Plane / Agent Gateway (opt-in).** mTLS
  entrypoint terminating the SN360 native protocol (TLS 1.3 +
  HTTP/2 + MessagePack). Enabled by flipping
  `server.enhanced.{tls, serialization}` on and setting
  `server.protocol: http2` in the deployment’s `config.yaml`.

The SIEM adapter back end can be compiled out of a given build by
dropping the `legacy-siem` Cargo feature; see the
[revised phase plan](./revised-phase-plan.md) for the timeline on
promoting the SN360 native protocol to default-on.

## 2. Packaging

```sh
# from repo root
make deb   # sda-agent_<version>_amd64.deb
make rpm   # sda-agent-<version>.x86_64.rpm
make pkg   # sda-agent-<version>.pkg (macOS installer)
make msi   # sda-agent-<version>.msi (Windows installer)
```

All scripts read the crate version from `crates/sda-agent/Cargo.toml`
so a single `cargo set-version` bumps every artefact. See
`packaging/` for the per-format build scripts.

### 2.1 systemd unit

`packaging/systemd/sda-agent.service` runs the agent as `root`
with:

- `ProtectSystem=strict`
- `ReadWritePaths=/etc/sn360-desktop-agent /var/lib/sn360-desktop-agent /var/log`
- `NoNewPrivileges=yes`
- `PrivateTmp=yes`

Note: the config dir is deliberately writable so enrolment can
persist `client.keys`. A previous revision had
`ReadOnlyPaths=/etc/sn360-desktop-agent`, which was a no-op
(overridden by `ReadWritePaths`) and was removed to avoid
confusion (PR review item A7).

### 2.2 Windows MSI

`packaging/windows/build-msi.ps1` ships the agent plus a default
config and a service definition. The config component carries
`NeverOverwrite="yes"` so operator edits survive upgrades (PR
review item A6).

## 3. Module tuning

SDA is event-driven by default. The knobs below are the ones most
often touched during rollout:

| Module                 | Knob                        | Effect                                              |
|------------------------|-----------------------------|-----------------------------------------------------|
| `fim`                  | `scan_interval`             | Seconds between idle-only baseline scans. Default 12 h. |
| `fim`                  | `batch_size`                | Max files per hash burst. Default 500.              |
| `fim`                  | `exclude`                   | Glob paths skipped by watcher and scanner.          |
| `logcollector`         | `max_lines_per_batch`       | Upper bound on events batched per send. Default 100. |
| `inventory`            | `interval`                  | Seconds between full inventory refreshes. Default 3600. |
| `sca`                  | `scan_on_idle`              | Defer checks until the host is idle.                |
| `local_detection`      | `rule_bundle_path`          | Path to the signed MessagePack bundle.              |
| `enhanced_inventory`   | `running_software_enabled`  | Toggle the per-10s process snapshot.                |
| `active_response`      | `allowed_commands`          | Command allow-list; defaults to `block_ip`, `kill_process`. |

## 4. Upgrade procedure

### 4.1 In-place via packaging

1. Stop the service:
   ```sh
   sudo systemctl stop sda-agent
   ```
2. Install the new package (`dpkg -i`, `rpm -U`, Installer.app, or
   MSI with `/qn`).
3. Confirm `sda-agent --version` matches the expected release.
4. Start the service:
   ```sh
   sudo systemctl start sda-agent
   ```
5. Tail the log for 5 minutes and confirm a keepalive lands on
   the manager’s event log (for the SN360 Control Plane, the
   Agent Gateway access log; for a legacy SIEM manager, its
   manager event log / `archives.json`).

### 4.2 Self-update (Phase 5.3)

If `updater.enabled: true` in `config.yaml`, the agent polls the
configured manifest endpoint and installs new signed releases in
place. The updater re-reads the installed version after every
successful install (PR review item A1) so a single manifest will
not trigger a re-download loop.

Rollback: the updater writes a `.sda-backup` sibling file to the
current binary before swapping. Restore by stopping the service,
renaming `sda-agent.sda-backup` → `sda-agent`, and restarting.

## 5. Migrating off the legacy SIEM adapter

The legacy SIEM protocol adapter is the shipped default today and
will be superseded by the SN360 native protocol. Once the SN360
Control Plane is available for a fleet, move agents onto the
SN360 native protocol:

1. Stand up the SN360 Agent Gateway reachable from the fleet.
2. Update the agent config so `server.address` points at the
   Agent Gateway, set `server.protocol: http2`, and flip
   `server.enhanced.tls: true` and
   `server.enhanced.serialization: msgpack`.
3. Roll out the updated config; agents reconnect via mTLS through
   the native protocol and obtain fresh native enrolment material
   from the Gateway.
4. Disable the legacy adapter in the build by producing an SDA
   release **without** the `legacy-siem` Cargo feature; the
   legacy transport code then compiles out entirely.

Earlier internal builds shipped under the `wda-*` prefix. Crate
names, binary names, and install paths have since been renamed
to `sda-*`. When upgrading from a pre-0.9 build:

1. Stop and disable the old service
   (`wda-agent.service` → `sda-agent.service`).
2. Move `/etc/wazuh-desktop-agent/` →
   `/etc/sn360-desktop-agent/` (preserve `client.keys`).
3. Install the new package.
4. Re-enable and start the `sda-agent` service.

The legacy `wazuh-desktop-agent` systemd unit is idempotent to
remove; the new unit does not conflict with it.

## 6. Observability

- **Logs:** `journalctl -u sda-agent` (systemd), `log show
  --predicate 'subsystem == "com.sn360.desktop-agent"'` (macOS),
  Event Viewer → Applications and Services Logs → SDA (Windows).
- **Metrics:** benchmark thresholds and CI results are tracked in
  [`benchmark-results.md`](../benchmark-results.md). The
  regression gate (`make benchmark-ci`) fails if idle RSS
  > 15 MB, idle CPU > 0.1 %, binary > 7 MB, or FIM burst peak
  > 3 %.
- **Health checks:** the agent writes a systemd watchdog ping
  every 30 s when `WatchdogSec=` is set in the unit file. The
  tamper-protection watchdog in `sda-agent::tamper` monitors the
  binary, config, and client.keys and restarts the agent on
  unauthorised mutation (PR #50).

## 7. Security posture

- Binary is built with `lto="fat"`, `panic="abort"`,
  `opt-level="z"`, `strip=true` — no debug symbols ship to prod.
- All parsers have `cargo fuzz` targets (see
  [`security-audit.md`](./security-audit.md)).
- Dependencies are gated through `cargo audit` in CI.
- TLS 1.3 + certificate pinning are available via the SN360
  native protocol (`server.enhanced.tls: true`,
  `server.enhanced.serialization: msgpack`,
  `server.protocol: http2`) — opt-in today, default-on in a
  future release tracked in the revised phase plan.
