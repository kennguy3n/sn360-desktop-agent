# SDA User Guide

Audience: individual contributors and endpoint owners who need to
install, enrol, and operate the SN360 Desktop Agent (SDA) on a
single machine.

For multi-host deployment automation see the
[admin guide](./admin-guide.md); for the full YAML schema see the
[configuration reference](./configuration-reference.md).

---

## 1. Supported platforms

| OS      | Versions                        | Install artefact |
|---------|---------------------------------|-------------------|
| Linux   | Ubuntu 22.04+, Debian 12+, Fedora 38+, Arch rolling | `.deb`, `.rpm`, tarball |
| macOS   | 12 Monterey – 15 Sequoia         | `.pkg`            |
| Windows | Windows 10 22H2, Windows 11      | `.msi`            |

All artefacts are produced by `make deb|rpm|pkg|msi` from the repo
root.

## 2. Installation

### 2.1 Linux (Debian/Ubuntu)

```sh
sudo apt install ./sda-agent_0.9.0-beta.1_amd64.deb
```

The package drops a systemd unit at
`/lib/systemd/system/sda-agent.service` and a default config at
`/etc/sn360-desktop-agent/config.yaml`. The unit is not started
automatically — enrol first (step 3), then run:

```sh
sudo systemctl enable --now sda-agent
```

### 2.2 Linux (Fedora/RHEL)

```sh
sudo dnf install ./sda-agent-0.9.0-beta.1.x86_64.rpm
sudo systemctl enable --now sda-agent
```

### 2.3 macOS

Double-click `sda-agent-0.9.0-beta.1.pkg` and follow the prompts.
The installer places `sda-agent` at
`/usr/local/bin/sda-agent` and a LaunchDaemon plist at
`/Library/LaunchDaemons/com.sn360.desktop-agent.plist`. Start
with:

```sh
sudo launchctl load /Library/LaunchDaemons/com.sn360.desktop-agent.plist
```

### 2.4 Windows

Run `sda-agent-0.9.0-beta.1.msi` as Administrator. The installer
creates a Windows service (`SDAAgent`), placing the binary at
`C:\Program Files\SN360DesktopAgent\sda-agent.exe` and the config
at `C:\Program Files\SN360DesktopAgent\config.yaml`.

## 3. Enrolment

SDA enrols against the SN360 Control Plane (or a compatible SIEM
manager via the legacy adapter) over the enrolment daemon on
port 1515. On Linux/macOS:

```sh
sudo /usr/local/bin/sda-agent --enroll \
  --server sn360.example.com \
  --password "$(cat /etc/sn360-desktop-agent/enrollment.password)"
```

On Windows (PowerShell, Administrator):

```powershell
& 'C:\Program Files\SN360DesktopAgent\sda-agent.exe' --enroll `
  --server sn360.example.com `
  --password (Get-Content 'C:\Program Files\SN360DesktopAgent\enrollment.password')
```

Successful enrolment writes `client.keys` into the config directory
and is persisted across restarts. The server address, port, and
whether to auto-enrol can also be set in `config.yaml` (see the
[configuration reference](./configuration-reference.md)).

## 4. Basic configuration

The minimal working configuration points the agent at a manager
and enables the FIM and log-collection modules:

```yaml
server:
  address: sn360.example.com
  port: 1514
  protocol: tcp     # "tcp" (default) | "udp" | "http2" (SN360 native)

enrollment:
  server: sn360.example.com
  port: 1515

modules:
  fim:
    enabled: true
    directories:
      - path: /etc
        recursive: true
        realtime: true
  logcollector:
    enabled: true
    sources:
      - type: file
        path: /var/log/auth.log
        format: syslog
```

Reload after editing:

```sh
sudo systemctl reload sda-agent     # Linux
sudo launchctl kickstart -k system/com.sn360.desktop-agent  # macOS
Restart-Service SDAAgent            # Windows (PowerShell)
```

## 5. Troubleshooting

### Agent fails to enrol

Symptom: `systemctl status sda-agent` shows repeated
`connection refused`, `TLS handshake failed`, or
`invalid enrollment password`.

- For the SN360 native protocol, confirm the Agent Gateway is
  reachable from the endpoint (`openssl s_client -alpn h2
  -connect sn360.example.com:443`) and that the endpoint trusts
  the Gateway’s certificate chain (or the configured
  `server.enhanced.tls_pinned_sha256`).
- When using the legacy adapter, check that the `authd`-
  compatible enrolment daemon is listening on the manager
  (`ss -tlnp | grep 1515`) and that the enrolment password
  matches the manager-side value
  (e.g. `/var/ossec/etc/authd.pass` on reference managers).
- Make sure the config directory is writable: enrolment writes
  `client.keys` to `/etc/sn360-desktop-agent/` (Linux) or
  `C:\Program Files\SN360DesktopAgent\` (Windows). The systemd
  unit intentionally allows write access here — see
  `packaging/systemd/sda-agent.service`.

### FIM events not reaching the manager

- Inspect `/var/log/sda-agent.log` (Linux/macOS) or Event Viewer
  → Applications and Services Logs → SDA (Windows).
- Confirm the monitored paths exist and that the agent user has
  read permission.
- On Linux, `fanotify` requires `CAP_SYS_ADMIN`; the agent
  transparently falls back to `inotify` if the capability is
  missing.

### High CPU during FIM scan

The burst budget is 3 % peak (see
[`benchmark-results.md`](../benchmark-results.md)). If you see
higher, adjust in `config.yaml`:

```yaml
modules:
  fim:
    scan_interval: 86400     # once per day instead of 12h
    batch_size: 50           # smaller burst cadence
```

### Reporting an issue

Collect:

1. The output of `sda-agent --version`.
2. `journalctl -u sda-agent --since '-10 min'` (Linux) or
   equivalent on macOS/Windows.
3. The redacted config file (strip `enrollment.password`).

Open a ticket at the repo issue tracker or email
`support@uney.com`.
