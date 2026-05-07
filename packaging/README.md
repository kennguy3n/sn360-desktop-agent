# Packaging

Installer recipes for the SN360 Desktop Agent across Linux, macOS, and
Windows. Each platform has a build script that takes an
already-compiled release binary (`cargo build --release -p sda-agent`)
and emits a ready-to-install package into `dist/`.

```
packaging/
├── config/
│   └── config.yaml              # Default /etc/sn360-desktop-agent/config.yaml
├── systemd/
│   └── sda-agent.service        # systemd unit (Type=simple, User=sda)
├── debian/
│   ├── control, conffiles, postinst, prerm, postrm
│   └── build-deb.sh             # dpkg-deb driver
├── rpm/
│   ├── sda-agent.spec
│   └── build-rpm.sh             # rpmbuild driver
├── macos/
│   ├── com.sn360.desktop-agent.plist
│   ├── scripts/{preinstall,postinstall}
│   └── build-pkg.sh             # pkgbuild + productbuild driver
└── windows/
    ├── sda-agent.wxs            # WiX 3.x manifest, registers Windows Service
    └── build-msi.ps1            # candle + light driver
```

## Install layout

| Path                                      | Purpose                                  | Platform |
|-------------------------------------------|------------------------------------------|----------|
| `/usr/bin/sda-agent`                      | Agent binary                             | Linux    |
| `/usr/local/bin/sda-agent`                | Agent binary                             | macOS    |
| `C:\Program Files\SN360DesktopAgent\sda-agent.exe` | Agent binary                  | Windows  |
| `/etc/sn360-desktop-agent/config.yaml`    | Main config (conffile, preserved on upgrade) | Linux/macOS |
| `/etc/sn360-desktop-agent/client.keys`    | Enrollment key, 0600 root:sda            | Linux/macOS |
| `/etc/sn360-desktop-agent/sca/`           | SCA policies                             | Linux/macOS |
| `/var/lib/sn360-desktop-agent/`           | State (FIM DB, rootcheck baseline, LDE)  | Linux/macOS |
| `/var/log/sn360-desktop-agent/`           | Log files                                | Linux/macOS |
| `C:\ProgramData\SN360DesktopAgent\`       | State                                    | Windows  |

## Service registration

- **Linux** — `systemctl enable --now sda-agent.service` (installed by
  `postinst`/`%post`). Unit runs as user `sda`, `Restart=on-failure`,
  `RestartSec=5`, hardened via `ProtectSystem=strict` and
  `NoNewPrivileges=true`.
- **macOS** — launchd daemon `com.sn360.desktop-agent`, loaded by the
  `.pkg` postinstall script. `KeepAlive.Crashed=true` so launchd
  restarts the agent on unexpected exit.
- **Windows** — Windows Service `SN360DesktopAgent` registered by the
  MSI (`ServiceInstall`). Recovery configured to restart on first,
  second, and third failures with a 5-second delay (matches
  `RestartSec=5` on Linux).

## Building

```bash
# All platforms share the same release binary for their native arch:
cargo build --release -p sda-agent

# Linux .deb (run on Debian/Ubuntu with dpkg-dev installed)
make deb

# Linux .rpm (run on Fedora/RHEL-family with rpm-build installed)
make rpm

# macOS .pkg (run on macOS)
make pkg

# Windows .msi (run on Windows with WiX Toolset 3.x on PATH)
make msi
```

The underlying scripts accept `BIN=...`, `VERSION=...`, and
`OUT_DIR=...` environment overrides so release jobs that compile
binaries via cross-compilation can point at the right target
directory (e.g. `BIN=target/x86_64-unknown-linux-gnu/release/sda-agent`).
