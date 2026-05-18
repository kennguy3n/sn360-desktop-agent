# Platform Testing

SDA targets Windows 10/11, macOS 12–15, and modern Linux
(Ubuntu, Fedora, Arch). The GitHub Actions matrix in
`.github/workflows/ci.yml` covers the platforms that are available
as hosted runners:

| Target                    | CI runner     | Coverage                                  |
|---------------------------|--------------|-------------------------------------------|
| Ubuntu 22.04 LTS          | `ubuntu-22.04` | `cargo test --all`, clippy, rustfmt     |
| Ubuntu 24.04 LTS          | `ubuntu-24.04` | `cargo test --all`                      |
| macOS 13 Ventura (x86_64) | `macos-13`    | `cargo test --all`                       |
| macOS 14 Sonoma (arm64)   | `macos-14`    | `cargo test --all`                       |
| Windows Server 2022       | `windows-2022`| `cargo test --all`                       |

Fedora and Arch Linux are not available as hosted runners, so they
are validated manually before each tagged release. The smoke checks
below cover the platform-specific paths most likely to regress:
package enumeration (PAL inventory), systemd unit install/start, and
fanotify-based FIM permission handling.

## Fedora (latest stable)

1. Provision a fresh Fedora Server 40 VM (minimum 2 GiB RAM, 10 GiB
   disk).
2. Install build dependencies:
   ```sh
   sudo dnf install -y rust cargo systemd-devel yara yara-devel
   ```
3. Build the release binary:
   ```sh
   cargo build --release
   ```
4. Install the `.rpm`:
   ```sh
   sudo dnf install -y ./dist/sda-agent-*.x86_64.rpm
   sudo systemctl enable --now sda-agent
   sudo systemctl status sda-agent
   ```
5. Point the agent at a local Wazuh 4.9.2 manager and run the
   E2E suite:
   ```sh
   make e2e
   ```
6. Verify RPM-backed package inventory:
   ```sh
   grep -c '"type":"syscollector"' /var/ossec/logs/archives/archives.json
   ```
   Expect a non-zero count after the 1h inventory interval.
7. Uninstall cleanly:
   ```sh
   sudo systemctl disable --now sda-agent
   sudo dnf remove -y sda-agent
   ```

## Arch Linux (rolling)

1. Provision a fresh `archlinux:latest` container or a rolling VM.
2. Install dependencies:
   ```sh
   sudo pacman -S --needed rust cargo systemd yara make
   ```
3. Build and install:
   ```sh
   cargo build --release
   sudo install -m 0755 target/release/sda-agent /usr/local/bin/
   sudo install -m 0644 packaging/systemd/sda-agent.service \
     /etc/systemd/system/
   sudo mkdir -p /etc/sn360-desktop-agent
   sudo install -m 0640 tests/sda-test-config.yaml \
     /etc/sn360-desktop-agent/config.yaml
   sudo systemctl daemon-reload
   sudo systemctl enable --now sda-agent
   ```
4. Run the E2E suite (requires Docker):
   ```sh
   make e2e
   ```
5. Verify pacman-backed package inventory populates `syscollector`
   (same oracle as Fedora).

## macOS 12 Monterey

macOS 13 and 14 are exercised in CI; macOS 12 Monterey is still
formally supported and must be validated by hand before each release.

1. Provision a Monterey VM or use a bare-metal Mac mini.
2. Build `.pkg`:
   ```sh
   make pkg
   ```
3. Install via Installer.app (double-click `.pkg`).
4. Start the launchd service:
   ```sh
   sudo launchctl load /Library/LaunchDaemons/com.sn360.desktop-agent.plist
   sudo launchctl start com.sn360.desktop-agent
   ```
5. Run `make e2e-macos` on a host with Docker Desktop.
6. Confirm FSEvents-based FIM and Unified Log collection via the
   usual archive oracles.

## Windows 10

Windows Server 2022 exercises the same SDK surface as Windows 11
and is covered in CI. Windows 10 22H2 still ships to a meaningful
share of endpoints and is validated by hand:

1. Provision a Windows 10 Enterprise 22H2 VM.
2. Build `.msi`:
   ```sh
   make msi
   ```
3. Install via the MSI UI with admin rights.
4. Confirm the service is running:
   ```powershell
   Get-Service SDAAgent
   ```
5. Run `tests/scripts/run-e2e-windows.ps1` against a Wazuh manager
   reachable from the host.

## Release sign-off

The release checklist in `CHANGELOG.md` references this document.
Manual validation artifacts (`journalctl -u sda-agent`, Event
Viewer exports, launchd logs) should be attached to the release
issue so the Fedora/Arch/macOS 12/Windows 10 coverage is auditable.
