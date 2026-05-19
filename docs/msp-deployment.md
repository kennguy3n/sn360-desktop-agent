# MSP / MSSP Deployment Guide

Mass deployment of the SN360 Desktop Agent (SDA) across managed
endpoints. This guide covers Windows (GPO / SCCM), macOS (MDM), and
Linux (apt / yum repository).

## Pre-built packages

SDA ships pre-built packages for all supported platforms:

| Platform | Format | Architecture |
|----------|--------|-------------|
| Windows | `.msi` | x86_64, ARM64 |
| macOS | `.pkg` | x86_64 (Intel), ARM64 (Apple Silicon) |
| Linux (Debian/Ubuntu) | `.deb` | x86_64, ARM64 |
| Linux (RHEL/Fedora/SUSE) | `.rpm` | x86_64, ARM64 |

Download packages from the release page or your SN360 provider's
distribution endpoint.

## Configuration

Every deployment needs two values:

- **Gateway URL** — the SN360 platform endpoint the agent connects to
  (provided by the MSSP operating the SN360 platform).
- **Bootstrap token** — a one-time enrollment credential scoped to the
  tenant (generated in the SN360 dashboard under Settings → Agents).

These are injected into the agent config at install time. The config
file is installed at:

- **Linux:** `/etc/sn360-desktop-agent/config.yaml`
- **macOS:** `/Library/Application Support/SN360/config.yaml`
- **Windows:** `C:\ProgramData\SN360\config.yaml`

Select a [feature profile](./feature-profiles.md) (Basic, Standard,
or Advanced) as the base config and substitute the gateway URL and
bootstrap token.

## Windows — GPO / SCCM

### Silent MSI install

```powershell
msiexec /i sn360-desktop-agent-x64.msi /qn ^
  SN360_GATEWAY_URL=https://gateway.example.com ^
  SN360_BOOTSTRAP_TOKEN=tok-xxxx ^
  SN360_PROFILE=standard
```

### Group Policy deployment

1. Copy the `.msi` to a network share accessible by target machines.
2. Create a GPO linked to the target OU.
3. Under **Computer Configuration → Policies → Software Settings →
   Software Installation**, add the MSI as an Assigned package.
4. Deploy the config file via GPO Preferences (File):
   - Source: `\\share\sn360\config.yaml`
   - Destination: `C:\ProgramData\SN360\config.yaml`
5. Force a Group Policy update: `gpupdate /force` or wait for the
   next refresh cycle.

### SCCM / Intune

Create an application deployment with:
- Install command: `msiexec /i sn360-desktop-agent-x64.msi /qn SN360_GATEWAY_URL=... SN360_BOOTSTRAP_TOKEN=...`
- Detection rule: file exists `C:\Program Files\SN360\sda-agent.exe`
- Uninstall: `msiexec /x {product-code} /qn`

## macOS — MDM

### Jamf Pro / Mosyle / Kandji

1. Upload the `.pkg` to your MDM's package repository.
2. Create a pre-install script that writes the config:

```bash
#!/bin/bash
mkdir -p "/Library/Application Support/SN360"
cat > "/Library/Application Support/SN360/config.yaml" <<'EOF'
# paste profile-standard.yaml contents with gateway URL + token
EOF
```

3. Deploy as a package policy targeted at the appropriate device groups.
4. The agent starts automatically via launchd after install.

### Manual install

```bash
sudo installer -pkg sn360-desktop-agent-arm64.pkg -target /
```

## Linux — apt / yum repository

### Debian / Ubuntu (APT)

```bash
# Add the SN360 repository
curl -fsSL https://packages.example.com/sn360/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/sn360.gpg
echo "deb [signed-by=/usr/share/keyrings/sn360.gpg] https://packages.example.com/sn360/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/sn360.list

# Install
sudo apt update
sudo apt install sn360-desktop-agent

# Deploy config
sudo cp profile-standard.yaml /etc/sn360-desktop-agent/config.yaml
sudo systemctl enable --now sn360-desktop-agent
```

### RHEL / Fedora / SUSE (YUM / DNF)

```bash
# Add the SN360 repository
sudo tee /etc/yum.repos.d/sn360.repo <<'EOF'
[sn360]
name=SN360 Agent Repository
baseurl=https://packages.example.com/sn360/rpm
gpgcheck=1
gpgkey=https://packages.example.com/sn360/gpg.key
enabled=1
EOF

# Install
sudo dnf install sn360-desktop-agent

# Deploy config
sudo cp profile-standard.yaml /etc/sn360-desktop-agent/config.yaml
sudo systemctl enable --now sn360-desktop-agent
```

### Ansible

```yaml
- name: Deploy SN360 Desktop Agent
  hosts: endpoints
  become: true
  tasks:
    - name: Install agent package
      package:
        name: sn360-desktop-agent
        state: present

    - name: Deploy agent config
      template:
        src: sn360-config.yaml.j2
        dest: /etc/sn360-desktop-agent/config.yaml
        owner: root
        group: sn360-agent
        mode: '0640'
      notify: restart sn360-desktop-agent

  handlers:
    - name: restart sn360-desktop-agent
      systemd:
        name: sn360-desktop-agent
        state: restarted
        enabled: true
```

## Post-deployment verification

After deployment, verify agents are checking in:

1. In the SN360 dashboard, navigate to **Agents → Inventory**.
2. Filter by the tenant and confirm the expected number of agents
   appear with status "Active".
3. Verify the agent version matches the deployed package version.
4. Check a sample endpoint: `systemctl status sn360-desktop-agent`
   (Linux) or check Services (Windows) for the SN360 service.
