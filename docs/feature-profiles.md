# Feature Profiles

SDA ships three pre-configured feature profiles that control which
modules are enabled at deployment time. Operators select a profile
based on the tenant's security maturity, compliance requirements, and
endpoint resource constraints.

## Profiles at a glance

| Profile | Modules enabled | Memory | Use case |
|---------|----------------|--------|----------|
| **Basic** | FIM, log collection, software inventory, SCA, TRDS | ~8-12 MB | SMEs on day one; minimal endpoint overhead |
| **Standard** | Basic + EDR (process telemetry + local detection) + network telemetry | ~20-30 MB | SMEs with compliance needs or wanting threat visibility |
| **Advanced** | Standard + DLP, identity monitoring, memory scanning, device control, MDM, host isolation, rootcheck, enhanced inventory | ~40-60 MB | Regulated industries (healthcare, finance, government) |

## Profile details

### Basic

The minimum viable security profile. Provides foundational endpoint
hygiene without the overhead of full EDR.

**Enabled modules:**
- File integrity monitoring (FIM) — realtime inotify on `/etc`, periodic SHA-256 on `/usr/bin`, `/usr/sbin`
- Log collection — journald for sshd, sudo, systemd-logind
- Software inventory — OS, network, packages, hardware (hourly)
- Security configuration assessment (SCA) — policy sweep every 12 hours
- Active response — IP blocking, process termination
- TRDS — rule distribution (always-on so the agent stays current)

**Disabled:** EDR, network telemetry, host isolation, memory scanning,
identity monitoring, DLP, device control, desktop MDM.

**Config:** [`configs/profile-basic.yaml`](../configs/profile-basic.yaml)

### Standard

Adds EDR and network visibility. The local detection engine (LDE)
performs edge IOC matching and behavioural rule evaluation. Detection
rule bundles are Ed25519-signed and hot-swap atomically.

**Enabled modules:** everything in Basic, plus:
- EDR — process telemetry (create, terminate, image load) + LDE
- Network telemetry — TCP/UDP connections + DNS monitoring + IOC matching

**Disabled:** Host isolation, memory scanning, identity monitoring,
DLP, device control, desktop MDM.

**Config:** [`configs/profile-standard.yaml`](../configs/profile-standard.yaml)

### Advanced

Full capability surface for maximum protection and compliance
evidence collection. Recommended for regulated industries and
high-value endpoints.

**Enabled modules:** everything in Standard, plus:
- Host isolation — per-OS firewall primitives for network quarantine
- Memory scanning — periodic RWX region scanning + in-memory YARA
- Identity monitoring — LSASS access (Windows), `/etc/shadow` and `/proc/kcore` (Linux), keychain (macOS)
- DLP — regex-based scanning of file writes with Blake3 fingerprinting
- Device control — USB and removable media policy enforcement
- Desktop MDM — auto-remediation, recovery key escrow, OS patch orchestration
- Rootcheck — rootkit detection (12-hour sweep)
- Enhanced inventory — running software, browser extensions, CycloneDX SBOM

**Config:** [`configs/profile-advanced.yaml`](../configs/profile-advanced.yaml)

## Deploying a profile

Copy the profile YAML to the agent's config directory, replace the
`${SN360_GATEWAY_URL}` placeholder with your actual gateway address,
and restart:

```bash
# Example: deploy standard profile
sudo cp configs/profile-standard.yaml /etc/sn360-desktop-agent/config.yaml
sudo sed -i 's|${SN360_GATEWAY_URL}|wss://gateway.example.com|' \
  /etc/sn360-desktop-agent/config.yaml
sudo systemctl restart sn360-desktop-agent
```

For mass deployment, embed the profile YAML in your GPO, MDM, or
configuration management tooling. See
[`docs/msp-deployment.md`](./msp-deployment.md) for per-platform
mass deployment guides.

## Customising profiles

Profiles are regular YAML config files — operators can enable or
disable individual modules to create custom combinations. The three
profiles above are starting points, not hard constraints. Any module
listed in the [configuration reference](./configuration-reference.md)
can be toggled independently.

## Upgrading profiles

Switching from Basic to Standard (or Standard to Advanced) is a
config-only change — no reinstall required. Update the config file
and restart the agent. The newly-enabled modules initialise on startup
and begin producing telemetry immediately.
