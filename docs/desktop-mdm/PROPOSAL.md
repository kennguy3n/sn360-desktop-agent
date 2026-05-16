# Technical Proposal: ShieldNet Desktop MDM

> **Version:** 0.1 | **Date:** May 2026 | **Status:** Planning
> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)
> **Target Platforms:** Windows 10/11, macOS 12+, Linux (Ubuntu/Fedora/Arch/SUSE)

> **Scope note:** ShieldNet Desktop MDM spans both the agent
> (`sn360-desktop-agent`, this repository) and the SN360 control plane
> (`sn360-security-platform`). This proposal covers the design end to
> end so the two repositories can be built in lockstep, but only the
> *agent-side* sections (§§ 3–6, 8, 10–12) are implemented in this
> repository. Control-plane sections (§ 7 and the ⚙️-tagged tasks in
> § 13) are implemented in
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform/blob/main/docs/desktop-mdm/PROPOSAL.md).

---

## Table of Contents

1. [Executive decision](#1-executive-decision)
2. [Product scope](#2-product-scope)
3. [New crate: `sda-mdm`](#3-new-crate-sda-mdm)
4. [PAL additions](#4-pal-additions)
5. [Configuration](#5-configuration)
6. [Security model](#6-security-model)
7. [Control-plane surface](#7-control-plane-surface)
8. [Performance](#8-performance)
9. [Evidence and audit](#9-evidence-and-audit)
10. [MessageType variants](#10-messagetype-variants)
11. [NATS subjects](#11-nats-subjects)
12. [SMI sub-scores](#12-smi-sub-scores)
13. [Competitive differentiation](#13-competitive-differentiation)
14. [Phasing](#14-phasing)
15. [Risk register](#15-risk-register)

---

## 1. Executive decision

SDA already runs on every laptop. Instead of bolting on Intune /
Jamf-style MDM enrollment, **SDA becomes the MDM enforcement point
natively**. Zero new infrastructure. Zero Apple Push certificates for
desktops. Zero per-device MDM license cost. Zero IT-admin enrollment
ceremony.

This proposal turns that into a first-class product surface called
**ShieldNet Desktop MDM**. The decision is to deliver it as:

- **An SDA-native Rust module** (`sda-mdm`) under
  [`crates/sda-mdm/`](../../crates/sda-mdm) that owns wipe, lock,
  lost mode, recovery-key escrow, OS patch orchestration, declarative
  configuration profiles, and posture auto-remediation.
- **A thin SN360 control-plane companion** (`services/desktop-mdm`)
  in
  [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)
  for command dispatch, recovery-key vault integration, and
  compliance aggregation. **No new control-plane infrastructure** —
  the service reuses NATS, Postgres, TRDS, the privacy-vault, and the
  existing alert pipeline.
- **Real per-OS implementations** that call native platform APIs
  (`manage-bde`, `fdesetup`, `cryptsetup`, `LockWorkStation`,
  `CGSession`, `loginctl`, `systemreset.exe`, `UsoClient`,
  `softwareupdate`, `unattended-upgrades`, `profiles`, `dconf`,
  `polkit`, registry / GPO). **No stub, no scaffold.**
- **A "found issue → auto-fix → evidence → SMI" loop**, identical to
  Device Control's philosophy
  ([`device-control/PROPOSAL.md` § 2.1](../device-control/PROPOSAL.md#21-product-promise)).
  When `sda-posture` reports FDE-off, firewall-off, or screen-lock-off,
  `sda-mdm` *auto-remediates locally* without a control-plane
  round-trip — this is the "no IT admin required" differentiator.
- **Default ON.** Unlike Device Control modules which default to
  `enabled: false`, the MDM module ships secure by default with
  `enabled: true` and `auto_remediate.*: true`.
- **No new external dependencies.** Everything wraps OS-native tools
  and APIs already shipped by the platform vendor.

The product targets SDA's existing resource budgets — idle RSS
< 15 MB, idle CPU < 0.1 %, FIM scan peak < 3 %, binary < 7 MB — without
regression. The `sda-mdm` crate adds < 1 MB to the agent binary.

---

## 2. Product scope

### 2.1 Product promise

> Every laptop is managed, compliant, and recoverable — without an IT
> admin babysitting it.

If a candidate MDM capability does not start at "found issue" and end
at "SMI improvement" *without operator involvement for the
common-case fixes*, it does not ship in MVP.

### 2.2 Customer-facing examples

| # | Example                                  | Plain-English risk                                                | One-click / auto fix                                                                                  |
|---|------------------------------------------|-------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| 1 | **3 laptops have disk encryption off**   | "3 laptops have disk encryption turned off — data at risk if lost." | Auto-enable BitLocker / FileVault / LUKS on next boot; escrow recovery key.                            |
| 2 | **2 devices missing for 14+ days**       | "2 devices haven't checked in for 14+ days — possibly lost."       | Remote lock + lost mode with custom message on next contact.                                            |
| 3 | **8 devices have pending OS security updates** | "8 devices have pending OS security patches — known CVEs apply." | Auto-install during the next maintenance window; defer feature updates pending approval.                |
| 4 | **Recovery keys not escrowed for 5 devices** | "5 devices have encrypted disks but no escrowed recovery key — locked-out risk." | Auto-escrow on next heartbeat to the privacy-vault.                                                    |
| 5 | **1 device reported stolen**             | "1 device reported stolen — wipe before the attacker boots it."    | Remote wipe (crypto-shred recovery / volume keys + OS factory reset) with dual-control approval.        |

### 2.3 Product boundary

**Build**

- Remote wipe (crypto-shred + OS reset).
- Remote lock (lock screen + custom message).
- Lost mode (locked display + last-known location via IP geolocation).
- Recovery key escrow (BitLocker / FileVault / LUKS).
- OS patch orchestration (Windows Update / softwareupdate / unattended-upgrades).
- Declarative configuration profiles (password policy, screen lock,
  Bluetooth / camera / Wi-Fi policy).
- Posture auto-remediation (FDE on, firewall on, screen lock on).

**Avoid**

- Full RMM parity with Tactical RMM, NinjaOne, N-able.
- BYOD containerisation (work / personal profile split).
- Mobile MDM (Android, Apple, ChromeOS) — already handled by the
  existing connectors documented in
  [`device-control/PROPOSAL.md` § 9.8](../device-control/PROPOSAL.md#98-mobile-mdm-later).
- Apple ADE / DEP / VPP enrollment ceremonies.
- Per-device MDM licensing or Apple Push certificate management.

### 2.4 Relationship to Device Control

Desktop MDM is a *sibling* module to Device Control, not a layer on
top of it. The two modules share infrastructure (`sda-pal`,
`sda-event-bus`, `sda-comms`, `sda-device-control`'s signed-job
router, `sda-posture`'s snapshots, the existing EvidenceRecord
chain) but ship and version independently. The crate dependency
graph in § 3 makes this explicit.

---

## 3. New crate: `sda-mdm`

`sda-mdm` lives under [`crates/sda-mdm/`](../../crates/sda-mdm) and
follows the same conventions as every other `sda-*` crate
([`docs/architecture.md` § Crate map](../architecture.md#1-crate-map)).

### 3.1 Dependencies

| Depends on            | Why                                                                                          |
|-----------------------|----------------------------------------------------------------------------------------------|
| `sda-core`            | Config (`AgentConfig::modules::mdm`), `EventKind`, `FindingKind`, `ActionKind`, time, RNG.    |
| `sda-pal`             | New `MdmProvider` trait + per-OS implementations (§ 4).                                       |
| `sda-event-bus`       | Pub-sub for posture snapshots, evidence records, vitals.                                      |
| `sda-comms`           | Outbound `Mdm*Result` / `MdmRecoveryKeyEscrowed` frames; inbound `SignedActionJob` (via `sda-device-control`'s router). |
| `sda-device-control`  | **Signed-job validation reuse.** All MDM commands flow through `SignedActionJob` and the existing 10-step validator in [`device-control/PROPOSAL.md` § 10.3](../device-control/PROPOSAL.md#103-signed-job-validation-10-step-checklist). No separate command channel. |
| `sda-posture`         | Compliance triggers — `PostureSnapshot` events drive the auto-remediation supervisor.         |

### 3.2 Sub-modules

The crate is organised as a single binary entry point
(`sda-mdm::Module`) plus seven sub-modules. Every sub-module is
independently feature-flagged through `modules.mdm.<name>.enabled`.

| Sub-module          | File                       | Responsibility                                                                                           |
|---------------------|----------------------------|-----------------------------------------------------------------------------------------------------------|
| `wipe`              | `src/wipe.rs`              | Per-OS remote wipe: crypto-shred volume / recovery key, then OS factory reset.                            |
| `lock`              | `src/lock.rs`              | Per-OS remote lock: lock screen + custom credential-provider message.                                     |
| `lost_mode`         | `src/lost_mode.rs`         | Agent enters a locked display state with custom tenant message; reports last-known location via IP geolocation. |
| `recovery_key`      | `src/recovery_key.rs`      | BitLocker / FileVault / LUKS recovery key escrow to the control-plane privacy-vault.                       |
| `os_patch`          | `src/os_patch.rs`          | Windows Update / macOS softwareupdate / Linux unattended-upgrades / dnf-automatic / zypper patch orchestration. |
| `config_profile`    | `src/config_profile.rs`    | Declarative configuration enforcement: password policy, screen lock, Bluetooth / camera / Wi-Fi.           |
| `auto_remediate`    | `src/auto_remediate.rs`    | Subscribes to `sda-posture` snapshots; on FDE-off / firewall-off / screen-lock-off dispatches a self-signed local job. |

### 3.3 `wipe.rs`

Per-OS remote wipe. The agent never deletes user data byte-by-byte —
it crypto-shreds (destroys the volume / recovery key) and then
triggers the OS factory reset path. This is fast, irrecoverable
(provided the key was the only copy), and matches what every modern
MDM vendor does.

| OS      | Step 1 (crypto-shred)                                                                                            | Step 2 (OS factory reset)                                                                          |
|---------|-------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------|
| Windows | `manage-bde -forcerecovery C:` followed by `manage-bde -off C:` to destroy the BitLocker FVEK, then overwrite recovery key escrow. | `systemreset.exe /factoryreset /quiet` — fully unattended factory reset.                            |
| macOS   | `fdesetup removerecovery -personal` to destroy the FileVault personal recovery key; `srm` over `/private/var/db/CryptoTokenKit/*`. | "Erase All Content and Settings" via `obliterate` API on Apple Silicon; `diskutil eraseDisk` on Intel. |
| Linux   | `cryptsetup luksErase /dev/<root>` to destroy the LUKS master key; `dd if=/dev/urandom of=/dev/<root> bs=1M count=10`. | `systemctl --force --force reboot` after key destruction; the next boot fails to unlock and the OS is unrecoverable. |

Wipe is **dual-control by construction** — see § 6. Wipe always emits
an `MdmWipeResult` *before* the irreversible step so the control
plane has audit evidence even if the device never boots again.

### 3.4 `lock.rs`

Per-OS remote lock. Lock is the lightest action in the module: it
puts the device into the standard OS lock screen with a tenant
message visible to anyone with physical access. Lock is **reversible**
— a subsequent unlock command (or a successful user login) clears
the lock.

| OS      | Lock mechanism                                                                                                              |
|---------|------------------------------------------------------------------------------------------------------------------------------|
| Windows | `user32::LockWorkStation()` + write tenant message to the credential-provider tile via `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background`. |
| macOS   | `/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession -suspend` + post `NSDistributedNotificationCenter` "com.apple.screenIsLocked" with the message. |
| Linux   | `loginctl lock-sessions` + Plymouth-rendered "tenant lock screen" via a one-shot systemd unit `sda-mdm-lock.service`.        |

### 3.5 `lost_mode.rs`

Lost mode is a *long-running locked display* with two extras over
plain `lock.rs`:

1. The lock screen runs full-screen with the tenant-configured
   message and tenant contact details. The user cannot bypass it
   without a tenant-issued unlock token.
2. The agent reports its last-known location on every successful
   network reconnect. Location uses **IP geolocation only** (against
   the control-plane's GeoIP database) — no GPS hardware required,
   no user-tracking permission prompt, no platform-specific Location
   Services entitlement.

Lost mode is **reversible from the dashboard**. The
`MdmLostModeExited` event is emitted on the same evidence chain as
`MdmLostModeEntered`.

### 3.6 `recovery_key.rs`

Recovery key escrow. The agent escrows the recovery key for the
local disk-encryption stack to the control-plane privacy-vault. The
key is **never stored in plaintext anywhere except in transit through
the privacy-vault's per-tenant encryption boundary** — see § 6.

| OS      | Recovery key source                                                                                                                                 |
|---------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| Windows | `manage-bde -protectors -get C: -type RecoveryPassword` — yields the 48-digit BitLocker numerical recovery password.                                |
| macOS   | `fdesetup showrecoverykey` (after the agent re-derives one) — yields the FileVault personal recovery key (HRK).                                       |
| Linux   | `cryptsetup luksDump --dump-master-key /dev/<root>` (privileged) or LUKS keyslot 7 reserved for SN360-escrowed recovery passphrase generated on enrolment. |

Escrow is **one-time per boot** (not recurring) and produces an
`MdmRecoveryKeyEscrowed` event with `RecoveryKeyPayload` (encrypted
under the tenant key — see § 6) attached.

### 3.7 `os_patch.rs`

OS patch orchestration wraps native tools. All patch operations are
gated by maintenance windows
([`device-control/PROPOSAL.md` § 11](../device-control/PROPOSAL.md#11-agent-configuration-extension))
and produce an `MdmOsUpdateResult` event with a captured installer
log hash + exit code.

| OS      | Scan                                                                       | Install                                                                          | Notes                                                                                                |
|---------|----------------------------------------------------------------------------|----------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| Windows | `UsoClient StartScan`; PowerShell `Get-WUList` from `PSWindowsUpdate`.      | PowerShell `Install-WindowsUpdate -AcceptAll -AutoReboot:$false` from `PSWindowsUpdate`. | `auto_install_security: true` ⇒ `-Category 'Security Updates'`; feature updates require approval.    |
| macOS   | `softwareupdate --list`.                                                    | `softwareupdate --install --all --restart` or `softwareupdate --install --recommended`. | `auto_install_security: true` ⇒ `--recommended`; `auto_install_all: true` ⇒ `--all`.                  |
| Linux   | `apt list --upgradable`; `dnf check-update`; `zypper list-patches`.        | `unattended-upgrades --debug` (Debian/Ubuntu); `dnf-automatic` config (Fedora/RHEL); `zypper patch -y` (SUSE). | Auto-detect package manager via `sda-pal::PackageManager::detect()`.                                  |

Patch operations are **power-aware** — when on battery and
`PowerMonitor::current_profile()` reports `BatterySaver`, the patch
job is deferred to the next AC-connected window.

### 3.8 `config_profile.rs`

Declarative configuration enforcement. Profiles are signed
(Ed25519, same path as Device Control's signed catalogue manifest)
and applied atomically.

| OS      | Mechanism                                                                                                                                                |
|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| Windows | Group Policy via registry writes under `HKLM\SOFTWARE\Policies\Microsoft\Windows\*`; passwords under `LSA\Notification Packages`; Bluetooth under `Bluetooth Disable Inbound File Transfer`. |
| macOS   | `/usr/bin/profiles install -path=<profile.mobileconfig>` (legacy) or DDM payload via `profiles -D` / `mdmclient` (Sequoia+). Password policy via `pwpolicy`. |
| Linux   | `dconf write` under `/org/gnome/desktop/lockdown/*` and `/org/gnome/desktop/screensaver/*`; polkit drop-in under `/etc/polkit-1/rules.d/`; `pam_pwquality.conf` for password policy. |

Supported policy classes:

- Password policy — `min_length`, `require_complexity`,
  `max_age_days`, `max_attempts`, `lockout_minutes`.
- Screen lock — `timeout_secs`, `require_password_on_resume`.
- Bluetooth — `allow` / `audit` / `block`.
- Camera — `allow` / `audit` / `block`.
- Wi-Fi restrictions — `allowed_ssids[]`, `block_open_networks`.

Tampered profiles are rejected at the signature check — there is no
"warn and continue" path.

### 3.9 `auto_remediate.rs`

The auto-remediation supervisor is the killer feature. It subscribes
to `sda-posture` snapshots
([`device-control/ARCHITECTURE.md` § 1](../device-control/ARCHITECTURE.md#1-crate-map))
and, when one of the configured posture conditions reads "off",
dispatches the corresponding fix as a **self-signed local job** —
*no control-plane round-trip*.

| Posture signal                              | Fix dispatched                                                  |
|---------------------------------------------|------------------------------------------------------------------|
| `disk_encryption == "off"` and `modules.mdm.auto_remediate.disk_encryption == true` | `enable_disk_encryption` via `MdmProvider::enable_disk_encryption()`. |
| `firewall == "off"` and `modules.mdm.auto_remediate.firewall == true`               | `enable_firewall` via `MdmProvider::enable_firewall()`.               |
| `screen_lock == "off"` and `modules.mdm.auto_remediate.screen_lock == true`         | `set_screen_lock(timeout_secs)` via `MdmProvider::set_screen_lock`.    |

Self-signed local jobs are validated against an **agent-local
ephemeral key** generated at enrolment and rotated on every
configuration push. The control-plane signing key is *not* used for
local jobs; the privilege boundary is the local OS, not the network.

Every auto-remediation produces an `MdmAutoRemediationResult` event
on the standard evidence chain. If the local remediation fails, the
supervisor falls back to emitting a `FindingKind` (FDE off, firewall
off, screen-lock off) on the standard finding stream so the
control-plane can recommend a human-driven path.

---

## 4. PAL additions

`sda-pal` exposes a new `MdmProvider` trait. The trait surface is
intentionally narrow — every method maps directly to one piece of
the customer-facing examples in § 2.2.

```rust
pub trait MdmProvider: Send + Sync {
    fn wipe(&self, opts: &WipeOpts) -> Result<WipeOutcome>;
    fn lock(&self, message: &str) -> Result<()>;
    fn escrow_recovery_key(&self) -> Result<RecoveryKeyPayload>;
    fn install_os_updates(&self, opts: &OsUpdateOpts) -> Result<OsUpdateOutcome>;
    fn apply_config_profile(&self, profile: &SignedConfigProfile) -> Result<()>;
    fn enable_disk_encryption(&self) -> Result<EncryptionOutcome>;
    fn enable_firewall(&self) -> Result<()>;
    fn set_screen_lock(&self, timeout_secs: u32) -> Result<()>;
    fn enter_lost_mode(&self, message: &str) -> Result<()>;
    fn exit_lost_mode(&self) -> Result<()>;
}
```

### 4.1 Per-OS implementation matrix

| Method                       | Windows                                                                  | macOS                                                                     | Linux                                                                       |
|------------------------------|--------------------------------------------------------------------------|---------------------------------------------------------------------------|------------------------------------------------------------------------------|
| `wipe`                       | `manage-bde` + `systemreset.exe /factoryreset`.                          | `fdesetup removerecovery` + `obliterate` / `diskutil eraseDisk`.           | `cryptsetup luksErase` + `dd` over header + forced reboot.                   |
| `lock`                       | `user32::LockWorkStation()` + credential-provider tile message.          | `CGSession -suspend` + `NSDistributedNotificationCenter` post.             | `loginctl lock-sessions` + Plymouth one-shot unit.                           |
| `escrow_recovery_key`        | `manage-bde -protectors -get C: -type RecoveryPassword`.                 | `fdesetup showrecoverykey`.                                                | `cryptsetup luksDump` (privileged) or pre-provisioned SN360 keyslot 7.       |
| `install_os_updates`         | `PSWindowsUpdate` PowerShell module + `UsoClient StartScan`.             | `softwareupdate --install --all` (or `--recommended` for security only).   | `unattended-upgrades` / `dnf-automatic` / `zypper patch` (auto-detect).      |
| `apply_config_profile`       | Registry writes under `HKLM\SOFTWARE\Policies\Microsoft\Windows\*`.       | `profiles install -path=…` (legacy) or DDM via `mdmclient` (Sequoia+).     | `dconf write` + polkit drop-in + `pam_pwquality.conf`.                       |
| `enable_disk_encryption`     | `manage-bde -on C: -RecoveryPassword` (TPM-backed; recovery key escrowed). | `fdesetup enable -user $user -keychain` + capture personal recovery key.   | `cryptsetup luksFormat` on staging volume + migration (only on supported FS). |
| `enable_firewall`            | `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True`.    | `socketfilterfw --setglobalstate on` + `--setblockall off`.                | `firewall-cmd --set-default-zone=public` / `nft add table inet filter`.       |
| `set_screen_lock`            | `HKCU\Control Panel\Desktop` `ScreenSaveTimeOut` + `ScreenSaverIsSecure`. | `defaults -currentHost write com.apple.screensaver idleTime <secs>`.       | `dconf write /org/gnome/desktop/session/idle-delay 'uint32 <secs>'`.          |
| `enter_lost_mode`            | Persistent lock screen via custom credential provider + `systemd-shutdown` lock-on-resume. | LaunchDaemon-driven full-screen lock view + `caffeinate` to prevent sleep. | Plymouth full-screen splash + `loginctl lock-sessions` looped via systemd unit. |
| `exit_lost_mode`             | Disable persistent lock screen + restart `Winlogon`.                      | Unload LaunchDaemon + send `com.apple.screenIsUnlocked` notification.      | Stop systemd unit + `loginctl unlock-sessions`.                              |

All `MdmProvider` implementations run inside SDA's existing
privilege-separated module process boundary
([`device-control/PROPOSAL.md` § 14.1](../device-control/PROPOSAL.md#141-threats-and-controls)).
No new privileged process is introduced by `sda-mdm`.

The full per-OS implementation detail (including registry paths,
profile XML structure, dconf schemas, and PowerShell module
provisioning) lives in
[`ARCHITECTURE.md` § 3](./ARCHITECTURE.md#3-data-flow-diagrams).

---

## 5. Configuration

`AgentConfig` gains a `modules.mdm` section. **The module defaults
to `enabled: true` with `auto_remediate.*` on** — this is the key
differentiator versus Device Control, which defaults to off.

```yaml
modules:
  mdm:
    enabled: true  # DEFAULT ON — this is the key differentiator
    auto_remediate:
      disk_encryption: true
      firewall: true
      screen_lock: true
      screen_lock_timeout_secs: 300
    os_patch:
      enabled: true
      auto_install_security: true  # security patches auto-install
      auto_install_all: false      # feature updates require approval
    recovery_key_escrow:
      enabled: true
    lost_mode:
      message: "This device belongs to {tenant_name}. Please contact {tenant_email}."
    config_profiles:
      password_policy:
        min_length: 8
        require_complexity: true
        max_age_days: 90
      bluetooth: "audit"    # allow | audit | block
      camera: "allow"
```

Tenant-scoped overrides are pushed via the TRDS bundle path
([`device-control/ARCHITECTURE.md` § 10b.1](../device-control/ARCHITECTURE.md#10b1-usbpolicysupervisor--devicepolicystore))
so a tenant administrator can flip `auto_remediate.disk_encryption`
to `false` (or push a tighter `bluetooth: "block"`) without an agent
release.

The full schema reference lives in
[`docs/configuration-reference.md`](../configuration-reference.md)
when the corresponding code lands.

---

## 6. Security model

### 6.1 Threats and controls

| Threat                                                            | Control                                                                                                  |
|-------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| Compromised control-plane account issues malicious wipe           | **Dual-control approval (two approvers) + Ed25519-signed job + per-action allow-list + maintenance-window enforcement**. Wipe is the only ActionKind that requires dual-control by construction. |
| Recovery key leakage in transit                                    | Recovery keys encrypted with the **tenant-scoped key** in `sda-mdm::recovery_key` before transmission; stored in the privacy-vault with crypto-shredding on tenant offboarding. |
| Recovery key leakage at rest                                       | Keys live in the privacy-vault behind the existing deanonymisation audit path; retrieval is role-gated and audit-logged.   |
| Posture auto-remediation triggers user disruption                  | Auto-remediation **only** flips FDE, firewall, screen lock — never installs software, never reconfigures applications. Each fix is reversible from the dashboard. |
| Server compromise pushes tampered config profile                   | Configuration profiles are signed (Ed25519, same path as Device Control's signed catalogue manifest); tampered profiles rejected. |
| Lost-mode message used for harassment                              | Lost-mode message is tenant-templated; the agent does not surface free-form operator text. Exiting lost mode is logged to the same evidence chain. |
| OS patch installs break user's workflow                            | Patch installs gated by `modules.device_control.windows` (maintenance windows + quiet hours); battery-aware deferral; rollback through the same OS update path. |
| Local self-signed remediation key abused                            | Local key is **ephemeral** — generated at enrolment, rotated on every config push, **never accepted by the control plane**. It can only sign jobs originating from inside the agent's own process. |
| Multi-tenant data leakage in escrow                                 | Existing Postgres RLS in the privacy-vault + per-tenant signing keys + agent-side `tenant_id` validation in the recovery key payload header. |

### 6.2 Wipe — dual-control

Wipe is the only `ActionKind` in `sda-mdm` that requires dual-control
by construction. Concretely:

1. The control plane's `Approval Service` requires two distinct
   approvers (different `user_id`s) before signing a wipe job.
2. The signed wipe job carries **two** Ed25519 signatures over the
   canonical encoding, each with its own `key_id`. The agent's
   signed-job validator (see
   [`device-control/PROPOSAL.md` § 10.3](../device-control/PROPOSAL.md#103-signed-job-validation-10-step-checklist))
   gains an explicit check: `if action == RemoteWipe && signatures.len() < 2 ⇒ JobRefused`.
3. The agent emits `MdmWipeResult { status: Refused, reason: "single_signature" }` and the job dies.

### 6.3 Recovery key escrow — encryption envelope

Recovery keys never travel in cleartext. The envelope is:

```
RecoveryKeyPayload {
    tenant_id: Uuid,
    device_id: Uuid,
    key_type: "BitLocker" | "FileVault" | "LUKS",
    ciphertext: Vec<u8>,    // ChaCha20-Poly1305 over the raw key,
                            // key = HKDF(tenant_master_key, "sda-mdm-recovery-key", device_id)
    nonce: [u8; 12],
    escrowed_at: DateTime<Utc>,
    signature: Vec<u8>,     // Ed25519 by the agent's evidence key over the envelope.
    key_id: String,
}
```

The tenant master key never leaves the privacy-vault; only the agent
holds a per-device key derived through HKDF on enrolment.

### 6.4 Auto-remediation — local-only

Auto-remediation fixes are LOCAL-ONLY: the agent fixes its own
device without waiting for server approval, because FDE-off /
firewall-off / screen-lock-off are critical security gaps that the
device should not survive crossing. Specifically:

- The signed-job validator's "is it an MDM auto-remediation?" arm
  accepts the local ephemeral key in addition to the control-plane
  rotation set.
- The job's `recommendation_id` is `None`.
- The `EvidenceRecord` carries `auto_remediated: true` so the
  control plane can distinguish operator-driven fixes from agent
  self-fixes in the audit log.

### 6.5 Lost mode — reversibility

Lost mode is reversible from the dashboard. The reverse path is:

1. Operator clicks "Exit lost mode" in the dashboard.
2. Control plane issues an `ExitLostMode` SignedActionJob.
3. Agent validates, calls `MdmProvider::exit_lost_mode()`.
4. Agent emits `MdmLostModeExited` on the evidence chain.

No data is destroyed in lost mode — only display state changes.

---

## 7. Control-plane surface

> All services in this section live in
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform/blob/main/docs/desktop-mdm/PROPOSAL.md),
> not in this repository. They are listed for cross-reference only.

| Service                  | Purpose                                                                                                |
|--------------------------|--------------------------------------------------------------------------------------------------------|
| `services/desktop-mdm`   | Command dispatch (wipe / lock / lost mode), recovery-key vault integration, OS patch status aggregation, config-profile distribution. |
| `services/risk-engine`   | New MDM recommendation rules: `disk_encryption_off`, `firewall_off`, `screen_lock_off`, `recovery_key_not_escrowed`, `os_patch_overdue`, `device_lost`. |
| `services/smi-engine`    | New `mdm_compliance` sub-score (§ 12).                                                                  |
| `services/approval-service` | Dual-control approval enforcement for wipe ActionKind.                                              |
| `services/evidence-vault`  | Append-only Ed25519 chain for every MDM action.                                                       |
| Privacy-vault              | Recovery-key storage behind the existing deanonymisation audit path.                                  |
| `sn360-dashboard-plugin`   | MDM status page, one-click action buttons, recovery-key viewer (role-gated, audit-logged).            |

The corresponding control-plane proposal is at
[`sn360-security-platform/docs/desktop-mdm/PROPOSAL.md`](https://github.com/kennguy3n/sn360-security-platform/blob/main/docs/desktop-mdm/PROPOSAL.md).

---

## 8. Performance

### 8.1 Rules

1. **No regression on existing budgets.** Idle RSS < 15 MB, idle CPU
   < 0.1 %, FIM scan peak < 3 %, binary < 7 MB. `sda-mdm` adds < 1 MB
   to the agent binary.
2. **Lazy module loading.** Disabled sub-modules consume zero
   threads, zero subscriptions, zero allocations beyond their static
   struct. The auto-remediation supervisor consumes one bus
   subscription regardless of whether any sub-module is enabled.
3. **No new timers.** Auto-remediation checks piggyback on existing
   `sda-posture` snapshot intervals (default 300 s). The OS patch
   scheduler reuses `sda-software`'s maintenance-window timer.
4. **Power-aware.** OS patch jobs defer on battery via
   `PowerMonitor::current_profile()`. Auto-remediation does not — a
   posture gap is a posture gap regardless of power state.
5. **One-time per boot.** Recovery key escrow runs once after the
   first successful comms handshake of each boot, not on every
   heartbeat. Subsequent escrow only re-runs if the recovery key
   rotates.

### 8.2 Event priorities

| EventKind                       | Priority   | Rationale                                                              |
|---------------------------------|------------|------------------------------------------------------------------------|
| `MdmWipeResult`                 | High       | Audit-critical; precedes an irreversible local action.                  |
| `MdmLockResult`                 | High       | Closes a control-plane job; must not be lost.                           |
| `MdmLostModeEntered/Exited`     | High       | User-visible; must not be lost.                                          |
| `MdmRecoveryKeyEscrowed`        | High       | Audit-critical; gates "recovery key not escrowed" finding.              |
| `MdmOsUpdateResult`             | Normal     | Closes a job, but the OS reports patch state independently on next scan. |
| `MdmConfigProfileApplied`       | Normal     | Closes a job.                                                            |
| `MdmAutoRemediationResult`      | High       | Local-only; the only audit trail for a self-driven fix.                  |

These priorities flow into `sda-event-bus`'s existing priority queue
without any new infrastructure.

---

## 9. Evidence and audit

Every MDM action (wipe, lock, unlock, escrow, patch install, config
profile apply, auto-remediate) produces an `EvidenceRecord` via the
existing chain
([`device-control/PROPOSAL.md` § 16](../device-control/PROPOSAL.md#16-evidence-and-audit-model)).
The `EvidenceRecord` schema is unchanged; the new content rides on
the existing `action` field.

### 9.1 New `FindingKind` variants

```rust
pub enum FindingKind {
    // ... existing variants ...
    DiskEncryptionOff,
    FirewallOff,
    ScreenLockOff,
    OsPatchOverdue,
    RecoveryKeyNotEscrowed,
    DeviceLost,
}
```

### 9.2 New `ActionKind` variants

```rust
pub enum ActionKind {
    // ... existing variants ...
    RemoteWipe,
    RemoteLock,
    EnterLostMode,
    ExitLostMode,
    EscrowRecoveryKey,
    InstallOsUpdate,
    ApplyConfigProfile,
    EnableDiskEncryption,
    EnableFirewall,
    SetScreenLock,
}
```

`RemoteWipe` is the only variant that requires dual-control by
construction (§ 6.2). The agent enforces this regardless of what the
control plane asks for.

---

## 10. MessageType variants

`sda-comms::MessageType` gains the following variants. Each variant
is exhaustively prefixed and validated in the existing protocol
encoder
([`crates/sda-comms/src/protocol.rs`](../../crates/sda-comms/src/protocol.rs)):

```rust
pub enum MessageType {
    // ... existing variants ...
    MdmWipeResult,
    MdmLockResult,
    MdmLostModeEntered,
    MdmLostModeExited,
    MdmRecoveryKeyEscrowed,
    MdmOsUpdateResult,
    MdmConfigProfileApplied,
    MdmAutoRemediationResult,
}
```

Per the existing repo invariant, every new `MessageType` variant
must also have an explicit arm in `WazuhMessage::encode_body()`
(see
[`crates/sda-comms/src/protocol.rs`](../../crates/sda-comms/src/protocol.rs))
when the optional `legacy-siem` Cargo feature is on; fall-through to
the catch-all is forbidden.

---

## 11. NATS subjects

On the control-plane side, the existing NATS topology gains a
`device_control.mdm.*` sub-tree (the MDM sub-tree lives under
`device_control.*` so existing consumers, dashboards, and
ISM/template wiring carry over without code changes):

```
device_control.mdm.wipe.<tid>.<did>
device_control.mdm.lock.<tid>.<did>
device_control.mdm.lost_mode.<tid>.<did>
device_control.mdm.recovery_key.<tid>.<did>
device_control.mdm.os_update.<tid>.<did>
device_control.mdm.config_profile.<tid>.<did>
device_control.mdm.auto_remediation.<tid>.<did>
```

The agent does not connect to NATS directly; the Agent Gateway (in
`sn360-security-platform`) translates between the agent's native
protocol frames and the NATS topology.

---

## 12. SMI sub-scores

The Security Maturity Index already exists at the SN360 control-plane
tier
([`device-control/PROPOSAL.md` § 13](../device-control/PROPOSAL.md#13-smi-scoring-model)).
Desktop MDM feeds it one new sub-score:

| Sub-score          | Source                                                                                              | Move on…                                                                                                          |
|--------------------|------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| `mdm_compliance`   | FDE on + firewall on + screen-lock on + recovery-key-escrowed + OS-patches-current.                  | All five conditions met. Formula: `clamp(100 - 10*fde_off - 10*fw_off - 10*sl_off - 5*rk_missing - 5*patch_overdue)`. |

`mdm_compliance` feeds into the existing SMI engine alongside the
six Device Control sub-scores. The composite score is unchanged in
structure; the new sub-score is averaged in with the others.

Worked example — finding to SMI:

```
Finding: DiskEncryptionOff (severity High)
  -> Local auto-remediation: EnableDiskEncryption
  -> ActionResult Success + recovery key escrowed
  -> EvidenceRecord written (auto_remediated: true)
  -> SMI sub-score "mdm_compliance": move +10 points (fde_off cleared).
```

---

## 13. Competitive differentiation

| Vendor                      | Price (typical SME)                            | Enrollment friction                                                              | IT admin overhead                                              |
|-----------------------------|------------------------------------------------|----------------------------------------------------------------------------------|----------------------------------------------------------------|
| **Microsoft Intune**        | $6–$12 / user / mo (Microsoft 365 E3 / EMS).   | Azure AD join + MDM autopilot + per-tenant Apple Push cert + ADE / DEP tokens.    | Per-policy authoring, per-app deployment, per-device baseline.  |
| **Jamf Pro**                | $4–$12 / device / mo.                          | Apple Push cert + ADE / DEP + Jamf Cloud tenancy.                                  | Configuration profile authoring + Smart Group management.       |
| **Kandji**                  | $5+ / device / mo.                             | Apple Push cert + ADE.                                                              | Library item authoring + assignment management.                  |
| **ShieldNet Desktop MDM**   | **$0 incremental cost (bundled in SDA).**      | **Zero — SDA already runs on every laptop.** No Push cert, no per-device license. | **None for common-case fixes** (auto-remediation handles them). |

The cost story is simple — desktops are already running SDA, and
SDA's existing comms / signing / evidence infrastructure covers
everything Desktop MDM needs. There is no separate billable
component, no Apple Push certificate, no per-device license, no
new server to deploy.

The "no IT admin" angle is more nuanced. It is **not** "Desktop MDM
has no admin surface" — there is a dashboard, there are policies,
there are approval workflows. It is "the common-case fixes
(FDE / firewall / screen lock) require zero admin involvement
because auto-remediation handles them" plus "every finding is
plain-English with a one-click fix" plus "MDM compliance feeds the
SMI score the admin already cares about". The admin still sees
everything in a dashboard; they just don't have to *do* anything for
the 80 % case.

---

## 14. Phasing

### 14.1 Phase summary

| Phase | Theme                                                          | Window         | Key deliverables                                                                                       |
|-------|----------------------------------------------------------------|----------------|---------------------------------------------------------------------------------------------------------|
| M1    | Auto-remediation + recovery key escrow + OS patch              | 8–10 weeks     | "80 % of MDM value for 20 % of effort": FDE / firewall / screen-lock auto-remediation, recovery key escrow, OS patch orchestration. |
| M2    | Remote wipe + remote lock + lost mode                          | 6–8 weeks      | Dual-control wipe, lock, lost mode with last-known location.                                            |
| M3    | Declarative configuration profiles                             | 6–8 weeks      | Password policy, screen lock, Bluetooth, camera, Wi-Fi enforcement on Windows / macOS / Linux.          |
| M4    | Dashboard UI + one-click actions + recovery key viewer         | 4–6 weeks      | MDM status page, role-gated recovery key viewer, OS patch status, one-click "patch all".               |

### 14.2 Phase M1 deliverables

- `sda-pal::MdmProvider` trait + per-OS implementations for disk
  encryption, firewall, screen lock.
- `sda-mdm` crate scaffold + auto-remediation supervisor.
- Recovery key escrow on Windows / macOS / Linux.
- OS patch orchestration on Windows / macOS / Linux.
- New `FindingKind` + `ActionKind` variants in `sda-core`.
- New `MessageType` variants in `sda-comms`.
- ⚙️ Control-plane: `services/desktop-mdm` scaffold, risk-engine MDM
  rules, SMI `mdm_compliance` sub-score.
- Phase M1 E2E suite (`make e2e-mdm`).

### 14.3 Phase M2 deliverables

- Remote wipe — per-OS crypto-shred + OS reset.
- Remote lock — per-OS lock screen with message.
- Lost mode — agent-side locked display + IP-geolocation
  last-known-location.
- ⚙️ Control-plane: command dispatch endpoints, dual-control approval
  integration for wipe.
- Phase M2 E2E suite.

### 14.4 Phase M3 deliverables

- Declarative configuration profile schema + signed manifest.
- Per-OS enforcement (registry / GPO, `profiles` CLI, dconf /
  polkit).
- Config profile push via TRDS signed bundle.
- Phase M3 E2E suite.

### 14.5 Phase M4 deliverables

- Dashboard MDM status page.
- One-click wipe / lock / unlock buttons.
- Recovery key viewer (role-gated, audit-logged).
- OS patch status + "patch all" action.
- Phase M4 E2E suite.

---

## 15. Risk register

| #  | Risk                                                              | Severity   | Mitigation                                                                                                                  |
|----|-------------------------------------------------------------------|------------|------------------------------------------------------------------------------------------------------------------------------|
| 1  | Accidental wipe takes down a user's primary device                 | Critical   | Dual-control approval (§ 6.2) — single-signature wipe jobs are refused by the agent regardless of control-plane intent.       |
| 2  | Recovery key leakage in transit                                    | Critical   | ChaCha20-Poly1305 envelope with tenant-derived per-device key (§ 6.3); no plaintext key ever leaves the device.               |
| 3  | Recovery key leakage at rest                                       | Critical   | Privacy-vault storage + role-gated retrieval + audit log; crypto-shredding on tenant offboarding.                              |
| 4  | Posture auto-remediation triggers user disruption                  | High       | Auto-remediation scope is narrow (FDE / firewall / screen lock only); every fix reversible; every fix logged.                  |
| 5  | OS patch installs break user's workflow                            | High       | Maintenance-window gating + battery-aware deferral + rollback path through the OS-native uninstaller.                          |
| 6  | Local self-signed remediation key abused                            | High       | Local key is ephemeral, rotated on every config push, never trusted by the control plane; only signs jobs originating in-process. |
| 7  | Tampered configuration profile pushed to agents                    | High       | Profiles are Ed25519-signed; tampered profiles rejected at signature check; no warn-and-continue path.                         |
| 8  | Lost mode used for harassment of a returned device                 | Medium     | Lost-mode message is tenant-templated; agent does not surface free-form operator text; exiting lost mode is logged.            |
| 9  | Auto-remediation feedback loop (agent re-enables FDE every snapshot) | Medium     | Auto-remediation is debounced on the local job state machine — `EnableDiskEncryption` is rejected if a successful one ran in the last 24 h. |
| 10 | Platform-specific inconsistency                                    | Medium     | `MdmProvider` trait enforces a uniform contract; per-OS implementations tested via `make e2e-{linux,macos,windows}-mdm`.       |
| 11 | OS factory reset incomplete on tampered firmware                   | Medium     | Crypto-shred is the primary guarantee; OS reset is the secondary cleanup. Even on a tampered firmware path, the data is unreachable. |
| 12 | Dual-control bypass via single approver with two devices           | Medium     | Approval-service enforces distinct `user_id`s, not distinct devices; SSO + MFA gating closes the loop on the control plane.    |

---
