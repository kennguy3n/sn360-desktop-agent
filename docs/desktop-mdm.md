# Desktop Mobile Device Management (Desktop MDM)

The SN360 Desktop Agent doubles as the MDM enforcement point for
the device it runs on — no separate MDM enrolment, no Apple Push
certificates, no per-device MDM licence cost, no IT-admin
enrolment ceremony.

Desktop MDM is delivered as a single agent crate, `sda-mdm`, plus
a thin control-plane companion (in
[`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)).
This document covers the agent side.

For the underlying signed-job validation see
[`device-control.md` § 4](./device-control.md#4-signed-job-lifecycle).
For the YAML schema see
[`configuration-reference.md`](./configuration-reference.md).

---

## Table of contents

1. [Product loop](#1-product-loop)
2. [Sub-modules](#2-sub-modules)
3. [Remote wipe](#3-remote-wipe)
4. [Remote lock and lost mode](#4-remote-lock-and-lost-mode)
5. [Recovery-key escrow](#5-recovery-key-escrow)
6. [OS patch orchestration](#6-os-patch-orchestration)
7. [Configuration profiles](#7-configuration-profiles)
8. [Auto-remediation](#8-auto-remediation)
9. [Security model](#9-security-model)
10. [Resource budgets](#10-resource-budgets)
11. [Relationship to Device Control](#11-relationship-to-device-control)

---

## 1. Product loop

> Every laptop is managed, compliant, and recoverable — without an
> IT admin babysitting it.

The same `found → fix → evidence → SMI` loop as Device Control,
biased toward auto-fixing the common cases without operator
involvement:

| # | Example | Plain-English risk | Auto / one-click fix |
|---|---|---|---|
| 1 | 3 laptops have disk encryption off | "3 laptops have disk encryption turned off — data at risk if lost." | Auto-enable BitLocker / FileVault / LUKS on next boot; escrow recovery key |
| 2 | 2 devices missing for 14+ days | "2 devices haven't checked in for 14+ days — possibly lost." | Remote lock + lost mode with custom message on next contact |
| 3 | 8 devices have pending OS security updates | "8 devices have pending OS security patches — known CVEs apply." | Auto-install during the next maintenance window |
| 4 | Recovery keys not escrowed for 5 devices | "5 devices have encrypted disks but no escrowed recovery key — locked-out risk." | Auto-escrow on next heartbeat |
| 5 | 1 device reported stolen | "1 device reported stolen — wipe before the attacker boots it." | Remote wipe with dual-control approval |

Desktop MDM is **default-on**. Unlike most Device Control modules,
`modules.mdm.enabled` defaults to `true` and the auto-remediation
toggles default to `true`. The product cost of the alternative —
disk-encryption-off endpoints sitting in the field for weeks until
an operator notices — is unacceptable.

---

## 2. Sub-modules

`sda-mdm` is a single crate split into seven independently
feature-flagged sub-modules:

| Sub-module | Responsibility |
|---|---|
| `wipe` | Per-OS remote wipe — crypto-shred volume / recovery key, then OS factory reset |
| `lock` | Per-OS remote lock — lock screen + custom credential-provider message |
| `lost_mode` | Long-running locked display with custom message; reports last-known location via IP geolocation |
| `recovery_key` | BitLocker / FileVault / LUKS recovery key escrow to the control-plane privacy vault |
| `os_patch` | Windows Update / `softwareupdate` / `unattended-upgrades` / `dnf-automatic` / `zypper` patch orchestration |
| `config_profile` | Declarative configuration enforcement: password policy, screen lock, Bluetooth / camera / Wi-Fi |
| `auto_remediate` | Subscribes to posture snapshots; on FDE-off / firewall-off / screen-lock-off dispatches a self-signed local job |

### 2.1 `MdmProvider` PAL trait

A single PAL trait — `MdmProvider` — abstracts the per-OS
mechanisms; per-OS implementations live in `sda-pal::mdm::{windows,
macos, linux}`.

```rust
pub trait MdmProvider: Send + Sync {
    fn wipe(&self, mode: WipeMode) -> Result<WipeOutcome>;
    fn lock(&self, message: &LockMessage) -> Result<()>;
    fn enter_lost_mode(&self, banner: &LostBanner) -> Result<()>;
    fn exit_lost_mode(&self) -> Result<()>;
    fn fetch_recovery_key(&self) -> Result<RecoveryKeyPayload>;
    fn scan_os_updates(&self) -> Result<Vec<PendingUpdate>>;
    fn install_os_updates(&self, scope: UpdateScope) -> Result<UpdateOutcome>;
    fn apply_profile(&self, profile: &ConfigProfile) -> Result<ProfileOutcome>;
}
```

---

## 3. Remote wipe

Wipe is **crypto-shred + OS factory reset**, never byte-by-byte
erasure. Crypto-shred destroys the volume / recovery key and the
factory-reset path leaves the device unable to boot the previous OS.

| OS | Step 1 (crypto-shred) | Step 2 (OS factory reset) |
|---|---|---|
| Windows | `manage-bde -forcerecovery C:` + `manage-bde -off C:` to destroy the BitLocker FVEK; overwrite recovery key escrow | `systemreset.exe /factoryreset /quiet` |
| macOS | `fdesetup removerecovery -personal` to destroy the FileVault personal recovery key; `srm` over `/private/var/db/CryptoTokenKit/*` | "Erase All Content and Settings" via `obliterate` API on Apple Silicon; `diskutil eraseDisk` on Intel |
| Linux | `cryptsetup luksErase /dev/<root>` to destroy the LUKS master key; `dd if=/dev/urandom of=/dev/<root> bs=1M count=10` | `systemctl --force --force reboot`; the next boot fails to unlock and the OS is unrecoverable |

### 3.1 Dual-control

Wipe is **dual-control by construction**. The `RemoteWipe` signed
job requires **two distinct approver signatures with two distinct
`key_id`s** — the agent rejects the job with a `JobRefused
{ reason: "wipe_requires_dual_control" }` if either is missing.

### 3.2 Pre-irrevocable evidence

The agent emits `MdmWipeResult` to the control plane **before** the
irrecoverable step runs. The evidence record is durable even if the
device never boots again.

---

## 4. Remote lock and lost mode

### 4.1 Lock

Lock puts the device into the standard OS lock screen with an
optional tenant message. Lock is **reversible** — a subsequent
unlock command or a successful user login clears the lock.

| OS | Mechanism |
|---|---|
| Windows | `user32::LockWorkStation()` + write tenant message to the credential-provider tile |
| macOS | `CGSession -suspend` + `NSDistributedNotificationCenter` with the message |
| Linux | `loginctl lock-sessions` + Plymouth-rendered tenant lock screen via a one-shot systemd unit |

### 4.2 Lost mode

Lost mode is a long-running locked display with two extras:

1. The lock screen runs full-screen with the tenant-configured
   message and contact details. The user cannot bypass it without a
   tenant-issued unlock token.
2. The agent reports its last-known location on every successful
   network reconnect. Location uses **IP geolocation only** (against
   the control plane's GeoIP database). No GPS hardware required,
   no user-tracking permission prompt, no platform-specific Location
   Services entitlement.

Lost mode is **reversible from the dashboard**. The
`MdmLostModeExited` event is emitted on the same evidence chain as
`MdmLostModeEntered`.

---

## 5. Recovery-key escrow

The agent escrows the recovery key for the local disk-encryption
stack to the control-plane privacy vault. The key is **never stored
in plaintext anywhere except in transit through the privacy vault's
per-tenant encryption boundary**.

| OS | Recovery key source |
|---|---|
| Windows | `manage-bde -protectors -get C: -type RecoveryPassword` — the 48-digit BitLocker numerical recovery password |
| macOS | `fdesetup showrecoverykey` (after the agent re-derives one) — the FileVault personal recovery key |
| Linux | `cryptsetup luksDump --dump-master-key /dev/<root>` (privileged) or LUKS keyslot 7 reserved for an SN360-escrowed recovery passphrase generated on enrolment |

Escrow is **one-time per boot** (not recurring). The
`MdmRecoveryKeyEscrowed` event carries a `RecoveryKeyPayload`
encrypted under the tenant key.

---

## 6. OS patch orchestration

All patch operations are gated by maintenance windows and quiet
hours; a patch operation produces an `MdmOsUpdateResult` event with
a captured installer log hash + exit code.

| OS | Scan | Install |
|---|---|---|
| Windows | `UsoClient StartScan`; `Get-WUList` via `PSWindowsUpdate` | `Install-WindowsUpdate -AcceptAll -AutoReboot:$false`. `auto_install_security: true` ⇒ `-Category 'Security Updates'`; feature updates require approval. |
| macOS | `softwareupdate --list` | `softwareupdate --install --all --restart` or `softwareupdate --install --recommended`. `auto_install_security: true` ⇒ `--recommended`; `auto_install_all: true` ⇒ `--all`. |
| Linux | `apt list --upgradable`; `dnf check-update`; `zypper list-patches` | `unattended-upgrades --debug` (Debian / Ubuntu); `dnf-automatic` config (Fedora / RHEL); `zypper patch -y` (SUSE). Auto-detect via `PackageManager::detect()`. |

Patch operations are **power-aware**: when on battery and
`PowerMonitor::current_profile()` reports `BatterySaver`, the patch
job is deferred to the next AC-connected maintenance window.

---

## 7. Configuration profiles

Configuration profiles are declarative — they describe the desired
end state, the agent applies it idempotently. Profiles are signed
(Ed25519, same path as the Device Control catalogue manifest) and
applied atomically.

| OS | Mechanism |
|---|---|
| Windows | Group Policy via registry writes under `HKLM\SOFTWARE\Policies\Microsoft\Windows\*`; password policy via `LSA\Notification Packages` |
| macOS | `/usr/bin/profiles install -path=<profile.mobileconfig>` (legacy) or DDM payload via `profiles -D` / `mdmclient` (Sequoia+); password policy via `pwpolicy` |
| Linux | `dconf write` under `/org/gnome/desktop/lockdown/*` and `/org/gnome/desktop/screensaver/*`; polkit drop-in under `/etc/polkit-1/rules.d/`; `pam_pwquality.conf` for password policy |

Supported policy classes:

- **Password policy** — `min_length`, `require_complexity`,
  `max_age_days`, `max_attempts`, `lockout_minutes`.
- **Screen lock** — `timeout_secs`, `require_password_on_resume`.
- **Bluetooth** — `enabled`, `inbound_transfer_allowed`.
- **Camera** — `enabled`, `per_app_allow_list`.
- **Wi-Fi** — `disallowed_ssids`, `require_802_1x`.

Profiles are **versioned per tenant**; the agent reconciles the
device's current applied profile against the latest published
version on every heartbeat and on every signed
`PushConfigProfile { profile_id, version }` job.

---

## 8. Auto-remediation

The `auto_remediate` sub-module is what makes MDM "no IT admin
required". It subscribes to `PostureSnapshot` events from
`sda-posture` and dispatches a **self-signed local job** when a
posture sub-state is non-compliant:

| Trigger | Auto-fix |
|---|---|
| `disk_encryption == Off` | Enable BitLocker / FileVault / LUKS on next boot; escrow recovery key |
| `firewall == Off` | Enable `Get-NetFirewallProfile -All | Set-NetFirewallProfile -Enabled True`; `socketfilterfw --setglobalstate on`; `ufw enable` / `firewall-cmd --reload` |
| `screen_lock.timeout > N` | Apply the tenant default screen-lock policy via `apply_profile` |
| `os_patch_level == Behind { security }` | Schedule `install_os_updates(Security)` for the next maintenance window |

A self-signed local job is the same `SignedActionJob` shape used
for control-plane-initiated work, signed by an
**agent-local installation key** that the signed-job validator
recognises only when the `tenant_id` and `device_id` exactly match
the agent's own. There is no path for a local job to escalate
across devices.

---

## 9. Security model

Desktop MDM is the highest-impact module in the agent —
`RemoteWipe` is irreversible — so it inherits the strictest
security invariants:

1. **Same 10-step signed-job validation** as Device Control
   ([`device-control.md` § 4](./device-control.md#4-signed-job-lifecycle);
   also documented in `architecture.md` § 3.2).
2. **Two-of-N approver signatures for irreversible actions** —
   `RemoteWipe` requires two distinct approver Ed25519 signatures
   with two distinct `key_id`s.
3. **Pre-irrevocable evidence** — every `Mdm*Result` is published
   to the control plane before the local side effect runs.
4. **Recovery key never leaves the privacy boundary** — the
   privacy vault is the only system that can decrypt
   `RecoveryKeyPayload`; the agent only ever has the plaintext
   long enough to encrypt it under the tenant key.
5. **Locally-signed jobs cannot cross device boundaries** — the
   agent installation key is per-device and locked to
   `(tenant_id, device_id)` at sign + verify time.

The threat model is the same as the rest of the agent — see
[`security.md`](./security.md).

---

## 10. Resource budgets

Desktop MDM adds < 1 MB to the agent binary and < 2 MB to idle RSS.
Auto-remediation runs at the posture snapshot interval (default 30
minutes), so idle CPU is dominated by the posture providers, not
the MDM sub-module. Patch orchestration only runs inside
maintenance windows.

| State | Idle RSS | Idle CPU |
|---|---|---|
| `modules.mdm.enabled = true`, no remediation needed | +2 MB over baseline | +0 % over baseline |
| Auto-remediation firing (e.g. firewall enable) | +2 MB | < 0.5 % for < 1 s |
| OS patch install running | +2 MB | dominated by the underlying OS updater |

See [`benchmarks.md`](./benchmarks.md) for the full numbers.

---

## 11. Relationship to Device Control

Desktop MDM is a **sibling** module to Device Control, not a layer
on top of it. The two modules share infrastructure (`sda-pal`,
`sda-event-bus`, `sda-comms`, `sda-device-control`'s signed-job
router, `sda-posture`'s snapshots, the existing `EvidenceRecord`
chain) but ship and version independently.

- Device Control owns `Finding` / `Recommendation` /
  `SignedActionJob` for the SME-style workflows in
  [`device-control.md`](./device-control.md).
- Desktop MDM owns the `Mdm*` event family and the wipe / lock /
  lost-mode / recovery-key / OS-patch / configuration-profile
  surface.
- Both flow through the same 10-step signed-job validator (Device
  Control's), so authorisation policy lives in one place.

The crate dependency direction is `sda-mdm → sda-device-control`,
never the other way.
