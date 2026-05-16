# ShieldNet Desktop MDM — Architecture

> **Version:** 0.1 | **Date:** May 2026 | **Status:** Planning
> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)

This document is the architecture reference for the Desktop MDM
module. It is intentionally narrower than [PROPOSAL.md](./PROPOSAL.md) —
that document captures the design rationale; this one captures the
target shape of the code as it will be when Phases M1–M4 are merged.

> **Scope note:** Desktop MDM spans the agent (this repository) and
> the SN360 control plane
> ([`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform/blob/main/docs/desktop-mdm/ARCHITECTURE.md)).
> Sections 1–8 below describe agent-side shape. Section 4's NATS
> subject hierarchy and the control-plane interaction surface are
> included for cross-reference; the corresponding code lives in
> `sn360-security-platform`, not here.

---

## Table of contents

1. [Architecture diagram](#1-architecture-diagram)
2. [PAL trait design](#2-pal-trait-design)
3. [Data-flow diagrams](#3-data-flow-diagrams)
4. [Protocol extension](#4-protocol-extension)
5. [Configuration schema](#5-configuration-schema)
6. [Module startup order](#6-module-startup-order)
7. [Security model](#7-security-model)
8. [Resource budgeting](#8-resource-budgeting)
9. [Further reading](#9-further-reading)

---

## 1. Architecture diagram

`sda-mdm` slots into the existing agent architecture beside
`sda-device-control`. Inbound `SignedActionJob` frames flow through
the same router; auto-remediation rides on `sda-posture` snapshots:

```
+----------------------------------------------------------------------+
|                            sda-agent (bin)                           |
+----------------------------------------------------------------------+
|   sda-mdm                                                            |
|   +------------------------------------------------------------+     |
|   | wipe | lock | lost_mode | recovery_key | os_patch |         |     |
|   | config_profile | auto_remediate                            |     |
|   +------------------------------------------------------------+     |
|        ^                ^                          ^                 |
|        | SignedActionJob | self-signed local job   | PostureSnapshot |
|        | (control plane) | (auto-remediation)      | (sda-posture)   |
|        |                |                          |                 |
|   +----+----------------+--------------------------+-----+           |
|   |          sda-device-control::router (10-step validator)|         |
|   +--------------------------------------------------------+         |
|                                                                      |
|   sda-device-control | sda-posture | sda-software | sda-jit-admin    |
|   sda-query          | sda-policy  | sda-script-runner               |
+----------------------------------------------------------------------+
|     existing modules: fim / inventory / sca / lde / ar               |
+----------------------------------------------------------------------+
|         sda-event-bus  (priority queues + back-pressure)             |
+----------------------------------------------------------------------+
|            sda-comms  (TLS 1.3 + HTTP/2 + MsgPack)                   |
+----------------------------------------------------------------------+
|     sda-pal: MdmProvider | PackageManager | AdminManager             |
|              DevicePostureProvider | …                               |
+----------------------------------------------------------------------+
|     Linux | macOS | Windows native APIs (per existing PAL)           |
+----------------------------------------------------------------------+
                            ||  TLS 1.3 / HTTP/2 / MsgPack
                            \/
+----------------------------------------------------------------------+
|              SN360 Control Plane (separate repo)                     |
|                                                                      |
|  Agent Gateway -> NATS -> {desktop-mdm, risk-engine, smi-engine,     |
|                            approval-service, evidence-vault,         |
|                            privacy-vault}                            |
+----------------------------------------------------------------------+
```

The arrow between agent and control plane is the existing SN360
native protocol path — there is no new transport. Desktop MDM adds
new `MessageType` variants and new NATS subjects under
`device_control.mdm.*`, not new sockets.

### 1.1 Sub-module wiring

`sda-mdm` is a single Rust crate exposing one public type
(`sda_mdm::Module`) that owns seven sub-modules. The relationships
between them are:

```
                                 +-----------------+
                                 | SignedActionJob |
                                 | from sda-       |
                                 | device-control  |
                                 +--------+--------+
                                          |
                                          v
                                 +-----------------+
                                 | sda_mdm::Module |
                                 |  (dispatcher)   |
                                 +-----------------+
                                          |
        +-----------+--------+---------+--+---------+-----------+-----------+
        |           |        |         |           |           |           |
        v           v        v         v           v           v           v
+--------------+ +------+ +-------+ +-----+ +------------+ +---------+ +----------+
|auto_remediate| | wipe | | lock  | |lost_| |recovery_key| |os_patch | |config_   |
| (PostureSnap | |      | |       | |mode | |            | |         | |profile   |
|  subscriber) | |      | |       | |     | |            | |         | |          |
+--------------+ +------+ +-------+ +-----+ +------------+ +---------+ +----------+
        |           |        |         |           |           |           |
        v           v        v         v           v           v           v
                +------------------------------------------------+
                |             sda_pal::MdmProvider               |
                +------------------------------------------------+
```

`auto_remediate` is the only sub-module that subscribes to events
(it watches `PostureSnapshot` from `sda-posture`). Every other
sub-module is driven exclusively by inbound `SignedActionJob`s
through the dispatcher.

---

## 2. PAL trait design

`sda-pal` exposes a single new trait, `MdmProvider`, with per-OS
implementations selected at compile time via `cfg`. The trait
surface is:

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

### 2.1 Per-platform implementation matrix

| Method                       | Windows                                                                                          | macOS                                                                                                | Linux                                                                                                  |
|------------------------------|---------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| `wipe`                       | `manage-bde -off C:` (FVEK destroy) + overwrite recovery escrow + `systemreset.exe /factoryreset /quiet`. | `fdesetup removerecovery -personal` + `srm /private/var/db/CryptoTokenKit/*` + Apple Silicon `obliterate` or `diskutil eraseDisk`. | `cryptsetup luksErase /dev/<root>` + `dd if=/dev/urandom of=/dev/<root> bs=1M count=10` + forced reboot. |
| `lock`                       | `user32::LockWorkStation()`; tenant message → `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background`. | `/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession -suspend` + `NSDistributedNotificationCenter` post. | `loginctl lock-sessions` + one-shot `sda-mdm-lock.service` rendering Plymouth.                          |
| `escrow_recovery_key`        | `manage-bde -protectors -get C: -type RecoveryPassword` (48-digit BitLocker numerical key).         | `fdesetup showrecoverykey` (personal HRK).                                                            | `cryptsetup luksDump --dump-master-key /dev/<root>` (privileged) **or** SN360 pre-provisioned keyslot 7. |
| `install_os_updates`         | PowerShell `Install-Module PSWindowsUpdate -Scope CurrentUser; Get-WUList; Install-WindowsUpdate -AcceptAll -AutoReboot:$false`; fallback `UsoClient StartScan` + `UsoClient StartInstall`. | `/usr/sbin/softwareupdate --install --all` (or `--recommended` for security-only).                    | `unattended-upgrades --debug` (apt) **or** `dnf-automatic-install.service` (dnf) **or** `zypper patch -y` (zypper). |
| `apply_config_profile`       | Registry writes under `HKLM\SOFTWARE\Policies\Microsoft\Windows\*`; passwords under `LSA\Notification Packages`; Bluetooth under `Policies\Microsoft\Bluetooth`; camera under `Policies\Microsoft\Camera`. | `/usr/bin/profiles install -path=<profile.mobileconfig>` (legacy) or DDM payload via `mdmclient` (macOS 14+). Password policy via `/usr/bin/pwpolicy`. | `dconf write /org/gnome/desktop/lockdown/disable-camera 'true'` etc.; polkit drop-in under `/etc/polkit-1/rules.d/`; `pam_pwquality.conf`. |
| `enable_disk_encryption`     | `manage-bde -on C: -RecoveryPassword -SkipHardwareTest -UsedSpaceOnly` (TPM-backed; recovery key emitted to stdout for escrow). | `fdesetup enable -user $current_user -keychain` + capture stdout for HRK escrow.                       | `cryptsetup luksFormat` on staging volume + migration script (only on supported partition layouts).      |
| `enable_firewall`            | `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True`.                              | `/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on` + `--setblockall off`.           | `firewall-cmd --set-default-zone=public --permanent && firewall-cmd --reload` **or** `nft add table inet filter && nft add chain inet filter input '{ type filter hook input priority 0 ; policy drop ; }'`. |
| `set_screen_lock`            | `HKCU\Control Panel\Desktop\ScreenSaveTimeOut = "<secs>"` + `HKCU\Control Panel\Desktop\ScreenSaverIsSecure = "1"`. | `defaults -currentHost write com.apple.screensaver idleTime <secs>`; `defaults write com.apple.screensaver askForPassword 1`. | `dconf write /org/gnome/desktop/session/idle-delay 'uint32 <secs>'` + `dconf write /org/gnome/desktop/screensaver/lock-enabled 'true'`. |
| `enter_lost_mode`            | Persistent lock screen via custom credential provider DLL registered under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{guid}` + `systemd-shutdown` lock-on-resume. | LaunchDaemon (`com.sn360.sda.mdm.lost-mode`) running `sda-mdm-lost-mode-view` (full-screen `NSWindow` over all spaces) + `caffeinate -dimsu`. | Plymouth full-screen splash (`/usr/share/plymouth/themes/sn360-lost-mode/`) + `loginctl lock-sessions` looped via `sda-mdm-lost-mode.service`. |
| `exit_lost_mode`             | Unregister credential provider + restart `Winlogon` service.                                        | Unload LaunchDaemon + post `com.apple.screenIsUnlocked` notification.                                 | Stop `sda-mdm-lost-mode.service` + `loginctl unlock-sessions`.                                          |

All `MdmProvider` implementations run inside SDA's existing
privilege-separated module process boundary; no new privileged
process is introduced by Desktop MDM.

### 2.2 Supporting types

```rust
pub struct WipeOpts {
    pub crypto_shred_only: bool,    // true ⇒ destroy keys, skip OS factory reset.
    pub wait_for_ac: bool,          // true ⇒ defer until on AC power.
}

pub struct WipeOutcome {
    pub crypto_shred_succeeded: bool,
    pub factory_reset_invoked: bool,
    pub started_at: DateTime<Utc>,
}

pub struct RecoveryKeyPayload {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub key_type: RecoveryKeyType,     // BitLocker | FileVault | LUKS
    pub ciphertext: Vec<u8>,           // ChaCha20-Poly1305 over the raw recovery key.
    pub nonce: [u8; 12],
    pub escrowed_at: DateTime<Utc>,
    pub signature: Vec<u8>,            // Ed25519 by the agent's evidence key.
    pub key_id: String,
}

pub struct OsUpdateOpts {
    pub include_security: bool,
    pub include_feature: bool,
    pub reboot_policy: RebootPolicy,   // Never | OnIdle | OnMaintenanceWindow
}

pub struct OsUpdateOutcome {
    pub updates_installed: u32,
    pub reboot_required: bool,
    pub log_sha256: [u8; 32],
}

pub struct EncryptionOutcome {
    pub enabled: bool,
    pub recovery_key_escrowed: bool,
    pub provider: &'static str,        // "bitlocker" | "filevault" | "luks"
}

pub struct SignedConfigProfile {
    pub profile_id: Uuid,
    pub tenant_id: Uuid,
    pub canonical_json: String,        // RFC 8785 canonical JSON of the profile body.
    pub signature: Vec<u8>,            // Ed25519 by the control-plane signing key.
    pub key_id: String,
}
```

---

## 3. Data-flow diagrams

### 3.1 Wipe

```
control-plane "Approval Service" gathers two distinct approvers
        |
        v
SignedActionJob { action: RemoteWipe, signatures: [s1, s2], key_ids: [k1, k2] }
        |
        v sda-comms ingress
        v
sda-device-control::router
   - 10-step validator
   - extra arm: signatures.len() >= 2 if action == RemoteWipe, else JobRefused
        |
        v
sda_mdm::Module::dispatch
        |
        v
sda_mdm::wipe::handle
   1. emit MdmWipeResult { status: Started }   ← evidence-before-action
   2. MdmProvider::wipe(opts)
        - crypto-shred volume / recovery key
        - invoke OS factory reset
   3. emit MdmWipeResult { status: Success | Failure, … }
   4. EvidenceRecord written (dual-signature pre-image hashed in)
```

### 3.2 Lock

```
SignedActionJob { action: RemoteLock, args: { message: "..." } }
        |
        v sda-device-control::router
        v
sda_mdm::Module::dispatch
        |
        v
sda_mdm::lock::handle
   1. MdmProvider::lock(message)
        - Windows: LockWorkStation + tile message
        - macOS:   CGSession -suspend + notification
        - Linux:   loginctl lock-sessions + Plymouth
   2. emit MdmLockResult { status, started_at, finished_at }
   3. EvidenceRecord written
```

### 3.3 Recovery key escrow

```
sda_mdm::Module spawn
   |
   v (one-time after first comms handshake of each boot)
sda_mdm::recovery_key::escrow_once
   |
   v
MdmProvider::escrow_recovery_key()
   1. read raw recovery key (manage-bde / fdesetup / cryptsetup)
   2. derive per-device wrapping key:
        wrapping_key = HKDF(tenant_master_key, "sda-mdm-recovery-key", device_id)
   3. ChaCha20-Poly1305 encrypt raw key under wrapping_key
   4. Ed25519 sign payload with agent evidence key
   5. emit MdmRecoveryKeyEscrowed { payload }
   6. EvidenceRecord written

control plane "privacy-vault" stores ciphertext blob; raw key never
appears in plaintext outside the agent's process.
```

### 3.4 OS patch

```
maintenance-window timer (shared with sda-software)
   |
   v
sda_mdm::os_patch::tick
   |
   v
PowerMonitor::current_profile()
   - BatterySaver ⇒ defer
   - other ⇒ continue
   |
   v
MdmProvider::install_os_updates(opts)
   - Windows: PSWindowsUpdate / UsoClient
   - macOS:   softwareupdate --install
   - Linux:   unattended-upgrades / dnf-automatic / zypper patch
   |
   v
capture installer log, hash with SHA-256
emit MdmOsUpdateResult { updates_installed, reboot_required, log_sha256 }
EvidenceRecord written
```

### 3.5 Config profile

```
TRDS bundle pull (existing path) writes
/var/lib/sn360-desktop-agent/bundle/policy/mdm/profile.json
   |
   v
sda_mdm::config_profile::watcher (filesystem notify)
   |
   v
verify Ed25519 signature against pinned control-plane keys
   - on failure ⇒ emit FindingKind::ConfigProfileTampered (high), keep previous profile
   - on success ⇒ continue
   |
   v
MdmProvider::apply_config_profile(profile)
   - Windows: registry / GPO writes
   - macOS:   profiles install / DDM payload
   - Linux:   dconf / polkit / pam_pwquality.conf
   |
   v
emit MdmConfigProfileApplied { profile_id }
EvidenceRecord written
```

### 3.6 Auto-remediation

```
sda-posture publishes PostureSnapshot every modules.posture.interval_secs (default 300)
   |
   v
sda_mdm::auto_remediate::subscriber
   |
   v
inspect snapshot fields:
   - disk_encryption == Off  && cfg.auto_remediate.disk_encryption ⇒ enqueue EnableDiskEncryption
   - firewall == Off         && cfg.auto_remediate.firewall        ⇒ enqueue EnableFirewall
   - screen_lock == Off      && cfg.auto_remediate.screen_lock     ⇒ enqueue SetScreenLock
   |
   v
debounce check (agent-local DB) — reject duplicates within 24h window
   |
   v
sign locally with ephemeral key (rotated on every config push)
   |
   v
sda-device-control::router (accepts local ephemeral key in addition to control-plane keys)
   |
   v
sda_mdm::Module::dispatch (same path as control-plane jobs)
   |
   v
MdmProvider::enable_disk_encryption() / .enable_firewall() / .set_screen_lock()
   |
   v
emit MdmAutoRemediationResult { kind, status }
EvidenceRecord written with auto_remediated: true
```

### 3.7 Lost mode

```
SignedActionJob { action: EnterLostMode, args: { message: "..." } }
   |
   v
sda_mdm::lost_mode::enter
   1. MdmProvider::enter_lost_mode(message)
        - Windows: register persistent credential provider
        - macOS:   load LaunchDaemon for full-screen view
        - Linux:   start sda-mdm-lost-mode.service (Plymouth)
   2. emit MdmLostModeEntered
   3. EvidenceRecord written

sda_mdm::lost_mode::reporter (long-running task)
   |
   v on every successful network reconnect
   v
IP geolocation against control-plane GeoIP database
emit AgentVitals { last_known_location: (lat, lon, accuracy_m) }
   ↑ last_known_location is an additive field; legacy AgentVitals consumers ignore it.

…

SignedActionJob { action: ExitLostMode }
   |
   v
sda_mdm::lost_mode::exit
   1. MdmProvider::exit_lost_mode()
   2. emit MdmLostModeExited
   3. EvidenceRecord written
```

---

## 4. Protocol extension

### 4.1 New `MessageType` variants

`sda-comms::MessageType` gains the following variants. Each variant
has an explicit arm in `WazuhMessage::encode_body()`
([`crates/sda-comms/src/protocol.rs`](../../crates/sda-comms/src/protocol.rs))
and a corresponding mapping in
`sda-agent::main::map_event_to_message`:

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

Every variant must have an explicit arm in `encode_body()` —
fall-through to the catch-all is forbidden per the existing repo
invariant.

### 4.2 New `EventKind` variants

`sda-core::EventKind` gains:

```rust
pub enum EventKind {
    // ... existing variants ...
    MdmWipeResult(MdmWipeResultPayload),
    MdmLockResult(MdmLockResultPayload),
    MdmLostModeEntered(MdmLostModeEnteredPayload),
    MdmLostModeExited(MdmLostModeExitedPayload),
    MdmRecoveryKeyEscrowed(RecoveryKeyPayload),
    MdmOsUpdateResult(MdmOsUpdateResultPayload),
    MdmConfigProfileApplied(MdmConfigProfileAppliedPayload),
    MdmAutoRemediationResult(MdmAutoRemediationResultPayload),
}
```

### 4.3 NATS subject hierarchy

The control plane consumes Desktop MDM traffic under
`device_control.mdm.*` (sitting beside the existing
`device_control.*` tree from
[`device-control/ARCHITECTURE.md` § 4.2](../device-control/ARCHITECTURE.md#42-nats-subject-hierarchy)):

```
device_control.mdm.wipe.<tenant_id>.<device_id>
device_control.mdm.lock.<tenant_id>.<device_id>
device_control.mdm.lost_mode.<tenant_id>.<device_id>
device_control.mdm.recovery_key.<tenant_id>.<device_id>
device_control.mdm.os_update.<tenant_id>.<device_id>
device_control.mdm.config_profile.<tenant_id>.<device_id>
device_control.mdm.auto_remediation.<tenant_id>.<device_id>
```

The agent does not connect to NATS directly; the Agent Gateway (in
`sn360-security-platform`) translates between the agent's native
protocol frames and the NATS topology.

### 4.4 Signed-job validation extensions

The 10-step validator from
[`device-control/PROPOSAL.md` § 10.3](../device-control/PROPOSAL.md#103-signed-job-validation-10-step-checklist)
is reused unchanged for every Desktop MDM action except `RemoteWipe`,
which gains an extra arm:

```
11. If action == RemoteWipe:
    11a. Require signatures.len() >= 2.
    11b. Verify each signature against its declared key_id.
    11c. Require all key_ids resolve to distinct approver user_ids
         (carried in the canonical signature pre-image as `approver_user_id`).
    11d. On any failure ⇒ JobRefused { reason: "wipe_requires_dual_control" }.
```

Auto-remediation jobs take a parallel arm:

```
12. If job was signed by the local ephemeral key:
    12a. Require action in {EnableDiskEncryption, EnableFirewall, SetScreenLock}.
    12b. Require recommendation_id == None.
    12c. Otherwise ⇒ JobRefused { reason: "local_key_not_authorised_for_action" }.
```

---

## 5. Configuration schema

`AgentConfig` gains the following section. **Defaults are ON** —
this is the key differentiator versus Device Control's defaults-off
posture:

```yaml
modules:
  mdm:
    enabled: true                # DEFAULT ON
    auto_remediate:
      disk_encryption: true      # DEFAULT ON
      firewall: true             # DEFAULT ON
      screen_lock: true          # DEFAULT ON
      screen_lock_timeout_secs: 300
      remediation_debounce_secs: 86400   # 24h: don't re-attempt the same fix.
    os_patch:
      enabled: true
      auto_install_security: true
      auto_install_all: false
      defer_on_battery: true
    recovery_key_escrow:
      enabled: true
      one_time_per_boot: true
    lost_mode:
      message: "This device belongs to {tenant_name}. Please contact {tenant_email}."
      report_location_interval_secs: 300
    config_profiles:
      password_policy:
        min_length: 8
        require_complexity: true
        max_age_days: 90
        max_attempts: 5
        lockout_minutes: 15
      screen_lock:
        timeout_secs: 300
        require_password_on_resume: true
      bluetooth: "audit"         # allow | audit | block
      camera: "allow"            # allow | audit | block
      wifi:
        allowed_ssids: []        # empty ⇒ no restriction
        block_open_networks: false
```

Tenant-scoped overrides arrive through the existing TRDS bundle
path and are applied atomically (compare-and-swap on a
`*ArcSwap<MdmConfig>`).

The full field reference is mirrored in
[`docs/configuration-reference.md`](../configuration-reference.md)
when the corresponding code lands.

---

## 6. Module startup order

`sda-mdm` hooks into the existing module startup sequence from
[`device-control/ARCHITECTURE.md` § 10](../device-control/ARCHITECTURE.md#10-module-startup-order)
without changing the order of any existing module:

```
1.  sda-core: load AgentConfig, derive feature flags (including
    modules.mdm.* defaults).
2.  sda-pal: select per-OS providers including MdmProvider.
3.  sda-event-bus: bring up bus.
4.  sda-comms: open native protocol session and register the new
    Mdm* MessageType arms.
5.  sda-agent-vitals: start heartbeat.
6.  sda-posture: subscribe to power profile, schedule snapshots.
7.  sda-query: start scheduler.
8.  sda-policy: subscribe to query results + posture + inventory.
9.  sda-device-control: subscribe to inbound jobs; wire signed-job
    validation pipeline with the new RemoteWipe dual-control arm and
    the local-ephemeral-key arm.
10. sda-mdm (NEW):
    10a. config_profile::watcher mounts the TRDS bundle path.
    10b. recovery_key::escrow_once fires once after first comms
         handshake succeeds.
    10c. auto_remediate::subscriber subscribes to PostureSnapshot.
    10d. os_patch::scheduler hooks into the maintenance-window timer
         shared with sda-software.
    10e. wipe / lock / lost_mode / config_profile sit idle until an
         inbound SignedActionJob is dispatched.
11. sda-software / sda-jit-admin / sda-script-runner: existing lazy
    init.
12. sda-app-control / sda-remote-support: existing lazy init.
```

Each step is independently observable via `AgentVitals` so a
mis-ordered start fails loudly.

---

## 7. Security model

### 7.1 Threats and controls (summary)

The full threat model lives in
[`PROPOSAL.md` § 6](./PROPOSAL.md#6-security-model). The
architecturally significant controls are:

- **Dual-control wipe.** Two distinct approver signatures required
  on every `RemoteWipe` job; enforced by the validator extension in
  § 4.4.
- **Tenant-scoped recovery key encryption.** Recovery key payload is
  ChaCha20-Poly1305-encrypted under a per-device key derived via
  HKDF from the tenant master key (which never leaves the
  privacy-vault).
- **Local-only auto-remediation.** Auto-remediation jobs are signed
  by an agent-local ephemeral key (rotated on every config push) and
  never accepted by the control plane.
- **Signed config profiles.** Profile bundles are Ed25519-signed by
  the control-plane signing key; verification failure ⇒ profile
  rejected, previous profile kept (no warn-and-continue).
- **Reversible lost mode.** Every lost-mode entry is paired with a
  corresponding `ExitLostMode` action on the same evidence chain;
  no data destroyed.
- **Battery-aware patching.** OS patch operations defer on battery
  via `PowerMonitor::current_profile()`.

### 7.2 Key material lifecycle

| Key                                    | Location                                                                 | Rotation                                                                       |
|----------------------------------------|--------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| Control-plane signing key              | Privacy-vault HSM-backed; pinned `key_id`s in the agent's rotation set.   | On policy.                                                                      |
| Tenant master key                      | Privacy-vault, per-tenant; never leaves the vault.                       | On tenant offboarding (cryptographic erasure).                                  |
| Per-device recovery-key wrapping key   | Derived on-the-fly via HKDF(tenant_master_key, "sda-mdm-recovery-key", device_id). | Never stored; re-derived as needed. Effectively rotates whenever the tenant master key changes. |
| Agent evidence-signing key             | Agent local secure storage; existing key from `sda-comms` enrolment.      | On agent re-enrolment.                                                         |
| Agent local-ephemeral key (auto-remediate) | Agent process memory only; persisted to disk encrypted under the OS keychain / TPM. | Generated at enrolment; rotated on every config push.                            |

### 7.3 Signed-job validation diff

The signed-job validator already implements 10 steps for Device
Control. Desktop MDM adds two arms (one for `RemoteWipe`
dual-control, one for the local-ephemeral-key path); see § 4.4.

---

## 8. Resource budgeting

### 8.1 Existing budgets are inviolable

| Metric                | Existing target | Desktop MDM rule                                                                                     |
|-----------------------|-----------------|------------------------------------------------------------------------------------------------------|
| Idle RSS              | < 15 MB         | `sda-mdm` adds < 0.5 MB idle RSS (one subscriber + one Tokio task for the maintenance-window timer).  |
| Idle CPU              | < 0.1 %         | Auto-remediation piggybacks on `sda-posture` snapshots; no new timers.                                 |
| FIM scan peak CPU     | < 3 %           | Desktop MDM uses `PowerMonitor::current_profile()` to defer OS patching on battery.                    |
| Binary size           | < 7 MB          | `sda-mdm` adds < 1 MB (most of the budget is per-OS Win32 / IOKit / sysd helpers).                     |

### 8.2 Sub-process budget

| Sub-process                                  | Max RSS | Max CPU | Notes                                                          |
|----------------------------------------------|---------|---------|----------------------------------------------------------------|
| `manage-bde` invocation (Windows)            | n/a     | n/a     | Short-lived; budget enforced via job timer.                     |
| `fdesetup` / `softwareupdate` invocation (macOS) | n/a     | n/a     | Short-lived; budget enforced via job timer.                     |
| `cryptsetup` / `unattended-upgrades` (Linux) | n/a     | n/a     | Short-lived; budget enforced via job timer.                     |
| `sda-mdm-lost-mode.service` (Linux)          | 5 MB    | 0.05 %  | Plymouth-based; runs only while lost mode is active.            |
| Windows credential provider DLL              | n/a     | n/a     | Loaded by `Winlogon`; in-process, not a separate process.        |
| macOS lost-mode `LaunchDaemon`               | 10 MB   | 0.1 %   | NSWindow over all spaces; runs only while lost mode is active.   |

### 8.3 Event priority assignments

| EventKind                              | Priority |
|----------------------------------------|----------|
| `MdmWipeResult`                        | High     |
| `MdmLockResult`                        | High     |
| `MdmLostModeEntered`/`Exited`          | High     |
| `MdmRecoveryKeyEscrowed`               | High     |
| `MdmOsUpdateResult`                    | Normal   |
| `MdmConfigProfileApplied`              | Normal   |
| `MdmAutoRemediationResult`             | High     |

These priorities flow into `sda-event-bus`'s existing priority queue
without any new infrastructure.

---

## 9. Further reading

- [PROPOSAL.md](./PROPOSAL.md) — full technical proposal.
- [PROGRESS.md](./PROGRESS.md) — delivery log.
- [`device-control/PROPOSAL.md`](../device-control/PROPOSAL.md) —
  sibling Device Control proposal; Desktop MDM reuses the
  signed-job validator and the evidence chain documented there.
- [`device-control/ARCHITECTURE.md`](../device-control/ARCHITECTURE.md) —
  sibling Device Control architecture; the module startup order,
  event-bus priorities, and PAL trait conventions are inherited from
  this document.
- Parent [`docs/architecture.md`](../architecture.md) — current SDA
  crate map, event flow, and protocol details.
- Control-plane companion:
  [`sn360-security-platform/docs/desktop-mdm/ARCHITECTURE.md`](https://github.com/kennguy3n/sn360-security-platform/blob/main/docs/desktop-mdm/ARCHITECTURE.md).
