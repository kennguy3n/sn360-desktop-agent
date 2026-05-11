# Phase D2 — Windows kernel filter driver productisation

> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)
>
> **Status:** Deferred — requires WDK, EV code-signing certificate,
> and the Windows Compatibility Lab.

This document pins the deferred-path roadmap for **Task D2.3-driver**:
lifting the user-mode SetupDi + named-pipe policy service that ships
today to a WHQL-signed kernel filter driver. PR #13 merged the
user-mode scaffold; this document is the work plan for the kernel
productisation step.

## 1. What the user-mode scaffold (today) covers

The user-mode service in [`crates/sda-device-control/src/usb_windows.rs`](../../crates/sda-device-control/src/usb_windows.rs)
covers:

- **Detection.** Subscribes to `CM_Register_Notification` for
  `DEVPKEY_Device_Class == DiskDrive` / `USB`, reads
  `DEVPKEY_Device_HardwareIds` / `DEVPKEY_Device_InstanceId` /
  `DEVPKEY_Device_LocationInfo`, and builds a `DeviceCandidate`.
- **Decision.** Talks to the agent over the named pipe
  `\\.\pipe\sn360-desktop-agent-usb-policy` (line-delimited JSON;
  see [`ARCHITECTURE.md` § 10b.3](./ARCHITECTURE.md#10b3-ipc-wire-format)).
- **Enforcement.** On `Block`, marks the device as
  `CM_PROB_DISABLED` via `SetupDiSetSelectedDriver` so Windows
  surfaces the "device is disabled" UX and does not mount the filesystem.
- **Audit.** Emits `EventKind::UsbDevicePolicyDecision` onto the bus
  for every Allow / Block / Audit decision.

What it **does not** cover (and the kernel filter driver must add):

- Pre-mount enforcement: today's hook fires after Windows has read
  the partition table; a malicious controller can still attempt I/O
  during the window between attach and our SetupDi call.
- Class-level filtering for non-USB removable buses (Thunderbolt,
  PCIe NVMe USB-C enclosures, SD/MMC controllers).
- Per-interface filtering (USB composite devices that expose, e.g.,
  HID + Mass Storage).
- Tamper resistance against userspace privilege-escalation that
  could `OpenProcessToken` + `SetTokenInformation` to disable our
  user-mode service.

## 2. Productisation prerequisites

| Item | Where it lives | Owner |
|---|---|---|
| **Windows Driver Kit (WDK)** — current LTSC version | Build server only | DevInfra |
| **Visual Studio Build Tools** with the WDF + KMDF + UMDF integration | Build server only | DevInfra |
| **EV code-signing certificate** for kernel-mode signing | HSM-backed, never on disk | Security |
| **Hardware Lab Kit (HLK)** for WHQL submission | Lab VM(s) | QA |
| **Microsoft Partner Center** account with **Windows Hardware Dev Center** | Org account | Compliance |
| **Test signing** dev box(es) with `bcdedit /set testsigning on` | Dev VMs only | DevInfra |

None of these are present on the current build VM, which is why
this work is deferred. The user-mode scaffold ships today so end-to-end
integration testing can proceed in parallel.

## 3. Driver architecture

The kernel driver is a **WDF (Windows Driver Framework)** USB filter
driver, layered above the bus driver and below the function driver.

```
+----------------------------------+
| Function driver (e.g. usbstor)   |
+----------------------------------+
| sn360-device-control.sys (NEW)   |  <- WDF filter; intercepts
+----------------------------------+     IRP_MJ_PNP / START_DEVICE
| Bus driver (usbhub3 / pcie root) |
+----------------------------------+
```

### 3.1 Decision path

1. On `IRP_MJ_PNP` `IRP_MN_START_DEVICE`, the filter extracts the
   hardware-id stack from the device's `DevNode`.
2. The filter sends the line-delimited JSON `DeviceCandidate` over a
   **kernel-mode WFP-style ALE callout** to the user-mode agent.
   *(Rationale: kernel mode cannot do `tokio` named-pipe I/O; we use
   `FltSendMessage` + an inverted-call port instead.)*
3. The user-mode agent computes the `Decision` exactly as today.
4. The driver receives the response synchronously (with a 250 ms
   wall-clock budget) and either completes the IRP with success
   (Allow / Audit) or fails it with `STATUS_ACCESS_DENIED` (Block).
5. On Block, the driver **also** issues a synchronous reset on the
   parent USB hub port so a re-enumeration cannot bypass us.

### 3.2 Tamper resistance

- The driver registers with **Protected Process Light (PPL)** at the
  `WinSystem` level so userland malware cannot terminate it.
- The filter driver verifies the user-mode agent's binary signature
  on every `FltSendMessage` connection by reading the peer process's
  signed binary path via `PsGetProcessImageFileName` and validating
  the SHA-256 against a hard-coded list of approved publisher hashes.
- A **safe-mode boot start fallback** runs the driver in
  closed-by-default mode (every device blocked) until the user-mode
  agent connects and applies a verified bundle.

## 4. Build / sign / package pipeline

```
$ build.ps1                    # produces sn360-device-control.sys + .pdb
$ inf2cat ...                  # produces sn360-device-control.cat
$ signtool sign /v /n "EV"   \ # sign the .sys, .cat, and the .inf
    /tr http://timestamp.digicert.com /td sha256 /fd sha256       \
    sn360-device-control.sys sn360-device-control.cat sn360-device-control.inf
$ hlk submit ...               # submit to Microsoft for WHQL attestation
```

The HLK submission produces a `WHQL`-signed `.cat` that Windows Update
will accept on every supported SKU.

### 4.1 INF / CAT layout

The `.inf` declares one filter-driver class entry per matched device
class. The minimum class set is:

- `{4d36e967-e325-11ce-bfc1-08002be10318}` — DiskDrive
- `{36fc9e60-c465-11cf-8056-444553540000}` — USB
- `{eec5ad98-8080-425f-922a-dabf3de3f69a}` — Thunderbolt
- `{72631e54-78a4-11d0-bcf7-00aa00b7b32a}` — Battery (for power-only
  device matching, future)

### 4.2 Install / upgrade / uninstall

| Lifecycle event | Mechanism | Notes |
|---|---|---|
| First install | `pnputil /add-driver sn360-device-control.inf /install` | Pulls in the WHQL `.cat`; reboot is **not** required for filter drivers. |
| Upgrade | `pnputil /add-driver` with the new `.inf` + `pnputil /delete-driver <oem-id>` for the old | Atomic; in-flight IRPs drain before swap. |
| Uninstall | `pnputil /delete-driver <oem-id> /uninstall /force` | Closed-by-default fallback in user-mode persists, so removing the kernel driver does **not** open up the device class. |

## 5. Test plan

1. **Unit (in `crates/sn360-device-control-driver/`, new crate behind
   the `windows-driver` Cargo feature):** mock the bus + function
   driver IRPs, assert the filter completes Block / Allow / Audit
   IRPs correctly and never panics on malformed `DeviceCandidate`s.
2. **Integration (HLK):** the standard "USB Filter Driver" HLK
   playlist + the "Mass Storage" playlist, run on x64 + ARM64 +
   Hyper-V Generation 2.
3. **Stress (HLK + custom):**
   - 10 000 attach / detach cycles with random `Decision` shapes.
   - 1 000 simultaneous attaches via a USB hub multiplexer.
   - 24-hour soak at 10 attach/sec with periodic bundle reloads.
4. **Tamper:**
   - User-mode agent killed mid-attach: filter falls back to
     closed-by-default; re-attach after agent restart succeeds.
   - User-mode agent binary swapped: filter rejects the next
     `FltSendMessage` connection until the binary is re-signed.

## 6. Microsoft compatibility lab submission

Submit the package via the Microsoft **Partner Center** to:

- **Windows 10 LTSC 2021** — required (long-tail enterprise).
- **Windows 11 24H2** — required.
- **Windows Server 2022 / 2025** — required (RDS hosts).

Each submission produces a per-SKU WHQL `.cat`. The WHQL'd `.cat`
files are bundled with the user-mode installer and selected at
install time based on the OS SKU.

## 7. Rollback

If the kernel driver is the source of a customer-impacting bug:

1. The user-mode installer `disable.ps1` script flips the driver's
   `Start` registry value to `4` (`Disabled`); on next reboot the
   kernel driver does not load. The user-mode agent continues to
   serve the line-delimited JSON IPC; no bundle slice changes are
   needed.
2. The kernel filter driver's `IRP_MJ_PNP` handler observes
   `KeRegisterNmiCallback` on a pre-allocated bug-check entry that
   downgrades to "filter passes through every IRP" after three
   consecutive panics, so an in-the-field bug self-disables before
   bug-check storms a fleet.
3. `pnputil /delete-driver <oem-id> /uninstall /force` is the
   permanent remediation. Closed-by-default fallback in user-mode
   keeps device-class enforcement intact during the rollback window.

## 8. Open questions / risks

- **WDM downgrade.** Some legacy USB hub drivers do not propagate
  `IRP_MJ_PNP` correctly to filter drivers. The HLK playlist covers
  the supported set; out-of-tree WDM drivers (rare in 2026+) may
  require a vendor-specific workaround.
- **Hyper-V passthrough.** USB-over-Hyper-V (Enhanced Session +
  RemoteFX USB) does not surface as a USB device class; we'll need
  a parallel Hyper-V-specific filter or an explicit policy that
  passthrough USB is always Audit-only.
- **AVD / Citrix pass-through.** Same problem class as Hyper-V; the
  fallback is the user-mode service which already runs inside the
  guest.

## 9. Owner / sign-off

- **Driver eng:** TBD
- **Security review:** Required (kernel signing, PPL claim, IPC).
- **WHQL submission:** Compliance team.
- **Customer rollout:** Tier-1 customers opt in via the
  `modules.device_control.usb_policy.kernel_driver = true` config
  flag once the WHQL attestation is in hand.
