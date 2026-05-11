# Phase D2 — macOS signed SystemExtension productisation

> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)
>
> **Status:** Deferred — requires Xcode, Apple Developer ID, the
> DriverKit entitlement, and the macOS notarisation pipeline.

This document pins the deferred-path roadmap for **Task D2.4-sysext**:
lifting the user-mode IOKit + UDS policy service that ships today to
a signed `IOUSBHostInterface` SystemExtension. PR #13 merged the
user-mode scaffold; this document is the work plan for the
SystemExtension productisation step.

## 1. What the user-mode scaffold (today) covers

The user-mode service in [`crates/sda-device-control/src/usb_macos.rs`](../../crates/sda-device-control/src/usb_macos.rs)
covers:

- **Detection.** Subscribes to `IOServiceMatching(kIOUSBDeviceClassName)`
  via `IOServiceAddMatchingNotification`, reads the standard IOKit
  property dictionary (`idVendor`, `idProduct`, `kUSBSerialNumberString`,
  `bDeviceClass`, `LocationID`), and builds a `DeviceCandidate`.
- **Decision.** Talks to the agent over the UDS at
  `/var/run/sn360-desktop-agent/usb-policy.sock` (line-delimited JSON;
  see [`ARCHITECTURE.md` § 10b.3](./ARCHITECTURE.md#10b3-ipc-wire-format)).
- **Enforcement.** On `Block`, calls `IOServiceClose` on the device's
  IOKit handle and issues a class-level eject for mass-storage devices.
- **Audit.** Emits `EventKind::UsbDevicePolicyDecision` onto the bus
  for every Allow / Block / Audit decision.

What it **does not** cover (and the SystemExtension must add):

- **Pre-mount enforcement.** Today's hook fires after `diskarbitrationd`
  has read the partition table; a malicious controller can attempt I/O
  during the window between attach and our `IOServiceClose` call.
- **Notarisation + Apple-distributed.** The user-mode service runs
  with elevated privileges via a `LaunchDaemon`; a signed
  SystemExtension is distributed in-band with the agent installer
  and survives macOS upgrades without re-prompting for a kernel
  extension load.
- **Class-level filtering.** A signed `IOUSBHostInterface` matcher
  intercepts I/O before any function driver claims the interface,
  including USB composite devices (HID + Mass Storage on the same
  bus), which the user-mode hook cannot reliably split.
- **Apple Silicon Reduced-Security mode requirement.** Without a
  signed SystemExtension, end users on Apple Silicon must enable
  Reduced Security to load any third-party kernel-mode component;
  with a signed SystemExtension, this is unnecessary.

## 2. Productisation prerequisites

| Item | Where it lives | Owner |
|---|---|---|
| **Xcode 16+** with the macOS SDK + DriverKit SDK | Build server only | DevInfra |
| **Apple Developer Program** organisation membership | Org account | Compliance |
| **Apple Developer ID + provisioning profile** with the `com.apple.developer.system-extension.install` entitlement | Apple ID + provisioning portal | Security |
| **DriverKit entitlement** (`com.apple.developer.driverkit`) — by Apple approval only | Apple-issued | Security |
| **`com.apple.developer.driverkit.transport.usb`** entitlement | Apple-issued | Security |
| **Notary service** account (`xcrun notarytool`) | Apple ID + app-specific password | DevInfra |
| **`SystemExtensions.framework`** + `OSSystemExtensionRequest` plumbing in the host installer | Existing macOS installer pkg | DevInfra |

None of these are present on the current build VM, which is why this
work is deferred. The user-mode scaffold ships today so end-to-end
integration testing can proceed in parallel.

## 3. SystemExtension architecture

The DriverKit extension is an `IOUSBHostInterface` matcher, distinct
from a kernel extension. It runs in `dext` (DriverKit) userland with
USB transport entitlements, and survives Apple Silicon Full Security.

```
+------------------------------------------+
| User-mode agent (sda-agent)              |
|   sda-device-control::usb_macos          |
|   /var/run/sn360-desktop-agent/usb-policy.sock
+----------------------------+-------------+
                             ^
                             | XPC over the
                             | DriverKit MachPort
                             |
+----------------------------+-------------+
| sn360-device-control-dext (NEW)          |
|   IOUSBHostInterface matcher             |
|   (ipl: kDriverKit, sandbox: dext)       |
+----------------------------+-------------+
                             ^
                             | IOUSBHostInterface
                             |
+----------------------------+-------------+
| AppleUSBHostXHCI / kIOUSBHostFamily      |
+------------------------------------------+
```

### 3.1 Decision path

1. The DriverKit framework matches the `IOUSBHostInterface` against
   the dext's `IOKitPersonalities` plist before any in-kernel
   function driver claims the interface.
2. The dext's `Start(IOService*)` gathers device properties, builds
   the `DeviceCandidate`, and sends it to the user-mode agent over
   an XPC `MachPort` (set up via `IOService::CopyClient`).
3. The user-mode agent computes the `Decision` exactly as today.
4. The dext receives the response synchronously (with a 250 ms
   wall-clock budget) and either calls `Stop()` + `Terminate()` to
   release the interface (Block) or returns control to the bus
   (Allow / Audit).
5. On Block, the dext **also** issues a USB device reset on the
   parent hub port so a re-enumeration cannot bypass us.

### 3.2 Tamper resistance

- The dext is **always signed** with our Developer ID; macOS will
  not load an unsigned dext on Full Security.
- The dext's XPC service connection is gated on the peer process's
  team-id matching ours, via `xpc_connection_get_audit_token` +
  `SecCodeCheckValidity` over the audit token.
- A **boot-start** entitlement (`com.apple.developer.driverkit.boot-start`)
  loads the dext before user space, so closed-by-default fallback
  applies before any login.

## 4. Build / sign / notarise pipeline

```
$ xcodebuild build -workspace SN360.xcworkspace            \
    -scheme sn360-device-control-dext                       \
    -configuration Release CODE_SIGN_IDENTITY="Developer ID Application: ..."
$ codesign --force --sign "Developer ID Application: ..."   \
    --entitlements sn360-device-control-dext.entitlements   \
    sn360-device-control-dext.dext
$ ditto -ck --keepParent --rsrc                             \
    sn360-device-control-dext.dext sn360-device-control-dext.zip
$ xcrun notarytool submit sn360-device-control-dext.zip     \
    --apple-id "$APPLE_ID" --password "$APP_SPECIFIC_PASSWORD" --team-id "$TEAM_ID" --wait
$ xcrun stapler staple sn360-device-control-dext.dext
```

The notarised dext is then bundled inside `sda-agent.pkg` (the host
installer) under `Contents/Library/SystemExtensions/`.

### 4.1 Entitlements

The dext's `.entitlements` file requires:

- `com.apple.developer.driverkit` — `true`
- `com.apple.developer.driverkit.transport.usb` — `true`
- `com.apple.developer.driverkit.allow-third-party-userclients` —
  `true`
- `com.apple.developer.driverkit.userclient-access` —
  `["com.uney.sn360.desktop-agent"]`
- `com.apple.developer.driverkit.boot-start` — `true`
- `com.apple.security.app-sandbox` — `true`

These entitlements are **all Apple-approval-required**. The DriverKit
USB-transport entitlement in particular requires a written use-case
submission to Apple Developer Relations.

### 4.2 Install / upgrade / uninstall

| Lifecycle event | Mechanism | Notes |
|---|---|---|
| First install | `OSSystemExtensionRequest.activationRequest` on first agent boot | macOS prompts the user once; subsequent boots load silently. |
| Upgrade | `OSSystemExtensionRequest.activationRequest` with the new bundle id | OS handles the swap atomically; no user prompt if the team-id matches. |
| Uninstall | `OSSystemExtensionRequest.deactivationRequest` | Triggered by the agent uninstaller; closed-by-default fallback in user-mode persists during the deactivation window. |

## 5. MDM payload

For managed fleets, the SystemExtension can be **pre-approved** so
the first-install user prompt is suppressed. The MDM payload is a
`com.apple.system-extension-policy` profile:

```xml
<dict>
  <key>AllowedSystemExtensions</key>
  <dict>
    <key>$TEAM_ID</key>
    <array>
      <string>com.uney.sn360.device-control-dext</string>
    </array>
  </dict>
  <key>AllowedSystemExtensionTypes</key>
  <dict>
    <key>$TEAM_ID</key>
    <array>
      <string>DriverExtension</string>
    </array>
  </dict>
</dict>
```

This profile is shipped via `sn360-security-platform` MDM connectors
(Task 4.10 — Apple DDM) once the dext team-id is registered.

## 6. Test plan

1. **Unit (in `crates/sn360-device-control-dext/`, new crate behind
   the `macos-dext` Cargo feature; the dext sources live in Swift +
   IOKit C++ but the test wrappers are Rust against XPC mocks):**
   - Mock the `IOService` interface, assert `Start()` decisions for
     each `Decision` shape.
   - Fuzz the IOKit property dictionary against malformed input.
2. **Integration (manual on macOS dev VMs):**
   - Boot a fresh VM with Full Security, install the agent, confirm
     the dext loads silently after the MDM profile is applied.
   - Plug a USB mass-storage device with an MDM `Block` policy;
     confirm `diskarbitrationd` never sees the partition table.
   - Plug an Allow-listed device; confirm normal Finder behaviour.
3. **Stress:**
   - 10 000 attach / detach cycles via a USB-C hub multiplexer.
   - Continuous bundle reloads from the user-mode agent during the
     attach storm; confirm no decision is missed and no IRPs leak.
4. **Tamper:**
   - User-mode agent killed mid-attach: dext falls back to
     closed-by-default; re-attach after agent restart succeeds.
   - Agent binary swapped: dext rejects the next XPC connection
     until the team-id check passes.

## 7. Rollback

If the dext is the source of a customer-impacting bug:

1. The user-mode installer `disable.sh` script issues
   `OSSystemExtensionRequest.deactivationRequest`. The user-mode
   agent continues to serve the line-delimited JSON IPC; no bundle
   slice changes are needed.
2. The dext's `Start()` handler enforces a per-launch panic budget
   (3 panics → permanent passthrough until the next OS upgrade or
   `kextcache --invalidate` reset) so a field bug self-disables
   before storming a fleet.
3. The MDM profile can also force the dext into deactivated state
   by removing it from `AllowedSystemExtensions`; macOS will revoke
   on next policy refresh.

## 8. Open questions / risks

- **Apple DriverKit USB-transport entitlement approval timeline.**
  Apple has historically taken 2–6 weeks to approve a new
  USB-transport DriverKit use case. This is the gating dependency
  for shipping the productised SystemExtension.
- **Apple Silicon Full Security.** The dext loads on Full Security
  only if Apple has issued the entitlement; until then, end users
  must opt in to Reduced Security or rely on the user-mode service.
- **Touch ID / Secure Enclave bypass.** A malicious user with
  physical access can boot into Recovery and disable
  SystemExtensions; the user-mode service remains the fallback in
  this case.

## 9. Owner / sign-off

- **macOS eng:** TBD
- **Security review:** Required (DriverKit entitlements, XPC IPC,
  notarisation chain).
- **Apple submission:** Compliance team.
- **Customer rollout:** Tier-1 customers opt in via the
  `modules.device_control.usb_policy.system_extension = true` config
  flag once the dext is notarised and the MDM profile is shipped.
