# EDR Parity — macOS Productisation

This document describes the build, signing, notarisation, and MDM
distribution pipeline for the optional macOS SystemExtension shipped
in Phase E6.3 of the EDR Parity workstream.

The SystemExtension is the *production-signed* replacement for the
user-mode Endpoint Security (ES) client introduced in Phase E1.3.
Agents that ship *without* the SystemExtension continue to operate on
the user-mode ES client — they simply forfeit the platform's
auto-launch + MDM-enforced loading guarantees.

## High-level architecture

```
+---------------------------------+
|     SystemExtension target      |
|     com.sn360.endpoint-security |
|                                 |
|  ES_EVENT_TYPE_NOTIFY_EXEC      |
|  ES_EVENT_TYPE_NOTIFY_EXIT      |
|  ES_EVENT_TYPE_NOTIFY_OPEN      |
|     (keychain access)           |
+---------------+-----------------+
                |  XPC mach port
                |  com.sn360.endpoint-security.xpc
                v
+---------------------------------+
|     Agent (user mode)           |
|                                 |
|  sda_pal::kernel::macos::       |
|    MacosKernelChannel           |
|                                 |
|    -> ProcessMonitor stream     |
|    -> Identity-monitor stream   |
+---------------------------------+
```

The wire format is line-delimited JSON matching
[`sda_pal::kernel::KernelEvent`](../../crates/sda-pal/src/kernel/mod.rs).
A user-mode parser
[`sda_pal::kernel::macos::parse_xpc_records`](../../crates/sda-pal/src/kernel/macos.rs)
is exercised under CI against a mock XPC channel. The SystemExtension
binary itself is **not** built in CI — see the toolchain section.

## Toolchain requirements

| Tool                                | Notes                            |
|-------------------------------------|----------------------------------|
| Xcode 15 + Command Line Tools       | SystemExtension target requires Xcode |
| Apple Developer ID (Team Membership)| For code signing                 |
| `com.apple.developer.endpoint-security.client` entitlement | Requested via the Apple Developer portal |
| `com.apple.developer.system-extension.install` entitlement | Allows the host app to install the SystemExtension |
| `notarytool` (ships with Xcode)     | For notarisation submission      |
| MDM payload                         | To pre-approve the SystemExtension on managed devices |

CI runners cannot run Xcode and do not hold the Developer ID. The
SystemExtension build runs on a dedicated macOS release box.

## SystemExtension scaffolding

The SystemExtension target is not committed because Apple's build
system generates non-portable `project.pbxproj` references:

1. In the existing `packaging/macos/` Xcode workspace, add a target
   of type **System Extension → Endpoint Security**.
2. Bundle identifier: `com.sn360.endpoint-security`.
3. Add the
   `com.apple.developer.endpoint-security.client` entitlement to the
   target's entitlements file (you must have already requested + been
   granted this entitlement on the Developer portal — this is the
   long-lead-time step).
4. Implement the ES client in Swift. The skeleton:
   - Subscribe to `ES_EVENT_TYPE_NOTIFY_EXEC`,
     `ES_EVENT_TYPE_NOTIFY_EXIT`, and
     `ES_EVENT_TYPE_NOTIFY_OPEN` (filtered to
     `/Library/Keychains/*` and `~/Library/Keychains/*` per Phase
     E5.3).
   - Serialise each event into a single-line JSON
     `KernelEvent` object.
   - Forward over an XPC connection to the host agent (service
     name `com.sn360.endpoint-security.xpc`).

The kernel-side serialiser MUST emit one JSON object per line. The
schema is the `serde`-derived shape of
[`KernelEvent`](../../crates/sda-pal/src/kernel/mod.rs); any new
variant must be added on the user-mode side first so the CI parser
catches schema drift.

## Build pipeline

```bash
# From the macOS release box:
cd packaging/macos
xcodebuild \
    -workspace SN360Agent.xcworkspace \
    -scheme com.sn360.endpoint-security \
    -configuration Release \
    -derivedDataPath build/sysext \
    CODE_SIGN_IDENTITY="Developer ID Application: SN360, Inc. (XXXXXXXXXX)" \
    DEVELOPMENT_TEAM=XXXXXXXXXX
```

The build produces `com.sn360.endpoint-security.systemextension/`.

## Signing + notarisation

```bash
codesign --force --options runtime \
    --sign "Developer ID Application: SN360, Inc. (XXXXXXXXXX)" \
    --entitlements com.sn360.endpoint-security.entitlements \
    build/sysext/.../com.sn360.endpoint-security.systemextension

ditto -c -k --keepParent \
    com.sn360.endpoint-security.systemextension \
    com.sn360.endpoint-security.systemextension.zip

xcrun notarytool submit \
    com.sn360.endpoint-security.systemextension.zip \
    --apple-id release@sn360.com \
    --team-id XXXXXXXXXX \
    --keychain-profile sn360-notary \
    --wait

xcrun stapler staple \
    com.sn360.endpoint-security.systemextension
```

Notarisation typically completes within 5-15 minutes.

## MDM deployment

The SystemExtension installation is gated by user approval **unless**
an MDM payload pre-approves it. The recommended payload:

```xml
<dict>
    <key>PayloadType</key>
    <string>com.apple.system-extension-policy</string>
    <key>AllowedSystemExtensions</key>
    <dict>
        <key>XXXXXXXXXX</key>
        <array>
            <string>com.sn360.endpoint-security</string>
        </array>
    </dict>
</dict>
```

The Endpoint Security client also needs a Privacy Preferences Policy
Control (PPPC) payload granting `SystemPolicyAllFiles` so the
SystemExtension can observe paths outside its own sandbox.

## Runtime contract

The agent supervisor calls
[`sda_pal::kernel::macos::attach_to_system_extension`](../../crates/sda-pal/src/kernel/macos.rs)
at startup. Without the `kernel-macos` feature this returns
`AttachError::NotPresent` and the supervisor falls back to the
user-mode ES client. With the feature enabled and the SystemExtension
activated, the channel returns event streams that flow into the same
`ProcessMonitor` / identity-monitor bus arms as the user-mode path.

## Failure mode handling

- **SystemExtension not approved**: `attach_to_system_extension`
  returns `NotPresent`. Logged once at startup at `INFO`. User-mode
  ES client continues running.
- **SystemExtension crashed**: the XPC connection returns
  `EXC_BAD_CONNECTION`. The channel is marked detached, the
  supervisor re-attaches every 30s, and in the interim the user-mode
  ES client resumes.
- **Schema drift**: per-line `serde_json::Error` is logged and the
  line is dropped. The supervisor never panics on a malformed kernel
  record.

## Open questions / future work

- File-write callbacks for FIM tamper-resistance can be added via
  `ES_EVENT_TYPE_NOTIFY_WRITE`. Out of scope for E6.3.
- DriverKit-based network filtering is a separate work item; the
  current scope is observation only via Endpoint Security.
