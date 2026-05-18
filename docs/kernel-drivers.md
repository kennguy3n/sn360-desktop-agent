# Optional kernel-mode telemetry

SDA's default deployment uses **user-mode telemetry sources only**:
ETW on Windows, the Endpoint Security (ES) framework on macOS,
`cn_proc` + `audit` on Linux. These cover the documented EDR and
Device Control feature surface and require no platform-specific
signing process beyond the standard installer signing.

For deployments that need **tamper-resistant telemetry that
survives a privileged user attempting to disable the agent**, SDA
ships an optional kernel-mode tier:

| Platform | Kernel-mode tier | Replaces (user-mode default) |
|---|---|---|
| Windows | WDK kernel filter driver | ETW process / network providers |
| macOS   | Signed `SystemExtension` (Endpoint Security client) | User-mode ES client |
| Linux   | eBPF tracing programs (kernel ≥ 5.8) | `cn_proc` + `audit` |

The kernel-mode tier is **feature-gated** (`kernel-windows`,
`kernel-macos`, `kernel-linux` Cargo features), **opt-in per
tenant** (`modules.kernel.*.enabled` in the agent config), and
**produces the same event shape** as the user-mode default. Detection
rules, response actions, and downstream consumers do not care which
tier is active.

This document is the productisation reference for builders shipping
the kernel tier on each platform.

---

## Table of contents

1. [Shared design](#1-shared-design)
2. [Windows: WDK kernel filter driver](#2-windows-wdk-kernel-filter-driver)
3. [macOS: signed SystemExtension](#3-macos-signed-systemextension)
4. [Linux: eBPF tracing](#4-linux-ebpf-tracing)
5. [Failure-mode handling](#5-failure-mode-handling)
6. [Rollback](#6-rollback)
7. [Test plan](#7-test-plan)

---

## 1. Shared design

All three kernel tiers are layered behind the same Rust abstraction:

```rust
pub trait KernelChannel: Send + Sync {
    fn try_attach(&self) -> Result<AttachState, AttachError>;
    fn poll_event(&self) -> Option<KernelEvent>;
    fn detach(&self);
}
```

The agent's supervisor calls `try_attach` at startup. If
`AttachError::NotPresent` is returned the supervisor falls back to
the user-mode channel for that subsystem and logs a single
`INFO`-level message; the agent runs identically from the
downstream consumer's perspective.

The wire format from kernel to user mode is **line-delimited JSON**
matching the `serde`-derived shape of `KernelEvent`. New variants
must be added to the Rust side first so the user-mode parser
catches schema drift in CI before any kernel-side binary ships.

### 1.1 Why line-delimited JSON

Kernel-mode code cannot link `serde_json` or any heap-allocating
Rust crate. The kernel side serialises a minimal hand-rolled JSON
emitter (or, on macOS, Swift's `JSONEncoder`) per event, one line
per event, into an OS-provided byte stream (named pipe / XPC
MachPort / eBPF perf buffer). The user-mode side parses each line
with `serde_json::from_slice` and ignores blank / malformed lines
without panicking — the supervisor never aborts on a hostile
kernel-side write.

### 1.2 Mock channels for CI

CI cannot load signed kernel drivers / SystemExtensions / eBPF
programs without elevated entitlements. Each platform ships a
**mock channel** that emits the same line-delimited JSON shape so
the user-mode parsers and event-bus plumbing are exercised on every
CI run. Mock channels live in
`crates/sda-pal/src/kernel/{windows,macos,linux_ebpf}.rs` behind
`#[cfg(test)]`.

---

## 2. Windows: WDK kernel filter driver

### 2.1 Architecture

A **WDF (Windows Driver Framework)** kernel filter driver layered
above the bus driver and below the function driver:

```
+----------------------------------+
| Function driver (e.g. usbstor)   |
+----------------------------------+
| sn360-driver.sys (filter)        |  <- intercepts IRP_MJ_PNP /
+----------------------------------+     IRP_MN_START_DEVICE +
| Bus driver (usbhub3 / pcie root) |     hooks the process / image
+----------------------------------+     callbacks for EDR
```

Three subsystems are folded into the driver:

- **Process / image telemetry** via `PsSetCreateProcessNotifyRoutineEx2`
  and `PsSetLoadImageNotifyRoutine`.
- **Network telemetry** via the Windows Filtering Platform (WFP)
  `FWPS_LAYER_ALE_AUTH_CONNECT_V4` / `_V6` callouts.
- **Device-control USB filter** intercepting `IRP_MJ_PNP`
  `IRP_MN_START_DEVICE` on the configured class GUIDs (USB,
  Thunderbolt, DiskDrive).

User-mode IPC is via `FltSendMessage` over an inverted-call port
served by `sda-agent`. Kernel mode cannot do `tokio` named-pipe
I/O; the filter sends each line-delimited JSON record over the
inverted-call port with a 250 ms wall-clock budget for the
user-mode response on device-control decisions.

### 2.2 Tamper resistance

- **Protected Process Light (PPL)** at `WinSystem` level so
  userland malware cannot terminate the agent that the driver talks
  to.
- The filter verifies the user-mode peer's signed binary path on
  every IPC connection via `PsGetProcessImageFileName` +
  SHA-256-of-binary against the hard-coded SN360 approved publisher
  hash list.
- **Safe-mode boot-start fallback** — the driver loads
  closed-by-default (every device blocked, every callout in
  observation-only) until the user-mode agent connects and applies
  a verified bundle.

### 2.3 Build / sign / package pipeline

```powershell
# 1. Build (requires WDK + Visual Studio Build Tools)
.\packaging\windows-driver\build-driver.ps1 -Configuration Release -Platform x64

# 2. Catalog generation
inf2cat /driver:bin\Release\x64 /os:10_X64,10_X86,Server2022_X64

# 3. EV code signing (HSM-backed key, never on disk)
signtool sign /v /n "SN360 EV"                                           `
    /tr http://timestamp.digicert.com /td sha256 /fd sha256                `
    bin\Release\x64\sn360-driver.sys                                       `
    bin\Release\x64\sn360-driver.cat                                       `
    bin\Release\x64\sn360-driver.inf

# 4. WHQL submission via the Hardware Lab Kit
hlkstudio submit ...
```

The HLK submission produces a per-SKU WHQL-signed `.cat` accepted
by Windows Update on every supported edition.

### 2.4 INF / CAT layout

Filter-driver class entries in the `.inf` for:

- `{4d36e967-e325-11ce-bfc1-08002be10318}` — DiskDrive
- `{36fc9e60-c465-11cf-8056-444553540000}` — USB
- `{eec5ad98-8080-425f-922a-dabf3de3f69a}` — Thunderbolt
- `{72631e54-78a4-11d0-bcf7-00aa00b7b32a}` — Battery (reserved for
  power-only device matching)

### 2.5 Install / upgrade / uninstall

| Lifecycle | Mechanism | Notes |
|---|---|---|
| First install | `pnputil /add-driver sn360-driver.inf /install` | Reboot is **not** required for filter drivers |
| Upgrade | `pnputil /add-driver` (new) + `pnputil /delete-driver <oem-id>` (old) | In-flight IRPs drain before swap |
| Uninstall | `pnputil /delete-driver <oem-id> /uninstall /force` | User-mode service remains and continues closed-by-default device-control |

### 2.6 Supported SKUs

WHQL submissions are required for each SKU the kernel tier ships
to. Initial target set:

- Windows 10 LTSC 2021
- Windows 11 24H2
- Windows Server 2022 / 2025

### 2.7 Toolchain prerequisites

| Item | Where it lives |
|---|---|
| Windows Driver Kit (current LTSC) | Build server only |
| Visual Studio Build Tools + WDF + KMDF + UMDF | Build server only |
| EV code-signing certificate | HSM-backed |
| Hardware Lab Kit | Dedicated QA VMs |
| Microsoft Partner Center / Hardware Dev Center | Org account |
| Test-signing dev box (`bcdedit /set testsigning on`) | Dev VMs only |

---

## 3. macOS: signed SystemExtension

### 3.1 Architecture

A **DriverKit SystemExtension** running in the `dext` (DriverKit)
userland with the required Apple entitlements. Two extensions ship:

- **`com.sn360.endpoint-security`** — Endpoint Security client
  feeding the EDR process / identity-monitor pipelines.
- **`com.sn360.device-control-dext`** — `IOUSBHostInterface`
  matcher feeding the device-control pipeline.

```
+------------------------------------------+
| Agent (user mode, sda-agent)             |
+------------------------------------------+
                ^   ^
                |   | XPC over Mach ports:
                |   |   com.sn360.endpoint-security.xpc
                |   |   com.sn360.device-control.xpc
                |   |
+---------------+---+--------------------------+
| SystemExtensions (dext userland)             |
|   com.sn360.endpoint-security                |
|     ES_EVENT_TYPE_NOTIFY_EXEC / _EXIT /      |
|     _OPEN (Keychain)                          |
|                                              |
|   com.sn360.device-control-dext              |
|     IOUSBHostInterface matcher               |
+----------------------------------------------+
                ^
                | IOKit / Endpoint Security
                |
+----------------------------------------------+
| Kernel: kIOUSBHostFamily / EndpointSecurity  |
+----------------------------------------------+
```

### 3.2 Entitlements

The dexts require the following Apple-approval-required
entitlements:

- `com.apple.developer.endpoint-security.client`
- `com.apple.developer.driverkit`
- `com.apple.developer.driverkit.transport.usb`
- `com.apple.developer.driverkit.allow-third-party-userclients`
- `com.apple.developer.driverkit.userclient-access`
- `com.apple.developer.driverkit.boot-start`
- `com.apple.developer.system-extension.install` (host installer)
- `com.apple.security.app-sandbox`
- A PPPC payload granting `SystemPolicyAllFiles` so the ES client
  can observe paths outside its own sandbox.

The DriverKit USB-transport entitlement requires a written
use-case submission to Apple Developer Relations. Approval timelines
are historically 2–6 weeks; this is the gating dependency for any
ship of the macOS kernel tier.

### 3.3 Build / sign / notarise pipeline

```bash
# 1. Build
xcodebuild build -workspace packaging/macos/SN360Agent.xcworkspace \
    -scheme com.sn360.endpoint-security                            \
    -configuration Release                                          \
    CODE_SIGN_IDENTITY="Developer ID Application: SN360, Inc. (XXXXXXXXXX)" \
    DEVELOPMENT_TEAM=XXXXXXXXXX

# 2. Code sign
codesign --force --options runtime                                  \
    --sign "Developer ID Application: SN360, Inc. (XXXXXXXXXX)"    \
    --entitlements com.sn360.endpoint-security.entitlements         \
    build/.../com.sn360.endpoint-security.systemextension

# 3. Notarise
ditto -c -k --keepParent com.sn360.endpoint-security.systemextension \
    com.sn360.endpoint-security.systemextension.zip
xcrun notarytool submit com.sn360.endpoint-security.systemextension.zip \
    --apple-id release@sn360.com --team-id XXXXXXXXXX                    \
    --keychain-profile sn360-notary --wait

# 4. Staple
xcrun stapler staple com.sn360.endpoint-security.systemextension
```

Notarisation typically completes within 5–15 minutes.

### 3.4 MDM deployment

For managed fleets, an MDM `com.apple.system-extension-policy`
payload pre-approves the SystemExtensions so first-install user
prompts are suppressed:

```xml
<dict>
  <key>AllowedSystemExtensions</key>
  <dict>
    <key>XXXXXXXXXX</key>
    <array>
      <string>com.sn360.endpoint-security</string>
      <string>com.sn360.device-control-dext</string>
    </array>
  </dict>
  <key>AllowedSystemExtensionTypes</key>
  <dict>
    <key>XXXXXXXXXX</key>
    <array>
      <string>EndpointSecurityExtension</string>
      <string>DriverExtension</string>
    </array>
  </dict>
</dict>
```

The MDM payload is shipped via the SN360 Apple DDM connector once
the dext team-id is registered.

### 3.5 Toolchain prerequisites

| Item | Where it lives |
|---|---|
| Xcode 16 + Command Line Tools | Build server (macOS) only |
| Apple Developer Program organisation membership | Org account |
| Apple Developer ID + provisioning profile | Apple ID + provisioning portal |
| DriverKit + USB-transport entitlements | Apple-issued |
| Endpoint Security client entitlement | Apple-issued |
| `notarytool` (ships with Xcode) | Build server |

---

## 4. Linux: eBPF tracing

### 4.1 Architecture

A set of eBPF tracing programs attached to a small number of
kernel tracepoints / kprobes:

| Tracepoint / kprobe | Subsystem |
|---|---|
| `sched_process_exec`, `sched_process_exit`, `sched_process_fork` | Process telemetry |
| `inet_csk_accept`, `tcp_v4_connect`, `tcp_v6_connect`, `udp_sendmsg` | Network telemetry |
| `vfs_open`, `vfs_unlink` (filtered on `/etc/shadow`, `/proc/kcore`, etc.) | Identity monitor |
| `sys_enter_openat` (filtered on USB device paths) | Device-control USB hooks |

Each program writes a fixed-size struct into a **per-CPU perf
buffer** (legacy kernels) or **ring buffer** (kernel ≥ 5.8). The
user-mode agent attaches via `aya` (Rust eBPF loader, MIT/Apache-2.0)
and reads the buffer through `tokio::io`.

```
+---------------------------+
| sda-agent (user mode)     |
|   sda_pal::kernel::linux  |
|     bpf_perf_event reader |
+-------------+-------------+
              ^
              | perf / ring buffer
              |
+-------------+-------------+
| eBPF program: process,    |
| network, identity, USB    |
+-------------+-------------+
              ^
              | kprobe / tracepoint
              |
+---------------------------+
| Linux kernel ≥ 5.8        |
+---------------------------+
```

### 4.2 Runtime detection and fallback

The user-mode agent probes kernel support at startup:

1. `uname -r` — require ≥ 5.8 for ring-buffer programs.
2. Attempt `bpf(BPF_PROG_LOAD, ...)` for a no-op program. If it
   returns `EPERM` (most likely cause: missing `CAP_BPF`), or any
   other error, attach fails.
3. On attach failure the supervisor falls back to the cn_proc /
   audit user-mode channels and logs a single `INFO` message
   `kernel-linux: eBPF unavailable, using user-mode telemetry`.

### 4.3 Build / package

The eBPF programs are compiled with `clang -target bpf -O2 -g
-c` into `.bpf.o` objects and shipped alongside the agent under
`/usr/lib/sn360-desktop-agent/bpf/*.bpf.o`. They are **not** loaded
unless `modules.kernel.linux.enabled: true`.

```bash
# Build the eBPF programs (requires clang ≥ 14 + libbpf-dev)
make -C bpf all

# Package
install -m 0644 bpf/*.bpf.o packaging/linux/payload/usr/lib/sn360-desktop-agent/bpf/
```

The agent installer's post-install script does **not** load the
programs; they are loaded on demand by the agent on first start
after the feature flag is enabled.

### 4.4 CAP_BPF and Lockdown

The agent's systemd unit grants `CAP_BPF` + `CAP_PERFMON`
(kernel ≥ 5.8) or `CAP_SYS_ADMIN` (older kernels). On systems with
`lockdown=integrity` or `lockdown=confidentiality` the unsigned
eBPF programs will fail to load; the agent falls back to user-mode
telemetry and emits a vitals warning so the operator can decide
whether to sign the programs.

### 4.5 Toolchain prerequisites

| Item | Where it lives |
|---|---|
| `clang ≥ 14`, `llvm`, `libbpf-dev` | Build server |
| `bpftool` | Build server (for verification) |
| `aya` (workspace dep, feature-gated) | `Cargo.toml` |
| Kernel ≥ 5.8 (ring buffer) or ≥ 4.18 (perf buffer) | Target host |

---

## 5. Failure-mode handling

The same failure-mode contract applies across all three platforms:

| Failure | Behaviour |
|---|---|
| Kernel-mode component not present / not approved | `try_attach` returns `AttachError::NotPresent`; supervisor logs once at `INFO`; user-mode channel continues |
| Kernel-mode component crashed | IPC connection returns peer-disconnect; supervisor marks channel detached, retries every 30 s, user-mode channel resumes |
| Schema drift (kernel emits unknown variant) | Per-line `serde_json::Error` logged at `DEBUG`; line dropped; supervisor never panics |
| Tamper detection trips (binary mismatch) | Kernel component refuses next IPC connection; agent emits an `AgentVitals` warning; user-mode falls back |

The user-mode channel is the floor. The kernel-mode tier is purely
additive — it cannot make telemetry *worse*.

---

## 6. Rollback

| Platform | Rollback path |
|---|---|
| Windows | `pnputil /delete-driver <oem-id> /uninstall /force`. The filter driver's `IRP_MJ_PNP` handler also enforces a panic budget — three consecutive bug-checks downgrade to "filter passes through every IRP" so an in-the-field bug self-disables before storming a fleet. |
| macOS | `OSSystemExtensionRequest.deactivationRequest`. The dext's `Start()` handler enforces a per-launch panic budget (3 panics → permanent passthrough until next OS upgrade). MDM can also force deactivation by removing the dext from `AllowedSystemExtensions`. |
| Linux | Set `modules.kernel.linux.enabled: false` and `systemctl restart sn360-desktop-agent`. The eBPF programs are detached and the user-mode channel resumes. |

In every case the user-mode channel resumes seamlessly; downstream
consumers (LDE, MDM, response) do not see a discontinuity.

---

## 7. Test plan

### 7.1 CI (every push)

- Mock kernel channels at `crates/sda-pal/src/kernel/*` exercise
  the line-delimited JSON parsers against representative event
  streams.
- Unit tests assert: parser does not panic on malformed lines,
  parser tolerates blank lines, parser ignores unknown JSON keys,
  parser preserves event order, schema matches the user-mode
  `KernelEvent` variants.

### 7.2 Per-platform integration

| Platform | Integration |
|---|---|
| Windows | HLK USB-filter playlist + Mass-Storage playlist on x64, ARM64, Hyper-V Generation 2 |
| macOS | Manual on macOS dev VMs: Full Security boot, dext loads silently after MDM profile, USB attach/detach storm, agent kill+restart |
| Linux | `bcc-tools`-based smoke tests on kernel 5.8 / 6.1 / 6.6; verify the eBPF programs load, attach to tracepoints, and the user-mode reader receives events |

### 7.3 Stress (all platforms)

- 10 000 attach / detach cycles with random `Decision` shapes.
- 24-hour soak at 10 events/sec with periodic bundle reloads.
- Agent killed mid-operation: closed-by-default fallback engages;
  re-attach after agent restart succeeds.
- Binary swap: kernel-mode component rejects the next IPC
  connection until signature passes.
