# EDR Parity — Windows Productisation

This document describes the build, signing, and distribution pipeline
for the optional EDR minifilter driver introduced in Phases E6.1 and
E6.2 of the EDR Parity workstream.

The minifilter is the *tamper-resistant* replacement for the user-mode
ETW process / network backends shipped in Phase E1. Agents that ship
*without* the signed driver continue to operate on ETW — they simply
forfeit the resistance to user-mode-only adversaries.

## High-level architecture

```
+---------------------------------+
|        Kernel mode              |
|                                 |
|  +---------------------------+  |
|  | sda-edr-minifilter.sys    |  |
|  |  PsSetCreateProcessNotify |  |
|  |  WFP ALE_AUTH_CONNECT_V4  |  |
|  +-------------+-------------+  |
|                |  serialise JSON|
|                |  KernelEvent   |
+----------------|----------------+
                 |  named pipe
                 |  \\.\pipe\sn360-kernel
                 v
+---------------------------------+
|        User mode (agent)        |
|                                 |
|  sda_pal::kernel::windows::     |
|     WindowsKernelChannel        |
|                                 |
|     -> ProcessMonitor stream    |
|     -> NetworkMonitor stream    |
+---------------------------------+
```

The wire format is **line-delimited JSON** matching
[`sda_pal::kernel::KernelEvent`](../../crates/sda-pal/src/kernel/mod.rs).
A user-mode parser
[`sda_pal::kernel::windows::parse_pipe_records`](../../crates/sda-pal/src/kernel/windows.rs)
is exercised under CI against a mock pipe. The kernel side itself is
**not** built in CI — see the toolchain section below.

## Toolchain requirements

| Tool                    | Version              | Purpose                |
|-------------------------|----------------------|------------------------|
| Windows Driver Kit (WDK)| 10.0.22621 or newer  | Headers + msbuild plugins |
| Visual Studio Build Tools | 2022                | `msbuild.exe`          |
| EV code-signing certificate | n/a (HSM-held)   | Local attestation sign |
| Hardware Dev Center account | n/a              | WHCP cross-signing submission |
| `signtool.exe`          | Ships with WDK       | Signing automation     |

CI runners cannot install the WDK and do not have access to the EV
cert. The signing pipeline runs on a dedicated release-manager
workstation.

## Driver scaffolding

The `sda-edr-minifilter.vcxproj` is **not** committed because it is
generated from the WDK's `File → New → Driver` template wizard:

1. Open Visual Studio with the WDK installed.
2. `File → New → Project → Windows Driver → Filter Driver: Filesystem
   Minifilter`.
3. Name the project `sda-edr-minifilter`. Place the folder under
   `packaging/windows-driver/sda-edr-minifilter/`.
4. Replace the template `Filter.c` with a thin shim that registers:
   - `PsSetCreateProcessNotifyRoutineEx` — emits
     `KernelEvent::ProcessCreated` / `ProcessExited` to the pipe.
   - A WFP callout at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` — emits
     `KernelEvent::NetworkConnect` to the pipe.
5. Commit the resulting `sda-edr-minifilter.vcxproj`,
   `sda-edr-minifilter.inf`, and the source files.

The kernel-side serialiser MUST emit one JSON object per line. The
schema is the `serde`-derived shape of
[`KernelEvent`](../../crates/sda-pal/src/kernel/mod.rs); any new
variant must be added on the user-mode side first so the CI parser
catches schema drift.

## Build pipeline

```powershell
# From an elevated Developer PowerShell:
cd packaging\windows-driver
.\build-driver.ps1 -Configuration Release -Platform x64
```

The script auto-detects the WDK and the MSBuild path via `vswhere`.
Output lands in `target/windows-driver/`.

## Signing pipeline

### Stage 1 — local attestation signature

```powershell
.\sign-driver.ps1 `
    -SysFile     target\windows-driver\sda-edr-minifilter.sys `
    -CatalogFile target\windows-driver\sda-edr-minifilter.cat `
    -CertSubject "SN360 Kernel Code Signing"
```

This applies a SHA-256 signature with the team's EV cert and a
RFC 3161 timestamp.

### Stage 2 — WHCP submission

The signing script prints the manual steps:

1. Bundle the `.sys` + `.cat` into a CAB.
2. Sign in to `https://partner.microsoft.com/dashboard/hardware/driver/New`.
3. Upload the CAB, request **Attestation Signing** (the path for
   minifilter drivers that pass the static-analysis HLK tests but
   don't need full HLK runs).
4. Microsoft cross-signs the catalog with their root and returns a
   `.cab`.
5. The cross-signed catalog replaces the locally-signed one in the
   agent MSI build.

### Stage 3 — packaging into the MSI

`packaging/windows/build-msi.ps1` references a WiX Component group
named `sn360EdrMinifilter`. Drop the cross-signed `.sys`, `.cat`, and
`.inf` into `packaging/windows/driver-staging/`; the MSI build copies
them into `%ProgramFiles%\SN360\drivers\` and the agent service
loads them via `fltmc load sda-edr-minifilter` on first boot.

## Runtime contract

The agent supervisor calls
[`sda_pal::kernel::windows::attach_to_named_pipe`](../../crates/sda-pal/src/kernel/windows.rs)
at startup. Without the `kernel-windows` feature this returns
`AttachError::NotPresent` and the supervisor falls back to the
user-mode ETW backend. With the feature enabled and the driver
loaded, the channel returns event streams that flow into the same
`ProcessMonitor` / `NetworkMonitor` event bus arms as the ETW path.

## Failure mode handling

- **Driver not loaded**: `attach_to_named_pipe` returns
  `NotPresent`. Logged once at startup at `INFO`. ETW backend
  continues running.
- **Driver crashed mid-run**: the named-pipe read returns EOF. The
  channel is marked detached, the supervisor re-attaches every 30s,
  and in the interim the ETW backend resumes.
- **Schema drift**: per-line `serde_json::Error` is logged and the
  line is dropped. The supervisor never panics on a malformed kernel
  record.

## Open questions / future work

- The minifilter currently emits process + network events only. A
  follow-up phase can add file-write callbacks for FIM tamper
  resistance.
- WHCP attestation signing is sufficient for the current driver
  scope. If we later want to ship a driver that interposes on
  privileged paths (e.g. anti-tampering for the agent service), we
  need to upgrade to full HLK certification.
