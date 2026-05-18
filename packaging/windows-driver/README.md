# SN360 EDR Minifilter Driver Packaging

This directory contains the Windows build + signing pipeline for the
optional EDR minifilter driver.

The minifilter driver replaces the user-mode ETW process / network
backends with tamper-resistant kernel-mode callbacks
(`PsSetCreateProcessNotifyRoutineEx` + WFP). It is **optional** —
agents without the signed driver continue to use the default
user-mode backends. See [`docs/kernel-drivers.md`](../../docs/kernel-drivers.md)
for the full driver overview.

## Scripts

- [`build-driver.ps1`](./build-driver.ps1) — invokes msbuild via the
  WDK + Visual Studio Build Tools toolchain. Requires a manually
  installed WDK and a `sda-edr-minifilter.vcxproj` generated from the
  WDK template wizard (see the Windows section of
  [`docs/kernel-drivers.md`](../../docs/kernel-drivers.md)).

- [`sign-driver.ps1`](./sign-driver.ps1) — applies the local
  attestation signature with the team's EV code-signing certificate
  and then prints the manual WHCP submission steps. WHQL
  cross-signing happens on Microsoft infrastructure and cannot be
  fully automated.

## CI posture

These scripts are **never** executed in the standard CI matrix:

- The WDK is a multi-gigabyte download not present on Linux / macOS
  CI runners.
- The EV cert lives in HSM on the release manager's signing box;
  CI does not have access.
- WHCP submissions require manual interaction with the partner
  portal.

The user-mode agent crate [`sda-pal`](../../crates/sda-pal) ships a
mock kernel channel (see
[`crates/sda-pal/src/kernel/windows.rs`](../../crates/sda-pal/src/kernel/windows.rs))
that simulates the kernel→user-mode named-pipe contract. CI exercises
the pipe-record parser end-to-end against the mock so the user-mode
side stays under test even though the kernel side does not.

## Build pipeline overview

1. **Scaffold the driver.** Use the WDK kernel-mode minifilter
   template wizard in Visual Studio to generate
   `sda-edr-minifilter.vcxproj`. Drop it under
   `packaging/windows-driver/sda-edr-minifilter/`.
2. **Author callbacks.** The driver registers
   `PsSetCreateProcessNotifyRoutineEx` (process create/exit) and a
   WFP callout at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` (outbound network).
   Each callback marshals the relevant fields into a single-line
   JSON object matching `sda_pal::kernel::KernelEvent` and writes it
   to the kernel-mode side of the `\\.\\pipe\\sn360-kernel` named
   pipe.
3. **Build.** Run `.\build-driver.ps1` from an elevated Developer
   PowerShell.
4. **Locally sign.** Run `.\sign-driver.ps1 -SysFile … -CatalogFile …
   -CertSubject "SN360 Kernel Code Signing"`.
5. **Submit to WHCP.** Follow the on-screen instructions; Microsoft
   typically returns a cross-signed CAB within 1-3 business days.
6. **Bundle.** The agent MSI build (`packaging/windows/build-msi.ps1`)
   has a placeholder copy step for the cross-signed driver — see the
   WiX `Component` group named `sn360EdrMinifilter` in
   [`packaging/windows/sda-agent.wxs`](../windows/sda-agent.wxs) once
   it is wired in.

## Reference

- [`docs/kernel-drivers.md`](../../docs/kernel-drivers.md) —
  canonical reference for the optional kernel-mode telemetry
  channels (Windows minifilter, macOS SystemExtension, Linux eBPF).
- [Microsoft: Driver signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing)
