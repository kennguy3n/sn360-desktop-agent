# Changelog

All notable changes to SN360 Desktop Agent (SDA) are documented
here. This project follows
[Semantic Versioning](https://semver.org) once it reaches 1.0;
pre-1.0 releases may introduce breaking config changes at each
minor bump.

## [Unreleased]

### Added

- **EDR — memory scanning and fileless detection.** New
  `sda-pal::MemoryScanner` trait with Linux `/proc/<pid>/maps`
  enumeration + bounded `pread` on `/proc/<pid>/mem` (requires
  `CAP_SYS_PTRACE`), Windows `VirtualQueryEx` +
  `ReadProcessMemory` over `PROCESS_QUERY_INFORMATION |
  PROCESS_VM_READ` handles (requires `SeDebugPrivilege`), and
  macOS `task_for_pid` + `mach_vm_region` +
  `mach_vm_read_overwrite` (requires
  `com.apple.security.cs.debugger` entitlement). New
  `sda-memory-scanner` crate runs the periodic RWX-region scan
  loop with CPU-budget gating, `only_when_idle_below_cpu_pct`
  deferral, and a hard self-pid exclusion enforced at both the
  trait and rule-engine level. Bounded byte slices feed the
  in-memory YARA scanner; matches emit `MemoryScanAlert` with
  `alert_type: "yara_match"`. Optional `amsi` Cargo feature
  registers an `IAmsiStream` provider on Windows so AMSI-scanned
  PowerShell / VBScript content also flows through the same alert
  path with `alert_type: "amsi_match"`. New hermetic E2E suite
  `make e2e-memory-scan`. See
  [`docs/edr.md`](./docs/edr.md#memory-scanning).
- **EDR — identity attack detection.** New `sda-identity-monitor`
  crate with three real detectors: Windows LSASS access via
  `Microsoft-Windows-Threat-Intelligence` ETW + `NtOpenProcess`
  instrumentation (MITRE `T1003.001`), Linux `/etc/shadow` access
  (FIM-fed, `T1003.008`) + `/proc/kcore` access (audit-fed,
  `T1003`), and macOS keychain access by non-Apple-signed
  binaries via Endpoint Security `ES_EVENT_TYPE_NOTIFY_OPEN` on
  `/Library/Keychains/*` and `~/Library/Keychains/*`
  (`T1555.001`). System-principal filtering happens at the module
  publish boundary so the same provider can feed the IDS pipeline
  and audit logs. Emits `IdentityAlert`. New hermetic E2E suite
  `make e2e-identity`.
- **EDR — DLP content inspection.** New `sda-dlp` crate ships the
  baseline regex pattern set (`pii.ssn` US SSN, `pii.uk_ni` UK
  National Insurance, `pci.pan_luhn` payment card PAN with Luhn
  validation) and a `DlpScanner` that returns matches as
  category + byte offset + length + Blake3 fingerprint of the
  surrounding 32-byte window — never the matched bytes
  themselves. File-write inspection subscribes to
  `FileCreated` / `FileModified`, performs a bounded read (1 MiB
  cap), and emits `LocalDetectionAlert` with `rule_type: "dlp"`.
  Monitor mode publishes `medium`-severity findings; Enforce mode
  escalates to `high` so `sda-active-response` can quarantine.
  Optional `dlp-clipboard` Cargo feature provides a
  `ClipboardProvider` trait and `MockClipboardProvider` for X11 /
  Wayland / Win32 / `NSPasteboard` taps. New hermetic E2E suite
  `make e2e-dlp`.
- **Optional kernel-mode telemetry.** New platform-agnostic
  `sda-pal::kernel` module defines a `KernelEvent` enum and a
  `KernelChannel` trait abstraction over kernel→user-mode
  transports. Per-platform mock channels —
  `MockWindowsKernelChannel` (named-pipe `\\.\pipe\sn360-kernel`
  for the WDK minifilter), `MockMacosKernelChannel` (XPC mach
  port `com.sn360.endpoint-security.xpc` for the signed
  SystemExtension), and `MockLinuxKernelChannel` (eBPF
  perf-buffer record parser with `detect_ebpf_capability()` /
  `parse_kernel_version_at_least()` runtime fallback to cn_proc /
  audit when the kernel is older than 5.8) — are gated behind
  `kernel-windows`, `kernel-macos`, and `kernel-linux-ebpf` Cargo
  features (all off by default). Production pipelines and
  packaging are documented in
  [`docs/kernel-drivers.md`](./docs/kernel-drivers.md); the
  Windows build / sign automation lives in
  [`packaging/windows-driver/`](./packaging/windows-driver/).
- **EDR — process telemetry.** New `sda-pal::ProcessMonitor`
  trait with Linux `cn_proc` netlink + `/proc` enrichment,
  Windows ETW `Microsoft-Windows-Kernel-Process`, macOS Endpoint
  Security framework, plus `MockProcessMonitor` for hermetic CI.
  New `sda-process-monitor` crate adds parent-chain enrichment,
  bounded mpsc + drop-oldest back-pressure, and a
  `parent_chain_regex` matcher extension to the behavioural rule
  DSL (Office→PowerShell, wmiprvse→rundll32, non-system
  `lsass.exe` access). New hermetic E2E suite
  `make e2e-process-telemetry`.
- **EDR — network and DNS telemetry, host isolation.** Three new
  PAL traits — `NetworkMonitor` (Linux `/proc/net/*` poller with
  `to_ne_bytes()` endian-correct IP parsing, Windows ETW
  `Microsoft-Windows-Kernel-Network`, macOS
  `NEFilterDataProvider`), `DnsMonitor` (Linux journalctl /
  systemd-resolved tap, Windows ETW
  `Microsoft-Windows-DNS-Client`, macOS `NEDNSProxyProvider`),
  and `HostIsolation` (Linux nftables `sn360_isolation` table,
  Windows `netsh advfirewall` + WFP, macOS `pfctl` anchor
  `com.sn360.host_isolation`) — plus two new module crates,
  `sda-network-monitor` (bounded LRU-ish dedup ring +
  4-per-second UDP flow sampler) and `sda-host-isolation`
  (10-step `SignedActionJob` validation, allow-list construction,
  `IsolateHost` / `UnisolateHost` `ActionKind` variants). New
  hermetic E2E suites `make e2e-network-telemetry`,
  `make e2e-host-isolation`.
- **Local Detection Engine — default on.** The TRDS hot-reload
  pipeline (`crates/sda-local-detection/src/trds_client.rs`) is
  now live with Ed25519 signature verification against a pinned
  key rotation set and atomic `Arc<ArcSwap<DetectionPipeline>>`
  swap. An embedded default bundle ships with the agent;
  `LocalDetectionConfig::default().enabled` is now `true`. See
  the "Migration" note below for upgrade impact. New hermetic E2E
  suite `make e2e-lde-hotreload`.
- **Desktop MDM.** New `sda-mdm` crate (default **on**) ships the
  auto-remediation supervisor with 24h debounce, one-time-per-boot
  recovery-key escrow with ChaCha20-Poly1305 + per-device
  HKDF-SHA256 wrapping key + Ed25519 evidence signing, and
  battery-aware OS-patch orchestration; the dual-control remote
  wipe handler, remote lock, and lost-mode enter/exit flow with
  an IP-geolocation reporter that attaches `last_known_location`
  to `AgentVitals`; and the Ed25519-verified declarative
  configuration profile schema with a `notify`-based bundle
  watcher and `ConfigProfileTampered` finding. New `FindingKind`
  variants (`DiskEncryptionOff`, `FirewallOff`, `ScreenLockOff`,
  `OsPatchOverdue`, `RecoveryKeyNotEscrowed`, `DeviceLost`,
  `ConfigProfileTampered`), new `ActionKind` variants
  (`RemoteWipe`, `RemoteLock`, `EnterLostMode`, `ExitLostMode`,
  `EscrowRecoveryKey`, `InstallOsUpdate`, `ApplyConfigProfile`,
  `EnableDiskEncryption`, `EnableFirewall`, `SetScreenLock`), new
  `MessageType` variants, and two new `JobRefused` variants
  (`WipeRequiresDualControl`, `LocalKeyNotAuthorisedForAction`).
  The signed-job validator in `sda-device-control` gains two
  steps for dual-control wipe enforcement and a local-ephemeral
  key allow-list. New hermetic E2E suites `make e2e-mdm`,
  `make e2e-mdm-actions`, `make e2e-mdm-profile`. See
  [`docs/desktop-mdm.md`](./docs/desktop-mdm.md).
- **Rootcheck — content-based inspection.** New
  `sda-rootcheck::content_checks` module reads
  `/etc/ld.so.preload`, `/etc/crontab`, and `/etc/hosts` and
  flags indicators that don't show up in file-existence
  signatures: LD_PRELOAD entries outside the benign allow-list,
  `curl … | bash` and `/dev/tcp/` reverse-shell patterns in
  cron, and redirections of security-update domains (e.g.
  `update.microsoft.com`) to non-loopback IPs. Wired into the
  rootcheck sweep via `tokio::task::spawn_blocking`.
- **Cross-platform hidden-process detection.** `hidden_process::scan`
  now has three backends: `/proc` + `kill(pid, 0)` on Linux,
  `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_ALL)` + `kill(pid, 0)`
  on macOS, and `CreateToolhelp32Snapshot` / `Process32FirstW` /
  `Process32NextW` + `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
  ...)` on Windows.
- **Linux user-idle detection via `loginctl`.**
  `PowerMonitor::user_idle_duration()` now returns a real
  `Some(Duration)` on systemd hosts by reading the
  `IdleSinceHint` property of the current session via
  `loginctl show-session self`. A pure `parse_idle_since_hint()`
  helper is exported for unit testing; the function returns
  `None` on headless or non-systemd hosts without errors. This
  unblocks `PowerProfile::IdleAC` / `PowerProfile::BatteryIdle`
  on Linux.
- **Release workflow (`.github/workflows/release.yml`).**
  Tag-triggered (`v*`) multi-OS build matrix that runs
  `make release` + `make deb rpm` / `make pkg` / `make msi` on
  `ubuntu-latest` / `macos-latest` / `windows-latest`, uploads
  every artefact, computes per-file `SHA256SUMS`, and drafts a
  GitHub Release with the `[Unreleased]` section of this
  changelog as the body. The draft is not auto-published;
  maintainers sign / notarise out-of-band per
  [`docs/release-process.md`](./docs/release-process.md) and
  promote manually.
- **Nightly `cargo-fuzz` CI job.** `.github/workflows/ci.yml`
  `nightly-fuzz` runs `cargo +nightly fuzz run` against
  `protocol_decode`, `protocol_decompress`,
  `msgpack_event_decode`, and `rule_store_msgpack` for 5 minutes
  per target on the cron schedule.
- **Release runbook
  ([`docs/release-process.md`](./docs/release-process.md)).**
  Step-by-step for cutting, signing (Linux apt/yum keys, macOS
  Developer ID + notarisation, Windows EV code-sign), promoting,
  and rolling back a release.
- **Enhanced protocol (opt-in).** TLS 1.3 transport (`rustls`,
  TLS 1.3 only, optional CA bundle + SHA-256 cert pinning),
  MessagePack event serialisation (`rmp-serde`), and HTTP/2
  transport with ALPN `h2`. All three are individually
  toggleable under `server.enhanced` and default **off** to stay
  compatible with legacy 4.x managers.
- **E2E compatibility harness against legacy 4.7.5 managers.**
  `tests/docker-compose-v4.7.yml` +
  `tests/scripts/run-compat-e2e.sh` + `make e2e-compat` run the
  standard 14-assertion suite against an older v4.x manager to
  catch protocol drift.
- **Platform CI matrix expansion.** `ubuntu-22.04`,
  `ubuntu-24.04`, `macos-13`, `macos-14`, `windows-2022`. Fedora
  and Arch are covered by the manual checks in
  [`docs/platform-testing.md`](./docs/platform-testing.md).
- **Performance regression gate.**
  `tests/scripts/benchmark-regression.sh` + `make benchmark-ci`
  fails CI if idle RSS > 15 MB, idle CPU > 0.1 %, binary > 7 MB,
  or FIM burst peak > 3 %. Runs nightly on CI with artifact
  upload.
- **Dependency audit gate.** `cargo audit --deny warnings` is
  now a required CI check.
- **Fuzzing harness.** Standalone `fuzz/` crate with cargo-fuzz
  targets for `WazuhMessage::decode`, `decompress_payload`,
  `MessagePackSerializer::decode_event`, and
  `RuleBundle::from_msgpack`. Setup and coverage goals are
  documented in [`docs/security.md`](./docs/security.md).
- **Documentation set.** `docs/user-guide.md`,
  `docs/admin-guide.md`, `docs/architecture.md`,
  `docs/configuration-reference.md`, `docs/edr.md`,
  `docs/device-control.md`, `docs/desktop-mdm.md`,
  `docs/kernel-drivers.md`, `docs/security.md`,
  `docs/licensing.md`, `docs/benchmarks.md`,
  `docs/platform-testing.md`, `docs/release-process.md`,
  `docs/integration.md`, and the canonical wire-protocol spec
  under `docs/wire-protocols/`.

### Changed

- **`LocalDetectionConfig::default().enabled` flipped from
  `false` to `true`.** Fresh installs ship the local detection
  engine live with the embedded baseline rule bundle. Existing
  installs upgrading in place keep their explicit
  `local_detection.enabled` value if set; configs without a
  `local_detection` block (or with `local_detection: {}`) now
  receive the new default. Set `local_detection.enabled: false`
  explicitly to opt out.
- `ServerConfig::default` now includes
  `enhanced: EnhancedProtocolConfig::default()` so older configs
  round-trip through serde without a "missing field" error.

### Fixed

- **Updater re-download loop.** `sda_updater::run_once` returns
  `Option<String>` and `sda_updater::run` updates its in-memory
  `current_version` after each install, so the next manifest
  fetch does not retry the same version forever.
- **Version-comparison trailing-zero bug.**
  `sda_updater::checker::is_newer` pads both parsed versions to
  the same length before comparing, so `is_newer("0.2.0", "0.2")
  == false` and `is_newer("0.2.1", "0.2") == true`.
- **Linux abstract-socket handling in the tamper watchdog.**
  `sda_agent::tamper::notify` detects `@`-prefixed paths and
  uses `std::os::linux::net::SocketAddrExt::from_abstract_name`;
  non-Linux callers fall through to the filesystem socket path.
- **32-bit Linux ioctl constants.** `FS_IOC_GETFLAGS` /
  `FS_IOC_SETFLAGS` are derived from
  `std::mem::size_of::<libc::c_long>()` so 32-bit builds encode
  the correct size field.
- **Windows MSI default binary path.**
  `packaging/windows/build-msi.ps1` defaults to
  `target\release\sda-agent.exe` instead of the target-triple
  path, matching `make release`.
- **WiX NeverOverwrite on the config component.**
  `packaging/windows/sda-agent.wxs` now carries
  `NeverOverwrite="yes"` so operator edits to `config.yaml`
  survive upgrades.
- **systemd ReadOnlyPaths dead code.** The misleading
  `ReadOnlyPaths=/etc/sn360-desktop-agent` was removed from
  `packaging/systemd/sda-agent.service`; a comment explains that
  the config directory is intentionally writable so enrolment
  can persist `client.keys`.

## [0.1.0] — initial public preview

The first tagged preview of the agent. The repository carries
detailed per-module configuration and architectural reference under
[`docs/`](./docs/). Highlights:

- Cross-platform Rust agent with separate crates per module and a
  unified Platform Abstraction Layer (`sda-pal`).
- File Integrity Monitoring, log collection, system inventory,
  SCA, active response, rootkit detection.
- SN360 native protocol (TLS 1.3, MessagePack, HTTP/2) and
  optional legacy 4.x manager adapter.
- Installer / packaging for Linux (.deb, .rpm), macOS (.pkg), and
  Windows (.msi), with a hardened systemd unit on Linux.
- Self-update with signed manifest fetch, atomic swap, and
  rollback on smoke-test failure.
- Privilege separation and tamper protection with a watchdog
  restart loop.
