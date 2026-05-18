# Changelog

All notable changes to SN360 Desktop Agent (SDA) are documented
here. This project follows
[Semantic Versioning](https://semver.org) once it reaches 1.0;
pre-1.0 releases may introduce breaking config changes at each
minor bump.

## [Unreleased]

### Added

- **ShieldNet EDR Parity — Phases E0–E3 (agent-side).**
  Agent-side delivery of the EDR Parity workstream defined in
  [`docs/edr-parity/PROGRESS.md`](./docs/edr-parity/PROGRESS.md).
  Phase E0 (architecture & schema) adds 8 new `EventKind` variants
  in `crates/sda-event-bus/src/event.rs` (`ProcessCreated`,
  `ProcessTerminated`, `ImageLoaded`, `NetworkConnection`,
  `DnsQuery`, `MemoryScanAlert`, `HostIsolationStateChanged`,
  `IdentityAlert`) following the existing `{ payload: String }`
  canonical-JSON pattern, matching `MessageType` variants and
  encoder arms in `crates/sda-comms/src/protocol.rs` under the
  `legacy-siem` feature gate, and the clean-room EDR posture note
  in `deny.toml` + [`docs/security-audit.md`](./docs/security-audit.md).
  Phase E1 (process telemetry) ships a new `sda-pal::ProcessMonitor`
  trait with Linux `cn_proc` netlink + `/proc` enrichment, Windows
  ETW `Microsoft-Windows-Kernel-Process`, macOS Endpoint Security
  framework, plus `MockProcessMonitor` for hermetic CI, and a new
  `crates/sda-process-monitor` module crate with parent-chain
  enrichment, bounded mpsc + drop-oldest back-pressure, and a
  `parent_chain_regex` matcher extension to the behavioural rule
  DSL (Office→PowerShell, wmiprvse→rundll32, non-system
  `lsass.exe` access). Phase E2 (LDE maturity + default-ON) lands
  the real TRDS hot-reload pipeline
  (`crates/sda-local-detection/src/trds_client.rs`) with Ed25519
  signature verification against a pinned key rotation set, atomic
  `Arc<ArcSwap<DetectionPipeline>>` swap, an embedded default
  bundle (`crates/sda-local-detection/src/default_bundle.rs`), and
  **flips `LocalDetectionConfig::default().enabled` from `false`
  to `true`** in `crates/sda-core/src/config.rs` — see "Migration"
  below for upgrade impact. Phase E3 (network telemetry + host
  isolation) ships three new PAL traits — `NetworkMonitor` (Linux
  `/proc/net/*` poller with `to_ne_bytes()` endian-correct IP
  parsing, Windows ETW `Microsoft-Windows-Kernel-Network`, macOS
  `NEFilterDataProvider`), `DnsMonitor` (Linux
  journalctl / systemd-resolved tap, Windows ETW
  `Microsoft-Windows-DNS-Client`, macOS `NEDNSProxyProvider`), and
  `HostIsolation` (Linux nftables `sn360_isolation`, Windows
  `netsh advfirewall` + WFP, macOS `pfctl` anchor
  `com.sn360.host_isolation`) — plus two new module crates,
  `sda-network-monitor` (bounded LRU-ish dedup ring +
  4-per-second UDP flow sampler) and `sda-host-isolation` (10-step
  `SignedActionJob` validation pipeline, allow-list construction
  with control-plane + loopback + DNS + extras, `IsolateHost` /
  `UnisolateHost` `ActionKind` variants). The LDE
  `handle_event` catch-all is replaced with explicit arms for
  every new variant; remote-IP and query-name IOC matching flows
  through the existing `pipeline.iocs` backends without new
  rule-engine code. Four new hermetic E2E suites
  (`make e2e-process-telemetry`, `make e2e-lde-hotreload`,
  `make e2e-network-telemetry`, `make e2e-host-isolation`)
  exercise the full pipeline against mock PAL implementations;
  combined live counts are 41 new agent-side E2E tests plus 178
  new unit tests. Server-side ⚙️ tasks (E1.9, E1.10, E2.5, E3.13,
  E3.14) remain tracked separately in
  [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
- **ShieldNet Desktop MDM — Phases M1–M3 (agent-side).**
  New `crates/sda-mdm` crate provides the agent-side surface for
  the Desktop MDM workstream (default **on**). Phase M1 lands the
  `MdmProvider` PAL trait with Windows / macOS / Linux back-ends
  (`crates/sda-pal/src/mdm.rs`), the auto-remediation supervisor
  with 24h debounce (`auto_remediate.rs`), one-time-per-boot
  recovery-key escrow with ChaCha20-Poly1305 + per-device
  HKDF-SHA256 wrapping key + Ed25519 evidence signing
  (`recovery_key.rs`), and battery-aware OS-patch orchestration
  (`os_patch.rs`). Phase M2 lands the dual-control remote wipe
  handler (`wipe.rs`), remote lock (`lock.rs`), and the lost-mode
  enter/exit flow with an IP-geolocation reporter that attaches
  `last_known_location` to `AgentVitals` (`lost_mode.rs`,
  `crates/sda-core/src/location.rs`,
  `crates/sda-agent-vitals/`). Phase M3 lands the Ed25519-verified
  declarative configuration profile schema, `notify`-based bundle
  watcher, and `ConfigProfileTampered` finding (`config_profile.rs`).
  New `FindingKind` variants (`DiskEncryptionOff`, `FirewallOff`,
  `ScreenLockOff`, `OsPatchOverdue`, `RecoveryKeyNotEscrowed`,
  `DeviceLost`, `ConfigProfileTampered`), new `ActionKind`
  variants (`RemoteWipe`, `RemoteLock`, `EnterLostMode`,
  `ExitLostMode`, `EscrowRecoveryKey`, `InstallOsUpdate`,
  `ApplyConfigProfile`, `EnableDiskEncryption`, `EnableFirewall`,
  `SetScreenLock`), new `MessageType` variants
  (`MdmWipeResult`, `MdmLockResult`, `MdmLostModeEntered`,
  `MdmLostModeExited`, `MdmRecoveryKeyEscrowed`,
  `MdmOsUpdateResult`, `MdmConfigProfileApplied`,
  `MdmAutoRemediationResult`), and new `JobRefused` variants
  (`WipeRequiresDualControl`, `LocalKeyNotAuthorisedForAction`)
  ride the existing alert / evidence pipeline unchanged. The
  signed-job validator in `sda-device-control` gains step 11
  (dual-control wipe enforcement: `signatures.len() >= 2` with
  distinct approvers) and step 12 (local-ephemeral-key allow-list:
  only `EnableDiskEncryption` / `EnableFirewall` / `SetScreenLock`
  with `recommendation_id == None`). The `MdmConfig` schema
  defaults `enabled = true` and `auto_remediate.*: true` — this is
  intentionally different from Device Control's default-off
  posture. PR [#20](https://github.com/kennguy3n/sn360-desktop-agent/pull/20).
- **Rootcheck content-based inspection (P1.4).**
  New `crates/sda-rootcheck/src/content_checks.rs` module reads
  `/etc/ld.so.preload`, `/etc/crontab`, and `/etc/hosts` and flags
  indicators that don’t show up in file-existence signatures:
  LD_PRELOAD entries outside the benign allow-list,
  `curl … | bash` and `/dev/tcp/` reverse-shell patterns in cron,
  and redirections of security-update domains (e.g.
  `update.microsoft.com`) to non-loopback IPs. Wired into the
  rootcheck sweep via `tokio::task::spawn_blocking`.
- **Cross-platform hidden-process detection (P1.5).**
  `hidden_process::scan` now has three backends:
  `/proc` + `kill(pid, 0)` on Linux (existing),
  `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_ALL)` + `kill(pid, 0)` on
  macOS, and `CreateToolhelp32Snapshot` /
  `Process32FirstW` / `Process32NextW` +
  `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, ...)` on
  Windows. Platform-gated unit tests cover each backend; the
  public API is unchanged.
- **Linux user-idle detection via `loginctl` (P1.8).**
  `PowerMonitor::user_idle_duration()` now returns a real
  `Some(Duration)` on systemd hosts by reading the
  `IdleSinceHint` property of the current session via
  `loginctl show-session self`. A pure
  `parse_idle_since_hint()` helper is exported for unit testing,
  and the function returns `None` on headless or non-systemd
  hosts without errors. Unblocks `PowerProfile::IdleAC` /
  `PowerProfile::BatteryIdle` on Linux.
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
- **Nightly `cargo-fuzz` CI job.**
  `.github/workflows/ci.yml` § `nightly-fuzz` runs
  `cargo +nightly fuzz run` against `protocol_decode`,
  `protocol_decompress`, `msgpack_event_decode`, and
  `rule_store_msgpack` for 5 minutes per target on the cron
  schedule.
- **Release runbook (`docs/release-process.md`).**
  Step-by-step for cutting, signing (Linux apt/yum keys, macOS
  Developer ID + notarisation, Windows EV code-sign), promoting,
  and rolling back a release.
- **Phase 5.6 enhanced protocol (opt-in).** TLS 1.3 transport
  (`rustls`, TLS 1.3 only, optional CA bundle + SHA-256 cert
  pinning), MessagePack event serialisation (`rmp-serde`), and
  HTTP/2 transport with ALPN `h2`. All three are individually
  toggleable under `server.enhanced` and default **off** to stay
  compatible with Wazuh 4.x managers.
  (`crates/sda-comms/src/transport/tls.rs`,
   `crates/sda-comms/src/transport/http2.rs`,
   `crates/sda-comms/src/msgpack.rs`)
- **E2E compatibility harness against Wazuh 4.7.5.**
  `tests/docker-compose-v4.7.yml` +
  `tests/scripts/run-compat-e2e.sh` + `make e2e-compat` run the
  standard 14-assertion suite against an older v4.x manager to
  catch protocol drift.
- **Platform CI matrix expansion.** `ubuntu-22.04`,
  `ubuntu-24.04`, `macos-13`, `macos-14`, `windows-2022`. Fedora
  and Arch are covered by the manual checks in
  `docs/platform-testing.md`.
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
  `RuleBundle::from_msgpack`. Setup and coverage goals documented
  in `docs/security-audit.md`.
- **Documentation set.** `docs/user-guide.md`,
  `docs/admin-guide.md`, `docs/architecture.md`,
  `docs/configuration-reference.md`,
  `docs/platform-testing.md`, `docs/security-audit.md`.

### Fixed

- **Updater re-download loop (A1, PR #49 review).**
  `sda_updater::run_once` now returns `Option<String>` and
  `sda_updater::run` updates its in-memory `current_version`
  after each install so the next manifest fetch does not retry
  the same version forever.
- **Version comparison trailing-zero bug (A2, PR #49 review).**
  `sda_updater::checker::is_newer` pads both parsed versions to
  the same length before comparing, so `is_newer("0.2.0",
  "0.2") == false` and `is_newer("0.2.1", "0.2") == true`.
- **Linux abstract socket handling in tamper-watchdog (A3, PR
  #50 review).** `sda_agent::tamper::notify` detects
  `@`-prefixed paths and uses
  `std::os::linux::net::SocketAddrExt::from_abstract_name`;
  non-Linux callers fall through to the filesystem socket path.
- **32-bit Linux ioctl constants (A4, PR #50 review).**
  `FS_IOC_GETFLAGS` / `FS_IOC_SETFLAGS` are derived from
  `std::mem::size_of::<libc::c_long>()` so 32-bit builds encode
  the correct size field.
- **Windows MSI default binary path (A5, PR #48 review).**
  `packaging/windows/build-msi.ps1` defaults to
  `target\release\sda-agent.exe` instead of the target-triple
  path, matching `make release`.
- **WiX NeverOverwrite on config component (A6, PR #48 review).**
  `packaging/windows/sda-agent.wxs` now carries
  `NeverOverwrite="yes"` so operator edits to `config.yaml`
  survive upgrades.
- **systemd ReadOnlyPaths dead code (A7, PR #48 review).** The
  misleading `ReadOnlyPaths=/etc/sn360-desktop-agent` was removed
  from `packaging/systemd/sda-agent.service`; a comment explains
  that the config directory is intentionally writable so
  enrolment can persist `client.keys`.

### Changed

- `ServerConfig::default` now includes
  `enhanced: EnhancedProtocolConfig::default()` so older configs
  round-trip through serde without a "missing field" error.

## [0.1.0] – prior work

Earlier merged milestones (pre-beta). The roadmap-level summary
lives in `PROGRESS.md`; representative PRs:

- PR #48 — Installer/packaging work (`.deb`, `.rpm`, `.pkg`,
  `.msi`, hardened systemd unit).
- PR #49 — Self-update: signed manifest fetch, atomic swap, rollback.
- PR #50 — Privilege separation and tamper protection with
  watchdog restart.
- PR #54 — Rename wda- → sda- and fix E2E cleanup hang.
