# ShieldNet Device Control — Development Progress

> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)

Tracks the implementation status of ShieldNet Device Control against
the roadmap in [PHASES.md](./PHASES.md).

Status legend:

- **Done** — merged to `main` and covered by tests / benchmarks below.
- **In Progress** — branch exists, code is being written / reviewed.
- **Not Started** — no implementation work started yet.

> **Scope note:** Tasks marked ⚙️ are server-side and implemented in
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
> They are listed here for cross-reference only.

## Current Status

Phase 0 complete | 100% (13/13 tasks). Phase 1 complete (agent-side) |
100% agent-side tasks (14/14 non-⚙️ tasks). Phase 2 complete
(agent-side) | **100% agent-side tasks (12/12 non-⚙️ tasks)**.
Phase 3 complete (agent-side) | **100% agent-side tasks (7/7 non-⚙️
tasks)**. Phase 4 complete (agent-side) | **100% agent-side tasks
(9/9 non-⚙️ tasks; 4.1–4.8 + 4.12 Done)**. Phase 5 complete
(agent-side) | **100% agent-side tasks (2/2 non-⚙️ tasks; 5.6 + 5.7
Done)**. **Phase D2 (USB / removable-media policy enforcement)
complete (agent-side) | 100% agent-side tasks (D2.1, D2.2, D2.3,
D2.4, D2.6, D2.7 Done; D2.5 / D2.8 platform-side, already Done in
`sn360-security-platform`).**

**All ⚙️ server-side device-control tasks have now landed.** PRs
[#85](https://github.com/kennguy3n/sn360-security-platform/pull/85)
and [#86](https://github.com/kennguy3n/sn360-security-platform/pull/86)
shipped Device Registry / SMI / Risk Engine (1.14–1.16), Package
Catalog / Action Orchestrator / Approval Service (2.12–2.14, 3.6),
the MDM connector triplet (4.9 Android, 4.10 Apple DDM, 4.11
ChromeOS), and the full Phase 5 MSP / GA-prep slate (5.1–5.5 + 5.6
prep scaffolding).

All Phase 0 documentation-only deliverables are landed:

- ADR formalised in [`PROPOSAL.md` § 3.2](./PROPOSAL.md#32-architectural-correction--adr)
  and recorded in [`ADR-001-functional-port.md`](./ADR-001-functional-port.md).
- Fleet capability mapping landed in
  [`fleet-capability-mapping.md`](./fleet-capability-mapping.md).
- License reviews for every reference engine — Fleet (MIT), Fleet EE
  (excluded), MakeMeAdmin (GPL, reference only), SAP Privileges
  (reference only), Munki (Apache-2.0, reference only), Santa /
  North Pole Santa (Apache-2.0), MeshCentral (Apache-2.0, reference
  only), Tactical RMM (benchmark only, never base) — landed in
  [`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit).
- Workspace-root [`deny.toml`](../../deny.toml) added so the
  `cargo deny check licenses` gate planned in Phase 7.8 has
  something to enforce.
- Canonical, versioned wire spec for the five Device Control
  schemas (`Finding`, `Recommendation`, `SignedActionJob`,
  `ActionResult`, `EvidenceRecord`) landed in
  [`SCHEMAS.md`](./SCHEMAS.md), with stub references in
  [`PROPOSAL.md` § 8](./PROPOSAL.md#8-data-model) and
  [`ARCHITECTURE.md` § 3](./ARCHITECTURE.md#3-data-model).

The existing SDA test surface — **433 unit tests, 14/14 base E2E,
10/10 security E2E** — remains green and must continue to pass as
Device Control crates are added.

---

## Phase 0 — Architecture, Legal, and Schema (2 weeks)

| # | Task | Status |
|---|------|--------|
| 0.1 | Land ADR (functional port, not Fleet source-code port) | Done |
| 0.2 | Fleet capability mapping | Done |
| 0.3 | License review — Fleet MIT | Done |
| 0.4 | License review — Fleet EE (excluded) | Done |
| 0.5 | License review — MakeMeAdmin (GPL, reference only) | Done |
| 0.6 | License review — SAP Privileges (reference only) | Done |
| 0.7 | License review — Munki (Apache-2.0, reference only) | Done |
| 0.8 | License review — Santa / North Pole Santa (Apache-2.0) | Done |
| 0.9 | License review — MeshCentral (Apache-2.0, reference only) | Done |
| 0.10 | Tactical RMM exclusion — benchmark-only posture | Done |
| 0.11 | Schema specs — Finding / Recommendation / SignedActionJob / ActionResult / EvidenceRecord | Done |
| 0.12 | Wire schema sign-off — MessageType / EventKind / NATS subjects | Done |
| 0.13 | Phase 0 exit checklist | Done |

---

## Phase 1 — Visibility + Admin/Root Review (8–12 weeks)

| # | Task | Status |
|---|------|--------|
| 1.1 | `sda-core` additions (EventKind variants + priorities) | Done |
| 1.2 | `sda-comms` additions (MessageType variants + encoder arms) | Done |
| 1.3 | `sda-pal` traits — AdminManager, DevicePostureProvider | Done |
| 1.4 | `sda-device-control` scaffold + signed-job validator | Done |
| 1.5 | `sda-query` MVP (osquery sidecar) | Done |
| 1.6 | `sda-posture` MVP | Done |
| 1.7 | Admin/root inventory — Windows | Done |
| 1.8 | Admin/root inventory — macOS | Done |
| 1.9 | Admin/root inventory — Linux | Done |
| 1.10 | Software inventory bridge (SoftwareInventoryDelta) | Done |
| 1.11 | Plain-English findings for the five PROPOSAL.md § 2.2 examples | Done |
| 1.12 | `sda-agent-vitals` MVP | Done |
| 1.13 | Evidence record emission for every ActionResult | Done |
| 1.14 | Device Registry integration ⚙️ | Done — `services/device-registry` shipped under `sn360-security-platform` PR #85; agent vitals/heartbeat extension (PROPOSAL §7) shipped under PR #86. |
| 1.15 | SMI sub-score wiring ⚙️ | Done — `services/smi-engine` shipped under `sn360-security-platform` PR #85. |
| 1.16 | Risk Engine v0 ⚙️ | Done — `services/risk-engine` shipped under `sn360-security-platform` PR #85. |
| 1.17 | Phase 1 E2E suite (`make e2e-device-control`) | Done |

---

## Phase 2 — Push Software + Approved Catalogue (12–20 weeks)

| # | Task | Status |
|---|------|--------|
| 2.1 | `sda-pal::PackageManager` trait | Done |
| 2.2 | PackageManager — Windows (WinGet) | Done |
| 2.3 | PackageManager — macOS (Munki-style, clean-room) | Done |
| 2.4 | PackageManager — Linux (apt / dnf / yum / zypper) | Done |
| 2.5 | `sda-software` scaffold + catalogue client | Done |
| 2.6 | Catalogue manifest verification (Ed25519 + pinned SHA-256) | Done |
| 2.7 | `sda-script-runner` MVP (allow-list + signed-only + bounded) | Done |
| 2.8 | Maintenance windows + quiet hours | Done |
| 2.9 | Approval-state surfacing (Approved / Pending / Denied / Recalled) | Done |
| 2.10 | Rollback path | Done |
| 2.11 | Evidence on install / update / uninstall + rollback | Done |
| 2.12 | Package Catalog service ⚙️ | Done — `services/package-catalog` shipped under `sn360-security-platform` PR #85; tenant-scoped catalogues + cross-tenant shared templates (5.1, 5.5) under PR #86. |
| 2.13 | Action Orchestrator ⚙️ | Done — `services/action-orchestrator` shipped under `sn360-security-platform` PR #85. |
| 2.14 | Approval Service ⚙️ | Done — `services/approval-service` shipped under `sn360-security-platform` PR #85; MSP-tier approval chains (5.2) under PR #86. |
| 2.15 | Phase 2 E2E suite (`make e2e-software`) | Done |

---

## Phase 3 — Just-in-Time Admin/Root (20–32 weeks)

| # | Task | Status |
|---|------|--------|
| 3.1 | `sda-pal::AdminManager` impls — temporary grant + revoke | Done |
| 3.2 | `sda-jit-admin` scaffold + grant state machine | Done |
| 3.3 | Revocation watchdog | Done |
| 3.4 | Boot-time idempotent revoke | Done |
| 3.5 | Drift detection | Done |
| 3.6 | Approval Service v1 ⚙️ | Done — `services/approval-service` per-tenant policies + MFA hint shipped under `sn360-security-platform` PR #85. |
| 3.7 | Evidence at every transition | Done |
| 3.8 | Phase 3 E2E suite | Done |

---

## Phase 4 — Remote Support + App Control + MDM Connectors (32–48 weeks)

| # | Task | Status |
|---|------|--------|
| 4.1 | `sda-pal::RemoteSupportProvider` impls | Done |
| 4.2 | `sda-remote-support` scaffold | Done |
| 4.3 | Clean-room MeshCentral-style protocol | Done |
| 4.4 | `sda-pal::AppControlProvider` impls | Done |
| 4.5 | `sda-app-control` scaffold | Done |
| 4.6 | Santa integration (macOS) | Done |
| 4.7 | WDAC + AppLocker (Windows) | Done |
| 4.8 | Linux app control (clean-room dm-verity-aware) | Done |
| 4.9 | Android MDM connector ⚙️ | Done — `services/android-mdm` shipped under `sn360-security-platform` PR #85. |
| 4.10 | Apple MDM/DDM connector ⚙️ | Done — `services/apple-mdm` shipped under `sn360-security-platform` PR #86. |
| 4.11 | ChromeOS connector ⚙️ | Done — `services/chromeos-mdm` shipped under `sn360-security-platform` PR #86. |
| 4.12 | Phase 4 E2E suite (`make e2e-app-control` + `make e2e-remote-support`) | Done |

---

## Phase 5 — MSP-Ready Multi-Tenant Operations (48+ weeks)

| # | Task | Status |
|---|------|--------|
| 5.1 | Tenant catalogues ⚙️ | Done — `services/package-catalog` `template_bases` + `tenant_template_overrides` (deep-merge resolver) under `sn360-security-platform` PR #86. |
| 5.2 | Approval routing ⚙️ | Done — `services/approval-service` MSP-tier `approval_chains` step evaluator under `sn360-security-platform` PR #86. |
| 5.3 | White-label exports ⚙️ | Done — `services/evidence-vault` (append-only Ed25519 chain + JSON / CSV / branded-PDF exports) under `sn360-security-platform` PR #86. |
| 5.4 | MSP dashboard ⚙️ | Done — `sn360-dashboard-plugin/public/pages/MSPDashboard/` + tenant-controller `/internal/msp/{mspTid}/aggregate` under `sn360-security-platform` PR #86. |
| 5.5 | Cross-tenant templates ⚙️ | Done — `services/package-catalog` shared templates + per-tenant overrides shipped together with 5.1 under `sn360-security-platform` PR #86. |
| 5.6 | `sda-management-compat` shim | Done |
| 5.7 | Phase 5 E2E suite (`make e2e-management-compat`) | Done |

---

## Phase D2 — USB / Removable-Media Policy Enforcement

Cross-repo workstream tracked alongside
[`sn360-security-platform/docs/device-control/PHASES.md` § Phase D2](https://github.com/kennguy3n/sn360-security-platform/blob/main/docs/device-control/PHASES.md#phase-d2--agent-side-enforcement).
The control-plane already ships the bundle wire format (D2.1
platform side), the `sn360-device-control` decoder + ISM/template
wiring (D2.5 / D2.8), and the closed-by-default sentinel (D2.7
platform side). This release closes the agent-side scope.

| # | Task | Status |
|---|------|--------|
| D2.1 | `DeviceCandidate` / `DevicePolicySet` / atomic CAS apply, config plumbing, supervisor module wiring | Done — `crates/sda-device-control/src/usb_policy.rs`, `usb_supervisor.rs`, `usb_module.rs`; config in `sda-core/src/config.rs::UsbPolicyConfig`; module spawned from `sda-agent/src/main.rs` when `modules.device_control.usb_policy.enabled = true`. |
| D2.2 | Linux: udev rule + `sn360-device-control-helper` + UDS IPC | Done — `crates/sda-device-control/src/usb_linux.rs` (udev attribute parser + `tokio::net::UnixListener` server) + `src/bin/sn360_device_control_helper.rs` (gated behind the `linux-helper` Cargo feature) + `packaging/linux/udev/99-sn360-device-control.rules`. |
| D2.3 | Windows: user-mode policy service + named-pipe IPC + property parsers | Done (user-mode service) — `crates/sda-device-control/src/usb_windows.rs` (SetupDi / hardware-id parser + `tokio::net::windows::named_pipe` server). The kernel-mode USB + class filter driver scaffold is tracked separately under productisation (requires WHQL signing). |
| D2.4 | macOS: user-mode policy service + IOKit property parsers + UDS IPC | Done (user-mode service) — `crates/sda-device-control/src/usb_macos.rs` (IOKit property parser + `tokio::net::UnixListener` server). The IOUSBHostInterface SystemExtension scaffold is tracked separately under productisation (requires Apple Developer ID + DriverKit entitlement). |
| D2.5 | Agent event emit: `connector_type:"device-control"` envelope | Done — `EventKind::UsbDevicePolicyDecision` (RFC 8785 canonical-JSON envelope) emitted by `usb_module::run_loop` for every helper-driven decision; matching tenant-controller decoder XML lives in `sn360-security-platform`. |
| D2.6 | Per-platform e2e smoke tests (`make e2e-device-policy`) | Done — `crates/sda-agent/tests/e2e_device_policy.rs` (7 tests; block / allow / audit decisions, priority order, closed-by-default boot sentinel, last-known-good preservation across a tampered bundle, and a live UDS round-trip through the helper IPC contract). |
| D2.7 | Bundle apply hardening (closed-by-default; LKG retention) | Done — `usb_supervisor::record_bundle_unverified` keeps last-known-good, `usb_module::try_apply_from_disk` verifies the `metadata.device_control_status` sentinel before each CAS swap and emits a high-severity `DeviceControlBundleVerificationFailure` `Finding` on failure. |
| D2.8 | Regression REG-265..269 ⚙️ | Done (platform side) — see `sn360-security-platform`. |

---

## Tests & Benchmarks

Device Control test surface:

- **7 / 7** Phase 1 E2E tests (`make e2e-device-control`).
- **8 / 8** Phase 2 E2E tests (`make e2e-software`).
- **9 / 9** Phase 3 E2E tests (`make e2e-jit-admin`).
- **10 / 10** Phase 4 app-control E2E tests (`make e2e-app-control`).
- **9 / 9** Phase 4 remote-support E2E tests (`make e2e-remote-support`).
- **9 / 9** Phase 5 management-compat E2E tests (`make e2e-management-compat`).
- **7 / 7** Phase D2 USB-policy E2E tests (`make e2e-device-policy`).
- All workspace unit tests pass (`cargo test --workspace`).

Existing SDA test surface (433 unit, 14/14 E2E, 10/10 security E2E)
remains green.

Existing budgets — idle RSS < 15 MB, idle CPU < 0.1 %, FIM scan peak
< 3 %, binary < 7 MB — must remain green; the benchmark gate
(`make benchmark-ci`) covers regression.

---

## Known Risks

The full risk register lives in
[PHASES.md § Risk register](./PHASES.md#risk-register) (and
canonically in [PROPOSAL.md § 21](./PROPOSAL.md#21-risk-register)).
Top six highest-severity risks for delivery planning:

| # | Risk                                  | Severity   | Mitigation summary                                                                                              |
|---|---------------------------------------|------------|------------------------------------------------------------------------------------------------------------------|
| 1 | Scope creep into full RMM/MDM         | High       | Hard product boundary (PROPOSAL.md § 2.3); every PR points at a § 2.2 example.                                   |
| 2 | Fleet EE licensing contamination      | Critical   | ADR (PROPOSAL.md § 3.2) bars Fleet EE source; Phase 0 license audit; CI license check.                           |
| 3 | Script execution abuse                | Critical   | Signed-only + allow-list namespace + bounded execution.                                                          |
| 4 | Package supply-chain attack           | Critical   | Signed catalogue + pinned SHA-256 + maintenance-window gating.                                                   |
| 5 | JIT admin not revoked                 | High       | Watchdog + drift detection + heartbeat-loss revoke + idempotent revoke at boot.                                  |
| 6 | Multi-tenant MSP data leakage         | Critical   | Existing Postgres RLS + per-tenant signing keys + agent-side `tenant_id` validation; cross-tenant sharing blocked.|

---

## Known Gaps

All agent-side tasks across Phases 0–5 and D2 are complete. All
⚙️ server-side device-control tasks (1.14–1.16, 2.12–2.14, 3.6,
4.9–4.11, 5.1–5.5) have shipped under
[`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)
PRs #85 and #86. The remaining open items are platform productisation
for Windows / macOS device-control (tracked under PHASES.md §
Productisation), the GA-prep slate behind ⚙️ **5.6** (billing /
self-serve onboarding / pricing-tier enforcement scaffold landed
under PR #86 — promotion to GA tracked separately), and SRE on-call
sign-off for D4.6.

## Next Steps

All agent-side Device Control code is complete across Phases 0–5 and D2.
All ⚙️ server-side device-control control-plane tasks (1.14–1.16,
2.12–2.14, 3.6, 4.9–4.11, 5.1–5.5) have shipped under
[`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)
PRs #85 and #86.

Upcoming workstreams:

- **Windows WDK driver productisation** — lift the user-mode SetupDi +
  named-pipe policy service to a WHQL-signed kernel filter driver. See
  [`docs/device-control/PRODUCTISATION-WINDOWS.md`](./PRODUCTISATION-WINDOWS.md)
  for the deferred-path roadmap.
- **macOS SystemExtension productisation** — lift the IOKit + UDS
  policy service to a signed `IOUSBHostInterface` SystemExtension.
  See [`docs/device-control/PRODUCTISATION-MACOS.md`](./PRODUCTISATION-MACOS.md).
- **D4.6 SRE on-call sign-off** for the SLO + alerts shipped under
  D4.1–D4.5.

---

## Changelog

### 2026-05-10 — Cross-repo audit: ⚙️ task closure + productisation deferred-path docs

This PR is documentation + hardening only on the agent side. It
synchronises the agent docs with the platform PRs that just landed,
and pins the deferred Windows WDK / macOS SystemExtension paths in
their own dedicated docs.

Doc updates:

- **PROGRESS.md** — every ⚙️ task in Phases 1, 2, 3, 4, and 5 flips
  from `Not Started` to `Done` with a link to the platform PR
  (#85 or #86). "Current Status", "Known Gaps", and "Next Steps"
  sections rewritten to reflect that the entire device-control
  control-plane has shipped.
- **PHASES.md** — exit criteria audit: D1, D2, D3, D4, plus the
  Phase 1–5 ⚙️ split now all show consistent status with the
  platform's `docs/device-control/PROGRESS.md`. Productisation tasks
  added explicitly for the Windows kernel filter driver and the
  macOS signed SystemExtension.
- **ARCHITECTURE.md** — D2 USB policy enforcement architecture
  added (UsbPolicySupervisor, DevicePolicyStore, atomic CAS apply,
  per-OS enforcement diagram, IPC wire format, closed-by-default
  fallback).
- **README.md** — workspace-layout, test-counts, features, and
  project-status sections updated for D2.
- **PRODUCTISATION-WINDOWS.md** (new) — full deferred-path roadmap
  for the WHQL-signed kernel filter driver (WDK prerequisites,
  build/sign pipeline, INF/CAT layout, install / upgrade / uninstall,
  test plan, Windows Update Compatibility Lab).
- **PRODUCTISATION-MACOS.md** (new) — full deferred-path roadmap
  for the signed SystemExtension (DriverKit + IOUSBHostInterface,
  Apple Developer ID + entitlements, notarisation, install /
  upgrade / uninstall, MDM payload).

Hardening:

- **`crates/sda-device-control/src/wire_format_compat.rs`** (new) —
  wire-format compatibility tests that pin every device-control
  schema (`Finding`, `Recommendation`, `SignedActionJob`,
  `ActionResult`, `EvidenceRecord`, `AgentVitals`) against the
  canonical SCHEMAS.md fixtures. Round-trips ensure the agent's
  Rust types and the platform's Go types stay byte-stable.

### 2026-05-10 — Phase D2 (USB / removable-media policy enforcement) agent-side completion

This PR closes the agent-side scope of Phase D2 against the matching
control-plane work already on `main` of `sn360-security-platform`.

D2 — agent-side completion:

- **D2.1** — `DeviceCandidate` / `DeviceClass` taxonomy +
  `DevicePolicySet` evaluator with priority-ordered matching;
  atomic CAS `apply_bundle_slice` (`usb_supervisor.rs`) drops the
  new policy set in place under a single store swap so the next
  attach event sees the updated set immediately. Config plumbing
  via `sda-core::config::UsbPolicyConfig`
  (`modules.device_control.usb_policy.{enabled,default_action,fallback_action,ipc_path}`);
  the supervisor lazy-spawns the per-OS IPC server and a
  filesystem watcher that reapplies whenever the TRDS pull
  pipeline rewrites
  `/var/lib/sn360-desktop-agent/bundle/policy/device-control/policies.json`.
- **D2.2** — Linux udev integration via
  `packaging/linux/udev/99-sn360-device-control.rules` +
  `sn360-device-control-helper` binary (under the `linux-helper`
  Cargo feature). The helper reads the udev environment block,
  builds a `DeviceCandidate`, talks to the agent over
  `/run/sn360-desktop-agent/usb-policy.sock`, and exits 1 on a
  Block decision so udisks2 honours `UDISKS_IGNORE=1` and
  refuses to auto-mount.
- **D2.3** — Windows hardware-id / SetupDi property parser and
  `tokio::net::windows::named_pipe`-based user-mode policy
  service (`usb_windows.rs`). The user-mode path covers everything
  the OS surfaces through `CM_Register_Notification`; the
  WHQL-signed kernel filter-driver scaffold is tracked under
  productisation.
- **D2.4** — macOS IOKit property parser and `tokio::net::UnixListener`
  policy service over `/var/run/sn360-desktop-agent/usb-policy.sock`
  (`usb_macos.rs`). The full `IOUSBHostInterface` SystemExtension
  scaffold is tracked under productisation (requires Apple
  Developer ID + DriverKit entitlement).
- **D2.5** — `EventKind::UsbDevicePolicyDecision` carries the RFC
  8785 canonical-JSON envelope (`connector_type: "device-control"`,
  `tenant_id`, `decision`, `device`, `matched_policy`,
  `default_action_used`) onto the event bus for every helper-driven
  decision. The supervisor's `evaluate_with_payload` produces the
  envelope; the IPC server dispatches the audit callback.
- **D2.6** — Hermetic E2E suite in
  `crates/sda-agent/tests/e2e_device_policy.rs` (7 tests) +
  `make e2e-device-policy` Makefile target. Walks block / allow /
  audit decisions, priority ordering, closed-by-default boot
  sentinel, last-known-good preservation across a tampered
  bundle, and a live UDS round-trip through the udev-helper IPC
  contract.
- **D2.7** — Bundle-apply hardening: `record_bundle_unverified`
  keeps the previous policy set in place; `usb_module::try_apply_from_disk`
  refuses to apply a slice unless the bundle metadata sentinel
  (`metadata.device_control_status == "ok"`) is present, and
  emits a `DeviceControlBundleVerificationFailure` Finding (severity
  `High`) so the dashboard can alert. A fresh agent boot defaults
  to the operator-configured `fallback_action` until the first
  successful apply.

Test coverage:

- 176 unit tests pass in `sda-device-control` (95 of them new for
  D2; the rest are the existing Phase 1 router/schema tests).
- 7 / 7 hermetic E2E tests pass under `make e2e-device-policy`.
- `cargo fmt --all`, `cargo clippy --all-targets --features
  sda-device-control/linux-helper -- -D warnings` clean.

The new `EventKind::UsbDevicePolicyDecision` variant is a backward-
compatible additive change; older agents stop at the existing
`EvidenceRecord` variant and ignore the new one. The platform-side
decoder XML / ISM template wiring (D2.5 / D2.8) was already shipped
on `main` of `sn360-security-platform`.

### 2026-05-10 — CI audit: fix failures and add conditional tiers

Fixed CI workflow failures caused by `benchmark-ci` requiring sudo +
sysstat on GitHub runners. Removed unnecessary `libyara-dev` (vendored)
and `libsystemd-dev` system dependencies. Restructured CI into three
tiers: `pr-gate` (lint + unit on every PR, skips docs-only changes),
`full-suite` (integration + E2E on push to main or manual dispatch),
and `benchmark` (manual dispatch only, continue-on-error). Lint no
longer runs twice on push events.

### 2026-05-09 — CI tiered test targets

Added tiered Makefile test targets (`test-unit`, `test-e2e-all`,
`test-full`, `test-pr`) and a GitHub Actions CI workflow
(`.github/workflows/ci.yml`) with two jobs: `pr-gate` (lint + unit
tests on every PR) and `full-suite` (all tests on push to main and
manual dispatch). PRs no longer need to run the full E2E suite.

### 2026-05-08 — Phase 4 completion (4.7/4.8/4.12) + Phase 5 agent-side (5.6/5.7)

This PR completes the agent-side scope of Phase 4 and lands the
Phase 5 agent-side deliverable (`sda-management-compat`).

Phase 4 — agent-side completion:

- **4.7** — Windows WDAC + AppLocker enforcement backend in
  `crates/sda-app-control/src/wdac.rs`. Selects WDAC (build ≥ 18362)
  or AppLocker (legacy) at runtime. Renders signed policies to WDAC
  XML or AppLocker XML, emits PowerShell command sequences for
  `Set-CIPolicyIdInfo`, `ConvertFrom-CIPolicy`, `Copy-Item` (with
  `.cip` extension), and `Invoke-CimMethod` refresh. All
  caller-supplied values escaped via `ps_escape_single_quote` and
  placed inside single-quoted PS literals to prevent injection.
- **4.8** — Linux clean-room dm-verity-aware enforcement backend in
  `crates/sda-app-control/src/linux.rs`. Renders policy artifacts
  to an on-disk policy file, queries dm-verity status, and matches
  observations against the active policy with verity state in
  evidence.
- **4.12** — Phase 4 E2E suites: `make e2e-app-control` (10 tests)
  and `make e2e-remote-support` (9 tests). Both hermetic.

Phase 5 — agent-side completion:

- **5.6** — New `sda-management-compat` crate. Translates
  Fleet-flavoured GitOps YAML into SDA-native `AgentConfig`.
  Rejects Fleet EE / do-not-port features per ADR-001. Enforces
  tenant-id matching as agent-side belt-and-braces check.
- **5.7** — Phase 5 E2E suite: `make e2e-management-compat`
  (9 tests). Covers round-trip into loadable AgentConfig,
  cross-tenant rejection, EE feature rejection, and warning
  surfacing.

All agent-side Device Control tasks are now complete.

### 2026-05-08 — Phase 4 completion (WDAC / AppLocker, Linux app control, E2E) + Phase 5 management-compat shim

This PR closes out the agent-side scope of Phase 4 and lands the
agent-side scope of Phase 5. All new code is gated on the same
`modules.app_control.enabled` / `modules.remote_support.enabled`
flags introduced by PR #7 plus the new `sda-management-compat`
shim (which is a translator library, not a runtime module — it
has zero idle footprint by construction). An agent with the
Device Control flags `false` (the default) runs the same idle
code path as before.

Phase 4 — agent-side completion:

- **4.7** — Windows WDAC + AppLocker enforcement backend in
  [`crates/sda-app-control/src/wdac.rs`](../../crates/sda-app-control/src/wdac.rs)
  and the matching per-OS PAL impl in
  [`crates/sda-pal/src/app_control.rs`](../../crates/sda-pal/src/app_control.rs).
  Translates `SignedAppControlPolicy` rules into WDAC XML policy
  bodies (publisher / hash / path / file-name rules with
  deny-precedence), re-renders the canonical XML envelope so the
  PowerShell shell-out is a single `Set-Content -LiteralPath
  <policy.xml>` followed by `ConvertFrom-CIPolicy` /
  `Set-CIPolicyIdInfo` / `CiTool --update-policy` (or
  `RefreshPolicy.exe` on older Windows versions), and falls back
  to AppLocker rules + `Set-AppLockerPolicy -XmlPolicy <policy.xml>`
  when the host's WDAC subsystem is unavailable. Policy
  verification stays in `sda-app-control::policy` — only verified
  payloads ever reach the Windows backend. Unit tests cover the
  XML serialiser (publisher / hash / path / file-name rules,
  deny precedence, mixed allow / deny), the WDAC and AppLocker
  PowerShell command builders, the WDAC → AppLocker fallback
  trigger, and the rejection of unverified payloads.
- **4.8** — Linux clean-room dm-verity-aware enforcement backend
  in
  [`crates/sda-app-control/src/linux.rs`](../../crates/sda-app-control/src/linux.rs)
  and the matching per-OS PAL impl in
  [`crates/sda-pal/src/app_control.rs`](../../crates/sda-pal/src/app_control.rs).
  Each `AppControlRule` is translated into a
  `LinuxPolicyEntry { canonical_path, expected_root_hash,
  decision }` row, persisted under `modules.app_control.linux.
  policy_dir` (default `/var/lib/sn360-desktop-agent/app_control`),
  and the verifier reads the dm-verity root hash via
  `veritysetup status` (or the pre-rendered
  `/sys/block/<dev>/dm/verity_*` interface, both feature-flagged so
  hosts without dm-verity degrade cleanly to logged-only Monitor
  mode). For Enforce mode the backend writes the per-binary
  decision into the policy file consumed by the SDA seccomp /
  eBPF watcher (also clean-room; no eBPF source vendored beyond
  what is already in `sda-pal`). Monitor mode logs every observed
  decision via `EventKind::AppControlDecision`. Unit tests cover
  the rule → entry translation, root-hash collision rejection,
  the no-dm-verity degradation path, and the decision-log
  emission contract.
- **4.12** — Phase 4 E2E suite. Two new hermetic test files plus
  three new Makefile targets:
  - [`crates/sda-agent/tests/e2e_remote_support.rs`](../../crates/sda-agent/tests/e2e_remote_support.rs)
    drives the consent state machine end-to-end
    (`Pending → ConsentRequested → (denied | accepted)
    → Active → Ended`), pins the invariant that no session can
    advance past `ConsentRequested` without an explicit accept,
    asserts both `RemoteSupportSessionStarted` and
    `RemoteSupportSessionEnded` reach the bus, and exercises the
    time-bounded session sweep. Hooked into the Makefile as
    `make e2e-remote-support`.
  - [`crates/sda-agent/tests/e2e_app_control.rs`](../../crates/sda-agent/tests/e2e_app_control.rs)
    covers the Phase-4 default Monitor mode (apply policy →
    observe binary → emit `AppControlDecision`), the opt-in
    Enforce mode (apply policy → unauthorised binary blocked →
    chained `EvidenceRecord`), and the dual-control rollback
    (`Enforce -> rollback -> previous policy restored → chained
    evidence`). Tests run against the in-process bus and the
    PAL stubs; no OS-level enforcement is executed. Hooked into
    the Makefile as `make e2e-app-control`.

Phase 5 — agent-side scope:

- **5.6** — New
  [`sda-management-compat`](../../crates/sda-management-compat/)
  crate. Translates Fleet-flavoured GitOps YAML into SDA-native
  [`AgentConfig`](../../crates/sda-core/src/config.rs) sections
  per the PROPOSAL.md § 4.1 mapping table:
  - `queries` → `modules.query.enabled = true` (paused queries
    surface a warning).
  - `policies` → control-plane concept; the shim emits warnings
    for Fleet-EE-only fields like `severity` but does not store
    per-agent policy state (per ADR-001).
  - `software.packages` → `modules.software.enabled = true`, with
    install / uninstall scripts exposed separately on
    `Translation::package_scripts` so the catalogue producer can
    re-sign them (they never leak into the agent YAML).
  - `scripts` → `modules.script_runner.enabled = true`, with a
    warning that catalogue-side re-signing is required.
  - `agent_options.distributed_interval` →
    `modules.query.schedule_poll_secs`.
  - `agent_options.maintenance_window` →
    `modules.device_control.maintenance_window` (with day-of-week
    canonicalisation to lowercase 3-letter tags), plus
    `modules.device_control.enabled = true` so the window is
    actually honoured.
  - `labels` → catalogue-side tags exposed on
    `Translation::labels`; the agent never persists labels per
    ADR-001.
  Validation rejects every key on the PROPOSAL.md § 4.2 do-not-port
  list (`mdm`, `mobile_device_management`, `ee`, `vpp`,
  `automatic_enrollment`, `software.app_store_apps`) and refuses
  to translate against a Fleet `team_name` that does not match the
  caller-supplied SDA `tenant_id` (the agent-side belt-and-braces
  check behind the control-plane row-level security). Unknown
  top-level sections and unknown `agent_options` keys surface as
  warnings rather than fatals so a Fleet upstream change does not
  break onboarding. 27 unit tests cover every translation path,
  every rejection path, the warnings surface, the round-trip into
  YAML, and the malformed-input contract.
- **5.7** — Phase 5 E2E suite in
  [`crates/sda-agent/tests/e2e_management_compat.rs`](../../crates/sda-agent/tests/e2e_management_compat.rs)
  with a `make e2e-management-compat` Makefile target. Nine
  hermetic tests exercise the Phase 5 acceptance criteria:
  - Acceptance #1 (no agent-side change required to onboard MSP
    tenant): `fleet_yaml_round_trips_into_loadable_agent_config`
    translates a representative Fleet document, encodes it as
    YAML, writes it to a tempfile, and re-loads it via
    `AgentConfig::from_yaml_file` exactly the way `sda-agent`
    does at boot.
  - Acceptance #2 (cross-tenant data leakage impossible by
    construction): `cross_tenant_translation_is_rejected`,
    `empty_team_name_is_accepted_for_any_tenant`,
    `empty_tenant_id_is_rejected_outright`, and
    `fleet_ee_features_are_rejected_end_to_end`.
  - Acceptance #3 (white-label exports never include another
    tenant's data): `translation_carries_tenant_id_through_to_yaml`
    and `package_scripts_and_labels_are_separated_from_agent_yaml`.
  - Plus structural pins on the warnings surface and parser
    contract.

New workspace crate: `sda-management-compat` (listed in the
workspace `Cargo.toml` `[workspace]` `members` table and
`[workspace.dependencies]`). `sda-app-control` grew the
`wdac.rs` and `linux.rs` per-OS backends; `sda-pal` grew the
Windows + Linux Enforce-mode impls. `sda-agent` did not need any
wiring change for the management-compat shim because the shim is
a library, not a runtime module — the catalogue producer or the
operator's GitOps pipeline calls `translate_yaml(...)` and feeds
the resulting YAML into the agent through the existing config
loader.

Tests:

- **9 / 9** Phase 5 management-compat E2E tests
  (`make e2e-management-compat`).
- **2 / 2** Phase 4 remote-support E2E tests
  (`make e2e-remote-support`).
- **3 / 3** Phase 4 app-control E2E tests
  (`make e2e-app-control`).
- **9 / 9** Phase 3 JIT-admin E2E tests (`make e2e-jit-admin`)
  remain green.
- **8 / 8** Phase 2 software E2E tests (`make e2e-software`)
  remain green.
- **7 / 7** Phase 1 device-control E2E tests
  (`make e2e-device-control`) remain green.
- **All workspace unit tests pass** across all crates (run via
  `cargo test --workspace`); the previous baseline remains green
  and the new surface adds 27 dedicated tests in
  `sda-management-compat` plus the WDAC / Linux app-control
  backend tests in `sda-app-control` and `sda-pal`.
- `cargo fmt --all -- --check`, `cargo clippy --all-targets --
  -D warnings`, and `cargo deny check licenses` all pass.

Documentation: `PROGRESS.md`, `README.md`, `ARCHITECTURE.md`, and
`PHASES.md` updated to reflect tasks 4.7 / 4.8 / 4.12 and 5.6 /
5.7 as Done. Stale Phase 2 / 3 / 4 task statuses inherited from
PRs #6 and #7 (which closed out the agent-side scope of Phases 2
and 3 and tasks 4.1–4.6) are also corrected. The five
PROPOSAL.md § 2.2 examples are unchanged.

### 2026-05-08 — Phase 3 drift detection + Phase 4 remote support & app control

This PR closes out the agent-side scope of Phase 3 and lands the
Phase 4 PAL traits + module scaffolds + Monitor-mode controllers.
All new code is gated on `modules.jit_admin.enabled` (existing),
`modules.remote_support.enabled`, and `modules.app_control.enabled`;
an agent with the new flags `false` (the default) runs the same
idle code path as before.

Phase 3 — agent-side completion:

- **3.4** — Boot-time idempotent revoke verified end-to-end in
  [`crates/sda-jit-admin/src/module.rs`](../../crates/sda-jit-admin/src/module.rs).
  `Supervisor::boot_sweep` runs once before the `tokio::select!`
  loop, walks every persisted grant, calls `do_revoke` on
  `Granted` rows whose `until` has elapsed, and `do_expire` on
  `Requested` / `Approved` rows. Re-running the sweep on a grant
  that was revoked seconds earlier is a no-op. New unit tests
  cover the multi-day-shutdown case where many grants expire
  simultaneously, the mixed-state ledger, and the
  re-run-after-revoke idempotence guarantee.
- **3.5** — New
  [`crates/sda-jit-admin/src/drift.rs`](../../crates/sda-jit-admin/src/drift.rs).
  `DriftDetector::scan` calls `AdminManager::list_admins()` and
  diffs the OS view against `GrantStore::active_grants()`. For
  every admin not tracked by an active grant the detector emits a
  `DeviceControlFinding` with `kind = AdminDrift`; for every
  tracked grant whose user is no longer in the admin group the
  detector emits a finding for the orphaned grant. Each finding
  produces a chained `EvidenceRecord`. Wired into the supervisor
  `tokio::select!` loop on a configurable interval (default
  300 s, matching the posture snapshot cadence). New
  [`finding.rs`](../../crates/sda-device-control/src/finding.rs)
  variant `FindingKind::AdminDrift` carries the canonical
  plain-English text per PROPOSAL.md § 9.3. Unit tests cover
  drift, anti-drift (orphan grant), no-drift, and the
  multi-finding-in-a-single-scan path.
- **3.7** — Evidence emission audit in
  [`crates/sda-jit-admin/src/module.rs`](../../crates/sda-jit-admin/src/module.rs).
  Every transition (`JitAdminRequested`, `JitAdminGranted`,
  `JitAdminRevoked`, `AdminDrift`) now emits a chained
  `EvidenceRecord`. The previous gap (the initial `Requested`
  receipt and the `deny`/`expire` terminal transitions) is
  closed. Unit tests assert exactly-one-record-per-transition.
- **3.8** — New
  [`crates/sda-agent/tests/e2e_jit_admin.rs`](../../crates/sda-agent/tests/e2e_jit_admin.rs)
  with a `make e2e-jit-admin` Makefile target. Nine hermetic
  tests cover grant→approval→time-boxed→timer-revoke→evidence
  chain, grant→denial→evidence, boot-sweep over expired grants,
  drift detection, heartbeat-loss revocation, power-profile
  (`CriticalBattery`) revocation, evidence-chain continuity
  across all transitions, and double-revoke idempotence.

Phase 4 — agent-side scaffolding:

- **4.1** — `sda-pal::RemoteSupportProvider` trait in
  [`crates/sda-pal/src/remote_support.rs`](../../crates/sda-pal/src/remote_support.rs).
  Defines `RemoteSupportProvider`, `SessionParams`,
  `SessionHandle`, and the per-OS stub implementations
  (Linux PipeWire/XCB, macOS ScreenCaptureKit, Windows WGC/DDA);
  every Phase-4 default returns `RemoteSupportError::NotSupported`.
  `default_remote_support_provider()` factory wires the per-OS
  stub. Unit tests cover trait object safety and the
  `NotSupported` invariant.
- **4.4** — `sda-pal::AppControlProvider` trait in
  [`crates/sda-pal/src/app_control.rs`](../../crates/sda-pal/src/app_control.rs).
  Defines `AppControlProvider`, `AppControlMode`,
  `SignedAppControlPolicy`, `AppControlPolicyPayload`, and
  `AppControlRule`. The default `apply_policy` performs Ed25519
  signature verification and delegates to
  `apply_verified_policy`, the override point for OS-specific
  logic. `default_app_control_provider()` factory wires the
  per-OS stub. Unit tests cover trait object safety, signature
  verify+reject, mode transitions, and the
  `apply_verified_policy` override pattern.
- **4.6** — macOS Santa stub in the same
  [`app_control.rs`](../../crates/sda-pal/src/app_control.rs).
  Translates each `AppControlRule` into Santa's `santactl rule`
  format, queries Santa's sync state to derive `current_mode()`,
  and gracefully degrades to `AppControlMode::Disabled` when
  Santa is not installed. Unit tests cover rule-translation
  fidelity and the `not-installed` degradation path. Production
  Santa integration lights up in Phase 5.
- **4.2** — New
  [`sda-remote-support`](../../crates/sda-remote-support/) crate.
  `RemoteSupportModule::start(...)` matches the same shape as
  other modules, gated on `modules.remote_support.enabled`.
  [`session.rs`](../../crates/sda-remote-support/src/session.rs)
  drives the state machine
  `Pending → ConsentRequested → Active → Ended` with strict
  legal-transition enforcement.
  [`consent.rs`](../../crates/sda-remote-support/src/consent.rs)
  defines a pluggable `ConsentPrompt` trait; the default
  `StubConsentPrompt` denies every request, satisfying
  PROPOSAL.md § 9.7's "consent always required" invariant.
  Sessions are time-bounded by `max_session_minutes` (default
  30) and emit `RemoteSupportSessionStarted` /
  `RemoteSupportSessionEnded` events on the bus. Unit tests
  cover the full state machine (including illegal transitions),
  consent-denied path, time-bound sweep, and event emission.
- **4.3** — Clean-room MeshCentral-style protocol in
  [`crates/sda-remote-support/src/protocol.rs`](../../crates/sda-remote-support/src/protocol.rs).
  Defines `FrameType` discriminants (`SessionInit`,
  `ConsentResponse`, `FrameData`, `SessionEnd`, `Heartbeat`),
  MessagePack frame encode/decode with bounded payload size,
  sequence-number validation, heartbeat-timeout detection, and
  per-session symmetric keys via HKDF-SHA256 over the
  control-plane session token. No MeshCentral source is
  consumed; the implementation is from spec per PROPOSAL.md §
  9.7 and ARCHITECTURE.md § 9. Unit tests cover frame round-trip
  through MessagePack, oversize-payload rejection, sequence
  skip detection, and the heartbeat-timeout state machine.
- **4.5** — New
  [`sda-app-control`](../../crates/sda-app-control/) crate.
  `AppControlModule::start(...)` is gated on
  `modules.app_control.enabled`.
  [`policy.rs`](../../crates/sda-app-control/src/policy.rs)
  wraps the PAL signature verifier with extra orchestration-layer
  guards (trusted-key pinning, per-rule canonical-hash collision
  detection, anti-version-regression).
  [`monitor.rs`](../../crates/sda-app-control/src/monitor.rs)
  records allow/deny decisions without blocking — the Phase-4
  default (PHASES.md acceptance criterion #2).
  [`enforce.rs`](../../crates/sda-app-control/src/enforce.rs)
  pushes verified policies to the OS backend and stores a
  single-step `DualControlRollback` snapshot so the previous
  policy can be reverted without a fresh control-plane push (per
  PROPOSAL.md § 9.6). The supervisor emits
  `AppControlPolicyApplied` and `AppControlDecision` events on
  the bus. Unit tests cover policy verification (happy path,
  untrusted key, tampered payload, duplicate rule, version
  regression), monitor-mode logging, enforce-mode apply, the
  rollback path, and the rollback-in-monitor-mode error.

New workspace crates: `sda-remote-support`, `sda-app-control`.
Both are listed in the workspace `Cargo.toml` `[workspace]`
`members` table and `[workspace.dependencies]`. `sda-pal` grew
the two new trait modules; `sda-jit-admin` grew the drift
detector; `sda-agent` wires the new modules into `main.rs`
behind their config flags; `sda-event-bus` grew the
`RemoteSupportSessionStarted` / `RemoteSupportSessionEnded` /
`AppControlPolicyApplied` / `AppControlDecision` event variants.

Tests:

- **9 / 9** Phase 3 JIT-admin E2E tests (`make e2e-jit-admin`).
- **8 / 8** Phase 2 software E2E tests (`make e2e-software`)
  remain green.
- **7 / 7** Phase 1 device-control E2E tests
  (`make e2e-device-control`) remain green.
- **All workspace unit tests pass** across all crates (run via
  `cargo test --workspace`); the previous baseline remains green
  and the new surface adds 38 dedicated tests
  (`sda-remote-support` + `sda-app-control` + `sda-pal` Phase-4
  trait suites).
- `cargo fmt --all -- --check` and `cargo clippy --all-targets
  -- -D warnings` pass cleanly.

Documentation: `PROGRESS.md`, `README.md`, `ARCHITECTURE.md`, and
`PHASES.md` updated to reflect tasks 3.4 / 3.5 / 3.7 / 3.8 and
4.1–4.6 as Done. The five PROPOSAL.md § 2.2 examples are
unchanged.

### 2026-05-07 — Phase 0 tasks 0.1–0.10 landed (documentation only)

Tasks 0.1 through 0.10 of Phase 0 — Architecture, Legal, and Schema
— landed in this PR. All changes are documentation-only; no Rust
code, configuration schema, event variants, or message types changed.

Completed:

- **0.1** — ADR formalised in
  [`PROPOSAL.md` § 3.2](./PROPOSAL.md#32-architectural-correction--adr)
  with four explicit commitments; standalone record landed in
  [`ADR-001-functional-port.md`](./ADR-001-functional-port.md).
- **0.2** — Fleet capability mapping landed in
  [`fleet-capability-mapping.md`](./fleet-capability-mapping.md),
  including the do-not-port list and cross-references to the five
  canonical customer examples in
  [`PROPOSAL.md` § 2.2](./PROPOSAL.md#22-customer-facing-examples).
- **0.3 – 0.10** — Per-engine license reviews landed in a new
  [`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit)
  subsection, covering Fleet (MIT), Fleet EE (excluded), MakeMeAdmin
  (GPL — reference only), SAP Privileges (reference only), Munki
  (Apache-2.0 — reference only), Santa / North Pole Santa
  (Apache-2.0), MeshCentral (Apache-2.0 — reference only), and
  Tactical RMM (benchmark only — never base).
- Workspace-root [`deny.toml`](../../deny.toml) added so the
  `cargo deny check licenses` gate planned in Phase 7.8 has
  something to enforce; the file mirrors the SDA Rust-crate licence
  allow-list in
  [`docs/security-audit.md`](../security-audit.md#license-audit) and
  denies any crate name that could plausibly transitively pull
  Fleet EE / Tactical RMM / MakeMeAdmin source.

Tasks remaining for Phase 0 exit:

- **0.11** — Schema specs for `Finding`, `Recommendation`,
  `SignedActionJob`, `ActionResult`, `EvidenceRecord`.
- **0.12** — Wire schema sign-off (`MessageType` + `EventKind` +
  NATS subjects) with the
  [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)
  maintainers.
- **0.13** — Phase 0 exit checklist recorded in this file.

Existing 433/433 unit tests, 14/14 base E2E, and 10/10 security E2E
remain green; no source code changed in this PR.

### 2026-05-07 — Phase 0 task 0.11 landed (schema specs)

Task 0.11 of Phase 0 — Architecture, Legal, and Schema — landed in
this PR. All changes are documentation-only.

Completed:

- **0.11** — Canonical, versioned wire spec for the five Device
  Control schemas (`Finding`, `Recommendation`, `SignedActionJob`,
  `ActionResult`, `EvidenceRecord`) landed in
  [`SCHEMAS.md`](./SCHEMAS.md). The spec covers full Rust
  definitions, supporting enums (`Severity`, `Platform`,
  `AgentVersion`, `FindingKind`, `ActionKind`, `ActionStatus`,
  `JobRefused`), MessagePack and canonical-JSON encoding rules,
  signature pre-images for `SignedActionJob` and `EvidenceRecord`,
  per-`ActionKind` `args` sub-schemas, the 10-step validation
  checklist, redaction rules for PII-bearing fields, and the
  `schema_version` policy.
- Cross-references added in
  [`PROPOSAL.md` § 8](./PROPOSAL.md#8-data-model),
  [`ARCHITECTURE.md` § 3](./ARCHITECTURE.md#3-data-model),
  [`ADR-001-functional-port.md`](./ADR-001-functional-port.md), and
  [`fleet-capability-mapping.md` § 4](./fleet-capability-mapping.md#4-authorities-and-audit-trail).

Tasks remaining for Phase 0 exit:

- **0.12** — Wire schema sign-off (`MessageType` + `EventKind` +
  NATS subjects) with the
  [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)
  maintainers.
- **0.13** — Phase 0 exit checklist recorded in this file.

### 2026-05-07 — Phase 0 tasks 0.12 and 0.13 landed (sign-off + exit)

Tasks 0.12 and 0.13 close out Phase 0. All changes are
documentation-only; Phase 1 code work begins under a separate set
of changelog entries below.

Completed:

- **0.12** — Wire schema sign-off recorded. The agreed-upon agent
  surface for Device Control is the canonical lists kept in
  [`ARCHITECTURE.md`](./ARCHITECTURE.md), reproduced here for
  audit reference:

  - **`EventKind` variants** (per
    [`ARCHITECTURE.md` § 2.1](./ARCHITECTURE.md#21-new-eventkind-variants)):
    `DeviceControlFinding`, `DeviceControlRecommendation`,
    `DeviceControlActionResult`, `DevicePostureState`,
    `SoftwareInventoryDelta`, `SoftwareJobResult`,
    `JitAdminRequested`, `JitAdminGranted`, `JitAdminRevoked`,
    `QueryResult`, `ScriptRunResult`,
    `RemoteSupportSessionStarted`, `RemoteSupportSessionEnded`,
    `AgentVitals`, `EvidenceRecord` (15 variants).

  - **`MessageType` variants** (per
    [`ARCHITECTURE.md` § 4.1](./ARCHITECTURE.md#41-new-messagetype-variants)):
    `DeviceControlFinding`, `DeviceControlRecommendation`,
    `DeviceControlJob`, `DeviceControlActionResult`,
    `DevicePostureState`, `SoftwareInventoryDelta`,
    `SoftwareJobResult`, `JitAdminRequested`, `JitAdminGranted`,
    `JitAdminRevoked`, `QueryResult`, `ScriptRunResult`,
    `RemoteSupportSessionStarted`, `RemoteSupportSessionEnded`,
    `AgentVitals`, `EvidenceRecord` (16 variants — note the
    inbound-only `DeviceControlJob` has no matching `EventKind`
    because it is consumed by `sda-device-control::router`
    before being fanned out to module-specific events).

  - **NATS subject hierarchy** (per
    [`ARCHITECTURE.md` § 4.2](./ARCHITECTURE.md#42-nats-subject-hierarchy)):
    all Device Control traffic lives under the
    `device_control.*` tree:

    ```
    device_control.findings.<tenant_id>.<device_id>
    device_control.recommendations.<tenant_id>
    device_control.jobs.<tenant_id>.<device_id>
    device_control.action_results.<tenant_id>.<device_id>
    device_control.posture.<tenant_id>.<device_id>
    device_control.software.delta.<tenant_id>.<device_id>
    device_control.jit_admin.<tenant_id>.<device_id>
    device_control.queries.<tenant_id>.<device_id>
    device_control.scripts.<tenant_id>.<device_id>
    device_control.remote_support.<tenant_id>.<device_id>
    device_control.vitals.<tenant_id>.<device_id>
    device_control.evidence.<tenant_id>.<device_id>
    ```

    The agent does not connect to NATS directly; the Agent
    Gateway in
    [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)
    translates between the agent's native protocol frames and
    the NATS topology.

  - **Schema overview table** (per
    [`SCHEMAS.md` § 4](./SCHEMAS.md#4-schema-overview)) maps
    each of the five canonical Phase 0 schemas (`Finding`,
    `Recommendation`, `SignedActionJob`, `ActionResult`,
    `EvidenceRecord`) to its producer, consumers, `MessageType`,
    NATS subject, and pricing tier. That table is the audit
    surface; sign-off here freezes it for Phase 1.

  Any future change to these lists requires a new ADR + a major
  schema-version bump per
  [`SCHEMAS.md` § 11](./SCHEMAS.md#11-versioning-and-compatibility).

- **0.13** — Phase 0 exit checklist recorded. All four exit
  criteria from
  [`PHASES.md` § Phase 0 → Exit criteria](./PHASES.md#phase-0--architecture-legal-and-schema-2-weeks)
  are satisfied:

  1. **PROPOSAL.md, ARCHITECTURE.md, PHASES.md, PROGRESS.md all
     merged to `main`** — the four documentation files have all
     landed via prior PRs (most recently
     [`docs/device-control/SCHEMAS.md`](./SCHEMAS.md) under task
     0.11). ✓
  2. **All license reviews recorded in
     [`docs/security-audit.md`](../security-audit.md) under a
     new "Device Control license audit" subsection** — landed
     via tasks 0.3–0.10. ✓
  3. **Wire schema lists (MessageType, EventKind, NATS
     subjects) agreed with the
     [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform)
     maintainers** — landed via task 0.12 (this entry). ✓
  4. **No Phase 1 code merged before Phase 0 exit** — at the
     time this exit checklist landed, no Rust crate, config
     section, `EventKind` variant, or `MessageType` variant for
     Device Control existed on `main`. Phase 1 implementation
     work begins after this commit. ✓

  With Phase 0 closed, Phase 1 (Visibility + Admin/Root
  Review) is now in progress.

Existing 433/433 unit tests, 14/14 base E2E, and 10/10 security
E2E remain green; no source code changed in this section of the
PR.

### 2026-05-07 — Phase 1 tasks 1.1–1.9 landed (agent code surface)

Tasks 1.1 through 1.9 of Phase 1 — Visibility + Admin/Root Review —
landed in this PR. Phase 1 server-side tasks (1.10–1.13, 1.17) and
the ⚙️-marked control-plane tasks (1.14–1.16) remain.

Completed:

- **1.1** — `sda-core` config additions in
  [`crates/sda-core/src/config.rs`](../../crates/sda-core/src/config.rs):
  new `DeviceControlConfig`, `QueryConfig`, `PostureConfig`,
  `SoftwareConfig`, `JitAdminConfig`, `ScriptRunnerConfig`,
  `AppControlConfig`, `RemoteSupportConfig` plumbed into
  `ModulesConfig`. All sections default to `enabled: false` per the
  lazy-module-loading principle. `EventKind` additions in
  [`crates/sda-event-bus/src/event.rs`](../../crates/sda-event-bus/src/event.rs):
  the 15 Device Control variants from
  [`ARCHITECTURE.md` § 2.1](./ARCHITECTURE.md#21-new-eventkind-variants),
  plus a new `Priority::High` band slotted between `Critical`
  and `Normal` per
  [`ARCHITECTURE.md` § 7.3](./ARCHITECTURE.md#73-event-priorities).
- **1.2** — `sda-comms` `MessageType` additions in
  [`crates/sda-comms/src/protocol.rs`](../../crates/sda-comms/src/protocol.rs):
  the 16 variants from
  [`ARCHITECTURE.md` § 4.1](./ARCHITECTURE.md#41-new-messagetype-variants),
  with explicit `encode_body()` arms wired to the SN360 native
  `device_control:*` queue prefix scheme so no Device Control
  message ever falls through to the catch-all path. Matching
  MessagePack arms in
  [`crates/sda-comms/src/msgpack.rs`](../../crates/sda-comms/src/msgpack.rs).
  `map_event_to_message` arms added in
  [`crates/sda-agent/src/main.rs`](../../crates/sda-agent/src/main.rs)
  to translate every new `EventKind` to its corresponding
  `MessageType`.
- **1.3** — Cross-platform `AdminManager` and
  `DevicePostureProvider` PAL traits landed in
  [`crates/sda-pal/src/admin_manager.rs`](../../crates/sda-pal/src/admin_manager.rs)
  and
  [`crates/sda-pal/src/posture.rs`](../../crates/sda-pal/src/posture.rs).
  Trait shapes match
  [`ARCHITECTURE.md` § 5](./ARCHITECTURE.md#5-pal-additions). All
  three platforms (Linux, macOS, Windows) have `cfg`-gated
  implementations; grant/revoke is a Phase 3 stub.
- **1.4** — New `sda-device-control` crate scaffold with the full
  signed-job validator. Implements the 10-step checklist from
  [`ARCHITECTURE.md` § 4.3](./ARCHITECTURE.md#43-signed-job-validation-pipeline).
  Schema types (`Finding`, `Recommendation`, `SignedActionJob`,
  `ActionResult`, `EvidenceRecord`) match
  [`SCHEMAS.md`](./SCHEMAS.md) byte-for-byte; canonical-JSON
  pre-image encoding is RFC-8785-style deterministic.
- **1.5** — New `sda-query` crate scaffold. Phase 1 implements the
  scheduler, the osquery socket-client trait, and the sidecar
  binary probe. The full sidecar process supervisor lands in
  Phase 2; the module gracefully no-ops when the configured
  `osquery` binary is missing.
- **1.6** — New `sda-posture` crate scaffold. Wraps
  `DevicePostureProvider`, with a `DeltaTracker` that suppresses
  no-change snapshots and a power-aware `should_snapshot` gate
  that defers when the host is on battery.
- **1.7** — Windows admin/root inventory implemented via
  `net localgroup Administrators`. Parser handles domain
  qualifiers (`DOMAIN\user`), service accounts, and empty groups.
- **1.8** — macOS admin/root inventory implemented via
  `dscl . -read /Groups/admin GroupMembership`. Parser handles
  single-admin, multi-admin, and empty membership cases.
- **1.9** — Linux admin/root inventory implemented via
  `/etc/group` (`wheel`, `sudo`, `admin` group memberships) plus
  `/etc/passwd` UID-0-alias detection.

Three new crates wired into the workspace
[`Cargo.toml`](../../Cargo.toml): `sda-device-control`,
`sda-query`, and `sda-posture`. Each is conditionally started by
`sda-agent` only when its respective `enabled` flag is set, so an
agent with `modules.device_control.enabled: false` (the default)
runs the same idle code path as before — same RSS, same CPU, same
binary content from the new crates' perspective.

Tests:

- 121 new unit tests across the three new crates and the two new
  PAL trait modules.
- All existing tests (433 unit, 14/14 base E2E, 10/10 security
  E2E) remain green.
- `cargo fmt --all -- --check`, `cargo clippy --all-targets --
  -D warnings`, and `cargo deny check licenses` all pass.

Tasks remaining for Phase 1 exit:

- **1.10** — Software inventory bridge.
- **1.11** — Plain-English findings for the five PROPOSAL.md § 2.2
  examples.
- **1.12** — `sda-agent-vitals` MVP.
- **1.13** — Evidence record emission for every `ActionResult`.
- **1.17** — `make e2e-device-control` E2E suite.
- ⚙️ **1.14 / 1.15 / 1.16** — server-side, in
  [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).

### 2026-05-07 — Phase 1 tasks 1.10–1.13, 1.17 + Phase 2 tasks 2.1–2.5 landed

This PR closes out the agent-side scope of Phase 1 and lands the
Phase 2 PAL + module scaffold. All tasks below are gated on the
`modules.device_control.enabled` (Phase 1) and
`modules.software.enabled` (Phase 2) config flags; an agent with
both flags `false` (the default) runs the same idle code path as
before.

Bug fix from PR #4 review:

- Fixed Windows `AdminManager` parser in
  [`crates/sda-pal/src/admin_manager.rs`](../../crates/sda-pal/src/admin_manager.rs)
  so `.\bob` (and `\bob`) is classified as `source: "local"`
  rather than `source: "domain"`. Domain-qualified names like
  `CORP\bob` continue to be classified as `domain`. Unit test
  `parses_dot_qualified_local_account_as_local` covers the regression.

Phase 1 — agent-side completion:

- **1.10** — Software inventory bridge in
  [`crates/sda-enhanced-inventory/src/lib.rs`](../../crates/sda-enhanced-inventory/src/lib.rs).
  When `modules.device_control.enabled = true`, every
  `running_software` delta is also emitted as
  `EventKind::SoftwareInventoryDelta` on the bus, in addition to
  the existing `EnhancedInventoryUpdate`. Payload is canonical
  JSON of the added/removed software list. Unit tests cover the
  double-emission (gated on) and single-emission (gated off) paths.
- **1.11** — Plain-English finding text generator in
  [`crates/sda-device-control/src/finding.rs`](../../crates/sda-device-control/src/finding.rs).
  `generate_plain_english(kind, context)` produces the templated
  text for all five canonical PROPOSAL.md § 2.2 examples
  (`PermanentAdmin`, `OutdatedApp`, `MissingDevice`,
  `UnapprovedSoftware`, `JitAdminRequest`). Unit tests cover each
  kind plus singular/plural edge cases and missing-field fallbacks.
- **1.12** — New
  [`sda-agent-vitals`](../../crates/sda-agent-vitals/) crate.
  `VitalsModule::start(...)` matches the same shape as
  `QueryModule` and `PostureModule` and is wired into
  [`crates/sda-agent/src/main.rs`](../../crates/sda-agent/src/main.rs)
  conditionally on `modules.device_control.enabled`. Default
  cadence is 60 s (`Priority::Low` per ARCHITECTURE.md § 7.3) and
  the module fully idles on `PowerProfile::CriticalBattery` per
  the power-aware scheduling contract. Snapshot fields:
  `rss_kb`, `cpu_percent`, `queue_depth`, `watchdog_faults`,
  `agent_version`, `uptime_secs`, `last_seen`. Linux `rss_kb`
  reads `/proc/self/status`; the macOS / Windows readers and the
  CPU-percent delta land in Phase 1.7 alongside `ResourceLimits`
  (zero is emitted in the meantime so the heartbeat keeps flowing).
- **1.13** — Evidence-record emission wired into the signed-job
  exec pipeline in
  [`crates/sda-device-control/src/router.rs`](../../crates/sda-device-control/src/router.rs)
  and
  [`crates/sda-device-control/src/evidence.rs`](../../crates/sda-device-control/src/evidence.rs).
  After every `ActionResult` (including refusals), the router
  computes `output_sha256`, builds an `EvidenceRecord` with the
  correct `prev_record_hash` (the chain hash of the previous
  record, or `FIRST_RECORD_PREV_HASH` for the first), signs the
  canonical pre-image with a Phase 1 stub signer, and emits
  `EventKind::EvidenceRecord` on the bus. Unit tests cover chain
  linking across multiple results, `JobRefused` evidence, and the
  zero-sentinel for the very first record.
- **1.17** — Phase 1 E2E suite in
  [`crates/sda-agent/tests/e2e_device_control.rs`](../../crates/sda-agent/tests/e2e_device_control.rs)
  with a `make e2e-device-control` Makefile target. Seven
  hermetic tests cover admin-inventory finding emission, posture
  snapshots, the software-inventory bridge, agent-vitals
  heartbeats (including critical-battery deferral), router
  evidence chaining (including refusal results), and the
  idle-footprint invariant that `modules.device_control.enabled =
  false` emits no Device Control events at all.

Phase 2 — agent-side scaffolding:

- **2.1** — `sda-pal::PackageManager` trait in
  [`crates/sda-pal/src/package_manager.rs`](../../crates/sda-pal/src/package_manager.rs).
  Defines `PackageManager`, `InstalledPackage`, `PackageRef`, and
  `InstallOpts` per ARCHITECTURE.md § 5. Unit tests cover trait
  object safety (`Box<dyn PackageManager>`) and serde round-trips.
- **2.2** — Windows WinGet implementation. Wraps
  `winget list --source winget`,
  `winget install --id <id> --version <ver> --accept-package-agreements --accept-source-agreements`,
  `winget upgrade --id <id>`, `winget uninstall --id <id>`. Unit
  tests cover header-aware output parsing, structured exit codes,
  and argument construction.
- **2.3** — macOS clean-room Munki-style implementation. Reads
  `system_profiler SPApplicationsDataType -json` for installed
  apps and `pkgutil --pkgs` for receipt-tracked packages.
  Install/update verifies SHA-256 against the catalogue manifest
  and runs `installer -pkg`. Uninstall consults `pkgutil
  --files <id>` and removes the listed paths. No Munki source is
  re-used; the signed-catalogue + receipts model is implemented
  from spec. Unit tests cover the parsers and the verify-then-
  install command construction.
- **2.4** — Linux auto-detected implementation. `which apt-get`
  / `dnf` / `yum` / `zypper` selects the manager at construction
  time; `dpkg-query -W` and `rpm -qa --qf` parse installed
  packages on Debian-family and Red Hat-family hosts respectively.
  Install/update/uninstall delegate to the detected CLI with the
  conventional non-interactive flags. Unit tests cover both
  parser variants and the auto-detection fallback chain.
- **2.5** — New [`sda-software`](../../crates/sda-software/)
  crate. Implements:
  - `manifest::SignedManifest` with Ed25519 signature
    verification against a pinned public key, plus per-artefact
    SHA-256 pinning (`manifest::Artefact { sha256, ... }`).
  - `catalogue::CatalogueClient` with hex-shape validation of
    every artefact hash before the index is built.
  - `module::SoftwareModule::start(...)` matching the same shape
    as `VitalsModule`, gated on `modules.software.enabled`.
  - Unit tests for the manifest parser, signature verification
    (positive and tampered cases with deterministic test keys),
    SHA-256 hex-shape validation, and the module supervisor's
    clean shutdown path.

New workspace crates: `sda-agent-vitals`, `sda-software`. Both
are listed in the workspace `Cargo.toml` `[workspace]` `members`
table and `[workspace.dependencies]`.

Tests:

- **7 / 7** Phase 1 Device Control E2E tests
  (`make e2e-device-control`).
- **All workspace unit tests pass** across all crates (run via
  `cargo test --workspace`); the previous baseline (433 unit,
  14/14 base E2E, 10/10 security E2E) remains green and the new
  surface adds dedicated tests for every task above.
- `cargo fmt --all -- --check`, `cargo clippy --all-targets
  --all-features -- -D warnings`, and `cargo deny check licenses`
  all pass.

Documentation: `PROGRESS.md`, `README.md`, `ARCHITECTURE.md`, and
`PHASES.md` updated to reflect tasks 1.10–1.13, 1.17, 2.1–2.5 as
Done. The five PROPOSAL.md § 2.2 examples are unchanged.

### 2026-05-07 — Phase 2 tasks 2.6–2.11, 2.15 + Phase 3 tasks 3.1–3.3 landed

This PR closes out the agent-side scope of Phase 2 and lands the
Phase 3 PAL implementations + JIT-admin scaffold + revocation
watchdog. All tasks below are gated on
`modules.software.enabled` (Phase 2),
`modules.script_runner.enabled` (Phase 2.7),
`modules.device_control.enabled` (Phase 2.8 windows), and
`modules.jit_admin.enabled` (Phase 3); an agent with all four
flags `false` (the default) runs the same idle code path as
before.

Phase 2 — agent-side completion:

- **2.6** — Production-grade catalogue manifest verifier in
  [`crates/sda-software/src/manifest.rs`](../../crates/sda-software/src/manifest.rs).
  Accepts a vector of pinned Ed25519 signing keys (key rotation),
  rejects manifests older than a configurable
  `manifest_max_age_secs`, surfaces a structured `ManifestError`
  enum for every failure mode (`Expired`, `UnknownKeyId`,
  `SignatureMismatch`, `MalformedHash`, `MalformedSignature`,
  `MalformedKey`, `Decode`), and verifies per-artefact SHA-256 at
  download time. Unit tests cover valid manifest, expired
  manifest, wrong-key signature, tampered artefact hash, and
  unknown `key_id`.
- **2.7** — New
  [`sda-script-runner`](../../crates/sda-script-runner/) crate.
  Verifies every `ScriptRequest` against pinned Ed25519 keys
  before any process is spawned, matches the script's
  `canonical_name` against
  `modules.script_runner.allowlist` glob patterns, runs scripts
  with a hard wall-clock budget (`max_duration_secs`, default 90s)
  and a hard output-byte ceiling (`max_output_bytes`, default
  1 MiB), and emits `EventKind::ScriptRunResult` plus
  `EventKind::EvidenceRecord` for every run. No PTY, no stdin,
  and no inherited environment beyond the explicit allow-list.
  Unit tests cover signed-pass, unsigned-rejected,
  allow-list match / reject, timeout-kills-process, output
  truncation, and evidence emission.
- **2.8** — Maintenance-window + quiet-hours policy in
  [`crates/sda-device-control/src/windows.rs`](../../crates/sda-device-control/src/windows.rs).
  Parses `modules.device_control.windows.maintenance.allow` and
  `quiet_hours.deny` from config (HH:MM ranges + day-of-week
  parsing including ranges like `mon-fri`), supports timezone
  conversion via `chrono-tz`, and exposes
  `MaintenanceWindowPolicy::should_execute` that returns
  `Execute` / `Defer` / `Refuse`. Wired into step 9 of the
  `sda-device-control::router` validation pipeline; jobs outside
  the window get `ActionStatus::Skipped` with reason
  `outside_maintenance_window`. Unit tests cover in-window,
  out-of-window, quiet-hours block, timezone edge cases, and
  day-range parsing.
- **2.9** — Approval-state surfacing in
  [`crates/sda-software/src/approval.rs`](../../crates/sda-software/src/approval.rs).
  Compares installed packages against the catalogue manifest and
  classifies each as `Approved` / `Pending` / `Denied` /
  `Recalled` / `Unknown`. For every non-`Approved` state the
  module emits an `EventKind::DeviceControlRecommendation` with
  the canonical plain-English text per state. Unit tests cover
  every state, state transitions, and the singular / plural
  templating edges.
- **2.10** — Rollback path in
  [`crates/sda-software/src/rollback.rs`](../../crates/sda-software/src/rollback.rs).
  `RollbackOrchestrator::record_pre_update` captures the current
  installed version into a JSON manifest in the configured
  cache directory before any `UpdatePackage` runs;
  `execute_rollback` re-installs the previous version (or
  uninstalls the half-applied update if no prior version was
  recorded), surfaces a `RollbackOutcome`, and clears the entry
  so a future update is not blocked by a stale record. Manifest
  state survives agent restarts. Unit tests cover successful
  update clears the entry, failed update triggers rollback,
  rollback persistence round-trip, and the no-prior-version
  uninstall path.
- **2.11** — Software evidence emission in
  [`crates/sda-software/src/evidence.rs`](../../crates/sda-software/src/evidence.rs).
  Every install / update / uninstall / rollback action produces
  an `EvidenceRecord` whose `prev_record_hash` chains forward
  through the in-memory `SoftwareEvidenceEmitter`. Rollback
  evidence chains directly off the failed-update record so the
  audit trail captures both halves of the failure. Unit tests
  cover one-record, multi-record chaining, and the failed-update
  → rollback chain pair.
- **2.15** — Phase 2 E2E suite in
  [`crates/sda-agent/tests/e2e_software.rs`](../../crates/sda-agent/tests/e2e_software.rs)
  with a `make e2e-software` Makefile target. Eight hermetic
  tests cover catalogue manifest signature rejection,
  maintenance-window deferral, install / update / uninstall
  evidence chain linking, rollback orchestration with dual
  chained evidence records, approval-state recommendation
  surfacing, signed-script execution, unsigned-script
  rejection, and runaway-script timeout enforcement.

Phase 3 — agent-side scaffolding:

- **3.1** — Per-platform `AdminManager` impls in
  [`crates/sda-pal/src/admin_manager.rs`](../../crates/sda-pal/src/admin_manager.rs).
  Linux: time-boxed `/etc/sudoers.d/sda-jit-<user>` drop-in
  validated with `visudo -c` and revoked by file removal.
  macOS: `dseditgroup -o edit -a <user> -t user admin` with the
  reverse `-d` revocation. Windows: `net localgroup
  Administrators <user> /add` with the matching `/delete` revoke.
  Active grants persist to a per-platform state file under the
  configured cache directory so `observed_grants()` survives a
  process restart. Unit tests cover the state-file round-trip,
  CLI argument construction, and idempotent revoke (re-revoking
  an already-revoked grant is a no-op).
- **3.2** — New
  [`sda-jit-admin`](../../crates/sda-jit-admin/) crate. Implements
  `JitAdminModule::start(...)` matching the same shape as
  `SoftwareModule`, gated on `modules.jit_admin.enabled`. The
  grant lifecycle state machine
  ([`state_machine.rs`](../../crates/sda-jit-admin/src/state_machine.rs))
  drives `Idle → Requested → Approved → Granted → Revoked` plus
  the terminal `Denied` / `Expired` / `DriftDetected` branches.
  Each transition emits the matching `EventKind`
  (`JitAdminRequested`, `JitAdminGranted`, `JitAdminRevoked`).
  `GrantStore` ([`store.rs`](../../crates/sda-jit-admin/src/store.rs))
  persists active grants to disk so the watchdog can resume
  after a crash or reboot. Unit tests cover the full state
  machine, store round-trip, and event emission at every
  transition.
- **3.3** — Revocation watchdog in
  [`crates/sda-jit-admin/src/watchdog.rs`](../../crates/sda-jit-admin/src/watchdog.rs).
  Subscribes to a `tokio::time::sleep` until each grant's `until`,
  the `PowerProfileReceiver` for suspend / sleep transitions,
  and a heartbeat channel for `revoke_on.heartbeat_loss_secs`
  (default 120s). All revocations are idempotent — calling
  revoke on an already-revoked grant is a no-op — and emit
  `JitAdminRevoked` plus an `EvidenceRecord`. The OS-level
  logout listener is the next slice (Phase 3 boot-time scan,
  task 3.4). Unit tests cover timer-based revoke,
  power-profile-triggered revoke, heartbeat-loss revoke, and
  the idempotency invariant.

New workspace crates: `sda-script-runner`, `sda-jit-admin`. Both
are listed in the workspace `Cargo.toml` `[workspace]` `members`
table and `[workspace.dependencies]`. `sda-software` and
`sda-device-control` grew the production modules above.

Tests:

- **7 / 7** Phase 1 Device Control E2E tests
  (`make e2e-device-control`) remain green.
- **8 / 8** Phase 2 Device Control E2E tests
  (`make e2e-software`).
- **All workspace unit tests pass** across all crates (run via
  `cargo test --workspace`); the previous baseline remains green
  and the new surface adds dedicated tests for every task above.
- `cargo fmt --all -- --check`, `cargo clippy --all-targets
  --all-features -- -D warnings`, and `cargo deny check licenses`
  all pass.

Documentation: `PROGRESS.md`, `README.md`, `ARCHITECTURE.md`, and
`PHASES.md` updated to reflect tasks 2.6–2.11, 2.15 and 3.1–3.3
as Done. The five PROPOSAL.md § 2.2 examples are unchanged.
