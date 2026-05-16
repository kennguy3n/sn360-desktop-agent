# ShieldNet Desktop MDM — Development Progress

> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)

Tracks the implementation status of ShieldNet Desktop MDM against
the roadmap in [PROPOSAL.md § 14](./PROPOSAL.md#14-phasing).

Status legend:

- **Done** — merged to `main` and covered by tests / benchmarks below.
- **In Progress** — branch exists, code is being written / reviewed.
- **Not Started** — no implementation work started yet.

> **Scope note:** Tasks marked ⚙️ are server-side and implemented in
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).
> They are listed here for cross-reference only. The matching
> control-plane progress tracker lives at
> [`sn360-security-platform/docs/desktop-mdm/PROGRESS.md`](https://github.com/kennguy3n/sn360-security-platform/blob/main/docs/desktop-mdm/PROGRESS.md).

> **Phase identifier note:** Desktop MDM uses **Phase M** identifiers
> (M1, M2, M3, M4) to avoid collision with the existing **Phase D**
> identifiers (D1–D4) for Device Control. The two workstreams ship
> independently.

## Current Status

**Phases M1–M3 (agent-side) are Done** — all agent-side code has
landed in PR [#20](https://github.com/kennguy3n/sn360-desktop-agent/pull/20).
Server-side tasks (M1.7, M1.8, M2.4, M4.*) remain Not Started.
The existing SDA test surface — **1075+ unit tests, 14/14 base E2E,
10/10 security E2E** — remains green.

## Phase summary

| Phase | Theme                                                            | Status      |
|-------|------------------------------------------------------------------|-------------|
| M1    | Auto-remediation + recovery key escrow + OS patch                | Done (agent-side) |
| M2    | Remote wipe + remote lock + lost mode                            | Done (agent-side) |
| M3    | Declarative configuration profiles                               | Done (agent-side) |
| M4    | Dashboard UI + one-click actions + recovery key viewer           | Not Started |

The headline exit criterion for Phase M as a whole is: a tenant admin
can author no configuration at all, deploy SDA with `modules.mdm`
default-on, and have every laptop self-remediate FDE / firewall /
screen-lock posture within one `sda-posture` snapshot interval
(default 300 s), with every action visible in the audit trail and
the corresponding `mdm_compliance` SMI sub-score recomputed inside
60 s.

---

## Phase M1 — Auto-remediation + recovery key escrow + OS patch (8–10 weeks)

The "80 % of MDM value for 20 % of effort" phase. Lands the
`MdmProvider` PAL trait, the `sda-mdm` crate scaffold, the
auto-remediation supervisor, recovery key escrow, and OS patch
orchestration. Ships with the new `FindingKind` / `ActionKind` /
`MessageType` variants needed to surface MDM compliance signals to
the control plane.

| ID    | Task                                                                                         | Status      |
|-------|-----------------------------------------------------------------------------------------------|-------------|
| M1.1  | `sda-pal::MdmProvider` trait + per-OS implementations for `enable_disk_encryption`, `enable_firewall`, `set_screen_lock` (Windows / macOS / Linux) | Done |
| M1.2  | `sda-mdm` crate scaffold (`crates/sda-mdm/`) + `auto_remediate::supervisor` subscribed to `sda-posture` snapshots, with the 24h debounce window from [PROPOSAL § 6.4](./PROPOSAL.md#64-auto-remediation--local-only) | Done |
| M1.3  | Recovery key escrow — BitLocker (`manage-bde -protectors -get`), FileVault (`fdesetup showrecoverykey`), LUKS (`cryptsetup luksDump` / SN360 keyslot 7); ChaCha20-Poly1305 envelope per [PROPOSAL § 6.3](./PROPOSAL.md#63-recovery-key-escrow--encryption-envelope) | Done |
| M1.4  | OS patch orchestration — Windows (`PSWindowsUpdate` / `UsoClient`), macOS (`softwareupdate`), Linux (`unattended-upgrades` / `dnf-automatic` / `zypper patch`); maintenance-window + battery-aware deferral | Done |
| M1.5  | New `FindingKind` variants in `sda-core` (`DiskEncryptionOff`, `FirewallOff`, `ScreenLockOff`, `OsPatchOverdue`, `RecoveryKeyNotEscrowed`, `DeviceLost`) + new `ActionKind` variants (`EscrowRecoveryKey`, `InstallOsUpdate`, `EnableDiskEncryption`, `EnableFirewall`, `SetScreenLock`) | Done |
| M1.6  | New `MessageType` variants in `sda-comms` (`MdmRecoveryKeyEscrowed`, `MdmOsUpdateResult`, `MdmAutoRemediationResult`) + explicit `encode_body()` arms + `map_event_to_message` mapping | Done |
| M1.7  | MDM Findings → Risk Engine recommendations ⚙️ (`services/risk-engine`: `disk_encryption_off`, `firewall_off`, `screen_lock_off`, `recovery_key_not_escrowed`, `os_patch_overdue` rules)         | Not Started |
| M1.8  | SMI `mdm_compliance` sub-score ⚙️ (`services/smi-engine`: formula `clamp(100 - 10*fde_off - 10*fw_off - 10*sl_off - 5*rk_missing - 5*patch_overdue)`) | Not Started |
| M1.9  | Phase M1 E2E suite (`make e2e-mdm`) — Linux / macOS / Windows hermetic tests for auto-remediation, recovery key escrow round-trip, OS patch scan + install | In Progress |

### Phase M1 exit criteria

- `cargo test --workspace` green; new `sda-mdm` crate passes
  `cargo clippy --workspace -- -D warnings`.
- `make e2e-mdm` passes on all three platforms.
- A device booted with `modules.mdm` default-on, FDE off, firewall
  off, screen lock off self-remediates all three within one
  `sda-posture` snapshot interval.
- Recovery key for the device's primary disk-encryption stack is
  escrowed to the privacy-vault within one boot of agent enrolment.
- `mdm_compliance` sub-score reflects the post-remediation state
  within 60 s of the auto-remediation `EvidenceRecord` being written.
- Existing benchmark gate (`make benchmark-ci`) shows no regression
  on idle RSS / idle CPU / FIM scan peak / binary size budgets.

---

## Phase M2 — Remote wipe + remote lock + lost mode (6–8 weeks)

Lands the operator-driven destructive / reversible actions: remote
wipe (dual-control), remote lock, lost mode with last-known IP
geolocation. Dual-control approval is enforced by both the
control-plane Approval Service and the agent's signed-job validator.

| ID    | Task                                                                                                                | Status      |
|-------|---------------------------------------------------------------------------------------------------------------------|-------------|
| M2.1  | Remote wipe — per-OS crypto-shred + OS factory reset (`manage-bde` + `systemreset.exe`, `fdesetup removerecovery` + `obliterate` / `diskutil eraseDisk`, `cryptsetup luksErase` + `dd` + forced reboot); evidence-before-action emit per [PROPOSAL § 6.2](./PROPOSAL.md#62-wipe--dual-control) | Done |
| M2.2  | Remote lock — per-OS lock screen + tenant message (`LockWorkStation` + credential-provider tile, `CGSession -suspend` + notification, `loginctl lock-sessions` + Plymouth) | Done |
| M2.3  | Lost mode — agent-side locked display + IP-geolocation last-known-location reporting on every successful reconnect; reversible via `ExitLostMode` action | Done |
| M2.4  | Desktop MDM service ⚙️ (`services/desktop-mdm` wipe / lock / lost-mode command dispatch endpoints) | Not Started |
| M2.5  | Dual-control approval for wipe actions — Approval Service enforces two distinct approvers; agent's signed-job validator enforces `signatures.len() >= 2` and distinct `approver_user_id` per [ARCHITECTURE § 4.4](./ARCHITECTURE.md#44-signed-job-validation-extensions) | Done |
| M2.6  | Phase M2 E2E suite — single-signature wipe job is refused; two-signature wipe job crypto-shreds; lock + lost-mode + exit-lost-mode round-trip; last-known-location appears in vitals after reconnect | In Progress |

### Phase M2 exit criteria

- A single-signature `RemoteWipe` job is refused by the agent
  regardless of control-plane intent (validator enforcement).
- A two-signature `RemoteWipe` job successfully crypto-shreds and
  invokes the OS factory reset path on Windows / macOS / Linux.
- Remote lock + exit cycle is end-to-end reversible without data
  loss.
- Lost mode reports last-known IP geolocation on every successful
  network reconnect.

---

## Phase M3 — Declarative configuration profiles (6–8 weeks)

Lands the declarative configuration enforcement path: password
policy, screen lock, Bluetooth / camera / Wi-Fi enforcement on
Windows / macOS / Linux. Profiles ship via the existing TRDS bundle
path with Ed25519 signature coverage.

| ID    | Task                                                                                                                  | Status      |
|-------|-----------------------------------------------------------------------------------------------------------------------|-------------|
| M3.1  | Declarative configuration profile schema — `SignedConfigProfile` type, RFC 8785 canonical-JSON body, Ed25519 signature, `key_id` rotation set | Done |
| M3.2  | Config profile enforcement — Windows (registry writes under `HKLM\SOFTWARE\Policies\Microsoft\Windows\*`), macOS (`profiles install` legacy + `mdmclient` DDM on Sequoia+), Linux (`dconf write` + polkit drop-in + `pam_pwquality.conf`) | Done |
| M3.3  | Config profile push via TRDS signed bundle — `policy/mdm/profile.json` slice + filesystem watcher under `/var/lib/sn360-desktop-agent/bundle/policy/mdm/` ⚙️ (TRDS-compiler side in `sn360-security-platform`) | Done (agent-side) |
| M3.4  | Phase M3 E2E suite — push profile via bundle, verify password policy / screen lock / Bluetooth enforcement on all three platforms; tampered profile rejected at signature check | In Progress |

### Phase M3 exit criteria

- A signed profile bundle slice applies password policy / screen
  lock / Bluetooth / camera / Wi-Fi enforcement on Windows / macOS /
  Linux within one TRDS bundle pull cadence.
- A tampered profile bundle is rejected at the signature check; the
  previous profile remains in force (no warn-and-continue).
- `MdmConfigProfileApplied` events appear in the audit trail with
  the `profile_id` of the active profile.

---

## Phase M4 — Dashboard UI + one-click actions + recovery key viewer (4–6 weeks)

All tasks in this phase are control-plane / dashboard work (⚙️) but
gate the agent's GA story. The agent-side dependency is that all
prior phases' `EventKind` variants ride the existing alert pipeline
unchanged; no new agent code lands in M4.

| ID    | Task                                                                                                       | Status      |
|-------|------------------------------------------------------------------------------------------------------------|-------------|
| M4.1  | Dashboard MDM status page ⚙️ (`sn360-dashboard-plugin/public/pages/DesktopMDM/` — device compliance grid)  | Not Started |
| M4.2  | One-click wipe / lock / unlock actions in dashboard ⚙️ (calls `services/desktop-mdm` REST endpoints; wipe button routes through the dual-control approval workflow) | Not Started |
| M4.3  | Recovery key viewer ⚙️ (role-gated, audit-logged; recovery key fetched through privacy-vault deanonymisation path with an audit-log entry per fetch) | Not Started |
| M4.4  | OS patch status + one-click "patch all" action ⚙️ (aggregate patch status across devices; "patch all" dispatches `InstallOsUpdate` jobs through the existing signed-job path with a maintenance-window default) | Not Started |
| M4.5  | Phase M4 E2E suite — dashboard create → one-click action → agent receives signed job → result visible in dashboard inside 30 s | Not Started |

### Phase M4 exit criteria

- Operator can view per-device MDM compliance grid in the dashboard.
- Operator can issue one-click wipe / lock / unlock from the
  dashboard; wipe requires the two-approver workflow.
- Operator with the `recovery_key_viewer` role can fetch a recovery
  key; every fetch writes an audit-log entry.
- Operator can view OS patch status and issue a "patch all" action
  bounded by the configured maintenance window.

---

## Tests & Benchmarks

Desktop MDM test surface (target):

- **N / N** Phase M1 E2E tests (`make e2e-mdm`) — auto-remediation,
  recovery key escrow, OS patch.
- **N / N** Phase M2 E2E tests (`make e2e-mdm-actions`) — wipe (dual
  control), lock, lost mode.
- **N / N** Phase M3 E2E tests (`make e2e-mdm-profile`) — config
  profile push + enforcement.
- All workspace unit tests pass (`cargo test --workspace`).
- All `MdmProvider` per-OS implementations covered by
  platform-gated tests under `crates/sda-mdm/tests/`.

Existing SDA test surface (1075 unit tests, 14/14 base E2E, 10/10
security E2E) remains green.

Existing budgets — idle RSS < 15 MB, idle CPU < 0.1 %, FIM scan peak
< 3 %, binary < 7 MB — must remain green; the benchmark gate
(`make benchmark-ci`) covers regression. The `sda-mdm` crate is
budgeted at < 1 MB binary size, < 0.5 MB idle RSS contribution.

---

## Known Risks

The full risk register lives in
[PROPOSAL.md § 15](./PROPOSAL.md#15-risk-register). The top three to
watch during M1 are:

1. **Recovery key leakage in transit / at rest** — mitigated by
   ChaCha20-Poly1305 envelope under a per-device HKDF-derived key
   plus privacy-vault role-gating; pinned by M1.3 test coverage.
2. **Auto-remediation feedback loop** — mitigated by the 24h
   debounce window on the local job state machine; pinned by M1.2
   test coverage.
3. **Platform-specific inconsistency** — mitigated by the
   `MdmProvider` trait's uniform contract; pinned by M1.1
   per-platform test coverage and `make e2e-{linux,macos,windows}-mdm`.

---

## Cross-references

- [PROPOSAL.md](./PROPOSAL.md) — full technical proposal.
- [ARCHITECTURE.md](./ARCHITECTURE.md) — diagram-first companion.
- [`device-control/PROPOSAL.md`](../device-control/PROPOSAL.md) —
  sibling Device Control proposal; reuses signed-job validator and
  evidence chain.
- [`device-control/PROGRESS.md`](../device-control/PROGRESS.md) —
  sibling Device Control progress tracker (phases D1–D4).
- Control-plane companion:
  [`sn360-security-platform/docs/desktop-mdm/PROGRESS.md`](https://github.com/kennguy3n/sn360-security-platform/blob/main/docs/desktop-mdm/PROGRESS.md).
