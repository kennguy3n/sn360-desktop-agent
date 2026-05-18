# Device Control

Device Control is SDA's SME-first device management surface. It
turns inventory + posture observations into plain-English findings,
turns findings into one-click signed actions, and produces an
append-only audit trail for each fix.

This document describes the agent-side module surface. The
companion control-plane services (Risk Engine, Action Orchestrator,
Approval Service, Package Catalog, Evidence Vault, SMI Engine) live
in
[`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).

For the wire formats see
[`wire-protocols/device-control.md`](./wire-protocols/device-control.md).
For the YAML configuration schema see
[`configuration-reference.md`](./configuration-reference.md).

---

## Table of contents

1. [Product loop](#1-product-loop)
2. [Modules](#2-modules)
3. [Data model](#3-data-model)
4. [Signed-job lifecycle](#4-signed-job-lifecycle)
5. [Posture and inventory](#5-posture-and-inventory)
6. [Approved software catalogue](#6-approved-software-catalogue)
7. [Just-in-Time admin](#7-just-in-time-admin)
8. [Application control](#8-application-control)
9. [Remote support](#9-remote-support)
10. [Pricing-tier alignment](#10-pricing-tier-alignment)
11. [Clean-room policy](#11-clean-room-policy)

---

## 1. Product loop

```
   inventory + posture     plain-English        signed action       evidence       SMI sub-score
   collected by agent  →   finding by control   job dispatched   →  recorded   →   moves on the
                           plane                to agent            (signed)       dashboard
```

If a feature does not start at "found issue" and end at "SMI moved",
it is not in scope for Device Control. Five canonical examples
drove the initial MVP shape:

| # | Example | Plain-English risk | One-click fix |
|---|---|---|---|
| 1 | 6 permanent admins | "6 users have permanent admin rights — risky on shared laptops." | Demote to standard; enrol in JIT admin |
| 2 | 12 outdated apps | "12 apps haven't been updated in 60+ days — known CVEs apply." | Patch via the approved catalogue |
| 3 | 4 missing laptops | "4 laptops haven't checked in for 14+ days — possibly lost." | Mark missing; require remote support on next check-in |
| 4 | Unknown software | "Software not on your approved list was installed on 3 devices." | Flag, request approval, optionally uninstall |
| 5 | User needs admin | "User X is asking for admin access to install Tool Y." | Grant time-boxed JIT admin with auto-revocation |

---

## 2. Modules

Device Control is the union of eleven agent crates:

| Crate | Responsibility |
|---|---|
| `sda-device-control` | Module that owns the event surface, signed-job intake, and result publishing |
| `sda-query` | osquery-compatible declarative query engine; runs scheduled and ad-hoc queries via PAL providers |
| `sda-policy` | Policy evaluator — turns query results + posture + inventory deltas into `Finding`s |
| `sda-posture` | Live device-posture snapshots: disk encryption, firewall, screen lock, OS patch level |
| `sda-software` | Approved-catalogue client + per-OS install / update / uninstall via the `PackageManager` PAL trait |
| `sda-jit-admin` | Just-in-Time admin/root grant + revocation watchdog + drift detection |
| `sda-script-runner` | Signed-script executor with a hard allow-list and short execution budget |
| `sda-app-control` | Application control (monitor → enforce) wrapping WDAC, Santa, dm-verity equivalents |
| `sda-remote-support` | Operator-initiated, user-consented remote support session |
| `sda-agent-vitals` | Agent self-telemetry: heartbeat, queue depth, last-seen, watchdog faults |
| `sda-management-compat` | Library-only translation shim for Fleet-flavoured GitOps YAML so existing customers can adopt SDA |

Every Device Control crate depends only on `sda-core`,
`sda-event-bus`, `sda-pal`, and `sda-comms`. Cross-module
communication is exclusively over the event bus.

### 2.1 PAL traits

Device Control introduces five PAL traits:

| Trait | Responsibility |
|---|---|
| `PackageManager` | Install / update / uninstall / list packages |
| `AdminManager` | Grant / revoke local admin / root + enumerate current admins |
| `DevicePostureProvider` | Disk encryption, firewall, screen lock, OS patch level snapshots |
| `AppControlProvider` | Application control policy push (WDAC / Santa / dm-verity) |
| `RemoteSupportProvider` | Start / end a user-consented remote support session |

Per-OS implementations are documented in
[`architecture.md` § 4.2](./architecture.md#42-per-os-implementation-matrix).

---

## 3. Data model

Device Control communicates over five canonical wire shapes. The
authoritative schema lives in
[`wire-protocols/device-control.md`](./wire-protocols/device-control.md);
the summary here is what a reader needs to understand the system.

| Shape | Producer | Consumer | Description |
|---|---|---|---|
| `Finding` | Agent | Control-plane Risk Engine | A single observation worth scoring |
| `Recommendation` | Control plane | Control-plane UI + agent (informational) | A plain-English fix attached to one or more findings |
| `SignedActionJob` | Control plane | Agent (executor) | An Ed25519-signed instruction the agent will execute |
| `ActionResult` | Agent | Control plane (Action Orchestrator + Evidence Vault) | What happened when the job ran |
| `EvidenceRecord` | Agent | Evidence Vault | The append-only audit projection of an `ActionResult` |

### 3.1 Encoding

- **Live wire (agent ↔ control plane):** MessagePack over `sda-comms`
  TLS 1.3 + HTTP/2 frames. `serde(rename_all = "snake_case")`.
- **On-disk evidence cache + Evidence Vault:** Canonical JSON
  (RFC 8785), one record per line, append-only.
- **Debug logs:** Compact JSON, redacted per the redaction invariant.

### 3.2 Bounded sizes

Every variable-length field is bounded; producers must reject
over-cap messages, consumers MUST reject (not truncate) over-cap
messages:

| Field | Hard cap |
|---|---|
| `Finding.plain_english` | 512 UTF-8 graphemes |
| `Finding.evidence` | 16 KiB |
| `Recommendation.plain_english` | 512 UTF-8 graphemes |
| `SignedActionJob.args` | 64 KiB |
| `ActionResult.output` | 64 KiB (full output SHA-256'd into the evidence chain) |

### 3.3 Required-field discipline

All schemas use `#[serde(deny_unknown_fields)]` on the consumer
side. Unknown fields are a hard parse error.

---

## 4. Signed-job lifecycle

Every server-issued action (install, uninstall, JIT admin, script
run, app-control policy push, remote-support start, host isolation,
MDM action) passes through the same 10-step validation pipeline
implemented in `sda-device-control::router`:

1. Verify the message frame decoded successfully under TLS 1.3 +
   HTTP/2 + MessagePack.
2. Parse `SignedActionJob` strictly (deny unknown fields).
3. Look up `key_id` against the locally pinned rotation set.
4. Verify the Ed25519 signature over the canonical encoding.
5. Reject if `not_before` is in the future or `not_after` in the
   past (≤ 60 s clock-skew tolerance).
6. Reject if `tenant_id` does not match the agent's enrolled tenant.
7. Reject if `device_id` does not match the agent's local identity.
8. Reject if `action` is not in the locally compiled allow-list for
   the agent's pricing tier.
9. Apply maintenance window / quiet hours configuration.
10. Hand off to the relevant sub-module with a deadline and a budget.

```
SignedActionJob       +-----------------+      Allow + budget
arrives over    --->  | 10-step router  | ---> sub-module executor
sda-comms             +--------+--------+
                               | Reject
                               v
                         JobRefused event
                         (reason string)
```

Failure at any step produces a `JobRefused` event with a structured
reason; the operator-facing UI uses these reasons verbatim. Wipe
(`RemoteWipe`) and a small number of other high-impact actions
require **two distinct approver signatures with two distinct
`key_id`s** — see [`desktop-mdm.md`](./desktop-mdm.md).

---

## 5. Posture and inventory

`sda-posture` and `sda-enhanced-inventory` are the producers that
feed the Risk Engine.

### 5.1 Posture snapshots

`sda-posture` emits `PostureSnapshot` events at a configurable
interval (default 30 minutes) and on demand:

```rust
PostureSnapshot {
    timestamp: DateTime<Utc>,
    disk_encryption: Encryption,    // Off | On { kind, key_escrowed }
    firewall: FirewallState,        // Off | On { default_inbound: Deny | Allow }
    screen_lock: ScreenLock,        // Off | On { timeout_secs }
    os_patch_level: PatchLevel,     // UpToDate | Behind { pending_security: u32, last_check: DateTime<Utc> }
}
```

| Platform | Backend |
|---|---|
| Windows | `manage-bde`, `Get-NetFirewallProfile`, `LockWorkStation`, `Get-WindowsUpdate` |
| macOS | `fdesetup`, `socketfilterfw`, `defaults read com.apple.screensaver`, `softwareupdate --list` |
| Linux | `cryptsetup status`, `firewalld` / `ufw` / `nftables`, `gsettings org.gnome.desktop.screensaver`, `apt`/`dnf`/`zypper` `check-update` |

### 5.2 Inventory

`sda-inventory` and `sda-enhanced-inventory` between them produce:

- Hardware + OS facts (one snapshot per heartbeat).
- Installed packages with version, publisher, and last-update time.
- Running software snapshot (per-heartbeat).
- Browser-extension inventory (Chrome / Edge / Firefox).
- CycloneDX SBOM, emitted on demand for compliance flows.
- Local admin / root account enumeration.

Inventory deltas flow on `device_control.inventory_delta.*` NATS
subjects so the Risk Engine can score change rather than absolute
state.

---

## 6. Approved software catalogue

`sda-software` is the catalogue client. The control plane publishes
a per-tenant signed manifest of approved packages (name, version,
publisher, SHA-256, install args); the agent reconciles the local
state against the manifest:

- `InstallPackage { catalogue_id, version }` — install if absent or
  upgrade if older.
- `UpdatePackage { catalogue_id }` — upgrade to the catalogue
  version.
- `UninstallPackage { catalogue_id }` — remove the local package.

The signed-job router validates the action; `sda-software` then
calls the per-OS `PackageManager` trait. Per-OS backends:

| Platform | Backend | Catalogue source |
|---|---|---|
| Windows | `winget` CLI | `winget` source bound to the tenant manifest |
| macOS | Munki-style local repo (clean-room) | HTTPS bucket with Ed25519-signed manifest + per-package SHA-256 |
| Linux | Native `apt` / `dnf` / `yum` / `zypper` auto-detected by `PackageManager::detect()` | Tenant repository pinned at install time |

Operations are gated by maintenance windows and quiet hours. Each
operation produces a `Software*Result` event with the installer log
hash + exit code.

---

## 7. Just-in-Time admin

`sda-jit-admin` grants time-boxed admin or root privileges to a
named user. The grant is dispatched as a signed
`GrantJitAdmin { user, duration, reason, approver_id }` job; on
expiry the watchdog revokes the grant and verifies no drift
remains.

| Platform | Grant mechanism | Revocation |
|---|---|---|
| Windows | `Add-LocalGroupMember -Group Administrators -Member <user>` | `Remove-LocalGroupMember` + enforce drift check every 30 s |
| macOS | `dseditgroup -o edit -a <user> -t user admin` | Symmetric `-d <user>` + drift check |
| Linux | Drop-in `/etc/sudoers.d/sn360-jit-<id>` with a `Defaults timeout` | Delete drop-in + drift check |

Drift detection runs on a separate `tokio` task from the watchdog;
if a grant outlives its budget or if the privilege was reinstated
out-of-band, the agent revokes and emits an `IdentityAlert`.

Grants are **always evidence-emitting** — the `GrantJitAdmin`
`ActionResult` and the matching revocation are both signed into the
evidence chain.

---

## 8. Application control

`sda-app-control` is a thin policy push surface over the platform's
native app-control mechanism. The agent does not implement
allow/deny enforcement itself.

| Platform | Backend | Modes |
|---|---|---|
| Windows | WDAC + AppLocker via PowerShell + signed `.cip` policies | Monitor → Enforce |
| macOS | Santa (Apache-2.0) integrated as a sidecar via XPC | Monitor → Lockdown |
| Linux | dm-verity-aware allow-list, `fapolicyd` where available | Monitor → Enforce |

The `PushAppControlPolicy { policy }` signed job ships a tenant
policy bundle; the agent applies it to the platform backend and
returns the activation status in an `ActionResult`. The agent does
not interpose on individual exec events — that is the backend's
job.

---

## 9. Remote support

`sda-remote-support` is a clean-room implementation of a
MeshCentral-style remote support protocol. Two invariants hold:

1. **User consent.** A consent banner with a count-down is shown to
   the local user before any session starts. If the user denies or
   the count-down expires, the session is refused.
2. **Time bounding.** Every session has a `not_after` deadline
   carried in the signed job. The agent forcibly tears down the
   session at the deadline.

| Platform | Backend |
|---|---|
| Windows | Windows Graphics Capture (`WGC`) + a virtual input channel |
| macOS | ScreenCaptureKit + a virtual input channel |
| Linux | PipeWire / X11 capture with the operator's pointer mediated by XCB |

Every session emits `RemoteSupportStarted` / `RemoteSupportEnded`
events into the evidence chain. The session content itself is
**not** mirrored to the control plane — only metadata.

---

## 10. Pricing-tier alignment

Device Control surfaces are gated by SN360 plan. The control plane
enforces tiers; the agent ships every capability and runs whatever
the gateway authorises:

| Tier | Device Control surface |
|---|---|
| Free | Inventory + admin / root review (read-only). Plain-English findings, no fixes. |
| Pro | Free + approved catalogue, one-click patch / update / uninstall, JIT admin with manual approval, SMI sub-scores. |
| Ultimate | Pro + auto-approval workflows, app control (monitor → enforce), remote support, mobile MDM connectors, MSP mode. |

---

## 11. Clean-room policy

Device Control's design borrows *concepts* from open-source
endpoint-management projects but does not vendor their source. The
binding decision:

- **Fleet** (MIT, Go + osquery) — concepts referenced (declarative
  queries, software jobs, agent vitals, GitOps workflows); **no
  Fleet source code (MIT or EE) is vendored, copied, or
  translated**. Fleet's Go server, `fleetd`/Orbit agent, MySQL
  schema, and EE features are explicitly out of scope.
- **MakeMeAdmin** (GPL) — concept-referenced for Windows JIT admin;
  clean-room re-implementation.
- **SAP Privileges** (Apache-2.0) — concept-referenced for macOS
  JIT admin; clean-room re-implementation.
- **Munki** (Apache-2.0) — concept-referenced for macOS package
  catalogue; clean-room re-implementation.
- **Santa / North Pole Santa** (Apache-2.0) — integrated as a
  sidecar on macOS (XPC API surface). No Santa source is vendored.
- **MeshCentral** (Apache-2.0) — concept-referenced; clean-room
  re-implementation.
- **Tactical RMM** — benchmark only; license restricts SaaS use.

The full licence audit lives in [`licensing.md`](./licensing.md).
