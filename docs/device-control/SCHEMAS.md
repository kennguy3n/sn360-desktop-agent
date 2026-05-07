# Device Control — Canonical Schema Specifications

> **License:** SN360 Proprietary — see [`../../LICENSE`](../../LICENSE)
> **Status:** Phase 0 — stable for Phase 1 implementation | **Date:** May 2026
> **Companion to:**
> [`ADR-001-functional-port.md`](./ADR-001-functional-port.md),
> [`PROPOSAL.md` § 8](./PROPOSAL.md#8-data-model),
> [`ARCHITECTURE.md` § 3](./ARCHITECTURE.md#3-data-model),
> [`fleet-capability-mapping.md`](./fleet-capability-mapping.md)

---

## 1. Purpose

This document is the **canonical, stable specification** for the
five Device Control wire schemas:

1. [`Finding`](#5-finding) — an observation produced by the agent.
2. [`Recommendation`](#6-recommendation) — a control-plane fix
   suggestion attached to one or more findings.
3. [`SignedActionJob`](#7-signedactionjob) — an Ed25519-signed
   instruction the agent will execute.
4. [`ActionResult`](#8-actionresult) — what happened when the job
   ran.
5. [`EvidenceRecord`](#9-evidencerecord) — the append-only audit
   projection of an `ActionResult`.

It satisfies Phase 0 task **0.11** in
[`PHASES.md`](./PHASES.md#phase-0--architecture-legal-and-schema-2-weeks)
("Schema specs — finalise `Finding`, `Recommendation`,
`SignedActionJob`, `ActionResult`, `EvidenceRecord`"). Once this
document is merged, the schemas are **stable**: any breaking change
requires a new ADR + a major-version bump (see
[§ 11. Versioning and compatibility](#11-versioning-and-compatibility)).

> **ADR alignment.** Every schema below is SDA-original; **no Fleet
> source code (MIT or EE) was consulted** during the design per
> [`ADR-001-functional-port.md`](./ADR-001-functional-port.md).
> Where the *concept* of a Fleet object inspired the SDA shape (e.g.
> Fleet "Activities" → `EvidenceRecord`), it is called out in
> [`fleet-capability-mapping.md`](./fleet-capability-mapping.md) and
> the implementation is clean-room.

---

## 2. Conventions

### 2.1 Encoding

| Surface | Encoding |
|---|---|
| Agent ↔ control plane (live wire) | **MessagePack** carried inside `sda-comms` TLS 1.3 + HTTP/2 frames. Field names match the Rust `serde` `#[serde(rename_all = "snake_case")]` form. |
| Agent on-disk evidence cache | **Canonical JSON** (RFC 8785) per record, one record per line, append-only. |
| Evidence Vault (control plane) | Canonical JSON (RFC 8785), Ed25519 signature chain. |
| Agent debug logs | Compact JSON (`serde_json` default), redacted per [§ 12](#12-redaction-and-pii-handling). |

The MessagePack and canonical-JSON forms must round-trip without
loss. Field ordering for canonical JSON follows RFC 8785 — fields
are emitted in lexicographic order so signatures are stable across
implementations.

### 2.2 Identifiers

| Field | Type | Notes |
|---|---|---|
| `*_id` (e.g. `finding_id`, `job_id`, `device_id`) | `Uuid` (UUIDv7) | UUIDv7 (time-ordered) so consumers can range-scan by time without joining a separate timestamp column. |
| `tenant_id` | `Uuid` | Allocated by the SN360 control plane during enrolment; mirrored into Postgres RLS via `sn360.tenant_id` GUC. |
| `key_id` | `String` (≤ 64 ASCII chars, regex `^[A-Za-z0-9._:-]+$`) | Rotation-aware label; never the bare key bytes. |

### 2.3 Time

All timestamps are **UTC**, `RFC 3339` with microsecond precision,
serialised as ISO-8601 strings in JSON and as
`{ tv_sec: i64, tv_nsec: u32 }` MessagePack ext-type 1 on the wire.

Clock skew is bounded to **±60 s** for any signed-job validation
window (see [§ 7.4 Validation rules](#74-validation-rules)).

### 2.4 Bounded sizes

| Field | Hard cap | Behaviour on overflow |
|---|---|---|
| `Finding.plain_english` | 512 chars (UTF-8 grapheme clusters) | Reject at the agent producer; emit `EventKind::FindingTooLarge`. |
| `Finding.evidence` (raw JSON) | 16 KiB serialized | Truncate to 16 KiB and add `"truncated": true` discriminator field. |
| `Recommendation.plain_english` | 512 chars | Reject at the control plane producer. |
| `SignedActionJob.args` (raw JSON) | 64 KiB serialized | Reject at the control plane producer. |
| `ActionResult.output` | 64 KiB | Truncate to first 64 KiB; SHA-256 the full output and store under `evidence_id`. |
| `EvidenceRecord.output_sha256` | 32 bytes | Always exactly 32 bytes (SHA-256). |

Producers MUST enforce the caps; consumers MUST reject (not
truncate) over-cap messages.

### 2.5 Required-field discipline

All schemas use `#[serde(deny_unknown_fields)]` on the consumer side.
Unknown fields are a hard parse error; this is an explicit
[ADR-001 commitment](./ADR-001-functional-port.md#decision)
(no compatibility creep with Fleet's wire format).

`Option<T>` fields default to `None` and are omitted on the wire
when `None` (`#[serde(skip_serializing_if = "Option::is_none")]`).

---

## 3. Type appendix (shared types)

### 3.1 `Severity`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
```

`Severity` aligns with the existing SDA detection-engine severity
ladder (see `crates/sda-local-detection`); reusing the same ladder
lets the control-plane Risk Engine merge Device Control findings
with on-device LDE detections without re-bucketing.

### 3.2 `Platform`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Platform {
    pub os: PlatformOs,           // "windows" | "macos" | "linux"
    pub version: String,          // OS version as reported by sda-pal::SystemInfo.
    pub arch: PlatformArch,       // "x86_64" | "aarch64" | "i686" | "armv7"
    pub distro: Option<String>,   // Linux distro id (e.g. "ubuntu", "fedora").
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformOs {
    Windows,
    Macos,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformArch {
    X86_64,
    Aarch64,
    I686,
    Armv7,
}
```

### 3.3 `AgentVersion`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentVersion {
    pub version: String,    // Semver — e.g. "0.10.0".
    pub build_sha: String,  // 40-char lowercase hex; the `sn360-desktop-agent` git SHA.
    pub channel: String,    // "stable" | "beta" | "canary" | "internal".
}
```

### 3.4 `FindingKind`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// Example #1: 6 permanent admins.
    PermanentAdmin,
    /// Example #2: 12 outdated apps (one finding per package).
    OutdatedApp,
    /// Example #3: 4 missing laptops (emitted by the control plane,
    /// not the agent — recorded here so consumers can pattern-match
    /// uniformly).
    DeviceMissing,
    /// Example #4: software not on the approved list.
    UnapprovedSoftware,
    /// Example #5: user requested admin access.
    AdminAccessRequested,
    /// Posture finding: a posture sub-state (BitLocker / FileVault /
    /// LUKS / firewall / screen-lock / patch level) is non-compliant.
    PostureViolation,
    /// Vulnerability finding: a CVE matched against the SBOM.
    VulnerabilityMatch,
    /// Catch-all for engine-specific findings; agent and control
    /// plane MUST treat the `evidence` blob as opaque.
    Other,
}
```

The `FindingKind` enum is **closed for Phase 1**. New variants
require a minor version bump and a new entry in
[`fleet-capability-mapping.md` § 3](./fleet-capability-mapping.md#3-cross-reference-to-canonical-customer-examples).

### 3.5 `ActionKind`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    InstallPackage,
    UpdatePackage,
    UninstallPackage,
    GrantJitAdmin,
    RevokeAdmin,
    RunScript,
    PushAppControlPolicy,
    StartRemoteSupport,
    EndRemoteSupport,
    QueryAdHoc,
}
```

Per-`ActionKind` argument sub-schemas are documented in
[§ 7.3 `args` sub-schemas](#73-args-sub-schemas).

### 3.6 `ActionStatus`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    /// Side-effect succeeded; the agent is convinced the system is
    /// in the desired state.
    Success,
    /// Side-effect was attempted but failed.
    Failure,
    /// The job was rejected before any side-effect ran. The
    /// `JobRefused` reason is mirrored into the `output` field.
    Refused,
    /// The agent decided the side-effect was unnecessary (e.g.
    /// "package already at desired version"). No state change.
    Skipped,
}
```

### 3.7 Cryptographic types

| Type | Wire form | Notes |
|---|---|---|
| Ed25519 signature | `bytes` (64 octets, MessagePack `bin`) on the wire; `"ed25519:" || base64url-no-pad` in canonical JSON. | All signatures are deterministic Ed25519 (RFC 8032). |
| SHA-256 hash | `bytes` (32 octets) on the wire; lowercase hex in canonical JSON. | Used for `output_sha256` and the evidence chain pre-image. |

---

## 4. Schema overview

| # | Schema | Producer | Consumer(s) | `MessageType` | NATS subject (`device_control.*`) | Pricing tier |
|---|---|---|---|---|---|---|
| 1 | `Finding` | Agent | Control-plane Risk Engine, Device Registry | `DeviceControlFinding` | `findings.<tenant_id>.<device_id>` | All |
| 2 | `Recommendation` | Control plane (Risk Engine) | Control-plane UI; agent (informational) | `DeviceControlRecommendation` | `recommendations.<tenant_id>` | Tier ≥ 2 |
| 3 | `SignedActionJob` | Control plane (Action Orchestrator) | Agent (executor) | `DeviceControlJob` | `jobs.<tenant_id>.<device_id>` | Tier ≥ 2 |
| 4 | `ActionResult` | Agent | Control-plane Action Orchestrator + Evidence Vault | `DeviceControlActionResult` | `action_results.<tenant_id>.<device_id>` | Tier ≥ 2 |
| 5 | `EvidenceRecord` | Agent | Evidence Vault (control plane); customer export | `EvidenceRecord` | `evidence.<tenant_id>.<device_id>` | All |

The `MessageType` and NATS rows above are reproduced from
[`ARCHITECTURE.md` § 4](./ARCHITECTURE.md#4-protocol-extension) so
this document is self-contained when reviewed in isolation. The
canonical list lives in `ARCHITECTURE.md` § 4.1 / § 4.2 and is
finalised in Phase 0 task 0.12.

---

## 5. `Finding`

A `Finding` is a single observation produced by the agent that the
control plane should consider for risk scoring or recommendations.
Findings are **idempotent by `finding_id`**: the agent must use the
same UUID for the same logical finding across re-emits (e.g. the
"6 permanent admins on this laptop" finding keeps the same
`finding_id` as long as the underlying admins do not change).

### 5.1 Rust definition

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    /// Stable finding identity; UUIDv7 (time-ordered).
    pub finding_id: Uuid,
    /// Identity of the device that produced the finding.
    pub device_id: Uuid,
    /// Tenant the device belongs to.
    pub tenant_id: Uuid,
    /// Schema version (see § 11). Always equal to `FINDING_SCHEMA_VERSION` (= 1).
    pub schema_version: u16,
    /// What kind of finding this is.
    pub kind: FindingKind,
    /// Severity classification.
    pub severity: Severity,
    /// Human-readable, SME-targeted explanation; ≤ 512 chars.
    pub plain_english: String,
    /// Compact structured detail; ≤ 16 KiB serialized. The shape of
    /// `evidence` is determined by `kind` (see § 5.3).
    pub evidence: serde_json::Value,
    /// When the agent observed the underlying state.
    pub observed_at: DateTime<Utc>,
    /// Optional: the queries / posture probes / inventory diff that
    /// produced this finding. Used for forensic re-walk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_refs: Option<Vec<SourceRef>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    /// Short identifier of the producing engine: "sda-query",
    /// "sda-posture", "sda-enhanced-inventory", etc.
    pub engine: String,
    /// Engine-specific reference (e.g. query name, posture probe id).
    pub reference: String,
}
```

### 5.2 Required-field invariants

- `tenant_id` MUST equal the agent's enrolled tenant id (validated
  at the Agent Gateway).
- `device_id` MUST equal the agent's local identity.
- `observed_at` MUST be ≤ now + 60 s and ≥ now − 24 h (older
  findings are evidence-only — emit them through `EvidenceRecord`
  instead).
- `plain_english` MUST be present and non-empty for `severity ∈ {
  Medium, High, Critical }` (the customer UI requires it).

### 5.3 Per-`FindingKind` `evidence` shapes

The `evidence` blob is opaque to the wire layer but has a strict
shape per `FindingKind` that the control-plane Risk Engine validates:

| `FindingKind` | `evidence` shape |
|---|---|
| `PermanentAdmin` | `{ "admins": [{ "user": "...", "since": "RFC3339", "via": "local"|"domain" }, …] }` |
| `OutdatedApp` | `{ "package": "...", "current_version": "...", "available_version": "...", "days_stale": u32, "cves": ["CVE-…", …] }` |
| `DeviceMissing` | `{ "last_checkin_at": "RFC3339", "last_known_ip": "...", "missed_intervals": u32 }` |
| `UnapprovedSoftware` | `{ "package": "...", "version": "...", "publisher": "...", "approval_state": "unknown"|"denied" }` |
| `AdminAccessRequested` | `{ "requested_by": "...", "for_tool": "...", "duration_minutes": u32, "reason": "..." }` |
| `PostureViolation` | `{ "control": "BitLocker"|"FileVault"|"LUKS"|"FirewallEnabled"|"ScreenLock"|"PatchLevel", "expected": "...", "actual": "..." }` |
| `VulnerabilityMatch` | `{ "cve": "...", "package": "...", "version": "...", "cvss": f32, "fixed_in": "..." }` |
| `Other` | Arbitrary JSON — opaque to the control plane. |

Validators are derived from this table; per-kind structs are
emitted in `crates/sda-device-control/src/finding.rs` (Phase 1).

### 5.4 Customer-example traceability

Every `Finding` produced in Phase 1 MUST trace to a
`docs/device-control/PROPOSAL.md` § 2.2 example. The mapping is:

| `FindingKind` | Customer example (PROPOSAL.md § 2.2) |
|---|---|
| `PermanentAdmin` | #1 — "6 permanent admins" |
| `OutdatedApp` | #2 — "12 outdated apps" |
| `DeviceMissing` | #3 — "4 missing laptops" |
| `UnapprovedSoftware` | #4 — "Unknown software" |
| `AdminAccessRequested` | #5 — "User needs admin" |
| `PostureViolation` | #1 follow-ups (e.g. BitLocker off after admin demote) |
| `VulnerabilityMatch` | #2 follow-ups |
| `Other` | n/a — opaque escape hatch |

### 5.5 NATS subject

`device_control.findings.<tenant_id>.<device_id>` — see
[`ARCHITECTURE.md` § 4.2](./ARCHITECTURE.md#42-nats-subject-hierarchy).

---

## 6. `Recommendation`

A `Recommendation` is a control-plane suggestion attached to one or
more findings. The control plane (Risk Engine) is the only producer;
the agent is **not** authorised to emit `Recommendation` objects.
Recommendations carry a `one_click` flag indicating whether they are
eligible for one-click execution at the customer's pricing tier.

### 6.1 Rust definition

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recommendation {
    /// Stable recommendation identity; UUIDv7.
    pub recommendation_id: Uuid,
    /// Tenant the recommendation belongs to.
    pub tenant_id: Uuid,
    /// Schema version (see § 11). Always equal to
    /// `RECOMMENDATION_SCHEMA_VERSION` (= 1).
    pub schema_version: u16,
    /// One or more devices the recommendation applies to.
    pub device_ids: Vec<Uuid>,
    /// One or more findings the recommendation is responding to.
    pub finding_ids: Vec<Uuid>,
    /// What the recommendation will do when executed.
    pub action: ActionKind,
    /// Pre-baked args for the eventual `SignedActionJob`. Same shape
    /// as `SignedActionJob.args`; see § 7.3.
    pub args: serde_json::Value,
    /// Human-readable, SME-targeted summary; ≤ 512 chars.
    pub plain_english: String,
    /// True if this recommendation is eligible for one-click
    /// execution at the customer's pricing tier.
    pub one_click: bool,
    /// Severity ladder mirrored from the highest-severity finding;
    /// duplicated here for UI sort stability.
    pub severity: Severity,
    /// When the recommendation was created.
    pub created_at: DateTime<Utc>,
    /// Optional approval-window hint for tier-2+ tenants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
}
```

### 6.2 Required-field invariants

- `device_ids.len() ≥ 1` and `finding_ids.len() ≥ 1`.
- Every `device_id` MUST belong to `tenant_id` (control-plane RLS
  enforcement).
- `args` MUST be valid for `action` (validated against the per-
  `ActionKind` strict struct in [§ 7.3](#73-args-sub-schemas)) at
  emission time.

### 6.3 NATS subject

`device_control.recommendations.<tenant_id>` — see
[`ARCHITECTURE.md` § 4.2](./ARCHITECTURE.md#42-nats-subject-hierarchy).

The recommendation is fanned out per device by the Action
Orchestrator when the customer (or auto-execution policy) approves
it; each fan-out becomes one `SignedActionJob`.

---

## 7. `SignedActionJob`

A `SignedActionJob` is an Ed25519-signed instruction the agent will
execute. Only the SN360 control plane may sign jobs; agents reject
any job whose `key_id` is not in the locally pinned rotation set.

### 7.1 Rust definition

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedActionJob {
    /// Stable job identity; UUIDv7.
    pub job_id: Uuid,
    /// Tenant the job belongs to.
    pub tenant_id: Uuid,
    /// Device the job targets.
    pub device_id: Uuid,
    /// Schema version (see § 11). Always equal to
    /// `SIGNED_ACTION_JOB_SCHEMA_VERSION` (= 1).
    pub schema_version: u16,
    /// Optional reference to the recommendation that birthed this
    /// job. Absent for ad-hoc jobs (e.g. operator-initiated remote
    /// support).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation_id: Option<Uuid>,
    /// What the job will do.
    pub action: ActionKind,
    /// Action-shaped arguments; see § 7.3.
    pub args: serde_json::Value,
    /// Earliest time the agent may begin executing the job.
    pub not_before: DateTime<Utc>,
    /// Latest time the agent may begin executing the job. Past
    /// `not_after`, the job is rejected with `JobRefused::Expired`.
    pub not_after: DateTime<Utc>,
    /// Ed25519 signature over the canonical encoding of every other
    /// field of this struct (see § 7.2).
    pub signature: Vec<u8>,
    /// Rotation-aware key identifier. The agent looks this up in
    /// the locally pinned rotation set.
    pub key_id: String,
    /// Optional dispatch correlation id used by the Agent Gateway
    /// to map results back to the original request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<Uuid>,
}
```

### 7.2 Canonical encoding (signature pre-image)

The signature is computed over the **canonical JSON** (RFC 8785)
representation of the `SignedActionJob` with the `signature` field
replaced by an empty string `""`. Lexicographic field ordering is
fixed by RFC 8785; whitespace is forbidden.

Pseudo-code:

```text
let mut to_sign = signed_action_job.clone();
to_sign.signature = vec![];
let pre_image = canonicalize(serde_json::to_value(&to_sign)?)?;
let signature = ed25519_signing_key.sign(&pre_image);
```

The agent re-derives the pre-image identically and verifies the
signature against the public key indexed by `key_id` in
`/etc/sn360-desktop-agent/keys.d/rotation.json`.

### 7.3 `args` sub-schemas

Every `ActionKind` has a strict argument struct. `args` is
`serde_json::Value` on the wire so the gateway and bus can shuttle
it untouched, but the agent **MUST** parse it into the per-kind
struct (with `#[serde(deny_unknown_fields)]`) before any side
effect runs. If parsing fails, the agent emits an `ActionResult`
with `status = Refused` and `JobRefused::ArgsParseError`.

| `ActionKind` | `args` shape |
|---|---|
| `InstallPackage` | `{ "package_id": "...", "version": "X.Y.Z", "channel": "stable", "source_url": "https://...", "sha256": "<hex>" }` |
| `UpdatePackage` | `{ "package_id": "...", "to_version": "X.Y.Z", "channel": "stable" }` |
| `UninstallPackage` | `{ "package_id": "...", "version": "X.Y.Z"|"*" }` |
| `GrantJitAdmin` | `{ "user": "...", "duration_minutes": u32, "reason": "...", "approver_id": "<uuid>" }` |
| `RevokeAdmin` | `{ "user": "...", "reason": "..." }` |
| `RunScript` | `{ "script_id": "...", "script_sha256": "<hex>", "args": ["..."], "timeout_seconds": u32 }` |
| `PushAppControlPolicy` | `{ "policy_id": "<uuid>", "policy_sha256": "<hex>", "policy_url": "https://..." }` |
| `StartRemoteSupport` | `{ "operator_id": "<uuid>", "session_id": "<uuid>", "consent_required": true, "max_duration_minutes": u32 }` |
| `EndRemoteSupport` | `{ "session_id": "<uuid>", "reason": "..." }` |
| `QueryAdHoc` | `{ "query_id": "<uuid>", "engine": "osquery", "sql": "...", "max_rows": u32 }` |

`duration_minutes`, `timeout_seconds`, and `max_duration_minutes`
have hard caps enforced by the agent (e.g. `duration_minutes ≤ 480`
for `GrantJitAdmin`). Caps are listed in
[`PROPOSAL.md` § 14](./PROPOSAL.md#14-security-model).

`RunScript` is restricted to scripts in the signed allow-list per
[`PROPOSAL.md` § 14.2](./PROPOSAL.md#142-script-execution); this is
not a generic shell. `script_sha256` MUST match the catalogue entry.

### 7.4 Validation rules

The agent applies the 10-step checklist from
[`ARCHITECTURE.md` § 4.3 / `PROPOSAL.md` § 10.3](./ARCHITECTURE.md#43-signed-job-validation-10-step-checklist)
before any side effect runs:

1. Frame decoded successfully under TLS 1.3 + HTTP/2 + MessagePack.
2. `SignedActionJob` parsed strictly (`deny_unknown_fields`).
3. `key_id` present in the locally pinned rotation set.
4. Ed25519 signature verifies over the canonical pre-image (§ 7.2).
5. Now is in `[not_before − 60s, not_after + 60s]`.
6. `tenant_id` matches the agent's enrolled tenant.
7. `device_id` matches the agent's local identity.
8. `action` is allow-listed for the agent's current pricing tier.
9. `modules.device_control.windows` (maintenance + quiet hours)
   permit execution now.
10. `args` parses against the strict per-`ActionKind` struct.

Any failure produces an `ActionResult` with `status = Refused` and
the corresponding `JobRefused::*` reason (see [§ 8.3](#83-jobrefused-reasons)).

### 7.5 NATS subject

`device_control.jobs.<tenant_id>.<device_id>` — see
[`ARCHITECTURE.md` § 4.2](./ARCHITECTURE.md#42-nats-subject-hierarchy).

---

## 8. `ActionResult`

An `ActionResult` is the agent's structured report of what happened
when a `SignedActionJob` ran. Every `ActionResult` references the
matching `EvidenceRecord` via `evidence_id`; the two are emitted
back-to-back on different `MessageType` variants but share the same
`evidence_id` so consumers can correlate.

### 8.1 Rust definition

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionResult {
    /// Job this result is for.
    pub job_id: Uuid,
    /// Tenant the job belonged to (mirrored for routing).
    pub tenant_id: Uuid,
    /// Device that ran the job.
    pub device_id: Uuid,
    /// Schema version (see § 11). Always equal to
    /// `ACTION_RESULT_SCHEMA_VERSION` (= 1).
    pub schema_version: u16,
    /// Action that ran (mirrored from the job for self-contained logs).
    pub action: ActionKind,
    /// Outcome.
    pub status: ActionStatus,
    /// Refusal reason; only present when `status = Refused`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused_reason: Option<JobRefused>,
    /// When the agent began executing.
    pub started_at: DateTime<Utc>,
    /// When the agent finished (or refused).
    pub finished_at: DateTime<Utc>,
    /// OS-level exit code for `RunScript` and similar; absent for
    /// actions that do not have one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Bounded captured output (≤ 64 KiB). Truncated at the head
    /// with a marker if larger; the SHA-256 of the full output
    /// lives in the matching `EvidenceRecord.output_sha256`.
    pub output: String,
    /// True if `output` was truncated.
    pub output_truncated: bool,
    /// Evidence record id (UUIDv7); always present.
    pub evidence_id: Uuid,
}
```

### 8.2 Required-field invariants

- `started_at ≤ finished_at`.
- If `status = Success | Skipped`, `refused_reason MUST be None`.
- If `status = Refused`, `refused_reason MUST be Some(_)` and
  `started_at == finished_at` (no side effect ran).
- `output.len()` ≤ 65_536 bytes.
- `evidence_id` MUST point at an `EvidenceRecord` emitted in the
  same comms session.

### 8.3 `JobRefused` reasons

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobRefused {
    /// Step 2 failed: deny_unknown_fields rejected the payload.
    SchemaParseError,
    /// Step 3 failed: key_id is not in the local rotation set.
    UnknownKeyId,
    /// Step 4 failed: signature did not verify.
    BadSignature,
    /// Step 5 failed: not_before / not_after window is closed.
    Expired,
    /// Step 6 failed: tenant_id mismatch.
    TenantMismatch,
    /// Step 7 failed: device_id mismatch.
    DeviceMismatch,
    /// Step 8 failed: action not allow-listed for current tier.
    ActionNotPermitted,
    /// Step 9 failed: outside maintenance / quiet-hours window.
    OutsideWindow,
    /// Step 10 failed: per-ActionKind args struct rejected the payload.
    ArgsParseError,
    /// Catch-all for refusals not covered above (e.g. a sub-module
    /// reported a precondition failure before any side effect).
    PreconditionFailed,
}
```

The user-facing UI uses these reasons verbatim per
[`ARCHITECTURE.md` § 4.3](./ARCHITECTURE.md#43-signed-job-validation-10-step-checklist);
do not change the wire spelling without a major version bump.

### 8.4 NATS subject

`device_control.action_results.<tenant_id>.<device_id>` — see
[`ARCHITECTURE.md` § 4.2](./ARCHITECTURE.md#42-nats-subject-hierarchy).

---

## 9. `EvidenceRecord`

`EvidenceRecord` is the **append-only audit projection** of an
`ActionResult` plus the `SignedActionJob` it executed. Every signed
job produces exactly one `EvidenceRecord` (including refusals — the
fact that a job was refused is itself audit-relevant).

Records are stored as an Ed25519 chain: each record signs the
prefix-hash of the previous record, so deletions in the Evidence
Vault are detectable per
[`PROPOSAL.md` § 16](./PROPOSAL.md#16-evidence-and-audit-model).

### 9.1 Rust definition

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    /// Stable evidence identity; UUIDv7. Same value as the
    /// matching `ActionResult.evidence_id`.
    pub evidence_id: Uuid,
    /// Tenant the evidence belongs to.
    pub tenant_id: Uuid,
    /// Device that produced the evidence.
    pub device_id: Uuid,
    /// Schema version (see § 11). Always equal to
    /// `EVIDENCE_RECORD_SCHEMA_VERSION` (= 1).
    pub schema_version: u16,
    /// Job that ran.
    pub job_id: Uuid,
    /// Optional recommendation that birthed the job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation_id: Option<Uuid>,
    /// Action that ran.
    pub action: ActionKind,
    /// RFC 8785 canonical JSON encoding of `SignedActionJob.args`.
    /// Stored as a string so the chain hash is stable independent
    /// of consumer JSON libraries.
    pub args_canonical: String,
    /// When the agent began executing (or refused).
    pub started_at: DateTime<Utc>,
    /// When the agent finished (or refused).
    pub finished_at: DateTime<Utc>,
    /// Outcome.
    pub status: ActionStatus,
    /// Refusal reason; only present when `status = Refused`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused_reason: Option<JobRefused>,
    /// OS-level exit code where applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// SHA-256 of the *full* (un-truncated) bounded output. The
    /// truncated head lives in `ActionResult.output`; the raw
    /// bytes are streamed to the Evidence Vault separately under
    /// the same `evidence_id`.
    pub output_sha256: [u8; 32],
    /// Platform descriptor at execution time.
    pub platform: Platform,
    /// Agent version at execution time.
    pub agent: AgentVersion,
    /// Hash of the previous evidence record on this device's chain
    /// (32 bytes; SHA-256). The first record on the chain uses
    /// `[0u8; 32]`.
    pub prev_record_hash: [u8; 32],
    /// Ed25519 signature over the canonical encoding of every
    /// other field of this struct, signed by the agent's
    /// per-device evidence key (see § 9.3).
    pub signature: Vec<u8>,
    /// Rotation-aware identifier of the agent's evidence key.
    pub key_id: String,
}
```

### 9.2 Canonical encoding (signature pre-image)

The agent computes:

```text
let mut to_sign = evidence_record.clone();
to_sign.signature = vec![];
let pre_image = canonicalize(serde_json::to_value(&to_sign)?)?;
let signature = agent_evidence_signing_key.sign(&pre_image);
```

`prev_record_hash` is `SHA-256(canonicalize(previous_record))`,
*including* the previous record's signature. This makes the chain
tamper-evident: the Evidence Vault can re-derive every `prev_record_hash`
and detect any insertion / deletion / mutation.

### 9.3 Key model

| Key | Holder | Used to sign | Verified by |
|---|---|---|---|
| Control-plane signing key | SN360 control plane (Action Orchestrator) | `SignedActionJob.signature` | Agent (locally pinned rotation set in `/etc/sn360-desktop-agent/keys.d/rotation.json`). |
| Agent evidence key | Each agent (per-device, generated at enrolment) | `EvidenceRecord.signature` | Evidence Vault (per-device public key registered at enrolment; rotated via the existing `sda-updater` channel). |

The agent's evidence key is **never** sent to the control plane in
private form; only the public half is registered at enrolment time.

### 9.4 Wire vs. on-disk

| Surface | Encoding | Notes |
|---|---|---|
| Live wire (`device_control.evidence.<tenant>.<device>`) | MessagePack | Same shape as the Rust struct; emitted right after the matching `ActionResult`. |
| Agent on-disk evidence cache | Canonical JSON, one record per line, append-only | Used as a replay buffer when `sda-comms` is offline. |
| Evidence Vault | Canonical JSON; chain re-verified on ingest | Stored under `tenant_id/device_id/yyyy/mm/dd/<evidence_id>.json`. |
| Customer JSON export | One canonical JSON record per line, signature retained | Importable into SIEMs. |
| Customer PDF export | Tenant-branded human-readable per-device report | Generated from the Evidence Vault. |
| MSP CSV export (Phase 5) | Flattened headers; signatures retained as base64url | Cross-tenant operational dashboards. |

### 9.5 NATS subject

`device_control.evidence.<tenant_id>.<device_id>` — see
[`ARCHITECTURE.md` § 4.2](./ARCHITECTURE.md#42-nats-subject-hierarchy).

---

## 10. End-to-end example

The following is the on-the-wire trace for canonical example #2
("12 outdated apps") for one package:

1. **Agent emits `Finding`** on `device_control.findings.<tenant>.<device>`:
   ```json
   {
     "finding_id":   "0192c7c1-…",
     "device_id":    "0192c7c0-…",
     "tenant_id":    "0192c7be-…",
     "schema_version": 1,
     "kind":         "outdated_app",
     "severity":     "medium",
     "plain_english": "Acme Reader has not been updated in 73 days; CVE-2026-1234 applies.",
     "evidence": {
       "package": "Acme Reader",
       "current_version": "11.0.4",
       "available_version": "11.2.0",
       "days_stale": 73,
       "cves": ["CVE-2026-1234"]
     },
     "observed_at": "2026-05-07T08:29:00Z",
     "source_refs": [{ "engine": "sda-enhanced-inventory", "reference": "running_software:acme-reader" }]
   }
   ```
2. **Risk Engine emits `Recommendation`** on
   `device_control.recommendations.<tenant>`:
   ```json
   {
     "recommendation_id": "0192c7c2-…",
     "tenant_id":         "0192c7be-…",
     "schema_version":    1,
     "device_ids":        ["0192c7c0-…"],
     "finding_ids":       ["0192c7c1-…"],
     "action":            "update_package",
     "args":              { "package_id": "acme-reader", "to_version": "11.2.0", "channel": "stable" },
     "plain_english":     "Update Acme Reader to 11.2.0 to clear CVE-2026-1234.",
     "one_click":         true,
     "severity":          "medium",
     "created_at":        "2026-05-07T08:29:05Z"
   }
   ```
3. **Action Orchestrator emits `SignedActionJob`** on
   `device_control.jobs.<tenant>.<device>` once the customer (or
   auto-policy) approves:
   ```json
   {
     "job_id":            "0192c7c3-…",
     "tenant_id":         "0192c7be-…",
     "device_id":         "0192c7c0-…",
     "schema_version":    1,
     "recommendation_id": "0192c7c2-…",
     "action":            "update_package",
     "args":              { "package_id": "acme-reader", "to_version": "11.2.0", "channel": "stable" },
     "not_before":        "2026-05-07T08:30:00Z",
     "not_after":         "2026-05-07T09:30:00Z",
     "signature":         "ed25519:…",
     "key_id":            "sn360-control-2026-05"
   }
   ```
4. **Agent runs the 10-step validation, executes via the
   `PackageManager` PAL trait, and emits `ActionResult` + `EvidenceRecord`**
   back-to-back on `device_control.action_results.<tenant>.<device>`
   and `device_control.evidence.<tenant>.<device>`:
   ```json
   {
     "job_id":         "0192c7c3-…",
     "tenant_id":      "0192c7be-…",
     "device_id":      "0192c7c0-…",
     "schema_version": 1,
     "action":         "update_package",
     "status":         "success",
     "started_at":     "2026-05-07T08:30:01Z",
     "finished_at":    "2026-05-07T08:30:14Z",
     "exit_code":      0,
     "output":         "winget upgrade acme-reader --version 11.2.0\\nSuccess.",
     "output_truncated": false,
     "evidence_id":    "0192c7c4-…"
   }
   ```
   ```json
   {
     "evidence_id":    "0192c7c4-…",
     "tenant_id":      "0192c7be-…",
     "device_id":      "0192c7c0-…",
     "schema_version": 1,
     "job_id":         "0192c7c3-…",
     "recommendation_id": "0192c7c2-…",
     "action":         "update_package",
     "args_canonical": "{\"channel\":\"stable\",\"package_id\":\"acme-reader\",\"to_version\":\"11.2.0\"}",
     "started_at":     "2026-05-07T08:30:01Z",
     "finished_at":    "2026-05-07T08:30:14Z",
     "status":         "success",
     "exit_code":      0,
     "output_sha256":  "8f1c…",
     "platform":       { "os": "windows", "version": "10.0.22631", "arch": "x86_64" },
     "agent":          { "version": "0.10.0", "build_sha": "…", "channel": "stable" },
     "prev_record_hash": "ad4f…",
     "signature":      "ed25519:…",
     "key_id":         "sda-evidence-0192c7c0-2026-05"
   }
   ```

The Risk Engine then closes the matching `Finding` and the SMI
sub-score moves up (per
[`PROPOSAL.md` § 13](./PROPOSAL.md#13-smi-scoring-model)).

---

## 11. Versioning and compatibility

Each schema carries an explicit `schema_version: u16`:

| Constant | Phase 0 / Phase 1 value |
|---|---|
| `FINDING_SCHEMA_VERSION` | `1` |
| `RECOMMENDATION_SCHEMA_VERSION` | `1` |
| `SIGNED_ACTION_JOB_SCHEMA_VERSION` | `1` |
| `ACTION_RESULT_SCHEMA_VERSION` | `1` |
| `EVIDENCE_RECORD_SCHEMA_VERSION` | `1` |

Compatibility rules:

- **Major version bump** (1 → 2) is a breaking change. Producers
  emit only the new version; consumers MUST reject the old version
  after a deprecation window. Triggers: removing a field, changing
  a field's type, splitting an enum variant.
- **Minor field additions** are not allowed without a major bump
  (this is a deliberate strictness — `deny_unknown_fields` would
  break consumers anyway).
- **Closed enum extensions** (adding a new `FindingKind` /
  `ActionKind` / `JobRefused` variant) are minor and only require:
  - A new entry in this document.
  - A new entry in
    [`fleet-capability-mapping.md` § 1](./fleet-capability-mapping.md#1-concepts-to-port)
    (for `ActionKind`) or § 3 (for `FindingKind`).
  - Synchronised release of agent + control plane that recognise
    the variant; older agents emit `JobRefused::ActionNotPermitted`
    for unknown `ActionKind` values.
- Every breaking change requires a new ADR in
  `docs/device-control/` referencing
  [`ADR-001-functional-port.md`](./ADR-001-functional-port.md).

`schema_version` is **read by the consumer first**; if it is
greater than the locally compiled constant the consumer MUST
reject the payload with `JobRefused::SchemaParseError` (jobs) or
the bus-level equivalent for findings / recommendations / results.

---

## 12. Redaction and PII handling

Per
[`PROPOSAL.md` § 14.1](./PROPOSAL.md#141-threats-and-controls)
and
[`ARCHITECTURE.md` § 8.1](./ARCHITECTURE.md#81-threats-and-controls),
the following fields are PII-bearing and MUST be redacted from
agent debug logs (`tracing::Event` payload):

- `Finding.evidence` for `kind ∈ { PermanentAdmin,
  AdminAccessRequested }` — contains usernames.
- `SignedActionJob.args` for `action ∈ { GrantJitAdmin, RevokeAdmin,
  StartRemoteSupport }` — contains usernames and operator ids.
- `ActionResult.output` for `action = RunScript` — script output
  may include arbitrary user data.
- `EvidenceRecord.args_canonical` and `EvidenceRecord.output_sha256`
  are NOT redacted; they live in the audit chain by design and are
  encrypted at rest in the Evidence Vault.

The redaction rule is implemented in `crates/sda-core::logging` and
mirrored in `sn360-security-platform`'s gateway service.

The full `output` bytes are encrypted on the wire (TLS 1.3) and at
rest in the Evidence Vault. The on-disk evidence cache on the
agent is protected by the existing tamper-protection mechanism
(see
[`PROPOSAL.md` § 14.1](./PROPOSAL.md#141-threats-and-controls)).

---

## 13. Phase 1 implementation pointers

Phase 1 (see
[`PHASES.md` Phase 1](./PHASES.md#phase-1--visibility--adminroot-review-812-weeks))
will materialise these schemas as Rust types in:

- `crates/sda-core/src/device_control/{finding,recommendation,signed_action_job,action_result,evidence_record}.rs`
  — the canonical struct definitions imported by every other crate.
- `crates/sda-core/src/device_control/canonicalize.rs` — RFC 8785
  canonical-JSON serializer used for signature pre-images.
- `crates/sda-core/src/device_control/version.rs` — the
  `*_SCHEMA_VERSION` constants enumerated in [§ 11](#11-versioning-and-compatibility).
- `crates/sda-comms/src/protocol.rs` — new `MessageType` arms
  (Phase 0 task 0.12).
- `crates/sda-event-bus/src/event.rs` — new `EventKind` variants
  (Phase 0 task 0.12).

No code lands until Phase 0 task 0.13 (Phase 0 exit checklist) is
signed off, per the binding constraint in
[`PHASES.md` Phase 0](./PHASES.md#phase-0--architecture-legal-and-schema-2-weeks).

---

## 14. Authority and audit trail

When in doubt, the order of precedence is:

1. **The proprietary licence** ([`../../LICENSE`](../../LICENSE)) and
   [`docs/proprietary-licensing-rationale.md`](../proprietary-licensing-rationale.md).
2. **[ADR-001-functional-port.md](./ADR-001-functional-port.md)**.
3. **This document** (`SCHEMAS.md`) — the canonical wire spec.
4. **[`ARCHITECTURE.md` § 3 / § 4](./ARCHITECTURE.md#3-data-model)**
   — the architectural sketch this spec finalises.
5. **[`PROPOSAL.md` § 8 / § 16](./PROPOSAL.md#8-data-model)** — the
   high-level proposal text.
6. **[`fleet-capability-mapping.md`](./fleet-capability-mapping.md)**
   — concept-to-crate mapping.
7. **[`docs/security-audit.md` § Device Control License Audit](../security-audit.md#device-control-license-audit)**
   — per-engine licence posture.

If any item below this list contradicts an item above it, the
higher item wins.
