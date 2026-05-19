# Device Control wire protocol

This document is the canonical wire-protocol reference for Device
Control. Five schemas are defined here:

1. [`Finding`](#5-finding) — an observation produced by the agent.
2. [`Recommendation`](#6-recommendation) — a control-plane fix
   suggestion attached to one or more findings.
3. [`SignedActionJob`](#7-signedactionjob) — an Ed25519-signed
   instruction the agent will execute.
4. [`ActionResult`](#8-actionresult) — what happened when the job
   ran.
5. [`EvidenceRecord`](#9-evidencerecord) — the append-only audit
   projection of an `ActionResult`.

Companion documents:
- [`../device-control.md`](../device-control.md) — module-level
  architecture and lifecycle.
- [`../security.md`](../security.md) — signed-job validation in
  the wider security model.

Any breaking change to a schema requires a new ADR and a major
version bump (see [§ 10. Versioning](#10-versioning)).

---

## Table of contents

1. [Encoding conventions](#1-encoding-conventions)
2. [Identifiers](#2-identifiers)
3. [Time](#3-time)
4. [Bounded sizes](#4-bounded-sizes)
5. [`Finding`](#5-finding)
6. [`Recommendation`](#6-recommendation)
7. [`SignedActionJob`](#7-signedactionjob)
8. [`ActionResult`](#8-actionresult)
9. [`EvidenceRecord`](#9-evidencerecord)
10. [Versioning](#10-versioning)
11. [Redaction](#11-redaction)

---

## 1. Encoding conventions

| Surface | Encoding |
|---|---|
| Agent ↔ control plane (live wire) | **MessagePack** carried inside `sda-comms` TLS 1.3 + HTTP/2 frames. Field names match the Rust `serde` `#[serde(rename_all = "snake_case")]` form. |
| Agent on-disk evidence cache | **Canonical JSON** (RFC 8785) per record, one record per line, append-only. |
| Evidence vault (control plane) | Canonical JSON (RFC 8785), Ed25519 signature chain. |
| Agent debug logs | Compact JSON (`serde_json` default), redacted per § 11. |

The MessagePack and canonical-JSON forms round-trip without loss.
Field ordering for canonical JSON follows RFC 8785 — fields are
emitted in lexicographic order so signatures are stable across
implementations.

All consumer-side parsers use `#[serde(deny_unknown_fields)]`.
Unknown fields are a hard parse error.

`Option<T>` fields default to `None` and are omitted on the wire
when `None`.

---

## 2. Identifiers

| Field | Type | Notes |
|---|---|---|
| `*_id` (e.g. `finding_id`, `job_id`, `device_id`) | `Uuid` (UUIDv7) | UUIDv7 is time-ordered so consumers can range-scan by time without joining a separate timestamp column |
| `tenant_id` | `Uuid` | Allocated by the SN360 control plane during enrolment |
| `key_id` | `String` (≤ 64 ASCII chars, `^[A-Za-z0-9._:-]+$`) | Rotation-aware label; never the bare key bytes |

---

## 3. Time

All timestamps are **UTC**, RFC 3339 with microsecond precision,
serialised as ISO-8601 strings in JSON and as
`{ tv_sec: i64, tv_nsec: u32 }` MessagePack ext-type 1 on the wire.

Clock skew is bounded to **±60 s** for any signed-job validation
window (see § 7.4).

---

## 4. Bounded sizes

| Field | Hard cap | Behaviour on overflow |
|---|---|---|
| `Finding.plain_english` | 512 chars (UTF-8 grapheme clusters) | Reject at the agent producer |
| `Finding.evidence` (raw JSON) | 16 KiB serialised | Truncate to 16 KiB and add `"truncated": true` |
| `Recommendation.plain_english` | 512 chars | Reject at the control plane producer |
| `SignedActionJob.args` (raw JSON) | 64 KiB serialised | Reject at the control plane producer |
| `ActionResult.output` | 64 KiB | Truncate to first 64 KiB; SHA-256 the full output and store under `evidence_id` |
| `EvidenceRecord.output_sha256` | 32 bytes | Always exactly 32 bytes (SHA-256) |

Producers MUST enforce the caps; consumers MUST reject (not
truncate) over-cap messages.

---

## 5. `Finding`

A `Finding` is a single observation produced by the agent that the
control plane should consider for risk scoring or recommendations.
Findings are **idempotent by `finding_id`**: the agent uses the
same UUID for the same logical finding across re-emits.

### 5.1 Rust definition

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub finding_id: Uuid,
    pub device_id: Uuid,
    pub tenant_id: Uuid,
    pub schema_version: u16,
    pub kind: FindingKind,
    pub severity: Severity,
    pub plain_english: String,
    pub evidence: serde_json::Value,
    pub observed_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_refs: Option<Vec<SourceRef>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    pub engine: String,
    pub reference: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    PermanentAdmin,
    OutdatedApp,
    DeviceMissing,
    UnapprovedSoftware,
    AdminAccessRequested,
    PostureViolation,
    VulnerabilityMatch,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info, Low, Medium, High, Critical,
}
```

### 5.2 Invariants

- `tenant_id` equals the agent's enrolled tenant id.
- `device_id` equals the agent's local identity.
- `observed_at` is in `[now − 24 h, now + 60 s]`.
- `plain_english` is non-empty for `severity ∈ { Medium, High, Critical }`.

### 5.3 Per-`FindingKind` evidence shapes

| Kind | `evidence` shape |
|---|---|
| `PermanentAdmin` | `{ "admins": [{ "user", "since": "RFC3339", "via": "local"\|"domain" }, …] }` |
| `OutdatedApp` | `{ "package", "current_version", "available_version", "days_stale": u32, "cves": ["CVE-…"] }` |
| `DeviceMissing` | `{ "last_checkin_at": "RFC3339", "last_known_ip", "missed_intervals": u32 }` |
| `UnapprovedSoftware` | `{ "package", "version", "publisher", "approval_state": "unknown"\|"denied" }` |
| `AdminAccessRequested` | `{ "requested_by", "for_tool", "duration_minutes": u32, "reason" }` |
| `PostureViolation` | `{ "control": "BitLocker"\|"FileVault"\|"LUKS"\|"FirewallEnabled"\|"ScreenLock"\|"PatchLevel", "expected", "actual" }` |
| `VulnerabilityMatch` | `{ "cve", "package", "version", "cvss": f32, "fixed_in" }` |
| `Other` | Arbitrary JSON — opaque to the control plane |

### 5.4 NATS subject

`device_control.findings.<tenant_id>.<device_id>`

---

## 6. `Recommendation`

A `Recommendation` is a control-plane suggestion attached to one or
more findings. The control plane is the only producer; the agent is
not authorised to emit recommendations.

### 6.1 Rust definition

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recommendation {
    pub recommendation_id: Uuid,
    pub tenant_id: Uuid,
    pub schema_version: u16,
    pub device_ids: Vec<Uuid>,
    pub finding_ids: Vec<Uuid>,
    pub action: ActionKind,
    pub args: serde_json::Value,
    pub plain_english: String,
    pub one_click: bool,
    pub severity: Severity,
    pub created_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
}
```

### 6.2 Invariants

- `device_ids.len() ≥ 1` and `finding_ids.len() ≥ 1`.
- Every `device_id` belongs to `tenant_id`.
- `args` is valid for `action` (validated against the per-
  `ActionKind` strict struct in § 7.3) at emission time.

### 6.3 NATS subject

`device_control.recommendations.<tenant_id>`

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
    pub job_id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub schema_version: u16,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation_id: Option<Uuid>,

    pub action: ActionKind,
    pub args: serde_json::Value,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub signature: Vec<u8>,
    pub key_id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<Uuid>,
}

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

### 7.2 Canonical encoding (signature pre-image)

The signature is computed over the **canonical JSON** (RFC 8785)
representation of the `SignedActionJob` with the `signature` field
replaced by an empty string `""`. Whitespace is forbidden.

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
| `InstallPackage` | `{ "package_id", "version": "X.Y.Z", "channel": "stable", "source_url": "https://…", "sha256": "<hex>" }` |
| `UpdatePackage` | `{ "package_id", "to_version": "X.Y.Z", "channel": "stable" }` |
| `UninstallPackage` | `{ "package_id", "version": "X.Y.Z"\|"*" }` |
| `GrantJitAdmin` | `{ "user", "duration_minutes": u32, "reason", "approver_id": "<uuid>" }` |
| `RevokeAdmin` | `{ "user", "reason" }` |
| `RunScript` | `{ "script_id", "script_sha256": "<hex>", "args": ["…"], "timeout_seconds": u32 }` |
| `PushAppControlPolicy` | `{ "policy_id": "<uuid>", "policy_sha256": "<hex>", "policy_url": "https://…" }` |
| `StartRemoteSupport` | `{ "operator_id": "<uuid>", "session_id": "<uuid>", "consent_required": true, "max_duration_minutes": u32 }` |
| `EndRemoteSupport` | `{ "session_id": "<uuid>", "reason" }` |
| `QueryAdHoc` | `{ "query_id": "<uuid>", "engine": "osquery", "sql", "max_rows": u32 }` |

`duration_minutes`, `timeout_seconds`, and `max_duration_minutes`
have hard caps enforced by the agent (e.g. `duration_minutes ≤ 480`
for `GrantJitAdmin`).

`RunScript` is restricted to scripts in the signed allow-list;
this is not a generic shell. `script_sha256` MUST match the
catalogue entry.

### 7.4 Validation rules

The agent applies the 10-step checklist before any side effect
runs:

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
the corresponding `JobRefused::*` reason (see § 8.3).

### 7.5 NATS subject

`device_control.jobs.<tenant_id>.<device_id>`

---

## 8. `ActionResult`

An `ActionResult` is the agent's structured report of what happened
when a `SignedActionJob` ran. Every `ActionResult` references the
matching `EvidenceRecord` via `evidence_id`.

### 8.1 Rust definition

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionResult {
    pub job_id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub schema_version: u16,
    pub action: ActionKind,
    pub status: ActionStatus,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused_reason: Option<JobRefused>,

    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,

    pub output: String,
    pub output_truncated: bool,
    pub evidence_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Success,
    Failure,
    Refused,
    Skipped,
}
```

### 8.2 Invariants

- `started_at ≤ finished_at`.
- If `status ∈ { Success, Skipped }`, `refused_reason` is `None`.
- If `status = Refused`, `refused_reason` is `Some(_)` and
  `started_at == finished_at` (no side effect ran).
- `output.len() ≤ 65_536` bytes.
- `evidence_id` references an `EvidenceRecord` emitted in the
  same comms session.

### 8.3 `JobRefused` reasons

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobRefused {
    SchemaParseError,    // step 2
    UnknownKeyId,        // step 3
    BadSignature,        // step 4
    Expired,             // step 5
    TenantMismatch,      // step 6
    DeviceMismatch,      // step 7
    ActionNotPermitted,  // step 8
    OutsideWindow,       // step 9
    ArgsParseError,      // step 10
    PreconditionFailed,  // sub-module reported a precondition failure
}
```

The user-facing UI uses these reasons verbatim. The wire spelling
is stable; do not change without a major version bump.

### 8.4 NATS subject

`device_control.action_results.<tenant_id>.<device_id>`

---

## 9. `EvidenceRecord`

`EvidenceRecord` is the **append-only audit projection** of an
`ActionResult` plus the `SignedActionJob` it executed. Every signed
job produces exactly one `EvidenceRecord` (including refusals —
the fact that a job was refused is itself audit-relevant).

Records form an Ed25519 chain: each record signs the prefix-hash of
the previous record, so deletions in the evidence vault are
detectable.

### 9.1 Rust definition

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    pub evidence_id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub schema_version: u16,
    pub job_id: Uuid,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation_id: Option<Uuid>,

    pub action: ActionKind,
    pub args_canonical: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub status: ActionStatus,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused_reason: Option<JobRefused>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,

    pub output_sha256: [u8; 32],
    pub agent_version: AgentVersion,
    pub platform: Platform,

    /// Chain signature over the canonical encoding of this record
    /// (with `prev_chain_signature` empty) plus the previous
    /// record's signature. See § 9.2.
    pub prev_chain_signature: Vec<u8>,
    pub chain_signature: Vec<u8>,
    pub key_id: String,
}
```

### 9.2 Chain construction

`chain_signature` is computed as:

```text
let prev = previous_record.chain_signature;
let mut to_sign = this_record.clone();
to_sign.prev_chain_signature = prev.clone();
to_sign.chain_signature = vec![];
let pre_image = canonicalize(serde_json::to_value(&to_sign)?)?;
this_record.chain_signature = ed25519_signing_key.sign(&pre_image);
```

The first record's `prev_chain_signature` is the agent's enrolment
public-key SHA-256.

### 9.3 NATS subject

`device_control.evidence.<tenant_id>.<device_id>`

---

## 10. Versioning

Each schema carries a `schema_version: u16`.  The initial release ships
schema_version = 1 for all five schemas.

| Change | Version bump |
|---|---|
| Adding a new optional field with a serde default | minor (consumers tolerate) |
| Adding a new `FindingKind` / `ActionKind` / `JobRefused` variant | minor (consumers must add an arm) |
| Removing or renaming a field | **major** (requires ADR + migration plan) |
| Changing the canonical-JSON encoding rules | **major** |

Consumers MUST refuse any schema_version higher than the maximum
they support and downgrade gracefully to a known-good lower version.

---

## 11. Redaction

Per [`architecture.md` § 8.2](../architecture.md#82-redaction-invariant),
no schema field carries unbounded user content. Specifically:

- `Finding.evidence` is bounded to 16 KiB and the per-kind shapes
  in § 5.3 do not include free-form user text outside of
  `plain_english` (which is producer-bounded to 512 chars).
- `ActionResult.output` is bounded to 64 KiB. The full output is
  SHA-256'd into `EvidenceRecord.output_sha256` for forensic
  re-walk; the raw bytes are kept in the agent's evidence cache
  with the same retention policy as other evidence.
- `RunScript` and `QueryAdHoc` `args` may contain sensitive
  parameters; consumers MUST NOT log `args` at `INFO` or below.
  The agent debug logger uses field-level redaction on these
  shapes.
