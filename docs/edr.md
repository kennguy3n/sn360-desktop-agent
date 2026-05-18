# Endpoint Detection & Response (EDR)

This document describes the EDR module surface in SDA: which OS
events it observes, which detection signals it produces, how rules
are distributed and evaluated on-device, and how the agent responds
to threats.

For the per-OS implementation matrix and PAL trait shapes see
[`architecture.md` § 4](./architecture.md#4-platform-abstraction-layer-sda-pal).
For optional kernel-mode telemetry sources see
[`kernel-drivers.md`](./kernel-drivers.md). For the configuration
schema see
[`configuration-reference.md`](./configuration-reference.md).

---

## Table of contents

1. [Overview](#1-overview)
2. [Telemetry sources](#2-telemetry-sources)
3. [Local Detection Engine](#3-local-detection-engine)
4. [Memory scanning and fileless detection](#4-memory-scanning-and-fileless-detection)
5. [Identity attack detection](#5-identity-attack-detection)
6. [Data Loss Prevention (DLP)](#6-data-loss-prevention-dlp)
7. [Rule distribution (TRDS)](#7-rule-distribution-trds)
8. [Response actions](#8-response-actions)
9. [Resource budgets](#9-resource-budgets)
10. [Security posture](#10-security-posture)

---

## 1. Overview

The EDR module is a set of six cooperating crates that together
provide the telemetry, detection, and response surface required for
endpoint detection and response on Windows, macOS, and Linux:

| Crate | Role |
|---|---|
| `sda-process-monitor` | Process create / terminate / image-load telemetry, parent-chain enrichment |
| `sda-network-monitor` | Network connection + DNS query telemetry |
| `sda-memory-scanner` | Periodic RWX-region scanning with in-memory YARA |
| `sda-identity-monitor` | Credential-access detection (LSASS, `/etc/shadow`, Keychain) |
| `sda-dlp` | Pattern-based content inspection on FIM file-write events |
| `sda-host-isolation` | Per-OS firewall isolation in response to signed jobs |

The detection engine in `sda-local-detection` consumes the telemetry
streams from those crates, evaluates rules against them, and emits
`LocalDetectionAlert` events that travel both back into the bus
(for downstream modules) and outbound to the SN360 control plane.

```
   +---------------------------------------------------------+
   |  telemetry crates                                       |
   |  sda-process-monitor                                    |
   |  sda-network-monitor                                    |
   |  sda-memory-scanner                                     |
   |  sda-identity-monitor                                   |
   |  sda-dlp                                                |
   +---------------------+-----------------------------------+
                         |  EventKind::ProcessCreated /
                         |  NetworkConnection / DnsQuery /
                         |  MemoryScanAlert / IdentityAlert /
                         |  LocalDetectionAlert
                         v
   +---------------------------------------------------------+
   |  sda-local-detection  (TRDS rule pipeline)              |
   |    aho-corasick + ioc bloom + yara + behavioural rules  |
   +---------------------+-----------------------------------+
                         |  LocalDetectionAlert
                         v
   +---------------------------------------------------------+
   |  sda-host-isolation  +  outbound comms                  |
   +---------------------------------------------------------+
```

Every EDR sub-module is feature-flagged. The defaults are
conservative: telemetry is enabled, response is enabled, and the
high-cost surfaces (memory scanning, DLP, identity-monitor on Linux
where it relies on FIM watches over sensitive paths) default to
`enabled: false` and require explicit opt-in.

---

## 2. Telemetry sources

### 2.1 Process telemetry

`sda-process-monitor` produces `ProcessCreated`, `ProcessTerminated`,
and `ImageLoaded` events. Per-OS sources:

| Platform | Source |
|---|---|
| Linux | `cn_proc` netlink (`NETLINK_CONNECTOR` + `CN_IDX_PROC`) for exec / fork / exit; `/proc/<pid>/` for enrichment (exe, cmdline, cgroup, namespaces, user) |
| Windows | ETW `Microsoft-Windows-Kernel-Process` (`PROCESS_START`, `PROCESS_STOP`, `IMAGE_LOAD`) |
| macOS | Endpoint Security (`ES_EVENT_TYPE_NOTIFY_EXEC`, `_FORK`, `_EXIT`, `_MMAP`) |

Each `ProcessCreated` event carries a `parent_chain` up to the
configured `parent_chain_depth` (default 4). The chain is the
enriched ancestor walk — `exe`, `cmdline`, `user`, `pid` per
ancestor — used by the behavioural rule engine to match on lineage.

### 2.2 Network telemetry

`sda-network-monitor` produces `NetworkConnection` and `DnsQuery`
events:

| Platform | Connection source | DNS source |
|---|---|---|
| Linux | `audit` (`AUDIT_SOCKADDR` / `AUDIT_CONNECT`) + `INET_DIAG` for established enumeration; attribution via `/proc/net/{tcp,tcp6,udp,udp6}` + `/proc/<pid>/fd` | journald `systemd-resolved` (or eBPF on kernel ≥ 5.8) |
| Windows | ETW `Microsoft-Windows-Kernel-Network` keyed on `ProcessId` | ETW `Microsoft-Windows-DNS-Client` |
| macOS | Network Extension `NEFilterDataProvider` | `NEDNSProxyProvider` |

Outbound UDP-heavy hosts can produce millions of `NetworkConnection`
events per minute; the module rate-limits via a bounded LRU
dedup-and-sample window and emits an `AgentVitals` warning when
dropping.

### 2.3 Memory telemetry

`sda-memory-scanner` does **not** produce a continuous event stream.
Instead it runs scheduled scan windows (default: 30 minutes between
windows; configurable). During a window it walks the live process
list, enumerates RWX regions, and applies in-memory YARA rules.
Matches are emitted as `MemoryScanAlert` events. See § 4 below.

### 2.4 Identity telemetry

`sda-identity-monitor` produces `IdentityAlert` events tagged with
MITRE ATT&CK technique IDs. Per-OS providers:

- **Windows.** Monitors handle opens against the LSASS process for
  `PROCESS_VM_READ` / `_QUERY_INFORMATION` access patterns (T1003.001
  *LSASS Memory*).
- **Linux.** Monitors FIM events on `/etc/shadow` (T1003.008
  */etc/passwd and /etc/shadow*) and `/proc/kcore` (T1003.007
  *Proc Filesystem*).
- **macOS.** Monitors Endpoint Security `_NOTIFY_OPEN` against the
  Keychain database (T1555.001 *Keychain*).

### 2.5 DLP telemetry

`sda-dlp` consumes `FileCreated` and `FileModified` events from
`sda-fim` and scans the file content against the configured pattern
set. Matches produce `LocalDetectionAlert` events with
**redaction-safe** evidence — see [`architecture.md` § 8.2](./architecture.md#82-redaction-invariant).

---

## 3. Local Detection Engine

The detection engine in `sda-local-detection` runs on every event
the bus carries. It is composed of four stages, each gated by a
budget so a pathological rule cannot starve the rest of the agent:

1. **Aho-Corasick string match.** First-pass filter for static
   strings (file paths, suspicious binary names, network signatures).
   Stage budget: 200 µs per event.
2. **IOC Bloom filter.** Second-pass filter against a periodically
   refreshed Bloom over IOCFS-distributed indicators. Stage budget:
   50 µs per event.
3. **YARA evaluation.** Runs against file content (`FileCreated`),
   in-memory regions (`MemoryScanAlert.region_base + region_size`),
   and `LogCollected` payloads. Stage budget: 5 ms per event.
4. **Behavioural rules.** A small DSL with predicates over the
   parent chain (`process_chain`), thresholds (`threshold`), and
   sequences (`sequence`). Evaluated against the rolling event
   window. Stage budget: 1 ms per event.

A match in any stage produces a `LocalDetectionAlert` carrying the
rule identifier, severity, evidence pointers (offset + length where
applicable), and the triggering `EventKind`. The alert is
re-published onto the bus so downstream modules (response,
isolation, MDM) can react, and forwarded to the control plane.

### 3.1 Behavioural rule DSL

A behavioural rule looks like:

```yaml
- id: lolbas-rundll32-fork
  description: rundll32.exe spawned by an Office process is a common LOLBAS path.
  severity: high
  match:
    kind: process_chain
    process_chain:
      - { exe_regex: '\\winword\.exe$' }
      - { exe_regex: '\\rundll32\.exe$', cmdline_regex: 'javascript:' }
```

The full DSL is documented in
[`configuration-reference.md`](./configuration-reference.md#local-detection-rules).

### 3.2 Default-on policy

The detection engine is **enabled by default**. The agent ships
with an embedded baseline TRDS bundle so detection works even
before a control-plane bundle has been fetched.

---

## 4. Memory scanning and fileless detection

The memory scanner is the EDR module's only proactive scanner; the
rest of the surface is event-driven.

### 4.1 Scheduling

The scanner runs in **scan windows** rather than continuously:

```yaml
modules:
  memory_scanner:
    enabled: false                # default off; opt-in
    scan_interval_secs: 1800      # 30 minutes between windows
    scan_window_secs: 60          # spend up to 60s scanning per window
    max_cpu_percent: 1            # back off if CPU exceeds this
```

Between windows the scanner sleeps and consumes ~0 CPU. Inside a
window it walks the process list, picks targets (configurable
allow / deny list), and enumerates RWX regions.

### 4.2 RWX-region enumeration

| Platform | Enumeration | Read |
|---|---|---|
| Windows | `VirtualQueryEx` requires `PROCESS_QUERY_INFORMATION` + `SeDebugPrivilege` | `ReadProcessMemory` |
| macOS | `task_for_pid` + `mach_vm_region` requires `com.apple.security.cs.debugger` or root | `mach_vm_read_overwrite` |
| Linux | parse `/proc/<pid>/maps` for RWX regions | seek + bounded read on `/proc/<pid>/mem` (requires `CAP_SYS_PTRACE`) |

Each region read is capped by `max_region_bytes` (default 16 MiB).
Oversize regions are truncated rather than streamed.

### 4.3 In-memory YARA

Region bytes are passed through the YARA engine using rules tagged
`memory:true` in the TRDS bundle. Matches produce
`MemoryScanAlert` events:

```rust
EventKind::MemoryScanAlert {
    pid: u32,
    process_name: String,
    region_base: u64,
    region_size: u64,
    alert_type: MemoryAlertKind,   // YaraMatch | RwxAnomaly
    description: String,
}
```

### 4.4 Safety invariants

The scanner reads other processes' address spaces, so it carries
two hard invariants:

1. **Self-PID exclusion.** The scanner refuses to read from the
   agent's own PID at both the PAL trait and the rule-engine level.
2. **Bounded reads.** Every `MemoryScanner::read` call is capped by
   `max_region_bytes`; oversize regions are truncated rather than
   streamed.

Both invariants have unit tests in `sda-pal::memory_scanner` and
`sda-memory-scanner`.

### 4.5 AMSI integration (Windows, optional)

When the `amsi-windows` feature is enabled and the AMSI public API
is available, the agent additionally registers an
`IAntimalwareProvider` consumer to receive in-memory script content
(PowerShell, JScript, VBScript). Matches feed into the same rule
engine as on-disk content. AMSI is a documented Windows public API,
not a Defender-specific surface.

---

## 5. Identity attack detection

`sda-identity-monitor` adapts each platform's most direct credential
surface and emits a unified `IdentityAlert` event.

```rust
EventKind::IdentityAlert {
    category: IdentityAlertCategory,
    user: String,
    technique: String,    // MITRE ATT&CK technique ID, e.g. "T1003.001"
    description: String,
}
```

### 5.1 Windows — LSASS access

The provider opens an ETW session for `Microsoft-Windows-Kernel-Audit-API-Calls`
and filters on `OpenProcess` calls targeting the LSASS PID with the
`PROCESS_VM_READ` or `PROCESS_QUERY_INFORMATION` access mask. A
match emits `IdentityAlert { category: LsassAccess, technique:
"T1003.001", … }`.

### 5.2 Linux — sensitive file access

The provider subscribes to `sda-fim` for events on the configured
sensitive paths (default: `/etc/shadow`, `/proc/kcore`,
`/etc/gshadow`). Any access by a non-system principal emits an
`IdentityAlert { category: ShadowAccess, technique: "T1003.008", … }`.

"System principal" is determined by `is_system_principal` —
case-insensitive ASCII match against the configured allow-list
(default: `root`, `systemd`, `daemon`).

### 5.3 macOS — Keychain access

The provider subscribes to Endpoint Security `_NOTIFY_OPEN` events
on `~/Library/Keychains/login.keychain-db` and the system Keychain.
Matches emit `IdentityAlert { category: KeychainAccess, technique:
"T1555.001", … }`.

---

## 6. Data Loss Prevention (DLP)

DLP runs over file-write events emitted by `sda-fim`. Every match
produces a `LocalDetectionAlert` containing the matched **pattern
category**, the **byte offset + length** of the match, and a
**Blake3 fingerprint** of the surrounding window. **The matched
content is never serialised to the bus or to the control plane.**

### 6.1 Pattern set

The shipped baseline catalogue is a ≈ 50-pattern set covering PII,
PCI, and developer-secret detectors across four region groups —
Asia, GCC, Europe, and Global. Each entry is a
`regex::bytes::Regex` (so non-UTF-8 input is byte-correctly
scanned) wrapped around a region-specific structural validator
implementing the published check-digit / format algorithm.

#### Asia (16 patterns)

| Category | Pattern example | Structural validator |
|---|---|---|
| `pii.vn_cccd` | `\b\d{12}\b` | Vietnam CCCD province code + birth year |
| `pii.vn_mst` | `\b\d{10}(-\d{3})?\b` | Vietnam MST mod-11 weighted checksum |
| `pii.vn_bhxh` | `\b[A-Z]{2}\d{10}\b` | Vietnam BHXH province prefix allow-list |
| `pii.th_national_id` | `\b\d{13}\b` | Thailand mod-11 check digit |
| `pii.th_tax_id` | `\b\d{13}\b` | Same mod-11 as national ID |
| `pii.sg_nric` | `\b[STFGM]\d{7}[A-Z]\b` | Singapore per-series check letter |
| `pii.sg_uen` | three published shapes | Singapore UEN format + check character |
| `pii.my_mykad` | `\b\d{6}-\d{2}-\d{4}\b` | Malaysia JPN state code + DOB |
| `pii.cn_resident_id` | `\b\d{17}[\dX]\b` | GB 11643-1999 mod-11-2 weighted checksum |
| `pii.jp_my_number` | `\b\d{12}\b` | Japan 番号法 weighted mod-11 |
| `pii.kr_rrn` | `\b\d{6}-[1-4]\d{6}\b` | Korea weighted mod-11 + DOB |
| `pii.in_aadhaar` | `\b\d{4}\s?\d{4}\s?\d{4}\b` | India Verhoeff check digit |
| `pii.in_pan` | `\b[A-Z]{5}\d{4}[A-Z]\b` | India PAN holder-type code |
| `pii.id_nik` | `\b\d{16}\b` | Indonesia Kemendagri province + DOB |
| `pii.ph_philsys` | `\b\d{4}-\d{4}-\d{4}\b` | Philippines Luhn check |
| `pii.hk_hkid` | `\b[A-Z]{1,2}\d{6}\([0-9A]\)\b` | Hong Kong mod-11 with letter weights |

#### GCC (8 patterns)

| Category | Pattern example | Structural validator |
|---|---|---|
| `pii.ae_emirates_id` | `\b784-?\d{4}-?\d{7}-?\d\b` | UAE 784 prefix + Luhn |
| `pii.ae_trn` | `\b\d{15}\b` | UAE TRN `100` prefix |
| `pii.qa_qid` | `\b\d{11}\b` | Qatar QID nationality digit + birth year |
| `pii.sa_national_id` | `\b[12]\d{9}\b` | Saudi nationality digit + Luhn |
| `pii.kw_civil_id` | `\b\d{12}\b` | Kuwait century digit + DOB |
| `pii.bh_cpr` | `\b\d{9}\b` | Bahrain birth year + mod-11 |
| `pii.om_civil_id` | `\b\d{8,9}\b` | Oman length-bound structural check |
| `pci.gcc_iban` | AE/QA/SA/KW/BH/OM IBANs | ISO 7064 mod-97 |

#### Europe (13 patterns)

| Category | Pattern example | Structural validator |
|---|---|---|
| `pii.uk_ni` | `\b[A-Z]{2}\d{6}[A-Z]\b` | HMRC NI prefix allow-list |
| `pii.ch_ahv` | `\b756\.\d{4}\.\d{4}\.\d{2}\b` | Swiss AHV 756 prefix + EAN-13 |
| `pii.ch_uid` | `\bCHE-?\d{3}\.\d{3}\.\d{3}\b` | Swiss UID mod-11 check digit |
| `pci.ch_iban` | `\bCH\d{2}…\b` | Swiss IBAN ISO 7064 mod-97 |
| `pii.de_steuer_id` | `\b\d{11}\b` | Germany ISO 7064 mod 11,10 + structure |
| `pii.fr_nir` | `\b[12]\d{12}\d{2}\b` | France INSEE NIR mod-97 |
| `pii.nl_bsn` | `\b\d{9}\b` | Netherlands BSN eleven-test |
| `pii.es_dni` | `\b(\d{8}[A-Z]|[XYZ]\d{7}[A-Z])\b` | Spain DNI/NIE letter lookup |
| `pii.it_cf` | Codice Fiscale | Italy odd/even check character |
| `pii.se_personnummer` | `\b\d{6}[-+]?\d{4}\b` | Sweden Luhn + DOB |
| `pii.pl_pesel` | `\b\d{11}\b` | Poland weighted mod-10 + DOB |
| `pii.eu_vat` | per-country VAT prefixes | Per-country check digit algorithm |
| `pci.eu_iban` | `\b[A-Z]{2}\d{2}[\dA-Z]+\b` | ISO 7064 mod-97 + per-country length table |

#### Global (13 patterns)

| Category | Pattern example | Structural validator |
|---|---|---|
| `pii.ssn` | `\b\d{3}-\d{2}-\d{4}\b` | US SSA area/group/serial rules |
| `pci.pan_luhn` | 13–19 contiguous digits | Luhn-10 checksum |
| `pii.email` | RFC 5321 simplified | Local-part / domain edge cases |
| `pii.phone_e164` | `\+\d{7,15}` | ITU country code prefix validation |
| `pii.passport_mrz` | ICAO 9303 TD3 MRZ | Per-field + composite check digits |
| `secrets.aws_access_key` | `\b(AKIA|ASIA|AIDA|…)[0-9A-Z]{16}\b` | ASCII pre-filter only |
| `secrets.private_key` | `-----BEGIN [A-Z ]+PRIVATE KEY-----` | PEM armor token |
| `secrets.github_pat` | `\bgh[pousr]_[A-Za-z0-9]{36}\b` | ASCII pre-filter only |
| `secrets.slack_token` | `\bxox[baprse]-[A-Za-z0-9-]{10,}\b` | Three-segment shape |
| `secrets.gcp_service_key` | `"type"\s*:\s*"service_account"` | JSON marker |
| `secrets.azure_client_secret` | `…8Q~…` modern Azure secret | ASCII pre-filter only |
| `secrets.jwt` | `\beyJ…\.eyJ…\.…\b` | Base64-decoded header check |
| `secrets.generic_api_key` | `apikey = "…"` heuristic | Mixed-alphabet entropy check |

The catalogue is configurable. Operators select patterns via the
[`modules.dlp.patterns`](./configuration-reference.md#modulesdlp)
field or the [`modules.dlp.region`](./configuration-reference.md#modulesdlp)
shorthand. Supported selectors:

- **Exact category** — e.g. `"pii.ssn"`, `"pci.pan_luhn"`.
- **Regional glob** — `"asia.*"`, `"gcc.*"`, `"europe.*"`, `"global.*"`.
- **Category-tag glob** — `"pii.*"`, `"pci.*"`, `"secrets.*"`.
- **Wildcard** — `"*"` or `"all"`.

An empty `patterns: []` selects the full catalogue (default
behaviour); to disable scanning entirely, set `enabled: false`.

Each pattern compiles to its own `regex::bytes::Regex` with the
regex crate's per-pattern Aho-Corasick literal prefilter, so the
patterns with strong literal anchors (e.g. `AKIA`, `ghp_`, `BEGIN`,
`service_account`) scan a 1 MiB buffer in microseconds. Structural
validators only run on the candidate pre-filter matches (typically
< 0.1 % of bytes), so adding validators has negligible cost
relative to the regex pass. The benchmark gate is **a full-
catalogue scan of a 1 MiB buffer in < 500 ms (release mode)**;
see [`benchmarks.md`](./benchmarks.md) § 5.1 for the rationale,
the `#[ignore]` semantics, and the long-term performance target.

### 6.2 Bounded scanning

DLP only inspects files up to `max_bytes_per_file` (default 2 MiB).
Larger files are skipped and an `AgentVitals` info event is
emitted. The scanner reads the file via `take().read_to_end()` to
honour the bound exactly, even on streams that return short reads.

### 6.3 Redaction invariant

The module's emitted evidence shape:

```rust
DlpMatch {
    category: String,     // e.g. "pii.ssn"
    offset: u64,
    length: u32,
    window_blake3: [u8; 32],   // hash of 32-byte window around the match
}
```

There is no `value` field. The matched content does not leave the
file-handling code path. This is verified by the DLP unit tests
which inspect the wire-format output of every test case.

---

## 7. Rule distribution (TRDS)

Rules ship as **TRDS bundles** — signed, versioned MessagePack
archives pulled from object storage published by the SN360 control
plane.

```
control plane                           agent
+----------------+                      +--------------------+
| TRDS publisher |------ HTTPS -------> | sda-local-detection|
| (Ed25519 sign) |  pinned signing key  |   trds_client.rs    |
+----------------+                      +--------------------+
                                                 |
                                                 | Arc<ArcSwap<DetectionPipeline>>
                                                 v
                                       +--------------------+
                                       |  Active pipeline   |
                                       +--------------------+
```

### 7.1 Bundle format

A bundle is a MessagePack-encoded `TrdsBundle`:

- `version: u32` — monotonically increasing per tenant.
- `signature: [u8; 64]` — Ed25519 detached signature over the
  canonical encoding of the bundle minus the signature field.
- `key_id: String` — index into the pinned signing key set.
- `rules: Vec<Rule>` — Aho-Corasick / IOC / YARA / behavioural rules.

### 7.2 Hot reload

The agent polls the bundle URL at `trds_poll_interval_secs`
(default 600 s). On a new version it:

1. Downloads the bundle to a temp file.
2. Verifies the signature against the pinned key set.
3. Compiles a new `DetectionPipeline`.
4. Atomically swaps the live pipeline via `Arc<ArcSwap<DetectionPipeline>>`.

The swap is lock-free; in-flight events finish against the old
pipeline and new events route to the new one. If verification or
compilation fails, the active pipeline is untouched and an
`AgentVitals` warning is emitted.

### 7.3 Embedded baseline

The agent embeds a baseline TRDS bundle at build time. On first run
the embedded bundle becomes the active pipeline; the TRDS poller
then upgrades it once a control-plane bundle is reachable. This
ensures detection works on a freshly enrolled agent before any
control-plane round-trip.

---

## 8. Response actions

### 8.1 Host isolation

`sda-host-isolation` accepts two signed jobs:

- `IsolateHost { allowed_ips: Vec<IpAddr> }` — installs firewall
  rules that allow only loopback and the configured SN360 control-plane
  IPs.
- `UnisolateHost` — removes the rule set.

| Platform | Backend | Rule scope |
|---|---|---|
| Windows | `netsh advfirewall` + WFP COM filter ordering | Rule group `sn360_isolation` |
| macOS | `pfctl` anchor `com.sn360.host_isolation` | Anchor reload |
| Linux | `nftables` table `sn360_isolation` | Atomic ruleset swap |

The job flows through the 10-step validation pipeline in
[`architecture.md` § 3.2](./architecture.md#32-signed-job-ingress)
before any rules are installed. Isolation state changes emit a
`HostIsolationStateChanged` event.

### 8.2 Active response

`sda-active-response` handles `block_ip` and `kill_process` jobs
against a hard-coded command allow-list. Active response is the
historical interop path for the legacy SIEM integration; for native
SN360 deployments, host isolation and signed device-control jobs
are the recommended response surface.

### 8.3 Bidirectional with Device Control

Detection alerts feed into Device Control's policy engine: a
`LocalDetectionAlert` of severity `Critical` against a known
package can produce a Recommendation to uninstall, which can be
turned into a signed `UninstallPackage` job. See
[`device-control.md`](./device-control.md).

---

## 9. Resource budgets

| Module (when enabled) | Idle RSS | Idle CPU | Active CPU |
|---|---|---|---|
| `sda-process-monitor` | 5 MB | 0.5 % | up to 2 % during exec storms |
| `sda-network-monitor` | 3 MB | 0.3 % | up to 1 % during burst |
| `sda-memory-scanner` | 4 MB | ~0 % | ≤ 1 % during scan window |
| `sda-identity-monitor` | 1 MB | 0.1 % | event-driven |
| `sda-dlp` | 3 MB | 0.5 % | bounded by FIM event rate |
| `sda-host-isolation` | < 0.5 MB | ~0 % | ms during transition |

Combined (full EDR slate enabled): idle RSS < 32 MB, idle CPU < 2 %.
See [`benchmarks.md`](./benchmarks.md) for the full numbers.

---

## 10. Security posture

The EDR module is the highest-privilege surface in the agent — it
reads other processes' memory, inspects file content, and modifies
the local firewall. The relevant invariants are:

1. **Memory-scanner self-PID exclusion** (§ 4.4) prevents the agent
   from reading or hashing its own address space.
2. **DLP redaction invariant** (§ 6.3) prevents matched content from
   ever crossing a wire boundary.
3. **Signed-job validation** (architecture.md § 3.2) gates every
   side-effect — including host isolation — behind two-factor
   Ed25519 signatures.
4. **Tamper protection** (architecture.md § 8.5) watches the agent
   binary, config, and key file; mutations trigger a watchdog
   restart and a vitals warning.
5. **Bounded reads everywhere** (memory regions, DLP file content,
   network sampler) prevent a hostile peer process or file from
   pinning agent CPU.

The clean-room implementation policy — no CrowdStrike Falcon,
SentinelOne Singularity, or Microsoft Defender for Endpoint source
code is vendored, copied, or translated — is documented in
[`licensing.md`](./licensing.md).
