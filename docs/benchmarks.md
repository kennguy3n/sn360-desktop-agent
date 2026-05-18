# Benchmarks

SDA is designed to be "invisible to the user." This document
captures the resource budgets, the methodology used to verify
them, and a representative set of numbers from a reference run.

The budgets are enforced in CI by
`tests/scripts/benchmark-regression.sh` (invoked via
`make benchmark-ci`). A regression that breaches any budget fails
the gate.

---

## Table of contents

1. [Budgets at a glance](#1-budgets-at-a-glance)
2. [Methodology](#2-methodology)
3. [Reference numbers](#3-reference-numbers)
4. [Comparison against a reference SIEM agent](#4-comparison-against-a-reference-siem-agent)
5. [Regression gate](#5-regression-gate)
6. [Caveats](#6-caveats)

---

## 1. Budgets at a glance

| Metric | Budget |
|---|---|
| Stripped binary size | < 7 MB |
| Idle resident memory (single process) | < 15 MB |
| Idle CPU (60 s average) | < 0.1 % |
| FIM scan CPU peak (1 000-file burst) | < 3 % |
| Memory-scanner idle RSS (per module) | < 4 MB |
| Memory-scanner per-scan CPU window | < 1 % over 60 s |

All numbers are measured on Linux x86_64. Windows and macOS budgets
are within 10 % on equivalent hardware; per-OS numbers are tracked
in the nightly benchmark CI artefact.

---

## 2. Methodology

### 2.1 Sampling

- `pidstat -p <pid> -r -u 2 30` for idle RSS and CPU (30 samples,
  2 s interval, 60 s window) after a 15–20 s warm-up.
- `pidstat -p <pid> 1 15` while running the burst workload for FIM
  scan CPU.
- `ls -lh` for binary size (stripped release build).

### 2.2 Build flags

The release profile in `Cargo.toml` is the audited build:

```toml
[profile.release]
lto = "fat"
codegen-units = 1
panic = "abort"
opt-level = "z"
strip = true
```

### 2.3 Reproduction

```sh
sudo apt-get install -y sysstat bc
make benchmark-ci
cat target/benchmark-regression/benchmark-regression.txt
```

The script:

1. Builds the release binary.
2. Starts a Wazuh 4.9.2 reference manager in Docker (for the
   comparison numbers in § 4).
3. Enrols the SDA agent against the manager.
4. Samples idle RSS and CPU.
5. Creates 1 000 files in a watched directory and samples FIM
   scan CPU.
6. Records binary size from `ls -lh`.
7. Exits non-zero on the first breach.

---

## 3. Reference numbers

Reference host: Ubuntu Linux x86_64, container-in-container CI runner.

| Metric | Budget | Observed | Status |
|---|---|---|---|
| Binary size | < 7 MB | 6.49 MB | Met |
| Idle RSS | < 15 MB | 5.7 MB | Met |
| Idle CPU (60 s avg) | < 0.1 % | 0.00 % | Met |
| FIM scan CPU peak | < 3 % | 3 % | Met (boundary) |
| FIM scan CPU 15-s avg | n/a | 1.33 % | — |

The FIM-burst budget is on the strict boundary because the test
creates 1 000 files back-to-back; real-world change rates are much
lower and the steady-state average has significant headroom. If a
future workload pushes the peak above 3 %, the recommended first
knob is `max_hashes_per_sec` in `crates/sda-fim/src/config.rs`
(50 → lower peak, longer tail latency).

### 3.1 Binary-size breakdown

`cargo bloat --release -p sda-agent --crates` attributes the 6.49 MB
binary as follows:

- On-device detection engine — `sda_local_detection`
  (≈ 190 KiB `.text`) + `yara_sys` (≈ 229 KiB) +
  `regex_automata` (≈ 307 KiB) + `aho_corasick` (≈ 122 KiB)
  matchers that back the local detection engine.
- Enhanced-protocol stack — `rustls` (≈ 270 KiB) + `ring`
  (≈ 180 KiB) + `webpki-roots` form the TLS 1.3 + HTTP/2 transport.
- Signed self-updater — `reqwest` (≈ 127 KiB) plus its small
  HTTP/JSON deps back `sda-updater`'s manifest-polling and
  atomic-swap upgrade path.

The remainder is `sda-*` crate code, `tokio`, `serde`, and
platform-specific PAL providers.

---

## 4. Comparison against a reference SIEM agent

For a like-for-like point of reference, SDA was benchmarked against
Wazuh Agent 4.9.2 (`wazuh-agent_4.9.2-1_amd64.deb`) talking to a
local `wazuh/wazuh-manager:4.9.2` Docker manager. Wazuh's agent
functionality is split across five daemons (`wazuh-agentd`,
`wazuh-syscheckd`, `wazuh-logcollector`, `wazuh-modulesd`,
`wazuh-execd`); totals are summed across all five for binary size
and RSS.

### 4.1 Binary size

| Component | Reference SIEM | SDA |
|---|---|---|
| Communications daemon | 752 KB | (integrated) |
| FIM daemon | 888 KB | (integrated) |
| Log-collector daemon | 780 KB | (integrated) |
| Inventory / SCA / rootcheck daemon | 700 KB | (integrated) |
| Active-response daemon | 724 KB | (integrated) |
| Single static binary | n/a | 6.49 MB |
| **Total shipped binaries** | **3.8 MB** | **6.49 MB** |

SDA is a single static binary that includes FIM, log collection,
inventory, SCA, rootcheck, active response, the on-device YARA
detection engine, the signed self-updater, and the optional TLS
1.3 + HTTP/2 native protocol stack. The reference SIEM agent splits
those responsibilities across five dynamically-linked ELF binaries
plus shipped shared libraries, Python, and OpenSSL under
`/var/ossec`, and does **not** ship on-device YARA.

### 4.2 Idle RSS

| Component | RSS |
|---|---|
| Reference SIEM (5-daemon total) | ~56.5 MB |
| SDA (single process) | ~5.7 MB |

SDA uses ~9.9× less resident memory than the combined reference
agent footprint.

### 4.3 Idle CPU (60 s avg)

| Component | Avg %CPU |
|---|---|
| Reference SIEM communications daemon only | 0.45 % |
| SDA | 0.00 % |

The reference number is only the communications daemon; the four
other reference daemons add additional idle cost that is not
aggregated here.

### 4.4 FIM scan CPU (1 000-file burst)

| Component | Peak %CPU | 15-s avg %CPU |
|---|---|---|
| Reference SIEM (`syscheckd` hashing) | 9 % | 1.60 % |
| SDA | 3 % | 1.33 % |

---

## 5. Regression gate

The four headline budgets are enforced in CI by
`tests/scripts/benchmark-regression.sh`. The script builds the
release binary, samples idle RSS and CPU via `pidstat`, measures
binary size from `ls`, runs a FIM burst against a temporary
watched directory, and exits non-zero on the first breach.

Hard thresholds encoded in the script:

- `MAX_IDLE_RSS_KB=15360` (15 MB)
- `MAX_IDLE_CPU_PCT=0.1`
- `MAX_BINARY_SIZE_BYTES=7340032` (7 MB)
- `MAX_FIM_PEAK_CPU_PCT=3.0`

Results land in
`target/benchmark-regression/benchmark-regression.txt` and are
uploaded as the `benchmark-regression` CI artefact from the nightly
schedule.

---

## 6. Caveats

- Binary-size comparison is not strictly apples-to-apples: SDA is
  a single static Rust binary; the reference SIEM agent is five
  dynamically-linked daemons plus shared libraries. A like-for-like
  comparison would measure the full install footprint (`du -sh
  /var/ossec` vs. `du -sh target/release/sda-agent`).
- Reference-agent idle CPU reflects only the communications daemon.
  The remaining four daemons have their own idle overhead that is
  not summed here.
- FIM stress pattern (1 000 files created back-to-back) is
  worst-case. Real-world change rates are lower, so steady-state
  CPU sits well below the peak.
- Absolute CPU numbers on a shared CI runner are indicative, not
  authoritative; the dedicated nightly benchmark runner publishes
  per-platform numbers that should be treated as canonical.
