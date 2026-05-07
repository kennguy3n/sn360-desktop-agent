# SN360 Desktop Agent (SDA): Architecture & Implementation Proposal

> **Version:** 1.0 | **Date:** April 2026 | **Status:** Draft Proposal
> **Target Platforms:** Windows 10/11, macOS 12+, Linux (Ubuntu/Fedora/Arch)
> **Goal:** Sub-20 MB RAM idle, <0.5% CPU baseline, unnoticeable to end users

> **Scope note (2026-04-22):** This proposal covers both agent-side and
> server-side components. The agent-side implementation lives in this
> repository (`sn360-agent-device`). All server-side Control Plane
> components described herein — TRDS, IOCFS, SIS, Agent Gateway — are
> implemented in
> [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform).

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Analysis of Existing SIEM Agent Architectures](#2-analysis-of-existing-siem-agent-architectures)
3. [Problem Statement & Design Goals](#3-problem-statement--design-goals)
4. [Proposed Architecture](#4-proposed-architecture)
5. [Core Module Design](#5-core-module-design)
6. [Cross-Platform Abstraction Layer](#6-cross-platform-abstraction-layer)
7. [Technology Stack & Justification](#7-technology-stack--justification)
8. [Communication Protocol](#8-communication-protocol)
9. [Resource Management Strategy](#9-resource-management-strategy)
10. [Security Architecture](#10-security-architecture)
11. [Configuration & Deployment](#11-configuration--deployment)
12. [Implementation Roadmap](#12-implementation-roadmap)
13. [Phase 4 Detail: Edge Detection, Software Inventory & Tenant Rule Distribution](#13-phase-4-detail-edge-detection-software-inventory--tenant-rule-distribution)
    - 13.1 [Local Detection Engine (LDE) Module](#131-local-detection-engine-lde-module)
    - 13.2 [Enhanced Software Inventory Module](#132-enhanced-software-inventory-module)
    - 13.3 [Companion Microservices](#133-companion-microservices)
      - 13.3.1 [Tenant Rule Distribution Service (TRDS)](#1331-tenant-rule-distribution-service-trds)
      - 13.3.2 [IOC Feed Aggregator Service (IOCFS)](#1332-ioc-feed-aggregator-service-iocfs)
      - 13.3.3 [Software Inventory Service (SIS)](#1333-software-inventory-service-sis)
    - 13.4 [Agent Gateway](#134-agent-gateway)
    - 13.5 [Updated Resource Budget](#135-updated-resource-budget)
    - 13.6 [Updated Configuration](#136-updated-configuration)
    - 13.7 [New Crate Structure](#137-new-crate-structure)
14. [Risk Assessment](#14-risk-assessment)
15. [Local SIEM Manager Test Environment](#15-local-siem-manager-test-environment)
16. [Summary](#16-summary)

---

## 1. Executive Summary

Typical current-generation SIEM endpoint agents are general-purpose C/C++ applications designed to serve every deployment context (servers, containers, endpoints, cloud) with a single binary. While feature-complete, that class of architecture carries unnecessary overhead for desktop and laptop endpoints, where user experience and battery life are paramount.

This proposal describes **SN360 Desktop Agent (SDA)** -- a purpose-built, modular security agent written from scratch in Rust, optimized exclusively for end-user devices. SDA is **not** a port, translation, or derivative work of any existing SIEM agent codebase; interoperability with legacy SIEM managers is provided as an optional, feature-gated adapter that implements publicly documented wire protocols (similar to how Samba implements SMB or Postfix implements SMTP). The design targets:

| Metric | Typical General-Purpose SIEM Agent | SDA Target |
|---|---|---|
| Idle RAM | 60-120 MB | **< 15 MB** |
| Idle CPU | 1-3% | **< 0.1%** |
| FIM scan CPU spike | 10-30% | **< 3%** |
| Binary size (stripped) | ~25 MB + deps | **< 7 MB** |
| Startup time | 3-8 seconds | **< 500 ms** |
| Disk I/O during idle | Continuous | **Near-zero** |

> Benchmark column values for general-purpose SIEM agents are drawn from industry-published desktop-agent sizing guides and public vendor documentation; no internal source code or confidential material from any third-party vendor was consulted in producing these figures.

The key architectural decisions enabling these targets are:

1. **Rust as the primary language** -- zero-cost abstractions, no GC pauses, fearless concurrency, and first-class cross-platform support.
2. **Event-driven, async-first architecture** -- using `tokio` with a single-threaded runtime by default, scaling only when work demands it.
3. **Modular plugin system** -- load only the modules the endpoint needs; unload when idle.
4. **OS-native notification APIs** -- replace polling with kernel-level filesystem/process watchers (inotify/fanotify, FSEvents, ReadDirectoryChangesW).
5. **Adaptive scheduling** -- back off scans when the user is active; run intensive work during idle/sleep transitions.

---

## 2. Analysis of Existing SIEM Agent Architectures

This section discusses architectural patterns commonly found in general-purpose, cross-platform SIEM endpoint agents and explains why those patterns are a poor fit for user-facing desktop and laptop devices. The analysis is drawn from publicly available vendor documentation, product datasheets, and the authors' operational experience deploying and running SIEM agents at scale. **No third-party SIEM agent source code was consulted, copied, or translated in the design of SDA.**

### 2.1 Typical Architectural Pattern

Many widely deployed SIEM agents share the same high-level shape:

- A **single monolithic daemon** (often written in C or C++) that hosts every feature module in one process.
- **Every module is always loaded**, whether the endpoint needs it or not, because the packaging is "one binary for every deployment target."
- A **thread-per-module concurrency model**, where each feature (file monitoring, log collection, inventory, active response, etc.) spawns one or more dedicated OS threads regardless of workload.
- **Embedded runtimes** (an interpreter such as Python, plus auxiliary tools) are bundled in to support cloud-connector or wodle-style plugins on server deployments, but still pay their memory cost on endpoints.
- **Heavy embedded data stores** (RocksDB, large in-memory SQLite, etc.) persist agent state.
- A long chain of **statically linked C libraries** (OpenSSL, cURL, libarchive, PCRE2, msgpack, cJSON, a compression library, and more) bulk up the binary.
- **Anti-flood circular buffers** with fixed pre-allocations regardless of event rate.

### 2.2 Why This Shape Is a Poor Fit for Desktops and Laptops

The same design decisions that make a general-purpose agent convenient to ship on servers become liabilities on user-facing devices:

| Pattern | Typical Desktop Impact | Root Cause |
|---|---|---|
| Embedded interpreter runtime | +30-40 MB RAM, +15 MB disk | Needed for plugins irrelevant on a laptop |
| Heavy embedded KV store (e.g. RocksDB) | +10-15 MB RAM | Over-sized for endpoint state volumes |
| In-memory FIM database | +5-15 MB RAM | Full scan results kept resident |
| Polling-based log collection | Continuous CPU | Files polled on configurable intervals instead of OS notifications |
| Full-disk FIM scans | CPU spikes to 10-30 % | Scheduled full hash scans of monitored directories |
| Monolithic process, no unload | All modules always resident | No runtime module lifecycle |
| Thread-per-module concurrency | Thread-stack overhead | Each module owns 1-3 threads irrespective of work |
| Large static dependency chain | +10-20 MB binary | 25+ transitively linked C libraries |
| Fixed anti-flood buffers | Wasted RAM at idle | Pre-allocated regardless of event rate |

### 2.3 Legacy SIEM Wire Protocols as an Interoperability Target

A number of SIEM managers speak a **legacy agent wire protocol** consisting of the following publicly documented ingredients:

- A **UDP or TCP** transport on a dedicated port.
- A **custom framing format** with a small textual header and AES-256 / Blowfish-CBC encrypted payload using a pre-shared agent key.
- A separate **enrollment endpoint** (typically TLS-wrapped) that issues agent IDs and pre-shared keys.
- **Keepalive messages** sent on a configurable interval.
- Queue-prefixed message types (e.g. `1:` for log data, `8:syscheck:` for FIM, `d:` for inventory) so the server-side router can dispatch events to the appropriate analysis pipeline.

SDA treats this wire format strictly as a **public interoperability target**. Supporting it does not imply any shared source lineage any more than a fresh SMTP client implementation implies lineage from Postfix or Sendmail. SDA's implementation of this legacy wire format lives entirely in an optional feature-gated adapter (see § 8.1) and is independent from the agent's default SN360-native protocol.

### 2.4 Cross-Platform Implementation Patterns

General-purpose SIEM agents historically handle cross-platform support via:

- **C preprocessor `#ifdef` walls** scattered throughout module source files.
- **Parallel platform-specific source files** with duplicated logic per OS.
- **Build-system target selection** (e.g. `make TARGET=...`) rather than a unified cross-compilation story.
- **Per-module ad-hoc platform handling** instead of a single platform abstraction layer.

SDA takes the opposite approach: a single **Platform Abstraction Layer (PAL)** (see § 6) exposes each OS integration (filesystem watcher, log source, service manager, firewall control, power monitor) as a Rust trait, with platform-specific implementations selected at compile time. This keeps module code portable and keeps OS-specific code isolated and individually auditable.

---

## 3. Problem Statement & Design Goals

### 3.1 Problem

Desktop/laptop users experience:
- Noticeable CPU spikes during FIM scans and inventory collection
- Memory footprint inappropriate for 8-16 GB RAM devices running user workloads
- Battery drain on laptops from continuous polling and periodic scans
- Occasional I/O contention with user applications during disk-heavy scans

### 3.2 Design Goals

| Priority | Goal | Metric |
|---|---|---|
| P0 | **Invisible to the user** | <0.1% idle CPU, <15 MB RAM, no perceptible disk I/O |
| P0 | **Security parity** | FIM, log collection, SCA, inventory, active response all functional |
| P0 | **Cross-platform** | Single codebase, native builds for Windows/macOS/Linux |
| P1 | **Battery-aware** | Defer scans on battery; adaptive scheduling |
| P1 | **Fast startup** | <500 ms cold start |
| P1 | **Small footprint** | <7 MB binary, <12 MB installed |
| P1 | **Edge detection capability** | Local IOC matching + behavioral rules, <1% CPU during event evaluation |
| P2 | **Legacy SIEM interoperability** | Communicate with common legacy SIEM managers through the optional, feature-gated legacy adapter |
| P2 | **Graceful degradation** | Reduce functionality under resource pressure rather than crash |
| P2 | **Auto-update** | Self-updating agent with rollback capability |

### 3.3 Non-Goals

- **Server/manager functionality** -- this agent is endpoint-only
- **Container monitoring** -- separate container-optimized agent
- **Cloud API integration** -- wodles for AWS/Azure/GCP remain server-side
- **Full vulnerability scanning** -- CVE matching remains server-side (in the SIS microservice); the agent now performs local IOC matching and behavioral detection but does not run full CVE analysis locally

---

## 4. Proposed Architecture

### 4.1 High-Level Architecture

```
+------------------------------------------------------------------+
|                    SN360 Desktop Agent (SDA)                      |
+------------------------------------------------------------------+
|                                                                    |
|  +--------------------+    +-------------------+                   |
|  |   Agent Core       |    |  Module Manager   |                   |
|  |  - Lifecycle mgmt  |    |  - Load/unload    |                   |
|  |  - Config engine   |    |  - Health checks  |                   |
|  |  - Signal handling |    |  - Scheduling     |                   |
|  +--------+-----------+    +--------+----------+                   |
|           |                         |                              |
|  +--------v-------------------------v----------+                   |
|  |            Event Bus (async channels)        |                  |
|  |  - Zero-copy message passing                 |                  |
|  |  - Backpressure support                      |                  |
|  |  - Priority queues                           |                  |
|  +----+--------+--------+--------+--------+----+                  |
|       |        |        |        |        |                        |
|  +----v--+ +---v---+ +--v---+ +-v----+ +-v-------+               |
|  |  FIM  | | Log   | | SCA  | | Inv  | | Active  |               |
|  |Module | |Collect | |Module| |Module| |Response |               |
|  +-------+ +-------+ +------+ +------+ +---------+               |
|                                                                    |
|  +-------------------------------------------------------------+  |
|  |          Platform Abstraction Layer (PAL)                     | |
|  |  +----------+  +----------+  +-----------+  +----------+    | |
|  |  |Filesystem|  |  Process |  |  Network  |  |  System  |    | |
|  |  | Watcher  |  |  Monitor |  |  Monitor  |  |   Info   |    | |
|  |  +----------+  +----------+  +-----------+  +----------+    | |
|  +-------------------------------------------------------------+  |
|                                                                    |
|  +-------------------------------------------------------------+  |
|  |              Communication Layer                              | |
|  |  - TLS 1.3 transport (rustls)                                | |
|  |  - Legacy SIEM protocol adapter (optional, feature-gated)   | |
|  |  - Automatic reconnection with exponential backoff           | |
|  |  - Message batching & compression                            | |
|  +-------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

### 4.2 Core Design Principles

#### 4.2.1 Event-Driven, Not Polling

Every module that can use OS-native notification APIs must do so:

| Function | Current (Polling) | SDA (Event-Driven) |
|---|---|---|
| File changes | Scheduled full-disk hash scans | `inotify`/`fanotify` (Linux), `FSEvents` (macOS), `ReadDirectoryChangesW` (Windows) |
| Log collection | Periodic file reads with seek tracking | `inotify` on log files + systemd journal subscription + macOS OSLog streaming |
| Process monitoring | Periodic `/proc` enumeration | `netlink` proc connector (Linux), `kqueue` (macOS), ETW (Windows) |
| Network changes | Periodic interface enumeration | `netlink` RTNL (Linux), `SCNetworkReachability` (macOS), `NotifyIpInterfaceChange` (Windows) |

Full-disk scans are retained only as a **fallback verification** mechanism, running during system idle periods.

#### 4.2.2 Lazy Module Loading

Modules are compiled as separate Rust crates but linked into a single binary. At runtime, each module's main loop is spawned as an async task only when enabled in configuration. Disabled modules consume zero CPU and near-zero RAM.

```rust
// Pseudocode for module lifecycle
trait AgentModule: Send + Sync {
    fn name(&self) -> &'static str;
    fn init(&mut self, config: &ModuleConfig) -> Result<()>;
    async fn run(&mut self, bus: EventBus) -> Result<()>;
    async fn shutdown(&mut self) -> Result<()>;
    fn health_check(&self) -> ModuleHealth;
}
```

#### 4.2.3 Adaptive Resource Budgeting

The agent monitors system state and adjusts its behavior:

```
System State         | FIM Scan Rate | Log Batch Size | Inventory Interval
---------------------|---------------|----------------|-------------------
User active + AC     | Normal        | Normal         | Normal (1h)
User active + Battery| Reduced 50%   | Increased 2x   | Extended (4h)
User idle + AC       | Accelerated   | Normal         | Normal (1h)
User idle + Battery  | Reduced 25%   | Increased 4x   | Extended (8h)
High CPU (>80%)      | Paused        | Increased 4x   | Deferred
Low memory (<500MB)  | Paused        | Minimal        | Deferred
```

#### 4.2.4 Single-Threaded Async by Default

The agent uses a **single-threaded tokio runtime** for all async I/O. CPU-intensive work (hashing, compression) is offloaded to a small (2-thread) blocking pool via `spawn_blocking`. This eliminates thread synchronization overhead for the common path.

```
Threads at idle:
  1x  Main async runtime (event loop + all modules)
  0x  Blocking pool threads (spawned on demand, reaped after timeout)

Threads during FIM scan:
  1x  Main async runtime
  1-2x Blocking pool (hash computation)
```

---

## 5. Core Module Design

### 5.1 File Integrity Monitoring (FIM)

**Current issues:** Full-disk scans hash every monitored file, causing CPU spikes up to 30%. The SQLite FIM database keeps full state in memory.

**SDA Design:**

```
FIM Module
  |
  +-- Real-time Watcher (primary)
  |     Linux:   fanotify (FAN_MARK_FILESYSTEM) or inotify
  |     macOS:   FSEvents with kFSEventStreamCreateFlagFileEvents
  |     Windows: ReadDirectoryChangesW with FILE_NOTIFY_CHANGE_*
  |
  +-- Change Processor
  |     - Debounce rapid changes (100ms window)
  |     - Hash only changed files (SHA-256 via ring crate)
  |     - Compare against on-disk state DB
  |     - Emit change events to Event Bus
  |
  +-- State Store
  |     - Memory-mapped SQLite (WAL mode, mmap_size=4MB)
  |     - Schema: path, hash, size, perms, uid, gid, mtime, inode
  |     - Bloom filter for fast "is this path monitored?" checks
  |
  +-- Baseline Scanner (secondary)
        - Runs only during detected system idle
        - Rate-limited: max 100 files/sec, yields every 10ms
        - Verifies real-time watcher hasn't missed changes
        - Incremental: only re-hashes files with changed mtime/size
```

**Memory budget:** ~2 MB for state DB + bloom filter for 500K monitored paths.

### 5.2 Log Collection

**Current issues:** 10,818 LoC with 17+ format-specific readers. Polling-based file reading. All readers always compiled in.

**SDA Design:**

```
Log Collector Module
  |
  +-- Source Registry
  |     - Tracks monitored log sources with seek positions
  |     - Persisted to disk on graceful shutdown
  |
  +-- Watcher (event-driven)
  |     Linux:   inotify IN_MODIFY on log files
  |     macOS:   FSEvents / kqueue EVFILT_VNODE
  |     Windows: ReadDirectoryChangesW on log directories
  |
  +-- Readers (feature-gated at compile time)
  |     - Syslog (plain text line reader)
  |     - JSON (streaming JSON parser via simd-json)
  |     - Windows Event Log (via windows-rs EvtSubscribe)
  |     - macOS Unified Log (via OSLog streaming API)
  |     - systemd Journal (via libsystemd sd_journal_* FFI)
  |
  +-- Output Buffer
        - Ring buffer with configurable capacity (default: 1000 events)
        - Backpressure: drops oldest events when full (configurable)
        - Batches events for transmission (default: every 5s or 100 events)
```

**Key optimization:** Instead of polling log files every N seconds, we receive OS-level notifications when files are modified, then read only the new data from the last seek position.

### 5.3 System Inventory (Syscollector)

**Current issues:** Enumerates all packages, processes, ports, network interfaces, and hardware on every scan cycle. The data_provider module is 24K+ LoC with heavy platform-specific code.

**SDA Design:**

```
Inventory Module
  |
  +-- Hardware Info (collected once at startup, cached)
  |     - CPU model, cores, RAM total
  |     - OS version, hostname, architecture
  |
  +-- Package Inventory
  |     Linux:   dpkg/rpm DB inotify watch + incremental diff
  |     macOS:   FSEvents on /Applications + receipts + Homebrew
  |     Windows: Registry watcher on Uninstall keys + AppX catalog
  |
  +-- Network Interfaces
  |     Linux:   netlink RTNL subscription
  |     macOS:   SCNetworkReachability callbacks
  |     Windows: NotifyIpInterfaceChange callbacks
  |
  +-- Process List
  |     - Snapshot only on demand or server request
  |     - NOT continuously monitored (high cost, low value for desktops)
  |
  +-- Open Ports
        - Snapshot only on demand or on network change events
```

**Key optimization:** Event-driven package tracking. Instead of scanning all packages every hour, watch the package database files for changes and only re-enumerate when something actually changed.

### 5.4 Security Configuration Assessment (SCA)

**Current issues:** Lua-based policy evaluation engine. Runs all checks sequentially.

**SDA Design:**

```
SCA Module
  |
  +-- Policy Engine
  |     - YAML policy files (SCA-style, compatible with common public SCA policy syntax)
  |     - Compiled to a check tree at load time
  |     - Checks are pure functions: (SystemState) -> CheckResult
  |
  +-- Check Executor
  |     - Runs during system idle only
  |     - Rate-limited: max 50 checks/sec
  |     - Results cached until relevant system state changes
  |     - Delta reporting: only send changed results to server
  |
  +-- Check Types
        - File existence/content/permissions
        - Registry keys (Windows)
        - Process running checks
        - Command output evaluation
        - System configuration values
```

### 5.5 Active Response

**Current issues:** Separate daemon (os_execd) that forks processes to run scripts.

**SDA Design:**

```
Active Response Module
  |
  +-- Command Registry
  |     - Pre-registered response actions with allowed parameters
  |     - Sandboxed: actions run with dropped privileges
  |
  +-- Executor
  |     - Async process spawning via tokio::process
  |     - Timeout enforcement (default: 30s)
  |     - Output capture and event reporting
  |
  +-- Built-in Actions
        - IP blocking (platform-native firewall APIs)
        - Process termination
        - User session disconnect
        - Custom script execution (configurable, off by default)
```

### 5.6 Rootkit Detection (Rootcheck)

**Current issues:** Scans for known rootkit files/directories, checks `/dev`, verifies system binaries.

**SDA Design:**

This module is retained but significantly simplified for desktops:

```
Rootcheck Module
  |
  +-- File-based checks (known rootkit signatures)
  |     - Run during system idle, once per day
  |
  +-- Process hiding detection
  |     - Compare /proc enumeration vs kill(pid, 0) sweep
  |     - Run once per hour during idle
  |
  +-- System binary integrity
        - Verify critical binaries against known hashes
        - Triggered by FIM changes to /usr/bin, /usr/sbin, etc.
```

---

## 6. Cross-Platform Abstraction Layer

### 6.1 PAL Architecture

The Platform Abstraction Layer is a set of Rust traits with platform-specific implementations selected at compile time via `cfg` attributes:

```rust
// Core PAL traits

pub trait FileSystemWatcher: Send + Sync {
    async fn watch(&self, paths: &[PathBuf], recursive: bool) -> Result<()>;
    async fn unwatch(&self, paths: &[PathBuf]) -> Result<()>;
    fn events(&self) -> &mpsc::Receiver<FsEvent>;
}

pub trait LogSource: Send + Sync {
    async fn open(&mut self, config: &LogSourceConfig) -> Result<()>;
    async fn read_new(&mut self) -> Result<Vec<LogEntry>>;
    async fn seek_to_end(&mut self) -> Result<()>;
}

pub trait SystemInfo: Send + Sync {
    fn os_info(&self) -> OsInfo;
    fn hardware_info(&self) -> HardwareInfo;
    fn network_interfaces(&self) -> Vec<NetworkInterface>;
    fn installed_packages(&self) -> Vec<Package>;
    fn running_processes(&self) -> Vec<Process>;
}

pub trait PowerStatus: Send + Sync {
    fn is_on_battery(&self) -> bool;
    fn battery_percentage(&self) -> Option<u8>;
    fn is_user_idle(&self) -> bool;
    fn idle_duration(&self) -> Duration;
}

pub trait ServiceManager: Send + Sync {
    fn install(&self) -> Result<()>;
    fn uninstall(&self) -> Result<()>;
    fn start(&self) -> Result<()>;
    fn stop(&self) -> Result<()>;
    fn status(&self) -> ServiceStatus;
}
```

### 6.2 Platform Implementations

| PAL Trait | Linux | macOS | Windows |
|---|---|---|---|
| `FileSystemWatcher` | `fanotify` (root) / `inotify` (user) | `FSEvents` framework | `ReadDirectoryChangesW` |
| `LogSource` (system) | `sd_journal` (systemd) | `OSLog` streaming | `EvtSubscribe` (Event Log) |
| `LogSource` (file) | `inotify` + read | `kqueue` + read | `ReadDirectoryChangesW` + read |
| `SystemInfo` | `/proc`, `/sys`, `uname`, dpkg/rpm | `sysctl`, `IOKit`, `system_profiler` | WMI, Registry, `GetSystemInfo` |
| `PowerStatus` | `/sys/class/power_supply`, D-Bus `UPower` | `IOPSCopyPowerSourcesInfo` | `GetSystemPowerStatus` |
| `ServiceManager` | systemd unit file | `launchd` plist | Windows Service API (SCM) |
| `FirewallControl` | `iptables`/`nftables` | `pfctl` | Windows Firewall API (COM) |

### 6.3 Compile-Time Feature Gates

```toml
# Cargo.toml feature configuration
[features]
default = ["fim", "logcollector", "sca", "inventory", "active-response"]

# Core modules (can be individually disabled)
fim = []
logcollector = []
sca = []
inventory = []
active-response = []
rootcheck = []

# Platform-specific features (auto-detected)
linux-ebpf = []          # eBPF-based FIM (requires kernel 5.8+)
linux-fanotify = []      # fanotify FIM (requires CAP_SYS_ADMIN)
linux-journal = ["dep:libsystemd"]
macos-endpoint-security = []  # macOS Endpoint Security Framework
windows-etw = []         # Event Tracing for Windows

# Optional capabilities
self-update = ["dep:reqwest"]
tls-native = ["dep:native-tls"]  # Use OS TLS stack
tls-rustls = ["dep:rustls"]      # Use rustls (default, smaller)
```

---

## 7. Technology Stack & Justification

### 7.1 Primary Language: Rust

| Criterion | C (current) | C++ (current shared_modules) | Go | Rust (proposed) |
|---|---|---|---|---|
| Memory safety | Manual | Manual (RAII helps) | GC | Compile-time ownership |
| Runtime overhead | None | Minimal | GC pauses, goroutine stack | None |
| Cross-compilation | Complex (MinGW) | Complex | Easy | Easy (rustup target) |
| Async I/O | Manual (select/epoll) | Manual / Boost.Asio | Built-in (goroutines) | tokio (mature, production-proven) |
| Binary size (hello world) | ~15 KB | ~25 KB | ~2 MB (static) | ~300 KB (stripped, static) |
| Dependency management | Manual/CMake | Manual/CMake | go mod | Cargo (excellent) |
| FFI for OS APIs | Native | Native | cgo (overhead) | Direct (no overhead) |
| Security | Buffer overflows common | Use-after-free possible | Safe | Memory safe by default |

**Why Rust over Go:** Go's garbage collector introduces unpredictable latency spikes (1-3 ms) and its minimum runtime memory (~5 MB) is too high for our targets. Rust's zero-cost abstractions and lack of GC make it possible to achieve truly minimal resource usage while maintaining safety.

**Why Rust over C/C++ (rewriting):** The current C codebase has 70+ header files in shared/include with complex manual memory management. A Rust rewrite eliminates entire classes of security bugs (buffer overflows, use-after-free, data races) that are critical in a security agent running with elevated privileges.

### 7.2 Key Dependencies

| Crate | Purpose | Size Impact | Justification |
|---|---|---|---|
| `tokio` (rt, io, net, time, process) | Async runtime | ~500 KB | Industry standard, single-threaded mode available |
| `rustls` + `ring` | TLS 1.3 + crypto | ~400 KB | No OpenSSL dependency, smaller, auditable |
| `serde` + `serde_json` | Serialization | ~200 KB | Zero-copy deserialization, compile-time code generation |
| `notify` | Cross-platform fs watching | ~50 KB | Wraps inotify/FSEvents/ReadDirectoryChanges |
| `rusqlite` (bundled) | SQLite for state storage | ~800 KB | Mature, WAL mode, memory-mapped I/O |
| `tracing` | Structured logging | ~100 KB | Zero-overhead when disabled, async-aware |
| `windows-rs` | Windows API bindings | Build-time | Official Microsoft crate, zero-overhead |
| `nix` | Unix API bindings | ~150 KB | Safe wrappers for Linux/macOS syscalls |
| `simd-json` | High-perf JSON parsing | ~100 KB | 2-4x faster than serde_json for log parsing |

**Estimated binary size (stripped, release):** ~3.5 MB (single static binary, all modules enabled)

### 7.3 Build & Distribution

```
Build Targets:
  x86_64-unknown-linux-gnu       # Linux x86_64
  aarch64-unknown-linux-gnu      # Linux ARM64
  x86_64-apple-darwin            # macOS Intel
  aarch64-apple-darwin           # macOS Apple Silicon
  x86_64-pc-windows-msvc         # Windows x86_64

Distribution:
  Linux:   .deb, .rpm, static binary, systemd unit
  macOS:   .pkg installer, launchd plist
  Windows: .msi installer, Windows Service
```

---

## 8. Communication Protocol

SDA ships two independent communication paths. The **SN360 Native Protocol** (§ 8.1) is the default for all new deployments and talks to the SN360 Control Plane. A **Legacy SIEM Protocol Adapter** (§ 8.2) is a separately compiled, feature-gated interoperability layer (Cargo feature `legacy-siem`) for sites that still need to feed events into a legacy SIEM manager.

### 8.1 SN360 Native Protocol (default)

The native protocol is used when SDA talks to the SN360 Agent Gateway / Control Plane. It is the only protocol enabled in the default proprietary distribution.

- **TLS 1.3 transport** (via `rustls`), with certificate-chain validation against a configured trust anchor and optional SHA-256 leaf-certificate pinning.
- **HTTP/2** with ALPN `h2` for multiplexed, bidirectional communication between agent and gateway.
- **MessagePack** event serialization (50-70 % smaller than JSON on inventory-heavy payloads).
- **mTLS-based enrollment** against the SN360 Agent Gateway (replaces the legacy authd enrollment flow).
- **Batched events** with delta compression.
- **Server-sent configuration and rule updates** via HTTP/2 streams (push model instead of polling).

### 8.2 Legacy SIEM Protocol Adapter (optional, feature-gated)

For sites that still need to deliver events to a legacy SIEM manager, SDA provides an optional **Legacy SIEM Protocol Adapter** that implements a publicly documented wire format. The adapter is compiled in only when the `legacy-siem` Cargo feature is enabled and is **off by default** in the proprietary distribution. It is purely an interoperability layer and is not a derivative work of any third-party agent:

```
+---+---+---+---+---+---+---+---+---+---+---+---+
| Agent ID | : | Message Type | : | Payload     |
+---+---+---+---+---+---+---+---+---+---+---+---+
              |
              v
    AES-256-CBC or Blowfish-CBC (pre-shared key)
              |
              v
    Compressed (zlib, optional)
              |
              v
    TCP or UDP transport to legacy agent-events port (1514)
```

The adapter is a clean-room implementation of a publicly documented wire protocol (analogous to implementing SMTP, SNMP, or SMB from a published specification). It shares no source code, types, or data structures with any third-party SIEM agent; it exists solely to let SDA emit events into an existing SIEM analysis pipeline during migration to the SN360 Control Plane.

### 8.3 Connection Management

```rust
// Connection strategy pseudocode
struct ConnectionManager {
    primary_server: ServerEndpoint,
    failover_servers: Vec<ServerEndpoint>,
    reconnect_strategy: ExponentialBackoff {
        initial: Duration::from_secs(1),
        max: Duration::from_secs(60),
        multiplier: 2.0,
        jitter: 0.1,
    },
    keepalive_interval: Duration::from_secs(600),
    batch_window: Duration::from_secs(5),
    max_batch_size: 100,
}
```

---

## 9. Resource Management Strategy

### 9.1 Memory Management

| Component | Budget | Strategy |
|---|---|---|
| Agent core + event bus | 2 MB | Static allocation, bounded channels |
| FIM state database | 2-4 MB | Memory-mapped SQLite, 4 MB mmap window |
| Log collector buffers | 1-2 MB | Ring buffer, bounded, backpressure |
| SCA policy cache | 0.5 MB | Loaded on demand, freed after scan |
| Inventory cache | 1-2 MB | Cached, refreshed on change events |
| Network buffers | 0.5 MB | Reusable buffer pool |
| **Total idle** | **~8-12 MB** | |

**Key techniques:**
- `jemalloc` replaced by system allocator (smaller, adequate for low-alloc workload)
- Zero-copy message passing between modules via `bytes::Bytes`
- String interning for repeated paths/log sources
- Bounded collections everywhere (no unbounded growth)

### 9.2 CPU Management

```
Priority Scheduling:

  IDLE TASKS (run only when system CPU < 20%):
    - FIM baseline scan
    - SCA policy evaluation
    - Rootkit detection scans
    - Full inventory refresh

  NORMAL TASKS (always run, rate-limited):
    - Real-time FIM event processing
    - Log collection (event-driven)
    - Server communication

  CRITICAL TASKS (never deferred):
    - Active response execution
    - Agent keepalive
    - Configuration updates
```

**CPU throttling implementation:**
```rust
async fn throttled_scan(scanner: &mut Scanner, budget: &ResourceBudget) {
    for entry in scanner.next_batch(100) {
        process_entry(entry).await;

        // Yield to other tasks
        tokio::task::yield_now().await;

        // Check if we should pause
        if budget.cpu_usage() > 0.03 {  // 3% threshold
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
```

### 9.3 Disk I/O Management

- **WAL mode SQLite** -- writes don't block reads, auto-checkpointing
- **Buffered, batched writes** -- accumulate events and write in batches
- **Log rotation awareness** -- detect rotated files, don't re-read
- **No continuous disk activity at idle** -- state persisted on events, not on timer

### 9.4 Battery & Power Awareness

```rust
enum PowerProfile {
    /// AC power, user active: normal operation
    Normal,
    /// AC power, user idle: run deferred scans
    IdleAC,
    /// Battery, user active: minimal scans, larger batches
    BatteryActive,
    /// Battery, user idle: reduced scans, extended intervals
    BatteryIdle,
    /// Critical battery (<10%): essential only
    CriticalBattery,
}

impl PowerProfile {
    fn fim_scan_rate(&self) -> f64 { /* multiplier */ }
    fn log_batch_interval(&self) -> Duration { /* ... */ }
    fn inventory_interval(&self) -> Duration { /* ... */ }
    fn sca_enabled(&self) -> bool { /* ... */ }
}
```

---

## 10. Security Architecture

### 10.1 Privilege Model

```
Linux:
  - Main process runs as unprivileged user (wazuh)
  - CAP_DAC_READ_SEARCH for FIM (read any file)
  - CAP_NET_ADMIN for active response (firewall)
  - fanotify requires CAP_SYS_ADMIN (optional, fallback to inotify)

macOS:
  - LaunchDaemon runs as root (required for Endpoint Security Framework)
  - Privilege separation via sandbox profiles where possible

Windows:
  - Windows Service runs as LOCAL SYSTEM (required for Event Log, Registry)
  - Active responses use constrained process tokens
```

### 10.2 Secure Communication

- **Key storage:** Platform keychain integration (Linux: kernel keyring, macOS: Keychain, Windows: DPAPI)
- **Certificate pinning:** Server certificate fingerprint cached and verified
- **Forward secrecy:** TLS 1.3 with ephemeral keys (in enhanced mode)
- **Anti-tampering:** Binary signature verification, config file integrity checks

### 10.3 Self-Protection

- **Binary signing** on all platforms (code signing certificates)
- **Config file permissions** enforced at startup (0640 on Unix, ACL on Windows)
- **Memory protection:** Stack canaries, ASLR, DEP (enabled by default in Rust)
- **Secure deletion** of temporary files and key material

---

## 11. Configuration & Deployment

### 11.1 Configuration Format

SDA uses YAML configuration (with backward-compatible XML config reader):

```yaml
# /etc/sn360-desktop-agent/config.yaml
agent:
  server:
    address: "sn360-gateway.example.com"
    port: 1514
    protocol: tcp  # "tcp" (default) | "udp" | "http2" (SN360 native, opt-in)
  enrollment:
    server: "sn360-gateway.example.com"
    port: 1515
    auto_enroll: true
  keepalive_interval: 600  # seconds

modules:
  fim:
    enabled: true
    directories:
      - path: /etc
        recursive: true
        realtime: true
      - path: /usr/bin
        recursive: false
        check_sha256: true
      - path: /home
        recursive: true
        realtime: true
        exclude:
          - "*.tmp"
          - ".cache/**"
    scan_interval: 43200  # 12h baseline scan (idle only)

  logcollector:
    enabled: true
    sources:
      - type: journald
        units: ["sshd", "sudo", "systemd-logind"]
      - type: file
        path: /var/log/auth.log
        format: syslog

  sca:
    enabled: true
    policies:
      - cis_ubuntu_22_04.yaml
    scan_on_idle: true

  inventory:
    enabled: true
    collect:
      - packages
      - network
      - hardware
      - os
    interval: 3600  # 1h

  active_response:
    enabled: true
    actions:
      - block_ip
      - kill_process

resource_limits:
  max_cpu_percent: 3
  max_memory_mb: 50
  battery_mode: adaptive  # adaptive | minimal | normal
  idle_detection: true
```

### 11.2 Deployment Automation

```
Packaging:
  - Linux: .deb (apt), .rpm (yum/dnf), static binary tarball
  - macOS: .pkg with installer scripts, Homebrew cask
  - Windows: .msi with WiX, winget manifest

Enrollment:
  - Automatic enrollment with pre-shared key or certificate
  - Group-based auto-assignment via agent labels
  - Native enrollment against the SN360 Agent Gateway (mTLS)
  - Optional legacy SIEM enrollment endpoint (port 1515) when the legacy adapter is enabled

Management:
  - Server-pushed configuration updates
  - Remote module enable/disable
  - Centralized policy deployment
```

---

## 12. Implementation Roadmap

### Phase 1: Foundation (Weeks 1-4)

| Task | Description | Est. Effort |
|---|---|---|
| **1.1** | Project scaffolding: Cargo workspace, CI/CD pipeline, cross-compilation targets | 3 days |
| **1.2** | Platform Abstraction Layer: `FileSystemWatcher` trait + Linux inotify impl | 5 days |
| **1.3** | Platform Abstraction Layer: macOS FSEvents + Windows ReadDirectoryChangesW | 5 days |
| **1.4** | Agent core: lifecycle management, signal handling, config engine (YAML + XML compat) | 5 days |
| **1.5** | Event bus: async channel-based inter-module communication | 3 days |
| **1.6** | Communication layer: SN360 native protocol (TLS 1.3 + HTTP/2 + MessagePack) and legacy SIEM protocol adapter (feature-gated) | 5 days |
| **1.7** | Enrollment: agent enrollment against the SN360 Agent Gateway (native, mTLS) and against a legacy SIEM enrollment endpoint (feature-gated adapter) | 3 days |

**Milestone:** Agent can start, enroll against the SN360 Agent Gateway (or a legacy SIEM enrollment endpoint when the legacy adapter is enabled), send keepalives, and receive messages.

### Phase 2: Core Modules (Weeks 5-10)

| Task | Description | Est. Effort |
|---|---|---|
| **2.1** | FIM module: real-time watcher (all platforms) + state database | 8 days |
| **2.2** | FIM module: baseline scanner with idle-aware scheduling | 4 days |
| **2.3** | FIM module: change event formatting (SN360 native schema; legacy adapter reuses the syscheck-compatible wire format) | 3 days |
| **2.4** | Log collector: file-based collection with seek tracking | 5 days |
| **2.5** | Log collector: systemd journal (Linux) | 3 days |
| **2.6** | Log collector: Windows Event Log (EvtSubscribe) | 4 days |
| **2.7** | Log collector: macOS Unified Log (OSLog) | 3 days |
| **2.8** | Inventory module: packages, network, hardware, OS info (all platforms) | 8 days |
| **2.9** | Active response module: command execution with sandboxing | 4 days |

**Milestone:** All core modules operational. Agent can collect FIM events, logs, and inventory and forward them to the SN360 Control Plane (or, when the legacy adapter is enabled, to a legacy SIEM manager).

### Phase 3: Optimization & Polish (Weeks 11-14)

| Task | Description | Est. Effort |
|---|---|---|
| **3.1** | Resource budgeting system: CPU/RAM monitoring and adaptive throttling | 5 days |
| **3.2** | Power awareness: battery detection, idle detection, profile switching | 4 days |
| **3.3** | SCA module: policy engine with YAML policy support | 5 days |
| **3.4** | Rootcheck module: basic rootkit detection checks | 3 days |
| **3.5** | Performance benchmarking: memory profiling, CPU profiling, I/O profiling | 3 days |
| **3.6** | Binary size optimization: LTO, panic=abort, strip, feature gating | 2 days |

**Milestone:** Agent meets all resource targets. Benchmarked and profiled.

### Phase 4: Edge Detection, Software Inventory & Tenant Rule Distribution (Weeks 15-22)

| Task | Description | Est. Effort |
|---|---|---|
| **4.1** | Local Detection Engine: rule store format, MessagePack schema, mmap loader | 4 days |
| **4.2** | LDE: Aho-Corasick pattern matcher + IOC bloom filter evaluator | 5 days |
| **4.3** | LDE: Behavioral rule state machine (JSON DSL → evaluator) | 5 days |
| **4.4** | LDE: Local Response Dispatcher (block IP, kill process, quarantine) | 4 days |
| **4.5** | LDE: YARA scanner integration (feature-gated, yara-rust) | 4 days |
| **4.6** | LDE: Offline detection queue + server sync on reconnect | 3 days |
| **4.7** | Enhanced Inventory: running software monitor (all platforms) | 5 days |
| **4.8** | Enhanced Inventory: browser extension inventory (Chrome/Firefox/Edge/Safari) | 3 days |
| **4.9** | Enhanced Inventory: SBOM generator (CycloneDX, on-demand) | 4 days |
| **4.10** | TRDS microservice: rule CRUD API, compiler, delta distribution | 8 days |
| **4.11** | IOCFS microservice: feed ingestion, normalization, bloom filter compilation | 6 days |
| **4.12** | SIS microservice: inventory ingestion, CVE matching, dashboard API | 8 days |
| **4.13** | Agent Gateway: mTLS termination, tenant routing, rate limiting | 5 days |
| **4.14** | Integration: agent ↔ TRDS rule pull, hot-reload, version tracking | 4 days |

**Milestone:** Agent performs local detection with tenant-specific rules, collects comprehensive software inventory, and companion microservices manage rule distribution and vulnerability analysis.

### Phase 5: Platform Hardening (Weeks 23-26)

| Task | Description | Est. Effort |
|---|---|---|
| **5.1** | Windows service integration: SCM, installer (.msi), Event Log integration | 5 days |
| **5.2** | macOS launchd integration: plist, .pkg installer, Endpoint Security entitlements | 5 days |
| **5.3** | Linux packaging: .deb, .rpm, systemd unit, capability setup | 4 days |
| **5.4** | Self-update mechanism: download, verify, replace, rollback | 5 days |
| **5.5** | Security hardening: binary signing, config protection, anti-tampering | 4 days |
| **5.6** | Enhanced protocol: TLS 1.3, MessagePack, HTTP/2 (opt-in) | 5 days |

**Milestone:** Production-ready agent with installers for all platforms.

### Phase 6: Testing & Release (Weeks 27-30)

| Task | Description | Est. Effort |
|---|---|---|
| **6.1** | Integration testing: agent ↔ SN360 Agent Gateway (native protocol) and legacy SIEM manager interoperability (legacy adapter) | 5 days |
| **6.2** | Platform testing: Windows 10/11, macOS 12-15, Ubuntu/Fedora/Arch | 5 days |
| **6.3** | Performance regression testing: automated benchmarks in CI | 3 days |
| **6.4** | Security audit: fuzzing (cargo-fuzz), dependency audit (cargo-audit) | 4 days |
| **6.5** | Documentation: user guide, admin guide, architecture docs | 3 days |
| **6.6** | Beta release and feedback cycle | 5 days |

**Milestone:** v1.0 release candidate.

---

## 13. Phase 4 Detail: Edge Detection, Software Inventory & Tenant Rule Distribution

> **Canonical reference:** For the *current* state of these components and
> their server-side counterparts, see [`docs/integration.md`](./docs/integration.md)
> and the platform repo's
> [`docs/NON_WAZUH_COMPONENTS.md`](https://github.com/kennguy3n/sn360-security-platform/blob/main/docs/NON_WAZUH_COMPONENTS.md).
> This section preserves the original design rationale; behaviour
> described here may have evolved since the proposal was written.

This section expands on Phase 4 of the implementation roadmap, detailing the Local Detection Engine, Enhanced Software Inventory module, and the companion microservices that support them.

### 13.1 Local Detection Engine (LDE) Module

The LDE enables the agent to evaluate detection rules locally — without a round-trip to the server — for low-latency threat response at the edge. It consumes events from the Event Bus, matches them against a tenant-specific rule store, and dispatches local responses when a rule fires.

```
Local Detection Engine (LDE)
  |
  +-- Rule Store (mmap, read-only)
  |     - MessagePack-encoded rule bundles
  |     - Versioned: pulled from TRDS, hot-reloaded on update
  |     - Sections: IOC lists, behavioral rules, YARA rule refs
  |
  +-- Micro Rule Evaluator
  |     +-- Aho-Corasick Pattern Matcher
  |     |     - Multi-pattern string search across event fields
  |     |     - Used for IOC domain/hash/IP matching
  |     |
  |     +-- IOC Bloom Filter Evaluator
  |     |     - Pre-compiled bloom filters from IOCFS
  |     |     - O(1) negative lookups for hashes, IPs, domains
  |     |
  |     +-- Behavioral Rule State Machine
  |           - JSON DSL rules compiled to state machines
  |           - Tracks sequences (e.g., "process A spawns B within 5 min")
  |           - Sliding-window counters for threshold rules
  |
  +-- Local Response Dispatcher
  |     - block_ip: platform-native firewall rule insertion
  |     - kill_process: terminate matching PID
  |     - quarantine: move file to quarantine directory + strip execute bits
  |     - notify: emit high-priority alert to Event Bus → server
  |
  +-- YARA Scanner (feature-gated: `yara`)
  |     - On-demand file scanning triggered by FIM events
  |     - Uses yara-rust crate (links libyara)
  |     - Rule files pulled alongside detection rules from TRDS
  |     - Scans rate-limited to 1 file/sec to stay within CPU budget
  |
  +-- Telemetry Forwarder
  |     - All detection events (hit or miss stats) batched to server
  |     - Offline detection queue: SQLite WAL table
  |     - Syncs queued detections on server reconnect
  |
  +-- Offline Detection Queue
        - SQLite WAL-mode table for detections generated while offline
        - Bounded: max 10,000 entries, FIFO eviction
        - Synced to server on reconnect via batched upload
```

**LDE Resource Budget:**

| Component | Memory | CPU | Notes |
|---|---|---|---|
| Rule store (mmap) | 1-2 MB | — | Memory-mapped, OS paging handles eviction |
| Aho-Corasick automaton | 0.5 MB | <0.5% per event batch | Built once per rule reload |
| Bloom filters | 0.25 MB | O(1) per lookup | ~2 MB on disk, partial mmap |
| Behavioral state machines | 0.5 MB | <0.1% | Sliding windows bounded by rule count |
| YARA scanner (optional) | 2 MB | <2% during scan | Only loaded when `yara` feature enabled |
| Offline queue (SQLite) | 0.25 MB | Negligible | Shared WAL with agent state DB |
| **Total (without YARA)** | **~2.5 MB** | **<1%** | |
| **Total (with YARA)** | **~4.5 MB** | **<3% during scan** | |

### 13.2 Enhanced Software Inventory Module

The Enhanced Software Inventory module extends the existing Inventory module with running-software monitoring, browser extension enumeration, and on-demand SBOM generation.

```
Enhanced Software Inventory Module
  |
  +-- Installed Software Tracker (existing, enhanced)
  |     - Package DB watchers (dpkg/rpm/Homebrew/MSI/AppX)
  |     - Event-driven: re-enumerates only on DB change
  |
  +-- Running Software Monitor
  |     Linux:   /proc polling (idle-only, 60s interval) + netlink proc events
  |     macOS:   NSWorkspace notifications + kqueue EVFILT_PROC
  |     Windows: WMI Win32_Process event subscription + ETW process events
  |     Output:  { name, version, pid, path, sha256, started_at, publisher }
  |
  +-- Browser Extension Inventory
  |     Chrome:   ~/.config/google-chrome/*/Extensions/*/manifest.json
  |     Firefox:  ~/.mozilla/firefox/*/extensions.json
  |     Edge:     ~/.config/microsoft-edge/*/Extensions/*/manifest.json
  |     Safari:   ~/Library/Safari/Extensions/ (macOS)
  |     Output:  { browser, ext_id, name, version, permissions[], store_url }
  |     Trigger: FSEvents / inotify on profile directories, plus scheduled (4h)
  |
  +-- SBOM Generator (on-demand)
  |     - Generates CycloneDX 1.5 JSON BOM
  |     - Sources: installed packages + running software + browser extensions
  |     - Triggered by server request or local schedule
  |     - Output written to local file + forwarded to SIS
  |
  +-- Normalized Output Format
        - All inventory sources emit unified JSON schema:
          { source: "installed"|"running"|"browser_ext",
            name, version, publisher, platform_id,
            sha256?, install_path?, detected_at }
        - Batched to server every inventory interval (default: 1h)
        - Delta reporting: only changed entries sent after initial baseline
```

**Enhanced Inventory Resource Budget:**

| Component | Memory | CPU | Notes |
|---|---|---|---|
| Running software monitor | 0.5 MB | <0.1% idle | Event-driven where possible |
| Browser extension cache | 0.25 MB | Negligible | Re-scanned on FS change events |
| SBOM generator | 1 MB (transient) | <2% during generation | On-demand only, freed after output |
| **Total additional** | **~0.75 MB steady** | **<0.2%** | |

### 13.3 Companion Microservices

The Phase 4 companion microservices run server-side within the SN360 Control Plane. They manage rule lifecycle, IOC feeds, and software inventory analysis.

```
+-----------------------------------------------------------------------+
|                        SN360 Control Plane                             |
+-----------------------------------------------------------------------+
|                                                                        |
|  +------------------+  +------------------+  +------------------+      |
|  | Tenant Rule      |  | IOC Feed         |  | Software         |      |
|  | Distribution     |  | Aggregator       |  | Inventory        |      |
|  | Service (TRDS)   |  | Service (IOCFS)  |  | Service (SIS)    |      |
|  +--------+---------+  +--------+---------+  +--------+---------+      |
|           |                      |                      |              |
|  +--------v----------------------v----------------------v---------+    |
|  |                       Message Queue                             |   |
|  |           (rule updates, IOC deltas, inventory batches)         |   |
|  +----------------------------+------------------------------------+   |
|                               |                                        |
|  +----------------------------v------------------------------------+   |
|  |                      Agent Gateway                               |  |
|  |  - mTLS termination          - Tenant routing                    |  |
|  |  - Rate limiting              - Protocol translation             |  |
|  +----------------------------+------------------------------------+   |
|                               |                                        |
+-----------------------------------------------------------------------+
                                |
                    +-----------v-----------+
                    |   SDA Agents (edge)    |
                    +-----------------------+
```

#### 13.3.1 Tenant Rule Distribution Service (TRDS)

The TRDS manages the lifecycle of detection rules across tenants, compiles them into agent-consumable bundles, and distributes delta updates.

**API Endpoints:**

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/tenants/{tid}/rules` | Create a new rule |
| GET | `/api/v1/tenants/{tid}/rules` | List rules (filterable by type, status) |
| PUT | `/api/v1/tenants/{tid}/rules/{rid}` | Update a rule |
| DELETE | `/api/v1/tenants/{tid}/rules/{rid}` | Soft-delete a rule |
| POST | `/api/v1/tenants/{tid}/rules/compile` | Trigger bundle compilation |
| GET | `/api/v1/tenants/{tid}/bundles/latest` | Get latest compiled bundle metadata |
| GET | `/api/v1/tenants/{tid}/bundles/{version}/delta?from={prev}` | Get delta update |

**Rule Types:**

| Type | Format | Agent Evaluation |
|---|---|---|
| IOC list | CSV/STIX → bloom filter + Aho-Corasick | Pattern match on event fields |
| Behavioral | JSON DSL (sequence, threshold, boolean) | State machine evaluation |
| YARA | `.yar` files | File content scanning (feature-gated) |
| Exclusion | Allowlist entries (hash, path, signer) | Skip matching entries |

**Workflow:**

1. Analyst creates/updates rules via API or dashboard
2. TRDS validates rule syntax and compiles to agent-native format
3. Compiled bundle is versioned and stored (S3/MinIO)
4. Delta diff computed against previous bundle version
5. Agents poll for updates (or receive push notification via gateway)
6. Agent downloads delta, applies to local rule store, hot-reloads LDE

**Storage:** PostgreSQL (rule metadata, tenant config) + S3-compatible object store (compiled bundles).

**Footprint:** 2 vCPU, 2 GB RAM per instance. Horizontally scalable behind load balancer.

#### 13.3.2 IOC Feed Aggregator Service (IOCFS)

The IOCFS ingests threat intelligence feeds, normalizes IOCs, and compiles them into optimized data structures for agent consumption.

**Sources:**

| Feed | Format | Refresh Interval |
|---|---|---|
| MISP (self-hosted or community) | MISP JSON | 15 min |
| Abuse.ch (URLhaus, MalBazaar, ThreatFox) | CSV | 1 hour |
| AlienVault OTX | STIX/TAXII 2.1 | 1 hour |
| Custom tenant feeds | CSV/STIX upload | On upload |

**Processing Pipeline:**

1. Ingest: pull/receive IOCs from configured feeds
2. Normalize: map to unified schema `{ type, value, confidence, source, expires_at }`
3. Deduplicate: merge across feeds, keep highest confidence
4. Compile:
   - Bloom filters (one per IOC type: hash, domain, IP, URL) — target FPR: 0.01%
   - Aho-Corasick automaton for string-matchable IOCs
5. Package: MessagePack bundle with version metadata
6. Publish: push to TRDS for inclusion in tenant rule bundles

**Output Size Targets:**

| IOC Type | Typical Count | Bloom Filter Size | Aho-Corasick Size |
|---|---|---|---|
| File hashes (SHA-256) | 500K | ~1.2 MB | N/A (bloom only) |
| Domains | 100K | ~240 KB | ~400 KB |
| IPv4 addresses | 50K | ~120 KB | N/A (bloom only) |
| URLs | 200K | ~480 KB | ~800 KB |
| **Total** | **~850K IOCs** | **~2 MB** | **~1.2 MB** |

**Footprint:** 2 vCPU, 4 GB RAM (bloom filter compilation is memory-intensive). Single instance with HA failover.

#### 13.3.3 Software Inventory Service (SIS)

The SIS ingests software inventory from agents, matches against CVE databases, and provides dashboard APIs for vulnerability visibility.

**Ingest:**

- Receives normalized inventory batches from agents via Agent Gateway
- Stores per-agent inventory snapshots in PostgreSQL (partitioned by tenant)
- Computes diffs: tracks install/uninstall/upgrade events over time

**CVE Matching:**

- NVD CPE dictionary + known exploited vulnerabilities (CISA KEV)
- CPE matching: software name + version → CVE lookup
- Refresh: NVD feed pulled every 2 hours
- Results stored per-agent: `{ cve_id, severity, software_name, version, fix_available }`

**Dashboard Integration:**

| Endpoint | Description |
|---|---|
| `GET /api/v1/tenants/{tid}/inventory` | Aggregated software inventory |
| `GET /api/v1/tenants/{tid}/inventory/{agent_id}` | Per-agent inventory |
| `GET /api/v1/tenants/{tid}/vulnerabilities` | All matched CVEs |
| `GET /api/v1/tenants/{tid}/vulnerabilities/critical` | Critical/high severity CVEs |
| `GET /api/v1/tenants/{tid}/sbom/{agent_id}` | Download agent SBOM (CycloneDX) |

**Storage:** PostgreSQL (inventory + CVE matches, partitioned by tenant). NVD mirror in local cache (~2 GB).

**Footprint:** 2 vCPU, 4 GB RAM per instance. Horizontally scalable for large deployments.

### 13.4 Agent Gateway

The Agent Gateway is the single entry point for all agent-to-server communication in the SN360 control plane.

**Responsibilities:**

- **mTLS termination:** Validates agent client certificates, extracts tenant ID from cert subject
- **Tenant routing:** Routes requests to the correct tenant-scoped backend services
- **Rate limiting:** Per-agent and per-tenant rate limits to prevent abuse
- **Protocol translation:** Accepts agent binary protocol, translates to internal gRPC/HTTP
- **Connection pooling:** Maintains persistent connections to backend services

**Configuration:**

| Parameter | Default | Description |
|---|---|---|
| `listen_address` | `0.0.0.0:8443` | mTLS listener |
| `max_connections` | 50,000 | Per-instance connection limit |
| `rate_limit_per_agent` | 100 req/min | Per-agent request rate limit |
| `rate_limit_per_tenant` | 10,000 req/min | Per-tenant aggregate limit |
| `backend_pool_size` | 64 | Connection pool to each backend service |

**Footprint:** 2 vCPU, 1 GB RAM per instance. Horizontally scalable behind L4 load balancer.

### 13.5 Updated Resource Budget

With the LDE and Enhanced Inventory modules, the SDA memory projection is updated:

```
SDA (projected, with Phase 4 modules):
  RSS: ~15 MB (without YARA), ~17 MB (with YARA)
    - Agent core + runtime:       2.0 MB
    - SQLite FIM DB (mmap):       3.0 MB
    - Log collector buffers:      1.0 MB
    - Inventory cache:            1.0 MB
    - Enhanced inventory:         0.75 MB  (running sw + browser ext)
    - Network/TLS buffers:        1.0 MB
    - SCA policy cache:           0.5 MB
    - LDE rule store (mmap):     1.5 MB
    - LDE Aho-Corasick + bloom:  0.75 MB
    - LDE behavioral state:      0.5 MB
    - LDE offline queue:         0.25 MB
    - Stack (2-3 threads):       1.5 MB
    - Other:                     1.25 MB
    - YARA scanner (optional):  +2.0 MB
```

### 13.6 Updated Configuration

The following sections are added to `config.yaml` for the new Phase 4 modules:

```yaml
modules:
  # ... existing modules ...

  local_detection:
    enabled: true
    rule_pull_interval: 300      # seconds, poll TRDS for rule updates
    offline_queue_max: 10000     # max queued detections while offline
    response_actions:
      block_ip: true
      kill_process: true
      quarantine: true
    yara:
      enabled: false             # feature-gated, requires 'yara' build feature
      scan_rate_limit: 1         # files per second
      max_file_size_mb: 50       # skip files larger than this
    bloom_filter:
      false_positive_rate: 0.01
    behavioral:
      max_window_sec: 300        # max sliding window for sequence rules
      max_tracked_entities: 5000 # max concurrent entity state machines

  enhanced_inventory:
    enabled: true
    running_software:
      enabled: true
      interval: 60               # seconds between running-sw snapshots
    browser_extensions:
      enabled: true
      browsers:
        - chrome
        - firefox
        - edge
        - safari
      interval: 14400            # seconds (4h) scheduled re-scan
    sbom:
      enabled: true
      format: cyclonedx          # cyclonedx | spdx (future)
      on_demand: true            # allow server-triggered generation
      scheduled_interval: 86400  # seconds (24h), 0 to disable scheduled
```

### 13.7 New Crate Structure

Two new crates are added to the workspace:

- **`sda-local-detection`** — Local Detection Engine: rule store, pattern matching, behavioral evaluation, response dispatch, YARA integration (feature-gated).
- **`sda-enhanced-inventory`** — Enhanced Software Inventory: running software monitor, browser extension inventory, SBOM generator.

**New workspace dependencies:**

| Crate | Version | Purpose |
|---|---|---|
| `aho-corasick` | 1 | Multi-pattern string matching for IOC detection |
| `bloomfilter` | 1 | Bloom filter data structure for O(1) IOC lookups |
| `yara` | 0.28 (optional) | YARA rule scanning via yara-rust bindings |
| `cyclonedx-bom` | 0.7 | CycloneDX SBOM generation |

---

## 14. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Legacy SIEM protocol changes | Medium | Medium | Legacy adapter is an optional, feature-gated interoperability layer; behavior is decoupled from the SN360 native protocol and SN360 Control Plane |
| macOS Endpoint Security Framework restrictions | Medium | Medium | Fallback to FSEvents; apply for Apple developer entitlements early |
| Windows SmartScreen / AV false positives | Medium | Medium | EV code signing certificate; submit to Microsoft for whitelisting |
| Rust async ecosystem maturity gaps | Low | Medium | tokio is battle-tested; fallback to synchronous I/O for edge cases |
| Performance regression in specific modules | Medium | Low | Automated benchmarks in CI; per-module resource budgets |
| SQLite performance under high event rates | Low | Medium | WAL mode + batched writes; consider redb as alternative |
| Binary size exceeding target | Low | Low | Feature gates, LTO, `panic=abort`, `opt-level=z` for size |

---

## 15. Local SIEM Manager Test Environment

This section describes how to stand up a **local SIEM manager** for development and integration testing of the SDA legacy adapter (see § 8.2). The recommended approach uses a publicly available Docker image of a reference SIEM manager stack. It is the fastest way to exercise the legacy adapter end-to-end on a single machine.

### 15.1 Prerequisites

- **Docker Engine 24+** and **Docker Compose v2**
- At least **4 GB RAM** available for the server stack
- The following ports must be available on the host:
  | Port | Service |
  |---|---|
  | 1514 | Agent communication (events) |
  | 1515 | Agent enrollment (authd) |
  | 443 | Wazuh dashboard (web UI) |
  | 55000 | Wazuh manager API |

### 15.2 Download & Start the Reference SIEM Manager (Docker)

```bash
# Clone the publicly available reference SIEM manager Docker deployment
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.2
cd wazuh-docker/single-node

# Generate self-signed certificates for the stack
docker compose -f generate-indexer-certs.yml run --rm generator

# Start the reference SIEM manager stack (manager + indexer + dashboard)
docker compose up -d
```

> **Note:** The stack includes three containers — `wazuh.manager`, `wazuh.indexer`, and `wazuh.dashboard`. The manager is the component SDA's legacy adapter talks to. The adapter speaks a publicly documented wire protocol; using this public reference image is pure interoperability testing and does not make SDA a derivative work.
>
> **Default credentials:** `admin` / `SecretPassword` (for the dashboard at https://localhost:443).

### 15.3 Verify the Server Is Running

```bash
# Check all containers are healthy
docker compose ps

# Verify the manager API is responding
curl -k -u admin:SecretPassword https://localhost:55000/?pretty
```

### 15.4 Configure the Server for SDA Legacy Adapter Testing

**Retrieve the enrollment password** from the manager container:

```bash
docker exec -it single-node-wazuh.manager-1 cat /var/ossec/etc/authd.pass
```

**Optionally set a known enrollment password** (easier for automated testing):

```bash
docker exec -it single-node-wazuh.manager-1 bash -c \
  'echo "MyTestPassword" > /var/ossec/etc/authd.pass && /var/ossec/bin/wazuh-control restart'
```

**Ensure the manager is listening** on ports 1514 (events) and 1515 (enrollment):

```bash
docker exec -it single-node-wazuh.manager-1 \
  /var/ossec/bin/wazuh-control status
```

### 15.5 Enroll & Connect the SDA Agent (Legacy Adapter)

Create a test configuration file (`test-config.yaml`) pointing at the local Docker server:

```yaml
agent:
  server:
    address: "127.0.0.1"
    port: 1514
    protocol: tcp
  enrollment:
    server: "127.0.0.1"
    port: 1515
    password: "MyTestPassword"
    auto_enroll: true
  keepalive_interval: 30   # shorter for testing

modules:
  fim:
    enabled: true
    directories:
      - path: /tmp/sda-test-fim
        recursive: true
        realtime: true
    scan_interval: 60
  logcollector:
    enabled: true
    sources:
      - type: file
        path: /tmp/sda-test-logs/test.log
        format: syslog
  sca:
    enabled: true
    scan_on_idle: false     # run immediately for testing
  inventory:
    enabled: true
    interval: 60
  active_response:
    enabled: true
    actions:
      - block_ip

resource_limits:
  max_cpu_percent: 10
  max_memory_mb: 100
  battery_mode: normal
  idle_detection: false
```

Build and run the agent against the local server:

```bash
# Build the agent
cargo build

# Run with the test config
RUST_LOG=debug cargo run --bin sda-agent -- --config ./test-config.yaml
```

### 15.6 Functional Verification Checklist

Use the following checklist to verify each module works against the local test server via the legacy adapter:

| Module | Test Procedure | Expected Server-Side Result |
|---|---|---|
| **Enrollment** | Start the agent; it should auto-enroll | Agent appears in `docker exec single-node-wazuh.manager-1 /var/ossec/bin/manage_agents -l` |
| **Keepalive** | Agent stays running | Agent shows as "Active" in the Wazuh dashboard (Agents page) |
| **FIM** | `mkdir -p /tmp/sda-test-fim && echo "test" > /tmp/sda-test-fim/hello.txt` | FIM alert in Dashboard → Security Events with rule.groups containing "syscheck" |
| **Log Collection** | `mkdir -p /tmp/sda-test-logs && echo "Apr 17 12:00:00 localhost sshd[1234]: Failed password for root" >> /tmp/sda-test-logs/test.log` | Log event visible in Dashboard → Security Events |
| **Inventory** | Agent sends inventory on startup | Dashboard → Agents → (agent) → Inventory shows packages, network, OS info |
| **SCA** | Agent runs SCA policies | Dashboard → Agents → (agent) → SCA shows policy results |
| **Active Response** | Trigger from server: `/var/ossec/bin/agent_control -b 10.0.0.99 -f firewall-drop0 -u <AGENT_ID>` | Agent logs show active response execution |

### 15.7 Teardown

```bash
cd wazuh-docker/single-node
docker compose down -v   # -v removes volumes (all data)
```

### 15.8 Alternative: Bare-Metal / VM Server Install

For longer-lived test environments, you can install the reference SIEM manager directly on a Linux VM using its publicly documented quickstart installer. This installs the full stack (manager + indexer + dashboard) on a single machine. Refer to the vendor's own documentation for current installer URLs and supported versions.

---

## 16. Summary

The SN360 Desktop Agent (SDA) is a purpose-built security agent for user-facing devices, independently developed from scratch in Rust. By leveraging Rust's zero-cost abstractions, event-driven OS APIs, adaptive resource management, and a modular architecture that loads only what's needed, SDA achieves a dramatic reduction in memory usage and near-invisible CPU impact compared to general-purpose SIEM endpoint agents.

The 30-week implementation roadmap breaks the work into six clear phases, each with concrete milestones and deliverables. The default deployment path is the SN360 Control Plane over the SN360 native protocol; SDA additionally supports interoperability with common legacy SIEM managers through an optional, feature-gated protocol adapter.

**Key differentiators of SDA:**
1. **Event-driven everywhere** -- no polling loops for file/log monitoring
2. **Single-threaded async** -- minimal thread overhead
3. **Adaptive scheduling** -- respects user activity and power state
4. **90% code reduction** -- leveraging Rust ecosystem and removing server features
5. **Cross-platform from day one** -- unified PAL instead of scattered `#ifdef`s
6. **Memory-bounded** -- every component has a hard memory budget
7. **Edge detection** -- local rule evaluation and response without server dependency
8. **Comprehensive software inventory** -- running apps, browser extensions, SBOM generation with event-driven tracking

---

*This document is a living proposal. Implementation details may evolve as development progresses and real-world benchmarking data becomes available.*

> **Note on licensing posture:** SDA is an independently developed security agent written from scratch in Rust. No third-party SIEM agent source code was copied, translated, or used as a template. Protocol interoperability with external SIEM managers is achieved through clean-room implementation of publicly documented wire protocols. See [`docs/proprietary-licensing-rationale.md`](./docs/proprietary-licensing-rationale.md) for the detailed licensing statement.
