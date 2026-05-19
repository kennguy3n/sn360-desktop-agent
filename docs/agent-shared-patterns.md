# Shared Patterns Across SN360 Agents

The SN360 agent family (SDA Desktop, VM, K8s) implements common
patterns independently in each repository. This is a deliberate
design choice — each agent is an independent deployment unit with no
shared-crate dependency — but it means bug fixes in one agent may
need to be applied to the others.

This document catalogues the shared patterns so developers know
where to look when a fix in one repo needs to be ported.

## SHARED_PATTERNS_VERSION

**Current version: 2026.1**

When a shared pattern is updated in one repo, bump this version and
check the corresponding files in the other repos.

## Pattern catalogue

### Event bus

| Agent | Crate | Key file |
|-------|-------|----------|
| SDA | `sda-event-bus` | `crates/sda-event-bus/src/lib.rs` |
| VM | `vma-event-bus` | `crates/vma-event-bus/src/bus.rs` |
| K8s | `ska-core` | `crates/ska-core/src/event_bus.rs` |

All three implement a bounded broadcast channel for inter-module
communication. Key shared semantics:
- Back-pressure: slow consumers are lagged, not blocked
- Server-bound mpsc queue alongside the broadcast
- `publish_to_server` broadcasts locally even on server-queue failure

### Module lifecycle

| Agent | Crate | Key file |
|-------|-------|----------|
| SDA | `sda-core` | `crates/sda-core/src/module.rs` |
| VM | `vma-core` | `crates/vma-core/src/module.rs` |
| K8s | `ska-core` | `crates/ska-core/src/module.rs` |

All implement `Module` / `AgentModule` trait with `init()`,
`start()`, `stop()` lifecycle and a `ModuleManager` that drives
registration-order init/start and reverse-order stop.

### Platform abstraction layer (PAL)

| Agent | Crate | Key file |
|-------|-------|----------|
| SDA | `sda-pal` | `crates/sda-pal/src/lib.rs` |
| VM | `vma-pal` | `crates/vma-pal/src/lib.rs` |
| K8s | `ska-kpal` | `crates/ska-kpal/src/lib.rs` |

OS-specific implementations behind platform-agnostic traits. K8s
uses a Kubernetes-specific PAL (`kpal`) for container runtime
interfaces.

### Communications

| Agent | Crate | Key file |
|-------|-------|----------|
| SDA | `sda-comms` | `crates/sda-comms/src/lib.rs` |
| VM | `vma-comms` | `crates/vma-comms/src/lib.rs` |
| K8s | `ska-comms` | `crates/ska-comms/src/lib.rs` |

All implement TLS 1.3 + HTTP/2 + MessagePack transport to the SN360
Agent Gateway, plus a legacy-comms path for backward compatibility.

### File integrity monitoring (FIM)

| Agent | Crate | Key file |
|-------|-------|----------|
| SDA | `sda-fim` | `crates/sda-fim/src/module.rs` |
| VM | `vma-fim` | `crates/vma-fim/src/module.rs` |
| K8s | `ska-fim` | `crates/ska-fim/src/module.rs` |

Shared design: inotify/kqueue/ReadDirectoryChangesW for realtime
events, periodic baseline sweeps with SHA-256, configurable
directories and exclusion patterns.

### Local detection engine (LDE)

| Agent | Crate | Key file |
|-------|-------|----------|
| SDA | `sda-lde` | `crates/sda-lde/src/lib.rs` |
| VM | `vma-local-detection` | `crates/vma-local-detection/src/lib.rs` |
| K8s | `ska-lde` | `crates/ska-lde/src/lib.rs` |

YAML-authored detection rules with Ed25519-signed hot-swap via
`Arc<ArcSwap<DetectionPipeline>>`. Edge IOC matching and behavioural
rules.

## Future: shared crate extraction

A future initiative may extract these patterns into an
`sn360-agent-core` shared crate published to a private registry.
This would eliminate triple-maintenance for bug fixes but requires
careful attention to:
- Platform-specific compilation (desktop, VM, K8s)
- Feature-flag compatibility across agent types
- Release coordination across three deployment pipelines
