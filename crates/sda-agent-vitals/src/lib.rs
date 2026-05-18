//! `sda-agent-vitals` — periodic agent-vitals heartbeat for the
//! SN360 Desktop Agent (Phase 1).
//!
//! This crate emits [`EventKind::AgentVitals`](sda_event_bus::EventKind::AgentVitals)
//! events every `interval_secs` (default 60s; `Priority::Low` per
//! docs/architecture.md § 3.1) carrying the agent's RSS, CPU, event-bus
//! queue depth, watchdog fault count, agent version, uptime, and
//! UTC last-seen timestamp. The control plane uses these
//! heartbeats both as liveness and as the input to the
//! `MissingDevice` Finding (``docs/desktop-mdm.md` § 8`).
//!
//! Layout:
//!
//! * [`collector`] — trait + default OS reader for [`VitalsSnapshot`]
//! * [`heartbeat`] — pure functions that build the bus event from a
//!   snapshot, plus power-aware deferral logic
//! * [`module`] — supervisor task ([`VitalsModule::start`]) that
//!   wires everything together behind the standard module pattern
//!
//! The supervisor is intentionally minimal — when
//! `device_control.enabled = false` the agent never spawns this
//! task, which keeps idle CPU at zero.

pub mod collector;
pub mod heartbeat;
pub mod module;

pub use collector::{Collector, DefaultCollector, VitalsSnapshot};
pub use heartbeat::{effective_interval, run_tick, snapshot_to_event_kind, TickOutcome};
pub use module::{VitalsCounters, VitalsModule, DEFAULT_HEARTBEAT_INTERVAL_SECS};
