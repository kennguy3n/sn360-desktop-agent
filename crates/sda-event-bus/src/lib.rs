//! Async event bus for inter-module communication in SDA.
//!
//! Provides a lightweight, bounded, priority-aware channel system for
//! passing events between agent modules with backpressure support.

mod bus;
mod event;

pub use bus::{EventBus, EventBusError, EventReceiver};
pub use event::{Event, EventKind, Priority};
