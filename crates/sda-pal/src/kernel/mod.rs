//! Kernel-mode PAL backends (part of the EDR Parity workstream).
//!
//! E0–E5 ship user-mode telemetry: ETW for Windows process / network
//! events, Endpoint Security framework for macOS, `cn_proc` + audit
//! for Linux. These backends are sufficient for parity but are
//! tamper-visible — a user-mode rootkit or a sufficiently privileged
//! adversary can detach them.  The kernel PAL introduces *optional*
//! kernel-mode replacements that preserve the same user-mode trait
//! surface (`ProcessMonitor`, `NetworkMonitor`, `MemoryScanner`) so
//! they can be swapped in by feature flag without code changes in
//! the calling modules.
//!
//! Production toolchains required (NOT exercised in CI):
//!
//! | Platform | Mechanism                                   | Build / sign |
//! |----------|---------------------------------------------|--------------|
//! | Windows  | WDK minifilter + WFP callout                | WDK + WHQL signing |
//! | macOS    | SystemExtension (Endpoint Security client) | Apple Developer ID + entitlement + notarisation |
//! | Linux    | eBPF programs (Aya)                         | clang + kernel ≥ 5.8 + `CAP_BPF` |
//!
//! What lives in this module:
//!
//! 1. A platform-agnostic [`KernelEvent`] enum that the kernel side
//!    serialises and the user-mode agent parses. Used by all three
//!    backends so the user-mode parser is fully cross-platform.
//! 2. A [`KernelChannel`] trait modelling the IPC channel between
//!    kernel-mode publisher and user-mode subscriber.
//! 3. Per-platform sub-modules with:
//!    - Feature gate (`kernel-windows`, `kernel-macos`,
//!      `kernel-linux-ebpf`) for the real implementation.
//!    - A [`MockKernelChannel`] always available for unit /
//!      integration tests.
//!    - Documentation of the build and signing requirements.

use serde::{Deserialize, Serialize};

pub mod linux_ebpf;
pub mod macos;
pub mod windows;

/// IPC envelope used by every kernel backend.
///
/// The kernel side (WDK minifilter / SystemExtension / eBPF) writes
/// a sequence of `KernelEvent` records to its respective transport
/// (named pipe on Windows, XPC mach port on macOS, eBPF ring buffer
/// on Linux). The user-mode agent reads them and forwards into the
/// corresponding user-mode trait stream.
///
/// The envelope is intentionally narrow: only the fields strictly
/// needed to reconstruct an equivalent user-mode event are carried.
/// All richer context (executable path resolution, parent process
/// chain) is enriched on the user side from `/proc`, the process
/// snapshot API, or LaunchServices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KernelEvent {
    /// A new process was created.
    ///
    /// Linux: `kprobe sys_execve` / `tracepoint:sched:sched_process_exec`.
    /// Windows: `PsSetCreateProcessNotifyRoutineEx`.
    /// macOS: `ES_EVENT_TYPE_NOTIFY_EXEC` (from SystemExtension).
    ProcessCreated {
        pid: u32,
        ppid: u32,
        uid: u32,
        /// Best-effort image path. The kernel side may emit `None`
        /// if it couldn't resolve the path synchronously; the
        /// user-mode side then back-fills from `/proc/<pid>/exe` or
        /// the equivalent.
        image_path: Option<String>,
    },
    /// A process exited (Linux `sched_process_exit` / Windows
    /// process-end callback / macOS `ES_EVENT_TYPE_NOTIFY_EXIT`).
    ProcessExited { pid: u32, exit_code: i32 },
    /// An outbound TCP/UDP connection was initiated.
    ///
    /// Linux: kprobe on `tcp_v4_connect` / `udp_sendmsg`.
    /// Windows: WFP `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4`.
    /// macOS: SystemExtension `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` is not
    /// network; on macOS the Network Extension framework is used
    /// instead.
    NetworkConnect {
        pid: u32,
        protocol: NetworkProtocol,
        local_addr: String,
        local_port: u16,
        remote_addr: String,
        remote_port: u16,
    },
}

/// Transport protocol carried by [`KernelEvent::NetworkConnect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
}

/// The transport channel between the kernel publisher and the
/// user-mode agent.
///
/// All three real backends implement the same trait so the agent
/// supervisor can swap them by feature flag. The mocks live in the
/// per-platform sub-modules.
pub trait KernelChannel: Send + Sync {
    /// True when the kernel component is loaded and the channel is
    /// ready to deliver events.
    fn is_attached(&self) -> bool;

    /// Pull the next event. Returns `None` once the channel is
    /// closed. The kernel implementations all wrap their async
    /// transport in a blocking dequeue inside a dedicated reader
    /// thread; this matches the user-mode `ProcessMonitor` /
    /// `NetworkMonitor` async-stream contract once bridged.
    fn try_recv(&self) -> Option<KernelEvent>;
}

/// Result type for kernel-channel attach operations.
pub type AttachResult<T> = std::result::Result<T, AttachError>;

/// Errors raised when attempting to attach to a kernel publisher.
#[derive(Debug, thiserror::Error)]
pub enum AttachError {
    /// The kernel component is not installed (driver not loaded,
    /// SystemExtension not approved, eBPF program not pinned).
    #[error("kernel publisher not present: {0}")]
    NotPresent(String),
    /// The user-mode process lacks the privilege to attach to the
    /// kernel side. Windows: not running as SYSTEM. macOS: missing
    /// entitlement. Linux: missing `CAP_BPF` / kernel < 5.8.
    #[error("insufficient privilege: {0}")]
    Privilege(String),
    /// I/O error opening the transport handle.
    #[error("kernel channel io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_event_process_created_round_trips_via_serde() {
        let ev = KernelEvent::ProcessCreated {
            pid: 1234,
            ppid: 1,
            uid: 1000,
            image_path: Some("/usr/bin/python3".to_string()),
        };
        let j = serde_json::to_string(&ev).unwrap();
        let back: KernelEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn kernel_event_network_connect_round_trips_via_serde() {
        let ev = KernelEvent::NetworkConnect {
            pid: 42,
            protocol: NetworkProtocol::Tcp,
            local_addr: "10.0.0.1".to_string(),
            local_port: 51234,
            remote_addr: "1.2.3.4".to_string(),
            remote_port: 443,
        };
        let j = serde_json::to_string(&ev).unwrap();
        let back: KernelEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn kernel_event_unknown_payload_is_rejected_not_silently_swallowed() {
        // Defensive: if a future kernel build sends a tagged variant
        // we don't know about, serde will return Err. We don't want
        // the user-mode agent to silently drop those — it must log
        // + skip explicitly.
        let bad = r#"{"kind":"future_variant","pid":1}"#;
        let parsed = serde_json::from_str::<KernelEvent>(bad);
        assert!(parsed.is_err(), "expected unknown-variant parse failure");
    }
}
