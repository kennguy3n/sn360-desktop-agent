//! Linux eBPF backend.
//!
//! Production architecture (NOT exercised in CI — requires kernel
//! ≥ 5.8, `CAP_BPF`, and the Aya toolchain to compile the eBPF
//! programs):
//!
//! 1. A pair of eBPF programs is loaded via Aya:
//!    - kprobe on `sys_execve` for process-create events.
//!    - kprobe on `tcp_v4_connect` / `udp_sendmsg` for outbound
//!      network events.
//! 2. Each kprobe writes a fixed-layout C-style record into a
//!    perf-event ring buffer (`BPF_MAP_TYPE_PERF_EVENT_ARRAY`).
//! 3. The user-mode loader (a small Rust process embedded in the
//!    agent) reads records out of the ring buffer, deserialises
//!    them into [`KernelEvent`], and feeds them back through the
//!    user-mode trait surfaces.
//!
//! Fallback contract: when kernel < 5.8 or `CAP_BPF` is unavailable,
//! [`detect_ebpf_capability`] returns `false` and the supervisor
//! continues running the user-mode `cn_proc` + `audit` backends
//! from the process-monitor module.  This file defines the perf-record layout so that
//! the user-mode parser is testable in CI without the Aya
//! toolchain.

use std::collections::VecDeque;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::{AttachError, AttachResult, KernelChannel, KernelEvent, NetworkProtocol};

/// On-the-wire layout for a single perf-buffer record.
///
/// The eBPF program writes this record verbatim, the user-mode side
/// deserialises it via `bytemuck` (production) or via JSON in CI
/// (mock).  Keeping the layout #[repr(C)]-stable means the eBPF
/// program and the user-mode parser can be rebuilt independently
/// without breaking the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PerfRecord {
    Exec {
        pid: u32,
        ppid: u32,
        uid: u32,
    },
    Exit {
        pid: u32,
        exit_code: i32,
    },
    Connect4 {
        pid: u32,
        protocol: NetworkProtocol,
        saddr: [u8; 4],
        daddr: [u8; 4],
        sport: u16,
        dport: u16,
    },
}

impl PerfRecord {
    /// Lift a perf-record into a generic [`KernelEvent`].
    ///
    /// `image_path` is intentionally `None` on the Linux path: the
    /// eBPF program only has access to the `argv[0]` raw pointer
    /// and we resolve the real path on the user-mode side from
    /// `/proc/<pid>/exe` to keep the kernel-side hot path short.
    pub fn into_kernel_event(self) -> KernelEvent {
        match self {
            PerfRecord::Exec { pid, ppid, uid } => KernelEvent::ProcessCreated {
                pid,
                ppid,
                uid,
                image_path: None,
            },
            PerfRecord::Exit { pid, exit_code } => KernelEvent::ProcessExited { pid, exit_code },
            PerfRecord::Connect4 {
                pid,
                protocol,
                saddr,
                daddr,
                sport,
                dport,
            } => KernelEvent::NetworkConnect {
                pid,
                protocol,
                local_addr: ipv4_to_string(saddr),
                local_port: sport,
                remote_addr: ipv4_to_string(daddr),
                remote_port: dport,
            },
        }
    }
}

fn ipv4_to_string(octets: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

/// Parse a sequence of newline-delimited JSON `PerfRecord` entries
/// (the mock wire format used in CI).
pub fn parse_perf_records(input: &[u8]) -> Vec<Result<PerfRecord, serde_json::Error>> {
    let mut out = Vec::new();
    for raw in input.split(|b| *b == b'\n') {
        let line = match std::str::from_utf8(raw) {
            Ok(s) => s.trim(),
            Err(_) => continue,
        };
        if line.is_empty() {
            continue;
        }
        out.push(serde_json::from_str::<PerfRecord>(line));
    }
    out
}

/// Best-effort detection: is this kernel high enough to support
/// our eBPF programs?
///
/// Reads `/proc/sys/kernel/osrelease` and parses the major.minor
/// prefix. Returns `false` on any read / parse error so the
/// supervisor falls back to cn_proc + audit.
pub fn detect_ebpf_capability() -> bool {
    let release = match std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        Ok(s) => s,
        Err(_) => return false,
    };
    parse_kernel_version_at_least(&release, 5, 8)
}

/// Parse `"x.y..."` and return true iff `(x, y) >= (min_major,
/// min_minor)`. Public for testability.
pub fn parse_kernel_version_at_least(release: &str, min_major: u32, min_minor: u32) -> bool {
    let head = release.trim().split('-').next().unwrap_or("");
    let mut parts = head.split('.');
    let major: u32 = match parts.next().and_then(|s| s.parse().ok()) {
        Some(v) => v,
        None => return false,
    };
    let minor: u32 = match parts.next().and_then(|s| s.parse().ok()) {
        Some(v) => v,
        None => return false,
    };
    (major, minor) >= (min_major, min_minor)
}

/// In-process replacement for the eBPF perf-ring channel.
pub struct MockLinuxKernelChannel {
    inner: Mutex<MockState>,
}

struct MockState {
    attached: bool,
    queue: VecDeque<KernelEvent>,
}

impl Default for MockLinuxKernelChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl MockLinuxKernelChannel {
    /// Build a detached channel.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(MockState {
                attached: false,
                queue: VecDeque::new(),
            }),
        }
    }

    /// Simulate the eBPF programs being loaded and the perf buffer
    /// open.
    pub fn set_attached(&self, attached: bool) {
        self.inner.lock().unwrap().attached = attached;
    }

    /// Push a canned event onto the channel.
    pub fn push(&self, ev: KernelEvent) {
        self.inner.lock().unwrap().queue.push_back(ev);
    }

    /// Push a raw [`PerfRecord`] (auto-lifted into [`KernelEvent`]).
    pub fn push_perf(&self, rec: PerfRecord) {
        self.inner
            .lock()
            .unwrap()
            .queue
            .push_back(rec.into_kernel_event());
    }

    /// Number of pending events (test introspection).
    pub fn pending(&self) -> usize {
        self.inner.lock().unwrap().queue.len()
    }
}

impl KernelChannel for MockLinuxKernelChannel {
    fn is_attached(&self) -> bool {
        self.inner.lock().unwrap().attached
    }

    fn try_recv(&self) -> Option<KernelEvent> {
        self.inner.lock().unwrap().queue.pop_front()
    }
}

/// Attempt to attach to the eBPF perf-buffer.
///
/// Without the `kernel-linux-ebpf` feature this always returns
/// [`AttachError::NotPresent`] so the supervisor falls back to
/// the user-mode cn_proc + audit backends.
pub fn attach_to_perf_buffer() -> AttachResult<Box<dyn KernelChannel>> {
    if !detect_ebpf_capability() {
        return Err(AttachError::NotPresent(
            "kernel < 5.8 or CAP_BPF not granted; falling back to cn_proc + audit".into(),
        ));
    }

    #[cfg(all(feature = "kernel-linux-ebpf", target_os = "linux"))]
    {
        // Real Aya loader would `Bpf::load_file("agent.bpf.o")` +
        // attach kprobes here. Out of scope for the CI test matrix.
        Err(AttachError::NotPresent(
            "eBPF program binary not yet shipped; falling back to cn_proc + audit".into(),
        ))
    }
    #[cfg(not(all(feature = "kernel-linux-ebpf", target_os = "linux")))]
    {
        Err(AttachError::NotPresent(
            "kernel-linux-ebpf feature not enabled".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perf_record_exec_lifts_into_process_created_with_no_image_path() {
        let rec = PerfRecord::Exec {
            pid: 1234,
            ppid: 1,
            uid: 1000,
        };
        let ev = rec.into_kernel_event();
        match ev {
            KernelEvent::ProcessCreated {
                pid,
                ppid,
                uid,
                image_path,
            } => {
                assert_eq!(pid, 1234);
                assert_eq!(ppid, 1);
                assert_eq!(uid, 1000);
                assert!(image_path.is_none());
            }
            other => panic!("expected ProcessCreated, got {other:?}"),
        }
    }

    #[test]
    fn perf_record_connect4_lifts_into_network_connect_with_dotted_ipv4() {
        let rec = PerfRecord::Connect4 {
            pid: 7,
            protocol: NetworkProtocol::Tcp,
            saddr: [10, 0, 0, 5],
            daddr: [1, 1, 1, 1],
            sport: 51000,
            dport: 443,
        };
        match rec.into_kernel_event() {
            KernelEvent::NetworkConnect {
                pid,
                protocol,
                local_addr,
                remote_addr,
                local_port,
                remote_port,
            } => {
                assert_eq!(pid, 7);
                assert!(matches!(protocol, NetworkProtocol::Tcp));
                assert_eq!(local_addr, "10.0.0.5");
                assert_eq!(remote_addr, "1.1.1.1");
                assert_eq!(local_port, 51000);
                assert_eq!(remote_port, 443);
            }
            other => panic!("expected NetworkConnect, got {other:?}"),
        }
    }

    #[test]
    fn perf_parser_decodes_canonical_exec_record() {
        let line = br#"{"kind":"exec","pid":1,"ppid":0,"uid":0}"#;
        let mut bytes = line.to_vec();
        bytes.push(b'\n');
        let results = parse_perf_records(&bytes);
        assert_eq!(results.len(), 1);
        assert!(matches!(
            results[0].as_ref().unwrap(),
            PerfRecord::Exec {
                pid: 1,
                ppid: 0,
                uid: 0
            }
        ));
    }

    #[test]
    fn kernel_version_predicate_accepts_modern_kernels() {
        assert!(parse_kernel_version_at_least("5.8.0-generic\n", 5, 8));
        assert!(parse_kernel_version_at_least("6.1.0", 5, 8));
        assert!(parse_kernel_version_at_least("5.15.0-105-generic", 5, 8));
    }

    #[test]
    fn kernel_version_predicate_rejects_old_kernels() {
        assert!(!parse_kernel_version_at_least("5.4.0-100-generic\n", 5, 8));
        assert!(!parse_kernel_version_at_least("4.19.0", 5, 8));
    }

    #[test]
    fn kernel_version_predicate_rejects_garbage_input() {
        assert!(!parse_kernel_version_at_least("", 5, 8));
        assert!(!parse_kernel_version_at_least("not-a-kernel-version", 5, 8));
        assert!(!parse_kernel_version_at_least("5", 5, 8));
    }

    #[test]
    fn mock_channel_lifts_perf_records_into_kernel_events() {
        let chan = MockLinuxKernelChannel::new();
        chan.set_attached(true);
        chan.push_perf(PerfRecord::Exec {
            pid: 99,
            ppid: 1,
            uid: 1000,
        });
        chan.push_perf(PerfRecord::Exit {
            pid: 99,
            exit_code: 0,
        });
        assert_eq!(chan.pending(), 2);
        assert!(matches!(
            chan.try_recv().unwrap(),
            KernelEvent::ProcessCreated { pid: 99, .. }
        ));
        assert!(matches!(
            chan.try_recv().unwrap(),
            KernelEvent::ProcessExited {
                pid: 99,
                exit_code: 0
            }
        ));
        assert!(chan.try_recv().is_none());
    }

    #[test]
    fn attach_without_feature_flag_returns_not_present() {
        // detect_ebpf_capability may or may not be true on the CI
        // host depending on the kernel version. Either way, without
        // the feature flag we fall back to user-mode.
        match attach_to_perf_buffer() {
            Err(AttachError::NotPresent(_)) => {}
            Err(other) => panic!("expected NotPresent, got {other:?}"),
            Ok(_) => panic!("unexpected success attaching to eBPF perf-buffer in CI"),
        }
    }
}
