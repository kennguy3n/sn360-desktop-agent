//! Windows WDK minifilter backend.
//!
//! Production architecture (NOT exercised in CI — requires the
//! Windows Driver Kit + WHQL signing + SYSTEM privilege):
//!
//! 1. A minifilter driver registers `PsSetCreateProcessNotifyRoutineEx`
//!    for process callbacks and a WFP callout at
//!    `FWPM_LAYER_ALE_AUTH_CONNECT_V4` for outbound network
//!    connections.
//! 2. Each callback marshals the relevant fields into a
//!    length-prefixed line-delimited JSON [`KernelEvent`] record and
//!    writes it to a kernel-mode named-pipe endpoint
//!    (`\\.\\pipe\\sn360-kernel`).
//! 3. The user-mode agent connects to the pipe and parses the JSON
//!    stream, feeding events back through the standard
//!    [`crate::process_monitor::ProcessMonitor`] /
//!    [`crate::network_monitor::NetworkMonitor`] dispatch.
//!
//! Build pipeline lives in `packaging/windows-driver/`; see
//! `docs/device-control/PRODUCTISATION-WINDOWS.md` for the WHCP
//! signing flow that this minifilter shares with the USB-policy
//! device-control driver.
//!
//! In CI we never load a real driver. The [`MockWindowsKernelChannel`]
//! below simulates the pipe by writing canned `KernelEvent` records
//! into an in-process `VecDeque`, so the user-mode parser is fully
//! exercised end-to-end without the WDK toolchain.

use std::collections::VecDeque;
use std::sync::Mutex;

use super::{AttachError, AttachResult, KernelChannel, KernelEvent};

/// Parse a line-delimited JSON stream into a sequence of
/// [`KernelEvent`] records.
///
/// The WDK minifilter writes one JSON object per line into the
/// kernel→user-mode named pipe. This function is the user-mode
/// parser: it tolerates blank lines, trims `\r\n`, and surfaces
/// every malformed record as an `Err` so the supervisor can log
/// + drop it rather than panicking.
pub fn parse_pipe_records(input: &[u8]) -> Vec<Result<KernelEvent, serde_json::Error>> {
    let mut out = Vec::new();
    for raw in input.split(|b| *b == b'\n') {
        let line = match std::str::from_utf8(raw) {
            Ok(s) => s.trim_end_matches('\r').trim(),
            Err(_) => continue,
        };
        if line.is_empty() {
            continue;
        }
        out.push(serde_json::from_str::<KernelEvent>(line));
    }
    out
}

/// In-process replacement for the named-pipe channel.
///
/// Used by unit + integration tests; the public surface mirrors
/// what the real `\\.\\pipe\\sn360-kernel` reader exposes.
pub struct MockWindowsKernelChannel {
    inner: Mutex<MockState>,
}

struct MockState {
    attached: bool,
    queue: VecDeque<KernelEvent>,
}

impl Default for MockWindowsKernelChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl MockWindowsKernelChannel {
    /// Build a detached channel (`is_attached` returns false).
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(MockState {
                attached: false,
                queue: VecDeque::new(),
            }),
        }
    }

    /// Simulate the minifilter being loaded and ready.
    pub fn set_attached(&self, attached: bool) {
        self.inner.lock().unwrap().attached = attached;
    }

    /// Push a canned event onto the channel.
    pub fn push(&self, ev: KernelEvent) {
        self.inner.lock().unwrap().queue.push_back(ev);
    }

    /// Number of pending events in the queue (test introspection).
    pub fn pending(&self) -> usize {
        self.inner.lock().unwrap().queue.len()
    }
}

impl KernelChannel for MockWindowsKernelChannel {
    fn is_attached(&self) -> bool {
        self.inner.lock().unwrap().attached
    }

    fn try_recv(&self) -> Option<KernelEvent> {
        self.inner.lock().unwrap().queue.pop_front()
    }
}

/// Attempt to attach to the real `\\.\\pipe\\sn360-kernel` named
/// pipe. Without the `kernel-windows` feature this always returns
/// [`AttachError::NotPresent`] — the runtime supervisor falls back
/// to the user-mode ETW backend.
pub fn attach_to_named_pipe() -> AttachResult<Box<dyn KernelChannel>> {
    #[cfg(all(feature = "kernel-windows", target_os = "windows"))]
    {
        // The real implementation would call `CreateFileW` on
        // `\\.\\pipe\\sn360-kernel` here, wrap the handle in a
        // reader thread, and return a `WindowsKernelChannel`. The
        // WDK build (`packaging/windows-driver/build-driver.ps1`)
        // is required for the driver side; for now we surface a
        // stub error so the supervisor falls back to ETW.
        Err(AttachError::NotPresent(
            "WDK minifilter binary not yet bundled; falling back to ETW backend".into(),
        ))
    }
    #[cfg(not(all(feature = "kernel-windows", target_os = "windows")))]
    {
        Err(AttachError::NotPresent(
            "kernel-windows feature not enabled".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::NetworkProtocol;

    fn pc(pid: u32, ppid: u32, path: &str) -> KernelEvent {
        KernelEvent::ProcessCreated {
            pid,
            ppid,
            uid: 0,
            image_path: Some(path.to_string()),
        }
    }

    #[test]
    fn pipe_parser_decodes_canonical_process_record() {
        let line = r#"{"kind":"process_created","pid":1234,"ppid":1,"uid":0,"image_path":"C:\\Windows\\System32\\notepad.exe"}"#;
        let mut bytes = line.as_bytes().to_vec();
        bytes.push(b'\n');
        let results = parse_pipe_records(&bytes);
        assert_eq!(results.len(), 1);
        let ev = results[0].as_ref().unwrap();
        match ev {
            KernelEvent::ProcessCreated { pid, ppid, uid, .. } => {
                assert_eq!(*pid, 1234);
                assert_eq!(*ppid, 1);
                assert_eq!(*uid, 0);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn pipe_parser_decodes_canonical_network_record() {
        let line = r#"{"kind":"network_connect","pid":42,"protocol":"tcp","local_addr":"10.0.0.5","local_port":50001,"remote_addr":"8.8.8.8","remote_port":443}"#;
        let mut bytes = line.as_bytes().to_vec();
        bytes.push(b'\n');
        let results = parse_pipe_records(&bytes);
        assert_eq!(results.len(), 1);
        match results[0].as_ref().unwrap() {
            KernelEvent::NetworkConnect {
                protocol,
                remote_port,
                ..
            } => {
                assert!(matches!(protocol, NetworkProtocol::Tcp));
                assert_eq!(*remote_port, 443);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn pipe_parser_tolerates_blank_lines_and_crlf() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(br#"{"kind":"process_exited","pid":7,"exit_code":0}"#);
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(b"\n");
        let results = parse_pipe_records(&bytes);
        assert_eq!(results.len(), 1);
        assert!(matches!(
            results[0].as_ref().unwrap(),
            KernelEvent::ProcessExited { pid: 7, .. }
        ));
    }

    #[test]
    fn pipe_parser_surfaces_per_line_errors_without_short_circuiting() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"this-is-not-json\n");
        bytes.extend_from_slice(br#"{"kind":"process_exited","pid":9,"exit_code":1}"#);
        bytes.push(b'\n');
        let results = parse_pipe_records(&bytes);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_err());
        assert!(results[1].is_ok());
    }

    #[test]
    fn mock_channel_starts_detached_and_drains_in_order() {
        let chan = MockWindowsKernelChannel::new();
        assert!(!chan.is_attached());
        chan.set_attached(true);
        assert!(chan.is_attached());

        chan.push(pc(1, 0, "C:\\a.exe"));
        chan.push(pc(2, 1, "C:\\b.exe"));
        assert_eq!(chan.pending(), 2);

        let first = chan.try_recv().unwrap();
        let second = chan.try_recv().unwrap();
        assert!(matches!(first, KernelEvent::ProcessCreated { pid: 1, .. }));
        assert!(matches!(second, KernelEvent::ProcessCreated { pid: 2, .. }));
        assert!(chan.try_recv().is_none());
    }

    #[test]
    fn attach_without_feature_flag_returns_not_present_so_supervisor_falls_back() {
        match attach_to_named_pipe() {
            Err(AttachError::NotPresent(_)) => {}
            Err(other) => panic!("expected NotPresent, got {other:?}"),
            Ok(_) => panic!("unexpected success attaching to WDK minifilter in CI"),
        }
    }
}
