//! macOS SystemExtension backend.
//!
//! Production architecture (NOT exercised in CI — requires the
//! `com.apple.developer.endpoint-security.client` entitlement, an
//! Apple Developer ID, notarisation, and an MDM payload to approve
//! the SystemExtension):
//!
//! 1. The user-mode agent ships a SystemExtension bundle
//!    (`com.sn360.endpoint-security`) signed with the Apple
//!    Developer ID team.
//! 2. The SystemExtension subscribes to Endpoint Security events
//!    (`ES_EVENT_TYPE_NOTIFY_EXEC`, `_EXIT`, `_OPEN`, …) and
//!    forwards a serialised [`KernelEvent`] stream to the agent
//!    over an XPC mach port.
//! 3. The agent reads the XPC stream and feeds it back through the
//!    standard user-mode trait surfaces.
//!
//! Build pipeline: `packaging/macos/build-pkg.sh` already produces
//! the agent installer; extending it to embed the SystemExtension
//! bundle is documented as a manual step in
//! `docs/kernel-drivers.md` § 3.3 (Build / sign / notarise pipeline).
//!
//! In CI we exercise [`MockMacosKernelChannel`] which uses the
//! same line-delimited JSON wire shape as the eBPF / WDK mocks so
//! the parser code in `mod.rs` can be reused.

use std::collections::VecDeque;
use std::sync::Mutex;

use super::{AttachError, AttachResult, KernelChannel, KernelEvent};

/// Parse a sequence of XPC-framed `KernelEvent` records.
///
/// The real XPC transport delivers events one at a time; for unit
/// tests we batch them into a `Vec<u8>` of newline-delimited JSON
/// to share the parser with the Windows / Linux backends.
pub fn parse_xpc_records(input: &[u8]) -> Vec<Result<KernelEvent, serde_json::Error>> {
    let mut out = Vec::new();
    for raw in input.split(|b| *b == b'\n') {
        let line = match std::str::from_utf8(raw) {
            Ok(s) => s.trim(),
            Err(_) => continue,
        };
        if line.is_empty() {
            continue;
        }
        out.push(serde_json::from_str::<KernelEvent>(line));
    }
    out
}

/// In-process replacement for the XPC mach-port channel.
pub struct MockMacosKernelChannel {
    inner: Mutex<MockState>,
}

struct MockState {
    attached: bool,
    queue: VecDeque<KernelEvent>,
}

impl Default for MockMacosKernelChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl MockMacosKernelChannel {
    /// Build a detached channel.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(MockState {
                attached: false,
                queue: VecDeque::new(),
            }),
        }
    }

    /// Simulate the SystemExtension being approved + activated by
    /// the MDM payload.
    pub fn set_attached(&self, attached: bool) {
        self.inner.lock().unwrap().attached = attached;
    }

    /// Push a canned event onto the channel.
    pub fn push(&self, ev: KernelEvent) {
        self.inner.lock().unwrap().queue.push_back(ev);
    }

    /// Number of pending events (test introspection).
    pub fn pending(&self) -> usize {
        self.inner.lock().unwrap().queue.len()
    }
}

impl KernelChannel for MockMacosKernelChannel {
    fn is_attached(&self) -> bool {
        self.inner.lock().unwrap().attached
    }

    fn try_recv(&self) -> Option<KernelEvent> {
        self.inner.lock().unwrap().queue.pop_front()
    }
}

/// Attempt to attach to the production SystemExtension XPC channel.
///
/// Without the `kernel-macos` feature this always returns
/// [`AttachError::NotPresent`] so the supervisor falls back to the
/// user-mode Endpoint Security client.
pub fn attach_to_system_extension() -> AttachResult<Box<dyn KernelChannel>> {
    #[cfg(all(feature = "kernel-macos", target_os = "macos"))]
    {
        // Real implementation would open an XPC connection to
        // `com.sn360.endpoint-security` here. The bundle build /
        // notarisation pipeline is documented in
        // `docs/kernel-drivers.md` § 3.3.
        Err(AttachError::NotPresent(
            "SystemExtension bundle not yet shipped; falling back to user-mode ES client".into(),
        ))
    }
    #[cfg(not(all(feature = "kernel-macos", target_os = "macos")))]
    {
        Err(AttachError::NotPresent(
            "kernel-macos feature not enabled".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe(pid: u32) -> KernelEvent {
        KernelEvent::ProcessExited { pid, exit_code: 0 }
    }

    #[test]
    fn xpc_parser_decodes_process_exited_record() {
        let line = br#"{"kind":"process_exited","pid":42,"exit_code":137}"#;
        let mut bytes = line.to_vec();
        bytes.push(b'\n');
        let results = parse_xpc_records(&bytes);
        assert_eq!(results.len(), 1);
        match results[0].as_ref().unwrap() {
            KernelEvent::ProcessExited { pid, exit_code } => {
                assert_eq!(*pid, 42);
                assert_eq!(*exit_code, 137);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn xpc_parser_decodes_process_created_with_null_image_path() {
        // Endpoint Security can fire NOTIFY_EXEC before the path
        // is resolved; the kernel side then emits `image_path: null`
        // and the user-mode side back-fills from
        // `proc_pidpath`.
        let line = br#"{"kind":"process_created","pid":12,"ppid":1,"uid":501,"image_path":null}"#;
        let mut bytes = line.to_vec();
        bytes.push(b'\n');
        let results = parse_xpc_records(&bytes);
        assert_eq!(results.len(), 1);
        match results[0].as_ref().unwrap() {
            KernelEvent::ProcessCreated {
                image_path, uid, ..
            } => {
                assert!(image_path.is_none());
                assert_eq!(*uid, 501);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn xpc_parser_skips_blank_lines_between_events() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\n\n");
        bytes.extend_from_slice(br#"{"kind":"process_exited","pid":1,"exit_code":0}"#);
        bytes.extend_from_slice(b"\n");
        let results = parse_xpc_records(&bytes);
        assert_eq!(results.len(), 1);
        assert!(matches!(
            results[0].as_ref().unwrap(),
            KernelEvent::ProcessExited { pid: 1, .. }
        ));
    }

    #[test]
    fn mock_channel_drains_queue_in_fifo_order() {
        let chan = MockMacosKernelChannel::new();
        chan.set_attached(true);
        chan.push(pe(1));
        chan.push(pe(2));
        chan.push(pe(3));
        assert_eq!(chan.pending(), 3);
        assert!(matches!(
            chan.try_recv().unwrap(),
            KernelEvent::ProcessExited { pid: 1, .. }
        ));
        assert!(matches!(
            chan.try_recv().unwrap(),
            KernelEvent::ProcessExited { pid: 2, .. }
        ));
        assert!(matches!(
            chan.try_recv().unwrap(),
            KernelEvent::ProcessExited { pid: 3, .. }
        ));
        assert!(chan.try_recv().is_none());
    }

    #[test]
    fn mock_channel_starts_detached_so_supervisor_uses_user_mode_es_client() {
        let chan = MockMacosKernelChannel::new();
        assert!(!chan.is_attached());
    }

    #[test]
    fn attach_without_feature_flag_returns_not_present() {
        match attach_to_system_extension() {
            Err(AttachError::NotPresent(_)) => {}
            Err(other) => panic!("expected NotPresent, got {other:?}"),
            Ok(_) => panic!("unexpected success attaching to SystemExtension in CI"),
        }
    }
}
