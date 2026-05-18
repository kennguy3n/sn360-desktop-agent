//! Optional DLP clipboard monitoring (`dlp-clipboard` feature).
//!
//! Production backends will hook into the platform clipboard
//! (X11 / Wayland on Linux, `AddClipboardFormatListener` on
//! Windows, `NSPasteboard.changeCount` on macOS). None of those
//! APIs are reachable from headless CI, so we ship the
//! [`MockClipboardSource`] for tests and the integration backends
//! plug in via E5.7 follow-ups.
//!
//! The scanner contract is identical to file inspection: the
//! provider yields raw clipboard text and the module applies
//! [`crate::scanner::Scanner::scan`] to it.

use std::sync::Mutex;

use tokio::sync::mpsc;
use tracing::debug;

use sda_core::signal::ShutdownSignal;

/// Stream contract for the optional clipboard providers.
pub trait ClipboardSource: Send + Sync {
    /// Yield the next clipboard string. Returns `None` when the
    /// underlying source has nothing left to emit.
    fn poll(&self) -> Option<String>;
}

/// Drive a [`ClipboardSource`] until shutdown, forwarding its
/// strings into the supplied channel.
pub async fn drive_clipboard_source<S: ClipboardSource>(
    source: S,
    tx: mpsc::Sender<String>,
    mut shutdown: ShutdownSignal,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(50));
    loop {
        tokio::select! {
            biased;
            _ = shutdown.wait() => {
                debug!("clipboard source: shutdown");
                return;
            }
            _ = interval.tick() => {
                if let Some(text) = source.poll() {
                    if tx.send(text).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// In-memory mock clipboard source for tests.
pub struct MockClipboardSource {
    items: Mutex<std::collections::VecDeque<String>>,
}

impl MockClipboardSource {
    /// Build a mock with a pre-populated queue.
    pub fn new<I: IntoIterator<Item = String>>(items: I) -> Self {
        Self {
            items: Mutex::new(items.into_iter().collect()),
        }
    }
}

impl ClipboardSource for MockClipboardSource {
    fn poll(&self) -> Option<String> {
        self.items.lock().unwrap().pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::baseline_patterns;
    use crate::scanner::Scanner;

    #[test]
    fn mock_clipboard_yields_items_in_order() {
        let mock = MockClipboardSource::new(vec!["a".into(), "b".into()]);
        assert_eq!(mock.poll(), Some("a".into()));
        assert_eq!(mock.poll(), Some("b".into()));
        assert_eq!(mock.poll(), None);
    }

    #[test]
    fn scanner_finds_ssn_in_clipboard_string() {
        let scanner = Scanner::new(baseline_patterns());
        let findings = scanner.scan("clipboard ssn 123-45-6789");
        assert!(findings.iter().any(|f| f.category == "pii.ssn"));
    }

    #[test]
    fn clean_clipboard_produces_no_finding() {
        let scanner = Scanner::new(baseline_patterns());
        let findings = scanner.scan("just a normal copy");
        assert!(findings.is_empty());
    }
}
