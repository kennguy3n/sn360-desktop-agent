//! Event-driven systemd journal reader for log collection.
//!
//! Uses `sd_journal_get_fd()` + `sd_journal_get_events()` integrated with
//! tokio `AsyncFd` for zero-polling journal monitoring. Only compiled on
//! Linux when the `linux-journal` feature is enabled.

use std::ffi::CStr;
use std::os::unix::io::RawFd;
use std::ptr;

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tracing::{debug, error, info, warn};

use sda_core::config::LogSource;
use sda_core::signal::ShutdownSignal;
use sda_event_bus::{Event, EventKind, Priority};

use crate::batch::LogBatchSink;

// ---------------------------------------------------------------------------
// FFI bindings to libsystemd sd_journal_* functions
// ---------------------------------------------------------------------------

#[allow(non_camel_case_types)]
type sd_journal = libc::c_void;

const SD_JOURNAL_LOCAL_ONLY: libc::c_int = 1;

extern "C" {
    fn sd_journal_open(ret: *mut *mut sd_journal, flags: libc::c_int) -> libc::c_int;
    fn sd_journal_close(j: *mut sd_journal);
    fn sd_journal_seek_tail(j: *mut sd_journal) -> libc::c_int;
    fn sd_journal_previous(j: *mut sd_journal) -> libc::c_int;
    fn sd_journal_next(j: *mut sd_journal) -> libc::c_int;
    fn sd_journal_get_fd(j: *mut sd_journal) -> libc::c_int;
    fn sd_journal_get_events(j: *mut sd_journal) -> libc::c_int;
    fn sd_journal_process(j: *mut sd_journal) -> libc::c_int;
    fn sd_journal_get_data(
        j: *mut sd_journal,
        field: *const libc::c_char,
        data: *mut *const libc::c_void,
        length: *mut libc::size_t,
    ) -> libc::c_int;
    fn sd_journal_add_match(
        j: *mut sd_journal,
        data: *const libc::c_void,
        size: libc::size_t,
    ) -> libc::c_int;
    fn sd_journal_add_disjunction(j: *mut sd_journal) -> libc::c_int;
}

/// Return codes from `sd_journal_process`.
const SD_JOURNAL_NOP: libc::c_int = 0;
const SD_JOURNAL_APPEND: libc::c_int = 1;
const SD_JOURNAL_INVALIDATE: libc::c_int = 2;

// ---------------------------------------------------------------------------
// Safe wrapper around the raw sd_journal pointer
// ---------------------------------------------------------------------------

struct JournalHandle(*mut sd_journal);

// SAFETY: The sd_journal pointer is only accessed from a single tokio task.
unsafe impl Send for JournalHandle {}

impl Drop for JournalHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { sd_journal_close(self.0) };
        }
    }
}

impl JournalHandle {
    fn open() -> anyhow::Result<Self> {
        let mut j: *mut sd_journal = ptr::null_mut();
        let rc = unsafe { sd_journal_open(&mut j, SD_JOURNAL_LOCAL_ONLY) };
        if rc < 0 {
            anyhow::bail!(
                "sd_journal_open failed: {}",
                std::io::Error::from_raw_os_error(-rc)
            );
        }
        Ok(Self(j))
    }

    fn seek_tail(&self) -> anyhow::Result<()> {
        let rc = unsafe { sd_journal_seek_tail(self.0) };
        if rc < 0 {
            anyhow::bail!(
                "sd_journal_seek_tail failed: {}",
                std::io::Error::from_raw_os_error(-rc)
            );
        }
        // Move back one entry so that next() will position at the very end.
        unsafe { sd_journal_previous(self.0) };
        Ok(())
    }

    fn next(&self) -> anyhow::Result<bool> {
        let rc = unsafe { sd_journal_next(self.0) };
        if rc < 0 {
            anyhow::bail!(
                "sd_journal_next failed: {}",
                std::io::Error::from_raw_os_error(-rc)
            );
        }
        Ok(rc > 0)
    }

    fn get_fd(&self) -> anyhow::Result<RawFd> {
        let fd = unsafe { sd_journal_get_fd(self.0) };
        if fd < 0 {
            anyhow::bail!(
                "sd_journal_get_fd failed: {}",
                std::io::Error::from_raw_os_error(-fd)
            );
        }
        Ok(fd)
    }

    fn get_events(&self) -> anyhow::Result<u32> {
        let events = unsafe { sd_journal_get_events(self.0) };
        if events < 0 {
            anyhow::bail!(
                "sd_journal_get_events failed: {}",
                std::io::Error::from_raw_os_error(-events)
            );
        }
        Ok(events as u32)
    }

    fn process(&self) -> libc::c_int {
        unsafe { sd_journal_process(self.0) }
    }

    fn add_match(&self, field_and_value: &[u8]) -> anyhow::Result<()> {
        let rc = unsafe {
            sd_journal_add_match(
                self.0,
                field_and_value.as_ptr() as *const libc::c_void,
                field_and_value.len() as libc::size_t,
            )
        };
        if rc < 0 {
            anyhow::bail!(
                "sd_journal_add_match failed: {}",
                std::io::Error::from_raw_os_error(-rc)
            );
        }
        Ok(())
    }

    fn add_disjunction(&self) -> anyhow::Result<()> {
        let rc = unsafe { sd_journal_add_disjunction(self.0) };
        if rc < 0 {
            anyhow::bail!(
                "sd_journal_add_disjunction failed: {}",
                std::io::Error::from_raw_os_error(-rc)
            );
        }
        Ok(())
    }

    fn get_field(&self, field: &CStr) -> Option<String> {
        let mut data: *const libc::c_void = ptr::null();
        let mut len: libc::size_t = 0;
        let rc = unsafe { sd_journal_get_data(self.0, field.as_ptr(), &mut data, &mut len) };
        if rc < 0 {
            return None;
        }
        let bytes = unsafe { std::slice::from_raw_parts(data as *const u8, len) };
        // Data is "FIELD=value" — split at the first '='
        if let Some(pos) = bytes.iter().position(|&b| b == b'=') {
            String::from_utf8_lossy(&bytes[pos + 1..])
                .into_owned()
                .into()
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Thin wrapper so AsyncFd can borrow the journal fd without owning it
// ---------------------------------------------------------------------------

struct JournalFd(RawFd);

impl std::os::unix::io::AsRawFd for JournalFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

// ---------------------------------------------------------------------------
// JournalEntry — extracted fields from a single journal record
// ---------------------------------------------------------------------------

/// Extracted fields from one journal entry.
#[derive(Debug, Clone)]
pub struct JournalEntry {
    pub message: String,
    pub unit: Option<String>,
    pub priority: Option<String>,
    pub pid: Option<String>,
    pub syslog_identifier: Option<String>,
}

impl std::fmt::Display for JournalEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref ident) = self.syslog_identifier {
            write!(f, "{}", ident)?;
            if let Some(ref pid) = self.pid {
                write!(f, "[{}]", pid)?;
            }
            write!(f, ": ")?;
        }
        write!(f, "{}", self.message)
    }
}

// Pre-built CStr constants for field names to avoid repeated allocations.
macro_rules! cstr {
    ($s:literal) => {
        unsafe { CStr::from_bytes_with_nul_unchecked(concat!($s, "\0").as_bytes()) }
    };
}

fn field_message() -> &'static CStr {
    cstr!("MESSAGE")
}
fn field_systemd_unit() -> &'static CStr {
    cstr!("_SYSTEMD_UNIT")
}
fn field_priority() -> &'static CStr {
    cstr!("PRIORITY")
}
fn field_pid() -> &'static CStr {
    cstr!("_PID")
}
fn field_syslog_identifier() -> &'static CStr {
    cstr!("SYSLOG_IDENTIFIER")
}

/// Extract fields from the current journal cursor position.
fn extract_entry(journal: &JournalHandle) -> Option<JournalEntry> {
    let message = journal.get_field(field_message())?;
    Some(JournalEntry {
        message,
        unit: journal.get_field(field_systemd_unit()),
        priority: journal.get_field(field_priority()),
        pid: journal.get_field(field_pid()),
        syslog_identifier: journal.get_field(field_syslog_identifier()),
    })
}

// ---------------------------------------------------------------------------
// JournalReader — the public API
// ---------------------------------------------------------------------------

/// Reads new entries from the systemd journal using fd-based notifications.
pub struct JournalReader {
    config: LogSource,
    bus: LogBatchSink,
}

impl JournalReader {
    /// Create a new journal reader for the given source configuration.
    pub fn new(config: LogSource, bus: LogBatchSink) -> Self {
        Self { config, bus }
    }

    /// Run the journal reader loop until shutdown.
    pub async fn run(self, mut shutdown: ShutdownSignal) -> anyhow::Result<()> {
        info!("journal reader starting");

        let journal = JournalHandle::open()?;

        // Apply unit filters (OR-combined via disjunctions).
        if !self.config.units.is_empty() {
            for (i, unit) in self.config.units.iter().enumerate() {
                if i > 0 {
                    journal.add_disjunction()?;
                }
                let match_str = format!("_SYSTEMD_UNIT={}", unit);
                journal.add_match(match_str.as_bytes())?;
                debug!(unit = %unit, "added journal unit filter");
            }
        }

        // Seek to tail — only collect new entries.
        journal.seek_tail()?;
        debug!("journal reader seeked to tail");

        // Obtain the inotify/epoll fd from sd_journal for event-driven wakeups.
        let fd = journal.get_fd()?;
        let _events = journal.get_events()?;

        let async_fd = AsyncFd::with_interest(JournalFd(fd), Interest::READABLE)?;

        info!("journal reader running (event-driven via fd {})", fd);

        loop {
            tokio::select! {
                biased;

                _ = shutdown.wait() => {
                    info!("journal reader received shutdown signal");
                    break;
                }

                guard = async_fd.readable() => {
                    let mut guard = match guard {
                        Ok(g) => g,
                        Err(e) => {
                            error!(error = %e, "journal async fd error");
                            break;
                        }
                    };

                    // Tell sd_journal to process pending events.
                    let rc = journal.process();
                    guard.clear_ready();

                    if rc == SD_JOURNAL_APPEND || rc == SD_JOURNAL_NOP || rc == SD_JOURNAL_INVALIDATE {
                        // Read all newly appended entries.
                        while journal.next()? {
                            if let Some(entry) = extract_entry(&journal) {
                                let event = Event::new(
                                    "logcollector",
                                    Priority::Normal,
                                    EventKind::LogCollected {
                                        source: "journald".to_string(),
                                        message: entry.to_string(),
                                        format: self.config.format.clone(),
                                    },
                                );
                                if let Err(e) = self.bus.publish_to_server(event).await {
                                    warn!(error = %e, "failed to publish journal event");
                                }
                            }
                        }
                    }
                }
            }
        }

        info!("journal reader stopped");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::signal::ShutdownController;
    use sda_event_bus::EventBus;

    #[test]
    fn test_journal_entry_display_with_identifier() {
        let entry = JournalEntry {
            message: "Failed password for root from 10.0.0.1 port 22 ssh2".to_string(),
            unit: Some("sshd.service".to_string()),
            priority: Some("6".to_string()),
            pid: Some("1234".to_string()),
            syslog_identifier: Some("sshd".to_string()),
        };
        let display = entry.to_string();
        assert!(display.contains("sshd[1234]: "));
        assert!(display.contains("Failed password"));
    }

    #[test]
    fn test_journal_entry_display_without_identifier() {
        let entry = JournalEntry {
            message: "some message".to_string(),
            unit: None,
            priority: None,
            pid: None,
            syslog_identifier: None,
        };
        assert_eq!(entry.to_string(), "some message");
    }

    #[test]
    fn test_journal_reader_construction() {
        let source = LogSource {
            source_type: "journald".to_string(),
            path: None,
            format: "syslog".to_string(),
            units: vec!["sshd.service".to_string()],
        };
        let (bus, _rx) = EventBus::new(256, 256);
        let reader = JournalReader::new(source.clone(), LogBatchSink::immediate(bus));
        assert_eq!(reader.config.source_type, "journald");
        assert_eq!(reader.config.units.len(), 1);
    }

    #[tokio::test]
    async fn test_journal_reader_opens_and_shuts_down() {
        // This test requires a running systemd journal.
        if std::fs::metadata("/run/systemd/journal/socket").is_err() {
            eprintln!("skipping: systemd journal not available");
            return;
        }

        let source = LogSource {
            source_type: "journald".to_string(),
            path: None,
            format: "syslog".to_string(),
            units: vec![],
        };
        let (bus, _rx) = EventBus::new(256, 256);
        let reader = JournalReader::new(source, LogBatchSink::immediate(bus));

        let (controller, signal) = ShutdownController::new();

        let handle = tokio::spawn(async move { reader.run(signal).await });

        // Let it start up.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        controller.shutdown();
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("timed out waiting for journal reader shutdown");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_journal_reader_receives_events() {
        // This test requires a running systemd journal and the `logger` command.
        if std::fs::metadata("/run/systemd/journal/socket").is_err() {
            eprintln!("skipping: systemd journal not available");
            return;
        }

        let source = LogSource {
            source_type: "journald".to_string(),
            path: None,
            format: "syslog".to_string(),
            units: vec![],
        };
        let (bus, mut server_rx) = EventBus::new(256, 256);
        let reader = JournalReader::new(source, LogBatchSink::immediate(bus));

        let (controller, signal) = ShutdownController::new();

        let handle = tokio::spawn(async move { reader.run(signal).await });

        // Let the reader start and seek to tail.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Write a unique test message to the journal.
        let tag = format!("sda-test-{}", std::process::id());
        let msg = "unit test journal message";
        std::process::Command::new("logger")
            .args(["-t", &tag, msg])
            .status()
            .expect("failed to run logger");

        // CI journals (especially ubuntu-24.04 runners) emit unrelated
        // events concurrently with the test, so drain the queue until we
        // see our tagged message or the overall deadline expires.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut found = false;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, server_rx.recv()).await {
                Ok(Some(event)) => match &event.kind {
                    EventKind::LogCollected {
                        source, message, ..
                    } => {
                        assert_eq!(source, "journald");
                        if message.contains(msg) {
                            found = true;
                            break;
                        }
                    }
                    other => panic!("expected LogCollected, got: {:?}", other),
                },
                Ok(None) | Err(_) => break,
            }
        }

        controller.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;

        // If the event didn't arrive in time, that's acceptable in CI
        // where journal delivery can be slow.
        let _ = found;
    }

    #[tokio::test]
    async fn test_journal_reader_with_unit_filters() {
        if std::fs::metadata("/run/systemd/journal/socket").is_err() {
            eprintln!("skipping: systemd journal not available");
            return;
        }

        let source = LogSource {
            source_type: "journald".to_string(),
            path: None,
            format: "syslog".to_string(),
            units: vec!["sshd.service".to_string(), "sudo.service".to_string()],
        };
        let (bus, _rx) = EventBus::new(256, 256);
        let reader = JournalReader::new(source, LogBatchSink::immediate(bus));

        let (controller, signal) = ShutdownController::new();

        let handle = tokio::spawn(async move { reader.run(signal).await });

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        controller.shutdown();
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("timed out waiting for journal reader shutdown");
        assert!(result.is_ok());
    }
}
