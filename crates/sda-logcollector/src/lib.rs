//! Log collection module for the SN360 Desktop Agent.
//!
//! Collects logs from file-based sources using event-driven APIs
//! (inotify/notify) with seek position tracking, and forwards them
//! to the event bus for server delivery.

pub mod batch;
pub mod file_reader;
#[cfg(all(target_os = "linux", feature = "linux-journal"))]
pub mod journal_reader;
#[cfg(target_os = "macos")]
pub mod oslog_reader;
pub mod state;
#[cfg(target_os = "windows")]
pub mod windows_eventlog;
pub mod windows_eventlog_parser;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use tracing::{error, info, warn};

use sda_core::config::AgentConfig;
use sda_core::module::ModuleHandle;
use sda_core::signal::ShutdownSignal;
use sda_core::PowerProfileReceiver;
use sda_event_bus::EventBus;

use crate::batch::{spawn_flush_task, LogBatchSink};
use crate::file_reader::FileReader;
#[cfg(all(target_os = "linux", feature = "linux-journal"))]
use crate::journal_reader::JournalReader;
#[cfg(target_os = "macos")]
use crate::oslog_reader::{OsLogConfig, OsLogReader};
use crate::state::SeekState;
#[cfg(target_os = "windows")]
use crate::windows_eventlog::{EventLogChannelConfig, WindowsEventLogReader};

const STATUS_INITIALIZED: u8 = 0;
const _STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// Log collector module.
pub struct LogCollectorModule;

impl LogCollectorModule {
    /// Start the log collector module, returning a `ModuleHandle`.
    ///
    /// `power_rx` drives the adaptive
    /// [`LogBatchSink`](crate::batch::LogBatchSink) flush cadence: as the
    /// active [`PowerProfile`](sda_core::PowerProfile) transitions between
    /// AC, battery, and critical-battery states the flush interval is
    /// updated to match [`PowerProfile::log_batch_interval`].
    pub fn start(
        config: &AgentConfig,
        bus: EventBus,
        shutdown: ShutdownSignal,
        power_rx: PowerProfileReceiver,
    ) -> ModuleHandle {
        let lc_config = config.modules.logcollector.clone();
        let status = Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = Arc::clone(&status);

        let task = tokio::spawn(async move {
            if let Err(e) = run(lc_config, bus, shutdown, power_rx, task_status.clone()).await {
                error!(error = %e, "logcollector module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });

        ModuleHandle::new("logcollector", task)
    }
}

impl sda_core::module::AgentModule for LogCollectorModule {
    fn name(&self) -> &'static str {
        "logcollector"
    }

    fn status(&self) -> sda_core::module::ModuleStatus {
        sda_core::module::ModuleStatus::Initialized
    }

    fn health(&self) -> sda_core::module::ModuleHealth {
        sda_core::module::ModuleHealth::Healthy
    }
}

/// The main log collector run loop.
async fn run(
    lc_config: sda_core::config::LogCollectorConfig,
    bus: EventBus,
    shutdown: ShutdownSignal,
    power_rx: PowerProfileReceiver,
    status: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    info!("logcollector module starting");

    // Every reader publishes through this batching sink so the agent
    // coalesces log bursts into periodic flushes. The flush cadence
    // follows the active power profile (5 s on AC, up to 60 s on
    // critical battery) via a dedicated flush task driven by the
    // shared `power_rx` watch receiver.
    let sink = LogBatchSink::batched(bus.clone());
    let flush_handle = spawn_flush_task(sink.clone(), power_rx, shutdown.clone());

    // Collect file-based sources and journal sources.
    let mut paths = Vec::new();
    let mut formats = Vec::new();
    #[cfg(all(target_os = "linux", feature = "linux-journal"))]
    let mut journal_sources = Vec::new();
    #[cfg(target_os = "windows")]
    let mut eventlog_channels: Vec<EventLogChannelConfig> = Vec::new();
    #[cfg(target_os = "macos")]
    let mut oslog_configs: Vec<OsLogConfig> = Vec::new();

    for source in &lc_config.sources {
        match source.source_type.as_str() {
            "file" => {
                if let Some(ref path) = source.path {
                    let p = PathBuf::from(path);
                    if !p.exists() {
                        warn!(path = %path, "log source file does not exist yet, will watch for creation");
                    }
                    paths.push(p);
                    formats.push(source.format.clone());
                } else {
                    warn!("file log source missing path, skipping");
                }
            }
            "journald" | "journal" => {
                #[cfg(all(target_os = "linux", feature = "linux-journal"))]
                {
                    journal_sources.push(source.clone());
                }
                #[cfg(not(all(target_os = "linux", feature = "linux-journal")))]
                {
                    warn!(
                        source_type = %source.source_type,
                        "journal source requires linux-journal feature, skipping"
                    );
                }
            }
            "eventlog" | "windows" => {
                #[cfg(target_os = "windows")]
                {
                    let channel = source
                        .path
                        .clone()
                        .unwrap_or_else(|| "Security".to_string());
                    eventlog_channels.push(EventLogChannelConfig {
                        channel,
                        query: None,
                    });
                }
                #[cfg(not(target_os = "windows"))]
                {
                    warn!(
                        source_type = %source.source_type,
                        "eventlog source requires Windows, skipping"
                    );
                }
            }
            "oslog" | "unified" => {
                #[cfg(target_os = "macos")]
                {
                    oslog_configs.push(OsLogConfig {
                        predicate: source.path.clone(),
                        level: None,
                    });
                }
                #[cfg(not(target_os = "macos"))]
                {
                    warn!(
                        source_type = %source.source_type,
                        "oslog source requires macOS, skipping"
                    );
                }
            }
            _ => {
                info!(
                    source_type = %source.source_type,
                    "unknown source type, skipping"
                );
            }
        }
    }

    // Load seek state.
    let state_path = SeekState::default_path();
    let state = SeekState::load(state_path);

    let file_reader = FileReader::new(paths, formats, state, sink.clone());

    status.store(_STATUS_RUNNING, Ordering::Relaxed);
    info!("logcollector module running");

    // Spawn journal readers as separate tasks alongside the file reader.
    #[cfg(all(target_os = "linux", feature = "linux-journal"))]
    let mut journal_handles = Vec::new();
    #[cfg(all(target_os = "linux", feature = "linux-journal"))]
    for source in journal_sources {
        let journal_sink = sink.clone();
        let journal_shutdown = shutdown.clone();
        let reader = JournalReader::new(source, journal_sink);
        let handle = tokio::spawn(async move {
            if let Err(e) = reader.run(journal_shutdown).await {
                error!(error = %e, "journal reader failed");
            }
        });
        journal_handles.push(handle);
    }

    // Spawn Windows Event Log reader.
    #[cfg(target_os = "windows")]
    let eventlog_handle = if !eventlog_channels.is_empty() {
        let el_sink = sink.clone();
        let el_shutdown = shutdown.clone();
        let reader = WindowsEventLogReader::new(eventlog_channels, el_sink);
        Some(tokio::spawn(async move {
            if let Err(e) = reader.run(el_shutdown).await {
                error!(error = %e, "Windows Event Log reader failed");
            }
        }))
    } else {
        None
    };

    // Spawn macOS Unified Log readers.
    #[cfg(target_os = "macos")]
    let mut oslog_handles = Vec::new();
    #[cfg(target_os = "macos")]
    for config in oslog_configs {
        let ol_sink = sink.clone();
        let ol_shutdown = shutdown.clone();
        let reader = OsLogReader::new(config, ol_sink);
        let handle = tokio::spawn(async move {
            if let Err(e) = reader.run(ol_shutdown).await {
                error!(error = %e, "macOS Unified Log reader failed");
            }
        });
        oslog_handles.push(handle);
    }

    file_reader.run(shutdown).await?;

    // Wait for journal readers to finish.
    #[cfg(all(target_os = "linux", feature = "linux-journal"))]
    for handle in journal_handles {
        let _ = handle.await;
    }

    // Wait for Windows Event Log reader to finish.
    #[cfg(target_os = "windows")]
    if let Some(handle) = eventlog_handle {
        let _ = handle.await;
    }

    // Wait for macOS Unified Log readers to finish.
    #[cfg(target_os = "macos")]
    for handle in oslog_handles {
        let _ = handle.await;
    }

    // Drain any events still buffered in the batch sink and wait for
    // the flush task to exit so we never lose the final window of
    // log events on shutdown.
    sink.flush_now().await;
    let _ = flush_handle.await;

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!("logcollector module stopped");
    Ok(())
}
