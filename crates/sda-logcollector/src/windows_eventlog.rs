//! Windows Event Log collector.
//!
//! Uses the native [`EvtSubscribe`] push-based API via the
//! [`windows`] crate to receive events for each configured channel.
//! Incoming events are rendered to XML via [`EvtRender`], parsed by
//! [`crate::windows_eventlog_parser::parse_event_message`], and
//! published on the event bus as [`EventKind::LogCollected`].
//!
//! Gated behind `#[cfg(target_os = "windows")]`.

#![cfg(target_os = "windows")]

use std::ffi::c_void;

use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use sda_core::signal::ShutdownSignal;
use sda_event_bus::{Event, EventKind, Priority};

use crate::batch::LogBatchSink;

use windows::core::{Error as WinError, HSTRING, PCWSTR};
use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows::Win32::System::EventLog::{
    EvtClose, EvtRender, EvtRenderEventXml, EvtSubscribe, EvtSubscribeActionDeliver,
    EvtSubscribeActionError, EvtSubscribeToFutureEvents, EVT_HANDLE, EVT_SUBSCRIBE_CALLBACK,
    EVT_SUBSCRIBE_NOTIFY_ACTION,
};

use crate::windows_eventlog_parser::parse_event_message;

/// Configuration for a single Windows Event Log channel subscription.
#[derive(Debug, Clone)]
pub struct EventLogChannelConfig {
    /// Channel name (e.g. "Security", "System", "Application").
    pub channel: String,
    /// Optional XPath query filter. Defaults to `*` when `None`.
    pub query: Option<String>,
}

/// Reads events from Windows Event Log channels via `EvtSubscribe`.
pub struct WindowsEventLogReader {
    channels: Vec<EventLogChannelConfig>,
    bus: LogBatchSink,
}

impl WindowsEventLogReader {
    pub fn new(channels: Vec<EventLogChannelConfig>, bus: LogBatchSink) -> Self {
        Self { channels, bus }
    }

    /// Run the event log reader until shutdown.
    pub async fn run(self, shutdown: ShutdownSignal) -> anyhow::Result<()> {
        info!(
            channels = self.channels.len(),
            "starting Windows Event Log reader"
        );

        let mut handles = Vec::new();

        for channel_cfg in &self.channels {
            let channel = channel_cfg.channel.clone();
            let query = channel_cfg.query.clone().unwrap_or_else(|| "*".to_string());
            let bus = self.bus.clone();
            let shutdown = shutdown.clone();

            let handle = tokio::spawn(async move {
                if let Err(e) = subscribe_channel(&channel, &query, bus, shutdown).await {
                    error!(channel = %channel, error = %e, "event log channel reader failed");
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }

        info!("Windows Event Log reader stopped");
        Ok(())
    }
}

/// Context passed to the `EvtSubscribe` callback. Carries the sender
/// half of an async channel that the callback uses to hand off
/// rendered event XML to the tokio task draining events.
struct CallbackContext {
    tx: mpsc::UnboundedSender<String>,
}

/// Wrapper that makes a raw `*mut CallbackContext` `Send`, so the
/// subscription task can be scheduled on tokio's multi-threaded
/// runtime. The underlying pointer is only dereferenced from the
/// Windows thread-pool callback (single-threaded per subscription)
/// and from `Box::from_raw` after `EvtClose` drains callbacks.
#[derive(Copy, Clone)]
struct SendPtr(*mut CallbackContext);

unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

/// `EvtSubscribe` callback. Called on a Windows thread-pool thread
/// whenever an event arrives. Renders the event to XML and sends it
/// over the async channel.
///
/// # Safety
/// Invoked only by `EvtSubscribe`. `user_context` must point to a live
/// `CallbackContext`. `event` must be a valid `EVT_HANDLE` while the
/// callback is running.
unsafe extern "system" fn subscribe_callback(
    action: EVT_SUBSCRIBE_NOTIFY_ACTION,
    user_context: *const c_void,
    event: EVT_HANDLE,
) -> u32 {
    if user_context.is_null() {
        return 0;
    }
    let ctx = &*(user_context as *const CallbackContext);

    if action == EvtSubscribeActionDeliver {
        match render_event_xml(event) {
            Ok(xml) => {
                // The receiver may already be dropped (channel closed
                // during shutdown); ignore the resulting send error.
                let _ = ctx.tx.send(xml);
            }
            Err(e) => {
                warn!(error = ?e, "failed to render event XML");
            }
        }
    } else if action == EvtSubscribeActionError {
        // When action is Error, `event` carries a Win32 error code in
        // its lower bits rather than being a real handle.
        warn!(code = ?event, "event log subscription reported error");
    }

    0
}

/// Render a single event handle to its XML representation.
fn render_event_xml(event: EVT_HANDLE) -> windows::core::Result<String> {
    const XML_FLAG: u32 = EvtRenderEventXml.0 as u32;

    let mut buffer_used: u32 = 0;
    let mut property_count: u32 = 0;

    // First call with a zero-size buffer so Windows reports the
    // required size in `buffer_used`. The call is expected to fail
    // with `ERROR_INSUFFICIENT_BUFFER`; any other failure is real
    // and should be propagated so the caller can log it.
    let probe = unsafe {
        EvtRender(
            None,
            event,
            XML_FLAG,
            0,
            None,
            &mut buffer_used,
            &mut property_count,
        )
    };
    if let Err(e) = probe {
        if e.code() != WinError::from(ERROR_INSUFFICIENT_BUFFER).code() {
            return Err(e);
        }
    }

    if buffer_used == 0 {
        return Ok(String::new());
    }

    // `buffer_used` is in bytes; XML is UTF-16 so allocate half as many u16s.
    let u16_count = (buffer_used as usize).div_ceil(2);
    let mut buffer: Vec<u16> = vec![0u16; u16_count];
    let byte_capacity = (buffer.len() * 2) as u32;

    unsafe {
        EvtRender(
            None,
            event,
            XML_FLAG,
            byte_capacity,
            Some(buffer.as_mut_ptr() as *mut c_void),
            &mut buffer_used,
            &mut property_count,
        )?;
    }

    let chars_written = (buffer_used as usize) / 2;
    // Strip trailing null terminator if present.
    let end = chars_written
        .checked_sub(1)
        .filter(|&n| buffer.get(n).copied() == Some(0))
        .unwrap_or(chars_written);

    Ok(String::from_utf16_lossy(&buffer[..end]))
}

/// Subscribe to a single channel and drain events until `shutdown`
/// fires. Safe to call per-channel from independent tasks.
async fn subscribe_channel(
    channel: &str,
    query: &str,
    bus: LogBatchSink,
    mut shutdown: ShutdownSignal,
) -> anyhow::Result<()> {
    info!(channel = %channel, query = %query, "subscribing to event log channel");

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let ctx = Box::new(CallbackContext { tx });
    // Hand ownership of the context to the Windows subscription; we
    // will reclaim it via `Box::from_raw` after `EvtClose` returns.
    //
    // The raw pointer is wrapped in `SendPtr` so the surrounding
    // async task is `Send`: `*mut` is not `Send` by default, but the
    // callback only dereferences the pointer from Windows' own thread
    // pool and the tokio task only uses it to call `Box::from_raw`
    // after `EvtClose`, which synchronously drains callbacks.
    let ctx_ptr = SendPtr(Box::into_raw(ctx));

    let channel_h = HSTRING::from(channel);
    let query_h = HSTRING::from(query);

    let callback: EVT_SUBSCRIBE_CALLBACK = Some(subscribe_callback);

    let subscription = unsafe {
        EvtSubscribe(
            EVT_HANDLE::default(),
            None,
            PCWSTR(channel_h.as_ptr()),
            PCWSTR(query_h.as_ptr()),
            EVT_HANDLE::default(),
            Some(ctx_ptr.0 as *const c_void),
            callback,
            EvtSubscribeToFutureEvents.0 as u32,
        )
    };

    let subscription = match subscription {
        Ok(handle) => handle,
        Err(e) => {
            // Reclaim the leaked context since Windows never took ownership.
            unsafe { drop(Box::from_raw(ctx_ptr.0)) };
            return Err(anyhow::anyhow!(
                "EvtSubscribe failed for channel {}: {:?}",
                channel,
                e
            ));
        }
    };

    info!(channel = %channel, "event log subscription active");

    let result: anyhow::Result<()> = loop {
        tokio::select! {
            _ = shutdown.wait() => {
                debug!(channel = %channel, "shutdown signal received");
                break Ok(());
            }
            maybe_xml = rx.recv() => {
                match maybe_xml {
                    Some(xml) => {
                        let message = parse_event_message(&xml);
                        let event = Event::new(
                            "logcollector",
                            Priority::Normal,
                            EventKind::LogCollected {
                                source: format!("eventlog:{}", channel),
                                message,
                                format: "eventlog".to_string(),
                            },
                        );
                        if let Err(e) = bus.publish_to_server(event).await {
                            warn!(error = %e, "failed to publish event log event");
                        }
                    }
                    None => break Ok(()),
                }
            }
        }
    };

    // `EvtClose` on a subscription handle synchronously cancels any
    // further callbacks before returning, so it is safe to drop the
    // context afterwards.
    unsafe {
        let _ = EvtClose(subscription);
        drop(Box::from_raw(ctx_ptr.0));
    }

    result
}
