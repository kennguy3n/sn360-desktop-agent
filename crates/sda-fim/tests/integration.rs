//! Integration tests for the FIM module.
//!
//! Tests the full pipeline: watch a temp directory, create/modify/delete files,
//! and verify the correct events appear on the EventBus.

use std::time::Duration;

use tempfile::TempDir;
use tokio::time::timeout;

use sda_core::config::{AgentConfig, FimConfig, FimDirectory};
use sda_core::power::{channel as power_channel, PowerProfile};
use sda_core::signal::ShutdownController;
use sda_event_bus::{EventBus, EventKind};

fn test_config(dir: &TempDir) -> AgentConfig {
    let mut config = AgentConfig::default();
    config.modules.fim = FimConfig {
        enabled: true,
        directories: vec![FimDirectory {
            path: dir.path().to_string_lossy().to_string(),
            recursive: true,
            realtime: true,
            check_sha256: true,
            exclude: Vec::new(),
        }],
        scan_interval: 86400,
        debounce_ms: 50, // short debounce for tests
        max_hashes_per_sec: 1000,
        batch_size: 1,
        batch_timeout_ms: 50,
    };
    config
}

#[tokio::test]
async fn test_fim_detects_file_creation() {
    let dir = TempDir::new().unwrap();
    let config = test_config(&dir);

    let (bus, mut server_rx) = EventBus::new(256, 256);
    let (shutdown_controller, _shutdown_signal) = ShutdownController::new();
    let shutdown = shutdown_controller.subscribe();
    let (_power_tx, power_rx) = power_channel(PowerProfile::Normal);

    let _handle = sda_fim::FimModule::start(&config, bus, shutdown, power_rx);

    // Give the watcher time to register.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create a file.
    let file_path = dir.path().join("hello.txt");
    std::fs::write(&file_path, "hello world").unwrap();

    // Wait for a FileCreated event on the server queue.
    let event = timeout(Duration::from_secs(10), server_rx.recv())
        .await
        .expect("should receive event within timeout")
        .expect("channel should not be closed");

    assert_eq!(event.source, "fim");
    // The OS may deliver a Created followed by a Modified (due to the write),
    // or just a Modified if the watcher debounce collapses them.  Accept either.
    match &event.kind {
        EventKind::FileCreated { path, .. } | EventKind::FileModified { path, .. } => {
            assert!(
                path.contains("hello.txt"),
                "expected path to contain 'hello.txt', got: {path}"
            );
        }
        other => panic!("expected FileCreated or FileModified, got: {other:?}"),
    }

    shutdown_controller.shutdown();
}

#[tokio::test]
async fn test_fim_detects_file_modification() {
    let dir = TempDir::new().unwrap();
    let config = test_config(&dir);

    let (bus, mut server_rx) = EventBus::new(256, 256);
    let (shutdown_controller, _shutdown_signal) = ShutdownController::new();
    let shutdown = shutdown_controller.subscribe();
    let (_power_tx, power_rx) = power_channel(PowerProfile::Normal);

    let _handle = sda_fim::FimModule::start(&config, bus, shutdown, power_rx);

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create and then modify.
    let file_path = dir.path().join("modify_me.txt");
    std::fs::write(&file_path, "original").unwrap();

    // Drain the creation event(s).
    let _ = timeout(Duration::from_secs(10), server_rx.recv()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Now modify.
    std::fs::write(&file_path, "modified content").unwrap();

    // Look for a FileModified event.
    let mut found_modified = false;
    for _ in 0..10 {
        match timeout(Duration::from_secs(5), server_rx.recv()).await {
            Ok(Some(event)) => {
                if matches!(&event.kind, EventKind::FileModified { .. }) {
                    found_modified = true;
                    break;
                }
            }
            _ => break,
        }
    }
    assert!(found_modified, "expected a FileModified event");

    shutdown_controller.shutdown();
}

#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "kqueue does not reliably deliver file deletion events on macOS CI"
)]
async fn test_fim_detects_file_deletion() {
    let dir = TempDir::new().unwrap();
    let config = test_config(&dir);

    let (bus, mut server_rx) = EventBus::new(256, 256);
    let (shutdown_controller, _shutdown_signal) = ShutdownController::new();
    let shutdown = shutdown_controller.subscribe();
    let (_power_tx, power_rx) = power_channel(PowerProfile::Normal);

    let _handle = sda_fim::FimModule::start(&config, bus, shutdown, power_rx);

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create and then delete.
    let file_path = dir.path().join("delete_me.txt");
    std::fs::write(&file_path, "temporary").unwrap();

    // Drain creation event(s).
    let _ = timeout(Duration::from_secs(10), server_rx.recv()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    std::fs::remove_file(&file_path).unwrap();

    // Look for a FileDeleted event.
    let mut found_deleted = false;
    for _ in 0..10 {
        match timeout(Duration::from_secs(5), server_rx.recv()).await {
            Ok(Some(event)) => {
                if matches!(&event.kind, EventKind::FileDeleted { .. }) {
                    found_deleted = true;
                    break;
                }
            }
            _ => break,
        }
    }
    assert!(found_deleted, "expected a FileDeleted event");

    shutdown_controller.shutdown();
}

#[tokio::test]
async fn test_fim_clean_shutdown() {
    let dir = TempDir::new().unwrap();
    let config = test_config(&dir);

    let (bus, _server_rx) = EventBus::new(256, 256);
    let (shutdown_controller, _shutdown_signal) = ShutdownController::new();
    let shutdown = shutdown_controller.subscribe();
    let (_power_tx, power_rx) = power_channel(PowerProfile::Normal);

    let handle = sda_fim::FimModule::start(&config, bus, shutdown, power_rx);

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Trigger shutdown.
    shutdown_controller.shutdown();

    // The task should complete within a reasonable timeout.
    let result = timeout(Duration::from_secs(5), handle.task).await;
    assert!(result.is_ok(), "FIM task should complete after shutdown");
    let inner = result.unwrap();
    assert!(inner.is_ok(), "FIM task should not panic");
}
