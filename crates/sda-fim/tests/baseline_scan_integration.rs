//! Integration test for the FIM baseline scanner.
//!
//! Starts the FIM module with a short scan interval, creates/modifies/deletes
//! files, and verifies the correct events are published.

use std::time::Duration;

use sda_core::config::{AgentConfig, FimConfig, FimDirectory, ModulesConfig};
use sda_core::power::{channel as power_channel, PowerProfile};
use sda_core::signal::ShutdownController;
use sda_event_bus::{EventBus, EventKind};
use sda_fim::FimModule;
use tempfile::TempDir;

fn test_config(dir: &str, scan_interval: u64) -> AgentConfig {
    AgentConfig {
        modules: ModulesConfig {
            fim: FimConfig {
                enabled: true,
                directories: vec![FimDirectory {
                    path: dir.to_string(),
                    recursive: true,
                    realtime: true,
                    check_sha256: true,
                    exclude: Vec::new(),
                }],
                scan_interval,
                debounce_ms: 50,
                max_hashes_per_sec: 1000,
                batch_size: 1,
                batch_timeout_ms: 50,
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Drain all events from the server channel within a timeout window.
async fn collect_events(
    server_rx: &mut tokio::sync::mpsc::Receiver<sda_event_bus::Event>,
    timeout: Duration,
) -> Vec<sda_event_bus::Event> {
    let mut events = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, server_rx.recv()).await {
            Ok(Some(ev)) => events.push(ev),
            _ => break,
        }
    }
    events
}

#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "kqueue does not reliably deliver file deletion events on macOS CI"
)]
async fn test_baseline_scan_lifecycle() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_str().unwrap();

    // Create files before starting FIM.
    std::fs::write(tmp.path().join("pre1.txt"), "pre-existing 1").unwrap();
    std::fs::write(tmp.path().join("pre2.txt"), "pre-existing 2").unwrap();

    // Use a 3-second scan interval for fast testing.
    let config = test_config(dir, 3);
    let (bus, mut server_rx) = EventBus::new(512, 512);
    let (controller, signal) = ShutdownController::new();
    let (_power_tx, power_rx) = power_channel(PowerProfile::Normal);

    let _handle = FimModule::start(&config, bus, signal, power_rx);

    // Wait for the initial baseline scan to complete (should run on startup).
    // Collect events over a generous window.
    let events = collect_events(&mut server_rx, Duration::from_secs(8)).await;

    // We should have FileCreated events for the pre-existing files (from the
    // initial baseline scan) plus the fim.db file is inside the watched dir
    // — but it may or may not appear depending on timing. Check for at least
    // the two we created.
    let created_paths: Vec<String> = events
        .iter()
        .filter_map(|e| match &e.kind {
            EventKind::FileCreated { path, .. } => Some(path.clone()),
            _ => None,
        })
        .collect();

    assert!(
        created_paths.iter().any(|p| p.contains("pre1.txt")),
        "should detect pre1.txt as new; events: {:?}",
        created_paths
    );
    assert!(
        created_paths.iter().any(|p| p.contains("pre2.txt")),
        "should detect pre2.txt as new; events: {:?}",
        created_paths
    );

    // Verify syscheck payloads are present and valid JSON.
    for ev in &events {
        if let EventKind::FileCreated {
            syscheck_payload, ..
        } = &ev.kind
        {
            let payload = syscheck_payload
                .as_ref()
                .expect("syscheck_payload should be present");
            let parsed: serde_json::Value =
                serde_json::from_str(payload).expect("should be valid JSON");
            assert_eq!(parsed["type"], "event");
        }
    }

    // Modify a file and wait for the next scan cycle.
    std::fs::write(tmp.path().join("pre1.txt"), "modified content here").unwrap();
    let events2 = collect_events(&mut server_rx, Duration::from_secs(8)).await;

    let modified_paths: Vec<String> = events2
        .iter()
        .filter_map(|e| match &e.kind {
            EventKind::FileModified { path, .. } => Some(path.clone()),
            _ => None,
        })
        .collect();

    // The modification might be caught by the real-time watcher or the next
    // baseline scan. Either way we should see a modification event.
    assert!(
        modified_paths.iter().any(|p| p.contains("pre1.txt"))
            || events2.iter().any(|e| matches!(
                &e.kind,
                EventKind::FileCreated { path, .. }
                | EventKind::FileMetadataChanged { path, .. }
                if path.contains("pre1.txt")
            )),
        "should detect pre1.txt modification; events: {:?}",
        events2
            .iter()
            .map(|e| format!("{:?}", e.kind))
            .collect::<Vec<_>>()
    );

    // Delete a file and wait for the next scan.
    std::fs::remove_file(tmp.path().join("pre2.txt")).unwrap();
    let events3 = collect_events(&mut server_rx, Duration::from_secs(8)).await;

    let deleted_paths: Vec<String> = events3
        .iter()
        .filter_map(|e| match &e.kind {
            EventKind::FileDeleted { path, .. } => Some(path.clone()),
            _ => None,
        })
        .collect();

    assert!(
        deleted_paths.iter().any(|p| p.contains("pre2.txt")),
        "should detect pre2.txt deletion; events: {:?}",
        events3
            .iter()
            .map(|e| format!("{:?}", e.kind))
            .collect::<Vec<_>>()
    );

    controller.shutdown();
}
