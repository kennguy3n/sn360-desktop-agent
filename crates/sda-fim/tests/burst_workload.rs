//! Burst-workload integration tests for the real-time FIM pipeline.
//!
//! These tests exercise the lazy-hashing / rate-limiting / batching
//! path added to keep FIM peak CPU under 3% during rapid bursts.

use std::time::{Duration, Instant};

use tempfile::TempDir;
use tokio::time::timeout;

use sda_core::config::{AgentConfig, FimConfig, FimDirectory, ModulesConfig};
use sda_core::power::{channel as power_channel, PowerProfile};
use sda_core::signal::ShutdownController;
use sda_event_bus::{EventBus, EventKind};
use sda_fim::FimModule;

/// Build an `AgentConfig` that applies production-style rate limiting
/// and batching so the test actually exercises those paths.
fn burst_test_config(dir: &str) -> AgentConfig {
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
                scan_interval: 86400,
                debounce_ms: 50,
                max_hashes_per_sec: 100,
                batch_size: 50,
                batch_timeout_ms: 200,
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Create `count` files in `dir` and measure how long the loop takes.
///
/// Returns the wall-clock duration for the whole burst so tests can
/// assert the FIM pipeline didn't block the caller.
fn create_files_burst(dir: &std::path::Path, count: usize) -> Duration {
    let start = Instant::now();
    for i in 0..count {
        let path = dir.join(format!("burst_{i:04}.txt"));
        // Write a small, unique payload so hashes differ per file.
        let _ = std::fs::write(&path, format!("burst file {i} content"));
    }
    start.elapsed()
}

/// A 1000-file burst must not block the agent's async event loop.
///
/// The real assertion is that our test task (which represents
/// keepalive / other async work sharing the runtime) keeps making
/// progress on a 100 ms cadence even while the FIM module is busy
/// processing the burst. If the FIM run loop were still computing
/// hashes inline, those ticks would slip by hundreds of ms.
#[cfg_attr(
    target_os = "macos",
    ignore = "kqueue may drop events under burst load on macOS CI; see docs/known-issues/fim-burst-workload-macos-ci.md"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_burst_does_not_block_event_loop() {
    let tmp = TempDir::new().unwrap();
    let canon = tmp.path().canonicalize().unwrap();
    let config = burst_test_config(canon.to_str().unwrap());

    let (bus, mut server_rx) = EventBus::new(4096, 4096);
    let (controller, signal) = ShutdownController::new();
    let (_power_tx, power_rx) = power_channel(PowerProfile::Normal);

    let _handle = FimModule::start(&config, bus, signal, power_rx);

    // Let the watcher register.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Drain any startup baseline-scan events so they don't skew
    // our timing assertions.
    while let Ok(Some(_)) = timeout(Duration::from_millis(300), server_rx.recv()).await {}

    // Parallel "keepalive" task that ticks every 100 ms. We record
    // each tick's timestamp so we can verify the cadence.
    let ticks = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<Instant>::new()));
    let ticks_clone = std::sync::Arc::clone(&ticks);
    let keepalive_done = std::sync::Arc::new(tokio::sync::Notify::new());
    let keepalive_done_clone = std::sync::Arc::clone(&keepalive_done);
    let keepalive = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        // Skip the first immediate tick.
        interval.tick().await;
        for _ in 0..30 {
            interval.tick().await;
            ticks_clone.lock().await.push(Instant::now());
        }
        keepalive_done_clone.notify_one();
    });

    // Create 1000 files as fast as we can.
    let burst_start = Instant::now();
    let burst_dir = tmp.path().to_path_buf();
    let burst_duration = tokio::task::spawn_blocking(move || create_files_burst(&burst_dir, 1_000))
        .await
        .expect("burst file-creation task panicked");
    // The file-creation loop itself is synchronous std::fs work
    // running on the test thread; the FIM runtime should not have
    // added noticeable back-pressure.
    assert!(
        burst_duration < Duration::from_secs(10),
        "creating 1000 files took {burst_duration:?}, pipeline is likely blocking"
    );

    // Wait for the keepalive task to finish recording ticks.
    let _ = timeout(Duration::from_secs(15), keepalive_done.notified()).await;
    keepalive.abort();

    let ticks = ticks.lock().await.clone();
    assert!(
        ticks.len() >= 20,
        "keepalive task didn't fire enough times during the burst: {} ticks",
        ticks.len()
    );

    // Inter-tick intervals should be close to 100 ms. Allow some
    // slack (500 ms worst case) but not multi-second stalls.
    for window in ticks.windows(2) {
        let gap = window[1] - window[0];
        assert!(
            gap < Duration::from_millis(750),
            "keepalive stalled for {:?} between ticks, FIM likely blocked the event loop",
            gap
        );
    }

    // Drain events over a generous window so the lazy hashes have
    // time to complete.
    let drain_start = Instant::now();
    let mut events = 0usize;
    let mut hashed = 0usize;
    while drain_start.elapsed() < Duration::from_secs(30) {
        match timeout(Duration::from_millis(500), server_rx.recv()).await {
            Ok(Some(event)) => {
                events += 1;
                let payload = match &event.kind {
                    EventKind::FileCreated {
                        syscheck_payload, ..
                    }
                    | EventKind::FileModified {
                        syscheck_payload, ..
                    } => syscheck_payload.as_deref(),
                    _ => None,
                };
                if let Some(p) = payload {
                    if p.contains("hash_sha256") {
                        hashed += 1;
                    }
                }
                if hashed >= 500 {
                    break;
                }
            }
            _ => {
                if hashed > 0 {
                    break;
                }
            }
        }
    }

    let _ = burst_start;
    assert!(
        events >= 500,
        "expected at least 500 FIM events across metadata+hash phases, got {events}"
    );
    assert!(
        hashed >= 100,
        "expected at least 100 hashed follow-up events, got {hashed} (rate limiter should still let hashes through)"
    );

    controller.shutdown();
}

/// Ensure that a file creation produces two events: a metadata-only
/// event with `hash_sha256` absent, followed by a follow-up event
/// with the hash populated.
#[tokio::test]
async fn test_two_phase_emission_metadata_then_hash() {
    let tmp = TempDir::new().unwrap();
    let canon = tmp.path().canonicalize().unwrap();
    let config = burst_test_config(canon.to_str().unwrap());

    let (bus, mut server_rx) = EventBus::new(256, 256);
    let (controller, signal) = ShutdownController::new();
    let (_power_tx, power_rx) = power_channel(PowerProfile::Normal);

    let _handle = FimModule::start(&config, bus, signal, power_rx);

    // Wait for watcher to register.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Drain any startup events.
    while let Ok(Some(_)) = timeout(Duration::from_millis(300), server_rx.recv()).await {}

    let file_path = tmp.path().join("two_phase.txt");
    std::fs::write(&file_path, "two-phase content").unwrap();

    // Collect events for up to 5 seconds.
    let mut saw_metadata_only = false;
    let mut saw_hash = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && (!saw_metadata_only || !saw_hash) {
        match timeout(Duration::from_millis(500), server_rx.recv()).await {
            Ok(Some(event)) => {
                let payload = match &event.kind {
                    EventKind::FileCreated {
                        syscheck_payload,
                        path,
                    }
                    | EventKind::FileModified {
                        syscheck_payload,
                        path,
                    }
                    | EventKind::FileMetadataChanged {
                        syscheck_payload,
                        path,
                    } => {
                        if !path.contains("two_phase.txt") {
                            continue;
                        }
                        syscheck_payload.as_deref()
                    }
                    _ => None,
                };
                let Some(p) = payload else { continue };
                if p.contains("hash_sha256") {
                    saw_hash = true;
                } else {
                    saw_metadata_only = true;
                }
            }
            _ => continue,
        }
    }

    assert!(
        saw_metadata_only,
        "expected a metadata-only event (hash_sha256 absent) before the hash was ready"
    );
    assert!(
        saw_hash,
        "expected a follow-up event with hash_sha256 populated"
    );

    controller.shutdown();
}
