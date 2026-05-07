//! Minimal harness that runs only the FIM module so we can benchmark
//! its CPU footprint under a burst of file creations.
//!
//! Usage:
//!   cargo run --release --example burst_watcher -p sda-fim -- /tmp/sda-bench-fim
//!
//! The process watches the directory given on the command line (or
//! `/tmp/sda-bench-fim` if none is provided), drains every event it
//! receives from the internal event bus, and runs until SIGINT /
//! SIGTERM. `tests/scripts/fim-burst-bench.sh` drives this harness
//! with pidstat to capture peak %CPU during a 1000-file burst.

use std::time::Duration;

use tokio::signal;

use sda_core::config::{AgentConfig, FimConfig, FimDirectory, ModulesConfig};
use sda_core::power::{channel as power_channel, PowerProfile};
use sda_core::signal::ShutdownController;
use sda_event_bus::EventBus;
use sda_fim::FimModule;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let watch = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/sda-bench-fim".to_string());

    let config = AgentConfig {
        modules: ModulesConfig {
            fim: FimConfig {
                enabled: true,
                directories: vec![FimDirectory {
                    path: watch.clone(),
                    recursive: true,
                    realtime: true,
                    check_sha256: true,
                    exclude: Vec::new(),
                }],
                scan_interval: 86_400,
                debounce_ms: 100,
                max_hashes_per_sec: 100,
                batch_size: 50,
                batch_timeout_ms: 200,
            },
            ..Default::default()
        },
        ..Default::default()
    };

    std::fs::create_dir_all(&watch).ok();

    let (bus, mut server_rx) = EventBus::new(4096, 4096);
    let (controller, shutdown) = ShutdownController::new();
    let (_power_tx, power_rx) = power_channel(PowerProfile::Normal);

    let _handle = FimModule::start(&config, bus, shutdown, power_rx);
    eprintln!("burst_watcher: watching {watch} (press Ctrl-C to stop)");

    // Drain the server queue on a separate task so events don't back
    // up in the bus.
    let drain = tokio::spawn(async move {
        let mut count = 0usize;
        let mut last_report = tokio::time::Instant::now();
        while let Some(_event) = server_rx.recv().await {
            count += 1;
            if last_report.elapsed() >= Duration::from_secs(1) {
                eprintln!("burst_watcher: {count} events so far");
                last_report = tokio::time::Instant::now();
            }
        }
        count
    });

    signal::ctrl_c().await.ok();
    eprintln!("burst_watcher: shutting down");
    controller.shutdown();
    drain.abort();
    Ok(())
}
