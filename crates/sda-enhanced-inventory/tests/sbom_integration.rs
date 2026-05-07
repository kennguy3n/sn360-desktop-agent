//! Integration tests for the CycloneDX SBOM generator (task 4.9).
//!
//! These exercise [`generate_sbom`] end-to-end against the live host
//! and verify the CycloneDX envelope is well-formed. They also drive
//! the `EnhancedInventoryModule` lifecycle with SBOM enabled to prove
//! the timer fires and publishes an `EventKind::EnhancedInventoryUpdate`
//! of category `"sbom"` on the bus.

use std::time::Duration;

use sda_core::config::AgentConfig;
use sda_core::power::{channel as power_channel, PowerProfile};
use sda_core::signal::ShutdownController;
use sda_enhanced_inventory::sbom::{generate_sbom, SPEC_VERSION};
use sda_enhanced_inventory::EnhancedInventoryModule;
use sda_event_bus::{EventBus, EventKind};

fn test_config() -> AgentConfig {
    let mut cfg = AgentConfig::default();
    cfg.modules.enhanced_inventory.enabled = true;
    // Keep running-software and browser-extensions enabled but at a
    // long interval so the SBOM event is easy to observe in isolation.
    cfg.modules.enhanced_inventory.running_software.enabled = true;
    cfg.modules.enhanced_inventory.running_software.interval = 3600;
    cfg.modules.enhanced_inventory.browser_extensions.enabled = true;
    cfg.modules.enhanced_inventory.browser_extensions.interval = 3600;
    // SBOM fires once on startup; the timer interval is irrelevant
    // because the test only observes the baseline snapshot.
    cfg.modules.enhanced_inventory.sbom.enabled = true;
    cfg.modules.enhanced_inventory.sbom.interval = 86_400;
    cfg.modules.enhanced_inventory.sbom.on_demand = true;
    cfg
}

#[tokio::test]
async fn generate_sbom_produces_parseable_cyclonedx_document() {
    // Run the blocking generator off the async worker the way the
    // module itself does.
    let bom = tokio::task::spawn_blocking(generate_sbom)
        .await
        .expect("generate_sbom task panicked");

    assert_eq!(bom["bomFormat"], "CycloneDX");
    assert_eq!(bom["specVersion"], SPEC_VERSION);
    assert_eq!(bom["version"], 1);

    // A CycloneDX consumer must be able to re-parse the document from
    // raw bytes, so serialize-then-deserialize through the wire
    // format.
    let bytes = serde_json::to_vec(&bom).expect("SBOM must serialize to JSON");
    let parsed: serde_json::Value =
        serde_json::from_slice(&bytes).expect("SBOM must round-trip through JSON");
    assert_eq!(parsed["bomFormat"], "CycloneDX");
    assert_eq!(parsed["specVersion"], SPEC_VERSION);
    assert!(parsed["components"].is_array());

    let serial = parsed["serialNumber"].as_str().expect("serialNumber");
    assert!(
        serial.starts_with("urn:uuid:"),
        "serialNumber must be a urn:uuid; got {serial}"
    );

    let tools = parsed["metadata"]["tools"]
        .as_array()
        .expect("metadata.tools array");
    assert!(!tools.is_empty());
    assert_eq!(tools[0]["name"], "sda-enhanced-inventory");

    // Every component must at minimum carry `type` and `name` —
    // CycloneDX 1.5 marks both fields as required.
    for c in parsed["components"].as_array().unwrap() {
        assert!(c["type"].is_string(), "component missing type: {c:?}");
        assert!(c["name"].is_string(), "component missing name: {c:?}");
    }
}

#[tokio::test]
async fn module_lifecycle_publishes_sbom_snapshot() {
    let cfg = test_config();
    let (controller, signal) = ShutdownController::new();
    let (bus, mut server_rx) = EventBus::new(32, 32);
    let (_power_tx, power_rx) = power_channel(PowerProfile::Normal);

    let handle = EnhancedInventoryModule::start(&cfg, bus, signal, power_rx);

    // Collect events until either the SBOM snapshot arrives or the
    // deadline expires. On Linux/macOS CI the startup path fires the
    // SBOM tick within ~1s, but on Windows the CycloneDX generator
    // walks installed software + browser extensions + the process
    // list synchronously and can take ~150s on a cold GitHub-hosted
    // runner (see `sbom::tests::test_generate_sbom_does_not_panic_on_host`
    // which routinely reports >60s on the same runner image). We
    // therefore pick a deadline comfortably above the observed worst
    // case so the test stays meaningful on every platform.
    let mut saw_sbom = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(240);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(250), server_rx.recv()).await {
            Ok(Some(event)) => {
                if let EventKind::EnhancedInventoryUpdate { category, data } = event.kind {
                    if category == "sbom" {
                        assert_eq!(data["type"], "snapshot");
                        assert!(
                            data["components"].is_u64() || data["components"].is_i64(),
                            "expected numeric component count, got {:?}",
                            data["components"]
                        );
                        let bom = &data["bom"];
                        assert_eq!(bom["bomFormat"], "CycloneDX");
                        assert_eq!(bom["specVersion"], SPEC_VERSION);
                        saw_sbom = true;
                        break;
                    }
                }
            }
            Ok(None) => break,  // channel closed
            Err(_) => continue, // timeout, keep polling
        }
    }

    controller.shutdown();
    // `spawn_blocking(generate_sbom)` is not cancellable, so if the
    // collect loop above gave up before the snapshot arrived the task
    // is still inside the CycloneDX walk when shutdown is signalled.
    // Pick a cap that matches the event deadline so we only fail on
    // an actual shutdown deadlock, not on a slow (but completing)
    // SBOM walk.
    tokio::time::timeout(Duration::from_secs(240), handle.task)
        .await
        .expect("enhanced inventory task did not stop within 240s")
        .expect("join error")
        .expect("enhanced inventory run returned Err");

    assert!(
        saw_sbom,
        "expected at least one sbom EnhancedInventoryUpdate event during module startup"
    );
}

#[tokio::test]
async fn module_lifecycle_with_sbom_disabled_does_not_publish_sbom() {
    let mut cfg = test_config();
    cfg.modules.enhanced_inventory.sbom.enabled = false;
    // Also disable running-software / browser-extensions so the
    // server queue stays quiet.
    cfg.modules.enhanced_inventory.running_software.enabled = false;
    cfg.modules.enhanced_inventory.browser_extensions.enabled = false;

    let (controller, signal) = ShutdownController::new();
    let (bus, mut server_rx) = EventBus::new(16, 16);
    let (_power_tx, power_rx) = power_channel(PowerProfile::Normal);

    let handle = EnhancedInventoryModule::start(&cfg, bus, signal, power_rx);

    // Give the module enough wall time to perform any initial work.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut unexpected: Vec<String> = Vec::new();
    while let Ok(event) = server_rx.try_recv() {
        if let EventKind::EnhancedInventoryUpdate { category, .. } = event.kind {
            unexpected.push(category);
        }
    }
    assert!(
        unexpected.is_empty(),
        "no EnhancedInventoryUpdate events expected when SBOM is disabled and other collectors are off, got: {unexpected:?}"
    );

    controller.shutdown();
    // SBOM is disabled in this variant and the other collectors are
    // turned off too, so the task should exit promptly. Match the
    // upper bound used by the SBOM-enabled variant so both tests
    // apply the same "is the shutdown path deadlocked?" gate.
    tokio::time::timeout(Duration::from_secs(240), handle.task)
        .await
        .expect("task did not stop within 240s")
        .expect("join error")
        .expect("run returned Err");
}
