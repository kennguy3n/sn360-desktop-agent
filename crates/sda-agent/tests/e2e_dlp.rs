//! Phase E5.8 — hermetic end-to-end coverage for the EDR DLP module
//! (`sda-dlp`).
//!
//! The DLP module subscribes to `EventKind::FileCreated` /
//! `EventKind::FileModified` events on the in-process `EventBus`,
//! reads a bounded prefix of the underlying file, scans the bytes
//! against the baseline regex set (`pii.ssn`, `pii.uk_ni`,
//! `pci.pan_luhn`), and emits `EventKind::LocalDetectionAlert {
//! rule_type: "dlp" }` events for each finding.
//!
//! This E2E suite drives the module end-to-end against real
//! temp-file contents — no mocks, no PAL fakes. Files are written
//! to a `tempfile::TempDir` and the synthetic FIM event is
//! published onto the bus exactly the way the real `sda-fim`
//! module would publish it.
//!
//! Coverage (≥ 6 tests for `docs/edr.md` § 6 — Data Loss Prevention):
//!
//! 1. Module disabled → no findings even when a juicy file is published.
//! 2. SSN file → emits `pii.ssn` finding with the file path
//!    embedded in the event (NOT the SSN itself).
//! 3. UK NI file → emits `pii.uk_ni` finding.
//! 4. Valid Luhn PAN file → emits `pci.pan_luhn` finding.
//! 5. Clean file → no findings.
//! 6. Multiple categories in one file → multiple findings, each
//!    carries the canonical category id.
//! 7. Redaction invariant: no event payload contains the raw SSN,
//!    PAN, or NI bytes. The fingerprint is a Blake3 hex digest.
//! 8. Enforce mode raises severity from `medium` to `high`.
//! 9. `inspect_file_writes = false` short-circuits scanning.
//! 10. `FileModified` events feed the scanner exactly like
//!     `FileCreated` does.
//! 11. Oversized files are truncated at `max_bytes_per_file`.

#![cfg(unix)]

use std::path::PathBuf;
use std::time::Duration;

use sda_core::config::DlpConfig;
use sda_core::signal::ShutdownController;
use sda_dlp::DlpModule;
use sda_event_bus::{Event, EventBus, EventKind, EventReceiver, Priority};
use tempfile::TempDir;

// ------------------------------------------------------------------ helpers

fn cfg(mode: &str) -> DlpConfig {
    DlpConfig {
        enabled: true,
        mode: mode.to_string(),
        patterns: vec![],
        inspect_file_writes: true,
        inspect_clipboard: false,
        max_bytes_per_file: 2 * 1024 * 1024,
    }
}

fn disabled_cfg() -> DlpConfig {
    let mut c = cfg("monitor");
    c.enabled = false;
    c
}

fn write_file(dir: &TempDir, name: &str, body: &str) -> PathBuf {
    use std::io::Write;
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).expect("create temp file");
    f.write_all(body.as_bytes()).expect("write temp file");
    path
}

fn publish_created(bus: &EventBus, path: &std::path::Path) {
    bus.publish(Event::new(
        "fim",
        Priority::Normal,
        EventKind::FileCreated {
            path: path.display().to_string(),
            syscheck_payload: None,
        },
    ))
    .expect("publish FileCreated");
}

fn publish_modified(bus: &EventBus, path: &std::path::Path) {
    bus.publish(Event::new(
        "fim",
        Priority::Normal,
        EventKind::FileModified {
            path: path.display().to_string(),
            syscheck_payload: None,
        },
    ))
    .expect("publish FileModified");
}

/// Drain DLP findings off the bus for `window`. Returns every
/// `LocalDetectionAlert` event whose `rule_type == "dlp"`.
async fn drain_dlp(rx: &mut EventReceiver, window: Duration) -> Vec<Event> {
    let deadline = tokio::time::Instant::now() + window;
    let mut out = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return out;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(ev)) => {
                if let EventKind::LocalDetectionAlert { rule_type, .. } = &ev.kind {
                    if rule_type == "dlp" {
                        out.push(ev);
                    }
                }
            }
            Ok(None) => return out,
            Err(_) => return out,
        }
    }
}

/// Convenience: pull `rule_id`, `severity`, `description`,
/// `matched_value` from a DLP alert.
fn unwrap_dlp(ev: &Event) -> (String, String, String, String) {
    let EventKind::LocalDetectionAlert {
        rule_id,
        rule_type: _,
        severity,
        description,
        matched_value,
    } = &ev.kind
    else {
        panic!("expected LocalDetectionAlert, got {:?}", ev.kind)
    };
    (
        rule_id.clone(),
        severity.clone(),
        description.clone(),
        matched_value.clone(),
    )
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn t01_disabled_module_emits_no_dlp_findings() {
    let tmp = TempDir::new().unwrap();
    let path = write_file(&tmp, "leak.txt", "patient ssn 123-45-6789\n");

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = DlpModule::start_with_config(disabled_cfg(), bus.clone(), shutdown);

    publish_created(&bus, &path);
    let findings = drain_dlp(&mut rx, Duration::from_millis(200)).await;
    assert!(
        findings.is_empty(),
        "disabled DLP module leaked {} findings",
        findings.len()
    );

    controller.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t02_ssn_file_emits_pii_ssn_finding() {
    let tmp = TempDir::new().unwrap();
    let path = write_file(&tmp, "patient.txt", "patient ssn 123-45-6789\n");

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = DlpModule::start_with_config(cfg("monitor"), bus.clone(), shutdown);

    publish_created(&bus, &path);

    let findings = drain_dlp(&mut rx, Duration::from_secs(2)).await;
    assert_eq!(findings.len(), 1, "expected exactly one DLP alert");
    let (rule_id, severity, description, matched_value) = unwrap_dlp(&findings[0]);
    assert_eq!(rule_id, "dlp.pii.ssn");
    assert_eq!(severity, "medium");
    assert!(description.contains("category=pii.ssn"));
    assert!(matched_value.starts_with(&path.display().to_string()));

    controller.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t03_uk_ni_file_emits_pii_uk_ni_finding() {
    let tmp = TempDir::new().unwrap();
    let path = write_file(&tmp, "hr.csv", "name,ni\nalice,AB123456C\n");

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = DlpModule::start_with_config(cfg("monitor"), bus.clone(), shutdown);

    publish_created(&bus, &path);

    let findings = drain_dlp(&mut rx, Duration::from_secs(2)).await;
    let rule_ids: Vec<_> = findings.iter().map(|e| unwrap_dlp(e).0).collect();
    assert!(
        rule_ids.iter().any(|r| r == "dlp.pii.uk_ni"),
        "no UK NI finding in {rule_ids:?}"
    );

    controller.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t04_valid_luhn_pan_emits_pci_pan_luhn_finding() {
    let tmp = TempDir::new().unwrap();
    let path = write_file(&tmp, "card.txt", "card 4242424242424242 expiry\n");

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = DlpModule::start_with_config(cfg("monitor"), bus.clone(), shutdown);

    publish_created(&bus, &path);

    let findings = drain_dlp(&mut rx, Duration::from_secs(2)).await;
    let pan = findings
        .iter()
        .find(|e| unwrap_dlp(e).0 == "dlp.pci.pan_luhn");
    assert!(pan.is_some(), "expected a PAN finding, got {findings:?}");

    controller.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t05_clean_file_emits_no_findings() {
    let tmp = TempDir::new().unwrap();
    let path = write_file(
        &tmp,
        "readme.txt",
        "This is a regular document with no PII or PCI content.\n",
    );

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = DlpModule::start_with_config(cfg("monitor"), bus.clone(), shutdown);

    publish_created(&bus, &path);
    let findings = drain_dlp(&mut rx, Duration::from_millis(300)).await;
    assert!(
        findings.is_empty(),
        "clean file produced {} findings",
        findings.len()
    );

    controller.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t06_multi_category_file_emits_distinct_findings() {
    let tmp = TempDir::new().unwrap();
    let path = write_file(
        &tmp,
        "dump.txt",
        "ssn 123-45-6789 ni AB123456C card 4242424242424242\n",
    );

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = DlpModule::start_with_config(cfg("monitor"), bus.clone(), shutdown);

    publish_created(&bus, &path);

    let findings = drain_dlp(&mut rx, Duration::from_secs(2)).await;
    let categories: std::collections::HashSet<_> =
        findings.iter().map(|e| unwrap_dlp(e).0).collect();
    for expected in ["dlp.pii.ssn", "dlp.pii.uk_ni", "dlp.pci.pan_luhn"] {
        assert!(
            categories.contains(expected),
            "missing {expected} in {categories:?}"
        );
    }

    controller.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t07_redaction_invariant_no_raw_bytes_in_event_payload() {
    let tmp = TempDir::new().unwrap();
    let ssn = "123-45-6789";
    let ni = "AB123456C";
    let pan = "4242424242424242";
    let path = write_file(&tmp, "leak.txt", &format!("ssn={ssn} ni={ni} card={pan}\n"));

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = DlpModule::start_with_config(cfg("monitor"), bus.clone(), shutdown);

    publish_created(&bus, &path);
    let findings = drain_dlp(&mut rx, Duration::from_secs(2)).await;
    assert!(!findings.is_empty(), "expected at least one finding");

    for ev in &findings {
        let (_, _, description, matched_value) = unwrap_dlp(ev);
        for raw in [ssn, ni, pan] {
            assert!(
                !description.contains(raw),
                "description leaked raw bytes ({raw}): {description}"
            );
            assert!(
                !matched_value.contains(raw),
                "matched_value leaked raw bytes ({raw}): {matched_value}"
            );
        }
        // The fingerprint embedded in matched_value is a hex Blake3
        // digest; check it's >=16 hex chars after the `#`.
        let fp = matched_value.split('#').nth(1).unwrap_or("");
        assert!(
            fp.len() >= 16 && fp.chars().all(|c| c.is_ascii_hexdigit()),
            "fingerprint malformed: {fp:?}"
        );
    }

    controller.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t08_enforce_mode_raises_severity_to_high() {
    let tmp = TempDir::new().unwrap();
    let path = write_file(&tmp, "leak.txt", "patient ssn 123-45-6789\n");

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = DlpModule::start_with_config(cfg("enforce"), bus.clone(), shutdown);

    publish_created(&bus, &path);
    let findings = drain_dlp(&mut rx, Duration::from_secs(2)).await;
    assert_eq!(findings.len(), 1);
    let (_, severity, _, _) = unwrap_dlp(&findings[0]);
    assert_eq!(severity, "high");

    controller.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t09_inspect_file_writes_disabled_short_circuits() {
    let tmp = TempDir::new().unwrap();
    let path = write_file(&tmp, "leak.txt", "patient ssn 123-45-6789\n");

    let mut c = cfg("monitor");
    c.inspect_file_writes = false;

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = DlpModule::start_with_config(c, bus.clone(), shutdown);

    publish_created(&bus, &path);
    let findings = drain_dlp(&mut rx, Duration::from_millis(200)).await;
    assert!(
        findings.is_empty(),
        "inspect_file_writes=false leaked {} findings",
        findings.len()
    );

    controller.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t10_file_modified_event_feeds_scanner() {
    let tmp = TempDir::new().unwrap();
    let path = write_file(&tmp, "leak.txt", "patient ssn 123-45-6789\n");

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = DlpModule::start_with_config(cfg("monitor"), bus.clone(), shutdown);

    publish_modified(&bus, &path);

    let findings = drain_dlp(&mut rx, Duration::from_secs(2)).await;
    assert_eq!(findings.len(), 1, "FileModified should feed the scanner");
    let (rule_id, _, _, _) = unwrap_dlp(&findings[0]);
    assert_eq!(rule_id, "dlp.pii.ssn");

    controller.shutdown();
    let _ = handle.task.await;
}

#[tokio::test]
async fn t11_oversized_file_is_truncated_to_max_bytes_per_file() {
    let tmp = TempDir::new().unwrap();
    // Place the SSN AFTER the configured byte limit. With
    // `max_bytes_per_file = 32` the SSN never gets scanned, so no
    // finding should appear.
    let body = format!("{}123-45-6789\n", "x".repeat(64));
    let path = write_file(&tmp, "huge.txt", &body);

    let mut c = cfg("monitor");
    c.max_bytes_per_file = 32;

    let (bus, _) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = DlpModule::start_with_config(c, bus.clone(), shutdown);

    publish_created(&bus, &path);
    let findings = drain_dlp(&mut rx, Duration::from_millis(300)).await;
    assert!(
        findings.is_empty(),
        "scanner read past max_bytes_per_file: {} findings",
        findings.len()
    );

    controller.shutdown();
    let _ = handle.task.await;
}
