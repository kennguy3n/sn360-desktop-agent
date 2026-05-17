//! Phase 2 software end-to-end suite (PHASES.md task 2.15).
//!
//! Hermetic exercises of the software-orchestration surfaces shipped
//! in Phase 2 (catalogue verification, maintenance windows, software
//! evidence emission, rollback, approval-state surfacing, script
//! runner). The harness reuses the in-process [`EventBus`] so every
//! scenario walks the same wire shape the supervisor publishes in
//! `sda-agent::main`.
//!
//! Coverage:
//!
//! 1. Catalogue verifier rejects manifests signed under the wrong
//!    pinned key with `ManifestError::SignatureMismatch`
//!    (PHASES.md task 2.6).
//! 2. The maintenance-window policy returns `Defer` for jobs landing
//!    outside the configured allow-list (PHASES.md task 2.8).
//! 3. A successful install/update/uninstall sequence emits one
//!    chain-linked `EvidenceRecord` per action and the chain head
//!    matches `prev_record_hash` of the next record
//!    (PHASES.md task 2.11).
//! 4. A failed `UpdatePackage` triggers an automatic re-install of
//!    the previously-installed version and emits two chain-linked
//!    evidence records sharing the same `job_id` but with distinct
//!    `evidence_id`s (PHASES.md task 2.10).
//! 5. An installed package whose catalogue state is `Pending` lands
//!    on the bus as a `DeviceControlRecommendation` with the
//!    plain-English text from `sda-software` (PHASES.md task 2.9).
//! 6. The script runner accepts a properly-signed script, refuses
//!    one whose signature does not verify, and kills a runaway
//!    script when the wall-clock budget elapses
//!    (PHASES.md task 2.7).
//!
//! All scenarios run on in-process state (mock `PackageManager`,
//! tempdirs, in-process bus). `make e2e-software` runs in
//! milliseconds on every CI host.

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sda_core::config::{MaintenanceWindow, QuietHours};
use sda_device_control::action_result::ActionResult;
use sda_device_control::evidence::FIRST_RECORD_PREV_HASH;
use sda_device_control::signed_job::SignedActionJob;
use sda_device_control::types::{
    ActionKind, ActionStatus, AgentVersion, Platform, PlatformArch, PlatformOs,
};
use sda_device_control::windows::{MaintenanceWindowPolicy, WindowDecision};
use sda_device_control::{ACTION_RESULT_SCHEMA_VERSION, SIGNED_ACTION_JOB_SCHEMA_VERSION};
use sda_event_bus::{Event, EventBus, EventKind, EventReceiver, Priority};
use sda_pal::package_manager::{
    InstallOpts, InstalledPackage as PalInstalledPackage, PackageError, PackageManager, PackageRef,
};
use sda_script_runner::runner::{
    truncation_reason, ScriptRequest, ScriptRunner, ScriptRunnerConfig, ScriptRunnerError,
};
use sda_software::approval::InstalledPackage as ApprovalInstalledPackage;
use sda_software::{
    build_recommendation_payload, ApprovalAuditor, ApprovalState, Artefact, CatalogueStore,
    Manifest, ManifestError, RollbackOrchestrator, SoftwareActionOutcome, SoftwareEvidenceEmitter,
    MANIFEST_SCHEMA_VERSION,
};
use serde_json::json;
use tempfile::TempDir;
use uuid::Uuid;

// ---------- Test harness ---------------------------------------------------

/// Receive-with-timeout that fails the calling test instead of
/// hanging if the bus never produces a matching event. Mirrors the
/// helper in `e2e_device_control.rs` so the two suites have the
/// same diagnostic UX.
async fn recv_one(rx: &mut EventReceiver) -> Event {
    tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("event bus did not produce an event within the 2s budget")
        .expect("event bus closed before producing an event")
}

fn fixed_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 7, 8, 30, 0).unwrap()
}

fn test_platform() -> Platform {
    Platform {
        os: PlatformOs::Linux,
        version: "24.04".into(),
        arch: PlatformArch::X86_64,
        distro: Some("ubuntu".into()),
    }
}

fn test_agent() -> AgentVersion {
    AgentVersion {
        version: env!("CARGO_PKG_VERSION").into(),
        build_sha: "e2e".into(),
        channel: "test".into(),
    }
}

fn test_job(action: ActionKind, args: serde_json::Value) -> SignedActionJob {
    SignedActionJob {
        job_id: Uuid::from_u128(0xA1),
        tenant_id: Uuid::from_u128(0x71),
        device_id: Uuid::from_u128(0xD1),
        schema_version: SIGNED_ACTION_JOB_SCHEMA_VERSION,
        recommendation_id: None,
        action,
        args,
        not_before: Utc.with_ymd_and_hms(2026, 5, 7, 8, 0, 0).unwrap(),
        not_after: Utc.with_ymd_and_hms(2026, 5, 7, 9, 0, 0).unwrap(),
        signature: vec![0; 64],
        key_id: "sn360-control-2026-05".into(),
        correlation_id: None,
        additional_signatures: Vec::new(),
    }
}

fn ok_result_for(job: &SignedActionJob, exit_code: i32) -> ActionResult {
    let started = fixed_now();
    let finished = started + chrono::Duration::seconds(7);
    ActionResult {
        job_id: job.job_id,
        tenant_id: job.tenant_id,
        device_id: job.device_id,
        schema_version: ACTION_RESULT_SCHEMA_VERSION,
        action: job.action,
        status: if exit_code == 0 {
            ActionStatus::Success
        } else {
            ActionStatus::Failure
        },
        refused_reason: None,
        started_at: started,
        finished_at: finished,
        exit_code: Some(exit_code),
        output: format!("{:?} exited with {}", job.action, exit_code),
        output_truncated: false,
        evidence_id: Uuid::from_u128(0xE0 + (exit_code as u128 & 0xFF)),
    }
}

fn outcome_for(action: ActionKind, package_id: &str, exit_code: i32) -> SoftwareActionOutcome {
    SoftwareActionOutcome {
        action,
        package_id: package_id.into(),
        version: Some("1.2.3".into()),
        exit_code: Some(exit_code),
        output_full: format!("captured stdout for {package_id} exit={exit_code}").into_bytes(),
        started_at: fixed_now(),
        finished_at: fixed_now() + chrono::Duration::seconds(7),
    }
}

/// Mock [`PackageManager`] that records every call and lets the test
/// pre-program install / update / uninstall outcomes per call. Used
/// by the rollback scenario.
#[derive(Debug, Default)]
struct MockManager {
    calls: Mutex<Vec<String>>,
    install_results: Mutex<Vec<Result<(), PackageError>>>,
    update_results: Mutex<Vec<Result<(), PackageError>>>,
}

impl MockManager {
    fn new() -> Self {
        Self::default()
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn queue_install(&self, result: Result<(), PackageError>) {
        self.install_results.lock().unwrap().push(result);
    }

    #[allow(dead_code)]
    fn queue_update(&self, result: Result<(), PackageError>) {
        self.update_results.lock().unwrap().push(result);
    }
}

impl PackageManager for MockManager {
    fn list_installed(&self) -> Result<Vec<PalInstalledPackage>, PackageError> {
        Ok(Vec::new())
    }

    fn install(&self, package: &PackageRef, _opts: &InstallOpts) -> Result<(), PackageError> {
        self.calls.lock().unwrap().push(format!(
            "install:{}:{}",
            package.id,
            package.version.as_deref().unwrap_or("*")
        ));
        self.install_results.lock().unwrap().pop().unwrap_or(Ok(()))
    }

    fn update(&self, package: &PackageRef) -> Result<(), PackageError> {
        self.calls.lock().unwrap().push(format!(
            "update:{}:{}",
            package.id,
            package.version.as_deref().unwrap_or("*")
        ));
        self.update_results.lock().unwrap().pop().unwrap_or(Ok(()))
    }

    fn uninstall(&self, package: &PackageRef) -> Result<(), PackageError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("uninstall:{}", package.id));
        Ok(())
    }
}

// ---------- Scenario 1: catalogue manifest verification --------------------

/// PHASES.md task 2.6 — the catalogue verifier must refuse manifests
/// signed under any key other than the pinned one. We exercise this
/// end-to-end by handing [`CatalogueStore::verify_and_swap`] bytes
/// whose `signature` field is well-shaped (64 hex bytes) but does
/// not verify under the pinned public key.
#[test]
fn catalogue_manifest_rejects_wrong_signature() {
    // Build a syntactically valid manifest with a hex-shaped but
    // garbage signature. Verification must fail with
    // `SignatureMismatch`, not `MalformedSignature` — the verifier
    // is supposed to reach the Ed25519 check and reject there.
    let trusted_key = SigningKey::generate(&mut OsRng);
    let pinned_pub_hex = hex::encode(trusted_key.verifying_key().to_bytes());
    let bogus_signature_hex = "0".repeat(128); // 64 bytes hex.
    let manifest = Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        catalogue_id: "sn360-e2e".into(),
        revision: 7,
        signed_at: None,
        artefacts: vec![Artefact {
            id: "Mozilla.Firefox".into(),
            name: "Mozilla Firefox".into(),
            version: "120.0".into(),
            url: "https://example.test/firefox".into(),
            sha256: "0".repeat(64),
            approval_state: "Approved".into(),
        }],
        key_id: pinned_pub_hex.clone(),
        signature: bogus_signature_hex,
    };
    let bytes = serde_json::to_vec(&manifest).expect("serialize manifest");
    let store = CatalogueStore::new();
    let err = store
        .verify_and_swap(&bytes, &pinned_pub_hex)
        .expect_err("garbage signature must not verify against the pinned key");
    assert!(
        matches!(err, ManifestError::SignatureMismatch),
        "expected SignatureMismatch, got {err:?}"
    );
    assert!(
        store.snapshot().is_none(),
        "store must not have swapped in an unverified catalogue"
    );
}

// ---------- Scenario 2: maintenance window enforcement ---------------------

/// PHASES.md task 2.8 — disruptive jobs must not run outside their
/// allowed maintenance window. We construct a window that allows
/// only Mondays 02:00–04:00 UTC and assert that a job evaluated on
/// a Thursday at 08:30 UTC defers, while one at 02:30 UTC on a
/// Monday executes.
#[test]
fn maintenance_window_defers_jobs_outside_allow_list() {
    let maintenance = MaintenanceWindow {
        enabled: true,
        start: "02:00".into(),
        end: "04:00".into(),
        days: vec!["mon".into()],
    };
    let quiet = QuietHours::default();
    let policy =
        MaintenanceWindowPolicy::from_config(&maintenance, &quiet, "UTC").expect("compile policy");

    // Thursday 08:30 UTC → outside the maintenance window.
    let outside = Utc.with_ymd_and_hms(2026, 5, 7, 8, 30, 0).unwrap();
    assert!(matches!(
        policy.should_execute(outside),
        WindowDecision::Defer
    ));

    // Monday 02:30 UTC → inside the maintenance window.
    let inside = Utc.with_ymd_and_hms(2026, 5, 4, 2, 30, 0).unwrap();
    assert!(matches!(
        policy.should_execute(inside),
        WindowDecision::Execute
    ));

    // Sanity: an "always open" policy (no allow-list, no quiet hours)
    // executes whenever it is asked.
    let always = MaintenanceWindowPolicy::always_open();
    assert!(matches!(
        always.should_execute(outside),
        WindowDecision::Execute
    ));
}

// ---------- Scenario 3: software evidence chain on bus ---------------------

/// PHASES.md task 2.11 — every successful install / update /
/// uninstall must emit one chain-linked `EvidenceRecord` event on
/// the bus. The first record's `prev_record_hash` is
/// `FIRST_RECORD_PREV_HASH`; subsequent records reference the
/// previous record's `chain_hash`.
#[tokio::test]
async fn install_update_uninstall_emits_chain_linked_evidence() {
    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let mut emitter = SoftwareEvidenceEmitter::new();

    // 1) Install.
    let install_job = test_job(
        ActionKind::InstallPackage,
        json!({
            "package_id": "Mozilla.Firefox",
            "version": "1.2.3",
            "channel": "stable",
            "source_url": "https://example.test/firefox",
            "sha256": "0".repeat(64),
        }),
    );
    let install_result = ok_result_for(&install_job, 0);
    let install_outcome = outcome_for(ActionKind::InstallPackage, "Mozilla.Firefox", 0);
    let install_record = emitter
        .record_action(
            &install_job,
            &install_result,
            &install_outcome,
            test_platform(),
            test_agent(),
        )
        .expect("install evidence");

    // 2) Update.
    let update_job = test_job(
        ActionKind::UpdatePackage,
        json!({
            "package_id": "Mozilla.Firefox",
            "to_version": "1.2.4",
            "channel": "stable",
        }),
    );
    let update_result = ok_result_for(&update_job, 0);
    let update_outcome = outcome_for(ActionKind::UpdatePackage, "Mozilla.Firefox", 0);
    let update_record = emitter
        .record_action(
            &update_job,
            &update_result,
            &update_outcome,
            test_platform(),
            test_agent(),
        )
        .expect("update evidence");

    // 3) Uninstall.
    let uninstall_job = test_job(
        ActionKind::UninstallPackage,
        json!({
            "package_id": "Mozilla.Firefox",
            "version": "1.2.4",
        }),
    );
    let uninstall_result = ok_result_for(&uninstall_job, 0);
    let uninstall_outcome = outcome_for(ActionKind::UninstallPackage, "Mozilla.Firefox", 0);
    let uninstall_record = emitter
        .record_action(
            &uninstall_job,
            &uninstall_result,
            &uninstall_outcome,
            test_platform(),
            test_agent(),
        )
        .expect("uninstall evidence");

    // Chain assertions: the emitter must hand records whose
    // `prev_record_hash` chains forward.
    assert_eq!(install_record.prev_record_hash, FIRST_RECORD_PREV_HASH);
    let install_chain = install_record.chain_hash().expect("hash install");
    assert_eq!(update_record.prev_record_hash, install_chain);
    let update_chain = update_record.chain_hash().expect("hash update");
    assert_eq!(uninstall_record.prev_record_hash, update_chain);

    // Each evidence record gets published as `EvidenceRecord` and the
    // matching `ActionResult` as `SoftwareJobResult`.
    for (record, result) in [
        (&install_record, &install_result),
        (&update_record, &update_result),
        (&uninstall_record, &uninstall_result),
    ] {
        bus.publish_to_server(Event::new(
            "software",
            Priority::Normal,
            EventKind::SoftwareJobResult {
                payload: serde_json::to_string(result).unwrap(),
            },
        ))
        .await
        .expect("publish action result");
        bus.publish_to_server(Event::new(
            "software",
            Priority::Normal,
            EventKind::EvidenceRecord {
                payload: serde_json::to_string(record).unwrap(),
            },
        ))
        .await
        .expect("publish evidence");
    }

    // Drain the bus, sift into result/evidence buckets, and verify
    // both wire shapes round-trip.
    let mut results = Vec::new();
    let mut evidences = Vec::new();
    for _ in 0..6 {
        match recv_one(&mut rx).await.kind {
            EventKind::SoftwareJobResult { payload } => {
                let r: ActionResult = serde_json::from_str(&payload).unwrap();
                results.push(r);
            }
            EventKind::EvidenceRecord { payload } => evidences.push(payload),
            other => panic!("unexpected event {other:?}"),
        }
    }
    assert_eq!(results.len(), 3);
    assert_eq!(evidences.len(), 3);
    let actions: Vec<_> = results.iter().map(|r| r.action).collect();
    assert_eq!(
        actions,
        vec![
            ActionKind::InstallPackage,
            ActionKind::UpdatePackage,
            ActionKind::UninstallPackage,
        ]
    );
}

// ---------- Scenario 4: rollback on failed update --------------------------

/// PHASES.md task 2.10 — a failed `UpdatePackage` must trigger an
/// automatic re-install of the previously-recorded version, and
/// PHASES.md task 2.11 — the failed update + the rollback attempt
/// must each appear as chain-linked evidence rows sharing the same
/// `job_id` but distinct `evidence_id`s.
#[tokio::test]
async fn failed_update_triggers_rollback_and_emits_two_chained_records() {
    let tmp = TempDir::new().expect("tmpdir");
    let manifest_path: PathBuf = tmp.path().join("rollback.json");
    let mut orchestrator = RollbackOrchestrator::load(&manifest_path).expect("load");

    let manager = Arc::new(MockManager::new());

    let job = test_job(
        ActionKind::UpdatePackage,
        json!({
            "package_id": "Mozilla.Firefox",
            "to_version": "2.0.0",
            "channel": "stable",
        }),
    );

    // 1) Capture pre-update version. Update will (synthetically)
    // fail — we don't actually run `manager.update()` here, we just
    // hand the orchestrator a failed `ActionResult`.
    orchestrator
        .record_pre_update(
            job.job_id,
            "Mozilla.Firefox",
            Some("1.2.3".to_string()),
            fixed_now(),
        )
        .expect("record pre-update");

    // 2) Pre-update entry must persist across an agent restart so a
    //    boot-time scan can resume any rollback that was interrupted
    //    by a reboot.
    drop(orchestrator);
    let mut orchestrator = RollbackOrchestrator::load(&manifest_path).expect("reload");
    assert_eq!(
        orchestrator.pending_entries().len(),
        1,
        "pre-update entry must persist across orchestrator reloads"
    );

    // 3) Synthesise the failed update result.
    let mut failed_update_result = ok_result_for(&job, 1);
    failed_update_result.evidence_id = Uuid::from_u128(0xE1);
    let failed_update_outcome = SoftwareActionOutcome {
        action: ActionKind::UpdatePackage,
        package_id: "Mozilla.Firefox".into(),
        version: Some("2.0.0".into()),
        exit_code: Some(1),
        output_full: b"update failed: simulated install error".to_vec(),
        started_at: fixed_now(),
        finished_at: fixed_now() + chrono::Duration::seconds(3),
    };

    // 4) Drive the rollback. The mock manager lets the re-install
    //    succeed; the orchestrator turns that into a `RollbackOutcome`
    //    and clears the manifest entry so a future update is not
    //    blocked by a stale record.
    manager.queue_install(Ok(()));
    let rollback_outcome = orchestrator
        .execute_rollback(
            manager.as_ref(),
            job.job_id,
            "Mozilla.Firefox",
            fixed_now() + chrono::Duration::seconds(4),
        )
        .expect("rollback ran");
    assert!(rollback_outcome.succeeded, "rollback must succeed");
    assert_eq!(
        rollback_outcome.previous_version.as_deref(),
        Some("1.2.3"),
        "rollback must target the captured prior version"
    );
    let calls = manager.calls();
    assert_eq!(
        calls,
        vec!["install:Mozilla.Firefox:1.2.3"],
        "rollback must call install with previous_version"
    );

    // 5) After a successful rollback the orchestrator must drop the
    //    entry so a future update is not blocked by a stale record.
    //    The cleared state must also persist across reloads.
    assert!(
        orchestrator.pending_entries().is_empty(),
        "rollback entry must be cleared after execute_rollback"
    );
    drop(orchestrator);
    let mut orchestrator = RollbackOrchestrator::load(&manifest_path).expect("reload");
    assert!(
        orchestrator.pending_entries().is_empty(),
        "cleared rollback entry must stay cleared across orchestrator reloads"
    );

    // 5) Emit the two chain-linked evidence rows: failed update, then
    //    rollback attempt. Both must share `job_id` but have distinct
    //    `evidence_id`s and chain forward.
    let mut emitter = SoftwareEvidenceEmitter::new();
    let failed_record = emitter
        .record_action(
            &job,
            &failed_update_result,
            &failed_update_outcome,
            test_platform(),
            test_agent(),
        )
        .expect("failed update evidence");
    let mut rollback_result = failed_update_result.clone();
    rollback_result.evidence_id = Uuid::from_u128(0xE2);
    rollback_result.output = rollback_outcome.to_canonical_json();
    let rollback_record = emitter
        .record_rollback(
            &job,
            &rollback_result,
            &rollback_outcome,
            test_platform(),
            test_agent(),
        )
        .expect("rollback evidence");

    assert_eq!(failed_record.job_id, rollback_record.job_id);
    assert_ne!(failed_record.evidence_id, rollback_record.evidence_id);
    let failed_chain_hash = failed_record
        .chain_hash()
        .expect("failed record canonicalises");
    assert_eq!(
        rollback_record.prev_record_hash, failed_chain_hash,
        "rollback record must chain off the failed-update record"
    );

    // 6) Publish both onto the bus so the supervisor surface is
    //    exercised end-to-end and the wire shape round-trips.
    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    bus.publish_to_server(Event::new(
        "software",
        Priority::Normal,
        EventKind::EvidenceRecord {
            payload: serde_json::to_string(&failed_record).unwrap(),
        },
    ))
    .await
    .expect("publish failed evidence");
    bus.publish_to_server(Event::new(
        "software",
        Priority::Normal,
        EventKind::EvidenceRecord {
            payload: serde_json::to_string(&rollback_record).unwrap(),
        },
    ))
    .await
    .expect("publish rollback evidence");

    let first = recv_one(&mut rx).await;
    let second = recv_one(&mut rx).await;
    for ev in [&first, &second] {
        match &ev.kind {
            EventKind::EvidenceRecord { payload } => {
                assert!(payload.contains("\"job_id\":\""));
            }
            other => panic!("unexpected event kind: {other:?}"),
        }
    }

    // 7) After both records have been emitted, callers `clear()` the
    //    rollback entry so the manifest does not retain it forever.
    orchestrator
        .clear(job.job_id, "Mozilla.Firefox")
        .expect("clear");
    assert!(
        orchestrator.pending_entries().is_empty(),
        "rollback entry must be cleared after follow-up evidence is emitted"
    );
}

// ---------- Scenario 5: approval-state recommendation surfacing ------------

/// PHASES.md task 2.9 — when an installed package surfaces in a
/// non-approved state (Pending, Denied, Recalled, or Unknown) the
/// agent must publish a `DeviceControlRecommendation` containing
/// the canonical plain-English text from `sda-software`.
#[tokio::test]
async fn pending_package_surfaces_as_recommendation() {
    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();

    let auditor = ApprovalAuditor::new();
    // One installed package; catalogue marks it as Pending.
    let installed = vec![ApprovalInstalledPackage {
        id: "Mozilla.Firefox".into(),
        version: "120.0".into(),
    }];
    let manifest = Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        catalogue_id: "sn360-e2e".into(),
        revision: 1,
        signed_at: None,
        artefacts: vec![Artefact {
            id: "Mozilla.Firefox".into(),
            name: "Mozilla Firefox".into(),
            version: "120.0".into(),
            url: "https://example.test/firefox".into(),
            sha256: "0".repeat(64),
            approval_state: "Pending".into(),
        }],
        key_id: "test-key".into(),
        signature: "0".repeat(128),
    };
    let catalogue = sda_software::Catalogue::from_manifest(manifest).expect("catalogue");
    let evals = auditor.evaluate(&installed, &catalogue);
    let pending = evals
        .into_iter()
        .find(|e| e.state == ApprovalState::Pending)
        .expect("Pending evaluation must be produced");

    let payload = build_recommendation_payload(
        &pending,
        Uuid::from_u128(0x71),
        Uuid::from_u128(0xD1),
        fixed_now(),
    );
    bus.publish_to_server(Event::new(
        "software",
        Priority::Normal,
        EventKind::DeviceControlRecommendation {
            payload: payload.clone(),
        },
    ))
    .await
    .expect("publish recommendation");

    match recv_one(&mut rx).await.kind {
        EventKind::DeviceControlRecommendation { payload: got } => {
            assert_eq!(got, payload);
            assert!(
                got.contains("Mozilla.Firefox"),
                "recommendation payload must reference the package id"
            );
            assert!(
                got.contains("pending administrator approval"),
                "plain-English text must surface the Pending status"
            );
        }
        other => panic!("expected DeviceControlRecommendation, got {other:?}"),
    }
}

// ---------- Scenario 6: script runner --------------------------------------

fn make_script_runner(
    pinned: &SigningKey,
    work_dir: PathBuf,
    max_duration: Duration,
) -> ScriptRunner {
    let pub_hex = hex::encode(pinned.verifying_key().to_bytes());
    let mut cfg = ScriptRunnerConfig::from_parts(
        Some(&pub_hex),
        vec!["sn360.diagnostics.*".into()],
        // `from_parts` enforces a minimum of 1 second; we override
        // `max_duration` directly below for the timeout test.
        5,
        64 * 1024,
    )
    .expect("config");
    cfg.max_duration = max_duration;
    ScriptRunner::new(cfg, work_dir)
}

fn signed_request(
    key: &SigningKey,
    canonical_name: &str,
    body: &[u8],
    job_id: &str,
) -> ScriptRequest {
    let signature = key.sign(body);
    ScriptRequest {
        job_id: job_id.into(),
        canonical_name: canonical_name.into(),
        script_body: body.to_vec(),
        signature: signature.to_bytes().to_vec(),
        extension: Some("sh".into()),
        args: vec![],
    }
}

/// PHASES.md task 2.7 — a properly-signed, allow-listed script runs
/// to completion and the supervisor surface emits exactly one
/// `ScriptRunResult` carrying the runner's outcome.
#[tokio::test]
async fn signed_script_runs_and_emits_script_run_result() {
    let tmp = TempDir::new().expect("tmpdir");
    let key = SigningKey::generate(&mut OsRng);
    let runner = make_script_runner(&key, tmp.path().to_path_buf(), Duration::from_secs(5));
    let request = signed_request(
        &key,
        "sn360.diagnostics.echo",
        b"#!/bin/sh\necho hello-from-script\n",
        "job-signed",
    );
    let outcome = runner.run(request).await.expect("script runs");
    assert_eq!(outcome.exit_code, Some(0));
    assert!(outcome.stdout_truncated.contains("hello-from-script"));
    assert!(!outcome.timed_out);

    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    bus.publish_to_server(Event::new(
        "script-runner",
        Priority::Normal,
        EventKind::ScriptRunResult {
            payload: serde_json::to_string(&outcome).unwrap(),
        },
    ))
    .await
    .expect("publish script result");

    match recv_one(&mut rx).await.kind {
        EventKind::ScriptRunResult { payload } => {
            assert!(payload.contains("hello-from-script"));
            assert!(payload.contains("\"job_id\":\"job-signed\""));
        }
        other => panic!("expected ScriptRunResult, got {other:?}"),
    }
}

/// PHASES.md task 2.7 — an unsigned (or wrong-key) script must be
/// rejected before any process is spawned. We simulate the wrong
/// key by signing with an attacker-controlled keypair while pinning
/// a different one in the runner config.
#[tokio::test]
async fn unsigned_script_is_rejected_before_spawn() {
    let tmp = TempDir::new().expect("tmpdir");
    let trusted = SigningKey::generate(&mut OsRng);
    let attacker = SigningKey::generate(&mut OsRng);
    let runner = make_script_runner(&trusted, tmp.path().to_path_buf(), Duration::from_secs(5));
    let request = signed_request(
        &attacker,
        "sn360.diagnostics.echo",
        b"#!/bin/sh\necho should-not-run\n",
        "job-attacker",
    );
    let err = runner
        .run(request)
        .await
        .expect_err("attacker-signed script must be rejected");
    assert!(matches!(err, ScriptRunnerError::SignatureMismatch));
}

/// PHASES.md task 2.7 — a runaway script must be killed when its
/// wall-clock budget elapses, and the resulting outcome must
/// indicate `timed_out=true` with the canonical truncation reason.
#[tokio::test]
async fn runaway_script_is_killed_when_timeout_fires() {
    let tmp = TempDir::new().expect("tmpdir");
    let key = SigningKey::generate(&mut OsRng);
    let runner = make_script_runner(&key, tmp.path().to_path_buf(), Duration::from_millis(200));
    let request = signed_request(
        &key,
        "sn360.diagnostics.sleep",
        b"#!/bin/sh\nsleep 30\n",
        "job-runaway",
    );
    let outcome = runner.run(request).await.expect("runner returns outcome");
    assert!(outcome.timed_out, "wall-clock budget must trip");
    assert_eq!(
        outcome.exit_code, None,
        "killed processes have no exit code"
    );
    assert_eq!(
        outcome.truncation_reason.as_deref(),
        Some(truncation_reason::TIMEOUT),
        "truncation reason must be TIMEOUT"
    );
}
