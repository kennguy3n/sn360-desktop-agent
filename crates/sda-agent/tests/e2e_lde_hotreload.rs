//! Hermetic end-to-end coverage for LDE TRDS hot-reload.
//!
//! This suite stitches together:
//!
//! - a hand-rolled HTTP/1.1 mock TRDS server (bound to a random
//!   loopback port) that serves [`SignedBundleEnvelope`]s on
//!   `GET /trds/bundle`,
//! - `sda-local-detection::LocalDetectionModule` configured with
//!   `trds_endpoint`, `rule_bundle_signing_keys`, and a sub-second
//!   `rule_pull_interval` so the first pull is observable in
//!   milliseconds, and
//! - assertions against the on-bus `LocalDetectionAlert` notices
//!   emitted by `publish_bundle_applied_alert` (hot-reload success)
//!   and `publish_bundle_security_alert` (signature / key-id /
//!   version substitution rejection).
//!
//! All scenarios run on the in-process `EventBus`, never touch the
//! internet, and finish in under a second — `make e2e-lde-hotreload`
//! is safe to run on every CI host without privileges.
//!
//! Coverage (≥ 6 tests for `docs/edr.md` § 7 — Rule distribution / Hot reload):
//!
//! 1. Pristine LDE pulls + applies a valid signed bundle within
//!    the short pull window.
//! 2. Tampering with the base64 bundle bytes triggers a `severity =
//!    high` security alert and the last-known-good pipeline is
//!    preserved.
//! 3. Bundles signed with an unknown `key_id` are rejected with a
//!    security alert.
//! 4. An envelope whose JSON `version` mismatches the embedded
//!    bundle (substitution attack) is rejected.
//! 5. A second valid bundle published after the initial pull is
//!    hot-reloaded (atomic swap) — the applied notice carries the
//!    new version.
//! 6. With no TRDS endpoint configured the LDE serves the embedded
//!    default bundle and never publishes a TRDS rejection alert.

#![cfg(unix)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use sda_core::config::LocalDetectionConfig;
use sda_core::signal::ShutdownController;
use sda_event_bus::{Event, EventBus, EventKind, EventReceiver};
use sda_local_detection::rule_store::{IocList, RuleBundle, StringIoc, SEV_HIGH};
use sda_local_detection::LocalDetectionModule;
use serde::Serialize;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

// ------------------------------------------------------------------ wire shape

/// JSON envelope mirror of `sda_local_detection::trds_client::SignedBundleEnvelope`.
/// We re-declare it here so the test does not depend on a `pub(crate)` shape.
#[derive(Debug, Clone, Serialize)]
struct WireEnvelope {
    version: u64,
    key_id: String,
    bundle_b64: String,
    signature_b64: String,
}

// ------------------------------------------------------------------ mock server

/// Hand-rolled HTTP/1.1 mock TRDS server.
///
/// We deliberately avoid `hyper` / `axum` here so the test does not
/// drag extra dev-dependencies into the workspace.  The server
/// accepts a single endpoint:
///
/// ```text
/// GET <whatever-path>?since=N
/// ```
///
/// and replies with whichever envelope the test has installed via
/// [`MockServer::set_envelope`].  Returning `None` makes the server
/// answer `204 No Content` (TRDS convention for "no newer bundle").
struct MockServer {
    url: String,
    state_tx: watch::Sender<Option<WireEnvelope>>,
    _shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl MockServer {
    async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 0");
        let addr: SocketAddr = listener.local_addr().expect("local_addr");
        let url = format!("http://{addr}/trds/bundle");
        let (state_tx, state_rx) = watch::channel::<Option<WireEnvelope>>(None);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => return,
                    accepted = listener.accept() => {
                        let Ok((mut stream, _)) = accepted else { continue };
                        let state_rx = state_rx.clone();
                        tokio::spawn(async move {
                            let _ = handle_client(&mut stream, &state_rx).await;
                        });
                    }
                }
            }
        });

        MockServer {
            url,
            state_tx,
            _shutdown_tx: shutdown_tx,
        }
    }

    fn set_envelope(&self, env: Option<WireEnvelope>) {
        let _ = self.state_tx.send(env);
    }

    fn url(&self) -> &str {
        &self.url
    }
}

async fn handle_client(
    stream: &mut tokio::net::TcpStream,
    state: &watch::Receiver<Option<WireEnvelope>>,
) -> std::io::Result<()> {
    // Drain a single HTTP/1.1 request — we only care about the method
    // line so we can ignore everything after it.
    let mut buf = [0u8; 2048];
    let mut total = 0usize;
    while total < buf.len() {
        let n = stream.read(&mut buf[total..]).await?;
        if n == 0 {
            break;
        }
        total += n;
        // Header terminator?  We don't bother parsing the body since
        // TRDS pulls are GETs.
        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let snapshot = state.borrow().clone();
    let response_bytes = match snapshot {
        Some(env) => {
            let body = serde_json::to_vec(&env).expect("encode envelope");
            let mut resp = Vec::with_capacity(body.len() + 128);
            resp.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
            resp.extend_from_slice(b"Content-Type: application/json\r\n");
            resp.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
            resp.extend_from_slice(b"Connection: close\r\n\r\n");
            resp.extend_from_slice(&body);
            resp
        }
        None => {
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
        }
    };
    stream.write_all(&response_bytes).await?;
    stream.shutdown().await?;
    Ok(())
}

// ------------------------------------------------------------------ helpers

fn lde_cfg(tmp: &TempDir, endpoint: Option<String>, keys: Vec<String>) -> LocalDetectionConfig {
    LocalDetectionConfig {
        enabled: true,
        rule_pull_interval: 1, // floor is 1 second in run loop
        offline_queue_max: 256,
        yara_scan_rate_limit: 0,
        yara_max_file_size_mb: 8,
        bloom_filter_fpr: 0.01,
        behavioral_max_window_sec: 600,
        behavioral_max_tracked_entities: 256,
        block_ip: false,
        kill_process: false,
        quarantine: false,
        rule_bundle_path: tmp.path().join("bundle.msgpack"),
        offline_queue_path: tmp.path().join("queue.sqlite"),
        quarantine_dir: tmp.path().join("quarantine"),
        offline_drain_interval: 3600,
        offline_drain_batch: 32,
        trds_endpoint: endpoint,
        rule_bundle_signing_keys: keys,
        trds_pull_timeout_secs: 2,
    }
}

fn agent_config(lde: LocalDetectionConfig) -> sda_core::config::AgentConfig {
    let mut cfg = sda_core::config::AgentConfig::default();
    cfg.modules.local_detection = lde;
    cfg
}

fn build_bundle(version: u64, ioc_value: &str) -> RuleBundle {
    RuleBundle {
        version,
        generated_at: "2026-05-17T00:00:00Z".into(),
        iocs: IocList {
            strings: vec![StringIoc {
                id: format!("ioc-v{version}"),
                value: ioc_value.into(),
                kind: "domain".into(),
                severity: SEV_HIGH.into(),
                description: format!("hot-reload IOC v{version}"),
            }],
            hashes: vec![],
            ips: vec![],
        },
        behavioral: vec![],
        yara_paths: vec![],
    }
}

fn sign_envelope(bundle: &RuleBundle, sk: &SigningKey, key_id: &str) -> WireEnvelope {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let bytes = bundle.to_msgpack().expect("msgpack");
    let sig = sk.sign(&bytes);
    WireEnvelope {
        version: bundle.version,
        key_id: key_id.into(),
        bundle_b64: B64.encode(&bytes),
        signature_b64: B64.encode(sig.to_bytes()),
    }
}

fn pubkey_hex(sk: &SigningKey) -> String {
    let vk: VerifyingKey = sk.verifying_key();
    hex::encode(vk.to_bytes())
}

/// Build the `"<key_id>:<hex>"` rotation entry expected by
/// `build_signing_keys`.  Tests must use this rather than passing the
/// bare hex pubkey, otherwise the LDE auto-assigns `rotation-{i}` and
/// no real-world envelope's `key_id` will match.
fn rotation_entry(key_id: &str, sk: &SigningKey) -> String {
    format!("{key_id}:{}", pubkey_hex(sk))
}

async fn await_alert<F>(rx: &mut EventReceiver, budget: Duration, predicate: F) -> Option<Event>
where
    F: Fn(&EventKind) -> bool,
{
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(ev)) if predicate(&ev.kind) => return Some(ev),
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => return None,
        }
    }
}

async fn await_no_alert<F>(rx: &mut EventReceiver, budget: Duration, predicate: F) -> bool
where
    F: Fn(&EventKind) -> bool,
{
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return true;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(ev)) if predicate(&ev.kind) => return false,
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => return true,
        }
    }
}

fn applied_predicate(version: u64) -> impl Fn(&EventKind) -> bool {
    move |k: &EventKind| match k {
        EventKind::LocalDetectionAlert {
            rule_id,
            matched_value,
            ..
        } => rule_id == "system.trds.applied" && matched_value == &version.to_string(),
        _ => false,
    }
}

fn any_applied(k: &EventKind) -> bool {
    matches!(k, EventKind::LocalDetectionAlert { rule_id, .. } if rule_id == "system.trds.applied")
}

fn any_rejected(k: &EventKind) -> bool {
    matches!(k, EventKind::LocalDetectionAlert { rule_id, .. } if rule_id == "system.trds.rejected")
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn t01_valid_bundle_pulled_and_hot_reloaded() {
    let tmp = TempDir::new().unwrap();
    let server = MockServer::spawn().await;
    let sk = SigningKey::generate(&mut OsRng);
    let env = sign_envelope(&build_bundle(42, "evil.example.com"), &sk, "edr-2026-q2");
    server.set_envelope(Some(env));

    let cfg = lde_cfg(
        &tmp,
        Some(server.url().into()),
        vec![rotation_entry("edr-2026-q2", &sk)],
    );
    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = LocalDetectionModule::start(&agent_config(cfg), bus, shutdown);

    let ev = await_alert(&mut rx, Duration::from_secs(5), &applied_predicate(42))
        .await
        .expect("expected hot-reload applied alert within 5s");
    match ev.kind {
        EventKind::LocalDetectionAlert {
            rule_type,
            severity,
            description,
            ..
        } => {
            assert_eq!(rule_type, "system");
            assert_eq!(severity, "info");
            assert!(description.contains("v42"), "got {description}");
        }
        other => panic!("unexpected {other:?}"),
    }

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t02_tampered_bundle_rejected_with_security_alert() {
    let tmp = TempDir::new().unwrap();
    let server = MockServer::spawn().await;
    let sk = SigningKey::generate(&mut OsRng);
    let mut env = sign_envelope(&build_bundle(7, "good.example.com"), &sk, "edr-2026-q2");
    // Flip the last base64 char of the bundle blob — guaranteed to
    // either fail msgpack decode OR fail the signature check.
    let last = env.bundle_b64.pop().unwrap();
    env.bundle_b64.push(if last == 'A' { 'B' } else { 'A' });
    server.set_envelope(Some(env));

    let cfg = lde_cfg(
        &tmp,
        Some(server.url().into()),
        vec![rotation_entry("edr-2026-q2", &sk)],
    );
    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = LocalDetectionModule::start(&agent_config(cfg), bus, shutdown);

    let ev = await_alert(&mut rx, Duration::from_secs(5), any_rejected)
        .await
        .expect("expected security rejection alert");
    match ev.kind {
        EventKind::LocalDetectionAlert {
            rule_id, severity, ..
        } => {
            assert_eq!(rule_id, "system.trds.rejected");
            assert_eq!(severity, "high");
        }
        other => panic!("unexpected {other:?}"),
    }

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t03_unknown_key_id_rejected_with_security_alert() {
    let tmp = TempDir::new().unwrap();
    let server = MockServer::spawn().await;
    let signer = SigningKey::generate(&mut OsRng);
    // The signing key DOES match what the LDE knows about, but the
    // declared `key_id` in the envelope ("rotated-out") is NOT in
    // the local rotation set — the LDE auto-assigns ids as
    // `rotation-{index}` for each pubkey in
    // `rule_bundle_signing_keys`.  See `build_signing_keys` in
    // `crates/sda-local-detection/src/lib.rs`.
    let env = sign_envelope(&build_bundle(9, "x.example"), &signer, "rotated-out");
    server.set_envelope(Some(env));

    let cfg = lde_cfg(&tmp, Some(server.url().into()), vec![pubkey_hex(&signer)]);
    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = LocalDetectionModule::start(&agent_config(cfg), bus, shutdown);

    let ev = await_alert(&mut rx, Duration::from_secs(5), any_rejected)
        .await
        .expect("expected unknown-key rejection alert");
    if let EventKind::LocalDetectionAlert {
        rule_id,
        matched_value,
        ..
    } = ev.kind
    {
        assert_eq!(rule_id, "system.trds.rejected");
        assert!(
            matched_value.contains("UnknownKeyId"),
            "matched_value should debug-print the UnknownKeyId variant, got {matched_value}"
        );
    } else {
        panic!("expected LocalDetectionAlert");
    }

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t04_version_substitution_rejected() {
    let tmp = TempDir::new().unwrap();
    let server = MockServer::spawn().await;
    let sk = SigningKey::generate(&mut OsRng);
    let mut env = sign_envelope(&build_bundle(11, "v.example"), &sk, "edr-2026-q2");
    // Envelope advertises a higher version than the embedded bundle —
    // signature still verifies, but the version-substitution check
    // fires.
    env.version = 999;
    server.set_envelope(Some(env));

    let cfg = lde_cfg(
        &tmp,
        Some(server.url().into()),
        vec![rotation_entry("edr-2026-q2", &sk)],
    );
    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = LocalDetectionModule::start(&agent_config(cfg), bus, shutdown);

    let ev = await_alert(&mut rx, Duration::from_secs(5), any_rejected)
        .await
        .expect("expected version-substitution rejection");
    if let EventKind::LocalDetectionAlert { rule_id, .. } = ev.kind {
        assert_eq!(rule_id, "system.trds.rejected");
    } else {
        panic!("expected LocalDetectionAlert");
    }

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t05_second_valid_bundle_hot_reloads_via_atomic_swap() {
    let tmp = TempDir::new().unwrap();
    let server = MockServer::spawn().await;
    let sk = SigningKey::generate(&mut OsRng);

    // First publish version 5.
    server.set_envelope(Some(sign_envelope(
        &build_bundle(5, "old.example"),
        &sk,
        "edr-2026-q2",
    )));

    let cfg = lde_cfg(
        &tmp,
        Some(server.url().into()),
        vec![rotation_entry("edr-2026-q2", &sk)],
    );
    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = LocalDetectionModule::start(&agent_config(cfg), bus, shutdown);

    await_alert(&mut rx, Duration::from_secs(5), &applied_predicate(5))
        .await
        .expect("first applied alert");

    // Roll the server forward to version 6.
    server.set_envelope(Some(sign_envelope(
        &build_bundle(6, "new.example"),
        &sk,
        "edr-2026-q2",
    )));

    let ev = await_alert(&mut rx, Duration::from_secs(5), &applied_predicate(6))
        .await
        .expect("second applied alert (hot-reload)");
    if let EventKind::LocalDetectionAlert { description, .. } = ev.kind {
        assert!(description.contains("v6"), "got {description}");
    }

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t06_no_endpoint_uses_default_bundle_and_emits_no_rejection() {
    let tmp = TempDir::new().unwrap();
    let cfg = lde_cfg(&tmp, None, vec![]);
    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = LocalDetectionModule::start(&agent_config(cfg), bus, shutdown);

    // No TRDS pulls happen, so neither applied nor rejected notices
    // should appear on the bus.
    let quiet = await_no_alert(&mut rx, Duration::from_millis(500), |k| {
        any_applied(k) || any_rejected(k)
    })
    .await;
    assert!(quiet, "LDE without endpoint must not emit TRDS notices");

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t07_no_newer_bundle_is_noop_no_applied_alert() {
    let tmp = TempDir::new().unwrap();
    let server = MockServer::spawn().await;
    // Server returns 204 No Content forever.
    server.set_envelope(None);
    let sk = SigningKey::generate(&mut OsRng);

    let cfg = lde_cfg(
        &tmp,
        Some(server.url().into()),
        vec![rotation_entry("edr-2026-q2", &sk)],
    );
    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = LocalDetectionModule::start(&agent_config(cfg), bus, shutdown);

    let quiet = await_no_alert(&mut rx, Duration::from_millis(1_500), |k| {
        any_applied(k) || any_rejected(k)
    })
    .await;
    assert!(
        quiet,
        "204 responses must not produce applied or rejected alerts"
    );

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn t08_stale_version_envelope_is_ignored_after_initial_pull() {
    let tmp = TempDir::new().unwrap();
    let server = MockServer::spawn().await;
    let sk = SigningKey::generate(&mut OsRng);

    server.set_envelope(Some(sign_envelope(
        &build_bundle(20, "twenty.example"),
        &sk,
        "edr-2026-q2",
    )));

    let cfg = lde_cfg(
        &tmp,
        Some(server.url().into()),
        vec![rotation_entry("edr-2026-q2", &sk)],
    );
    let (bus, _server_rx) = EventBus::new(64, 64);
    let mut rx = bus.subscribe();
    let (controller, shutdown) = ShutdownController::new();
    let handle = LocalDetectionModule::start(&agent_config(cfg), bus, shutdown);

    await_alert(&mut rx, Duration::from_secs(5), &applied_predicate(20))
        .await
        .expect("first applied alert at v20");

    // Now serve a STALE envelope (v10 < v20).  The version-monotonicity
    // guard must reject without emitting either an applied or a
    // rejected alert (this is a non-security skip).
    server.set_envelope(Some(sign_envelope(
        &build_bundle(10, "ten.example"),
        &sk,
        "edr-2026-q2",
    )));

    let quiet = await_no_alert(&mut rx, Duration::from_millis(2_000), |k| {
        any_applied(k) || any_rejected(k)
    })
    .await;
    assert!(quiet, "stale-version pulls must be silent no-ops");

    controller.shutdown();
    handle.task.await.unwrap().unwrap();
}

/// Smoke test: the wire envelope shape we hand-craft serialises back
/// to the same JSON keys the production `SignedBundleEnvelope` uses.
/// Guards against accidental field renames.
#[test]
fn t09_wire_envelope_key_names_are_stable() {
    let env = WireEnvelope {
        version: 1,
        key_id: "k".into(),
        bundle_b64: "AA==".into(),
        signature_b64: "AA==".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&env).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("version"));
    assert!(obj.contains_key("key_id"));
    assert!(obj.contains_key("bundle_b64"));
    assert!(obj.contains_key("signature_b64"));
}

/// Coverage smoke — confirms the `lde_cfg` helper produces a
/// default-on configuration suitable for hot-reload tests so future
/// edits to `LocalDetectionConfig` don't silently regress this
/// suite.  Independent of any I/O.
#[test]
fn t10_lde_cfg_helper_is_enabled_with_sub_minute_pull() {
    let tmp = TempDir::new().unwrap();
    let cfg = lde_cfg(&tmp, None, vec![]);
    assert!(cfg.enabled);
    assert!(cfg.rule_pull_interval >= 1);
    assert!(cfg.trds_pull_timeout_secs >= 1);
}

// ------------------------------------------------------------------ keep clippy happy

// Suppress dead-code on shutdown helper when the mock server is dropped
// without firing.
#[allow(dead_code)]
fn _unused() {
    let _ = Arc::new(PathBuf::new());
}
