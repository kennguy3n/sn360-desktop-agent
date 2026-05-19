//! USB / removable-media device-policy end-to-end suite.
//!
//! Hermetic exercises of the per-OS USB policy enforcement surface
//! shipped in this PR. The harness:
//!
//! 1. Drives the supervisor directly with a synthetic `DeviceCandidate`
//!    (mimicking the parser layer the per-OS helpers run).
//! 2. Asserts the decision and the canonical-JSON audit envelope.
//! 3. Round-trips through the live IPC server (`tokio::net::UnixListener`
//!    on Linux/macOS) so the udev / SystemExtension helper path is
//!    exercised end-to-end.
//!
//! Tests run on every CI host; no real hardware is required. The
//! Makefile target `make e2e-device-policy` invokes only this
//! file.
//!
//! Coverage:
//!
//! * `block_policy_for_usb_mass_storage_blocks_and_emits_decision`
//!   — block policy for `usb` class with `device_class_match` →
//!   decision is Block, audit envelope is connector_type=device-control.
//! * `audit_policy_allows_but_emits_decision`
//!   — audit policy emits the decision but the helper exits 0.
//! * `allow_policy_lets_device_through`
//!   — allow policy with explicit allow decision.
//! * `priority_order_is_honoured` — lower priority wins over higher.
//! * `closed_by_default_no_bundle` — fresh supervisor in boot
//!   sentinel uses fallback action.
//! * `bundle_unverified_keeps_last_known_good` — D2.7: a tampered
//!   bundle does NOT downgrade the in-effect policy.
//! * `live_uds_ipc_server_round_trip` (linux only) — exercises the
//!   `usb_linux::async_server::serve` server with a real Unix
//!   socket; spawn helper-equivalent client; assert wire frames.

#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use sda_device_control::{
    decode_query_response, encode_query_request, DeviceCandidate, DeviceClass, UsbPolicyAction,
    UsbPolicySupervisor, UsbPolicySupervisorConfig,
};
use serde_json::json;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use uuid::Uuid;

fn supervisor() -> Arc<UsbPolicySupervisor> {
    UsbPolicySupervisor::new(&UsbPolicySupervisorConfig {
        tenant_id: "tenant-a".into(),
        default_action: sda_device_control::usb_policy::Action::Audit,
        fallback_action: sda_device_control::usb_policy::Action::Audit,
    })
}

fn slice_with_block_policy_for_usb() -> Vec<u8> {
    let policies = json!([{
        "id": "00000000-0000-0000-0000-000000000001",
        "tenant_id": "tenant-a",
        "name": "Block USB mass-storage",
        "enabled": true,
        "device_class": "usb",
        "match": {},
        "action": "block",
        "priority": 100,
        "severity": 9,
    }]);
    serde_json::to_vec(&policies).unwrap()
}

fn slice_with_audit_policy_for_usb() -> Vec<u8> {
    let policies = json!([{
        "id": "00000000-0000-0000-0000-000000000002",
        "tenant_id": "tenant-a",
        "name": "Audit USB",
        "enabled": true,
        "device_class": "usb",
        "match": {},
        "action": "audit",
        "priority": 100,
        "severity": 1,
    }]);
    serde_json::to_vec(&policies).unwrap()
}

fn slice_with_allow_policy_for_usb() -> Vec<u8> {
    let policies = json!([{
        "id": "00000000-0000-0000-0000-000000000003",
        "tenant_id": "tenant-a",
        "name": "Allow USB",
        "enabled": true,
        "device_class": "usb",
        "match": {},
        "action": "allow",
        "priority": 100,
        "severity": 1,
    }]);
    serde_json::to_vec(&policies).unwrap()
}

fn usb_mass_storage_candidate() -> DeviceCandidate {
    DeviceCandidate {
        device_class: DeviceClass::Usb,
        vendor_id: Some("05ac".to_string()),
        product_id: Some("0220".to_string()),
        serial: Some("ABC123".to_string()),
        bus_path: Some("/devices/pci0000:00/0000:00:14.0/usb3/3-1".to_string()),
    }
}

#[test]
fn block_policy_for_usb_mass_storage_blocks_and_emits_decision() {
    let sup = supervisor();
    sup.apply_bundle_slice(&slice_with_block_policy_for_usb())
        .expect("apply bundle");
    let cand = usb_mass_storage_candidate();
    let (decision, payload) = sup.evaluate_with_payload(&cand).expect("evaluate");

    assert_eq!(decision.action, UsbPolicyAction::Block);
    assert!(decision.matched_policy_id.is_some());

    let v: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(v["connector_type"], "device-control");
    assert_eq!(v["decision"], "block");
    assert_eq!(v["tenant_id"], "tenant-a");
    assert_eq!(v["device"]["device_class"], "usb");
}

#[test]
fn audit_policy_allows_but_emits_decision() {
    let sup = supervisor();
    sup.apply_bundle_slice(&slice_with_audit_policy_for_usb())
        .expect("apply bundle");
    let cand = usb_mass_storage_candidate();
    let (decision, payload) = sup.evaluate_with_payload(&cand).expect("evaluate");

    assert_eq!(decision.action, UsbPolicyAction::Audit);
    let v: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(v["decision"], "audit");
}

#[test]
fn allow_policy_lets_device_through() {
    let sup = supervisor();
    sup.apply_bundle_slice(&slice_with_allow_policy_for_usb())
        .expect("apply bundle");
    let cand = usb_mass_storage_candidate();
    let (decision, payload) = sup.evaluate_with_payload(&cand).expect("evaluate");

    assert_eq!(decision.action, UsbPolicyAction::Allow);
    let v: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(v["decision"], "allow");
}

#[test]
fn priority_order_is_honoured() {
    // Lower priority wins.
    let policies = json!([
        {
            "id": "00000000-0000-0000-0000-000000000020",
            "tenant_id": "tenant-a",
            "name": "Block USB",
            "enabled": true,
            "device_class": "usb",
            "match": {},
            "action": "block",
            "priority": 200,
            "severity": 9,
        },
        {
            "id": "00000000-0000-0000-0000-000000000010",
            "tenant_id": "tenant-a",
            "name": "Allow USB (override)",
            "enabled": true,
            "device_class": "usb",
            "match": {},
            "action": "allow",
            "priority": 10,
            "severity": 1,
        },
    ]);
    let sup = supervisor();
    sup.apply_bundle_slice(&serde_json::to_vec(&policies).unwrap())
        .expect("apply bundle");
    let cand = usb_mass_storage_candidate();
    let decision = sup.evaluate(&cand);
    assert_eq!(decision.action, UsbPolicyAction::Allow);
    assert_eq!(
        decision.matched_policy_id.as_deref(),
        Some("00000000-0000-0000-0000-000000000010")
    );
}

#[test]
fn closed_by_default_no_bundle() {
    // Supervisor configured to BLOCK as fallback when no verified
    // policy is loaded yet (D2.7 closed-by-default).
    let sup = UsbPolicySupervisor::new(&UsbPolicySupervisorConfig {
        tenant_id: "tenant-a".into(),
        default_action: sda_device_control::usb_policy::Action::Audit,
        fallback_action: sda_device_control::usb_policy::Action::Block,
    });
    let cand = usb_mass_storage_candidate();
    let decision = sup.evaluate(&cand);
    assert_eq!(decision.action, UsbPolicyAction::Block);
    assert!(decision.matched_policy_id.is_none());
}

#[test]
fn bundle_unverified_keeps_last_known_good() {
    let sup = supervisor();
    sup.apply_bundle_slice(&slice_with_block_policy_for_usb())
        .expect("apply bundle");

    // Unverified bundle: record_bundle_unverified must NOT clobber
    // the loaded set.
    let _ = sup.record_bundle_unverified("ed25519 verification failed");

    let cand = usb_mass_storage_candidate();
    let decision = sup.evaluate(&cand);
    assert_eq!(decision.action, UsbPolicyAction::Block);
    assert!(decision.matched_policy_id.is_some());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn live_uds_ipc_server_round_trip() {
    // Pick a unique socket path under the per-test temp dir so
    // parallel test runs don't collide.
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("usb-policy.sock");

    let sup = supervisor();
    sup.apply_bundle_slice(&slice_with_block_policy_for_usb())
        .expect("apply bundle");

    let socket_for_server = socket.clone();
    let sup_for_server = sup.clone();

    let audit: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let audit_for_server = audit.clone();

    // Spawn the live server.
    tokio::spawn(async move {
        let _ = sda_device_control::usb_linux::async_server::serve(
            &socket_for_server,
            sup_for_server,
            move |payload| {
                audit_for_server.lock().unwrap().push(payload);
            },
        )
        .await;
    });

    // Wait for the server to bind. UnixListener::bind happens
    // synchronously inside `serve` so a brief sleep suffices.
    for _ in 0..20 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(socket.exists(), "server failed to bind socket in 500ms");

    // Open a UDS, write a request, read the response — same wire
    // shape the udev helper uses.
    let req = sda_device_control::UsbIpcQueryRequest {
        v: 1,
        transaction_id: format!("e2e-{}", Uuid::new_v4()),
        candidate: usb_mass_storage_candidate(),
    };
    let frame = encode_query_request(&req).unwrap();

    let mut stream = UnixStream::connect(&socket).await.unwrap();
    stream.write_all(&frame).await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let resp = decode_query_response(&buf).expect("decode response");
    assert_eq!(resp.v, 1);
    assert_eq!(resp.transaction_id, req.transaction_id);
    assert_eq!(resp.decision.action, UsbPolicyAction::Block);

    // The audit callback must have fired.
    for _ in 0..20 {
        if !audit.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let recorded = audit.lock().unwrap();
    assert_eq!(recorded.len(), 1, "exactly one audit envelope expected");
    let v: Value = serde_json::from_str(&recorded[0]).unwrap();
    assert_eq!(v["connector_type"], "device-control");
    assert_eq!(v["decision"], "block");
}
