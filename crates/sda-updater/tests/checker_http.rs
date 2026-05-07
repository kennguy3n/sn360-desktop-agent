//! Integration tests for [`sda_updater::checker`] using a hand-rolled
//! single-shot HTTP server.
//!
//! A purpose-built listener keeps the test lightweight (no new
//! dev-dep on wiremock/httptest) and works across all CI targets. The
//! server only needs to answer a single GET with a canned body.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use sda_core::config::UpdateConfig;
use sda_updater::check_for_update;

/// Spawn a blocking TCP listener on an ephemeral port and reply with
/// `body` (as JSON) to exactly one request. Returns the URL the test
/// should point at.
fn spawn_once_server(body: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();

    thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        // Drain request headers; we don't care what's in them.
        let mut buf = [0u8; 1024];
        let _ = sock.read(&mut buf);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = sock.write_all(resp.as_bytes());
        let _ = sock.flush();
    });

    format!("http://{addr}/latest.json")
}

fn cfg(server_url: String) -> UpdateConfig {
    UpdateConfig {
        enabled: true,
        server_url,
        check_interval: 60,
        public_key: String::new(),
        smoke_test_timeout: 10,
    }
}

#[tokio::test]
async fn newer_version_is_returned() {
    let body = r#"{
        "version": "9.9.9",
        "url": "https://cdn.example.invalid/sda-agent-9.9.9",
        "sha256": "deadbeef",
        "signature": "abcd"
    }"#
    .to_string();
    let url = spawn_once_server(body);

    let manifest = check_for_update(&cfg(url), "0.1.0")
        .await
        .expect("check_for_update should succeed")
        .expect("server advertises a newer version");

    assert_eq!(manifest.version, "9.9.9");
    assert_eq!(manifest.sha256, "deadbeef");
}

#[tokio::test]
async fn older_or_equal_version_returns_none() {
    let body = r#"{
        "version": "0.0.1",
        "url": "https://cdn.example.invalid/sda-agent-0.0.1",
        "sha256": "deadbeef",
        "signature": "abcd"
    }"#
    .to_string();
    let url = spawn_once_server(body);

    let result = check_for_update(&cfg(url), "0.1.0")
        .await
        .expect("check_for_update should succeed");
    assert!(result.is_none(), "older version should not trigger update");
}

#[tokio::test]
async fn malformed_json_is_surfaced_as_error() {
    let url = spawn_once_server("not-json".to_string());
    let err = check_for_update(&cfg(url), "0.1.0")
        .await
        .expect_err("malformed JSON must return Err");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("manifest") || msg.contains("decode"),
        "error should mention manifest decode: {msg}"
    );
}
