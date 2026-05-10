//! `sn360-device-control-helper` — Linux udev helper for D2.2.
//!
//! Invoked by `systemd-udevd` from the rule installed under
//! `packaging/linux/sn360-device-control.rules`. The helper reads
//! the device attributes from its environment block, builds a
//! [`DeviceCandidate`], talks to the running `sda-agent` over the
//! Unix-domain socket the agent owns, and exits with code:
//!
//! * `0` — the supervisor returned `Action::Allow` or
//!   `Action::Audit`. udev binds the device.
//! * `1` — the supervisor returned `Action::Block`. udev leaves
//!   the device unbound so it cannot be mounted.
//!
//! The helper is intentionally tiny (no async runtime, no logging
//! framework) so it executes well inside the
//! `udev_event_default_timeout_secs` budget.
//!
//! It is gated behind the `linux-helper` Cargo feature so the
//! binary is only compiled when the linux packaging Makefile asks
//! for it. CI exercises the binary's logic via the unit tests in
//! [`sda_device_control::usb_linux`] and the e2e harness, so no
//! standalone test target is required.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use sda_device_control::usb_ipc::{
    decode_query_response, encode_query_request, USB_IPC_PROTOCOL_VERSION,
};
use sda_device_control::usb_linux::{build_query_request, parse_udev_environment};

/// Hard cap on the round-trip helper latency. udev gives each rule
/// `udev_event_timeout` (default 180s) but the helper's own budget
/// is much tighter so a stuck agent does not delay device binding
/// for human-visible periods.
const HELPER_TIMEOUT: Duration = Duration::from_millis(750);

/// Default socket path. Overridden by the
/// `SN360_DEVICE_CONTROL_SOCKET` environment variable so packaging
/// can keep the rule template generic.
const DEFAULT_SOCKET: &str = sda_device_control::usb_linux::DEFAULT_LINUX_SOCKET_PATH;

fn main() -> ExitCode {
    match run() {
        Ok(action) => match action {
            sda_device_control::UsbPolicyAction::Block => ExitCode::from(1),
            // Audit and Allow both let the OS bind the device.
            _ => ExitCode::from(0),
        },
        Err(e) => {
            // Closed-by-default *behaviour* on helper failure is
            // governed by the agent's `usb_policy.fallback_action`,
            // not by the helper's exit code. If we cannot reach
            // the agent at all, exiting 0 keeps the device usable
            // (so a crashed agent does not brick every USB port);
            // exiting 1 would brick. We log the failure to stderr
            // so the udev journal records it.
            eprintln!("sn360-device-control-helper: {e}");
            ExitCode::from(0)
        }
    }
}

fn run() -> Result<sda_device_control::UsbPolicyAction, Box<dyn std::error::Error>> {
    let env = collect_env();
    let candidate = parse_udev_environment(&env)?;
    let transaction_id = format!("udev-{}", std::process::id());
    let req = build_query_request(transaction_id, candidate);
    let frame = encode_query_request(&req)?;

    let socket_path =
        std::env::var("SN360_DEVICE_CONTROL_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.to_string());

    let deadline = Instant::now() + HELPER_TIMEOUT;
    let mut stream = UnixStream::connect(&socket_path)?;
    stream.set_write_timeout(Some(HELPER_TIMEOUT))?;
    stream.set_read_timeout(Some(remaining(deadline)))?;
    stream.write_all(&frame)?;
    stream.flush()?;

    let mut buf = Vec::with_capacity(1024);
    stream.read_to_end(&mut buf)?;
    if buf.is_empty() {
        return Err("agent closed the socket before sending a response".into());
    }
    let line = match buf.iter().position(|b| *b == b'\n') {
        Some(idx) => &buf[..=idx],
        None => &buf[..],
    };
    let resp = decode_query_response(line)?;
    if resp.v != USB_IPC_PROTOCOL_VERSION {
        return Err(format!("unsupported protocol version {}", resp.v).into());
    }
    Ok(resp.decision.action)
}

fn collect_env() -> HashMap<String, String> {
    std::env::vars().collect()
}

fn remaining(deadline: Instant) -> Duration {
    deadline
        .checked_duration_since(Instant::now())
        .unwrap_or_else(|| Duration::from_millis(50))
}
