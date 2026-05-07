//! Fuzz the Wazuh wire-format decoder.
//!
//! `WazuhMessage::decode` is the first function to touch any byte
//! coming off the TCP socket, so a parse panic here turns into an
//! agent crash loop. libFuzzer drives arbitrary byte sequences
//! through it and flags any input that panics or hangs.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sda_comms::protocol::WazuhMessage;

fuzz_target!(|data: &[u8]| {
    let _ = WazuhMessage::decode(data);
});
