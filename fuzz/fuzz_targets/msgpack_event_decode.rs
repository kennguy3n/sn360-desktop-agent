//! Fuzz the MessagePack event decoder.
//!
//! When the enhanced protocol is enabled the agent round-trips
//! `EventKind` values through `rmp-serde`; arbitrary server-side
//! input must fail gracefully with `MsgPackError`, never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sda_comms::msgpack::MessagePackSerializer;

fuzz_target!(|data: &[u8]| {
    let s = MessagePackSerializer;
    let _ = s.decode_event(data);
    let _ = s.decode_kind(data);
});
