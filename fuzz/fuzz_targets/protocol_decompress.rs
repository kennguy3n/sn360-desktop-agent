//! Fuzz the zlib decompression helper used on server → agent frames.
//!
//! A malformed compressed payload must never panic or allocate an
//! unbounded buffer.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sda_comms::protocol::decompress_payload;

fuzz_target!(|data: &[u8]| {
    let _ = decompress_payload(data);
});
