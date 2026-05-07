//! Fuzz the TRDS rule-bundle MessagePack loader.
//!
//! Rule bundles are signed server-side but the parser runs before the
//! signature check, so any panic in `RuleBundle::from_msgpack` is an
//! attacker-reachable crash.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sda_local_detection::rule_store::RuleBundle;

fuzz_target!(|data: &[u8]| {
    let _ = RuleBundle::from_msgpack(data);
});
