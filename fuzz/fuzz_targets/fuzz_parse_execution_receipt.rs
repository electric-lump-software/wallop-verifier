//! Fuzz target for the execution-receipt schema dispatcher.
//!
//! Feeds arbitrary bytes (reinterpreted as UTF-8 strings where valid)
//! into `parse_execution_receipt`. The function MUST NOT panic on any
//! input — every invalid input should produce `Err(_)`. A panic is a
//! P1 finding; a `PayloadShapeMismatch` that admits a shape the spec
//! says should reject is a P0 finding.
//!
//! Run (from the crate root):
//!
//!     cargo +nightly fuzz run fuzz_parse_execution_receipt
//!
//! For an 8-hour bounded run:
//!
//!     cargo +nightly fuzz run fuzz_parse_execution_receipt -- -max_total_time=28800
#![no_main]

use libfuzzer_sys::fuzz_target;
use wallop_verifier::parse_execution_receipt;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_execution_receipt(s);
    }
});
