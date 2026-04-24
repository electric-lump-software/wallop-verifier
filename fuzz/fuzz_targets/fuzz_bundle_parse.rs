//! Fuzz target for `ProofBundle::from_json`.
//!
//! The proof bundle is the public ingress for every third-party
//! verifier. Arbitrary JSON (and arbitrary bytes reinterpreted as JSON)
//! MUST NEVER panic the parser. A panic here means a hostile bundle
//! served over HTTP can crash any consumer that calls `from_json` in
//! a naive error-handling loop.
//!
//! Run (from the crate root):
//!
//!     cargo +nightly fuzz run fuzz_bundle_parse
#![no_main]

use libfuzzer_sys::fuzz_target;
use wallop_verifier::bundle::ProofBundle;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ProofBundle::from_json(s);
    }
});
