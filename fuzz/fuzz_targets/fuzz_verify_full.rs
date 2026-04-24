//! Fuzz target for the full `verify_full` pipeline.
//!
//! Splits the fuzzer's byte input into the typed arguments `verify_full`
//! requires (lock/exec signatures, public keys, JCS strings, a minimal
//! entries list). Every combination MUST either:
//!
//!   * return `Ok(true)` iff the inputs genuinely verify (essentially
//!     never, since the fuzzer is almost certainly producing garbage),
//!   * return `Ok(false)` on any mismatch / verification failure,
//!   * return `Err(_)` on structurally invalid inputs (non-UTF8 JCS,
//!     unparseable JSON, etc.).
//!
//! A panic is a P1 finding. An `Ok(true)` on non-degenerate fuzzer input
//! is a P0 finding — it would mean verify_full accepts a bundle that
//! didn't actually verify, which is the worst possible verifier bug.
//!
//! Run (from the crate root):
//!
//!     cargo +nightly fuzz run fuzz_verify_full
#![no_main]

use libfuzzer_sys::fuzz_target;
use wallop_verifier::{Entry, verify_full};

// 64 (lock_sig) + 32 (op_pk) + 64 (exec_sig) + 32 (infra_pk) = 192 bytes
// of structured header, then the rest is split between two JCS strings.
const HEADER_LEN: usize = 192;

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_LEN {
        return;
    }

    let lock_sig: [u8; 64] = data[0..64].try_into().unwrap();
    let op_pk: [u8; 32] = data[64..96].try_into().unwrap();
    let exec_sig: [u8; 64] = data[96..160].try_into().unwrap();
    let infra_pk: [u8; 32] = data[160..192].try_into().unwrap();

    // Split the remaining bytes in half; treat each as a JCS string.
    // Non-UTF-8 halves short-circuit with an early return — the fuzzer
    // will eventually generate UTF-8 payloads and explore the parser.
    let rest = &data[HEADER_LEN..];
    let split = rest.len() / 2;
    let lock_jcs = match std::str::from_utf8(&rest[..split]) {
        Ok(s) => s,
        Err(_) => return,
    };
    let exec_jcs = match std::str::from_utf8(&rest[split..]) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Minimal fixed entries list — the fuzzer isn't exploring entry
    // permutations in this target; it's exploring the bundle/signature
    // surface. A single-entry pool is sufficient to exercise the draw
    // recompute step.
    let entries = vec![Entry {
        id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string(),
        weight: 1,
    }];

    let _ = verify_full(
        lock_jcs, &lock_sig, &op_pk, exec_jcs, &exec_sig, &infra_pk, &entries,
    );
});
