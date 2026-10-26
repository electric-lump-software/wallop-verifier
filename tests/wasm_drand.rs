//! Proves the drand BLS check runs inside wasm32, not just natively.
#![cfg(target_arch = "wasm32")]

use wallop_verifier::drand::{QUICKNET_CHAIN_HASH, verify_drand_round};
use wasm_bindgen_test::*;

// Real quicknet round 1000, from https://api.drand.sh/<chain>/public/1000
const SIG_1000: &str = "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39";
const RAND_1000: &str = "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd";

#[wasm_bindgen_test]
fn real_beacon_verifies_in_wasm() {
    assert!(verify_drand_round(QUICKNET_CHAIN_HASH, 1000, SIG_1000, RAND_1000).is_ok());
}

#[wasm_bindgen_test]
fn zero_signature_fails_in_wasm() {
    assert!(verify_drand_round(QUICKNET_CHAIN_HASH, 1000, &"00".repeat(48), RAND_1000).is_err());
}

#[wasm_bindgen_test]
fn wrong_round_fails_in_wasm() {
    assert!(verify_drand_round(QUICKNET_CHAIN_HASH, 1001, SIG_1000, RAND_1000).is_err());
}
