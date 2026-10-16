//! The grid-frequency path runs inside wasm32: the seed, the winners, and
//! full bundles through verify_bundle_with.
#![cfg(target_arch = "wasm32")]

use wallop_verifier::_test_support::{FreqParams, MockResolver, build_freq_bundle};
use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::verify_steps::{VerifierMode, verify_bundle_with};
use wasm_bindgen_test::*;

fn report(p: &FreqParams) -> wallop_verifier::verify_steps::VerificationReport {
    let (json, pk_hex, kid) = build_freq_bundle(p);
    let pk: [u8; 32] = hex::decode(pk_hex).unwrap().try_into().unwrap();
    verify_bundle_with(
        &ProofBundle::from_json(&json).unwrap(),
        &MockResolver::new(&kid, pk),
        VerifierMode::Attestable,
    )
}

#[wasm_bindgen_test]
fn frequency_seed_matches_core_in_wasm() {
    let (seed, _) = wallop_verifier::compute_seed_freq(
        &"ab".repeat(32),
        "140117383b03a0c0c7a899a32b8cbd2ffff9e2569504037c358ee8c7c2efe2fd",
        "50018;50012;49983;49980;49953;49912;49883;49887",
    );
    assert_eq!(
        hex::encode(seed),
        "ab4a8f4bba2b29e391e185625a5b963d026c9f8d3f84bd116aeeae31e864b295"
    );
}

#[wasm_bindgen_test]
fn frequency_bundles_verify_in_wasm() {
    for p in [FreqParams::value(), FreqParams::fallback()] {
        let r = report(&p);
        assert!(r.passed(), "{:?}", r.steps);
    }
}

#[wasm_bindgen_test]
fn a_late_frequency_lock_fails_in_wasm() {
    let p = FreqParams {
        locked_at: "2026-10-14T19:53:00.500000Z".into(),
        ..FreqParams::value()
    };
    assert!(!report(&p).passed());
}

#[wasm_bindgen_test]
fn a_weather_seed_over_a_frequency_value_fails_in_wasm() {
    let p = FreqParams {
        seed_from: Some(None),
        ..FreqParams::value()
    };
    assert!(!report(&p).passed());
}
