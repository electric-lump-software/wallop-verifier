//! Lock schema 6 / execution schema 5 bundles through the public API.

use wallop_verifier::_test_support::{
    MockResolver, V6_NEGATIVE_CASES, V6Params, build_v6_bundle, v6_negative_bundle,
};
use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::verify_steps::{
    StepName, StepStatus, VerificationReport, VerifierMode, verify_bundle, verify_bundle_with,
};

fn verify_json(json: &str, pk_hex: &str, kid: &str) -> VerificationReport {
    let pk: [u8; 32] = hex::decode(pk_hex).unwrap().try_into().unwrap();
    verify_bundle_with(
        &ProofBundle::from_json(json).unwrap(),
        &MockResolver::new(kid, pk),
        VerifierMode::Attestable,
    )
}

fn verify(p: &V6Params) -> VerificationReport {
    let (json, pk_hex, kid) = build_v6_bundle(p);
    verify_json(&json, &pk_hex, &kid)
}

/// The snake_case names of every step that fails, sorted.
fn failing_steps(report: &VerificationReport) -> Vec<String> {
    let mut got: Vec<String> = report
        .steps
        .iter()
        .filter(|s| matches!(s.status, StepStatus::Fail(_)))
        .map(|s| {
            serde_json::to_value(s.name)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    got.sort();
    got
}

#[test]
fn every_negative_case_fails_at_exactly_its_expected_steps() {
    for (name, steps) in V6_NEGATIVE_CASES {
        let (json, pk_hex, kid) = v6_negative_bundle(name);
        let report = verify_json(&json, &pk_hex, &kid);
        assert!(!report.passed(), "{name} passed");
        let mut want: Vec<String> = steps.iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(failing_steps(&report), want, "{name}: {:?}", report.steps);
    }
}

#[test]
fn lock_v6_with_exec_v4_still_passes_the_drand_step() {
    // The fixture's executed_at is after pub(R), so only the pairing fails.
    let (json, pk_hex, kid) = v6_negative_bundle("lock_v6_with_exec_v4");
    let report = verify_json(&json, &pk_hex, &kid);
    let drand = report
        .steps
        .iter()
        .find(|s| s.name == StepName::DrandBlsSignature)
        .unwrap();
    assert_eq!(drand.status, StepStatus::Pass);
}

#[test]
fn wrong_entropy_composition_exec_and_lock_v5_with_exec_v5_fail() {
    // Named here as well as in the loop above, so a missing case is obvious.
    for name in ["wrong_entropy_composition_exec", "lock_v5_with_exec_v5"] {
        assert!(
            V6_NEGATIVE_CASES.iter().any(|(n, _)| *n == name),
            "{name} missing"
        );
        let (json, pk_hex, kid) = v6_negative_bundle(name);
        let report = verify_json(&json, &pk_hex, &kid);
        assert!(!report.passed(), "{name} passed");
        let shape = report
            .steps
            .iter()
            .find(|s| s.name == StepName::BundleShape)
            .unwrap();
        assert!(
            matches!(shape.status, StepStatus::Fail(_)),
            "{name}: {:?}",
            shape.status
        );
    }
}

#[test]
fn weather_backup_and_fallback_bundles_pass() {
    for p in [
        V6Params::weather(),
        V6Params::backup(),
        V6Params::fallback(),
    ] {
        assert!(verify(&p).passed(), "{p:?}");
    }
}

#[test]
fn a_shifted_weather_time_fails_the_gate() {
    let mut p = V6Params::weather();
    p.weather_time = p.weather_time.replace("T19:", "T18:");
    p.weather_observation_time = Some(p.weather_time.clone());
    let report = verify(&p);
    assert!(!report.passed());
    let window = report
        .steps
        .iter()
        .find(|s| s.name == StepName::WeatherObservationWindow)
        .unwrap();
    assert!(matches!(window.status, StepStatus::Fail(_)));
}

#[test]
fn self_consistency_mode_cannot_pass_a_v6_bundle() {
    // No inline keys: the bundle-embedded resolver finds nothing.
    let (json, _, _) = build_v6_bundle(&V6Params::weather());
    assert!(!verify_bundle(&ProofBundle::from_json(&json).unwrap()).passed());
}
