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

/// For each case in `V6_NEGATIVE_CASES`, a substring of one failing step's
/// message, so each case fails for the reason its name gives.
const NEGATIVE_CASE_REASONS: &[(&str, &str)] = &[
    ("weather_time_not_whole_hour", "is not a whole UTC hour"),
    ("weather_time_not_calendar", "is not a valid calendar time"),
    (
        "weather_time_not_derived_from_round",
        "is not the observation hour for drand round",
    ),
    (
        "locked_at_after_latest_lock_at",
        "is later than weather_time minus 46 minutes",
    ),
    (
        "round_published_before_lock",
        "not after lock receipt locked_at",
    ),
    (
        "lock_station_not_first_in_tag",
        "is not the primary station",
    ),
    ("exec_station_not_in_tag", "\"wmo-03772\" is not one of"),
    (
        "backup_named_on_fallback",
        "a fallback execution receipt must name the primary station",
    ),
    (
        "observation_time_not_weather_time",
        "weather_observation_time 2026-10-01T20:00:00.000000Z must equal lock weather_time",
    ),
    (
        "partial_fallback_value_null_reason_null",
        "it has weather_value null, weather_observation_time null, weather_fallback_reason null",
    ),
    (
        "partial_fallback_reason_set_value_set",
        "it has weather_value set, weather_observation_time set, weather_fallback_reason set",
    ),
    ("value_grammar_minus_zero", "weather_value t is -0"),
    ("value_grammar_leading_zero", "has a leading zero"),
    ("value_grammar_three_parts", "must have 4 parts"),
    ("value_out_of_bounds", "is outside [-900, 600]"),
    (
        "v5_reason_in_v6_exec",
        "weather_fallback_reason \"unreachable\" is not \"no_observation_by_deadline\"",
    ),
    (
        "wrong_entropy_composition",
        "lock receipt validation: unknown entropy_composition",
    ),
    (
        "wrong_entropy_composition_exec",
        "exec receipt validation: unknown entropy_composition",
    ),
    ("lock_v6_with_exec_v4", "must be used together"),
    ("lock_v5_with_exec_v5", "must be used together"),
    (
        "inline_key_on_lock_v6",
        "lock receipt schema_version=\"6\" must not carry inline public_key_hex",
    ),
    (
        "inline_key_on_exec_v5",
        "execution receipt schema_version=\"5\" must not carry inline public_key_hex",
    ),
    (
        "executed_before_round_published",
        "is before drand round 32693812 was published",
    ),
];

#[test]
fn every_negative_case_fails_at_exactly_its_expected_steps() {
    assert_eq!(
        NEGATIVE_CASE_REASONS.len(),
        V6_NEGATIVE_CASES.len(),
        "one reason per case"
    );
    let mut names: Vec<&str> = NEGATIVE_CASE_REASONS.iter().map(|(n, _)| *n).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        NEGATIVE_CASE_REASONS.len(),
        "case names in NEGATIVE_CASE_REASONS are unique"
    );
    for (name, steps) in V6_NEGATIVE_CASES {
        let (json, pk_hex, kid) = v6_negative_bundle(name);
        let report = verify_json(&json, &pk_hex, &kid);
        assert!(!report.passed(), "{name} passed");
        let mut want: Vec<String> = steps.iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(failing_steps(&report), want, "{name}: {:?}", report.steps);

        // Every step outside the expected set passes.
        for step in &report.steps {
            if !matches!(step.status, StepStatus::Fail(_)) {
                assert_eq!(step.status, StepStatus::Pass, "{name}: {}", step.name);
            }
        }

        // And at least one failing step fails for the named reason.
        let reason = NEGATIVE_CASE_REASONS
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("{name} has no expected reason"))
            .1;
        assert!(
            report
                .steps
                .iter()
                .any(|s| matches!(&s.status, StepStatus::Fail(m) if m.contains(reason))),
            "{name}: no failing step says {reason:?}: {:?}",
            report.steps
        );
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
