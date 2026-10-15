//! Lock v6 / execution v5 checks through the full pipeline.

use super::*;
use crate::_test_support::{MockResolver, V6Params, build_v6_bundle};

pub(super) fn run_json(json: &str, pk_hex: &str, kid: &str) -> VerificationReport {
    let pk: [u8; 32] = hex::decode(pk_hex).unwrap().try_into().unwrap();
    verify_bundle_with(
        &ProofBundle::from_json(json).unwrap(),
        &MockResolver::new(kid, pk),
        VerifierMode::Attestable,
    )
}

pub(super) fn run(p: &V6Params) -> VerificationReport {
    let (json, pk_hex, kid) = build_v6_bundle(p);
    run_json(&json, &pk_hex, &kid)
}

pub(super) fn status(report: &VerificationReport, name: StepName) -> &StepStatus {
    &report.steps.iter().find(|s| s.name == name).unwrap().status
}

pub(super) fn assert_step_fails(report: &VerificationReport, name: StepName, needle: &str) {
    match status(report, name) {
        StepStatus::Fail(reason) => {
            assert!(
                reason.contains(needle),
                "{name}: {reason:?} lacks {needle:?}"
            )
        }
        other => panic!("{name}: expected Fail containing {needle:?}, got {other:?}"),
    }
    assert!(!report.passed());
}

#[test]
fn v6_bundles_pass_bundle_shape() {
    for p in [
        V6Params::weather(),
        V6Params::fallback(),
        V6Params::backup(),
    ] {
        assert_eq!(
            status(&run(&p), StepName::BundleShape),
            &StepStatus::Pass,
            "{p:?}"
        );
    }
}

#[test]
fn v6_lock_with_inline_key_fails_bundle_shape() {
    let (json, pk_hex, kid) = build_v6_bundle(&V6Params::weather());
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    v["lock_receipt"]["operator_public_key_hex"] = serde_json::json!(pk_hex.clone());
    assert_step_fails(
        &run_json(&v.to_string(), &pk_hex, &kid),
        StepName::BundleShape,
        "downgrade-relabel",
    );
}

#[test]
fn v5_exec_with_inline_key_fails_bundle_shape() {
    let (json, pk_hex, kid) = build_v6_bundle(&V6Params::weather());
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    v["execution_receipt"]["infrastructure_public_key_hex"] = serde_json::json!(pk_hex.clone());
    assert_step_fails(
        &run_json(&v.to_string(), &pk_hex, &kid),
        StepName::BundleShape,
        "downgrade-relabel",
    );
}

#[test]
fn v6_lock_naming_the_backup_fails_bundle_shape() {
    let p = V6Params {
        lock_station: "wmo-03462".into(),
        ..V6Params::weather()
    };
    assert_step_fails(&run(&p), StepName::BundleShape, "weather_station");
}

#[test]
fn v6_lock_with_the_forecast_tag_fails_bundle_shape() {
    let p = V6Params {
        lock_entropy_composition: crate::protocol::receipts::ENTROPY_COMPOSITION.into(),
        ..V6Params::weather()
    };
    assert_step_fails(&run(&p), StepName::BundleShape, "entropy_composition");
}

#[test]
fn v5_exec_with_the_forecast_tag_fails_bundle_shape() {
    let p = V6Params {
        exec_entropy_composition: crate::protocol::receipts::ENTROPY_COMPOSITION.into(),
        ..V6Params::weather()
    };
    assert_step_fails(&run(&p), StepName::BundleShape, "entropy_composition");
}

#[test]
fn v5_exec_with_a_v5_era_reason_fails_bundle_shape() {
    let p = V6Params {
        weather_fallback_reason: Some("unreachable".into()),
        ..V6Params::fallback()
    };
    assert_step_fails(&run(&p), StepName::BundleShape, "weather_fallback_reason");
}

#[test]
fn v5_exec_with_a_bad_value_fails_bundle_shape() {
    let p = V6Params {
        weather_value: Some("1013".into()),
        ..V6Params::weather()
    };
    assert_step_fails(&run(&p), StepName::BundleShape, "weather_value");
}

#[test]
fn v5_exec_naming_an_unknown_station_fails_bundle_shape() {
    let p = V6Params {
        exec_station: Some("wmo-03772".into()),
        ..V6Params::weather()
    };
    assert_step_fails(&run(&p), StepName::BundleShape, "weather_station");
}
