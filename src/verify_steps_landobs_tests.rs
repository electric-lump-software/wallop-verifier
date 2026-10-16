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

#[test]
fn lock_v6_with_exec_v4_fails_bundle_shape() {
    let p = V6Params {
        exec_schema: "4".into(),
        exec_entropy_composition: crate::protocol::receipts::ENTROPY_COMPOSITION.into(),
        ..V6Params::weather()
    };
    assert_eq!(
        status(&run(&p), StepName::BundleShape),
        &StepStatus::Fail(SCHEMA_PAIRING_ERROR.into())
    );
}

#[test]
fn lock_v5_with_exec_v5_fails_bundle_shape() {
    let p = V6Params {
        lock_schema: "5".into(),
        lock_entropy_composition: crate::protocol::receipts::ENTROPY_COMPOSITION.into(),
        ..V6Params::weather()
    };
    assert_eq!(
        status(&run(&p), StepName::BundleShape),
        &StepStatus::Fail(SCHEMA_PAIRING_ERROR.into())
    );
}

#[test]
fn lock_v4_with_exec_v5_fails_bundle_shape() {
    // Lock v4 needs the inline key on the wrapper, so the pairing rule is
    // the only thing wrong with this bundle.
    let p = V6Params {
        lock_schema: "4".into(),
        lock_entropy_composition: crate::protocol::receipts::ENTROPY_COMPOSITION.into(),
        ..V6Params::weather()
    };
    let (json, pk_hex, kid) = build_v6_bundle(&p);
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    v["lock_receipt"]["operator_public_key_hex"] = serde_json::json!(pk_hex.clone());
    assert_eq!(
        status(
            &run_json(&v.to_string(), &pk_hex, &kid),
            StepName::BundleShape
        ),
        &StepStatus::Fail(SCHEMA_PAIRING_ERROR.into())
    );
}

#[test]
fn v6_weather_time_off_the_hour_fails_bundle_shape() {
    for wt in ["2026-10-01T19:30:00.000000Z", "2026-10-01T19:00:00.000001Z"] {
        let p = V6Params {
            weather_time: wt.into(),
            weather_observation_time: Some(wt.into()),
            ..V6Params::weather()
        };
        assert_step_fails(&run(&p), StepName::BundleShape, "whole UTC hour");
    }
}

#[test]
fn v6_weather_time_that_only_normalises_to_an_hour_fails_bundle_shape() {
    let wt = "2026-10-01T18:60:00.000000Z";
    let p = V6Params {
        weather_time: wt.into(),
        weather_observation_time: Some(wt.into()),
        ..V6Params::weather()
    };
    assert_step_fails(&run(&p), StepName::BundleShape, "calendar time");
}

#[test]
fn legacy_v5_lock_with_off_hour_weather_time_still_passes_bundle_shape() {
    // Lock v5 has no whole-hour rule; that behaviour is unchanged.
    let (json, pk_hex, kid) = crate::_test_support::build_valid_v5_bundle(
        &crate::_test_support::v6_entries(),
        Some("1013"),
        2,
    );
    let report = run_json(&json, &pk_hex, &kid);
    assert_eq!(status(&report, StepName::BundleShape), &StepStatus::Pass);
}

#[test]
fn v6_lock_with_a_normalising_locked_at_fails_bundle_shape() {
    // 17:99 would otherwise be read as 18:39.
    let p = V6Params {
        locked_at: "2026-10-01T17:99:00.000000Z".into(),
        ..V6Params::weather()
    };
    assert_step_fails(&run(&p), StepName::BundleShape, "lock.locked_at");
}

#[test]
fn v5_exec_with_a_normalising_executed_at_fails_bundle_shape() {
    let p = V6Params {
        executed_at: "2026-10-01T19:60:05.000000Z".into(),
        ..V6Params::weather()
    };
    assert_step_fails(&run(&p), StepName::BundleShape, "exec.executed_at");
}

#[test]
fn v5_exec_with_a_normalising_observation_time_fails_bundle_shape() {
    let p = V6Params {
        weather_observation_time: Some("2026-10-01T18:60:00.000000Z".into()),
        ..V6Params::weather()
    };
    assert_step_fails(
        &run(&p),
        StepName::BundleShape,
        "exec.weather_observation_time",
    );
}

#[test]
fn legacy_v5_lock_with_a_normalising_locked_at_still_passes_bundle_shape() {
    // Lock v4/v5 timestamps are checked for shape only; that is unchanged.
    let (json, pk_hex, kid) = crate::_test_support::build_valid_v5_bundle(
        &crate::_test_support::v6_entries(),
        Some("1013"),
        2,
    );
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let mut lock: serde_json::Value =
        serde_json::from_str(v["lock_receipt"]["payload_jcs"].as_str().unwrap()).unwrap();
    lock["locked_at"] = serde_json::json!("2023-08-23T15:99:00.000000Z");
    v["lock_receipt"]["payload_jcs"] = serde_json::json!(lock.to_string());
    let report = run_json(&v.to_string(), &pk_hex, &kid);
    assert_eq!(status(&report, StepName::BundleShape), &StepStatus::Pass);
}

use crate::protocol::landobs_v1;

fn derived_weather_time() -> i64 {
    landobs_v1::weather_time_for_round(crate::_test_support::BEACON_V6_ROUND).unwrap()
}

fn latest_lock(weather_time: i64) -> i64 {
    landobs_v1::latest_lock_at(weather_time).unwrap()
}

#[test]
fn v6_window_passes_for_weather_backup_and_fallback() {
    for p in [
        V6Params::weather(),
        V6Params::backup(),
        V6Params::fallback(),
    ] {
        assert_eq!(
            status(&run(&p), StepName::WeatherObservationWindow),
            &StepStatus::Pass,
            "{p:?}"
        );
    }
}

#[test]
fn v6_weather_time_an_hour_early_fails() {
    let wt = derived_weather_time() - 3600;
    let p = V6Params {
        weather_time: format_canonical(wt, 0),
        weather_observation_time: Some(format_canonical(wt, 0)),
        locked_at: format_canonical(latest_lock(wt) - 60, 0),
        ..V6Params::weather()
    };
    assert_step_fails(
        &run(&p),
        StepName::WeatherObservationWindow,
        "not the observation hour",
    );
}

#[test]
fn v6_weather_time_an_hour_late_fails() {
    let wt = derived_weather_time() + 3600;
    let p = V6Params {
        weather_time: format_canonical(wt, 0),
        weather_observation_time: Some(format_canonical(wt, 0)),
        ..V6Params::weather()
    };
    assert_step_fails(
        &run(&p),
        StepName::WeatherObservationWindow,
        "not the observation hour",
    );
}

#[test]
fn v6_lock_exactly_at_the_offset_passes() {
    let p = V6Params {
        locked_at: format_canonical(latest_lock(derived_weather_time()), 0),
        ..V6Params::weather()
    };
    assert_eq!(
        status(&run(&p), StepName::WeatherObservationWindow),
        &StepStatus::Pass
    );
}

#[test]
fn v6_lock_one_microsecond_late_fails() {
    let p = V6Params {
        locked_at: format_canonical(latest_lock(derived_weather_time()), 1),
        ..V6Params::weather()
    };
    assert_step_fails(
        &run(&p),
        StepName::WeatherObservationWindow,
        "minus 46 minutes",
    );
}

#[test]
fn v6_normalising_locked_at_fails_the_window() {
    // One minute before the latest lock time, written with the minutes
    // pushed past 59 into the previous hour; a lenient parse reads it as a
    // valid lock time.
    let honest = format_canonical(latest_lock(derived_weather_time()) - 60, 0);
    let earlier = format_canonical(latest_lock(derived_weather_time()) - 60 - 3600, 0);
    let minutes: u32 = earlier[14..16].parse().unwrap();
    let locked_at = format!("{}{}{}", &earlier[..14], minutes + 60, &earlier[16..]);
    assert_eq!(
        chrono_parse_canonical(&locked_at).unwrap().timestamp(),
        chrono_parse_canonical(&honest).unwrap().timestamp()
    );
    let p = V6Params {
        locked_at,
        ..V6Params::weather()
    };
    assert_step_fails(
        &run(&p),
        StepName::WeatherObservationWindow,
        "lock.locked_at",
    );
}

#[test]
fn v6_observation_an_hour_before_weather_time_fails() {
    // Allowed under lock v5; not under v6.
    let p = V6Params {
        weather_observation_time: Some(format_canonical(derived_weather_time() - 3600, 0)),
        ..V6Params::weather()
    };
    assert_step_fails(&run(&p), StepName::WeatherObservationWindow, "must equal");
}

#[test]
fn v6_partial_weather_fails() {
    let cases = [
        V6Params {
            weather_observation_time: None,
            ..V6Params::weather()
        },
        V6Params {
            weather_value: None,
            ..V6Params::weather()
        },
        V6Params {
            weather_fallback_reason: Some("no_observation_by_deadline".into()),
            ..V6Params::weather()
        },
        V6Params {
            weather_fallback_reason: None,
            ..V6Params::fallback()
        },
        V6Params {
            weather_value: None,
            weather_fallback_reason: Some("no_observation_by_deadline".into()),
            ..V6Params::weather()
        },
        V6Params {
            weather_observation_time: None,
            weather_fallback_reason: Some("no_observation_by_deadline".into()),
            ..V6Params::weather()
        },
    ];
    for p in cases {
        assert_step_fails(&run(&p), StepName::WeatherObservationWindow, "must carry");
    }
}

#[test]
fn mismatched_schemas_fail_the_window() {
    let p = V6Params {
        exec_schema: "4".into(),
        exec_entropy_composition: crate::protocol::receipts::ENTROPY_COMPOSITION.into(),
        ..V6Params::weather()
    };
    assert_eq!(
        status(&run(&p), StepName::WeatherObservationWindow),
        &StepStatus::Fail(SCHEMA_PAIRING_ERROR.into())
    );
}

#[test]
fn legacy_v5_observation_an_hour_early_still_passes_the_window() {
    let (json, pk_hex, kid) = crate::_test_support::build_valid_v5_bundle(
        &crate::_test_support::v6_entries(),
        Some("1013"),
        2,
    );
    let edited = crate::_test_support::resign_exec(&json, |exec| {
        exec["weather_observation_time"] = serde_json::json!("2023-08-23T15:00:00.000000Z");
    });
    let report = run_json(&edited.to_string(), &pk_hex, &kid);
    assert_eq!(
        status(&report, StepName::WeatherObservationWindow),
        &StepStatus::Pass
    );
}

#[test]
fn v6_backup_station_passes_end_to_end() {
    let report = run(&V6Params::backup());
    assert_eq!(
        status(&report, StepName::ReceiptFieldConsistency),
        &StepStatus::Pass
    );
    assert!(report.passed(), "{:?}", report.steps);
}

#[test]
fn fallback_naming_the_backup_fails_field_consistency() {
    let p = V6Params {
        exec_station: Some("wmo-03462".into()),
        ..V6Params::fallback()
    };
    assert_step_fails(
        &run(&p),
        StepName::ReceiptFieldConsistency,
        "primary station",
    );
}

#[test]
fn v6_exec_station_outside_the_list_fails_field_consistency() {
    let p = V6Params {
        exec_station: Some("wmo-03772".into()),
        ..V6Params::weather()
    };
    assert_step_fails(
        &run(&p),
        StepName::ReceiptFieldConsistency,
        "weather_station",
    );
}

#[test]
fn v6_lock_station_not_primary_fails_field_consistency() {
    let p = V6Params {
        lock_station: "wmo-03462".into(),
        ..V6Params::backup()
    };
    assert_step_fails(
        &run(&p),
        StepName::ReceiptFieldConsistency,
        "weather_station",
    );
}

#[test]
fn mismatched_schemas_fail_field_consistency() {
    let p = V6Params {
        lock_schema: "5".into(),
        lock_entropy_composition: crate::protocol::receipts::ENTROPY_COMPOSITION.into(),
        ..V6Params::weather()
    };
    assert_eq!(
        status(&run(&p), StepName::ReceiptFieldConsistency),
        &StepStatus::Fail(SCHEMA_PAIRING_ERROR.into())
    );
}

#[test]
fn legacy_v5_station_difference_still_fails_field_consistency() {
    let (json, pk_hex, kid) = crate::_test_support::build_valid_v5_bundle(
        &crate::_test_support::v6_entries(),
        Some("1013"),
        2,
    );
    let edited = crate::_test_support::resign_exec(&json, |exec| {
        exec["weather_station"] = serde_json::json!("wmo-03462");
    });
    assert_step_fails(
        &run_json(&edited.to_string(), &pk_hex, &kid),
        StepName::ReceiptFieldConsistency,
        "weather_station",
    );
}

#[test]
fn station_errors_name_the_station_without_option_debug_text() {
    let exec = serde_json::json!({"weather_station": "wmo-03749", "weather_value": "x"});
    assert_eq!(
        check_landobs_stations(&serde_json::json!({}), &exec).unwrap_err(),
        "lock weather_station missing or not a string is not the primary station wmo-03749"
    );
    assert_eq!(
        check_landobs_stations(&serde_json::json!({"weather_station": 3749}), &exec).unwrap_err(),
        "lock weather_station missing or not a string is not the primary station wmo-03749"
    );
    assert_eq!(
        check_landobs_stations(&serde_json::json!({"weather_station": "wmo-03462"}), &exec)
            .unwrap_err(),
        "lock weather_station \"wmo-03462\" is not the primary station wmo-03749"
    );
    let lock = serde_json::json!({"weather_station": "wmo-03749"});
    let off_list = serde_json::json!({"weather_station": "wmo-03772", "weather_value": "x"});
    assert_eq!(
        check_landobs_stations(&lock, &off_list).unwrap_err(),
        "exec weather_station \"wmo-03772\" is not one of \"wmo-03749\", \"wmo-03462\""
    );
    assert_eq!(
        check_landobs_stations(&lock, &serde_json::json!({"weather_value": "x"})).unwrap_err(),
        "exec weather_station missing or not a string is not one of \"wmo-03749\", \"wmo-03462\""
    );
}

#[test]
fn landobs_cross_checked_fields_swap_weather_station_for_slug_and_fair_pick() {
    let only_legacy: Vec<&str> = CROSS_CHECKED_FIELDS
        .iter()
        .copied()
        .filter(|f| !CROSS_CHECKED_FIELDS_LANDOBS.contains(f))
        .collect();
    let only_landobs: Vec<&str> = CROSS_CHECKED_FIELDS_LANDOBS
        .iter()
        .copied()
        .filter(|f| !CROSS_CHECKED_FIELDS.contains(f))
        .collect();
    assert_eq!(only_legacy, ["weather_station"]);
    assert_eq!(only_landobs, ["operator_slug", "fair_pick_version"]);
}

fn published() -> i64 {
    crate::drand::quicknet_round_time(crate::_test_support::BEACON_V6_ROUND).unwrap()
}

#[test]
fn v6_bundles_pass_every_step() {
    for p in [
        V6Params::weather(),
        V6Params::fallback(),
        V6Params::backup(),
    ] {
        let report = run(&p);
        assert!(report.passed(), "{p:?}: {:?}", report.steps);
        for step in &report.steps {
            assert_eq!(step.status, StepStatus::Pass, "{}", step.name);
        }
    }
}

#[test]
fn v6_execution_exactly_at_publication_passes() {
    let p = V6Params {
        executed_at: format_canonical(published(), 0),
        ..V6Params::weather()
    };
    assert_eq!(
        status(&run(&p), StepName::DrandBlsSignature),
        &StepStatus::Pass
    );
}

#[test]
fn v6_execution_before_publication_fails() {
    let p = V6Params {
        executed_at: format_canonical(published() - 1, 999_999),
        ..V6Params::weather()
    };
    assert_step_fails(&run(&p), StepName::DrandBlsSignature, "before drand round");
}

#[test]
fn v6_normalising_executed_at_fails_the_drand_step() {
    // 09-31 is not a date; read leniently it becomes 10-01 20:00:05, five
    // seconds after the round published.
    assert_eq!(
        format_canonical(published() + 5, 0),
        "2026-10-01T20:00:05.000000Z"
    );
    let p = V6Params {
        executed_at: "2026-09-31T20:00:05.000000Z".into(),
        ..V6Params::weather()
    };
    assert_step_fails(
        &run(&p),
        StepName::DrandBlsSignature,
        "execution receipt executed_at (2026-09-31T20:00:05.000000Z)",
    );
}

#[test]
fn legacy_v4_exec_before_publication_still_passes_the_drand_step() {
    let (json, pk_hex, kid) = crate::_test_support::build_valid_v5_bundle(
        &crate::_test_support::v6_entries(),
        Some("1013"),
        2,
    );
    let edited = crate::_test_support::resign_exec(&json, |exec| {
        exec["executed_at"] = serde_json::json!("2023-08-23T15:55:00.000000Z");
    });
    let report = run_json(&edited.to_string(), &pk_hex, &kid);
    assert_eq!(
        status(&report, StepName::DrandBlsSignature),
        &StepStatus::Pass
    );
}

/// The seed and winner steps, which a pair with no seed rule skips.
fn is_seed_step(name: StepName) -> bool {
    matches!(
        name,
        StepName::SeedRecomputation | StepName::WinnerSelection
    )
}

/// A pair with no seed rule skips the seed and winner steps: never a pass,
/// never a guessed derivation.
fn assert_no_seed_rule_skip(step: &StepResult, case: &str) {
    assert!(
        matches!(&step.status, StepStatus::Skip(r) if r.starts_with("no seed rule for this tag pair")),
        "{case}: {} is {:?}",
        step.name,
        step.status
    );
}

#[test]
fn mismatched_schema_pairs_fail_exactly_shape_window_and_consistency() {
    let forecast = crate::protocol::receipts::ENTROPY_COMPOSITION.to_string();
    let lock_5_exec_5 = V6Params {
        lock_schema: "5".into(),
        lock_entropy_composition: forecast.clone(),
        ..V6Params::weather()
    };
    let lock_6_exec_4 = V6Params {
        exec_schema: "4".into(),
        exec_entropy_composition: forecast,
        ..V6Params::weather()
    };
    let expected = [
        StepName::BundleShape,
        StepName::WeatherObservationWindow,
        StepName::ReceiptFieldConsistency,
    ];
    for p in [lock_5_exec_5, lock_6_exec_4] {
        let report = run(&p);
        for step in &report.steps {
            if expected.contains(&step.name) {
                assert!(
                    matches!(step.status, StepStatus::Fail(_)),
                    "{p:?}: {} should fail, got {:?}",
                    step.name,
                    step.status
                );
            } else if is_seed_step(step.name) {
                assert_no_seed_rule_skip(step, &format!("{p:?}"));
            } else {
                assert_eq!(step.status, StepStatus::Pass, "{p:?}: {}", step.name);
            }
        }
        for name in &expected {
            assert!(
                report.steps.iter().any(|s| &s.name == name),
                "{name} missing"
            );
        }
    }
}

#[test]
fn null_value_and_reason_naming_the_backup_fails_window_and_consistency() {
    let p = V6Params {
        exec_station: Some(landobs_v1::STATIONS[1].into()),
        weather_fallback_reason: None,
        ..V6Params::fallback()
    };
    let report = run(&p);
    let failing: Vec<StepName> = report
        .steps
        .iter()
        .filter(|s| matches!(s.status, StepStatus::Fail(_)))
        .map(|s| s.name)
        .collect();
    assert_eq!(
        failing,
        [
            StepName::ReceiptFieldConsistency,
            StepName::WeatherObservationWindow
        ],
        "{:?}",
        report.steps
    );
}

// ── Rules chosen by (schema_version, entropy_composition) ──────────────

/// A tag no receipt schema carries today: a later Land Observations
/// revision that this verifier has never heard of.
const UNKNOWN_TAG: &str = "drand-quicknet+metoffice-landobs-v2";
const NOT_KNOWN: &str = "is not a combination this verifier knows";

/// Every step that fails, in report order.
fn failing(report: &VerificationReport) -> Vec<StepName> {
    report
        .steps
        .iter()
        .filter(|s| matches!(s.status, StepStatus::Fail(_)))
        .map(|s| s.name)
        .collect()
}

/// What an unknown pairing must fail: the shape gate (tag validator) and
/// both steps that pick their rules from the pair. Nothing else.
const FAILS_CLOSED: [StepName; 3] = [
    StepName::ReceiptFieldConsistency,
    StepName::WeatherObservationWindow,
    StepName::BundleShape,
];

/// Apply `lock_edit` and `exec_edit` to the two signed payloads, re-sign
/// both receipts with the test key, and re-link the execution receipt to
/// the new lock.
fn resign_both(
    json: &str,
    lock_edit: impl FnOnce(&mut serde_json::Value),
    exec_edit: impl FnOnce(&mut serde_json::Value),
) -> String {
    use ed25519_dalek::Signer;
    let sk = crate::_test_support::test_signing_key();
    let mut bundle: serde_json::Value = serde_json::from_str(json).unwrap();
    let payload = |b: &serde_json::Value, w: &str| -> serde_json::Value {
        serde_json::from_str(b[w]["payload_jcs"].as_str().unwrap()).unwrap()
    };
    let mut lock = payload(&bundle, "lock_receipt");
    lock_edit(&mut lock);
    let lock_jcs = lock.to_string();
    let mut exec = payload(&bundle, "execution_receipt");
    exec_edit(&mut exec);
    exec["lock_receipt_hash"] = serde_json::json!(lock_receipt_hash(&lock_jcs));
    let exec_jcs = exec.to_string();
    for (w, jcs) in [("lock_receipt", lock_jcs), ("execution_receipt", exec_jcs)] {
        bundle[w]["signature_hex"] =
            serde_json::json!(hex::encode(sk.sign(jcs.as_bytes()).to_bytes()));
        bundle[w]["payload_jcs"] = serde_json::json!(jcs);
    }
    bundle.to_string()
}

/// Set the lock and execution `entropy_composition` and re-sign both.
fn retag(json: &str, lock_tag: &str, exec_tag: &str) -> String {
    resign_both(
        json,
        |lock| lock["entropy_composition"] = serde_json::json!(lock_tag),
        |exec| exec["entropy_composition"] = serde_json::json!(exec_tag),
    )
}

fn assert_fails_closed(report: &VerificationReport, case: &str) {
    assert_eq!(failing(report), FAILS_CLOSED, "{case}: {:?}", report.steps);
    assert!(!report.passed(), "{case}");
    for step in &report.steps {
        if is_seed_step(step.name) {
            assert_no_seed_rule_skip(step, case);
        } else if !FAILS_CLOSED.contains(&step.name) {
            assert!(
                matches!(step.status, StepStatus::Pass | StepStatus::NotApplicable(_)),
                "{case}: {} is {:?}",
                step.name,
                step.status
            );
        }
    }
}

#[test]
fn v6_with_an_unknown_tag_fails_closed() {
    let forecast = crate::protocol::receipts::ENTROPY_COMPOSITION;
    let landobs = landobs_v1::ENTROPY_COMPOSITION;
    for (lock_tag, exec_tag) in [
        (UNKNOWN_TAG, UNKNOWN_TAG),
        (UNKNOWN_TAG, landobs),
        (landobs, UNKNOWN_TAG),
        (forecast, forecast),
        (forecast, landobs),
        (landobs, forecast),
        ("", ""),
    ] {
        let case = format!("lock 6 {lock_tag:?} / exec 5 {exec_tag:?}");
        for p in [V6Params::weather(), V6Params::fallback()] {
            let report = run(&V6Params {
                lock_entropy_composition: lock_tag.into(),
                exec_entropy_composition: exec_tag.into(),
                ..p
            });
            assert_fails_closed(&report, &case);
            // Never treated as Land Observations, never skipped, never
            // waved through as not applicable: the window and the field
            // check both name the unknown pairing.
            for name in [
                StepName::WeatherObservationWindow,
                StepName::ReceiptFieldConsistency,
            ] {
                assert_step_fails(&report, name, NOT_KNOWN);
            }
        }
    }
}

#[test]
fn v6_unknown_tag_names_the_receipt_and_the_tag() {
    let report = run(&V6Params {
        lock_entropy_composition: UNKNOWN_TAG.into(),
        exec_entropy_composition: UNKNOWN_TAG.into(),
        ..V6Params::weather()
    });
    assert_eq!(
        status(&report, StepName::WeatherObservationWindow),
        &StepStatus::Fail(format!(
            "lock receipt schema_version \"6\" with entropy_composition \"{UNKNOWN_TAG}\" {NOT_KNOWN}"
        ))
    );
    let report = run(&V6Params {
        exec_entropy_composition: UNKNOWN_TAG.into(),
        ..V6Params::weather()
    });
    assert_eq!(
        status(&report, StepName::ReceiptFieldConsistency),
        &StepStatus::Fail(format!(
            "execution receipt schema_version \"5\" with entropy_composition \"{UNKNOWN_TAG}\" {NOT_KNOWN}"
        ))
    );
}

#[test]
fn legacy_v5_v4_with_an_unexpected_tag_fails_closed() {
    let forecast = crate::protocol::receipts::ENTROPY_COMPOSITION;
    let landobs = landobs_v1::ENTROPY_COMPOSITION;
    let entries = crate::_test_support::v6_entries();
    for weather in [Some("1013"), None] {
        let (json, pk_hex, kid) = crate::_test_support::build_valid_v5_bundle(&entries, weather, 2);
        // The untouched bundle passes, and re-signing alone changes nothing.
        assert!(run_json(&json, &pk_hex, &kid).passed());
        assert!(run_json(&retag(&json, forecast, forecast), &pk_hex, &kid).passed());
        for (lock_tag, exec_tag) in [
            (UNKNOWN_TAG, UNKNOWN_TAG),
            (landobs, landobs),
            (UNKNOWN_TAG, forecast),
            (forecast, UNKNOWN_TAG),
            (forecast, landobs),
        ] {
            let report = run_json(&retag(&json, lock_tag, exec_tag), &pk_hex, &kid);
            let case = format!("{weather:?}: lock 5 {lock_tag:?} / exec 4 {exec_tag:?}");
            assert_fails_closed(&report, &case);
            assert_step_fails(&report, StepName::WeatherObservationWindow, NOT_KNOWN);
            assert_step_fails(&report, StepName::ReceiptFieldConsistency, NOT_KNOWN);
        }
    }
}

#[test]
fn legacy_v4_v2_with_an_unexpected_tag_fails_closed() {
    let forecast = crate::protocol::receipts::ENTROPY_COMPOSITION;
    let entries = crate::_test_support::v6_entries();
    for weather in [Some("1013"), None] {
        let json = crate::_test_support::build_valid_bundle(&entries, weather, 2);
        let verify = |j: &str| verify_bundle(&ProofBundle::from_json(j).unwrap());
        assert!(verify(&json).passed());
        assert!(verify(&retag(&json, forecast, forecast)).passed());
        for (lock_tag, exec_tag) in [
            (UNKNOWN_TAG, UNKNOWN_TAG),
            (landobs_v1::ENTROPY_COMPOSITION, forecast),
            (forecast, UNKNOWN_TAG),
        ] {
            let report = verify(&retag(&json, lock_tag, exec_tag));
            let case = format!("{weather:?}: lock 4 {lock_tag:?} / exec 2 {exec_tag:?}");
            assert_fails_closed(&report, &case);
            assert_step_fails(&report, StepName::WeatherObservationWindow, NOT_KNOWN);
            assert_step_fails(&report, StepName::ReceiptFieldConsistency, NOT_KNOWN);
        }
    }
}

#[test]
fn weather_rules_dispatch_on_the_schema_and_tag_pair() {
    let forecast = crate::protocol::receipts::ENTROPY_COMPOSITION;
    let landobs = landobs_v1::ENTROPY_COMPOSITION;
    let r = |schema: &str, tag: Option<&str>| {
        let mut v = serde_json::json!({ "schema_version": schema });
        if let Some(tag) = tag {
            v["entropy_composition"] = serde_json::json!(tag);
        }
        v
    };
    let unrecognised = |w: WeatherRules| matches!(w, WeatherRules::Unrecognised(_));
    for (lock, exec) in [("4", "2"), ("4", "3"), ("5", "3"), ("5", "4")] {
        assert_eq!(
            weather_rules(&r(lock, Some(forecast)), &r(exec, Some(forecast))),
            WeatherRules::Legacy,
            "{lock}/{exec}"
        );
    }
    assert_eq!(
        weather_rules(&r("6", Some(landobs)), &r("5", Some(landobs))),
        WeatherRules::LandObs
    );
    assert_eq!(
        weather_rules(&r("6", Some(landobs)), &r("4", Some(forecast))),
        WeatherRules::Mismatched
    );
    assert_eq!(
        weather_rules(&r("5", Some(forecast)), &r("5", Some(landobs))),
        WeatherRules::Mismatched
    );
    for (lock, exec) in [
        (r("6", Some(UNKNOWN_TAG)), r("5", Some(landobs))),
        (r("6", Some(landobs)), r("5", Some(UNKNOWN_TAG))),
        (r("6", None), r("5", Some(landobs))),
        (r("6", Some(landobs)), r("5", None)),
        (r("6", Some(forecast)), r("5", Some(landobs))),
        (r("5", Some(landobs)), r("4", Some(forecast))),
        (r("4", Some(UNKNOWN_TAG)), r("2", Some(forecast))),
        (r("4", Some(forecast)), r("2", Some(landobs))),
        (r("7", Some(landobs)), r("5", Some(landobs))),
        (r("6", Some(landobs)), r("6", Some(landobs))),
        (serde_json::json!({}), r("5", Some(landobs))),
    ] {
        assert!(
            unrecognised(weather_rules(&lock, &exec)),
            "{lock} / {exec} was not refused"
        );
    }
}

#[test]
fn entropy_composition_is_cross_checked_under_both_rule_sets() {
    assert!(CROSS_CHECKED_FIELDS.contains(&"entropy_composition"));
    assert!(CROSS_CHECKED_FIELDS_LANDOBS.contains(&"entropy_composition"));
    assert!(CROSS_CHECKED_FIELDS_FREQ.contains(&"entropy_composition"));
}

/// Today a lock/exec tag difference always leaves one receipt with an
/// unknown (schema, tag) pair, so field consistency fails on that, before
/// the `entropy_composition` cross-check is reached. This proves the
/// difference fails; it does not exercise the cross-check itself (see
/// `each_schema_tag_pair_is_listed_once`).
#[test]
fn lock_and_exec_tags_that_differ_fail_field_consistency_as_an_unknown_pair() {
    let report = run(&V6Params {
        exec_entropy_composition: crate::protocol::receipts::ENTROPY_COMPOSITION.into(),
        ..V6Params::weather()
    });
    assert_eq!(
        status(&report, StepName::ReceiptFieldConsistency),
        &StepStatus::Fail(format!(
            "execution receipt schema_version \"5\" with entropy_composition \"{}\" {NOT_KNOWN}",
            crate::protocol::receipts::ENTROPY_COMPOSITION
        ))
    );
    assert!(!report.passed());
}

/// Each (schema, tag) pair is listed once, and two known but different tags
/// on lock and exec fail closed (they are a mismatched pair, so the
/// `entropy_composition` cross-check is never the only guard): see
/// `freq_tests::known_but_different_tags_on_lock_and_exec_fail_on_the_pairing`.
#[test]
fn each_schema_tag_pair_is_listed_once() {
    for (table, rows) in [
        ("LOCK_RULE_SETS", LOCK_RULE_SETS),
        ("EXEC_RULE_SETS", EXEC_RULE_SETS),
    ] {
        for (schema, tag, _) in rows {
            let n = rows
                .iter()
                .filter(|(s, t, _)| s == schema && t == tag)
                .count();
            assert_eq!(n, 1, "{table}: ({schema:?}, {tag:?}) is listed {n} times");
        }
    }
}

// ---- fair_pick_version, operator_slug and commitment_hash (v6 / v5 only) ----

const FIELD_MISMATCH: &str = "differs between lock";

/// The v6 bundle for `p` with both receipts edited and re-signed.
fn v6_edited(
    p: &V6Params,
    lock_edit: impl FnOnce(&mut serde_json::Value),
    exec_edit: impl FnOnce(&mut serde_json::Value),
) -> VerificationReport {
    let (json, pk_hex, kid) = build_v6_bundle(p);
    run_json(&resign_both(&json, lock_edit, exec_edit), &pk_hex, &kid)
}

/// Exactly `only` fails; every other step passes.
fn assert_only_fails(report: &VerificationReport, only: StepName, needle: &str, case: &str) {
    assert_eq!(failing(report), [only], "{case}: {:?}", report.steps);
    for step in &report.steps {
        if step.name != only {
            assert_eq!(step.status, StepStatus::Pass, "{case}: {}", step.name);
        }
    }
    assert_step_fails(report, only, needle);
}

fn set(field: &'static str, value: serde_json::Value) -> impl FnOnce(&mut serde_json::Value) {
    move |r| r[field] = value
}

fn keep(_: &mut serde_json::Value) {}

#[test]
fn v6_fair_pick_versions_this_verifier_implements_pass() {
    for v in FAIR_PICK_VERSIONS {
        for p in [V6Params::weather(), V6Params::fallback()] {
            let report = v6_edited(
                &p,
                set("fair_pick_version", serde_json::json!(v)),
                set("fair_pick_version", serde_json::json!(v)),
            );
            assert!(report.passed(), "{v}: {:?}", report.steps);
            for step in &report.steps {
                assert_eq!(step.status, StepStatus::Pass, "{v}: {}", step.name);
            }
        }
    }
}

#[test]
fn v6_fair_pick_version_differing_between_receipts_fails_field_consistency() {
    for (lock_v, exec_v) in [("0.2.0", "0.1.0"), ("0.1.0", "0.2.0"), ("0.2.0", "0.2.1")] {
        let case = format!("lock {lock_v} / exec {exec_v}");
        for p in [V6Params::weather(), V6Params::fallback()] {
            let report = v6_edited(
                &p,
                set("fair_pick_version", serde_json::json!(lock_v)),
                set("fair_pick_version", serde_json::json!(exec_v)),
            );
            assert_only_fails(
                &report,
                StepName::ReceiptFieldConsistency,
                FIELD_MISMATCH,
                &case,
            );
            assert_step_fails(
                &report,
                StepName::ReceiptFieldConsistency,
                "fair_pick_version",
            );
        }
    }
}

#[test]
fn v6_unknown_fair_pick_version_fails_field_consistency() {
    for v in ["0.2.1", "0.3.0", "1.0.0", "0.2", "v0.2.0", ""] {
        for p in [V6Params::weather(), V6Params::fallback()] {
            let report = v6_edited(
                &p,
                set("fair_pick_version", serde_json::json!(v)),
                set("fair_pick_version", serde_json::json!(v)),
            );
            assert_only_fails(
                &report,
                StepName::ReceiptFieldConsistency,
                "is not one this verifier implements",
                v,
            );
        }
    }
    let report = v6_edited(
        &V6Params::weather(),
        set("fair_pick_version", serde_json::json!("0.2.1")),
        set("fair_pick_version", serde_json::json!("0.2.1")),
    );
    assert_eq!(
        status(&report, StepName::ReceiptFieldConsistency),
        &StepStatus::Fail(
            "fair_pick_version \"0.2.1\" is not one this verifier implements (\"0.1.0\", \"0.2.0\")"
                .into()
        )
    );
}

#[test]
fn v6_operator_slug_differing_between_receipts_fails_field_consistency() {
    for p in [V6Params::weather(), V6Params::fallback()] {
        let report = v6_edited(
            &p,
            keep,
            set("operator_slug", serde_json::json!("other-prizes")),
        );
        assert_only_fails(
            &report,
            StepName::ReceiptFieldConsistency,
            "operator_slug",
            "exec",
        );
        let report = v6_edited(
            &p,
            set("operator_slug", serde_json::json!("other-prizes")),
            keep,
        );
        assert_only_fails(
            &report,
            StepName::ReceiptFieldConsistency,
            "operator_slug",
            "lock",
        );
        // The same new slug on both receipts is consistent.
        let report = v6_edited(
            &p,
            set("operator_slug", serde_json::json!("other-prizes")),
            set("operator_slug", serde_json::json!("other-prizes")),
        );
        assert!(report.passed(), "{:?}", report.steps);
    }
}

#[test]
fn v6_lock_commitment_hash_equal_to_entry_hash_passes() {
    for p in [V6Params::weather(), V6Params::fallback()] {
        let (json, _, _) = build_v6_bundle(&p);
        let bundle: serde_json::Value = serde_json::from_str(&json).unwrap();
        let lock: serde_json::Value =
            serde_json::from_str(bundle["lock_receipt"]["payload_jcs"].as_str().unwrap()).unwrap();
        assert_eq!(lock["commitment_hash"], lock["entry_hash"]);
        assert_eq!(
            status(&run(&p), StepName::LockReceiptEntryHash),
            &StepStatus::Pass
        );
    }
}

#[test]
fn v6_lock_commitment_hash_other_than_entry_hash_fails_lock_entry_hash() {
    let zeros = "00".repeat(32);
    let other = "ab".repeat(32);
    for (label, value) in [
        ("zeros", serde_json::json!(zeros)),
        ("other", serde_json::json!(other)),
        ("upper", serde_json::Value::Null),
    ] {
        for p in [V6Params::weather(), V6Params::fallback()] {
            let (json, pk_hex, kid) = build_v6_bundle(&p);
            let value = value.clone();
            let tampered = resign_both(
                &json,
                |lock| {
                    lock["commitment_hash"] = if value.is_null() {
                        // Same bytes as entry_hash, but upper-case.
                        serde_json::json!(lock["entry_hash"].as_str().unwrap().to_uppercase())
                    } else {
                        value
                    }
                },
                keep,
            );
            let report = run_json(&tampered, &pk_hex, &kid);
            assert_only_fails(
                &report,
                StepName::LockReceiptEntryHash,
                "commitment_hash",
                label,
            );
            assert_step_fails(
                &report,
                StepName::LockReceiptEntryHash,
                "is not its entry_hash",
            );
        }
    }
}

/// Lock v5 / exec v4 and lock v4 / exec v2: a differing `fair_pick_version`,
/// a differing or unknown `operator_slug`, an unknown `fair_pick_version` and
/// a zero `commitment_hash` verify exactly as before (the fixtures already
/// sign a zero `commitment_hash`).
#[test]
fn v6_only_rules_leave_older_schemas_unchanged() {
    let entries = crate::_test_support::v6_entries();
    let edits: [(&str, &str, &str, &str, &str); 3] = [
        // (case, lock fair_pick, exec fair_pick, lock slug, exec slug)
        (
            "fair_pick differs",
            "0.1.0",
            "9.9.9",
            "acme-prizes",
            "acme-prizes",
        ),
        (
            "fair_pick unknown",
            "9.9.9",
            "9.9.9",
            "acme-prizes",
            "acme-prizes",
        ),
        (
            "slug differs",
            "0.1.0",
            "0.1.0",
            "acme-prizes",
            "other-prizes",
        ),
    ];
    for weather in [Some("1013"), None] {
        let (v5, pk_hex, kid) = crate::_test_support::build_valid_v5_bundle(&entries, weather, 2);
        let v4 = crate::_test_support::build_valid_bundle(&entries, weather, 2);
        for json in [&v5, &v4] {
            let lock: serde_json::Value = serde_json::from_str(
                serde_json::from_str::<serde_json::Value>(json).unwrap()["lock_receipt"]
                    ["payload_jcs"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(lock["commitment_hash"], "00".repeat(32));
            assert_ne!(lock["commitment_hash"], lock["entry_hash"]);
        }
        for (case, lock_fp, exec_fp, lock_slug, exec_slug) in edits {
            let edited = |json: &str| {
                resign_both(
                    json,
                    |l| {
                        l["fair_pick_version"] = serde_json::json!(lock_fp);
                        l["operator_slug"] = serde_json::json!(lock_slug);
                    },
                    |e| {
                        e["fair_pick_version"] = serde_json::json!(exec_fp);
                        e["operator_slug"] = serde_json::json!(exec_slug);
                    },
                )
            };
            let report = run_json(&edited(&v5), &pk_hex, &kid);
            assert!(
                report.passed(),
                "v5/v4 {weather:?} {case}: {:?}",
                report.steps
            );
            let report = verify_bundle(&ProofBundle::from_json(&edited(&v4)).unwrap());
            assert!(
                report.passed(),
                "v4/v2 {weather:?} {case}: {:?}",
                report.steps
            );
        }
        // Untouched (zero commitment_hash) still passes.
        assert!(run_json(&v5, &pk_hex, &kid).passed());
        assert!(verify_bundle(&ProofBundle::from_json(&v4).unwrap()).passed());
    }
}

/// The commitment rule follows the lock's rule set, not the pair: a lock 6
/// paired with exec 4 already fails as a mismatched pair, and a lock 5 paired
/// with exec 5 is not checked for its commitment.
#[test]
fn commitment_hash_rule_follows_the_lock_rule_set() {
    let zero = |p: V6Params| {
        v6_edited(
            &p,
            set("commitment_hash", serde_json::json!("00".repeat(32))),
            keep,
        )
    };
    let forecast = crate::protocol::receipts::ENTROPY_COMPOSITION.to_string();
    let lock5 = zero(V6Params {
        lock_schema: "5".into(),
        lock_entropy_composition: forecast.clone(),
        ..V6Params::weather()
    });
    assert_eq!(
        status(&lock5, StepName::LockReceiptEntryHash),
        &StepStatus::Pass
    );
    let lock6 = zero(V6Params {
        exec_schema: "4".into(),
        exec_entropy_composition: forecast,
        ..V6Params::weather()
    });
    assert_step_fails(&lock6, StepName::LockReceiptEntryHash, "commitment_hash");
}
