//! Lock v6 / execution v5 under the grid-frequency tag, through the full pipeline.

use super::*;
use crate::_test_support::{
    FreqParams, MockResolver, V6Params, build_freq_bundle, build_v6_bundle,
};

fn run_json(json: &str, pk_hex: &str, kid: &str) -> VerificationReport {
    let pk: [u8; 32] = hex::decode(pk_hex).unwrap().try_into().unwrap();
    verify_bundle_with(
        &ProofBundle::from_json(json).unwrap(),
        &MockResolver::new(kid, pk),
        VerifierMode::Attestable,
    )
}

fn run(p: &FreqParams) -> VerificationReport {
    let (json, pk, kid) = build_freq_bundle(p);
    run_json(&json, &pk, &kid)
}

fn status(report: &VerificationReport, name: StepName) -> &StepStatus {
    &report.steps.iter().find(|s| s.name == name).unwrap().status
}

fn failing(report: &VerificationReport) -> Vec<StepName> {
    let mut out: Vec<StepName> = report
        .steps
        .iter()
        .filter(|s| matches!(s.status, StepStatus::Fail(_)))
        .map(|s| s.name)
        .collect();
    out.sort_by_key(|n| *n as u8);
    out
}

fn assert_only(report: &VerificationReport, expected: &[StepName]) {
    let mut expected = expected.to_vec();
    expected.sort_by_key(|n| *n as u8);
    assert_eq!(failing(report), expected, "steps: {:?}", report.steps);
    assert!(!report.passed());
}

fn fail_reason(report: &VerificationReport, name: StepName) -> String {
    match status(report, name) {
        StepStatus::Fail(r) => r.clone(),
        other => panic!("{name}: expected a failure, got {other:?}"),
    }
}

/// The frequency bundle for `p`, with the execution receipt edited and
/// re-signed after it was built.
fn resigned_exec(p: &FreqParams, edit: impl FnOnce(&mut serde_json::Value)) -> VerificationReport {
    let (json, pk, kid) = build_freq_bundle(p);
    let val = crate::_test_support::resign_exec(&json, edit);
    run_json(&val.to_string(), &pk, &kid)
}

#[test]
fn freq_value_and_fallback_bundles_pass_every_step() {
    for p in [FreqParams::value(), FreqParams::fallback()] {
        let report = run(&p);
        assert!(report.passed(), "{p:?}: {:?}", report.steps);
        assert_eq!(
            status(&report, StepName::WeatherObservationWindow),
            &StepStatus::Pass
        );
        // Every step ran and passed: no step was waived or skipped.
        assert!(
            report.steps.iter().all(|s| s.status == StepStatus::Pass),
            "{:?}",
            report.steps
        );
    }
}

#[test]
fn freq_start_not_derived_from_the_round_fails_the_window() {
    for start in ["2026-10-14T19:53:45.000000Z", "2026-10-14T19:54:15.000000Z"] {
        let p = FreqParams {
            freq_start: start.into(),
            ..FreqParams::value()
        };
        let report = run(&p);
        assert_only(&report, &[StepName::WeatherObservationWindow]);
        assert!(
            fail_reason(&report, StepName::WeatherObservationWindow)
                .contains("not the window start for drand round 33068212"),
            "{start}"
        );
    }
}

#[test]
fn freq_start_off_the_15_second_grid_fails_shape_and_window() {
    for start in [
        "2026-10-14T19:54:01.000000Z",
        "2026-10-14T19:54:00.000001Z",
        "2026-10-14T19:53:60.000000Z",
    ] {
        let p = FreqParams {
            freq_start: start.into(),
            ..FreqParams::value()
        };
        assert_only(
            &run(&p),
            &[StepName::BundleShape, StepName::WeatherObservationWindow],
        );
    }
}

#[test]
fn freq_lock_exactly_at_the_gap_passes_and_any_later_fails() {
    let at = FreqParams {
        locked_at: "2026-10-14T19:53:00.000000Z".into(),
        ..FreqParams::value()
    };
    assert!(run(&at).passed());
    // To the microsecond: half a second late (T - 59.5 s) and one
    // microsecond late both fail, so seconds are never truncated.
    for late in ["2026-10-14T19:53:00.000001Z", "2026-10-14T19:53:00.500000Z"] {
        let p = FreqParams {
            locked_at: late.into(),
            ..FreqParams::value()
        };
        let report = run(&p);
        assert_only(&report, &[StepName::WeatherObservationWindow]);
        assert!(
            fail_reason(&report, StepName::WeatherObservationWindow)
                .contains("later than freq_start minus 60 seconds"),
            "{late}"
        );
    }
}

#[test]
fn value_with_a_reason_or_neither_fails_the_window() {
    let both = FreqParams {
        freq_fallback_reason: Some("no_frequency_by_deadline".into()),
        ..FreqParams::value()
    };
    let report = run(&both);
    assert!(!report.passed());
    assert_only(&report, &[StepName::WeatherObservationWindow]);
    assert!(
        fail_reason(&report, StepName::WeatherObservationWindow)
            .contains("freq_value set, freq_fallback_reason set")
    );
    let neither = FreqParams {
        freq_fallback_reason: None,
        ..FreqParams::fallback()
    };
    let report = run(&neither);
    assert!(!report.passed());
    assert_only(&report, &[StepName::WeatherObservationWindow]);
    assert!(
        fail_reason(&report, StepName::WeatherObservationWindow)
            .contains("freq_value null, freq_fallback_reason null")
    );
}

#[test]
fn the_weather_reason_or_a_weather_field_under_the_frequency_tag_fails_shape() {
    let reason = FreqParams {
        freq_fallback_reason: Some("no_observation_by_deadline".into()),
        ..FreqParams::fallback()
    };
    assert_only(
        &run(&reason),
        &[StepName::BundleShape, StepName::WeatherObservationWindow],
    );
    let station = FreqParams {
        lock_weather_station: Some("wmo-03749".into()),
        ..FreqParams::value()
    };
    assert!(failing(&run(&station)).contains(&StepName::BundleShape));
    let weather = FreqParams {
        exec_weather_value: Some("141;1025;85;2432".into()),
        ..FreqParams::value()
    };
    assert!(failing(&run(&weather)).contains(&StepName::BundleShape));
}

#[test]
fn a_bad_freq_value_fails_shape() {
    for v in [
        "50000;50000;50000;50000;50000;50000;50012;50013",
        "53000;50012;49983;49980;49953;49912;49883;49887",
        "00000;50012;49983;49980;49953;49912;49883;49887",
        "4998;50012;49983;49980;49953;49912;49883;49887",
    ] {
        let p = FreqParams {
            freq_value: Some(v.into()),
            ..FreqParams::value()
        };
        assert_only(&run(&p), &[StepName::BundleShape]);
    }
}

#[test]
fn the_seed_is_derived_from_freq_value_under_this_tag() {
    // Seed computed from the weather-style JCS key instead: the seed step fails.
    let (json, pk, kid) = build_freq_bundle(&FreqParams::value());
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let exec: serde_json::Value =
        serde_json::from_str(v["execution_receipt"]["payload_jcs"].as_str().unwrap()).unwrap();
    let (eh, r, fv) = (
        exec["entry_hash"].as_str().unwrap(),
        exec["drand_randomness"].as_str().unwrap(),
        exec["freq_value"].as_str().unwrap(),
    );
    assert_ne!(
        hex::encode(crate::protocol::compute_seed(eh, r, fv).0),
        exec["seed"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(crate::protocol::compute_seed_freq(eh, r, fv).0),
        exec["seed"].as_str().unwrap()
    );

    let drand_seed = FreqParams {
        seed_from: Some(None),
        ..FreqParams::value()
    };
    let report = run(&drand_seed);
    assert!(failing(&report).contains(&StepName::SeedRecomputation));
    assert!(fail_reason(&report, StepName::SeedRecomputation).contains("(drand + grid frequency)"));

    let other_value = FreqParams {
        seed_from: Some(Some(
            "50012;50018;50012;49983;49980;49953;49912;49884".into(),
        )),
        ..FreqParams::value()
    };
    assert!(failing(&run(&other_value)).contains(&StepName::SeedRecomputation));

    v["entropy"]["freq_value"] =
        serde_json::json!("50012;50018;50012;49983;49980;49953;49912;49884");
    assert_only(
        &run_json(&v.to_string(), &pk, &kid),
        &[StepName::DrandBlsSignature],
    );
    v["entropy"].as_object_mut().unwrap().remove("freq_value");
    assert_only(
        &run_json(&v.to_string(), &pk, &kid),
        &[StepName::DrandBlsSignature],
    );
}

#[test]
fn a_fallback_seed_is_drand_only() {
    // The fallback bundle's seed is the drand-only one; a frequency seed of
    // some value would not match.
    let wrong = FreqParams {
        seed_from: Some(Some(
            "50012;50018;50012;49983;49980;49953;49912;49883".into(),
        )),
        ..FreqParams::fallback()
    };
    let report = run(&wrong);
    assert!(failing(&report).contains(&StepName::SeedRecomputation));
    assert!(fail_reason(&report, StepName::SeedRecomputation).contains("(drand only)"));
}

#[test]
fn the_seed_input_is_chosen_by_the_pair_from_the_signed_receipt() {
    use crate::protocol::{freq_v1, landobs_v1};
    let lock = |tag: &str| serde_json::json!({"schema_version": "6", "entropy_composition": tag});
    let exec = |tag: &str, extra: serde_json::Value| {
        let mut e = serde_json::json!({"schema_version": "5", "entropy_composition": tag});
        for (k, v) in extra.as_object().unwrap() {
            e[k] = v.clone();
        }
        e
    };
    let freq = freq_v1::ENTROPY_COMPOSITION;
    let landobs = landobs_v1::ENTROPY_COMPOSITION;
    let v = "50012;50018;50012;49983;49980;49953;49912;49883";

    let e = exec(freq, serde_json::json!({"freq_value": v}));
    assert_eq!(
        SeedInput::from_receipts(&lock(freq), &e),
        Ok(SeedInput::Freq(v))
    );
    let e = exec(freq, serde_json::json!({"freq_value": null}));
    assert_eq!(
        SeedInput::from_receipts(&lock(freq), &e),
        Ok(SeedInput::DrandOnly)
    );
    let e = exec(freq, serde_json::json!({}));
    assert_eq!(
        SeedInput::from_receipts(&lock(freq), &e),
        Ok(SeedInput::DrandOnly)
    );
    // A non-string value is malformed, never "no frequency".
    let e = exec(freq, serde_json::json!({"freq_value": 50012}));
    assert!(matches!(
        SeedInput::from_receipts(&lock(freq), &e),
        Err(SeedError::Invalid(r)) if r.contains("freq_value is neither a string nor null")
    ));
    // A weather value under the frequency pair is refused, never used.
    let e = exec(
        freq,
        serde_json::json!({"weather_value": "141;1025;85;2432"}),
    );
    assert!(matches!(
        SeedInput::from_receipts(&lock(freq), &e),
        Err(SeedError::Invalid(_))
    ));
    let e = exec(
        freq,
        serde_json::json!({"weather_value": null, "freq_value": v}),
    );
    assert_eq!(
        SeedInput::from_receipts(&lock(freq), &e),
        Ok(SeedInput::Freq(v))
    );
    // Under the Land Observations pair, the three-state table decides,
    // and a receipt in none of the states is refused, never seeded.
    let state = |w: serde_json::Value,
                 r: serde_json::Value,
                 f: serde_json::Value,
                 fr: serde_json::Value| {
        let o = if w.is_null() {
            serde_json::Value::Null
        } else {
            serde_json::json!("2026-10-01T19:00:00.000000Z")
        };
        exec(
            landobs,
            serde_json::json!({
                "weather_value": w, "weather_observation_time": o,
                "weather_fallback_reason": r, "freq_value": f, "freq_fallback_reason": fr
            }),
        )
    };
    let null = serde_json::Value::Null;
    let no_obs = serde_json::json!(landobs_v1::FALLBACK_NO_OBSERVATION);
    let no_freq = serde_json::json!(freq_v1::FALLBACK_NO_FREQUENCY);
    let w = serde_json::json!("141;1025;85;2432");
    let e = state(w.clone(), null.clone(), null.clone(), null.clone());
    assert_eq!(
        SeedInput::from_receipts(&lock(landobs), &e),
        Ok(SeedInput::Weather("141;1025;85;2432"))
    );
    let e = state(
        null.clone(),
        no_obs.clone(),
        serde_json::json!(v),
        null.clone(),
    );
    assert_eq!(
        SeedInput::from_receipts(&lock(landobs), &e),
        Ok(SeedInput::Freq(v))
    );
    let e = state(null.clone(), no_obs.clone(), null.clone(), no_freq.clone());
    assert_eq!(
        SeedInput::from_receipts(&lock(landobs), &e),
        Ok(SeedInput::DrandOnly)
    );
    for e in [
        state(w.clone(), null.clone(), serde_json::json!(v), null.clone()),
        state(w, null.clone(), null.clone(), no_freq),
        state(null.clone(), no_obs, null.clone(), null.clone()),
        exec(landobs, serde_json::json!({"freq_value": v})),
    ] {
        assert!(
            matches!(
                SeedInput::from_receipts(&lock(landobs), &e),
                Err(SeedError::Invalid(_))
            ),
            "{e}"
        );
    }
    // A mismatched or unknown pair has no seed rule at all.
    for (l, e) in [
        (
            lock(landobs),
            exec(freq, serde_json::json!({"freq_value": v})),
        ),
        (
            lock(freq),
            exec(
                landobs,
                serde_json::json!({"weather_value": "141;1025;85;2432"}),
            ),
        ),
        (
            lock("drand-quicknet+elexon-freq-v2"),
            exec(freq, serde_json::json!({"freq_value": v})),
        ),
        (lock(freq), exec("", serde_json::json!({"freq_value": v}))),
    ] {
        assert!(
            matches!(
                SeedInput::from_receipts(&l, &e),
                Err(SeedError::NoRule(r)) if r.starts_with("no seed rule for this tag pair")
            ),
            "{l} {e}"
        );
    }

    let (eh, r) = (
        "ab".repeat(32),
        crate::_test_support::BEACON_FREQ_RANDOMNESS,
    );
    assert_eq!(
        SeedInput::Freq(v).seed(&eh, r),
        crate::protocol::compute_seed_freq(&eh, r, v).0
    );
    assert_eq!(
        SeedInput::Weather(v).seed(&eh, r),
        compute_seed(&eh, r, v).0
    );
    assert_eq!(
        SeedInput::DrandOnly.seed(&eh, r),
        compute_seed_drand_only(&eh, r).0
    );
}

#[test]
fn a_weather_value_on_a_frequency_receipt_never_feeds_the_seed() {
    // The seed is chosen by the pair, never by which field is present: a
    // weather seed over a frequency receipt fails.
    let report = resigned_exec(&FreqParams::fallback(), |exec| {
        exec["weather_value"] = serde_json::json!("141;1025;85;2432");
        let (eh, r) = (
            exec["entry_hash"].as_str().unwrap().to_string(),
            exec["drand_randomness"].as_str().unwrap().to_string(),
        );
        exec["seed"] = serde_json::json!(hex::encode(
            crate::protocol::compute_seed(&eh, &r, "141;1025;85;2432").0
        ));
    });
    assert!(
        fail_reason(&report, StepName::SeedRecomputation)
            .contains("weather_value must be null under drand-quicknet+elexon-freq-v1"),
        "{:?}",
        report.steps
    );
}

#[test]
fn freq_execution_before_publication_fails_the_drand_step() {
    let p = FreqParams {
        executed_at: "2026-10-14T19:59:59.000000Z".into(),
        ..FreqParams::value()
    };
    assert_only(&run(&p), &[StepName::DrandBlsSignature]);
}

#[test]
fn a_frequency_lock_with_a_landobs_exec_fails_closed() {
    let p = FreqParams {
        exec_entropy_composition: crate::protocol::landobs_v1::ENTROPY_COMPOSITION.into(),
        ..FreqParams::value()
    };
    let report = run(&p);
    for step in [
        StepName::BundleShape,
        StepName::WeatherObservationWindow,
        StepName::ReceiptFieldConsistency,
    ] {
        assert!(
            failing(&report).contains(&step),
            "{step}: {:?}",
            report.steps
        );
    }
    assert!(!report.passed());
}

/// Two known v6/v5 tags that differ: each receipt is valid on its own, so
/// only the pairing rules refuse them.
#[test]
fn known_but_different_tags_on_lock_and_exec_fail_on_the_pairing() {
    use crate::protocol::receipts::{parse_execution_receipt, parse_lock_receipt};
    let (freq_json, _, _) = build_freq_bundle(&FreqParams::value());
    let (landobs_json, pk, kid) = build_v6_bundle(&V6Params::weather());
    let freq: serde_json::Value = serde_json::from_str(&freq_json).unwrap();
    for (lock_from, exec_from) in [(&freq, false), (&freq, true)] {
        let mut b: serde_json::Value = serde_json::from_str(&landobs_json).unwrap();
        if exec_from {
            b["execution_receipt"] = lock_from["execution_receipt"].clone();
        } else {
            b["lock_receipt"] = lock_from["lock_receipt"].clone();
        }
        let bundle = ProofBundle::from_json(&b.to_string()).unwrap();
        // Both receipts parse and validate as their own tag.
        assert!(parse_lock_receipt(&bundle.lock_receipt.payload_jcs).is_ok());
        assert!(parse_execution_receipt(&bundle.execution_receipt.payload_jcs).is_ok());
        assert_eq!(
            check_bundle_shape(&bundle).status,
            StepStatus::Fail(TAG_PAIRING_ERROR.into())
        );
        let report = run_json(&b.to_string(), &pk, &kid);
        for step in [
            StepName::WeatherObservationWindow,
            StepName::ReceiptFieldConsistency,
        ] {
            assert_eq!(
                status(&report, step),
                &StepStatus::Fail(TAG_PAIRING_ERROR.into()),
                "{step}"
            );
        }
        assert!(!report.passed());
    }
}

#[test]
fn freq_bundles_get_the_v6_hardening() {
    // fair_pick_version: lock and exec agree, and name a release this verifier implements.
    let p = FreqParams {
        exec_fair_pick_version: "0.2.0".into(),
        ..FreqParams::value()
    };
    assert_only(&run(&p), &[StepName::ReceiptFieldConsistency]);
    let p = FreqParams {
        lock_fair_pick_version: "9.9.9".into(),
        exec_fair_pick_version: "9.9.9".into(),
        ..FreqParams::value()
    };
    let report = run(&p);
    assert_only(&report, &[StepName::ReceiptFieldConsistency]);
    assert!(
        fail_reason(&report, StepName::ReceiptFieldConsistency)
            .contains("not one this verifier implements")
    );
    let p = FreqParams {
        lock_fair_pick_version: "0.2.0".into(),
        exec_fair_pick_version: "0.2.0".into(),
        ..FreqParams::value()
    };
    assert!(run(&p).passed());
    // operator_slug: lock and exec agree.
    let p = FreqParams {
        exec_operator_slug: "someone-else".into(),
        ..FreqParams::value()
    };
    let report = run(&p);
    assert_only(&report, &[StepName::ReceiptFieldConsistency]);
    assert!(fail_reason(&report, StepName::ReceiptFieldConsistency).contains("operator_slug"));
    // commitment_hash is the entry hash.
    let p = FreqParams {
        commitment_hash: Some("00".repeat(32)),
        ..FreqParams::value()
    };
    assert_only(&run(&p), &[StepName::LockReceiptEntryHash]);
}

#[test]
fn a_freq_receipt_carrying_a_weather_station_on_exec_fails() {
    // Cross-checked as null on both; the exec validator refuses it first.
    let report = resigned_exec(&FreqParams::value(), |exec| {
        exec["weather_station"] = serde_json::json!("wmo-03749");
    });
    assert!(failing(&report).contains(&StepName::BundleShape));
    assert!(failing(&report).contains(&StepName::ReceiptFieldConsistency));
}

#[test]
fn a_landobs_bundle_is_unchanged_by_the_new_tag() {
    for p in [V6Params::weather(), V6Params::fallback()] {
        let (json, pk, kid) = build_v6_bundle(&p);
        assert!(run_json(&json, &pk, &kid).passed());
    }
}

#[test]
fn weather_rules_dispatch_on_the_pair_for_the_frequency_tag() {
    let lock = |tag: &str| serde_json::json!({"schema_version": "6", "entropy_composition": tag});
    let exec = |tag: &str| serde_json::json!({"schema_version": "5", "entropy_composition": tag});
    let freq = crate::protocol::freq_v1::ENTROPY_COMPOSITION;
    let landobs = crate::protocol::landobs_v1::ENTROPY_COMPOSITION;
    assert_eq!(weather_rules(&lock(freq), &exec(freq)), WeatherRules::Freq);
    assert_eq!(
        weather_rules(&lock(freq), &exec(landobs)),
        WeatherRules::Mismatched
    );
    assert_eq!(
        weather_rules(&lock(landobs), &exec(freq)),
        WeatherRules::Mismatched
    );
    assert!(matches!(
        weather_rules(&lock("drand-quicknet+elexon-freq-v2"), &exec(freq)),
        WeatherRules::Unrecognised(_)
    ));
    let legacy = |schema: &str| serde_json::json!({"schema_version": schema, "entropy_composition": crate::protocol::receipts::ENTROPY_COMPOSITION});
    assert_eq!(
        weather_rules(&lock(freq), &legacy("4")),
        WeatherRules::Mismatched
    );
    assert_eq!(
        weather_rules(&legacy("5"), &exec(freq)),
        WeatherRules::Mismatched
    );
    assert_eq!(
        mismatch_reason(&lock(freq), &exec(landobs)),
        TAG_PAIRING_ERROR
    );
    assert_eq!(
        mismatch_reason(&lock(freq), &legacy("4")),
        SCHEMA_PAIRING_ERROR
    );
}

#[test]
fn a_freq_timestamp_that_only_normalises_fails_shape() {
    for (field, value) in [
        ("locked_at", "2026-10-14T19:49:60.000000Z"),
        ("executed_at", "2026-10-14T20:00:60.000000Z"),
    ] {
        let mut p = FreqParams::value();
        match field {
            "locked_at" => p.locked_at = value.into(),
            _ => p.executed_at = value.into(),
        }
        let report = run(&p);
        let reason = fail_reason(&report, StepName::BundleShape);
        assert!(reason.contains(field), "{field}: {reason}");
    }
}

#[test]
fn an_inline_key_on_a_freq_receipt_wrapper_fails_shape() {
    for wrapper in ["lock_receipt", "execution_receipt"] {
        let (json, pk, kid) = build_freq_bundle(&FreqParams::value());
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v[wrapper]["public_key_hex"] = serde_json::json!(pk);
        let report = run_json(&v.to_string(), &pk, &kid);
        let reason = fail_reason(&report, StepName::BundleShape);
        assert!(reason.contains("downgrade-relabel"), "{wrapper}: {reason}");
        assert!(!report.passed());
    }
}

fn skipped(report: &VerificationReport, name: StepName) -> String {
    match status(report, name) {
        StepStatus::Skip(r) => r.clone(),
        other => panic!("{name}: expected a skip, got {other:?}"),
    }
}

/// A pair with no seed rule skips the seed and winner steps (never a
/// pass), while the pairing steps fail it, so the bundle fails.
#[test]
fn a_mismatched_pair_skips_the_seed_and_winner_steps_and_fails() {
    let p = FreqParams {
        exec_entropy_composition: crate::protocol::landobs_v1::ENTROPY_COMPOSITION.into(),
        ..FreqParams::value()
    };
    let (json, pk, kid) = build_freq_bundle(&p);
    // Re-sign the exec as a well-formed Land Observations v5 receipt, so
    // both receipts are valid known pairs that differ.
    let v = crate::_test_support::resign_exec(&json, |exec| {
        exec["freq_value"] = serde_json::Value::Null;
        exec["weather_station"] = serde_json::json!("wmo-03749");
        exec["weather_fallback_reason"] = serde_json::json!("no_observation_by_deadline");
    });
    let mut v = v;
    v["entropy"].as_object_mut().unwrap().remove("freq_value");
    let report = run_json(&v.to_string(), &pk, &kid);
    assert_eq!(status(&report, StepName::ExecSignature), &StepStatus::Pass);
    for step in [StepName::SeedRecomputation, StepName::WinnerSelection] {
        let reason = skipped(&report, step);
        assert!(
            reason.contains("no seed rule for this tag pair") && reason.contains(TAG_PAIRING_ERROR),
            "{step}: {reason}"
        );
    }
    assert_only(
        &report,
        &[
            StepName::BundleShape,
            StepName::WeatherObservationWindow,
            StepName::ReceiptFieldConsistency,
        ],
    );
}

#[test]
fn an_unknown_pair_skips_the_seed_and_winner_steps_and_fails() {
    // An unknown tag on schema 6 / 5 parses on the Land Observations shape,
    // so the signatures verify and only the pair is unknown.
    for tag in [
        "drand-quicknet+elexon-freq-v2",
        "drand-quicknet+metoffice-landobs-v2",
    ] {
        let p = V6Params {
            lock_entropy_composition: tag.into(),
            exec_entropy_composition: tag.into(),
            ..V6Params::weather()
        };
        let (json, pk, kid) = build_v6_bundle(&p);
        let report = run_json(&json, &pk, &kid);
        assert_eq!(status(&report, StepName::ExecSignature), &StepStatus::Pass);
        for step in [StepName::SeedRecomputation, StepName::WinnerSelection] {
            let reason = skipped(&report, step);
            assert!(
                reason.contains("no seed rule for this tag pair")
                    && reason.contains("not a combination this verifier knows"),
                "{tag} {step}: {reason}"
            );
        }
        assert!(failing(&report).contains(&StepName::BundleShape));
        assert!(failing(&report).contains(&StepName::ReceiptFieldConsistency));
        assert!(!report.passed());
    }
}
