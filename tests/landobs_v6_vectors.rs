//! wallop_core's frozen Land Observations vectors
//! (`drand-quicknet+metoffice-landobs-v1`): the schedule, the value grammar
//! and row rules, the lock 6 / execution 5 receipts in each of the three
//! execution states, the passing proof bundles, and the negative bundles
//! of both lock 6 tags. Read under the rules in `tests/common`.

mod common;

use std::collections::BTreeMap;

use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use wallop_verifier::_test_support::V6_NEGATIVE_CASES;
use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::protocol::receipts::{
    ParsedExecutionReceipt, ParsedLockReceipt, parse_execution_receipt, parse_lock_receipt,
    validate_execution_receipt_tags_v5, validate_lock_receipt_tags_v6,
};
use wallop_verifier::protocol::{freq_v1, landobs_v1};
use wallop_verifier::verify_steps::{
    StepStatus, VerificationReport, VerifierMode, verify_bundle_with,
};

fn vector(name: &str) -> serde_json::Value {
    common::core_vector(name, None)
}

/// A bundle given as a JSON object or as a JSON string.
fn bundle_json(bundle: &serde_json::Value) -> String {
    bundle
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| bundle.to_string())
}

fn verify(bundle: &serde_json::Value, keys: &serde_json::Value) -> VerificationReport {
    verify_bundle_with(
        &ProofBundle::from_json(&bundle_json(bundle)).unwrap(),
        &common::resolver(keys),
        VerifierMode::Attestable,
    )
}

fn sorted(steps: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut v: Vec<String> = steps.into_iter().collect();
    v.sort();
    v
}

fn step_names(list: &serde_json::Value) -> Vec<String> {
    sorted(
        list.as_array()
            .expect("expected_failing_steps is a list")
            .iter()
            .map(|s| s.as_str().unwrap().to_string()),
    )
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Weather,
    Freq,
    DrandOnly,
}

fn state_of(exec: &serde_json::Value) -> State {
    match landobs_v1::exec_state(exec).unwrap() {
        landobs_v1::ExecState::Weather(_) => State::Weather,
        landobs_v1::ExecState::Freq(_) => State::Freq,
        landobs_v1::ExecState::DrandOnly => State::DrandOnly,
    }
}

/// The description each state file must open with, so its name can't be
/// mistaken for a grid-frequency tag file.
fn state_prefix(state: State) -> String {
    let letter = match state {
        State::Weather => "a",
        State::Freq => "b",
        State::DrandOnly => "c",
    };
    format!("{}, state ({letter}):", landobs_v1::ENTROPY_COMPOSITION)
}

#[test]
fn schedule_vector_matches_the_constants_and_the_maths() {
    let v = vector("weather-schedule-landobs-v1.json");
    assert_eq!(v["entropy_composition"], landobs_v1::ENTROPY_COMPOSITION);
    assert_eq!(
        v["stations"],
        serde_json::json!([landobs_v1::PRIMARY_STATION])
    );
    assert_eq!(v["w_secs"], landobs_v1::W_SECS, "W differs");
    assert_eq!(v["publish_margin_secs"], landobs_v1::PUBLISH_MARGIN_SECS);
    assert_eq!(v["lock_offset_secs"], landobs_v1::LOCK_OFFSET_SECS);

    let cases = v["cases"].as_array().expect("cases is a list");
    // Every schedule time, freq_start included, is canonical RFC 3339 with
    // six fractional digits; freq_v1 exposes the crate's one public renderer.
    let at = freq_v1::format_freq_start;
    let mut at_bound = None;
    let mut rounds = Vec::new();
    for c in cases {
        let round = c["drand_round"].as_u64().unwrap();
        rounds.push(round);
        let published = wallop_verifier::drand::quicknet_round_time(round).unwrap();
        let wt = landobs_v1::weather_time_for_round(round).unwrap();
        assert_eq!(at(published), c["published_at"].as_str().unwrap(), "{c}");
        assert_eq!(at(wt), c["weather_time"].as_str().unwrap(), "{c}");
        assert_eq!(
            at(landobs_v1::latest_lock_at(wt).unwrap()),
            c["latest_lock_at"].as_str().unwrap(),
            "{c}"
        );
        assert_eq!(
            at(freq_v1::freq_start_for_round(round).unwrap()),
            c["freq_start"].as_str().unwrap(),
            "{c}"
        );
        if published == wt + landobs_v1::W_SECS + landobs_v1::PUBLISH_MARGIN_SECS {
            at_bound = Some((round, wt));
        }
    }
    // The round exactly at the bound and the round before it are both present.
    let (round, wt) = at_bound.expect("no case exactly at the bound");
    let before = cases
        .iter()
        .find(|c| c["drand_round"].as_u64() == Some(round - 1))
        .expect("no case for the round before the bound");
    assert_eq!(before["weather_time"].as_str().unwrap(), at(wt - 3600));
    // And at least one other round, away from the bound.
    assert!(
        rounds.iter().any(|r| *r != round && *r != round - 1),
        "no case other than the bound and the round before it: {rounds:?}"
    );
}

/// `weather-value-landobs-v1.json`, read typed: each `row` field stays its
/// JSON text. A `serde_json::Value` would read the numbers through a float,
/// and refuses the file outright (a field nobody reads holds `1e400`).
#[derive(serde::Deserialize)]
struct ValueVector {
    bounds: Bounds,
    valid: Vec<ValidCase>,
    invalid: Vec<InvalidCase>,
    from_row: Vec<FromRowCase>,
}

#[derive(serde::Deserialize)]
struct Bounds {
    t: [i64; 2],
    mslp: [i64; 2],
    rh: [i64; 2],
    vis: [i64; 2],
}

#[derive(serde::Deserialize)]
struct ValidCase {
    value: String,
    t: i64,
    mslp: i64,
    rh: i64,
    vis: i64,
}

#[derive(serde::Deserialize)]
struct InvalidCase {
    value: String,
    reason: String,
}

#[derive(serde::Deserialize)]
struct FromRowCase {
    row: BTreeMap<String, Box<RawValue>>,
    #[serde(default)]
    expected_value: Option<String>,
    #[serde(default)]
    expected_error: bool,
}

#[test]
fn value_vector_matches_the_bounds_grammar_and_row_rules() {
    let text = common::core_vector_text("weather-value-landobs-v1.json", None);
    let v: ValueVector = serde_json::from_str(&text).unwrap();
    use landobs_v1::{MSLP_MAX, MSLP_MIN, RH_MAX, RH_MIN, T_MAX, T_MIN, VIS_MAX, VIS_MIN};
    assert_eq!(v.bounds.t, [T_MIN, T_MAX]);
    assert_eq!(v.bounds.mslp, [MSLP_MIN, MSLP_MAX]);
    assert_eq!(v.bounds.rh, [RH_MIN, RH_MAX]);
    assert_eq!(v.bounds.vis, [VIS_MIN, VIS_MAX]);

    // The counts are pinned, so a dropped case fails rather than shrinking
    // the check.
    assert_eq!(
        (v.valid.len(), v.invalid.len(), v.from_row.len()),
        (7, 30, 55)
    );
    for c in &v.valid {
        let p = landobs_v1::parse_weather_value(&c.value)
            .unwrap_or_else(|e| panic!("{}: {e}", c.value));
        assert_eq!(
            (p.t, p.mslp, p.rh, p.vis),
            (c.t, c.mslp, c.rh, c.vis),
            "{}",
            c.value
        );
    }
    for c in &v.invalid {
        assert!(
            landobs_v1::parse_weather_value(&c.value).is_err(),
            "{:?} ({}) was accepted",
            c.value,
            c.reason
        );
    }
    for (i, c) in v.from_row.iter().enumerate() {
        let got = landobs_v1::row_to_value(|field| c.row.get(field).map(|r| r.get()));
        match (&c.expected_value, c.expected_error) {
            (Some(expected), false) => {
                assert_eq!(got.as_deref(), Ok(expected.as_str()), "from_row[{i}]")
            }
            (None, true) => assert!(got.is_err(), "from_row[{i}]: got {got:?}"),
            _ => panic!(
                "from_row[{i}] must carry exactly one of expected_value or expected_error: true"
            ),
        }
    }
}

#[test]
fn receipt_vectors_match_their_hashes_counts_schemas_and_states() {
    let receipts = [
        ("lock-receipt-v6.json", None),
        ("execution-receipt-v5.json", Some(State::Weather)),
        ("execution-receipt-freq-window-v5.json", Some(State::Freq)),
        ("execution-receipt-fallback-v5.json", Some(State::DrandOnly)),
    ];
    for (name, state) in receipts {
        let v = vector(name);
        let jcs = v["payload_jcs"].as_str().expect("payload_jcs");
        assert_eq!(
            hex::encode(Sha256::digest(jcs.as_bytes())),
            v["expected_payload_sha256"].as_str().unwrap(),
            "{name}"
        );
        let payload: serde_json::Value = serde_json::from_str(jcs).unwrap();
        assert_eq!(
            payload.as_object().unwrap().len() as u64,
            v["expected_field_count"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            payload["schema_version"], v["expected_schema_version"],
            "{name}"
        );
        assert_eq!(
            payload["entropy_composition"],
            landobs_v1::ENTROPY_COMPOSITION,
            "{name}"
        );
        assert_eq!(
            payload["weather_station"],
            landobs_v1::PRIMARY_STATION,
            "{name}"
        );
        match state {
            None => {
                assert_eq!(v["expected_field_count"], 20, "{name}");
                assert_eq!(
                    v["expected_field_count"],
                    landobs_v1::LOCK_KEYS.len() as u64
                );
                assert_eq!(v["expected_schema_version"], "6", "{name}");
                match parse_lock_receipt(jcs).unwrap() {
                    ParsedLockReceipt::V6(p) => {
                        assert_eq!(validate_lock_receipt_tags_v6(&p), Ok(()), "{name}")
                    }
                    other => panic!("{name} parsed as {other:?}"),
                }
            }
            Some(state) => {
                assert_eq!(v["expected_field_count"], 28, "{name}");
                assert_eq!(
                    v["expected_field_count"],
                    landobs_v1::EXEC_KEYS.len() as u64
                );
                assert_eq!(v["expected_schema_version"], "5", "{name}");
                match parse_execution_receipt(jcs).unwrap() {
                    ParsedExecutionReceipt::V5(p) => {
                        assert_eq!(validate_execution_receipt_tags_v5(&p), Ok(()), "{name}")
                    }
                    other => panic!("{name} parsed as {other:?}"),
                }
                assert_eq!(state_of(&payload), state, "{name}");
                let description = v["description"].as_str().unwrap();
                assert!(
                    description.starts_with(&state_prefix(state)),
                    "{name}: {description}"
                );
            }
        }
    }
}

#[test]
fn positive_bundle_vectors_pass_every_step_in_their_state() {
    let bundles = [
        ("proof-bundle-v6.json", State::Weather),
        ("proof-bundle-v6-freq-window.json", State::Freq),
        ("proof-bundle-v6-fallback.json", State::DrandOnly),
    ];
    for (name, state) in bundles {
        let v = vector(name);
        assert_eq!(v["expected_passed"], true, "{name}");
        let description = v["description"].as_str().unwrap();
        assert!(
            description.starts_with(&state_prefix(state)),
            "{name}: {description}"
        );
        let report = verify(&v["bundle"], &v["keys"]);
        assert!(report.passed(), "{name}: {:?}", report.steps);
        assert!(
            report.steps.iter().all(|s| s.status == StepStatus::Pass),
            "{name}: {:?}",
            report.steps
        );

        let b = ProofBundle::from_json(&bundle_json(&v["bundle"])).unwrap();
        let lock: serde_json::Value = serde_json::from_str(&b.lock_receipt.payload_jcs).unwrap();
        let exec: serde_json::Value =
            serde_json::from_str(&b.execution_receipt.payload_jcs).unwrap();
        assert_eq!(lock.as_object().unwrap().len(), 20, "{name}");
        assert_eq!(exec.as_object().unwrap().len(), 28, "{name}");
        match parse_lock_receipt(&b.lock_receipt.payload_jcs).unwrap() {
            ParsedLockReceipt::V6(p) => {
                assert_eq!(validate_lock_receipt_tags_v6(&p), Ok(()), "{name}")
            }
            other => panic!("{name}: {other:?}"),
        }
        match parse_execution_receipt(&b.execution_receipt.payload_jcs).unwrap() {
            ParsedExecutionReceipt::V5(p) => {
                assert_eq!(validate_execution_receipt_tags_v5(&p), Ok(()), "{name}");
                assert_eq!(
                    p.weather_station.as_deref(),
                    Some(landobs_v1::PRIMARY_STATION),
                    "{name}"
                );
            }
            other => panic!("{name}: {other:?}"),
        }
        assert_eq!(state_of(&exec), state, "{name}");
    }
}

#[test]
fn negative_bundle_vectors_fail_at_exactly_the_named_steps() {
    let v = vector("proof-bundle-v6-negative.json");
    let keys = &v["keys"];
    let cases = v["cases"].as_array().expect("cases is a list");
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let report = verify(&case["bundle"], keys);
        assert!(!report.passed(), "{name} passed");
        let got = sorted(
            report
                .steps
                .iter()
                .filter(|s| matches!(s.status, StepStatus::Fail(_)))
                .map(|s| {
                    serde_json::to_value(s.name)
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_string()
                }),
        );
        assert_eq!(
            got,
            step_names(&case["expected_failing_steps"]),
            "{name}: {:?}",
            report.steps
        );
    }
}

/// The negative cases the vector carries beyond `V6_NEGATIVE_CASES` (which
/// the crate builds itself), with their exact failing step sets. Together
/// they are every case in `proof-bundle-v6-negative.json`.
const VECTOR_ONLY_NEGATIVE_CASES: &[(&str, &[&str])] = &[
    (
        "unknown_v6_tag",
        &[
            "bundle_shape",
            "receipt_field_consistency",
            "weather_observation_window",
        ],
    ),
    (
        "entropy_composition_mismatch",
        &[
            "bundle_shape",
            "receipt_field_consistency",
            "weather_observation_window",
        ],
    ),
    (
        "observation_time_without_weather_value",
        &[
            "receipt_field_consistency",
            "seed_recomputation",
            "weather_observation_window",
        ],
    ),
    (
        "freq_window_with_weather_value",
        &[
            "receipt_field_consistency",
            "seed_recomputation",
            "weather_observation_window",
        ],
    ),
    (
        "freq_window_with_observation_time",
        &[
            "receipt_field_consistency",
            "seed_recomputation",
            "weather_observation_window",
        ],
    ),
    (
        "fallback_with_weather_value",
        &[
            "receipt_field_consistency",
            "seed_recomputation",
            "weather_observation_window",
        ],
    ),
    (
        "fallback_with_observation_time",
        &[
            "receipt_field_consistency",
            "seed_recomputation",
            "weather_observation_window",
        ],
    ),
    (
        "fallback_executed_before_round_published",
        &["drand_bls_signature"],
    ),
    (
        "freq_start_not_derived_from_round",
        &["weather_observation_window"],
    ),
    (
        "freq_start_not_on_grid",
        &["bundle_shape", "weather_observation_window"],
    ),
    (
        "freq_locked_at_after_latest_lock_at",
        &["weather_observation_window"],
    ),
    (
        "freq_round_published_before_lock",
        &["drand_bls_signature", "weather_observation_window"],
    ),
    ("freq_value_and_reason", &["weather_observation_window"]),
    (
        "freq_value_null_reason_null",
        &["weather_observation_window"],
    ),
    (
        "freq_weather_reason",
        &["bundle_shape", "weather_observation_window"],
    ),
    ("freq_value_stuck_run", &["bundle_shape"]),
    ("freq_value_zero_reading", &["bundle_shape"]),
    ("freq_value_out_of_bounds", &["bundle_shape"]),
    ("freq_value_four_digits", &["bundle_shape"]),
    (
        "weather_value_under_freq_tag",
        &["bundle_shape", "seed_recomputation"],
    ),
    (
        "weather_station_under_freq_tag",
        &["bundle_shape", "receipt_field_consistency"],
    ),
    (
        "freq_lock_with_landobs_exec",
        &[
            "bundle_shape",
            "receipt_field_consistency",
            "weather_observation_window",
        ],
    ),
    (
        "landobs_lock_with_freq_exec",
        &[
            "bundle_shape",
            "receipt_field_consistency",
            "weather_observation_window",
        ],
    ),
    (
        "unknown_freq_tag",
        &[
            "bundle_shape",
            "lock_signature",
            "receipt_field_consistency",
            "weather_observation_window",
        ],
    ),
    (
        "freq_executed_before_round_published",
        &["drand_bls_signature"],
    ),
    ("freq_entropy_value_mismatch", &["drand_bls_signature"]),
];

/// How many cases `proof-bundle-v6-negative.json` carries.
const NEGATIVE_CASE_COUNT: usize = 59;

#[test]
fn negative_vector_carries_exactly_the_pinned_cases_with_their_steps() {
    let v = vector("proof-bundle-v6-negative.json");
    let cases = v["cases"].as_array().expect("cases is a list");
    assert_eq!(cases.len(), NEGATIVE_CASE_COUNT);
    let got: BTreeMap<&str, Vec<String>> = cases
        .iter()
        .map(|c| {
            (
                c["name"].as_str().unwrap(),
                step_names(&c["expected_failing_steps"]),
            )
        })
        .collect();
    assert_eq!(got.len(), cases.len(), "case names are not unique");

    let pinned: BTreeMap<&str, Vec<String>> = V6_NEGATIVE_CASES
        .iter()
        .chain(VECTOR_ONLY_NEGATIVE_CASES)
        .map(|(name, steps)| (*name, sorted(steps.iter().map(|s| s.to_string()))))
        .collect();
    assert_eq!(
        pinned.len(),
        V6_NEGATIVE_CASES.len() + VECTOR_ONLY_NEGATIVE_CASES.len(),
        "a pinned name is listed twice"
    );
    assert_eq!(pinned.len(), NEGATIVE_CASE_COUNT);
    assert_eq!(
        got.keys().collect::<Vec<_>>(),
        pinned.keys().collect::<Vec<_>>(),
        "case names"
    );
    for (name, steps) in &pinned {
        assert_eq!(&got[name], steps, "{name}");
    }
}
