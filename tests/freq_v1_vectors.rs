//! wallop_core's frozen grid-frequency vectors (`drand-quicknet+elexon-freq-v1`):
//! the schedule, the value grammar, the lock 6 / execution 5 receipts and
//! the proof bundles. Read under the rules in `tests/common`: the vendored
//! copy; a failure if one is missing once any v6 vector is vendored;
//! before that, `WALLOP_CORE_VECTORS_DIR`.

mod common;

use sha2::{Digest, Sha256};
use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::protocol::freq_v1;
use wallop_verifier::protocol::receipts::{
    ParsedExecutionReceipt, ParsedLockReceipt, parse_execution_receipt, parse_lock_receipt,
    validate_execution_receipt_tags_v5_freq, validate_lock_receipt_tags_v6_freq,
};
use wallop_verifier::verify_steps::{StepStatus, VerifierMode, verify_bundle_with};

fn vector(name: &str) -> Option<serde_json::Value> {
    common::core_vector(name, None)
}

#[test]
fn schedule_vector_matches_the_constants_and_the_maths() {
    let Some(v) = vector("frequency-schedule-elexon-v1.json") else {
        return;
    };
    assert_eq!(v["entropy_composition"], freq_v1::ENTROPY_COMPOSITION);
    assert_eq!(v["readings"], freq_v1::READINGS as u64);
    assert_eq!(v["spacing_secs"], freq_v1::SPACING_SECS);
    assert_eq!(v["w_freq_secs"], freq_v1::W_FREQ_SECS);
    assert_eq!(v["margin_secs"], freq_v1::MARGIN_SECS);
    assert_eq!(v["lock_gap_secs"], freq_v1::LOCK_GAP_SECS);
    assert_eq!(v["stuck_run"], freq_v1::STUCK_RUN as u64);
    assert_eq!(
        v["bounds_mhz"],
        serde_json::json!([freq_v1::MIN_MHZ, freq_v1::MAX_MHZ])
    );
    let cases = v["cases"].as_array().expect("cases is a list");
    assert!(!cases.is_empty());
    for c in cases {
        let round = c["drand_round"].as_u64().unwrap();
        let published = wallop_verifier::drand::quicknet_round_time(round).unwrap();
        assert_eq!(
            freq_v1::format_freq_start(published),
            c["published_at"].as_str().unwrap(),
            "{c}"
        );
        let start = freq_v1::freq_start_for_round(round).unwrap();
        assert_eq!(
            freq_v1::parse_freq_start(c["freq_start"].as_str().unwrap()),
            Ok(start),
            "{c}"
        );
        assert_eq!(
            freq_v1::format_freq_start(start + freq_v1::SPAN_SECS + freq_v1::W_FREQ_SECS),
            c["fetch_deadline"].as_str().unwrap(),
            "{c}"
        );
        let latest = freq_v1::latest_lock_at(start).unwrap();
        assert_eq!(
            freq_v1::format_freq_start(latest),
            c["latest_lock_at"].as_str().unwrap(),
            "{c}"
        );
    }
}

#[test]
fn value_vector_matches_the_grammar() {
    let Some(v) = vector("frequency-value-elexon-v1.json") else {
        return;
    };
    assert_eq!(
        v["bounds_mhz"],
        serde_json::json!([freq_v1::MIN_MHZ, freq_v1::MAX_MHZ])
    );
    assert_eq!(v["stuck_run"], freq_v1::STUCK_RUN as u64);
    let list = |k: &str| v[k].as_array().unwrap_or_else(|| panic!("{k} is a list"));
    for c in list("valid") {
        assert!(
            freq_v1::parse_freq_value(c.as_str().unwrap()).is_ok(),
            "{c}"
        );
    }
    for c in list("invalid") {
        assert!(
            freq_v1::parse_freq_value(c["value"].as_str().unwrap()).is_err(),
            "{c}"
        );
    }
    for c in list("readings") {
        let got = freq_v1::reading_from_text(c["text"].as_str().unwrap());
        match c.get("expected_mhz") {
            Some(m) => assert_eq!(got, Ok(m.as_u64().unwrap() as u32), "{c}"),
            None => {
                assert_eq!(c["expected_error"], true, "{c}");
                assert!(got.is_err(), "{c}");
            }
        }
    }
    for c in list("from_rows") {
        let start = freq_v1::parse_freq_start(c["freq_start"].as_str().unwrap()).unwrap();
        let rows: Vec<(String, String)> = c["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r[0].as_str().unwrap().to_string(),
                    r[1].as_str().unwrap().to_string(),
                )
            })
            .collect();
        let got = freq_v1::window_from_rows(&rows, start);
        match c.get("expected_value") {
            Some(e) => assert_eq!(got.as_deref(), Ok(e.as_str().unwrap()), "{c}"),
            None => {
                assert_eq!(c["expected_error"], true, "{c}");
                assert!(got.is_err(), "{c}");
            }
        }
    }
}

/// A receipt vector: its field count, schema and payload hash, and that it
/// parses as the frequency variant and passes its tag validator.
fn check_receipt_vector(name: &str, lock: bool) {
    let Some(v) = vector(name) else { return };
    let jcs = v["payload_jcs"].as_str().expect("payload_jcs");
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
        hex::encode(Sha256::digest(jcs.as_bytes())),
        v["expected_payload_sha256"].as_str().unwrap(),
        "{name}"
    );
    if lock {
        assert_eq!(v["expected_field_count"], freq_v1::LOCK_KEYS.len() as u64);
        match parse_lock_receipt(jcs).unwrap() {
            ParsedLockReceipt::V6Freq(p) => {
                assert_eq!(validate_lock_receipt_tags_v6_freq(&p), Ok(()), "{name}")
            }
            other => panic!("{name} parsed as {other:?}"),
        }
    } else {
        assert_eq!(v["expected_field_count"], freq_v1::EXEC_KEYS.len() as u64);
        match parse_execution_receipt(jcs).unwrap() {
            ParsedExecutionReceipt::V5Freq(p) => {
                assert_eq!(
                    validate_execution_receipt_tags_v5_freq(&p),
                    Ok(()),
                    "{name}"
                )
            }
            other => panic!("{name} parsed as {other:?}"),
        }
    }
}

#[test]
fn receipt_vectors_parse_as_the_frequency_tag() {
    check_receipt_vector("lock-receipt-v6-freq.json", true);
    check_receipt_vector("execution-receipt-v5-freq.json", false);
    check_receipt_vector("execution-receipt-fallback-v5-freq.json", false);
}

#[test]
fn proof_bundle_vectors_pass_every_step() {
    for name in [
        "proof-bundle-v6-freq.json",
        "proof-bundle-v6-freq-fallback.json",
    ] {
        let Some(v) = vector(name) else { continue };
        assert_eq!(v["expected_passed"], true, "{name}");
        let json = v["bundle"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| v["bundle"].to_string());
        let report = verify_bundle_with(
            &ProofBundle::from_json(&json).unwrap(),
            &common::resolver(&v["keys"]),
            VerifierMode::Attestable,
        );
        assert!(report.passed(), "{name}: {:?}", report.steps);
        assert!(
            report.steps.iter().all(|s| s.status == StepStatus::Pass),
            "{name}: {:?}",
            report.steps
        );
    }
}
