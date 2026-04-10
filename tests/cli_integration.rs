//! Integration tests for wallop-verify CLI pipeline.
//!
//! These tests verify that the step-by-step pipeline and verify_full()
//! agree on all inputs.

use ed25519_dalek::{Signer, SigningKey};
use wallop_rs::bundle::ProofBundle;
use wallop_rs::verify_steps::{verify_bundle, StepStatus};
use wallop_rs::{Entry, compute_seed, compute_seed_drand_only, draw, entry_hash};
use wallop_rs::protocol::receipts::lock_receipt_hash;

fn test_signing_key() -> SigningKey {
    let secret_bytes: [u8; 32] =
        hex::decode("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60")
            .unwrap()
            .try_into()
            .unwrap();
    SigningKey::from_bytes(&secret_bytes)
}

fn build_valid_bundle(entries: &[Entry], weather: Option<&str>, winner_count: u32) -> String {
    let sk = test_signing_key();
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());

    let (ehash, _) = entry_hash(entries);
    let drand = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    let (seed_bytes, _) = match weather {
        Some(w) => compute_seed(&ehash, drand, w),
        None => compute_seed_drand_only(&ehash, drand),
    };
    let seed_hex = hex::encode(seed_bytes);
    let winners = draw(entries, &seed_bytes, winner_count).unwrap();
    let results_array: Vec<String> = winners.iter().map(|w| w.entry_id.clone()).collect();

    // Lock receipt — serde_json::Map preserves insertion order but json! macro uses BTreeMap
    // which sorts alphabetically. Use json! for consistency with JCS expectations.
    let lock_jcs = serde_json::json!({
        "commitment_hash": "00".repeat(32),
        "drand_chain": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
        "drand_round": 12345,
        "draw_id": "22222222-2222-2222-2222-222222222222",
        "entry_hash": &ehash,
        "fair_pick_version": "0.1.0",
        "locked_at": "2026-04-09T12:00:00.000000Z",
        "operator_id": "11111111-1111-1111-1111-111111111111",
        "operator_slug": "acme-prizes",
        "schema_version": "2",
        "sequence": 1,
        "signing_key_id": "deadbeef",
        "wallop_core_version": "0.14.1",
        "weather_station": "middle-wallop",
        "weather_time": "2026-04-09T12:10:00.000000Z",
        "winner_count": winner_count
    }).to_string();
    let lock_sig_hex = hex::encode(sk.sign(lock_jcs.as_bytes()).to_bytes());
    let lrh = lock_receipt_hash(&lock_jcs);

    // Execution receipt
    let exec_jcs = serde_json::json!({
        "drand_chain": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
        "drand_randomness": drand,
        "drand_round": 12345,
        "drand_signature": "00".repeat(48),
        "draw_id": "22222222-2222-2222-2222-222222222222",
        "entry_hash": &ehash,
        "executed_at": "2026-04-09T12:15:00.000000Z",
        "execution_schema_version": "1",
        "fair_pick_version": "0.1.0",
        "lock_receipt_hash": &lrh,
        "operator_id": "11111111-1111-1111-1111-111111111111",
        "operator_slug": "acme-prizes",
        "results": &results_array,
        "seed": &seed_hex,
        "sequence": 1,
        "wallop_core_version": "0.14.1",
        "weather_fallback_reason": null,
        "weather_observation_time": if weather.is_some() { serde_json::json!("2026-04-09T12:10:00.000000Z") } else { serde_json::Value::Null },
        "weather_station": if weather.is_some() { serde_json::json!("middle-wallop") } else { serde_json::Value::Null },
        "weather_value": match weather { Some(w) => serde_json::json!(w), None => serde_json::Value::Null }
    }).to_string();
    let exec_sig_hex = hex::encode(sk.sign(exec_jcs.as_bytes()).to_bytes());

    // Bundle
    let mut entropy = serde_json::Map::new();
    entropy.insert("drand_round".into(), serde_json::json!(12345));
    entropy.insert("drand_randomness".into(), serde_json::json!(drand));
    entropy.insert("drand_signature".into(), serde_json::json!("00".repeat(48)));
    entropy.insert("drand_chain_hash".into(), serde_json::json!("52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"));
    if let Some(w) = weather {
        entropy.insert("weather_value".into(), serde_json::json!(w));
    }
    // Note: for drand-only, weather_value key is OMITTED entirely (not null)

    serde_json::json!({
        "version": 1,
        "draw_id": "22222222-2222-2222-2222-222222222222",
        "entries": entries.iter().map(|e| serde_json::json!({"id": &e.id, "weight": e.weight})).collect::<Vec<_>>(),
        "results": winners.iter().map(|w| serde_json::json!({"entry_id": &w.entry_id, "position": w.position})).collect::<Vec<_>>(),
        "entropy": entropy,
        "lock_receipt": {
            "payload_jcs": &lock_jcs,
            "signature_hex": &lock_sig_hex,
            "operator_public_key_hex": &pk_hex
        },
        "execution_receipt": {
            "payload_jcs": &exec_jcs,
            "signature_hex": &exec_sig_hex,
            "infrastructure_public_key_hex": &pk_hex
        }
    }).to_string()
}

fn run_verify_full(bundle: &ProofBundle) -> bool {
    let entries: Vec<Entry> = bundle.entries.iter()
        .map(|e| Entry { id: e.id.clone(), weight: e.weight })
        .collect();
    let lock_sig: [u8; 64] = hex::decode(&bundle.lock_receipt.signature_hex)
        .unwrap().try_into().unwrap();
    let op_pk: [u8; 32] = hex::decode(&bundle.lock_receipt.public_key_hex)
        .unwrap().try_into().unwrap();
    let exec_sig: [u8; 64] = hex::decode(&bundle.execution_receipt.signature_hex)
        .unwrap().try_into().unwrap();
    let infra_pk: [u8; 32] = hex::decode(&bundle.execution_receipt.public_key_hex)
        .unwrap().try_into().unwrap();

    wallop_rs::verify_full(
        &bundle.lock_receipt.payload_jcs, &lock_sig, &op_pk,
        &bundle.execution_receipt.payload_jcs, &exec_sig, &infra_pk,
        &entries,
    ).unwrap_or(false)
}

/// Drift guard: step-by-step (steps 1-7) must agree with verify_full() on valid bundles.
#[test]
fn step_by_step_agrees_with_verify_full() {
    let entries = vec![
        Entry { id: "ticket-47".into(), weight: 1 },
        Entry { id: "ticket-48".into(), weight: 1 },
        Entry { id: "ticket-49".into(), weight: 1 },
    ];

    // Test with weather
    let json = build_valid_bundle(&entries, Some("1013"), 2);
    let bundle = ProofBundle::from_json(&json).unwrap();
    let report = verify_bundle(&bundle);
    // Check steps 1-7 individually (step 8 BLS is a skip without real drand sig)
    let steps_1_to_7_pass = report.steps[..7].iter()
        .all(|s| matches!(s.status, StepStatus::Pass));
    let vf_pass = run_verify_full(&bundle);
    assert_eq!(steps_1_to_7_pass, vf_pass,
        "drift detected: steps 1-7 all pass={steps_1_to_7_pass}, verify_full={vf_pass}");

    // Test drand-only
    let json2 = build_valid_bundle(&entries, None, 1);
    let bundle2 = ProofBundle::from_json(&json2).unwrap();
    let report2 = verify_bundle(&bundle2);
    let steps_1_to_7_pass2 = report2.steps[..7].iter()
        .all(|s| matches!(s.status, StepStatus::Pass));
    let vf_pass2 = run_verify_full(&bundle2);
    assert_eq!(steps_1_to_7_pass2, vf_pass2,
        "drift detected (drand-only): steps={steps_1_to_7_pass2}, verify_full={vf_pass2}");
}

#[test]
fn drand_only_bundle_omits_weather() {
    let entries = vec![
        Entry { id: "a".into(), weight: 1 },
        Entry { id: "b".into(), weight: 1 },
    ];
    let json = build_valid_bundle(&entries, None, 1);

    // Verify the bundle JSON has no weather_value key in entropy
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(val["entropy"].get("weather_value").is_none(),
        "drand-only bundle should not contain weather_value key");

    let bundle = ProofBundle::from_json(&json).unwrap();
    assert!(bundle.is_drand_only());
    let report = verify_bundle(&bundle);
    // Steps 1-7 should pass
    for step in &report.steps[..7] {
        assert!(matches!(step.status, StepStatus::Pass),
            "step {} was {:?}", step.name, step.status);
    }
}
