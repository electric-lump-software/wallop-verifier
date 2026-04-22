use super::*;
use sha2::{Digest, Sha256};

const LOCK_RECEIPT_VECTOR: &str =
    include_str!("../../vendor/wallop/spec/vectors/lock-receipt.json");
const EXECUTION_RECEIPT_VECTOR: &str =
    include_str!("../../vendor/wallop/spec/vectors/execution-receipt.json");
const CROSS_RECEIPT_VECTOR: &str =
    include_str!("../../vendor/wallop/spec/vectors/cross-receipt-linkage.json");
const DRAND_ONLY_VECTOR: &str =
    include_str!("../../vendor/wallop/spec/vectors/execution-receipt-drand-only.json");

fn sha256_hex(data: &str) -> String {
    hex::encode(Sha256::digest(data.as_bytes()))
}

fn lock_receipt_from_json(input: &serde_json::Value) -> LockReceiptV3 {
    LockReceiptV3 {
        commitment_hash: input["commitment_hash"].as_str().unwrap().into(),
        draw_id: input["draw_id"].as_str().unwrap().into(),
        drand_chain: input["drand_chain"].as_str().unwrap().into(),
        drand_round: input["drand_round"].as_u64().unwrap(),
        entry_hash: input["entry_hash"].as_str().unwrap().into(),
        fair_pick_version: input["fair_pick_version"].as_str().unwrap().into(),
        locked_at: input["locked_at"].as_str().unwrap().into(),
        operator_id: input["operator_id"].as_str().unwrap().into(),
        operator_slug: input["operator_slug"].as_str().unwrap().into(),
        sequence: input["sequence"].as_u64().unwrap(),
        signing_key_id: input["signing_key_id"].as_str().unwrap().into(),
        wallop_core_version: input["wallop_core_version"].as_str().unwrap().into(),
        weather_station: input["weather_station"].as_str().unwrap().into(),
        weather_time: input["weather_time"].as_str().unwrap().into(),
        winner_count: input["winner_count"].as_u64().unwrap(),
    }
}

fn execution_receipt_from_json(input: &serde_json::Value) -> ExecutionReceiptV1 {
    ExecutionReceiptV1 {
        drand_chain: input["drand_chain"].as_str().unwrap().into(),
        drand_randomness: input["drand_randomness"].as_str().unwrap().into(),
        drand_round: input["drand_round"].as_u64().unwrap(),
        drand_signature: input["drand_signature"].as_str().unwrap().into(),
        draw_id: input["draw_id"].as_str().unwrap().into(),
        entry_hash: input["entry_hash"].as_str().unwrap().into(),
        executed_at: input["executed_at"].as_str().unwrap().into(),
        fair_pick_version: input["fair_pick_version"].as_str().unwrap().into(),
        lock_receipt_hash: input["lock_receipt_hash"].as_str().unwrap().into(),
        operator_id: input["operator_id"].as_str().unwrap().into(),
        operator_slug: input["operator_slug"].as_str().unwrap().into(),
        results: input["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().into())
            .collect(),
        seed: input["seed"].as_str().unwrap().into(),
        sequence: input["sequence"].as_u64().unwrap(),
        wallop_core_version: input["wallop_core_version"].as_str().unwrap().into(),
        weather_fallback_reason: input["weather_fallback_reason"].as_str().map(String::from),
        weather_observation_time: input["weather_observation_time"].as_str().map(String::from),
        weather_station: input["weather_station"].as_str().map(String::from),
        weather_value: input["weather_value"].as_str().map(String::from),
    }
}

// ── V-5: lock receipt payload ──────────────────────────────────────

#[test]
fn v5_lock_receipt_payload_sha256_pinned() {
    let vector: serde_json::Value = serde_json::from_str(LOCK_RECEIPT_VECTOR).unwrap();
    let input = lock_receipt_from_json(&vector["input"]);

    let payload = build_receipt_payload(&input);

    assert_eq!(
        sha256_hex(&payload),
        vector["expected_payload_sha256"].as_str().unwrap()
    );

    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(
        parsed.as_object().unwrap().len(),
        vector["expected_field_count"].as_u64().unwrap() as usize
    );
}

#[test]
fn v5_lock_receipt_schema_version_is_2() {
    let vector: serde_json::Value = serde_json::from_str(LOCK_RECEIPT_VECTOR).unwrap();
    let input = lock_receipt_from_json(&vector["input"]);

    let payload = build_receipt_payload(&input);
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(
        parsed["schema_version"].as_str().unwrap(),
        vector["expected_schema_version"].as_str().unwrap()
    );
}

#[test]
fn v5_lock_receipt_exact_jcs() {
    let vector: serde_json::Value = serde_json::from_str(LOCK_RECEIPT_VECTOR).unwrap();
    let input = lock_receipt_from_json(&vector["input"]);

    let payload = build_receipt_payload(&input);

    // Verify roundtrip: parse and re-serialize to confirm key ordering
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    let reserialized = serde_json::to_string(&parsed).unwrap();
    assert_eq!(payload, reserialized);
}

// ── V-6: execution receipt payload ─────────────────────────────────

#[test]
fn v6_execution_receipt_payload_sha256_pinned() {
    let vector: serde_json::Value = serde_json::from_str(EXECUTION_RECEIPT_VECTOR).unwrap();
    let input = execution_receipt_from_json(&vector["input"]);

    let payload = build_execution_receipt_payload(&input);

    assert_eq!(
        sha256_hex(&payload),
        vector["expected_payload_sha256"].as_str().unwrap()
    );

    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(
        parsed.as_object().unwrap().len(),
        vector["expected_field_count"].as_u64().unwrap() as usize
    );
}

#[test]
fn v6_execution_receipt_schema_version_is_1() {
    let vector: serde_json::Value = serde_json::from_str(EXECUTION_RECEIPT_VECTOR).unwrap();
    let input = execution_receipt_from_json(&vector["input"]);

    let payload = build_execution_receipt_payload(&input);
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(
        parsed["execution_schema_version"].as_str().unwrap(),
        vector["expected_execution_schema_version"]
            .as_str()
            .unwrap()
    );
}

#[test]
fn v6_execution_receipt_exact_jcs() {
    let vector: serde_json::Value = serde_json::from_str(EXECUTION_RECEIPT_VECTOR).unwrap();
    let input = execution_receipt_from_json(&vector["input"]);

    let payload = build_execution_receipt_payload(&input);

    // Verify roundtrip: parse and re-serialize to confirm key ordering
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    let reserialized = serde_json::to_string(&parsed).unwrap();
    assert_eq!(payload, reserialized);
}

// ── V-11: cross-receipt linkage ────────────────────────────────────

#[test]
fn v11_lock_receipt_hash_pinned() {
    let vector: serde_json::Value = serde_json::from_str(CROSS_RECEIPT_VECTOR).unwrap();
    let input = lock_receipt_from_json(&vector["lock_receipt_input"]);

    let payload = build_receipt_payload(&input);
    let hash = lock_receipt_hash(&payload);

    assert_eq!(
        hash,
        vector["expected_lock_payload_sha256"].as_str().unwrap()
    );
}

#[test]
fn v11_execution_receipt_uses_lock_receipt_hash() {
    let vector: serde_json::Value = serde_json::from_str(CROSS_RECEIPT_VECTOR).unwrap();
    let lock_input = lock_receipt_from_json(&vector["lock_receipt_input"]);

    let lock_payload = build_receipt_payload(&lock_input);
    let lock_hash = lock_receipt_hash(&lock_payload);

    // The drand-only vector's execution receipt uses this lock_receipt_hash
    let drand_vector: serde_json::Value = serde_json::from_str(DRAND_ONLY_VECTOR).unwrap();
    let drand_input = &drand_vector["input"];

    assert_eq!(
        drand_input["lock_receipt_hash"].as_str().unwrap(),
        lock_hash
    );
}

// ── V-12: drand-only execution receipt ─────────────────────────────

#[test]
fn v12_drand_only_null_weather_fields_present() {
    let vector: serde_json::Value = serde_json::from_str(DRAND_ONLY_VECTOR).unwrap();
    let input = execution_receipt_from_json(&vector["input"]);
    let assertions = &vector["assertions"];

    let payload = build_execution_receipt_payload(&input);
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();

    // Null weather fields must be present as JSON null, not omitted
    assert_eq!(
        parsed.get("weather_station").is_some(),
        assertions["weather_station_key_present"].as_bool().unwrap()
    );
    assert_eq!(
        parsed.get("weather_observation_time").is_some(),
        assertions["weather_observation_time_key_present"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        parsed.get("weather_value").is_some(),
        assertions["weather_value_key_present"].as_bool().unwrap()
    );

    assert!(parsed["weather_station"].is_null());
    assert!(parsed["weather_observation_time"].is_null());
    assert!(parsed["weather_value"].is_null());
    assert_eq!(parsed["weather_fallback_reason"], "met_office_timeout");
}

#[test]
fn v12_drand_only_payload_sha256_pinned() {
    let vector: serde_json::Value = serde_json::from_str(DRAND_ONLY_VECTOR).unwrap();
    let input = execution_receipt_from_json(&vector["input"]);

    let payload = build_execution_receipt_payload(&input);

    assert_eq!(
        sha256_hex(&payload),
        vector["expected_payload_sha256"].as_str().unwrap()
    );
}

// ── receipt_schema_version helper ──────────────────────────────────

#[test]
fn receipt_schema_version_v3() {
    let vector: serde_json::Value = serde_json::from_str(LOCK_RECEIPT_VECTOR).unwrap();
    let input = lock_receipt_from_json(&vector["input"]);

    let payload = build_receipt_payload(&input);
    assert_eq!(receipt_schema_version(&payload), Some("3".into()));
}

#[test]
fn receipt_schema_version_missing() {
    assert_eq!(receipt_schema_version(r#"{"foo":"bar"}"#), None);
}

#[test]
fn receipt_schema_version_invalid_json() {
    assert_eq!(receipt_schema_version("not json"), None);
}
