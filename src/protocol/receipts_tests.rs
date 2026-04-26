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
const EXECUTION_RECEIPT_V3_VECTOR: &str =
    include_str!("../../vendor/wallop/spec/vectors/execution-receipt-v3.json");
const DRAND_ONLY_V3_VECTOR: &str =
    include_str!("../../vendor/wallop/spec/vectors/execution-receipt-drand-only-v3.json");

fn sha256_hex(data: &str) -> String {
    hex::encode(Sha256::digest(data.as_bytes()))
}

fn lock_receipt_from_json(input: &serde_json::Value) -> LockReceiptV4 {
    LockReceiptV4 {
        commitment_hash: input["commitment_hash"].as_str().unwrap().into(),
        draw_id: input["draw_id"].as_str().unwrap().into(),
        drand_chain: input["drand_chain"].as_str().unwrap().into(),
        drand_round: input["drand_round"].as_u64().unwrap(),
        entropy_composition: ENTROPY_COMPOSITION.into(),
        entry_hash: input["entry_hash"].as_str().unwrap().into(),
        fair_pick_version: input["fair_pick_version"].as_str().unwrap().into(),
        jcs_version: JCS_VERSION.into(),
        locked_at: input["locked_at"].as_str().unwrap().into(),
        operator_id: input["operator_id"].as_str().unwrap().into(),
        operator_slug: input["operator_slug"].as_str().unwrap().into(),
        schema_version: LOCK_SCHEMA_VERSION.into(),
        sequence: input["sequence"].as_u64().unwrap(),
        signature_algorithm: SIGNATURE_ALGORITHM.into(),
        signing_key_id: input["signing_key_id"].as_str().unwrap().into(),
        wallop_core_version: input["wallop_core_version"].as_str().unwrap().into(),
        weather_station: input["weather_station"].as_str().unwrap().into(),
        weather_time: input["weather_time"].as_str().unwrap().into(),
        winner_count: input["winner_count"].as_u64().unwrap(),
    }
}

fn execution_receipt_from_json(input: &serde_json::Value) -> ExecutionReceiptV2 {
    ExecutionReceiptV2 {
        drand_chain: input["drand_chain"].as_str().unwrap().into(),
        drand_randomness: input["drand_randomness"].as_str().unwrap().into(),
        drand_round: input["drand_round"].as_u64().unwrap(),
        drand_signature: input["drand_signature"].as_str().unwrap().into(),
        drand_signature_algorithm: DRAND_SIGNATURE_ALGORITHM.into(),
        draw_id: input["draw_id"].as_str().unwrap().into(),
        entropy_composition: ENTROPY_COMPOSITION.into(),
        entry_hash: input["entry_hash"].as_str().unwrap().into(),
        executed_at: input["executed_at"].as_str().unwrap().into(),
        fair_pick_version: input["fair_pick_version"].as_str().unwrap().into(),
        jcs_version: JCS_VERSION.into(),
        lock_receipt_hash: input["lock_receipt_hash"].as_str().unwrap().into(),
        merkle_algorithm: MERKLE_ALGORITHM.into(),
        operator_id: input["operator_id"].as_str().unwrap().into(),
        operator_slug: input["operator_slug"].as_str().unwrap().into(),
        results: input["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().into())
            .collect(),
        schema_version: EXECUTION_SCHEMA_VERSION.into(),
        seed: input["seed"].as_str().unwrap().into(),
        sequence: input["sequence"].as_u64().unwrap(),
        signature_algorithm: SIGNATURE_ALGORITHM.into(),
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
fn v6_execution_receipt_schema_version_is_2() {
    let vector: serde_json::Value = serde_json::from_str(EXECUTION_RECEIPT_VECTOR).unwrap();
    let input = execution_receipt_from_json(&vector["input"]);

    let payload = build_execution_receipt_payload(&input);
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(
        parsed["schema_version"].as_str().unwrap(),
        vector["expected_schema_version"].as_str().unwrap()
    );
    assert_eq!(parsed.get("execution_schema_version"), None);
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
    assert_eq!(parsed["weather_fallback_reason"], "unreachable");
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

// ── V-13: execution receipt v3 (signing_key_id) ────────────────────

fn execution_receipt_v3_from_v2(
    v2: &ExecutionReceiptV2,
    signing_key_id: &str,
) -> ExecutionReceiptV3 {
    ExecutionReceiptV3 {
        drand_chain: v2.drand_chain.clone(),
        drand_randomness: v2.drand_randomness.clone(),
        drand_round: v2.drand_round,
        drand_signature: v2.drand_signature.clone(),
        drand_signature_algorithm: v2.drand_signature_algorithm.clone(),
        draw_id: v2.draw_id.clone(),
        entropy_composition: v2.entropy_composition.clone(),
        entry_hash: v2.entry_hash.clone(),
        executed_at: v2.executed_at.clone(),
        fair_pick_version: v2.fair_pick_version.clone(),
        jcs_version: v2.jcs_version.clone(),
        lock_receipt_hash: v2.lock_receipt_hash.clone(),
        merkle_algorithm: v2.merkle_algorithm.clone(),
        operator_id: v2.operator_id.clone(),
        operator_slug: v2.operator_slug.clone(),
        results: v2.results.clone(),
        schema_version: EXECUTION_SCHEMA_VERSION_V3.into(),
        seed: v2.seed.clone(),
        sequence: v2.sequence,
        signature_algorithm: v2.signature_algorithm.clone(),
        signing_key_id: signing_key_id.into(),
        wallop_core_version: v2.wallop_core_version.clone(),
        weather_fallback_reason: v2.weather_fallback_reason.clone(),
        weather_observation_time: v2.weather_observation_time.clone(),
        weather_station: v2.weather_station.clone(),
        weather_value: v2.weather_value.clone(),
    }
}

#[test]
fn v13_execution_receipt_v3_payload_contains_signing_key_id() {
    let vector: serde_json::Value = serde_json::from_str(EXECUTION_RECEIPT_VECTOR).unwrap();
    let v2_input = execution_receipt_from_json(&vector["input"]);
    let v3_input = execution_receipt_v3_from_v2(&v2_input, "cafebabe");

    let payload = build_execution_receipt_payload_v3(&v3_input);
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(parsed["schema_version"].as_str().unwrap(), "3");
    assert_eq!(parsed["signing_key_id"].as_str().unwrap(), "cafebabe");
    // v2 field count + 1 for signing_key_id
    let v2_count = vector["expected_field_count"].as_u64().unwrap() as usize;
    assert_eq!(parsed.as_object().unwrap().len(), v2_count + 1);
}

#[test]
fn v13_execution_receipt_v3_deny_unknown_fields_on_v2_payload_missing_signing_key_id() {
    // A V2 payload (no signing_key_id) relabelled as schema_version "3"
    // MUST fail to deserialize as ExecutionReceiptV3 because signing_key_id
    // is a required field (no Option, no default). Closes the upgrade
    // spoof attack — attacker cannot relabel a historical v2 payload as v3.
    let vector: serde_json::Value = serde_json::from_str(EXECUTION_RECEIPT_VECTOR).unwrap();
    let v2_input = execution_receipt_from_json(&vector["input"]);
    let v2_payload = build_execution_receipt_payload(&v2_input);

    // Mutate schema_version in the v2 payload to "3"
    let mut parsed: serde_json::Value = serde_json::from_str(&v2_payload).unwrap();
    parsed["schema_version"] = serde_json::Value::String("3".into());
    let mutated = serde_json::to_string(&parsed).unwrap();

    let result: Result<ExecutionReceiptV3, _> = serde_json::from_str(&mutated);
    assert!(
        result.is_err(),
        "V3 parser MUST reject a v2 payload missing signing_key_id even when schema_version is relabelled; got Ok({:?})",
        result.ok().map(|r| r.signing_key_id)
    );
}

#[test]
fn v13_execution_receipt_v2_rejects_v3_payload_with_signing_key_id() {
    // A V3 payload (with signing_key_id) relabelled as schema_version "2"
    // MUST fail to deserialize as ExecutionReceiptV2 because
    // deny_unknown_fields rejects the extra key. Closes the downgrade
    // attack — attacker cannot relabel a v3 payload as v2 to trick an
    // older verifier.
    let vector: serde_json::Value = serde_json::from_str(EXECUTION_RECEIPT_VECTOR).unwrap();
    let v2_input = execution_receipt_from_json(&vector["input"]);
    let v3_input = execution_receipt_v3_from_v2(&v2_input, "cafebabe");
    let v3_payload = build_execution_receipt_payload_v3(&v3_input);

    // Mutate schema_version in the v3 payload to "2"
    let mut parsed: serde_json::Value = serde_json::from_str(&v3_payload).unwrap();
    parsed["schema_version"] = serde_json::Value::String("2".into());
    let mutated = serde_json::to_string(&parsed).unwrap();

    let result: Result<ExecutionReceiptV2, _> = serde_json::from_str(&mutated);
    assert!(
        result.is_err(),
        "V2 parser MUST reject a v3 payload with signing_key_id even when schema_version is relabelled"
    );
}

// ── V-14: parse_execution_receipt dispatcher ───────────────────────

#[test]
fn v14_dispatcher_parses_v2_payload() {
    let vector: serde_json::Value = serde_json::from_str(EXECUTION_RECEIPT_VECTOR).unwrap();
    let v2_input = execution_receipt_from_json(&vector["input"]);
    let payload = build_execution_receipt_payload(&v2_input);

    let parsed = parse_execution_receipt(&payload).expect("v2 payload should parse");
    assert!(matches!(parsed, ParsedExecutionReceipt::V2(_)));
}

#[test]
fn v14_dispatcher_parses_v3_payload() {
    let vector: serde_json::Value = serde_json::from_str(EXECUTION_RECEIPT_VECTOR).unwrap();
    let v2_input = execution_receipt_from_json(&vector["input"]);
    let v3_input = execution_receipt_v3_from_v2(&v2_input, "deadbeef");
    let payload = build_execution_receipt_payload_v3(&v3_input);

    let parsed = parse_execution_receipt(&payload).expect("v3 payload should parse");
    match parsed {
        ParsedExecutionReceipt::V3(r) => assert_eq!(r.signing_key_id, "deadbeef"),
        other => panic!("expected V3, got {:?}", other),
    }
}

#[test]
fn v14_dispatcher_rejects_unknown_schema_version_terminally() {
    // A payload with schema_version "99" MUST return UnknownSchemaVersion.
    // This is terminal — the error carries the offending value and is not
    // mapped to any transient/retryable variant. A verifier receiving this
    // MUST upgrade (spec §4.2.1 older-schema rejection), not retry.
    let payload = r#"{"schema_version":"99","foo":"bar"}"#;
    let err = parse_execution_receipt(payload).expect_err("must reject unknown schema");
    match err {
        ParseExecutionReceiptError::UnknownSchemaVersion(v) => assert_eq!(v, "99"),
        other => panic!("expected UnknownSchemaVersion, got {:?}", other),
    }
}

#[test]
fn v14_dispatcher_rejects_missing_schema_version() {
    let payload = r#"{"foo":"bar"}"#;
    let err = parse_execution_receipt(payload).expect_err("must reject missing schema");
    assert_eq!(err, ParseExecutionReceiptError::MissingSchemaVersion);
}

#[test]
fn v14_dispatcher_rejects_invalid_json() {
    let err = parse_execution_receipt("not json").expect_err("must reject invalid json");
    assert!(matches!(err, ParseExecutionReceiptError::InvalidJson(_)));
}

#[test]
fn v14_dispatcher_rejects_v3_payload_relabelled_as_v2() {
    // Downgrade attack: v3 payload (with signing_key_id) relabelled as v2.
    // Dispatcher routes to V2 parser because schema_version says "2"; V2
    // parser rejects because deny_unknown_fields disallows signing_key_id.
    // Result: PayloadShapeMismatch.
    let vector: serde_json::Value = serde_json::from_str(EXECUTION_RECEIPT_VECTOR).unwrap();
    let v2_input = execution_receipt_from_json(&vector["input"]);
    let v3_input = execution_receipt_v3_from_v2(&v2_input, "deadbeef");
    let v3_payload = build_execution_receipt_payload_v3(&v3_input);

    let mut parsed: serde_json::Value = serde_json::from_str(&v3_payload).unwrap();
    parsed["schema_version"] = serde_json::Value::String("2".into());
    let mutated = serde_json::to_string(&parsed).unwrap();

    let err = parse_execution_receipt(&mutated).expect_err("must reject downgrade");
    assert!(matches!(
        err,
        ParseExecutionReceiptError::PayloadShapeMismatch(_)
    ));
}

#[test]
fn v14_dispatcher_rejects_v2_payload_relabelled_as_v3() {
    // Upgrade spoof: v2 payload (no signing_key_id) relabelled as v3.
    // Dispatcher routes to V3 parser because schema_version says "3"; V3
    // parser rejects because signing_key_id is a required field.
    let vector: serde_json::Value = serde_json::from_str(EXECUTION_RECEIPT_VECTOR).unwrap();
    let v2_input = execution_receipt_from_json(&vector["input"]);
    let v2_payload = build_execution_receipt_payload(&v2_input);

    let mut parsed: serde_json::Value = serde_json::from_str(&v2_payload).unwrap();
    parsed["schema_version"] = serde_json::Value::String("3".into());
    let mutated = serde_json::to_string(&parsed).unwrap();

    let err = parse_execution_receipt(&mutated).expect_err("must reject upgrade spoof");
    assert!(matches!(
        err,
        ParseExecutionReceiptError::PayloadShapeMismatch(_)
    ));
}

// ── V-15: v3 execution receipt — byte-pinned against vendored vectors ──

// Builds an ExecutionReceiptV3 from a vector file's "input" JSON object.
// Mirror of execution_receipt_from_json but for the v3 shape — the
// vendored v3 vector includes signing_key_id, so this helper reads it
// from the JSON rather than taking it as a separate argument.
fn execution_receipt_v3_from_json(input: &serde_json::Value) -> ExecutionReceiptV3 {
    ExecutionReceiptV3 {
        drand_chain: input["drand_chain"].as_str().unwrap().into(),
        drand_randomness: input["drand_randomness"].as_str().unwrap().into(),
        drand_round: input["drand_round"].as_u64().unwrap(),
        drand_signature: input["drand_signature"].as_str().unwrap().into(),
        drand_signature_algorithm: DRAND_SIGNATURE_ALGORITHM.into(),
        draw_id: input["draw_id"].as_str().unwrap().into(),
        entropy_composition: ENTROPY_COMPOSITION.into(),
        entry_hash: input["entry_hash"].as_str().unwrap().into(),
        executed_at: input["executed_at"].as_str().unwrap().into(),
        fair_pick_version: input["fair_pick_version"].as_str().unwrap().into(),
        jcs_version: JCS_VERSION.into(),
        lock_receipt_hash: input["lock_receipt_hash"].as_str().unwrap().into(),
        merkle_algorithm: MERKLE_ALGORITHM.into(),
        operator_id: input["operator_id"].as_str().unwrap().into(),
        operator_slug: input["operator_slug"].as_str().unwrap().into(),
        results: input["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().into())
            .collect(),
        schema_version: EXECUTION_SCHEMA_VERSION_V3.into(),
        seed: input["seed"].as_str().unwrap().into(),
        sequence: input["sequence"].as_u64().unwrap(),
        signature_algorithm: SIGNATURE_ALGORITHM.into(),
        signing_key_id: input["signing_key_id"].as_str().unwrap().into(),
        wallop_core_version: input["wallop_core_version"].as_str().unwrap().into(),
        weather_fallback_reason: input["weather_fallback_reason"].as_str().map(String::from),
        weather_observation_time: input["weather_observation_time"].as_str().map(String::from),
        weather_station: input["weather_station"].as_str().map(String::from),
        weather_value: input["weather_value"].as_str().map(String::from),
    }
}

#[test]
fn v15_execution_receipt_v3_payload_sha256_pinned() {
    let vector: serde_json::Value = serde_json::from_str(EXECUTION_RECEIPT_V3_VECTOR).unwrap();
    let input = execution_receipt_v3_from_json(&vector["input"]);

    let payload = build_execution_receipt_payload_v3(&input);

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
fn v15_execution_receipt_v3_schema_version_matches_vector() {
    let vector: serde_json::Value = serde_json::from_str(EXECUTION_RECEIPT_V3_VECTOR).unwrap();
    let input = execution_receipt_v3_from_json(&vector["input"]);

    let payload = build_execution_receipt_payload_v3(&input);
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(
        parsed["schema_version"].as_str().unwrap(),
        vector["expected_schema_version"].as_str().unwrap()
    );
    assert_eq!(parsed["signing_key_id"].as_str().unwrap(), "cafebabe");
}

#[test]
fn v15_execution_receipt_v3_exact_jcs_roundtrip() {
    let vector: serde_json::Value = serde_json::from_str(EXECUTION_RECEIPT_V3_VECTOR).unwrap();
    let input = execution_receipt_v3_from_json(&vector["input"]);

    let payload = build_execution_receipt_payload_v3(&input);

    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    let reserialized = serde_json::to_string(&parsed).unwrap();
    assert_eq!(payload, reserialized);
}

#[test]
fn v15_execution_receipt_v3_drand_only_payload_sha256_pinned() {
    let vector: serde_json::Value = serde_json::from_str(DRAND_ONLY_V3_VECTOR).unwrap();
    let input = execution_receipt_v3_from_json(&vector["input"]);

    let payload = build_execution_receipt_payload_v3(&input);

    assert_eq!(
        sha256_hex(&payload),
        vector["expected_payload_sha256"].as_str().unwrap()
    );

    // null weather fields must be present as JSON null, not omitted
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert!(parsed.get("weather_station").unwrap().is_null());
    assert!(parsed.get("weather_observation_time").unwrap().is_null());
    assert!(parsed.get("weather_value").unwrap().is_null());
    assert_eq!(
        parsed["weather_fallback_reason"].as_str().unwrap(),
        "unreachable"
    );
}

// ── receipt_schema_version helper ──────────────────────────────────

#[test]
fn receipt_schema_version_v4() {
    let vector: serde_json::Value = serde_json::from_str(LOCK_RECEIPT_VECTOR).unwrap();
    let input = lock_receipt_from_json(&vector["input"]);

    let payload = build_receipt_payload(&input);
    assert_eq!(receipt_schema_version(&payload), Some("4".into()));
}

#[test]
fn receipt_schema_version_missing() {
    assert_eq!(receipt_schema_version(r#"{"foo":"bar"}"#), None);
}

#[test]
fn receipt_schema_version_invalid_json() {
    assert_eq!(receipt_schema_version("not json"), None);
}

// ── A1: closed-set discipline on LockReceiptV4 ─────────────────────────

#[test]
fn lock_receipt_rejects_unknown_field() {
    // Build a valid lock receipt JCS payload, then add an unknown field.
    let vector: serde_json::Value = serde_json::from_str(LOCK_RECEIPT_VECTOR).unwrap();
    let input = lock_receipt_from_json(&vector["input"]);
    let payload_jcs = build_receipt_payload(&input);
    let mut payload: serde_json::Value = serde_json::from_str(&payload_jcs).unwrap();
    payload
        .as_object_mut()
        .unwrap()
        .insert("backdoor".into(), serde_json::Value::String("evil".into()));

    let result: Result<LockReceiptV4, _> = serde_json::from_value(payload);
    assert!(
        result.is_err(),
        "lock receipt with unknown field must reject"
    );
    assert!(
        result.unwrap_err().to_string().contains("unknown field"),
        "error must name the unknown field"
    );
}

// ── A1: parse_lock_receipt dispatcher ──────────────────────────────────

#[test]
fn parse_lock_receipt_accepts_v4() {
    let vector: serde_json::Value = serde_json::from_str(LOCK_RECEIPT_VECTOR).unwrap();
    let input = lock_receipt_from_json(&vector["input"]);
    let payload = build_receipt_payload(&input);

    let parsed = parse_lock_receipt(&payload).expect("v4 payload must parse");
    match parsed {
        ParsedLockReceipt::V4(_) => (),
    }
}

#[test]
fn parse_lock_receipt_rejects_unknown_schema_version() {
    let payload = serde_json::json!({
        "schema_version": "99",
        "draw_id": "00000000-0000-4000-8000-000000000000"
    })
    .to_string();

    let result = parse_lock_receipt(&payload);
    match result {
        Err(ParseLockReceiptError::UnknownSchemaVersion(v)) => assert_eq!(v, "99"),
        other => panic!("expected UnknownSchemaVersion(\"99\"), got {:?}", other),
    }
}

#[test]
fn parse_lock_receipt_rejects_missing_schema_version() {
    let payload = r#"{"draw_id":"00000000-0000-4000-8000-000000000000"}"#;
    let result = parse_lock_receipt(payload);
    assert!(matches!(
        result,
        Err(ParseLockReceiptError::MissingSchemaVersion)
    ));
}

#[test]
fn parse_lock_receipt_rejects_unknown_field_via_dispatcher() {
    // The dispatcher inherits deny_unknown_fields from LockReceiptV4.
    let vector: serde_json::Value = serde_json::from_str(LOCK_RECEIPT_VECTOR).unwrap();
    let input = lock_receipt_from_json(&vector["input"]);
    let payload_jcs = build_receipt_payload(&input);
    let mut payload: serde_json::Value = serde_json::from_str(&payload_jcs).unwrap();
    payload
        .as_object_mut()
        .unwrap()
        .insert("backdoor".into(), serde_json::Value::String("evil".into()));

    let result = parse_lock_receipt(&payload.to_string());
    assert!(
        matches!(result, Err(ParseLockReceiptError::PayloadShapeMismatch(_))),
        "expected PayloadShapeMismatch, got: {:?}",
        result
    );
}

// ── A3: weather_station charset validation ─────────────────────────────

#[test]
fn validate_weather_station_accepts_canonical() {
    assert!(validate_weather_station("middle-wallop").is_ok());
    assert!(validate_weather_station("heathrow").is_ok());
    assert!(validate_weather_station("station-42").is_ok());
}

#[test]
fn validate_weather_station_rejects_capitals() {
    assert!(validate_weather_station("Middle-Wallop").is_err());
    assert!(validate_weather_station("HEATHROW").is_err());
}

#[test]
fn validate_weather_station_rejects_spaces() {
    assert!(validate_weather_station("middle wallop").is_err());
}

#[test]
fn validate_weather_station_rejects_special_chars() {
    assert!(validate_weather_station("middle_wallop").is_err());
    assert!(validate_weather_station("middle.wallop").is_err());
    assert!(validate_weather_station("middle/wallop").is_err());
    assert!(validate_weather_station("middle:wallop").is_err());
}

#[test]
fn validate_weather_station_rejects_leading_digit() {
    assert!(validate_weather_station("42-station").is_err());
    assert!(validate_weather_station("-leading-hyphen").is_err());
}

#[test]
fn validate_weather_station_rejects_empty() {
    assert!(validate_weather_station("").is_err());
}

// ── A3: weather_station validation flows through tag validators ────────

#[test]
fn validate_lock_receipt_tags_rejects_bad_weather_station() {
    let vector: serde_json::Value = serde_json::from_str(LOCK_RECEIPT_VECTOR).unwrap();
    let mut input = lock_receipt_from_json(&vector["input"]);
    input.weather_station = "Middle-Wallop".into();

    assert!(validate_lock_receipt_tags(&input).is_err());
}

#[test]
fn validate_execution_receipt_tags_rejects_bad_weather_station() {
    let vector: serde_json::Value = serde_json::from_str(EXECUTION_RECEIPT_VECTOR).unwrap();
    let mut input = execution_receipt_from_json(&vector["input"]);
    input.weather_station = Some("HEATHROW".into());

    assert!(validate_execution_receipt_tags(&input).is_err());
}
