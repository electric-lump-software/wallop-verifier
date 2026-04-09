use super::*;
use sha2::{Digest, Sha256};

fn sha256_hex(data: &str) -> String {
    hex::encode(Sha256::digest(data.as_bytes()))
}

// ── V-5: lock receipt payload ──────────────────────────────────────

// V-5: lock receipt payload SHA-256 is pinned
#[test]
fn v5_lock_receipt_payload_sha256_pinned() {
    let input = LockReceiptV2 {
        commitment_hash: "abc".into(),
        draw_id: "22222222-2222-2222-2222-222222222222".into(),
        drand_chain: "quicknet-chain-hash".into(),
        drand_round: 12_345,
        entry_hash: "abc".into(),
        fair_pick_version: "0.2.1".into(),
        locked_at: "2026-04-07T12:34:56.789012Z".into(),
        operator_id: "11111111-1111-1111-1111-111111111111".into(),
        operator_slug: "acme-prizes".into(),
        sequence: 42,
        signing_key_id: "deadbeef".into(),
        wallop_core_version: "0.11.2".into(),
        weather_station: "middle-wallop".into(),
        weather_time: "2026-04-07T13:00:00.000000Z".into(),
        winner_count: 3,
    };

    let payload = build_receipt_payload(&input);

    assert_eq!(
        sha256_hex(&payload),
        "cc268c285bd6df5a6acfd56034b4a2a1f191e7e4db41ec7b675a306149f39724"
    );

    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(parsed.as_object().unwrap().len(), 16);
}

// V-5: schema_version is "2"
#[test]
fn v5_lock_receipt_schema_version_is_2() {
    let input = LockReceiptV2 {
        commitment_hash: "abc".into(),
        draw_id: "22222222-2222-2222-2222-222222222222".into(),
        drand_chain: "quicknet-chain-hash".into(),
        drand_round: 12_345,
        entry_hash: "abc".into(),
        fair_pick_version: "0.2.1".into(),
        locked_at: "2026-04-07T12:34:56.789012Z".into(),
        operator_id: "11111111-1111-1111-1111-111111111111".into(),
        operator_slug: "acme-prizes".into(),
        sequence: 42,
        signing_key_id: "deadbeef".into(),
        wallop_core_version: "0.11.2".into(),
        weather_station: "middle-wallop".into(),
        weather_time: "2026-04-07T13:00:00.000000Z".into(),
        winner_count: 3,
    };

    let payload = build_receipt_payload(&input);
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(parsed["schema_version"], "2");
}

// V-5: exact JCS output
#[test]
fn v5_lock_receipt_exact_jcs() {
    let input = LockReceiptV2 {
        commitment_hash: "abc".into(),
        draw_id: "22222222-2222-2222-2222-222222222222".into(),
        drand_chain: "quicknet-chain-hash".into(),
        drand_round: 12_345,
        entry_hash: "abc".into(),
        fair_pick_version: "0.2.1".into(),
        locked_at: "2026-04-07T12:34:56.789012Z".into(),
        operator_id: "11111111-1111-1111-1111-111111111111".into(),
        operator_slug: "acme-prizes".into(),
        sequence: 42,
        signing_key_id: "deadbeef".into(),
        wallop_core_version: "0.11.2".into(),
        weather_station: "middle-wallop".into(),
        weather_time: "2026-04-07T13:00:00.000000Z".into(),
        winner_count: 3,
    };

    let payload = build_receipt_payload(&input);

    let expected = r#"{"commitment_hash":"abc","drand_chain":"quicknet-chain-hash","drand_round":12345,"draw_id":"22222222-2222-2222-2222-222222222222","entry_hash":"abc","fair_pick_version":"0.2.1","locked_at":"2026-04-07T12:34:56.789012Z","operator_id":"11111111-1111-1111-1111-111111111111","operator_slug":"acme-prizes","schema_version":"2","sequence":42,"signing_key_id":"deadbeef","wallop_core_version":"0.11.2","weather_station":"middle-wallop","weather_time":"2026-04-07T13:00:00.000000Z","winner_count":3}"#;

    assert_eq!(payload, expected);
}

// ── V-6: execution receipt payload ─────────────────────────────────

// V-6: execution receipt payload SHA-256 is pinned
#[test]
fn v6_execution_receipt_payload_sha256_pinned() {
    let input = ExecutionReceiptV1 {
        drand_chain: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971".into(),
        drand_randomness: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".into(),
        drand_round: 12_345,
        drand_signature: "a]fake-bls-signature-hex".into(),
        draw_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
        entry_hash: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592".into(),
        executed_at: "2026-04-09T13:01:23.456789Z".into(),
        fair_pick_version: "0.2.1".into(),
        lock_receipt_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .into(),
        operator_id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".into(),
        operator_slug: "acme-prizes".into(),
        results: vec!["ticket-47".into(), "ticket-49".into()],
        seed: "deadbeef00000000000000000000000000000000000000000000000000000000".into(),
        sequence: 42,
        wallop_core_version: "0.12.0".into(),
        weather_fallback_reason: None,
        weather_observation_time: Some("2026-04-09T13:00:00.000000Z".into()),
        weather_station: Some("middle-wallop".into()),
        weather_value: Some("1013".into()),
    };

    let payload = build_execution_receipt_payload(&input);

    assert_eq!(
        sha256_hex(&payload),
        "38f04bb616c97e960f9ab04d565deb805e66e6fdfb1f5ebe8a9cebb4683c8f72"
    );

    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(parsed.as_object().unwrap().len(), 20);
}

// V-6: execution_schema_version is "1"
#[test]
fn v6_execution_receipt_schema_version_is_1() {
    let input = ExecutionReceiptV1 {
        drand_chain: "x".into(),
        drand_randomness: "x".into(),
        drand_round: 1,
        drand_signature: "x".into(),
        draw_id: "x".into(),
        entry_hash: "x".into(),
        executed_at: "x".into(),
        fair_pick_version: "x".into(),
        lock_receipt_hash: "x".into(),
        operator_id: "x".into(),
        operator_slug: "x".into(),
        results: vec![],
        seed: "x".into(),
        sequence: 1,
        wallop_core_version: "x".into(),
        weather_fallback_reason: None,
        weather_observation_time: None,
        weather_station: None,
        weather_value: None,
    };

    let payload = build_execution_receipt_payload(&input);
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(parsed["execution_schema_version"], "1");
}

// V-6: exact JCS output
#[test]
fn v6_execution_receipt_exact_jcs() {
    let input = ExecutionReceiptV1 {
        drand_chain: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971".into(),
        drand_randomness: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".into(),
        drand_round: 12_345,
        drand_signature: "a]fake-bls-signature-hex".into(),
        draw_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
        entry_hash: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592".into(),
        executed_at: "2026-04-09T13:01:23.456789Z".into(),
        fair_pick_version: "0.2.1".into(),
        lock_receipt_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .into(),
        operator_id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".into(),
        operator_slug: "acme-prizes".into(),
        results: vec!["ticket-47".into(), "ticket-49".into()],
        seed: "deadbeef00000000000000000000000000000000000000000000000000000000".into(),
        sequence: 42,
        wallop_core_version: "0.12.0".into(),
        weather_fallback_reason: None,
        weather_observation_time: Some("2026-04-09T13:00:00.000000Z".into()),
        weather_station: Some("middle-wallop".into()),
        weather_value: Some("1013".into()),
    };

    let payload = build_execution_receipt_payload(&input);

    let expected = r#"{"drand_chain":"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971","drand_randomness":"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890","drand_round":12345,"drand_signature":"a]fake-bls-signature-hex","draw_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","entry_hash":"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592","executed_at":"2026-04-09T13:01:23.456789Z","execution_schema_version":"1","fair_pick_version":"0.2.1","lock_receipt_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","operator_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","operator_slug":"acme-prizes","results":["ticket-47","ticket-49"],"seed":"deadbeef00000000000000000000000000000000000000000000000000000000","sequence":42,"wallop_core_version":"0.12.0","weather_fallback_reason":null,"weather_observation_time":"2026-04-09T13:00:00.000000Z","weather_station":"middle-wallop","weather_value":"1013"}"#;

    assert_eq!(payload, expected);
}

// ── V-11: cross-receipt linkage ────────────────────────────────────

// V-11: lock receipt payload → SHA-256 → lock_receipt_hash is pinned
#[test]
fn v11_lock_receipt_hash_pinned() {
    let input = LockReceiptV2 {
        commitment_hash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
        draw_id: "22222222-2222-2222-2222-222222222222".into(),
        drand_chain: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971".into(),
        drand_round: 12_345,
        entry_hash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
        fair_pick_version: "0.2.1".into(),
        locked_at: "2026-04-09T12:00:00.000000Z".into(),
        operator_id: "11111111-1111-1111-1111-111111111111".into(),
        operator_slug: "acme-prizes".into(),
        sequence: 1,
        signing_key_id: "deadbeef".into(),
        wallop_core_version: "0.14.1".into(),
        weather_station: "middle-wallop".into(),
        weather_time: "2026-04-09T12:10:00.000000Z".into(),
        winner_count: 2,
    };

    let payload = build_receipt_payload(&input);
    let hash = lock_receipt_hash(&payload);

    assert_eq!(
        hash,
        "3e05d89b6674e825d2b1badc83ac26d6e59272bc84e5742d5d5bd482bb81468a"
    );
}

// V-11: execution receipt uses the same lock_receipt_hash
#[test]
fn v11_execution_receipt_uses_lock_receipt_hash() {
    let lock_input = LockReceiptV2 {
        commitment_hash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
        draw_id: "22222222-2222-2222-2222-222222222222".into(),
        drand_chain: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971".into(),
        drand_round: 12_345,
        entry_hash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
        fair_pick_version: "0.2.1".into(),
        locked_at: "2026-04-09T12:00:00.000000Z".into(),
        operator_id: "11111111-1111-1111-1111-111111111111".into(),
        operator_slug: "acme-prizes".into(),
        sequence: 1,
        signing_key_id: "deadbeef".into(),
        wallop_core_version: "0.14.1".into(),
        weather_station: "middle-wallop".into(),
        weather_time: "2026-04-09T12:10:00.000000Z".into(),
        winner_count: 2,
    };

    let lock_payload = build_receipt_payload(&lock_input);
    let lock_hash = lock_receipt_hash(&lock_payload);

    let exec_input = ExecutionReceiptV1 {
        drand_chain: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971".into(),
        drand_randomness: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".into(),
        drand_round: 12_345,
        drand_signature: "deadbeef-bls-signature".into(),
        draw_id: "22222222-2222-2222-2222-222222222222".into(),
        entry_hash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
        executed_at: "2026-04-09T12:05:00.000000Z".into(),
        fair_pick_version: "0.2.1".into(),
        lock_receipt_hash: lock_hash.clone(),
        operator_id: "11111111-1111-1111-1111-111111111111".into(),
        operator_slug: "acme-prizes".into(),
        results: vec!["ticket-48".into(), "ticket-47".into()],
        seed: "aaaa000000000000000000000000000000000000000000000000000000000000".into(),
        sequence: 1,
        wallop_core_version: "0.14.1".into(),
        weather_fallback_reason: None,
        weather_observation_time: Some("2026-04-09T12:10:00.000000Z".into()),
        weather_station: Some("middle-wallop".into()),
        weather_value: Some("1013".into()),
    };

    let exec_payload = build_execution_receipt_payload(&exec_input);
    let parsed: serde_json::Value = serde_json::from_str(&exec_payload).unwrap();

    assert_eq!(parsed["lock_receipt_hash"].as_str().unwrap(), lock_hash);
}

// ── V-12: drand-only execution receipt ─────────────────────────────

// V-12: null weather fields are present as JSON null, not omitted
#[test]
fn v12_drand_only_null_weather_fields_present() {
    let input = ExecutionReceiptV1 {
        drand_chain: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971".into(),
        drand_randomness: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".into(),
        drand_round: 12_345,
        drand_signature: "deadbeef-bls-signature".into(),
        draw_id: "22222222-2222-2222-2222-222222222222".into(),
        entry_hash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
        executed_at: "2026-04-09T12:05:00.000000Z".into(),
        fair_pick_version: "0.2.1".into(),
        lock_receipt_hash: "3e05d89b6674e825d2b1badc83ac26d6e59272bc84e5742d5d5bd482bb81468a"
            .into(),
        operator_id: "11111111-1111-1111-1111-111111111111".into(),
        operator_slug: "acme-prizes".into(),
        results: vec!["ticket-48".into(), "ticket-47".into()],
        seed: "aaaa000000000000000000000000000000000000000000000000000000000000".into(),
        sequence: 1,
        wallop_core_version: "0.14.1".into(),
        weather_fallback_reason: Some("met_office_timeout".into()),
        weather_observation_time: None,
        weather_station: None,
        weather_value: None,
    };

    let payload = build_execution_receipt_payload(&input);
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();

    assert!(parsed.get("weather_station").is_some());
    assert!(parsed.get("weather_observation_time").is_some());
    assert!(parsed.get("weather_value").is_some());

    assert!(parsed["weather_station"].is_null());
    assert!(parsed["weather_observation_time"].is_null());
    assert!(parsed["weather_value"].is_null());
    assert_eq!(parsed["weather_fallback_reason"], "met_office_timeout");
}

// V-12: drand-only payload SHA-256 is pinned
#[test]
fn v12_drand_only_payload_sha256_pinned() {
    let input = ExecutionReceiptV1 {
        drand_chain: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971".into(),
        drand_randomness: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".into(),
        drand_round: 12_345,
        drand_signature: "deadbeef-bls-signature".into(),
        draw_id: "22222222-2222-2222-2222-222222222222".into(),
        entry_hash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
        executed_at: "2026-04-09T12:05:00.000000Z".into(),
        fair_pick_version: "0.2.1".into(),
        lock_receipt_hash: "3e05d89b6674e825d2b1badc83ac26d6e59272bc84e5742d5d5bd482bb81468a"
            .into(),
        operator_id: "11111111-1111-1111-1111-111111111111".into(),
        operator_slug: "acme-prizes".into(),
        results: vec!["ticket-48".into(), "ticket-47".into()],
        seed: "aaaa000000000000000000000000000000000000000000000000000000000000".into(),
        sequence: 1,
        wallop_core_version: "0.14.1".into(),
        weather_fallback_reason: Some("met_office_timeout".into()),
        weather_observation_time: None,
        weather_station: None,
        weather_value: None,
    };

    let payload = build_execution_receipt_payload(&input);

    assert_eq!(
        sha256_hex(&payload),
        "3c847e0c73bf65695f66966524029f23c8be3ac6544a6f54e0a03239b4e8ac12"
    );
}

// ── receipt_schema_version helper ──────────────────────────────────

#[test]
fn receipt_schema_version_v2() {
    let input = LockReceiptV2 {
        commitment_hash: "x".into(),
        draw_id: "x".into(),
        drand_chain: "x".into(),
        drand_round: 1,
        entry_hash: "x".into(),
        fair_pick_version: "x".into(),
        locked_at: "x".into(),
        operator_id: "x".into(),
        operator_slug: "x".into(),
        sequence: 1,
        signing_key_id: "x".into(),
        wallop_core_version: "x".into(),
        weather_station: "x".into(),
        weather_time: "x".into(),
        winner_count: 1,
    };
    let payload = build_receipt_payload(&input);
    assert_eq!(receipt_schema_version(&payload), Some("2".into()));
}

#[test]
fn receipt_schema_version_missing() {
    assert_eq!(receipt_schema_version(r#"{"foo":"bar"}"#), None);
}

#[test]
fn receipt_schema_version_invalid_json() {
    assert_eq!(receipt_schema_version("not json"), None);
}
