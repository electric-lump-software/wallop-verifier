//! Cross-language regression test for operator key rotation (spec §4.2.4).
//!
//! Loads the same `spec/vectors/key-rotation-bidirectional.json` vector
//! consumed by `wallop_core`'s `protocol_key_rotation_test.exs`. Asserts
//! that this Rust verifier reaches identical verdicts on the four
//! cross-key cases:
//!
//! 1. Historical receipts continue to verify against the original key.
//! 2. New receipts verify against the new active key.
//! 3. Cross-key verifications fail in both directions.
//! 4. The Ed25519 primitive itself has no forward lower bound — temporal
//!    binding is a separate pipeline-level concern.
//!
//! Plus the `key_id` derivation block, which pins the first-4-bytes-of-
//! `SHA-256(public_key)` rule byte-for-byte across implementations.

use crate::protocol::crypto::{key_id, verify_receipt};
use serde_json::Value;

const KEY_ROTATION_VECTOR: &str =
    include_str!("../../vendor/wallop/spec/vectors/key-rotation-bidirectional.json");

fn load_vector() -> Value {
    serde_json::from_str(KEY_ROTATION_VECTOR).expect("key-rotation-bidirectional.json parse")
}

fn run_case(vector: &Value, case_name: &str) -> bool {
    let case_ = vector["verifications"]
        .as_array()
        .expect("verifications is array")
        .iter()
        .find(|c| c["name"].as_str() == Some(case_name))
        .unwrap_or_else(|| panic!("vector case not found: {case_name}"));

    let receipt = &vector["receipts"][case_["receipt"].as_str().unwrap()];
    let key = &vector["keys"][case_["verify_against_key"].as_str().unwrap()];

    let payload =
        hex::decode(receipt["payload_jcs_hex"].as_str().unwrap()).expect("payload_jcs_hex is hex");
    let signature: [u8; 64] = hex::decode(receipt["signature_hex"].as_str().unwrap())
        .expect("signature_hex is hex")
        .try_into()
        .expect("signature is 64 bytes");
    let public_key: [u8; 32] = hex::decode(key["public_key_hex"].as_str().unwrap())
        .expect("public_key_hex is hex")
        .try_into()
        .expect("public_key is 32 bytes");

    verify_receipt(&payload, &signature, &public_key)
}

// --- the four cross-key verification cases ---

#[test]
fn historical_receipt_continues_to_verify_with_original_key() {
    let v = load_vector();
    assert!(run_case(
        &v,
        "historical receipt continues to verify with original key"
    ));
}

#[test]
fn post_rotation_receipt_verifies_with_new_key() {
    let v = load_vector();
    assert!(run_case(&v, "post-rotation receipt verifies with new key"));
}

#[test]
fn wrong_key_pre_rotation_receipt_against_post_rotation_key_fails() {
    let v = load_vector();
    assert!(!run_case(
        &v,
        "wrong-key — pre-rotation receipt against post-rotation key"
    ));
}

#[test]
fn wrong_key_post_rotation_receipt_against_pre_rotation_key_fails() {
    let v = load_vector();
    assert!(!run_case(
        &v,
        "wrong-key — post-rotation receipt against pre-rotation key"
    ));
}

#[test]
fn ed25519_verify_has_no_forward_lower_bound() {
    // The receipt is signed with the post-rotation key but its
    // locked_at predates that key's inserted_at. At the cryptographic
    // primitive level the signature is valid — verify_receipt MUST
    // accept it. The pipeline-level temporal-binding step (spec §4.2.4)
    // is a separate layer that rejects such receipts.
    let v = load_vector();
    assert!(run_case(
        &v,
        "Ed25519 verify itself has no forward lower bound"
    ));
}

// --- key_id_derivation block ---

#[test]
fn every_public_key_hashes_to_its_recorded_key_id() {
    let v = load_vector();
    let checks = v["key_id_derivation"]["checks"]
        .as_array()
        .expect("checks is array");

    for check in checks {
        let public_key: [u8; 32] = hex::decode(check["public_key_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let derived = key_id(&public_key);
        let expected = check["expected_key_id"].as_str().unwrap();
        assert_eq!(
            derived,
            expected,
            "public_key_hex {} hashes to {}, vector records {} — \
             JCS / SHA-256 / hex casing drift",
            check["public_key_hex"].as_str().unwrap(),
            derived,
            expected
        );
    }
}

#[test]
fn key_id_is_exactly_8_lowercase_hex_chars() {
    let v = load_vector();
    let checks = v["key_id_derivation"]["checks"]
        .as_array()
        .expect("checks is array");

    for check in checks {
        let id = check["expected_key_id"].as_str().unwrap();
        assert!(
            id.len() == 8
                && id
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "vector records non-canonical key_id: {id}"
        );
    }
}

#[test]
fn top_level_keys_block_key_id_matches_derivation() {
    // Belt-and-braces: the key_id_derivation.checks[] block already pins
    // the rule, but if a future vector edit decoupled keys.*.key_id from
    // its public_key_hex (typo, copy-paste error), only this assertion
    // would catch it on the Rust side.
    let v = load_vector();
    for (key_name, key) in v["keys"].as_object().unwrap() {
        let public_key: [u8; 32] = hex::decode(key["public_key_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let derived = key_id(&public_key);
        let recorded = key["key_id"].as_str().unwrap();
        assert_eq!(
            derived, recorded,
            "keys.{key_name}: public_key_hex hashes to {derived}, \
             but key_id field records {recorded}"
        );
    }
}

// --- vector self-consistency (parity with the Elixir test) ---

#[test]
fn every_signing_key_referenced_in_receipts_is_defined_in_keys() {
    let v = load_vector();
    let defined: std::collections::HashSet<String> =
        v["keys"].as_object().unwrap().keys().cloned().collect();

    for (receipt_name, receipt) in v["receipts"].as_object().unwrap() {
        let signing_key = receipt["signing_key"].as_str().unwrap();
        assert!(
            defined.contains(signing_key),
            "receipt {receipt_name} references signing_key {signing_key} \
             which is not defined in keys[]"
        );
    }
}

#[test]
fn every_verification_case_names_a_receipt_and_key_that_both_exist() {
    let v = load_vector();
    let defined_receipts: std::collections::HashSet<String> =
        v["receipts"].as_object().unwrap().keys().cloned().collect();
    let defined_keys: std::collections::HashSet<String> =
        v["keys"].as_object().unwrap().keys().cloned().collect();

    for case_ in v["verifications"].as_array().unwrap() {
        let name = case_["name"].as_str().unwrap();
        let receipt = case_["receipt"].as_str().unwrap();
        let key = case_["verify_against_key"].as_str().unwrap();
        let expect = case_["expect"].as_str().unwrap();

        assert!(
            defined_receipts.contains(receipt),
            "verification case {name} references unknown receipt {receipt}"
        );
        assert!(
            defined_keys.contains(key),
            "verification case {name} references unknown key {key}"
        );
        assert!(
            expect == "pass" || expect == "fail",
            "verification case {name} has expect={expect}, must be pass|fail"
        );
    }
}

#[test]
fn the_two_keys_have_distinct_key_ids() {
    let v = load_vector();
    let key_ids: Vec<String> = v["keys"]
        .as_object()
        .unwrap()
        .values()
        .map(|k| k["key_id"].as_str().unwrap().to_string())
        .collect();

    let unique: std::collections::HashSet<&String> = key_ids.iter().collect();
    assert_eq!(
        key_ids.len(),
        unique.len(),
        "rotation vector has duplicate key_ids: {key_ids:?}"
    );
}

#[test]
fn the_two_keys_have_distinct_public_keys() {
    let v = load_vector();
    let pks: Vec<String> = v["keys"]
        .as_object()
        .unwrap()
        .values()
        .map(|k| k["public_key_hex"].as_str().unwrap().to_string())
        .collect();

    let unique: std::collections::HashSet<&String> = pks.iter().collect();
    assert_eq!(
        pks.len(),
        unique.len(),
        "rotation vector has duplicate public keys"
    );
}
