use fair_pick_rs::{Entry, Winner};
use wasm_bindgen::prelude::*;

use crate::protocol;
use crate::protocol::receipts::{ExecutionReceiptV1, LockReceiptV2};

/// WASM entry point for draw.
#[wasm_bindgen]
pub fn draw_wasm(entries_js: JsValue, seed_js: &[u8], count: u32) -> Result<JsValue, JsError> {
    let entries: Vec<Entry> =
        serde_wasm_bindgen::from_value(entries_js).map_err(|e| JsError::new(&e.to_string()))?;

    let seed: [u8; 32] = seed_js
        .try_into()
        .map_err(|_| JsError::new("seed must be exactly 32 bytes"))?;

    let result = fair_pick_rs::draw(&entries, &seed, count).map_err(|e| JsError::new(&e))?;
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// WASM entry point for entry_hash.
#[wasm_bindgen]
pub fn entry_hash_wasm(entries_js: JsValue) -> Result<JsValue, JsError> {
    let entries: Vec<Entry> =
        serde_wasm_bindgen::from_value(entries_js).map_err(|e| JsError::new(&e.to_string()))?;

    let (hash, jcs) = protocol::entry_hash(&entries);

    let result = serde_json::json!({ "hash": hash, "jcs": jcs });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// WASM entry point for compute_seed.
#[wasm_bindgen]
pub fn compute_seed_wasm(
    entry_hash: &str,
    drand_randomness: &str,
    weather_value: &str,
) -> Result<JsValue, JsError> {
    let (seed_bytes, jcs) = protocol::compute_seed(entry_hash, drand_randomness, weather_value);

    let result = serde_json::json!({
        "seed": hex::encode(seed_bytes),
        "jcs": jcs,
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// WASM entry point for compute_seed (drand-only).
#[wasm_bindgen]
pub fn compute_seed_drand_only_wasm(
    entry_hash: &str,
    drand_randomness: &str,
) -> Result<JsValue, JsError> {
    let (seed_bytes, jcs) = protocol::compute_seed_drand_only(entry_hash, drand_randomness);

    let result = serde_json::json!({
        "seed": hex::encode(seed_bytes),
        "jcs": jcs,
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// WASM entry point for full verification pipeline.
#[wasm_bindgen]
pub fn verify_wasm(
    entries_js: JsValue,
    drand_randomness: &str,
    weather_value: Option<String>,
    count: u32,
    expected_results_js: JsValue,
) -> Result<bool, JsError> {
    let entries: Vec<Entry> =
        serde_wasm_bindgen::from_value(entries_js).map_err(|e| JsError::new(&e.to_string()))?;

    let expected: Vec<Winner> = serde_wasm_bindgen::from_value(expected_results_js)
        .map_err(|e| JsError::new(&e.to_string()))?;

    Ok(crate::verify(
        &entries,
        drand_randomness,
        weather_value.as_deref(),
        count,
        &expected,
    ))
}

/// WASM entry point for verify_receipt.
#[wasm_bindgen]
pub fn verify_receipt_wasm(
    payload_jcs: &str,
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<bool, JsError> {
    let signature_bytes = hex::decode(signature_hex)
        .map_err(|e| JsError::new(&format!("invalid signature hex: {}", e)))?;
    let signature: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| JsError::new("signature must be exactly 64 bytes"))?;

    let key_bytes = hex::decode(public_key_hex)
        .map_err(|e| JsError::new(&format!("invalid public key hex: {}", e)))?;
    let public_key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| JsError::new("public key must be exactly 32 bytes"))?;

    Ok(protocol::crypto::verify_receipt(
        payload_jcs.as_bytes(),
        &signature,
        &public_key,
    ))
}

/// WASM entry point for key_id.
#[wasm_bindgen]
pub fn key_id_wasm(public_key_hex: &str) -> Result<String, JsError> {
    let key_bytes = hex::decode(public_key_hex)
        .map_err(|e| JsError::new(&format!("invalid public key hex: {}", e)))?;
    let public_key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| JsError::new("public key must be exactly 32 bytes"))?;

    Ok(protocol::crypto::key_id(&public_key))
}

/// WASM entry point for build_receipt_payload (lock receipt v2).
#[wasm_bindgen]
pub fn build_receipt_payload_wasm(input_js: JsValue) -> Result<String, JsError> {
    let input: LockReceiptV2 =
        serde_wasm_bindgen::from_value(input_js).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(protocol::receipts::build_receipt_payload(&input))
}

/// WASM entry point for build_execution_receipt_payload.
#[wasm_bindgen]
pub fn build_execution_receipt_payload_wasm(input_js: JsValue) -> Result<String, JsError> {
    let input: ExecutionReceiptV1 =
        serde_wasm_bindgen::from_value(input_js).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(protocol::receipts::build_execution_receipt_payload(&input))
}

/// WASM entry point for lock_receipt_hash.
#[wasm_bindgen]
pub fn lock_receipt_hash_wasm(payload_jcs: &str) -> String {
    protocol::receipts::lock_receipt_hash(payload_jcs)
}

/// WASM entry point for receipt_schema_version.
#[wasm_bindgen]
pub fn receipt_schema_version_wasm(payload_jcs: &str) -> Option<String> {
    protocol::receipts::receipt_schema_version(payload_jcs)
}

/// WASM entry point for merkle_root.
#[wasm_bindgen]
pub fn merkle_root_wasm(leaves_js: JsValue) -> Result<String, JsError> {
    let leaves_strs: Vec<String> =
        serde_wasm_bindgen::from_value(leaves_js).map_err(|e| JsError::new(&e.to_string()))?;

    let leaves_bytes: Vec<Vec<u8>> = leaves_strs.iter().map(|s| s.as_bytes().to_vec()).collect();
    let leaves_refs: Vec<&[u8]> = leaves_bytes.iter().map(|v| v.as_slice()).collect();

    Ok(hex::encode(protocol::merkle::merkle_root(&leaves_refs)))
}

/// WASM entry point for anchor_root.
#[wasm_bindgen]
pub fn anchor_root_wasm(op_root_hex: &str, exec_root_hex: &str) -> Result<String, JsError> {
    let op_bytes = hex::decode(op_root_hex)
        .map_err(|e| JsError::new(&format!("invalid operator root hex: {}", e)))?;
    let op_root: [u8; 32] = op_bytes
        .try_into()
        .map_err(|_| JsError::new("operator root must be exactly 32 bytes"))?;

    let exec_bytes = hex::decode(exec_root_hex)
        .map_err(|e| JsError::new(&format!("invalid execution root hex: {}", e)))?;
    let exec_root: [u8; 32] = exec_bytes
        .try_into()
        .map_err(|_| JsError::new("execution root must be exactly 32 bytes"))?;

    Ok(hex::encode(protocol::merkle::anchor_root(
        &op_root, &exec_root,
    )))
}

/// WASM entry point for verify_full.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn verify_full_wasm(
    lock_receipt_jcs: &str,
    lock_signature_hex: &str,
    operator_public_key_hex: &str,
    execution_receipt_jcs: &str,
    execution_signature_hex: &str,
    infrastructure_public_key_hex: &str,
    entries_js: JsValue,
    count: u32,
) -> Result<bool, JsError> {
    let lock_sig_bytes = hex::decode(lock_signature_hex)
        .map_err(|e| JsError::new(&format!("invalid lock signature hex: {}", e)))?;
    let lock_sig: [u8; 64] = lock_sig_bytes
        .try_into()
        .map_err(|_| JsError::new("lock signature must be exactly 64 bytes"))?;

    let op_key_bytes = hex::decode(operator_public_key_hex)
        .map_err(|e| JsError::new(&format!("invalid operator public key hex: {}", e)))?;
    let op_key: [u8; 32] = op_key_bytes
        .try_into()
        .map_err(|_| JsError::new("operator public key must be exactly 32 bytes"))?;

    let exec_sig_bytes = hex::decode(execution_signature_hex)
        .map_err(|e| JsError::new(&format!("invalid execution signature hex: {}", e)))?;
    let exec_sig: [u8; 64] = exec_sig_bytes
        .try_into()
        .map_err(|_| JsError::new("execution signature must be exactly 64 bytes"))?;

    let infra_key_bytes = hex::decode(infrastructure_public_key_hex)
        .map_err(|e| JsError::new(&format!("invalid infrastructure public key hex: {}", e)))?;
    let infra_key: [u8; 32] = infra_key_bytes
        .try_into()
        .map_err(|_| JsError::new("infrastructure public key must be exactly 32 bytes"))?;

    let entries: Vec<Entry> =
        serde_wasm_bindgen::from_value(entries_js).map_err(|e| JsError::new(&e.to_string()))?;

    crate::verify_full(
        lock_receipt_jcs,
        &lock_sig,
        &op_key,
        execution_receipt_jcs,
        &exec_sig,
        &infra_key,
        &entries,
        count,
    )
    .map_err(|e| JsError::new(&e))
}
