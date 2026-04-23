use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// Pinned algorithm identity tags embedded verbatim into every signed
// receipt. Rotating any of these requires a new tag value plus a schema
// version bump. The verifier rejects any receipt whose tag value does
// not match the expectations here.
pub const JCS_VERSION: &str = "sha256-jcs-v1";
pub const SIGNATURE_ALGORITHM: &str = "ed25519";
pub const ENTROPY_COMPOSITION: &str = "drand-quicknet+openmeteo-v1";
pub const DRAND_SIGNATURE_ALGORITHM: &str = "bls12_381_g2";
pub const MERKLE_ALGORITHM: &str = "sha256-pairwise-v1";

// Current supported schema versions. Verifier rejects anything else.
pub const LOCK_SCHEMA_VERSION: &str = "4";
pub const EXECUTION_SCHEMA_VERSION: &str = "2";

// Allowed values for execution receipt's weather_fallback_reason.
// A fifth value requires a receipt schema bump.
pub const VALID_WEATHER_FALLBACK_REASONS: &[Option<&str>] = &[
    Some("station_down"),
    Some("stale"),
    Some("unreachable"),
    None,
];

#[derive(serde::Deserialize)]
pub struct LockReceiptV4 {
    pub commitment_hash: String,
    pub draw_id: String,
    pub drand_chain: String,
    pub drand_round: u64,
    pub entropy_composition: String,
    pub entry_hash: String,
    pub fair_pick_version: String,
    pub jcs_version: String,
    pub locked_at: String,
    pub operator_id: String,
    pub operator_slug: String,
    pub schema_version: String,
    pub sequence: u64,
    pub signature_algorithm: String,
    pub signing_key_id: String,
    pub wallop_core_version: String,
    pub weather_station: String,
    pub weather_time: String,
    pub winner_count: u64,
}

#[derive(serde::Deserialize)]
pub struct ExecutionReceiptV2 {
    pub drand_chain: String,
    pub drand_randomness: String,
    pub drand_round: u64,
    pub drand_signature: String,
    pub drand_signature_algorithm: String,
    pub draw_id: String,
    pub entropy_composition: String,
    pub entry_hash: String,
    pub executed_at: String,
    pub fair_pick_version: String,
    pub jcs_version: String,
    pub lock_receipt_hash: String,
    pub merkle_algorithm: String,
    pub operator_id: String,
    pub operator_slug: String,
    pub results: Vec<String>,
    pub schema_version: String,
    pub seed: String,
    pub sequence: u64,
    pub signature_algorithm: String,
    pub wallop_core_version: String,
    pub weather_fallback_reason: Option<String>,
    pub weather_observation_time: Option<String>,
    pub weather_station: Option<String>,
    pub weather_value: Option<String>,
}

fn option_to_value(opt: &Option<String>) -> serde_json::Value {
    match opt {
        Some(v) => serde_json::Value::String(v.clone()),
        None => serde_json::Value::Null,
    }
}

pub fn build_receipt_payload(input: &LockReceiptV4) -> String {
    let mut map = BTreeMap::new();
    map.insert(
        "commitment_hash",
        serde_json::Value::String(input.commitment_hash.clone()),
    );
    map.insert(
        "drand_chain",
        serde_json::Value::String(input.drand_chain.clone()),
    );
    map.insert("drand_round", serde_json::json!(input.drand_round));
    map.insert("draw_id", serde_json::Value::String(input.draw_id.clone()));
    map.insert(
        "entropy_composition",
        serde_json::Value::String(ENTROPY_COMPOSITION.into()),
    );
    map.insert(
        "entry_hash",
        serde_json::Value::String(input.entry_hash.clone()),
    );
    map.insert(
        "fair_pick_version",
        serde_json::Value::String(input.fair_pick_version.clone()),
    );
    map.insert("jcs_version", serde_json::Value::String(JCS_VERSION.into()));
    map.insert(
        "locked_at",
        serde_json::Value::String(input.locked_at.clone()),
    );
    map.insert(
        "operator_id",
        serde_json::Value::String(input.operator_id.clone()),
    );
    map.insert(
        "operator_slug",
        serde_json::Value::String(input.operator_slug.clone()),
    );
    map.insert(
        "schema_version",
        serde_json::Value::String(LOCK_SCHEMA_VERSION.into()),
    );
    map.insert("sequence", serde_json::json!(input.sequence));
    map.insert(
        "signature_algorithm",
        serde_json::Value::String(SIGNATURE_ALGORITHM.into()),
    );
    map.insert(
        "signing_key_id",
        serde_json::Value::String(input.signing_key_id.clone()),
    );
    map.insert(
        "wallop_core_version",
        serde_json::Value::String(input.wallop_core_version.clone()),
    );
    map.insert(
        "weather_station",
        serde_json::Value::String(input.weather_station.clone()),
    );
    map.insert(
        "weather_time",
        serde_json::Value::String(input.weather_time.clone()),
    );
    map.insert("winner_count", serde_json::json!(input.winner_count));
    serde_json::to_string(&map).unwrap()
}

pub fn build_execution_receipt_payload(input: &ExecutionReceiptV2) -> String {
    let mut map = BTreeMap::new();
    map.insert(
        "drand_chain",
        serde_json::Value::String(input.drand_chain.clone()),
    );
    map.insert(
        "drand_randomness",
        serde_json::Value::String(input.drand_randomness.clone()),
    );
    map.insert("drand_round", serde_json::json!(input.drand_round));
    map.insert(
        "drand_signature",
        serde_json::Value::String(input.drand_signature.clone()),
    );
    map.insert(
        "drand_signature_algorithm",
        serde_json::Value::String(DRAND_SIGNATURE_ALGORITHM.into()),
    );
    map.insert("draw_id", serde_json::Value::String(input.draw_id.clone()));
    map.insert(
        "entropy_composition",
        serde_json::Value::String(ENTROPY_COMPOSITION.into()),
    );
    map.insert(
        "entry_hash",
        serde_json::Value::String(input.entry_hash.clone()),
    );
    map.insert(
        "executed_at",
        serde_json::Value::String(input.executed_at.clone()),
    );
    map.insert(
        "fair_pick_version",
        serde_json::Value::String(input.fair_pick_version.clone()),
    );
    map.insert("jcs_version", serde_json::Value::String(JCS_VERSION.into()));
    map.insert(
        "lock_receipt_hash",
        serde_json::Value::String(input.lock_receipt_hash.clone()),
    );
    map.insert(
        "merkle_algorithm",
        serde_json::Value::String(MERKLE_ALGORITHM.into()),
    );
    map.insert(
        "operator_id",
        serde_json::Value::String(input.operator_id.clone()),
    );
    map.insert(
        "operator_slug",
        serde_json::Value::String(input.operator_slug.clone()),
    );
    map.insert("results", serde_json::json!(input.results));
    map.insert(
        "schema_version",
        serde_json::Value::String(EXECUTION_SCHEMA_VERSION.into()),
    );
    map.insert("seed", serde_json::Value::String(input.seed.clone()));
    map.insert("sequence", serde_json::json!(input.sequence));
    map.insert(
        "signature_algorithm",
        serde_json::Value::String(SIGNATURE_ALGORITHM.into()),
    );
    map.insert(
        "wallop_core_version",
        serde_json::Value::String(input.wallop_core_version.clone()),
    );
    map.insert(
        "weather_fallback_reason",
        option_to_value(&input.weather_fallback_reason),
    );
    map.insert(
        "weather_observation_time",
        option_to_value(&input.weather_observation_time),
    );
    map.insert("weather_station", option_to_value(&input.weather_station));
    map.insert("weather_value", option_to_value(&input.weather_value));
    serde_json::to_string(&map).unwrap()
}

pub fn lock_receipt_hash(payload_jcs: &str) -> String {
    hex::encode(Sha256::digest(payload_jcs.as_bytes()))
}

pub fn receipt_schema_version(payload_jcs: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(payload_jcs).ok()?;
    parsed.get("schema_version")?.as_str().map(String::from)
}

// Rejection rules. Verifier callers use these to validate a received
// receipt before trusting any of its claims.

pub fn validate_lock_receipt_tags(payload: &LockReceiptV4) -> Result<(), String> {
    if payload.schema_version != LOCK_SCHEMA_VERSION {
        return Err(format!(
            "unknown lock receipt schema_version: {} (expected {})",
            payload.schema_version, LOCK_SCHEMA_VERSION
        ));
    }
    if payload.jcs_version != JCS_VERSION {
        return Err(format!("unknown jcs_version: {}", payload.jcs_version));
    }
    if payload.signature_algorithm != SIGNATURE_ALGORITHM {
        return Err(format!(
            "unknown signature_algorithm: {}",
            payload.signature_algorithm
        ));
    }
    if payload.entropy_composition != ENTROPY_COMPOSITION {
        return Err(format!(
            "unknown entropy_composition: {}",
            payload.entropy_composition
        ));
    }
    Ok(())
}

pub fn validate_execution_receipt_tags(payload: &ExecutionReceiptV2) -> Result<(), String> {
    if payload.schema_version != EXECUTION_SCHEMA_VERSION {
        return Err(format!(
            "unknown execution receipt schema_version: {} (expected {})",
            payload.schema_version, EXECUTION_SCHEMA_VERSION
        ));
    }
    if payload.jcs_version != JCS_VERSION {
        return Err(format!("unknown jcs_version: {}", payload.jcs_version));
    }
    if payload.signature_algorithm != SIGNATURE_ALGORITHM {
        return Err(format!(
            "unknown signature_algorithm: {}",
            payload.signature_algorithm
        ));
    }
    if payload.entropy_composition != ENTROPY_COMPOSITION {
        return Err(format!(
            "unknown entropy_composition: {}",
            payload.entropy_composition
        ));
    }
    if payload.drand_signature_algorithm != DRAND_SIGNATURE_ALGORITHM {
        return Err(format!(
            "unknown drand_signature_algorithm: {}",
            payload.drand_signature_algorithm
        ));
    }
    if payload.merkle_algorithm != MERKLE_ALGORITHM {
        return Err(format!(
            "unknown merkle_algorithm: {}",
            payload.merkle_algorithm
        ));
    }
    let reason_ref = payload.weather_fallback_reason.as_deref();
    if !VALID_WEATHER_FALLBACK_REASONS.contains(&reason_ref) {
        return Err(format!(
            "unknown weather_fallback_reason: {:?}",
            payload.weather_fallback_reason
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "receipts_tests.rs"]
mod tests;
