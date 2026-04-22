use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(serde::Deserialize)]
pub struct LockReceiptV3 {
    pub commitment_hash: String,
    pub draw_id: String,
    pub drand_chain: String,
    pub drand_round: u64,
    pub entry_hash: String,
    pub fair_pick_version: String,
    pub locked_at: String,
    pub operator_id: String,
    pub operator_slug: String,
    pub sequence: u64,
    pub signing_key_id: String,
    pub wallop_core_version: String,
    pub weather_station: String,
    pub weather_time: String,
    pub winner_count: u64,
}

#[derive(serde::Deserialize)]
pub struct ExecutionReceiptV1 {
    pub drand_chain: String,
    pub drand_randomness: String,
    pub drand_round: u64,
    pub drand_signature: String,
    pub draw_id: String,
    pub entry_hash: String,
    pub executed_at: String,
    pub fair_pick_version: String,
    pub lock_receipt_hash: String,
    pub operator_id: String,
    pub operator_slug: String,
    pub results: Vec<String>,
    pub seed: String,
    pub sequence: u64,
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

pub fn build_receipt_payload(input: &LockReceiptV3) -> String {
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
        "entry_hash",
        serde_json::Value::String(input.entry_hash.clone()),
    );
    map.insert(
        "fair_pick_version",
        serde_json::Value::String(input.fair_pick_version.clone()),
    );
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
    map.insert("schema_version", serde_json::Value::String("3".into()));
    map.insert("sequence", serde_json::json!(input.sequence));
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

pub fn build_execution_receipt_payload(input: &ExecutionReceiptV1) -> String {
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
    map.insert("draw_id", serde_json::Value::String(input.draw_id.clone()));
    map.insert(
        "entry_hash",
        serde_json::Value::String(input.entry_hash.clone()),
    );
    map.insert(
        "executed_at",
        serde_json::Value::String(input.executed_at.clone()),
    );
    map.insert(
        "execution_schema_version",
        serde_json::Value::String("1".into()),
    );
    map.insert(
        "fair_pick_version",
        serde_json::Value::String(input.fair_pick_version.clone()),
    );
    map.insert(
        "lock_receipt_hash",
        serde_json::Value::String(input.lock_receipt_hash.clone()),
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
    map.insert("seed", serde_json::Value::String(input.seed.clone()));
    map.insert("sequence", serde_json::json!(input.sequence));
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

#[cfg(test)]
#[path = "receipts_tests.rs"]
mod tests;
