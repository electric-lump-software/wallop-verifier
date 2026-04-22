pub mod crypto;
pub mod merkle;
pub mod receipts;

use std::collections::BTreeMap;

use fair_pick_rs::Entry;
use sha2::{Digest, Sha256};

/// Compute the entry hash for a draw.
///
/// Canonical form:
///
/// ```text
/// SHA-256(JCS({
///   "draw_id": "<lowercase-hyphenated-uuidv4>",
///   "entries": [{"uuid": "...", "weight": N}, ...]
/// }))
/// ```
///
/// Entries are sorted ascending by `uuid` (binary lex). The input
/// `fair_pick_rs::Entry` struct's `id` field is treated as the public
/// UUID at this boundary.
///
/// # Durable invariant
///
/// Anything this function hashes MUST be derivable from the public
/// ProofBundle bytes alone. Do not add fields here that aren't also
/// present byte-identically in the public bundle — a third-party
/// verifier reading the public bundle must be able to reproduce this
/// exact hash without any operator-only data. `operator_ref` lives on
/// the Entry resource as an operator-private sidecar and is deliberately
/// NOT committed in the hash for this reason.
///
/// Returns `(hex_hash, jcs_string)`:
/// - `hex_hash` is the 64-char lowercase hex SHA-256 of the JCS bytes
/// - `jcs_string` is the canonical JSON for verification / debugging
pub fn entry_hash(draw_id: &str, entries: &[Entry]) -> (String, String) {
    let mut sorted: Vec<&Entry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));

    let entries_array: Vec<serde_json::Value> = sorted
        .iter()
        .map(|e| serde_json::json!({"uuid": &e.id, "weight": e.weight}))
        .collect();

    // BTreeMap sorts top-level keys alphabetically — draw_id < entries.
    let mut top = BTreeMap::new();
    top.insert("draw_id", serde_json::Value::String(draw_id.into()));
    top.insert("entries", serde_json::Value::Array(entries_array));
    let jcs = serde_json::to_string(&top).unwrap();

    let hash = Sha256::digest(jcs.as_bytes());
    let hex_hash = hex::encode(hash);

    (hex_hash, jcs)
}

/// Compute the draw seed from entry hash, drand randomness, and weather value.
///
/// Returns `(seed_bytes, jcs_string)` where:
/// - `seed_bytes` is the raw 32-byte SHA-256 (passed directly to `draw()`)
/// - `jcs_string` is the canonical JSON for the proof record
pub fn compute_seed(
    entry_hash: &str,
    drand_randomness: &str,
    weather_value: &str,
) -> ([u8; 32], String) {
    let mut map = BTreeMap::new();
    map.insert(
        "drand_randomness",
        serde_json::Value::String(drand_randomness.into()),
    );
    map.insert("entry_hash", serde_json::Value::String(entry_hash.into()));
    map.insert(
        "weather_value",
        serde_json::Value::String(weather_value.into()),
    );
    let jcs = serde_json::to_string(&map).unwrap();

    let seed_bytes: [u8; 32] = Sha256::digest(jcs.as_bytes()).into();
    (seed_bytes, jcs)
}

/// Compute the draw seed from entry hash and drand randomness only (no weather).
///
/// The `weather_value` key is omitted entirely from the JSON, providing
/// implicit domain separation — this function can never produce the same
/// seed as `compute_seed` with the same inputs.
pub fn compute_seed_drand_only(entry_hash: &str, drand_randomness: &str) -> ([u8; 32], String) {
    let mut map = BTreeMap::new();
    map.insert(
        "drand_randomness",
        serde_json::Value::String(drand_randomness.into()),
    );
    map.insert("entry_hash", serde_json::Value::String(entry_hash.into()));
    let jcs = serde_json::to_string(&map).unwrap();

    let seed_bytes: [u8; 32] = Sha256::digest(jcs.as_bytes()).into();
    (seed_bytes, jcs)
}

#[cfg(test)]
mod tests;
