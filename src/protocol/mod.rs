pub mod crypto;
pub mod merkle;
pub mod receipts;

use fair_pick_rs::Entry;
use sha2::{Digest, Sha256};

/// Compute the entry hash for a list of entries.
///
/// Returns `(hex_hash, jcs_string)` where:
/// - `hex_hash` is the 64-char lowercase hex SHA-256 of the JCS bytes
/// - `jcs_string` is the canonical JSON for verification/debugging
pub fn entry_hash(entries: &[Entry]) -> (String, String) {
    let mut sorted: Vec<&Entry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));

    // serde_json without `preserve_order` uses BTreeMap, which sorts keys
    // alphabetically — matching JCS requirements.
    let entries_array: Vec<serde_json::Value> = sorted
        .iter()
        .map(|e| serde_json::json!({"id": &e.id, "weight": e.weight}))
        .collect();
    let jcs = serde_json::to_string(&serde_json::json!({"entries": entries_array})).unwrap();

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
    let jcs = format!(
        r#"{{"drand_randomness":"{}","entry_hash":"{}","weather_value":"{}"}}"#,
        drand_randomness, entry_hash, weather_value
    );

    let seed_bytes: [u8; 32] = Sha256::digest(jcs.as_bytes()).into();
    (seed_bytes, jcs)
}

/// Compute the draw seed from entry hash and drand randomness only (no weather).
///
/// The `weather_value` key is omitted entirely from the JSON, providing
/// implicit domain separation — this function can never produce the same
/// seed as `compute_seed` with the same inputs.
pub fn compute_seed_drand_only(entry_hash: &str, drand_randomness: &str) -> ([u8; 32], String) {
    let jcs = format!(
        r#"{{"drand_randomness":"{}","entry_hash":"{}"}}"#,
        drand_randomness, entry_hash
    );

    let seed_bytes: [u8; 32] = Sha256::digest(jcs.as_bytes()).into();
    (seed_bytes, jcs)
}

#[cfg(test)]
mod tests;
