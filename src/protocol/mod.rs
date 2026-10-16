pub mod crypto;
pub mod freq_v1;
pub mod landobs_v1;
pub mod merkle;
pub mod receipts;

/// The start of `refuse_duplicate_keys`'s error for a repeated key.
pub const DUPLICATE_KEY: &str = "duplicate key";

/// `Ok` when `json` is one JSON value with no object, at any depth, that
/// repeats a key, compared after unescaping (so `"a"` and `"\u0061"` are
/// the same key). A repeated key leaves the bytes meaning different things
/// to a first-wins and a last-wins reader, so the record's bytes would not
/// prove one value. `Err` names the first repeated key, or says the bytes
/// are not JSON.
pub fn refuse_duplicate_keys(json: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(json).map_err(|e| format!("not UTF-8: {e}"))?;
    let mut found = None;
    unique_keys(text, &mut found).map_err(|e| match found {
        Some(key) => format!("{DUPLICATE_KEY} {key:?}"),
        None => e.to_string(),
    })
}

/// Walks one JSON value. Scalars are taken as raw text, so a number is
/// never converted (and `1e999` is not refused here). `found` gets the
/// first repeated key.
fn unique_keys(text: &str, found: &mut Option<String>) -> Result<(), serde_json::Error> {
    use serde::de::{DeserializeSeed, Deserializer, Error, MapAccess, SeqAccess, Visitor};
    use serde_json::value::RawValue;

    struct Walk<'f>(&'f mut Option<String>);
    impl<'de> DeserializeSeed<'de> for Walk<'_> {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            d.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Walk<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a JSON object or list")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            let mut seen = std::collections::HashSet::new();
            while let Some(key) = map.next_key::<String>()? {
                let value: &RawValue = map.next_value()?;
                if !seen.insert(key.clone()) {
                    *self.0 = Some(key);
                    return Err(A::Error::custom("duplicate key"));
                }
                unique_keys(value.get(), self.0).map_err(A::Error::custom)?;
            }
            Ok(())
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
            while let Some(item) = seq.next_element::<&RawValue>()? {
                unique_keys(item.get(), self.0).map_err(A::Error::custom)?;
            }
            Ok(())
        }
    }

    match text.trim_start().as_bytes().first() {
        Some(b'{' | b'[') => {
            let mut de = serde_json::Deserializer::from_str(text);
            Walk(found).deserialize(&mut de)?;
            de.end()
        }
        _ => serde_json::from_str::<&RawValue>(text).map(|_| ()),
    }
}

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

/// Compute the draw seed for a grid-frequency draw from entry hash, drand
/// randomness and `freq_value`:
/// `SHA-256(JCS({drand_randomness, entry_hash, freq_value}))`.
///
/// The `freq_value` key keeps it apart from `compute_seed` and
/// `compute_seed_drand_only`, even for the same string.
pub fn compute_seed_freq(
    entry_hash: &str,
    drand_randomness: &str,
    freq_value: &str,
) -> ([u8; 32], String) {
    let mut map = BTreeMap::new();
    map.insert(
        "drand_randomness",
        serde_json::Value::String(drand_randomness.into()),
    );
    map.insert("entry_hash", serde_json::Value::String(entry_hash.into()));
    map.insert("freq_value", serde_json::Value::String(freq_value.into()));
    let jcs = serde_json::to_string(&map).unwrap();

    let seed_bytes: [u8; 32] = Sha256::digest(jcs.as_bytes()).into();
    (seed_bytes, jcs)
}

#[cfg(test)]
mod tests;
