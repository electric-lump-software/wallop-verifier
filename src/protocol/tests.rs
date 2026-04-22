use super::*;

const ENTRY_HASH_VECTORS: &str = include_str!("../../vendor/wallop/spec/vectors/entry-hash.json");
const COMPUTE_SEED_VECTORS: &str =
    include_str!("../../vendor/wallop/spec/vectors/compute-seed.json");
const END_TO_END_VECTOR: &str = include_str!("../../vendor/wallop/spec/vectors/end-to-end.json");
const FAIR_PICK_VECTORS: &str = include_str!("../../vendor/wallop/spec/vectors/fair-pick.json");

fn entries_from_bundle_json(arr: &[serde_json::Value]) -> Vec<Entry> {
    // Bundle / protocol fixtures carry UUIDs in the `uuid` field; map onto
    // the fair_pick_rs::Entry shape where `id` is the canonical public id.
    arr.iter()
        .map(|e| Entry {
            id: e["uuid"].as_str().unwrap().into(),
            weight: e["weight"].as_u64().unwrap() as u32,
        })
        .collect()
}

// --- entry_hash (from entry-hash.json) ---
// Vectors share the same structure: {name, draw_id, entries, expected_jcs, expected_hash}.

fn run_vector_case(vector: &serde_json::Value) {
    let draw_id = vector["draw_id"].as_str().unwrap();
    let entries = entries_from_bundle_json(vector["entries"].as_array().unwrap());
    let (hash, jcs) = entry_hash(draw_id, &entries);

    assert_eq!(jcs, vector["expected_jcs"].as_str().unwrap());
    assert_eq!(hash, vector["expected_hash"].as_str().unwrap());
}

fn vector_by_name<'a>(vectors: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("vector '{}' not found", name))
}

#[test]
fn entry_hash_single_entry() {
    let vectors: serde_json::Value = serde_json::from_str(ENTRY_HASH_VECTORS).unwrap();
    run_vector_case(vector_by_name(&vectors, "single entry"));
}

#[test]
fn entry_hash_operator_ref_ignored() {
    let vectors: serde_json::Value = serde_json::from_str(ENTRY_HASH_VECTORS).unwrap();
    run_vector_case(vector_by_name(
        &vectors,
        "operator_ref does not affect hash",
    ));
}

#[test]
fn entry_hash_two_entries_sorted_by_uuid() {
    let vectors: serde_json::Value = serde_json::from_str(ENTRY_HASH_VECTORS).unwrap();
    run_vector_case(vector_by_name(&vectors, "two entries sorted by uuid"));
}

// The 2^53-1 boundary vector pins JS-interop behaviour (IEEE 754 safe
// integer). It is not directly representable under fair_pick_rs::Entry's
// `weight: u32`, so we verify the byte-level expected_hash against a
// hand-constructed JCS string rather than hashing via entry_hash()/Entry.
#[test]
fn entry_hash_weight_boundary_jcs_bytes() {
    let vectors: serde_json::Value = serde_json::from_str(ENTRY_HASH_VECTORS).unwrap();
    let v = vector_by_name(&vectors, "weight at 2^53-1 boundary");

    let jcs = v["expected_jcs"].as_str().unwrap();
    let computed = hex::encode(Sha256::digest(jcs.as_bytes()));
    assert_eq!(computed, v["expected_hash"].as_str().unwrap());
}

#[test]
fn entry_hash_different_draw_id_different_hash() {
    let vectors: serde_json::Value = serde_json::from_str(ENTRY_HASH_VECTORS).unwrap();
    run_vector_case(vector_by_name(&vectors, "same entries different draw_id"));

    // Cross-check: same entries under two different draw_ids MUST produce
    // different hashes. Pins the draw_id binding property.
    let v_base = vector_by_name(&vectors, "single entry");
    let v_other = vector_by_name(&vectors, "same entries different draw_id");
    assert_ne!(
        v_base["expected_hash"].as_str().unwrap(),
        v_other["expected_hash"].as_str().unwrap()
    );
}

#[test]
fn entry_hash_sorts_by_uuid_regardless_of_input_order() {
    let draw_id = "11111111-1111-4111-8111-111111111111";
    let uuid_a = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let uuid_z = "ffffffff-ffff-4fff-8fff-ffffffffffff";

    let entries_a = vec![
        Entry {
            id: uuid_z.into(),
            weight: 2,
        },
        Entry {
            id: uuid_a.into(),
            weight: 1,
        },
    ];
    let entries_b = vec![
        Entry {
            id: uuid_a.into(),
            weight: 1,
        },
        Entry {
            id: uuid_z.into(),
            weight: 2,
        },
    ];
    assert_eq!(
        entry_hash(draw_id, &entries_a),
        entry_hash(draw_id, &entries_b)
    );
}

// --- compute_seed (from compute-seed.json) ---

#[test]
fn compute_seed_drand_plus_weather() {
    let vectors: serde_json::Value = serde_json::from_str(COMPUTE_SEED_VECTORS).unwrap();
    let v = &vectors["vectors"][0];

    let entry_hash_val = v["entry_hash"].as_str().unwrap();
    let drand = v["drand_randomness"].as_str().unwrap();
    let weather = v["weather_value"].as_str().unwrap();

    let (seed_bytes, seed_json) = compute_seed(entry_hash_val, drand, weather);

    assert_eq!(seed_json, v["expected_jcs"].as_str().unwrap());
    assert_eq!(seed_bytes.len(), 32);
    assert_eq!(
        hex::encode(seed_bytes),
        v["expected_seed_hex"].as_str().unwrap()
    );
}

#[test]
fn compute_seed_drand_only_from_vector() {
    let vectors: serde_json::Value = serde_json::from_str(COMPUTE_SEED_VECTORS).unwrap();
    let v = &vectors["vectors"][1];

    let entry_hash_val = v["entry_hash"].as_str().unwrap();
    let drand = v["drand_randomness"].as_str().unwrap();

    let (seed_bytes, seed_json) = compute_seed_drand_only(entry_hash_val, drand);

    assert_eq!(seed_bytes.len(), 32);
    assert_eq!(
        hex::encode(seed_bytes),
        v["expected_seed_hex"].as_str().unwrap()
    );

    // Verify weather key is omitted, not null
    assert!(!seed_json.contains("weather"));
}

#[test]
fn compute_seed_jcs_sorts_keys_alphabetically() {
    let (_, json) = compute_seed("zzz_entry", "aaa_drand", "mmm_weather");
    assert_eq!(
        json,
        r#"{"drand_randomness":"aaa_drand","entry_hash":"zzz_entry","weather_value":"mmm_weather"}"#
    );
}

#[test]
fn drand_only_seed_differs_from_weather_seed() {
    let vectors: serde_json::Value = serde_json::from_str(COMPUTE_SEED_VECTORS).unwrap();
    let v0 = &vectors["vectors"][0];
    let v1 = &vectors["vectors"][1];

    // Same entry_hash and drand, but one has weather and one doesn't
    assert_eq!(v0["entry_hash"], v1["entry_hash"]);
    assert_eq!(v0["drand_randomness"], v1["drand_randomness"]);
    assert_ne!(
        v0["expected_seed_hex"].as_str().unwrap(),
        v1["expected_seed_hex"].as_str().unwrap()
    );
}

// --- end-to-end (from end-to-end.json) ---

#[test]
fn end_to_end_pipeline() {
    let vector: serde_json::Value = serde_json::from_str(END_TO_END_VECTOR).unwrap();
    let input = &vector["input"];
    let expected = &vector["expected"];

    let draw_id = input["draw_id"].as_str().unwrap();
    let entries = entries_from_bundle_json(input["entries"].as_array().unwrap());
    let drand = input["drand_randomness"].as_str().unwrap();
    let weather = input["weather_value"].as_str().unwrap();
    let count = input["winner_count"].as_u64().unwrap() as u32;

    let (ehash, _jcs) = entry_hash(draw_id, &entries);
    let (seed_bytes, _json) = compute_seed(&ehash, drand, weather);
    let result = fair_pick_rs::draw(&entries, &seed_bytes, count).unwrap();

    assert_eq!(ehash, expected["entry_hash"].as_str().unwrap());
    assert_eq!(
        hex::encode(seed_bytes),
        expected["seed_hex"].as_str().unwrap()
    );

    let expected_winners: Vec<&str> = expected["winners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let actual_winners: Vec<&str> = result.iter().map(|w| w.entry_id.as_str()).collect();
    assert_eq!(actual_winners, expected_winners);
}

// --- vector supply-chain integrity: seed_note → seed_hex cross-check ---

#[test]
fn fair_pick_vectors_seed_note_matches_seed_hex() {
    let vectors: serde_json::Value = serde_json::from_str(FAIR_PICK_VECTORS).unwrap();

    for v in vectors["vectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        if let Some(note) = v.get("seed_note").and_then(|n| n.as_str()) {
            // seed_note is SHA-256("inner-string") — extract and hash the inner string
            let inner = note
                .strip_prefix("SHA-256(\"")
                .and_then(|s| s.strip_suffix("\")"))
                .unwrap_or_else(|| panic!("malformed seed_note in vector '{name}': {note}"));

            let computed = hex::encode(Sha256::digest(inner.as_bytes()));
            let expected = v["seed_hex"].as_str().unwrap();

            assert_eq!(
                computed, expected,
                "seed_note cross-check failed for vector '{name}'"
            );
        }
    }
}

// --- large-pool fair-pick vectors (from fair-pick.json) ---
// fair-pick.json is authored around fair_pick_rs::Entry shape directly
// ({id, weight}), independent of the protocol entry_hash canonical form.

fn fair_pick_entries_from_json(arr: &[serde_json::Value]) -> Vec<Entry> {
    arr.iter()
        .map(|e| Entry {
            id: e["id"].as_str().unwrap().into(),
            weight: e["weight"].as_u64().unwrap() as u32,
        })
        .collect()
}

#[test]
fn fair_pick_large_pool_500_mixed_weights() {
    let vectors: serde_json::Value = serde_json::from_str(FAIR_PICK_VECTORS).unwrap();
    let v = &vectors["vectors"][4];

    let entries = fair_pick_entries_from_json(v["entries"].as_array().unwrap());
    let seed_hex = v["seed_hex"].as_str().unwrap();
    let seed: [u8; 32] = hex::decode(seed_hex).unwrap().try_into().unwrap();
    let count = v["winner_count"].as_u64().unwrap() as u32;

    let result = fair_pick_rs::draw(&entries, &seed, count).unwrap();
    let actual: Vec<&str> = result.iter().map(|w| w.entry_id.as_str()).collect();
    let expected: Vec<&str> = v["expected_winners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    assert_eq!(actual, expected);
}

#[test]
fn fair_pick_large_pool_1000_ten_winners() {
    let vectors: serde_json::Value = serde_json::from_str(FAIR_PICK_VECTORS).unwrap();
    let v = &vectors["vectors"][5];

    let entries = fair_pick_entries_from_json(v["entries"].as_array().unwrap());
    let seed_hex = v["seed_hex"].as_str().unwrap();
    let seed: [u8; 32] = hex::decode(seed_hex).unwrap().try_into().unwrap();
    let count = v["winner_count"].as_u64().unwrap() as u32;

    let result = fair_pick_rs::draw(&entries, &seed, count).unwrap();
    let actual: Vec<&str> = result.iter().map(|w| w.entry_id.as_str()).collect();
    let expected: Vec<&str> = v["expected_winners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    assert_eq!(actual, expected);
}
