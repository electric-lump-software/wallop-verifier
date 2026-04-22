//! Test fixtures and helpers for constructing valid proof bundles.
//!
//! Exposed publicly because Rust's integration test model requires it —
//! integration tests in `tests/` compile as separate crates that link
//! against the library, so anything they need must be `pub`. The underscore
//! prefix on this module name and the `#[doc(hidden)]` attribute on items
//! together signal "internal, do not depend on this from production code."
//!
//! API stability is NOT guaranteed. Contents may change in any release.

use crate::protocol::receipts::lock_receipt_hash;
use crate::{Entry, compute_seed, compute_seed_drand_only, draw, entry_hash};
use ed25519_dalek::{Signer, SigningKey};

/// Fixed test signing key used by all generated bundles. Deterministic so
/// bundles are reproducible across runs.
#[doc(hidden)]
pub fn test_signing_key() -> SigningKey {
    let secret_bytes: [u8; 32] =
        hex::decode("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60")
            .unwrap()
            .try_into()
            .unwrap();
    SigningKey::from_bytes(&secret_bytes)
}

/// Build a fully-signed, verifiable proof bundle using fixed test keys.
///
/// Returns the bundle as a JSON string suitable for `ProofBundle::from_json`.
/// The bundle is valid end-to-end: entry hash, seed derivation, draw, and
/// both receipt signatures all verify correctly.
///
/// - `entries`: the draw's entry set
/// - `weather`: `Some("1013")` for weather-variant, `None` for drand-only
/// - `winner_count`: how many winners the draw picks
#[doc(hidden)]
pub fn build_valid_bundle(entries: &[Entry], weather: Option<&str>, winner_count: u32) -> String {
    let sk = test_signing_key();
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());

    // Fixed test draw_id — bound into entry_hash; same value in the lock
    // and execution receipts below so signatures verify.
    let draw_id = "22222222-2222-2222-2222-222222222222";
    let (ehash, _) = entry_hash(draw_id, entries);
    let drand = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    let (seed_bytes, _) = match weather {
        Some(w) => compute_seed(&ehash, drand, w),
        None => compute_seed_drand_only(&ehash, drand),
    };
    let seed_hex = hex::encode(seed_bytes);
    let winners = draw(entries, &seed_bytes, winner_count).unwrap();
    let results_array: Vec<String> = winners.iter().map(|w| w.entry_id.clone()).collect();

    // Lock receipt — json! macro uses BTreeMap which sorts keys alphabetically,
    // consistent with JCS expectations.
    let lock_jcs = serde_json::json!({
        "commitment_hash": "00".repeat(32),
        "drand_chain": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
        "drand_round": 12345,
        "draw_id": "22222222-2222-2222-2222-222222222222",
        "entry_hash": &ehash,
        "fair_pick_version": "0.1.0",
        "locked_at": "2026-04-09T12:00:00.000000Z",
        "operator_id": "11111111-1111-1111-1111-111111111111",
        "operator_slug": "acme-prizes",
        "schema_version": "3",
        "sequence": 1,
        "signing_key_id": "deadbeef",
        "wallop_core_version": "0.14.1",
        "weather_station": "middle-wallop",
        "weather_time": "2026-04-09T12:10:00.000000Z",
        "winner_count": winner_count
    })
    .to_string();
    let lock_sig_hex = hex::encode(sk.sign(lock_jcs.as_bytes()).to_bytes());
    let lrh = lock_receipt_hash(&lock_jcs);

    // Execution receipt
    let exec_jcs = serde_json::json!({
        "drand_chain": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
        "drand_randomness": drand,
        "drand_round": 12345,
        "drand_signature": "00".repeat(48),
        "draw_id": "22222222-2222-2222-2222-222222222222",
        "entry_hash": &ehash,
        "executed_at": "2026-04-09T12:15:00.000000Z",
        "execution_schema_version": "1",
        "fair_pick_version": "0.1.0",
        "lock_receipt_hash": &lrh,
        "operator_id": "11111111-1111-1111-1111-111111111111",
        "operator_slug": "acme-prizes",
        "results": &results_array,
        "seed": &seed_hex,
        "sequence": 1,
        "wallop_core_version": "0.14.1",
        "weather_fallback_reason": null,
        "weather_observation_time": if weather.is_some() { serde_json::json!("2026-04-09T12:10:00.000000Z") } else { serde_json::Value::Null },
        "weather_station": if weather.is_some() { serde_json::json!("middle-wallop") } else { serde_json::Value::Null },
        "weather_value": match weather { Some(w) => serde_json::json!(w), None => serde_json::Value::Null }
    }).to_string();
    let exec_sig_hex = hex::encode(sk.sign(exec_jcs.as_bytes()).to_bytes());

    // Bundle JSON
    let mut entropy = serde_json::Map::new();
    entropy.insert("drand_round".into(), serde_json::json!(12345));
    entropy.insert("drand_randomness".into(), serde_json::json!(drand));
    entropy.insert("drand_signature".into(), serde_json::json!("00".repeat(48)));
    entropy.insert(
        "drand_chain_hash".into(),
        serde_json::json!("52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"),
    );
    if let Some(w) = weather {
        entropy.insert("weather_value".into(), serde_json::json!(w));
    }
    // For drand-only, weather_value key is OMITTED entirely (not null)

    serde_json::json!({
        "version": 1,
        "draw_id": "22222222-2222-2222-2222-222222222222",
        "entries": entries.iter().map(|e| serde_json::json!({"uuid": &e.id, "weight": e.weight})).collect::<Vec<_>>(),
        "results": winners.iter().map(|w| serde_json::json!({"entry_id": &w.entry_id, "position": w.position})).collect::<Vec<_>>(),
        "entropy": entropy,
        "lock_receipt": {
            "payload_jcs": &lock_jcs,
            "signature_hex": &lock_sig_hex,
            "operator_public_key_hex": &pk_hex
        },
        "execution_receipt": {
            "payload_jcs": &exec_jcs,
            "signature_hex": &exec_sig_hex,
            "infrastructure_public_key_hex": &pk_hex
        }
    })
    .to_string()
}
