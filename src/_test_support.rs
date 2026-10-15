//! Test fixtures and helpers for constructing valid proof bundles.
//!
//! Exposed publicly because Rust's integration test model requires it —
//! integration tests in `tests/` compile as separate crates that link
//! against the library, so anything they need must be `pub`. The underscore
//! prefix on this module name and the `#[doc(hidden)]` attribute on items
//! together signal "internal, do not depend on this from production code."
//!
//! API stability is NOT guaranteed. Contents may change in any release.

use crate::key_resolver::{InsertedAt, KeyClass, KeyResolver, ResolutionError, ResolvedKey};
use crate::protocol::landobs_v1;
use crate::protocol::receipts::lock_receipt_hash;
use crate::verify_steps::format_canonical;
use crate::{Entry, compute_seed, compute_seed_drand_only, draw, entry_hash};
use ed25519_dalek::{Signer, SigningKey};

/// Real quicknet beacons, from
/// https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/<round>.
/// Fixtures use these because every build now verifies the BLS signature.
#[doc(hidden)]
pub const BEACON_ROUND: u64 = 1000;
#[doc(hidden)]
pub const BEACON_SIGNATURE: &str = "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39";
#[doc(hidden)]
pub const BEACON_RANDOMNESS: &str =
    "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd";
#[doc(hidden)]
pub const BEACON_2_ROUND: u64 = 1001;
#[doc(hidden)]
pub const BEACON_2_SIGNATURE: &str = "b33bf3667cbd5a82de3a24b4e0e9fe5513cc1a0e840368c6e31f5fcfa79bea03f73896b25883abf2853d10337fb8fa41";
#[doc(hidden)]
pub const BEACON_2_RANDOMNESS: &str =
    "b0a591ad1b9002cfc372ac6e30abd3da8d3088d4caae026961743474fb94235f";

/// `inserted_at` for the test key as a resolver reports it: before every
/// fixture's `locked_at` and `executed_at`, so temporal binding passes.
#[doc(hidden)]
pub const KEY_INSERTED_AT: &str = "2023-08-01T00:00:00.000000Z";

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
/// - `weather`: `Some("1013")` for weather-variant, `None` for drand-only.
///   Drand-only takes the shape wallop_core emits when the weather fetch
///   falls back: the execution receipt keeps the station, carries
///   `weather_fallback_reason: "unreachable"`, and has null
///   `weather_value` / `weather_observation_time`.
/// - `winner_count`: how many winners the draw picks
#[doc(hidden)]
pub fn build_valid_bundle(entries: &[Entry], weather: Option<&str>, winner_count: u32) -> String {
    let sk = test_signing_key();
    let pk_bytes: [u8; 32] = sk.verifying_key().to_bytes();
    let pk_hex = hex::encode(pk_bytes);
    let kid = crate::protocol::crypto::key_id(&pk_bytes);

    // Fixed test draw_id — bound into entry_hash; same value in the lock
    // and execution receipts below so signatures verify.
    let draw_id = "22222222-2222-2222-2222-222222222222";
    let (ehash, _) = entry_hash(draw_id, entries);
    let drand = BEACON_RANDOMNESS;

    let (seed_bytes, _) = match weather {
        Some(w) => compute_seed(&ehash, drand, w),
        None => compute_seed_drand_only(&ehash, drand),
    };
    let seed_hex = hex::encode(seed_bytes);
    let winners = draw(entries, &seed_bytes, winner_count).unwrap();
    let results_array: Vec<String> = winners.iter().map(|w| w.entry_id.clone()).collect();

    // Lock receipt — json! macro uses BTreeMap which sorts keys alphabetically,
    // consistent with JCS expectations. Field set matches `LockReceiptV4`
    // exactly so the typed parser + tag validators (BundleShape step) pass.
    let lock_jcs = serde_json::json!({
        "commitment_hash": "00".repeat(32),
        "drand_chain": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
        "drand_round": BEACON_ROUND,
        "draw_id": "22222222-2222-2222-2222-222222222222",
        "entropy_composition": "drand-quicknet+openmeteo-v1",
        "entry_hash": &ehash,
        "fair_pick_version": "0.1.0",
        "jcs_version": "sha256-jcs-v1",
        "locked_at": "2023-08-23T15:50:00.000000Z",
        "operator_id": "11111111-1111-1111-1111-111111111111",
        "operator_slug": "acme-prizes",
        "schema_version": "4",
        "sequence": 1,
        "signature_algorithm": "ed25519",
        "signing_key_id": &kid,
        "wallop_core_version": "0.14.1",
        "weather_station": "middle-wallop",
        "weather_time": "2023-08-23T16:00:00.000000Z",
        "winner_count": winner_count
    })
    .to_string();
    let lock_sig_hex = hex::encode(sk.sign(lock_jcs.as_bytes()).to_bytes());
    let lrh = lock_receipt_hash(&lock_jcs);

    // Execution receipt — field set matches `ExecutionReceiptV2` exactly.
    let exec_jcs = serde_json::json!({
        "drand_chain": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
        "drand_randomness": drand,
        "drand_round": BEACON_ROUND,
        "drand_signature": BEACON_SIGNATURE,
        "drand_signature_algorithm": "bls12_381_g2",
        "draw_id": "22222222-2222-2222-2222-222222222222",
        "entropy_composition": "drand-quicknet+openmeteo-v1",
        "entry_hash": &ehash,
        "executed_at": "2023-08-23T16:05:00.000000Z",
        "fair_pick_version": "0.1.0",
        "jcs_version": "sha256-jcs-v1",
        "lock_receipt_hash": &lrh,
        "merkle_algorithm": "sha256-pairwise-v1",
        "operator_id": "11111111-1111-1111-1111-111111111111",
        "operator_slug": "acme-prizes",
        "results": &results_array,
        "schema_version": "2",
        "seed": &seed_hex,
        "sequence": 1,
        "signature_algorithm": "ed25519",
        "wallop_core_version": "0.14.1",
        "weather_fallback_reason": if weather.is_some() { serde_json::Value::Null } else { serde_json::json!("unreachable") },
        "weather_observation_time": if weather.is_some() { serde_json::json!("2023-08-23T16:00:00.000000Z") } else { serde_json::Value::Null },
        "weather_station": "middle-wallop",
        "weather_value": match weather { Some(w) => serde_json::json!(w), None => serde_json::Value::Null }
    }).to_string();
    let exec_sig_hex = hex::encode(sk.sign(exec_jcs.as_bytes()).to_bytes());

    // Bundle JSON
    let mut entropy = serde_json::Map::new();
    entropy.insert("drand_round".into(), serde_json::json!(BEACON_ROUND));
    entropy.insert("drand_randomness".into(), serde_json::json!(drand));
    entropy.insert(
        "drand_signature".into(),
        serde_json::json!(BEACON_SIGNATURE),
    );
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

/// Build a fully-signed drand-only bundle in the shape wallop_core emits
/// when the weather fetch falls back (see the vendored
/// `proof-bundle-drand-only.json` vector): the lock receipt still commits
/// to a weather time and station, the execution receipt repeats the
/// station with `weather_fallback_reason: "unreachable"` and null
/// `weather_value` / `weather_observation_time`, and the bundle's entropy
/// has no `weather_value`. Uses the genuine `BEACON_*`, so every step
/// either passes or is not applicable.
///
/// Returned tuple: `(bundle_json, public_key_hex)`.
#[doc(hidden)]
pub fn build_valid_drand_only_bundle() -> (String, String) {
    let entries = vec![
        Entry {
            id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            weight: 1,
        },
        Entry {
            id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
            weight: 1,
        },
        Entry {
            id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into(),
            weight: 1,
        },
    ];
    let pk_hex = hex::encode(test_signing_key().verifying_key().to_bytes());
    (build_valid_bundle(&entries, None, 2), pk_hex)
}

/// Build a fully-signed, verifiable proof bundle in resolver-driven shape:
/// lock receipt schema_version "5", execution receipt schema_version "4",
/// no inline `public_key_hex` on either bundle wrapper.
///
/// `verify_bundle` (default `BundleEmbeddedResolver`) will reject these
/// bundles with `KeyNotFound` at signature time — the inline keys are
/// gone. `verify_bundle_with` driven by a resolver that returns the right
/// key (e.g. `MockResolver`) will pass them.
///
/// Returned tuple: `(bundle_json, public_key_hex, signing_key_id)`.
/// The signing_key_id is derived from the test signing key (the first
/// 4 bytes of `SHA-256(verifying_key)` — the same scheme as `crypto::key_id`).
#[doc(hidden)]
pub fn build_valid_v5_bundle(
    entries: &[Entry],
    weather: Option<&str>,
    winner_count: u32,
) -> (String, String, String) {
    let sk = test_signing_key();
    let pk_bytes: [u8; 32] = sk.verifying_key().to_bytes();
    let pk_hex = hex::encode(pk_bytes);
    let signing_key_id = crate::protocol::crypto::key_id(&pk_bytes);

    let draw_id = "22222222-2222-2222-2222-222222222222";
    let (ehash, _) = entry_hash(draw_id, entries);
    let drand = BEACON_RANDOMNESS;

    let (seed_bytes, _) = match weather {
        Some(w) => compute_seed(&ehash, drand, w),
        None => compute_seed_drand_only(&ehash, drand),
    };
    let seed_hex = hex::encode(seed_bytes);
    let winners = draw(entries, &seed_bytes, winner_count).unwrap();
    let results_array: Vec<String> = winners.iter().map(|w| w.entry_id.clone()).collect();

    // Lock receipt — byte-identical field set to v4; only `schema_version`
    // changes. The producer-side rule (spec §4.2.4) requires the bundle
    // wrapper to omit `public_key_hex` for v5.
    let lock_jcs = serde_json::json!({
        "commitment_hash": "00".repeat(32),
        "drand_chain": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
        "drand_round": BEACON_ROUND,
        "draw_id": "22222222-2222-2222-2222-222222222222",
        "entropy_composition": "drand-quicknet+openmeteo-v1",
        "entry_hash": &ehash,
        "fair_pick_version": "0.1.0",
        "jcs_version": "sha256-jcs-v1",
        "locked_at": "2023-08-23T15:50:00.000000Z",
        "operator_id": "11111111-1111-1111-1111-111111111111",
        "operator_slug": "acme-prizes",
        "schema_version": "5",
        "sequence": 1,
        "signature_algorithm": "ed25519",
        "signing_key_id": &signing_key_id,
        "wallop_core_version": "0.18.0",
        "weather_station": "middle-wallop",
        "weather_time": "2023-08-23T16:00:00.000000Z",
        "winner_count": winner_count
    })
    .to_string();
    let lock_sig_hex = hex::encode(sk.sign(lock_jcs.as_bytes()).to_bytes());
    let lrh = lock_receipt_hash(&lock_jcs);

    // Execution receipt — byte-identical field set to v3; only
    // `schema_version` changes (and the wrapper omits inline pubkey).
    let exec_jcs = serde_json::json!({
        "drand_chain": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
        "drand_randomness": drand,
        "drand_round": BEACON_ROUND,
        "drand_signature": BEACON_SIGNATURE,
        "drand_signature_algorithm": "bls12_381_g2",
        "draw_id": "22222222-2222-2222-2222-222222222222",
        "entropy_composition": "drand-quicknet+openmeteo-v1",
        "entry_hash": &ehash,
        "executed_at": "2023-08-23T16:05:00.000000Z",
        "fair_pick_version": "0.1.0",
        "jcs_version": "sha256-jcs-v1",
        "lock_receipt_hash": &lrh,
        "merkle_algorithm": "sha256-pairwise-v1",
        "operator_id": "11111111-1111-1111-1111-111111111111",
        "operator_slug": "acme-prizes",
        "results": &results_array,
        "schema_version": "4",
        "seed": &seed_hex,
        "sequence": 1,
        "signature_algorithm": "ed25519",
        "signing_key_id": &signing_key_id,
        "wallop_core_version": "0.18.0",
        "weather_fallback_reason": if weather.is_some() { serde_json::Value::Null } else { serde_json::json!("unreachable") },
        "weather_observation_time": if weather.is_some() { serde_json::json!("2023-08-23T16:00:00.000000Z") } else { serde_json::Value::Null },
        "weather_station": "middle-wallop",
        "weather_value": match weather { Some(w) => serde_json::json!(w), None => serde_json::Value::Null }
    }).to_string();
    let exec_sig_hex = hex::encode(sk.sign(exec_jcs.as_bytes()).to_bytes());

    let mut entropy = serde_json::Map::new();
    entropy.insert("drand_round".into(), serde_json::json!(BEACON_ROUND));
    entropy.insert("drand_randomness".into(), serde_json::json!(drand));
    entropy.insert(
        "drand_signature".into(),
        serde_json::json!(BEACON_SIGNATURE),
    );
    entropy.insert(
        "drand_chain_hash".into(),
        serde_json::json!("52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"),
    );
    if let Some(w) = weather {
        entropy.insert("weather_value".into(), serde_json::json!(w));
    }

    // Bundle wrappers omit `public_key_hex` entirely — the protocol rule
    // for v5/v4 receipts. `BundleShape` rejects v5 + inline pk and v4 +
    // inline pk as downgrade-relabel attempts; tests asserting the
    // resolver-driven path rely on this absence.
    let bundle = serde_json::json!({
        "version": 1,
        "draw_id": "22222222-2222-2222-2222-222222222222",
        "entries": entries.iter().map(|e| serde_json::json!({"uuid": &e.id, "weight": e.weight})).collect::<Vec<_>>(),
        "results": winners.iter().map(|w| serde_json::json!({"entry_id": &w.entry_id, "position": w.position})).collect::<Vec<_>>(),
        "entropy": entropy,
        "lock_receipt": {
            "payload_jcs": &lock_jcs,
            "signature_hex": &lock_sig_hex
        },
        "execution_receipt": {
            "payload_jcs": &exec_jcs,
            "signature_hex": &exec_sig_hex
        }
    })
    .to_string();

    (bundle, pk_hex, signing_key_id)
}

/// A real quicknet beacon published 2026-10-01T20:00:00Z, from
/// https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/32693812.
/// Lock v6 fixtures derive their weather time and lock time from it.
#[doc(hidden)]
pub const BEACON_V6_ROUND: u64 = 32_693_812;
#[doc(hidden)]
pub const BEACON_V6_SIGNATURE: &str = "995ffde0adb77c55a684f709ece0f4cb1effd6284584df0a60a4d16c1a186ce882ba602dfc28acf8139385dfbfe4e637";
#[doc(hidden)]
pub const BEACON_V6_RANDOMNESS: &str =
    "63f5ac51561140f314891a16e6239142924611c313ff4cbf1aeb4dbb3c3ae135";

/// A synthetic, grammar-valid weather value (t 18.4 C, 1021 hPa, 51 %,
/// 41.14 km). Not a real observation.
#[doc(hidden)]
pub const V6_WEATHER_VALUE: &str = "184;1021;51;4114";

/// Every field (signed receipts and the entropy block) a lock v6 /
/// execution v5 fixture varies. Start from `weather()`, `fallback()` or
/// `backup()` and change fields to build negative cases; `build_v6_bundle`
/// signs whatever it is given.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct V6Params {
    pub lock_schema: String,
    pub exec_schema: String,
    pub lock_entropy_composition: String,
    pub exec_entropy_composition: String,
    pub drand_round: u64,
    pub drand_signature: String,
    pub drand_randomness: String,
    pub locked_at: String,
    pub weather_time: String,
    pub executed_at: String,
    pub lock_station: String,
    pub exec_station: Option<String>,
    pub weather_value: Option<String>,
    pub weather_observation_time: Option<String>,
    pub weather_fallback_reason: Option<String>,
}

impl V6Params {
    /// A valid draw that used the primary station's observation. The lock
    /// is one minute before the latest permitted lock time, and execution
    /// is five seconds after the round published.
    #[doc(hidden)]
    pub fn weather() -> Self {
        let wt = landobs_v1::weather_time_for_round(BEACON_V6_ROUND)
            .expect("fixture round has a weather time");
        let latest_lock =
            landobs_v1::latest_lock_at(wt).expect("fixture weather time has a lock time");
        let published = crate::drand::quicknet_round_time(BEACON_V6_ROUND)
            .expect("fixture round has a publish time");
        let weather_time = format_canonical(wt, 0);
        Self {
            lock_schema: "6".into(),
            exec_schema: "5".into(),
            lock_entropy_composition: landobs_v1::ENTROPY_COMPOSITION.into(),
            exec_entropy_composition: landobs_v1::ENTROPY_COMPOSITION.into(),
            drand_round: BEACON_V6_ROUND,
            drand_signature: BEACON_V6_SIGNATURE.into(),
            drand_randomness: BEACON_V6_RANDOMNESS.into(),
            locked_at: format_canonical(latest_lock - 60, 0),
            weather_time: weather_time.clone(),
            executed_at: format_canonical(published + 5, 0),
            lock_station: landobs_v1::PRIMARY_STATION.into(),
            exec_station: Some(landobs_v1::PRIMARY_STATION.into()),
            weather_value: Some(V6_WEATHER_VALUE.into()),
            weather_observation_time: Some(weather_time),
            weather_fallback_reason: None,
        }
    }

    /// A valid draw with no observation by the deadline: drand only.
    #[doc(hidden)]
    pub fn fallback() -> Self {
        Self {
            weather_value: None,
            weather_observation_time: None,
            weather_fallback_reason: Some(landobs_v1::FALLBACK_NO_OBSERVATION.into()),
            ..Self::weather()
        }
    }

    /// A valid draw that used the backup station's observation.
    #[doc(hidden)]
    pub fn backup() -> Self {
        Self {
            exec_station: Some(landobs_v1::STATIONS[1].into()),
            ..Self::weather()
        }
    }
}

/// The three entries every v6 fixture uses.
#[doc(hidden)]
pub fn v6_entries() -> Vec<Entry> {
    [
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    ]
    .iter()
    .map(|id| Entry {
        id: (*id).into(),
        weight: 1,
    })
    .collect()
}

/// Build and sign a resolver-driven bundle (no inline keys) from `p`. The
/// seed and winners are recomputed from `p`, so they always agree with
/// the receipt. Returns `(bundle_json, public_key_hex, signing_key_id)`.
#[doc(hidden)]
pub fn build_v6_bundle(p: &V6Params) -> (String, String, String) {
    let sk = test_signing_key();
    let pk_bytes: [u8; 32] = sk.verifying_key().to_bytes();
    let pk_hex = hex::encode(pk_bytes);
    let kid = crate::protocol::crypto::key_id(&pk_bytes);
    let entries = v6_entries();
    let draw_id = "22222222-2222-2222-2222-222222222222";
    let (ehash, _) = entry_hash(draw_id, &entries);
    let (seed_bytes, _) = match p.weather_value.as_deref() {
        Some(w) => compute_seed(&ehash, &p.drand_randomness, w),
        None => compute_seed_drand_only(&ehash, &p.drand_randomness),
    };
    let winners = draw(&entries, &seed_bytes, 2).unwrap();
    let results: Vec<String> = winners.iter().map(|w| w.entry_id.clone()).collect();
    let chain = crate::drand::QUICKNET_CHAIN_HASH;

    let lock_jcs = serde_json::json!({
        "commitment_hash": &ehash,
        "drand_chain": chain,
        "drand_round": p.drand_round,
        "draw_id": draw_id,
        "entropy_composition": &p.lock_entropy_composition,
        "entry_hash": &ehash,
        "fair_pick_version": "0.2.0",
        "jcs_version": "sha256-jcs-v1",
        "locked_at": &p.locked_at,
        "operator_id": "11111111-1111-1111-1111-111111111111",
        "operator_slug": "acme-prizes",
        "schema_version": &p.lock_schema,
        "sequence": 1,
        "signature_algorithm": "ed25519",
        "signing_key_id": &kid,
        "wallop_core_version": "0.29.0",
        "weather_station": &p.lock_station,
        "weather_time": &p.weather_time,
        "winner_count": 2
    })
    .to_string();
    let lock_sig_hex = hex::encode(sk.sign(lock_jcs.as_bytes()).to_bytes());

    let exec_jcs = serde_json::json!({
        "drand_chain": chain,
        "drand_randomness": &p.drand_randomness,
        "drand_round": p.drand_round,
        "drand_signature": &p.drand_signature,
        "drand_signature_algorithm": "bls12_381_g2",
        "draw_id": draw_id,
        "entropy_composition": &p.exec_entropy_composition,
        "entry_hash": &ehash,
        "executed_at": &p.executed_at,
        "fair_pick_version": "0.2.0",
        "jcs_version": "sha256-jcs-v1",
        "lock_receipt_hash": lock_receipt_hash(&lock_jcs),
        "merkle_algorithm": "sha256-pairwise-v1",
        "operator_id": "11111111-1111-1111-1111-111111111111",
        "operator_slug": "acme-prizes",
        "results": &results,
        "schema_version": &p.exec_schema,
        "seed": hex::encode(seed_bytes),
        "sequence": 1,
        "signature_algorithm": "ed25519",
        "signing_key_id": &kid,
        "wallop_core_version": "0.29.0",
        "weather_fallback_reason": &p.weather_fallback_reason,
        "weather_observation_time": &p.weather_observation_time,
        "weather_station": &p.exec_station,
        "weather_value": &p.weather_value
    })
    .to_string();
    let exec_sig_hex = hex::encode(sk.sign(exec_jcs.as_bytes()).to_bytes());

    let mut entropy = serde_json::Map::new();
    entropy.insert("drand_round".into(), serde_json::json!(p.drand_round));
    entropy.insert(
        "drand_randomness".into(),
        serde_json::json!(&p.drand_randomness),
    );
    entropy.insert(
        "drand_signature".into(),
        serde_json::json!(&p.drand_signature),
    );
    entropy.insert("drand_chain_hash".into(), serde_json::json!(chain));
    if let Some(w) = &p.weather_value {
        entropy.insert("weather_value".into(), serde_json::json!(w));
    }

    let bundle = serde_json::json!({
        "version": 1,
        "draw_id": draw_id,
        "entries": entries.iter().map(|e| serde_json::json!({"uuid": &e.id, "weight": e.weight})).collect::<Vec<_>>(),
        "results": winners.iter().map(|w| serde_json::json!({"entry_id": &w.entry_id, "position": w.position})).collect::<Vec<_>>(),
        "entropy": entropy,
        "lock_receipt": { "payload_jcs": &lock_jcs, "signature_hex": &lock_sig_hex },
        "execution_receipt": { "payload_jcs": &exec_jcs, "signature_hex": &exec_sig_hex }
    })
    .to_string();
    (bundle, pk_hex, kid)
}

/// Every negative case the shared `proof-bundle-v6-negative.json` vector
/// must carry, as `(name, expected_failing_steps)`. Steps are in their
/// snake_case wire form. `v6_negative_bundle` builds each one. Each set
/// is every step that fails: a `weather_time` that is not a whole calendar
/// hour is also not the round's observation hour, and a reason other than
/// `no_observation_by_deadline` is also outside the window's fallback rule.
#[doc(hidden)]
pub const V6_NEGATIVE_CASES: &[(&str, &[&str])] = &[
    (
        "weather_time_not_whole_hour",
        &["bundle_shape", "weather_observation_window"],
    ),
    (
        "weather_time_not_calendar",
        &["bundle_shape", "weather_observation_window"],
    ),
    (
        "weather_time_not_derived_from_round",
        &["weather_observation_window"],
    ),
    (
        "locked_at_after_latest_lock_at",
        &["weather_observation_window"],
    ),
    (
        "round_published_before_lock",
        &["weather_observation_window", "drand_bls_signature"],
    ),
    (
        "lock_station_not_first_in_tag",
        &["bundle_shape", "receipt_field_consistency"],
    ),
    (
        "exec_station_not_in_tag",
        &["bundle_shape", "receipt_field_consistency"],
    ),
    ("backup_named_on_fallback", &["receipt_field_consistency"]),
    (
        "observation_time_not_weather_time",
        &["weather_observation_window"],
    ),
    (
        "partial_fallback_value_null_reason_null",
        &["weather_observation_window"],
    ),
    (
        "partial_fallback_reason_set_value_set",
        &["weather_observation_window"],
    ),
    ("value_grammar_minus_zero", &["bundle_shape"]),
    ("value_grammar_leading_zero", &["bundle_shape"]),
    ("value_grammar_three_parts", &["bundle_shape"]),
    ("value_out_of_bounds", &["bundle_shape"]),
    (
        "v5_reason_in_v6_exec",
        &["bundle_shape", "weather_observation_window"],
    ),
    (
        "wrong_entropy_composition",
        &[
            "bundle_shape",
            "weather_observation_window",
            "receipt_field_consistency",
        ],
    ),
    (
        "wrong_entropy_composition_exec",
        &[
            "bundle_shape",
            "weather_observation_window",
            "receipt_field_consistency",
        ],
    ),
    (
        "lock_v6_with_exec_v4",
        &[
            "bundle_shape",
            "weather_observation_window",
            "receipt_field_consistency",
        ],
    ),
    (
        "lock_v5_with_exec_v5",
        &[
            "bundle_shape",
            "weather_observation_window",
            "receipt_field_consistency",
        ],
    ),
    ("inline_key_on_lock_v6", &["bundle_shape"]),
    ("inline_key_on_exec_v5", &["bundle_shape"]),
    ("executed_before_round_published", &["drand_bls_signature"]),
];

/// The signed bundle for one case in `V6_NEGATIVE_CASES`. Each case changes
/// `V6Params::weather()` (or `fallback()`) and re-signs, so exactly the
/// steps listed in `V6_NEGATIVE_CASES` fail. Returns `(bundle_json, public_key_hex, signing_key_id)`.
#[doc(hidden)]
pub fn v6_negative_bundle(name: &str) -> (String, String, String) {
    let wt = landobs_v1::weather_time_for_round(BEACON_V6_ROUND)
        .expect("fixture round has a weather time");
    let published = crate::drand::quicknet_round_time(BEACON_V6_ROUND)
        .expect("fixture round has a publish time");
    let latest_lock = |weather_time: i64| {
        landobs_v1::latest_lock_at(weather_time).expect("fixture weather time has a lock time")
    };
    let at = |secs: i64| format_canonical(secs, 0);
    let with_weather_time = |s: String| V6Params {
        weather_time: s.clone(),
        weather_observation_time: Some(s),
        ..V6Params::weather()
    };
    let forecast_tag = crate::protocol::receipts::ENTROPY_COMPOSITION.to_string();
    let base = V6Params::weather();
    let p = match name {
        "weather_time_not_whole_hour" => with_weather_time(at(wt + 1800)),
        "weather_time_not_calendar" => {
            with_weather_time(format!("{}:60:00.000000Z", &at(wt - 3600)[..13]))
        }
        "weather_time_not_derived_from_round" => V6Params {
            locked_at: at(latest_lock(wt - 3600) - 60),
            ..with_weather_time(at(wt - 3600))
        },
        "locked_at_after_latest_lock_at" => V6Params {
            locked_at: format_canonical(latest_lock(wt), 1),
            ..base
        },
        "round_published_before_lock" => V6Params {
            locked_at: at(published + 1),
            ..base
        },
        "lock_station_not_first_in_tag" => V6Params {
            lock_station: landobs_v1::STATIONS[1].into(),
            ..base
        },
        "exec_station_not_in_tag" => V6Params {
            exec_station: Some("wmo-03772".into()),
            ..base
        },
        "backup_named_on_fallback" => V6Params {
            exec_station: Some(landobs_v1::STATIONS[1].into()),
            ..V6Params::fallback()
        },
        "observation_time_not_weather_time" => V6Params {
            weather_observation_time: Some(at(wt + 3600)),
            ..base
        },
        "partial_fallback_value_null_reason_null" => V6Params {
            weather_fallback_reason: None,
            ..V6Params::fallback()
        },
        "partial_fallback_reason_set_value_set" => V6Params {
            weather_fallback_reason: Some(landobs_v1::FALLBACK_NO_OBSERVATION.into()),
            ..base
        },
        "value_grammar_minus_zero" => V6Params {
            weather_value: Some("-0;1021;51;4114".into()),
            ..base
        },
        "value_grammar_leading_zero" => V6Params {
            weather_value: Some("0184;1021;51;4114".into()),
            ..base
        },
        "value_grammar_three_parts" => V6Params {
            weather_value: Some("184;1021;51".into()),
            ..base
        },
        "value_out_of_bounds" => V6Params {
            weather_value: Some("601;1021;51;4114".into()),
            ..base
        },
        "v5_reason_in_v6_exec" => V6Params {
            weather_fallback_reason: Some("unreachable".into()),
            ..V6Params::fallback()
        },
        "wrong_entropy_composition" => V6Params {
            lock_entropy_composition: forecast_tag.clone(),
            exec_entropy_composition: forecast_tag,
            ..base
        },
        "wrong_entropy_composition_exec" => V6Params {
            exec_entropy_composition: forecast_tag,
            ..base
        },
        "lock_v6_with_exec_v4" => V6Params {
            exec_schema: "4".into(),
            exec_entropy_composition: forecast_tag,
            ..base
        },
        "lock_v5_with_exec_v5" => V6Params {
            lock_schema: "5".into(),
            lock_entropy_composition: forecast_tag,
            ..base
        },
        "executed_before_round_published" => V6Params {
            executed_at: at(published - 1),
            ..base
        },
        "inline_key_on_lock_v6" | "inline_key_on_exec_v5" => {
            let (json, pk_hex, kid) = build_v6_bundle(&base);
            let mut v: serde_json::Value =
                serde_json::from_str(&json).expect("fixture bundle is JSON");
            let (wrapper, field) = if name == "inline_key_on_lock_v6" {
                ("lock_receipt", "operator_public_key_hex")
            } else {
                ("execution_receipt", "infrastructure_public_key_hex")
            };
            v[wrapper][field] = serde_json::json!(pk_hex.clone());
            return (v.to_string(), pk_hex, kid);
        }
        other => panic!("unknown v6 negative case {other}"),
    };
    build_v6_bundle(&p)
}

/// Apply `edit` to the signed execution receipt payload of bundle `json`
/// and re-sign it with the test signing key, so the execution signature
/// still verifies. Returns the whole bundle as a JSON value.
#[doc(hidden)]
pub fn resign_exec(json: &str, edit: impl FnOnce(&mut serde_json::Value)) -> serde_json::Value {
    let mut bundle: serde_json::Value = serde_json::from_str(json).unwrap();
    let mut exec: serde_json::Value =
        serde_json::from_str(bundle["execution_receipt"]["payload_jcs"].as_str().unwrap()).unwrap();
    edit(&mut exec);
    let exec_jcs = exec.to_string();
    let sig_hex = hex::encode(test_signing_key().sign(exec_jcs.as_bytes()).to_bytes());
    bundle["execution_receipt"]["payload_jcs"] = serde_json::json!(exec_jcs);
    bundle["execution_receipt"]["signature_hex"] = serde_json::json!(sig_hex);
    bundle
}

/// Test-only resolver that maps a fixed `signing_key_id` to a fixed public
/// key, regardless of `KeyClass`. Used by tests asserting the
/// resolver-driven verification path on v5/v4 bundles.
#[doc(hidden)]
pub struct MockResolver {
    pub key_id: String,
    pub public_key: [u8; 32],
    pub inserted_at: InsertedAt,
}

impl MockResolver {
    /// Construct a resolver that returns `public_key` for `key_id` and
    /// `KeyNotFound` for anything else. `inserted_at` defaults to a
    /// fixed canonical timestamp — non-bundle resolvers always commit a
    /// concrete timestamp, never the `Sentinel` variant.
    #[doc(hidden)]
    pub fn new(key_id: impl Into<String>, public_key: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            public_key,
            inserted_at: InsertedAt::At(KEY_INSERTED_AT.into()),
        }
    }
}

impl KeyResolver for MockResolver {
    fn resolve(&self, key_id: &str, key_class: KeyClass) -> Result<ResolvedKey, ResolutionError> {
        if key_id == self.key_id {
            Ok(ResolvedKey {
                public_key: self.public_key,
                inserted_at: self.inserted_at.clone(),
                key_class,
            })
        } else {
            Err(ResolutionError::KeyNotFound)
        }
    }
}

#[cfg(test)]
mod beacon_tests {
    use super::*;
    use crate::drand::{QUICKNET_CHAIN_HASH, verify_drand_round};

    #[test]
    fn fixture_beacons_are_genuine() {
        assert!(
            verify_drand_round(
                QUICKNET_CHAIN_HASH,
                BEACON_ROUND,
                BEACON_SIGNATURE,
                BEACON_RANDOMNESS
            )
            .is_ok()
        );
        assert!(
            verify_drand_round(
                QUICKNET_CHAIN_HASH,
                BEACON_2_ROUND,
                BEACON_2_SIGNATURE,
                BEACON_2_RANDOMNESS
            )
            .is_ok()
        );
    }
}

#[cfg(test)]
mod fixture_tests {
    use super::*;
    use crate::bundle::ProofBundle;
    use crate::protocol::landobs_v1;
    use crate::verify_steps::{VerifierMode, verify_bundle, verify_bundle_with};

    fn entries() -> Vec<Entry> {
        ["a", "b", "c"]
            .iter()
            .map(|id| Entry {
                id: (*id).into(),
                weight: 1,
            })
            .collect()
    }

    #[test]
    fn drand_only_bundle_is_valid() {
        let json = build_valid_bundle(&entries(), None, 2);
        let report = verify_bundle(&ProofBundle::from_json(&json).unwrap());
        assert!(report.passed(), "steps: {:?}", report.steps);
    }

    #[test]
    fn drand_only_v5_bundle_is_valid() {
        let (json, pk_hex, kid) = build_valid_v5_bundle(&entries(), None, 2);
        let pk: [u8; 32] = hex::decode(pk_hex).unwrap().try_into().unwrap();
        let resolver = MockResolver::new(kid, pk);
        let report = verify_bundle_with(
            &ProofBundle::from_json(&json).unwrap(),
            &resolver,
            VerifierMode::Attestable,
        );
        assert!(report.passed(), "steps: {:?}", report.steps);
    }

    #[test]
    fn v6_fixture_beacon_is_genuine() {
        assert!(
            crate::drand::verify_drand_round(
                crate::drand::QUICKNET_CHAIN_HASH,
                BEACON_V6_ROUND,
                BEACON_V6_SIGNATURE,
                BEACON_V6_RANDOMNESS
            )
            .is_ok()
        );
    }

    #[test]
    fn v6_fixture_timestamps_follow_the_schedule() {
        use crate::verify_steps::chrono_parse_canonical;
        let p = V6Params::weather();
        let published = crate::drand::quicknet_round_time(p.drand_round).unwrap();
        let wt = landobs_v1::parse_weather_time(&p.weather_time).unwrap();
        assert_eq!(Some(wt), landobs_v1::weather_time_for_round(p.drand_round));
        let locked = chrono_parse_canonical(&p.locked_at).unwrap().timestamp();
        assert!(locked <= landobs_v1::latest_lock_at(wt).unwrap());
        assert!(locked < published, "the round must publish after the lock");
        let executed = chrono_parse_canonical(&p.executed_at).unwrap().timestamp();
        assert!(executed >= published);
        assert_eq!(
            p.weather_observation_time.as_deref(),
            Some(p.weather_time.as_str())
        );
        assert_eq!(p.weather_time, "2026-10-01T19:00:00.000000Z");
        assert_eq!(p.locked_at, "2026-10-01T18:13:00.000000Z");
        assert_eq!(p.executed_at, "2026-10-01T20:00:05.000000Z");
    }

    #[test]
    fn v6_backup_fixture_uses_wittering() {
        let (json, _, _) = build_v6_bundle(&V6Params::backup());
        let bundle: serde_json::Value = serde_json::from_str(&json).unwrap();
        let lock: serde_json::Value =
            serde_json::from_str(bundle["lock_receipt"]["payload_jcs"].as_str().unwrap()).unwrap();
        let exec: serde_json::Value =
            serde_json::from_str(bundle["execution_receipt"]["payload_jcs"].as_str().unwrap())
                .unwrap();
        assert_eq!(exec["weather_station"], "wmo-03462");
        assert_eq!(lock["weather_station"], "wmo-03749");
        assert!(exec["weather_value"].is_string());
        assert!(exec["weather_observation_time"].is_string());
        assert!(exec["weather_fallback_reason"].is_null());
    }

    #[test]
    fn v6_fixture_receipts_are_signed_and_resolver_driven() {
        let (json, pk_hex, kid) = build_v6_bundle(&V6Params::weather());
        let bundle: serde_json::Value = serde_json::from_str(&json).unwrap();
        let pk: [u8; 32] = hex::decode(&pk_hex).unwrap().try_into().unwrap();
        assert_eq!(crate::protocol::crypto::key_id(&pk), kid);
        for wrapper in ["lock_receipt", "execution_receipt"] {
            let w = &bundle[wrapper];
            assert!(w.get("operator_public_key_hex").is_none());
            assert!(w.get("infrastructure_public_key_hex").is_none());
            let sig: [u8; 64] = hex::decode(w["signature_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            assert!(crate::protocol::crypto::verify_receipt(
                w["payload_jcs"].as_str().unwrap().as_bytes(),
                &sig,
                &pk
            ));
        }
        let lock: serde_json::Value =
            serde_json::from_str(bundle["lock_receipt"]["payload_jcs"].as_str().unwrap()).unwrap();
        assert_eq!(lock["schema_version"], "6");
        assert_eq!(lock["entropy_composition"], landobs_v1::ENTROPY_COMPOSITION);
        assert_eq!(lock["weather_station"], "wmo-03749");
    }

    #[test]
    fn v6_fallback_fixture_has_no_weather() {
        let (json, _, _) = build_v6_bundle(&V6Params::fallback());
        let bundle: serde_json::Value = serde_json::from_str(&json).unwrap();
        let exec: serde_json::Value =
            serde_json::from_str(bundle["execution_receipt"]["payload_jcs"].as_str().unwrap())
                .unwrap();
        assert!(exec["weather_value"].is_null());
        assert!(exec["weather_observation_time"].is_null());
        assert_eq!(
            exec["weather_fallback_reason"],
            "no_observation_by_deadline"
        );
        assert_eq!(exec["weather_station"], "wmo-03749");
        assert!(bundle["entropy"].get("weather_value").is_none());
    }
}
