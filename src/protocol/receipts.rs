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
// v3 adds `signing_key_id` to the signed payload (F2 closure — see
// `spec/protocol.md` §4.2). Both v2 and v3 remain verifiable for the
// life of 1.x; historical v2 receipts continue to verify byte-identically.
pub const EXECUTION_SCHEMA_VERSION_V3: &str = "3";

// Allowed values for execution receipt's weather_fallback_reason.
// A fifth value requires a receipt schema bump.
pub const VALID_WEATHER_FALLBACK_REASONS: &[Option<&str>] = &[
    Some("station_down"),
    Some("stale"),
    Some("unreachable"),
    None,
];

#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
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

#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
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

#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceiptV3 {
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
    pub signing_key_id: String,
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

pub fn build_execution_receipt_payload_v3(input: &ExecutionReceiptV3) -> String {
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
        serde_json::Value::String(EXECUTION_SCHEMA_VERSION_V3.into()),
    );
    map.insert("seed", serde_json::Value::String(input.seed.clone()));
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
    validate_weather_station(&payload.weather_station)?;
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
    if let Some(station) = &payload.weather_station {
        validate_weather_station(station)?;
    }
    Ok(())
}

pub fn validate_execution_receipt_tags_v3(payload: &ExecutionReceiptV3) -> Result<(), String> {
    if payload.schema_version != EXECUTION_SCHEMA_VERSION_V3 {
        return Err(format!(
            "unknown execution receipt schema_version: {} (expected {})",
            payload.schema_version, EXECUTION_SCHEMA_VERSION_V3
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
    if let Some(station) = &payload.weather_station {
        validate_weather_station(station)?;
    }
    Ok(())
}

/// Maximum length (in bytes) of a `weather_station` identifier.
///
/// Defence-in-depth against DoS via pathologically long station names in
/// otherwise-valid bundles. The producer side currently uses a single
/// hardcoded value (`"middle-wallop"`, 13 bytes); 64 leaves comfortable
/// headroom for plausible future stations while keeping memory bounded.
/// Producer-side enforcement of the same cap is a follow-up.
pub const WEATHER_STATION_MAX_LEN: usize = 64;

/// Validate `weather_station` against the spec §4.2.1 charset rule.
///
/// MUST match `^[a-z][a-z0-9-]*$` — lowercase ASCII letters, digits, and
/// hyphens, starting with a letter. Free-form station names smuggle
/// arbitrary strings into a signed payload and break cross-language
/// canonicalisation parity. The charset matches the producer-side rule
/// in wallop_core's weather station registry.
///
/// Length-capped at `WEATHER_STATION_MAX_LEN` bytes for verifier
/// defence-in-depth (Colin round-2 review).
pub fn validate_weather_station(station: &str) -> Result<(), String> {
    if station.is_empty() {
        return Err("weather_station is empty".into());
    }
    if station.len() > WEATHER_STATION_MAX_LEN {
        return Err(format!(
            "weather_station exceeds {} bytes",
            WEATHER_STATION_MAX_LEN
        ));
    }
    let mut chars = station.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(format!(
            "weather_station must start with [a-z], got: {:?}",
            station
        ));
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return Err(format!("weather_station has invalid character {:?}", c));
        }
    }
    Ok(())
}

/// Parse a lock receipt JCS payload as `LockReceiptV4`, the only schema
/// version supported in 1.x. Strict — `deny_unknown_fields` rejects any
/// extra field, and an unknown `schema_version` returns
/// `Err(UnknownSchemaVersion)`. **Terminal**: a verifier receiving this
/// error MUST upgrade, MUST NOT retry. Mirrors `parse_execution_receipt`'s
/// dispatcher pattern so future lock receipt schema bumps land cleanly.
#[derive(Debug)]
pub enum ParsedLockReceipt {
    V4(LockReceiptV4),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseLockReceiptError {
    InvalidJson(String),
    MissingSchemaVersion,
    UnknownSchemaVersion(String),
    PayloadShapeMismatch(String),
}

impl std::fmt::Display for ParseLockReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson(e) => write!(f, "invalid lock receipt JSON: {}", e),
            Self::MissingSchemaVersion => write!(f, "missing schema_version"),
            Self::UnknownSchemaVersion(v) => write!(
                f,
                "unknown lock receipt schema_version: {} (expected \"4\")",
                v
            ),
            Self::PayloadShapeMismatch(e) => write!(
                f,
                "payload shape does not match declared schema_version: {}",
                e
            ),
        }
    }
}

impl std::error::Error for ParseLockReceiptError {}

pub fn parse_lock_receipt(payload_jcs: &str) -> Result<ParsedLockReceipt, ParseLockReceiptError> {
    let value: serde_json::Value = serde_json::from_str(payload_jcs)
        .map_err(|e| ParseLockReceiptError::InvalidJson(e.to_string()))?;

    let schema = value
        .get("schema_version")
        .and_then(|v| v.as_str())
        .ok_or(ParseLockReceiptError::MissingSchemaVersion)?;

    match schema {
        "4" => {
            let parsed: LockReceiptV4 = serde_json::from_str(payload_jcs)
                .map_err(|e| ParseLockReceiptError::PayloadShapeMismatch(e.to_string()))?;
            Ok(ParsedLockReceipt::V4(parsed))
        }
        other => Err(ParseLockReceiptError::UnknownSchemaVersion(
            other.to_string(),
        )),
    }
}

/// Parse an execution receipt JCS payload and dispatch to the correct
/// struct based on `schema_version`. Returns a typed enum that callers
/// pattern-match on. Any unknown `schema_version` returns
/// `Err(UnknownSchemaVersion)` — this is **terminal**, not retryable.
/// A verifier receiving this error MUST upgrade, not retry the draw
/// (spec §4.2.1 — older-schema rejection).
#[derive(Debug)]
pub enum ParsedExecutionReceipt {
    V2(ExecutionReceiptV2),
    V3(ExecutionReceiptV3),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseExecutionReceiptError {
    InvalidJson(String),
    MissingSchemaVersion,
    UnknownSchemaVersion(String),
    PayloadShapeMismatch(String),
}

impl std::fmt::Display for ParseExecutionReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson(e) => write!(f, "invalid execution receipt JSON: {}", e),
            Self::MissingSchemaVersion => write!(f, "missing schema_version"),
            Self::UnknownSchemaVersion(v) => write!(
                f,
                "unknown execution receipt schema_version: {} (expected \"2\" or \"3\")",
                v
            ),
            Self::PayloadShapeMismatch(e) => write!(
                f,
                "payload shape does not match declared schema_version: {}",
                e
            ),
        }
    }
}

impl std::error::Error for ParseExecutionReceiptError {}

pub fn parse_execution_receipt(
    payload_jcs: &str,
) -> Result<ParsedExecutionReceipt, ParseExecutionReceiptError> {
    let value: serde_json::Value = serde_json::from_str(payload_jcs)
        .map_err(|e| ParseExecutionReceiptError::InvalidJson(e.to_string()))?;

    let schema = value
        .get("schema_version")
        .and_then(|v| v.as_str())
        .ok_or(ParseExecutionReceiptError::MissingSchemaVersion)?;

    match schema {
        "2" => {
            let parsed: ExecutionReceiptV2 = serde_json::from_str(payload_jcs)
                .map_err(|e| ParseExecutionReceiptError::PayloadShapeMismatch(e.to_string()))?;
            Ok(ParsedExecutionReceipt::V2(parsed))
        }
        "3" => {
            let parsed: ExecutionReceiptV3 = serde_json::from_str(payload_jcs)
                .map_err(|e| ParseExecutionReceiptError::PayloadShapeMismatch(e.to_string()))?;
            Ok(ParsedExecutionReceipt::V3(parsed))
        }
        other => Err(ParseExecutionReceiptError::UnknownSchemaVersion(
            other.to_string(),
        )),
    }
}

#[cfg(test)]
#[path = "receipts_tests.rs"]
mod tests;
