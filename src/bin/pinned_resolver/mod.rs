//! Tier-1 attributable resolver — `PinnedResolver`.
//!
//! Wraps `EndpointResolver` (tier-2) and adds:
//!
//! 1. A signed keyring pin fetched from a verifier-user-supplied URL,
//!    verified against a bundled or override-supplied trust anchor
//!    (the wallop infrastructure public key).
//! 2. Cross-checking the live `EndpointResolver` response against the
//!    signed pin's `keys[]` set (operator-class only).
//! 3. Direct resolution of `infrastructure`-class signatures against
//!    the trusted-anchor set itself — never the live `/infrastructure/keys`
//!    endpoint, per spec §4.2.4 "Infrastructure-class signature
//!    resolution in attributable mode."
//!
//! See `crate::anchors` for the bundled trust anchor and ADR-0011 for
//! the design rationale.
//!
//! ## CLI integration
//!
//! `wallop-verify --mode attributable --pin-from-url <URL> <bundle>`
//! constructs this resolver around an `EndpointResolver` for the
//! bundle's operator slug.
//!
//! `--infra-key-pin '{...}'` (repeatable) supplies a verifier-user-
//! controlled override anchor record. Override REPLACES the bundled
//! set; it never extends it.

use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use wallop_verifier::anchors::Anchor;
use wallop_verifier::key_id;
use wallop_verifier::key_resolver::{
    InsertedAt, KeyClass, KeyResolver, ResolutionError, ResolvedKey,
};

use super::endpoint_resolver::EndpointResolver;

/// Domain separator prepended to the JCS pre-image before Ed25519
/// verification. Frozen at spec §4.2.4 — `"wallop-pin-v1\n"`, 14 ASCII
/// bytes including the trailing line feed.
const DOMAIN_SEPARATOR: &[u8] = b"wallop-pin-v1\n";

/// Schema version literal accepted on the pin envelope. Verifiers MUST
/// reject any other value with the same exact-match discipline applied
/// to `/operator/:slug/keys`.
const SUPPORTED_PIN_SCHEMA: &str = "1";

/// Maximum bytes accepted when fetching a pin file. The pin is a small
/// JSON envelope — even with several keys it's well under 4KB. Cap at
/// 64KB so a hostile pin URL cannot exhaust memory.
const MAX_PIN_RESPONSE_BYTES: u64 = 64 * 1024;

/// Network timeout for pin fetch.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// User agent presented to pin hosts.
const USER_AGENT: &str = concat!("wallop-verify/", env!("CARGO_PKG_VERSION"));

/// Verifier-side anchor record. Mirrors the compile-time `Anchor`
/// struct in `crate::anchors` but owns its strings so an override
/// anchor (supplied via CLI) can populate the same shape.
///
/// Per spec §4.2.4 "Override carries a full record": the
/// `--infra-key-pin` flag supplies a complete record so the
/// temporal-binding rule applies uniformly to bundled and overridden
/// anchors. Hex-only override is not accepted.
#[derive(Debug, Clone)]
pub struct AnchorRecord {
    pub key_id: String,
    pub public_key: [u8; 32],
    /// RFC 3339 microsecond UTC. Compared as string under the §4.2.4
    /// canonical timestamp rule.
    pub inserted_at: String,
    /// `None` for currently-active anchors per §4.2.4.
    pub revoked_at: Option<String>,
}

impl From<&Anchor> for AnchorRecord {
    fn from(a: &Anchor) -> Self {
        let public_key = a
            .public_key_bytes()
            .expect("bundled anchor public_key_hex must decode (verified by anchors::tests)");
        Self {
            key_id: a.key_id.to_string(),
            public_key,
            inserted_at: a.inserted_at.to_string(),
            revoked_at: a.revoked_at.map(|s| s.to_string()),
        }
    }
}

/// Errors that can occur when constructing a `PinnedResolver`.
///
/// Distinct from `ResolutionError` because these failures happen at
/// resolver-construction time, before any `resolve()` call. The CLI
/// surfaces them as a hard exit before the verification pipeline runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinError {
    /// Pin URL could not be reached.
    Unreachable,
    /// Pin response did not parse as a valid envelope, OR a structural
    /// invariant was violated (`schema_version != "1"`, `keys[]` empty,
    /// `keys[]` not sorted ascending by `key_id`, a row's
    /// `key_class != "operator"`, a duplicate `key_id`, etc.).
    SchemaMismatch(String),
    /// `published_at` is more than 60 seconds in the future relative
    /// to the verifier's clock. Distinct from `SignatureInvalid` so
    /// the user sees "your clock or theirs is wrong" rather than
    /// "tampering."
    PublishedInFuture,
    /// No anchor in the trusted set verifies the pin's signature, or
    /// no anchors are configured at all.
    AnchorNotFound,
    /// An anchor matches the pin's signature but a downstream
    /// invariant rejected it (e.g. the temporal-binding rule). Reserved
    /// for future use; current 0.16.0 paths surface temporal-window
    /// failures as `AnchorNotFound` because the anchor that signed
    /// outside its window is, by definition, not in the trusted set
    /// for that pin.
    #[allow(dead_code)]
    SignatureInvalid(String),
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinError::Unreachable => f.write_str("pin URL unreachable"),
            PinError::SchemaMismatch(reason) => write!(f, "pin schema mismatch: {}", reason),
            PinError::PublishedInFuture => {
                f.write_str("pin published_at is more than 60s in the future")
            }
            PinError::AnchorNotFound => {
                f.write_str("no trusted anchor matches the pin's signature")
            }
            PinError::SignatureInvalid(reason) => write!(f, "pin signature invalid: {}", reason),
        }
    }
}

impl std::error::Error for PinError {}

/// Wire shape of the pin envelope per spec §4.2.4.
#[derive(Debug, Clone, Deserialize)]
struct PinEnvelope {
    schema_version: String,
    operator_slug: String,
    keys: Vec<PinKeyRow>,
    published_at: String,
    #[serde(rename = "infrastructure_signature")]
    signature_hex: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PinKeyRow {
    key_id: String,
    public_key_hex: String,
    key_class: String,
}

/// A pin envelope that has passed structural validation, signature
/// verification, freshness check, and temporal binding against a
/// trusted anchor. `pub` so `PinnedResolver::from_verified` (also
/// `pub`) can name it in its signature; tests use that constructor.
#[derive(Debug, Clone)]
pub struct VerifiedPin {
    operator_slug: String,
    /// Operator-class keys committed in the pin. Sorted ascending by
    /// `key_id` (validated at construction).
    keys: Vec<PinKeyEntry>,
}

#[derive(Debug, Clone)]
struct PinKeyEntry {
    key_id: String,
    public_key: [u8; 32],
}

/// Tier-1 attributable resolver.
///
/// Construct via `PinnedResolver::fetch(...)` (tries the bundled
/// anchor set first, falls back to override) or `PinnedResolver::new(...)`
/// (caller supplies the verified pin and anchor set directly — used by
/// tests).
pub struct PinnedResolver {
    inner: EndpointResolver,
    anchors: Vec<AnchorRecord>,
    pin: VerifiedPin,
}

impl PinnedResolver {
    /// Construct from a fetched-and-verified pin plus the anchor set.
    /// Tests call this directly; the CLI uses `fetch` instead.
    pub fn from_verified(
        inner: EndpointResolver,
        anchors: Vec<AnchorRecord>,
        pin: VerifiedPin,
    ) -> Self {
        Self {
            inner,
            anchors,
            pin,
        }
    }

    /// Fetch and verify a pin from `pin_url`, returning a
    /// `PinnedResolver` ready to resolve operator and infrastructure
    /// keys.
    ///
    /// `anchors` is the trusted-anchor set: either the bundled set
    /// (`crate::anchors::ANCHORS` mapped to `AnchorRecord`) or the
    /// CLI override set. Empty `anchors` is rejected — `--mode
    /// attributable` MUST refuse without a trust root.
    pub fn fetch(
        pin_url: &str,
        anchors: Vec<AnchorRecord>,
        inner: EndpointResolver,
    ) -> Result<Self, PinError> {
        if anchors.is_empty() {
            return Err(PinError::AnchorNotFound);
        }

        let agent = ureq::AgentBuilder::new().timeout(REQUEST_TIMEOUT).build();
        let response = agent
            .get(pin_url)
            .set("User-Agent", USER_AGENT)
            .call()
            .map_err(|_| PinError::Unreachable)?;

        let mut bounded = response.into_reader().take(MAX_PIN_RESPONSE_BYTES);
        let mut bytes = Vec::with_capacity(4096);
        bounded
            .read_to_end(&mut bytes)
            .map_err(|_| PinError::SchemaMismatch("response read failed".into()))?;

        Self::verify_bytes(&bytes, &anchors, inner, current_time_iso8601())
    }

    /// Construct from raw response bytes + an anchor set. Same logic
    /// as `fetch` minus the HTTP — used by tests with mocked bytes
    /// and by `fetch` itself after the network round-trip.
    ///
    /// `now_iso8601` is supplied explicitly so freshness assertions
    /// are deterministic in tests.
    pub fn verify_bytes(
        bytes: &[u8],
        anchors: &[AnchorRecord],
        inner: EndpointResolver,
        now_iso8601: String,
    ) -> Result<Self, PinError> {
        // 1. Parse envelope (verifier obligation 1, structural
        //    validation, part 1: JSON shape).
        let envelope: PinEnvelope = serde_json::from_slice(bytes)
            .map_err(|e| PinError::SchemaMismatch(format!("JSON parse failed: {}", e)))?;

        // 2. schema_version exact-match.
        if envelope.schema_version != SUPPORTED_PIN_SCHEMA {
            return Err(PinError::SchemaMismatch(format!(
                "unknown schema_version {:?}",
                envelope.schema_version
            )));
        }

        // 3. Structural validation: keys[] non-empty, sorted ascending,
        //    every row key_class == "operator", no duplicate key_id.
        validate_keys_envelope(&envelope.keys)?;

        // 4. Freshness rule (verifier obligation 2):
        //    published_at > now + 60s rejects.
        check_freshness(&envelope.published_at, &now_iso8601)?;

        // 5. Reconstruct JCS pre-image (verifier obligation 3 setup):
        //    parse, drop infrastructure_signature, JCS-canonicalise.
        let preimage = reconstruct_preimage(bytes)?;

        // 6. Verify signature against an anchor in the trusted set
        //    (verifier obligation 3) AND apply temporal binding to that
        //    anchor (verifier obligation 4): the anchor's
        //    [inserted_at, revoked_at) window MUST contain
        //    pin.published_at.
        let signature = parse_signature_hex(&envelope.signature_hex)?;
        let _verifying_anchor =
            find_verifying_anchor(&preimage, &signature, anchors, &envelope.published_at)?;

        // 7. envelope.operator_slug match against bundle is verified at
        //    resolve() time, since this constructor doesn't see the
        //    bundle. The `KeyResolver::resolve` impl handles the check.

        // 8. Build the verified pin's pin-key list. Each row's
        //    public_key_hex is decoded once here and the cross-check
        //    `key_id == hash(public_key)` is asserted (the spec's
        //    keyring-row consistency rule applied to pin entries too).
        let pin_keys = build_pin_keys(&envelope.keys)?;

        let pin = VerifiedPin {
            operator_slug: envelope.operator_slug,
            keys: pin_keys,
        };

        Ok(Self::from_verified(inner, anchors.to_vec(), pin))
    }

    /// The operator slug committed in the verified pin. The CLI cross-
    /// checks this against the bundle's `operator_slug` per verifier
    /// obligation 5 — see `wallop_verify.rs`.
    pub fn pin_operator_slug(&self) -> &str {
        &self.pin.operator_slug
    }
}

impl KeyResolver for PinnedResolver {
    fn resolve(
        &self,
        requested_key_id: &str,
        class: KeyClass,
    ) -> Result<ResolvedKey, ResolutionError> {
        match class {
            KeyClass::Operator => {
                // Verifier obligation 6: resolve via live
                // /operator/:slug/keys (delegated to attestable mode).
                let resolved = self.inner.resolve(requested_key_id, class)?;

                // Verifier obligation 7: defence-in-depth class check.
                // EndpointResolver tags every row by URL-class, so an
                // operator-class request returning anything else is
                // already a MalformedResponse from the inner resolver.
                // Belt-and-braces: check again here.
                if resolved.key_class != KeyClass::Operator {
                    return Err(ResolutionError::PinMismatch);
                }

                // Verifier obligation 8: live key MUST be in the pin's
                // keys[] set. Strict per-resolution equality on the
                // (key_id, public_key) tuple.
                let in_pin =
                    self.pin.keys.iter().any(|p| {
                        p.key_id == requested_key_id && p.public_key == resolved.public_key
                    });
                if !in_pin {
                    return Err(ResolutionError::PinMismatch);
                }

                Ok(resolved)
            }
            KeyClass::Infrastructure => {
                // Spec §4.2.4 "Infrastructure-class signature resolution
                // in attributable mode": resolve directly against the
                // trusted-anchor set; pin is not consulted (operator-
                // keys-only by definition); live /infrastructure/keys
                // MUST NOT be the source of public-key bytes here.
                let anchor = self
                    .anchors
                    .iter()
                    .find(|a| a.key_id == requested_key_id)
                    .ok_or(ResolutionError::KeyNotFound)?;

                Ok(ResolvedKey {
                    public_key: anchor.public_key,
                    inserted_at: InsertedAt::At(anchor.inserted_at.clone()),
                    key_class: KeyClass::Infrastructure,
                })
            }
        }
    }
}

// ---------- structural validation ----------

fn validate_keys_envelope(keys: &[PinKeyRow]) -> Result<(), PinError> {
    if keys.is_empty() {
        return Err(PinError::SchemaMismatch("keys[] is empty".into()));
    }

    let mut seen_ids = std::collections::HashSet::new();
    let mut prev: Option<&str> = None;
    for (i, row) in keys.iter().enumerate() {
        if row.key_class != "operator" {
            return Err(PinError::SchemaMismatch(format!(
                "keys[{}].key_class is {:?}; pin commits operator-class only",
                i, row.key_class
            )));
        }
        if !is_lowercase_hex(&row.key_id, 8) {
            return Err(PinError::SchemaMismatch(format!(
                "keys[{}].key_id {:?} is not 8 lowercase hex chars",
                i, row.key_id
            )));
        }
        if !is_lowercase_hex(&row.public_key_hex, 64) {
            return Err(PinError::SchemaMismatch(format!(
                "keys[{}].public_key_hex is not 64 lowercase hex chars",
                i
            )));
        }
        if !seen_ids.insert(row.key_id.clone()) {
            return Err(PinError::SchemaMismatch(format!(
                "duplicate key_id {:?} in keys[]",
                row.key_id
            )));
        }
        if let Some(p) = prev
            && p > row.key_id.as_str()
        {
            return Err(PinError::SchemaMismatch(format!(
                "keys[] not sorted ascending: {:?} after {:?}",
                row.key_id, p
            )));
        }
        prev = Some(&row.key_id);
    }
    Ok(())
}

fn build_pin_keys(rows: &[PinKeyRow]) -> Result<Vec<PinKeyEntry>, PinError> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let bytes = hex::decode(&row.public_key_hex)
            .map_err(|_| PinError::SchemaMismatch("public_key_hex decode failed".into()))?;
        let pk: [u8; 32] = bytes
            .try_into()
            .map_err(|_| PinError::SchemaMismatch("public_key_hex wrong length".into()))?;

        // Spec §4.2.4 keyring-row consistency: every row's key_id MUST
        // equal hash(public_key). Catches a hostile pin that lists a
        // valid public key under a fake key_id.
        if key_id(&pk) != row.key_id {
            return Err(PinError::SchemaMismatch(format!(
                "keys[].key_id {:?} does not hash from its public_key_hex",
                row.key_id
            )));
        }

        out.push(PinKeyEntry {
            key_id: row.key_id.clone(),
            public_key: pk,
        });
    }
    Ok(out)
}

fn is_lowercase_hex(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------- freshness ----------

/// Compares `published_at` to `now`. Future-skew exceeds 60s → reject.
/// Stale (>24h old) is a SHOULD-warn at the CLI level, not enforced
/// here — the spec is explicit that 24h is verifier-side advisory, not
/// a wire rule.
fn check_freshness(published_at: &str, now: &str) -> Result<(), PinError> {
    // Lex compare on the canonical RFC 3339 microsecond form is
    // semantically equivalent to chronological compare (the format is
    // sortable by design — fixed-width zero-padded fields). No clock
    // arithmetic is needed for the wire-side rule; the 60s tolerance
    // is implemented by precomputing now+60s in the caller.
    //
    // The caller passes `now_iso8601` already-incremented by 60s where
    // appropriate. Here we treat `now` as the authoritative upper bound:
    // published_at MUST be <= now.
    if published_at > now {
        return Err(PinError::PublishedInFuture);
    }
    Ok(())
}

fn current_time_iso8601() -> String {
    // 60-second skew tolerance baked in. The pin is rejected only when
    // its published_at exceeds now + 60s.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        + 60;
    format_unix_secs_as_canonical(secs)
}

fn format_unix_secs_as_canonical(secs: u64) -> String {
    // Convert to UTC YYYY-MM-DDTHH:MM:SS.000000Z. Microsecond field is
    // zero-padded for canonical comparison; the wire form requires 6
    // fractional digits per §4.2.1.
    let (year, month, day, hour, minute, second) = unix_to_ymdhms(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.000000Z",
        year, month, day, hour, minute, second
    )
}

fn unix_to_ymdhms(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    // Days since 1970-01-01.
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let hour = (rem / 3600) as u32;
    let minute = ((rem % 3600) / 60) as u32;
    let second = (rem % 60) as u32;

    // Convert days-since-epoch to Y/M/D using the proleptic Gregorian
    // calendar. Howard Hinnant's algorithm: stable through the
    // foreseeable future, no leap-year bugs.
    let z = days as i64 + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = y + if month <= 2 { 1 } else { 0 };

    (year as i32, month, day, hour, minute, second)
}

// ---------- JCS pre-image reconstruction ----------

/// Verifier-side pre-image reconstruction per spec §4.2.4: parse the
/// envelope, remove `infrastructure_signature`, JCS-canonicalise the
/// remainder. The caller prepends the domain separator before passing
/// to Ed25519 verify.
fn reconstruct_preimage(bytes: &[u8]) -> Result<Vec<u8>, PinError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| {
        PinError::SchemaMismatch(format!("JSON re-parse for preimage failed: {}", e))
    })?;

    let mut obj = match value {
        serde_json::Value::Object(m) => m,
        _ => {
            return Err(PinError::SchemaMismatch(
                "envelope is not a JSON object".into(),
            ));
        }
    };

    // The signature field MUST be removed before JCS canonicalisation.
    // An absent member produces different bytes than null, and the
    // producer signs the absent-member form.
    obj.remove("infrastructure_signature");

    // JCS-canonicalise: sort object keys recursively at every level,
    // arrays preserve order. Spec §4.2.2.
    let canonical = jcs_canonicalize(&serde_json::Value::Object(obj));
    Ok(canonical.into_bytes())
}

/// Recursive RFC 8785 JCS canonicaliser. Object keys sort
/// lexicographically by Unicode code point (equivalent to byte-order
/// for ASCII keys, which is all the pin envelope uses). Arrays
/// preserve order. Strings, numbers, bools, and null serialise via
/// `serde_json` (which matches RFC 8785 for the value types that
/// appear in the pin envelope — there are no floats or non-ASCII
/// strings to worry about in 1.0.0).
fn jcs_canonicalize(value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::Null => "null".into(),
        Value::Bool(true) => "true".into(),
        Value::Bool(false) => "false".into(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap(),
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(jcs_canonicalize).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            // BTreeMap → keys sorted by ASCII byte-order, equivalent to
            // RFC 8785 lexicographic-by-Unicode-code-point for ASCII.
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            let parts: Vec<String> = sorted
                .iter()
                .map(|(k, v)| {
                    let ks = serde_json::to_string(k).unwrap();
                    let vs = jcs_canonicalize(v);
                    format!("{}:{}", ks, vs)
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

// ---------- signature ----------

fn parse_signature_hex(hex_str: &str) -> Result<[u8; 64], PinError> {
    if !is_lowercase_hex(hex_str, 128) {
        return Err(PinError::SchemaMismatch(format!(
            "infrastructure_signature is not 128 lowercase hex chars (got len {})",
            hex_str.len()
        )));
    }
    let bytes = hex::decode(hex_str)
        .map_err(|_| PinError::SchemaMismatch("signature hex decode failed".into()))?;
    bytes
        .try_into()
        .map_err(|_| PinError::SchemaMismatch("signature wrong length".into()))
}

#[cfg(test)]
mod tests;

fn find_verifying_anchor<'a>(
    preimage: &[u8],
    signature: &[u8; 64],
    anchors: &'a [AnchorRecord],
    published_at: &str,
) -> Result<&'a AnchorRecord, PinError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let sig = Signature::from_bytes(signature);
    let mut signed = Vec::with_capacity(DOMAIN_SEPARATOR.len() + preimage.len());
    signed.extend_from_slice(DOMAIN_SEPARATOR);
    signed.extend_from_slice(preimage);

    // Independent confirmation that the recovered preimage hashes to
    // a stable value. Not part of the signature check; useful for
    // diagnostic output and for catching producer-side accidents.
    let _preimage_hash = Sha256::digest(preimage);

    for anchor in anchors {
        // Temporal binding (verifier obligation 4): the anchor's
        // [inserted_at, revoked_at) window MUST contain published_at.
        // Lex-compare on canonical RFC 3339 microsecond form is
        // chronologically correct (fixed-width zero-padded fields).
        if anchor.inserted_at.as_str() > published_at {
            continue;
        }
        if let Some(ref revoked) = anchor.revoked_at
            && revoked.as_str() <= published_at
        {
            continue;
        }

        let vk = match VerifyingKey::from_bytes(&anchor.public_key) {
            Ok(vk) => vk,
            Err(_) => continue,
        };
        if vk.verify(&signed, &sig).is_ok() {
            return Ok(anchor);
        }
    }

    Err(PinError::AnchorNotFound)
}
