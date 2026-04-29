//! Tier-2 (attestable) HTTP-backed `KeyResolver` for the CLI binary.
//!
//! Lives in the binary tree because it needs `ureq` (HTTP + TLS) which
//! the verifier crate proper deliberately keeps out of its dependency
//! tree — that crate compiles to WASM and ships to crates.io without
//! pulling in TLS or async runtimes.
//!
//! `EndpointResolver` calls into the wallop-side endpoints documented in
//! spec §4.2.4:
//!
//! - `GET <base>/operator/<slug>/keys` for operator keys
//! - `GET <base>/infrastructure/keys` for infrastructure keys
//!
//! Both return the same JSON shape:
//!
//! ```json
//! {
//!   "schema_version": "1",
//!   "keys": [
//!     {
//!       "key_id": "<8 lowercase hex>",
//!       "public_key_hex": "<64 lowercase hex>",
//!       "inserted_at": "<canonical RFC 3339>",
//!       "key_class": "operator" | "infrastructure"
//!     }
//!   ]
//! }
//! ```
//!
//! The resolver fetches each class once per run and caches the response
//! in-process, so a verification that needs both an operator key and an
//! infra key issues at most two HTTP requests.

use serde::Deserialize;
use std::collections::HashMap;
use std::io::Read;
use std::sync::Mutex;
use std::time::Duration;

use wallop_verifier::key_id;
use wallop_verifier::key_resolver::{
    InsertedAt, KeyClass, KeyResolver, ResolutionError, ResolvedKey,
};

/// Wire-shape version pinned exactly per spec §4.2.4. Verifiers MUST
/// reject any other value terminally — no semver coercion, no prefix
/// matching, no implicit forward compatibility. A future shape bump is
/// a coordinated wallop_verifier release; the new value is a different
/// exact match.
const SUPPORTED_KEYS_RESPONSE_SCHEMA: &str = "1";

/// Default request timeout. Conservative — tier-2 calls are made once
/// per verification per class against a public endpoint that should
/// respond in well under a second when healthy.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Hard cap on a single response body. Keys-list payloads are tiny
/// (kilobytes for a healthy operator); 1 MiB is two orders of
/// magnitude beyond any plausible legitimate response. Defends the
/// verifier against a misbehaving / hostile endpoint shipping a
/// pathologically large body that would OOM the process.
const MAX_RESPONSE_BYTES: u64 = 1_048_576;

/// Hard cap on the number of keys per response. A keyring with
/// thousands of entries is a producer-side bug. Defence-in-depth in
/// addition to the byte cap above; produces a more useful error than
/// "we ran out of memory parsing JSON."
const MAX_KEYS_PER_RESPONSE: usize = 10_000;

/// User-Agent header on outgoing requests. Operator-side rate limiting
/// and abuse triage are much harder when verifiers' UA is anonymous.
const USER_AGENT: &str = concat!("wallop-verifier/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysResponse {
    schema_version: String,
    keys: Vec<KeyEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    key_id: String,
    public_key_hex: String,
    inserted_at: String,
    key_class: String,
}

/// Tier-2 (attestable) resolver. Fetches keys from the wallop-side
/// `/operator/:slug/keys` and `/infrastructure/keys` endpoints,
/// validates each row's internal consistency
/// (`key_id == hash(public_key)`) and the response's `schema_version`,
/// caches per class for the lifetime of the resolver, and returns
/// `ResolvedKey { inserted_at: At(timestamp), .. }` — never `Sentinel`
/// (per the protocol violation rule in spec §4.2.4: a non-bundle
/// resolver returning `Sentinel` is itself a violation).
///
/// **Cache lifetime.** The per-class cache lives for the resolver's
/// own lifetime and does not poll for key rotations. The CLI binary
/// constructs a new resolver per invocation, so this is exactly right
/// for one-shot verification. Long-lived consumers (daemons,
/// server-side verifiers) MUST construct a new `EndpointResolver` per
/// verification — otherwise a key rotation that lands mid-process
/// remains invisible to the resolver and verdicts diverge from
/// reality. The tier-1 (`PinnedResolver`) follow-up does not address
/// this; a future TTL-or-staleness layer is a separate piece of work.
pub struct EndpointResolver {
    base_url: String,
    operator_slug: String,
    /// Reusable HTTP agent. Built once in `::new` so connection pooling
    /// across the (at most) two requests per verification is cheap.
    agent: ureq::Agent,
    cache: Mutex<HashMap<KeyClass, Vec<ResolvedKey>>>,
}

impl EndpointResolver {
    /// Construct a resolver for a given wallop instance.
    ///
    /// `base_url` is the scheme + host (and optional port + path prefix)
    /// — e.g. `https://wallop.example.com`. The resolver appends the
    /// canonical endpoint paths from spec §4.2.4. No trailing slash on
    /// `base_url` is required; one is stripped if present.
    ///
    /// `operator_slug` identifies which operator's keys to fetch. The
    /// CLI typically derives this from the bundle's `lock_receipt`
    /// payload; see `wallop_verify.rs`. Slug-charset validation is the
    /// caller's responsibility — this constructor does not parse the
    /// slug itself.
    pub fn new(base_url: impl Into<String>, operator_slug: impl Into<String>) -> Self {
        let base_url = base_url.into();
        let trimmed = base_url.trim_end_matches('/').to_string();
        let agent = ureq::AgentBuilder::new().timeout(REQUEST_TIMEOUT).build();
        Self {
            base_url: trimmed,
            operator_slug: operator_slug.into(),
            agent,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The canonicalised URL the resolver will hit for operator keys.
    /// Exposes the resolver's actual request shape so report-printing
    /// surfaces the URL the resolver used, not a re-formatted version
    /// of the user's input. Tightens the audit trail.
    pub fn operator_keys_url(&self) -> String {
        self.url_for(KeyClass::Operator)
    }

    /// The canonicalised URL the resolver will hit for infrastructure
    /// keys. See `operator_keys_url`.
    pub fn infrastructure_keys_url(&self) -> String {
        self.url_for(KeyClass::Infrastructure)
    }

    fn url_for(&self, class: KeyClass) -> String {
        // URL composition is per-class; the operator endpoint
        // interpolates the slug, the infrastructure endpoint does not.
        // Asserting class membership on every returned row (below)
        // closes the "mixed response from a single endpoint" hole; a
        // future single-endpoint shape would weaken this — do not
        // collapse without re-deriving the cross-check.
        match class {
            KeyClass::Operator => {
                format!("{}/operator/{}/keys", self.base_url, self.operator_slug)
            }
            KeyClass::Infrastructure => format!("{}/infrastructure/keys", self.base_url),
        }
    }

    /// Network fetch + validation. Errors are mapped into the
    /// closed-set `ResolutionError` variants per spec §4.2.4: failure
    /// is terminal at the pipeline level, with no soft fallback.
    fn fetch_class(&self, class: KeyClass) -> Result<Vec<ResolvedKey>, ResolutionError> {
        let url = self.url_for(class);

        let response = self
            .agent
            .get(&url)
            .set("User-Agent", USER_AGENT)
            .call()
            .map_err(map_ureq_error)?;

        // Cap response body size before deserialising. `into_reader()`
        // returns `impl Read`; `take(MAX_RESPONSE_BYTES)` bounds it.
        // A response that exceeds the cap surfaces as
        // `MalformedResponse` (truncated JSON fails to parse).
        let mut bounded = response.into_reader().take(MAX_RESPONSE_BYTES);
        let mut bytes = Vec::with_capacity(4096);
        bounded
            .read_to_end(&mut bytes)
            .map_err(|_| ResolutionError::MalformedResponse)?;

        let body: KeysResponse =
            serde_json::from_slice(&bytes).map_err(|_| ResolutionError::MalformedResponse)?;

        if body.schema_version != SUPPORTED_KEYS_RESPONSE_SCHEMA {
            return Err(ResolutionError::MalformedResponse);
        }

        if body.keys.len() > MAX_KEYS_PER_RESPONSE {
            return Err(ResolutionError::MalformedResponse);
        }

        let expected_class = match class {
            KeyClass::Operator => "operator",
            KeyClass::Infrastructure => "infrastructure",
        };

        let mut resolved = Vec::with_capacity(body.keys.len());
        for entry in body.keys {
            if entry.key_class != expected_class {
                // Endpoint must not mix classes in a single response.
                // Today the URL is per-class so a mixed response is
                // either an endpoint bug or an attempt at confusion;
                // either way we reject before any signature use.
                return Err(ResolutionError::MalformedResponse);
            }

            // Wire-shape strictness: spec §4.2.4 pins `key_id` as 8
            // lowercase hex chars and `public_key_hex` as 64 lowercase
            // hex chars. `hex::decode` accepts mixed case; an endpoint
            // emitting uppercase hex would still hash-match (because
            // `key_id(pk)` happens to be lowercase too) but would
            // violate the wire contract. Reject early so cross-
            // implementation conformance is asserted, not implied.
            if !is_lowercase_hex(&entry.key_id, 8) {
                return Err(ResolutionError::MalformedResponse);
            }
            if !is_lowercase_hex(&entry.public_key_hex, 64) {
                return Err(ResolutionError::MalformedResponse);
            }

            let pk_bytes = hex::decode(&entry.public_key_hex)
                .map_err(|_| ResolutionError::MalformedResponse)?;
            let pk: [u8; 32] = pk_bytes
                .try_into()
                .map_err(|_| ResolutionError::MalformedResponse)?;

            // Verifier-side keyring-row consistency check (spec §4.2.4):
            // the row's `key_id` MUST hash to its `public_key`. A buggy
            // or hostile keyring response that crosses these would
            // otherwise pass through to the signature step against the
            // wrong key.
            if key_id(&pk) != entry.key_id {
                return Err(ResolutionError::InconsistentRow);
            }

            resolved.push(ResolvedKey {
                public_key: pk,
                inserted_at: InsertedAt::At(entry.inserted_at),
                key_class: class,
            });
        }

        Ok(resolved)
    }
}

/// Strict lowercase-hex check matching spec §4.2.4's pinned wire
/// shape: exact length, `[0-9a-f]` only.
fn is_lowercase_hex(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl KeyResolver for EndpointResolver {
    fn resolve(
        &self,
        requested_key_id: &str,
        class: KeyClass,
    ) -> Result<ResolvedKey, ResolutionError> {
        // Recover from a poisoned mutex rather than propagating the
        // panic. The mutex protects a `HashMap` that holds resolved
        // keys; a previous panic during `.lock()`-held work cannot
        // corrupt the verification verdict, only the cache state.
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entries = match cache.get(&class) {
            Some(e) => e,
            None => {
                let fetched = self.fetch_class(class)?;
                cache.insert(class, fetched);
                cache.get(&class).expect("just-inserted key present")
            }
        };

        entries
            .iter()
            .find(|k| key_id(&k.public_key) == requested_key_id)
            .cloned()
            .ok_or(ResolutionError::KeyNotFound)
    }
}

/// Map ureq's transport / HTTP errors into the resolver's closed-set
/// failure variants. Network unreachable → `Unreachable`; HTTP status
/// errors (4xx / 5xx) → `MalformedResponse` because the wire contract
/// is violated. The pipeline treats both as terminal.
///
/// **Intentional simplification.** All non-2xx HTTP statuses collapse
/// to `MalformedResponse` regardless of whether the upstream said
/// "your request was wrong" (4xx) or "I am sad" (5xx). The verdict
/// outcome is the same (terminal rejection); the discrimination
/// matters only for user-facing diagnostics, which are surfaced in a
/// follow-up release. Do not refine without coordinating that follow-up.
fn map_ureq_error(err: ureq::Error) -> ResolutionError {
    match err {
        ureq::Error::Transport(_) => ResolutionError::Unreachable,
        ureq::Error::Status(_, _) => ResolutionError::MalformedResponse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use wallop_verifier::key_resolver::{InsertedAt, ResolutionError};

    /// Deterministic test key (RFC 8032 test vector — same one used
    /// throughout the verifier crate's frozen-vector tests).
    fn test_key() -> ([u8; 32], SigningKey) {
        let secret: [u8; 32] =
            hex::decode("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60")
                .unwrap()
                .try_into()
                .unwrap();
        let sk = SigningKey::from_bytes(&secret);
        let pk = sk.verifying_key().to_bytes();
        (pk, sk)
    }

    fn canonical_keys_response(pk_hex: &str, key_id_hex: &str, class: &str) -> String {
        format!(
            r#"{{"schema_version":"1","keys":[{{"key_id":"{}","public_key_hex":"{}","inserted_at":"2026-04-01T00:00:00.000000Z","key_class":"{}"}}]}}"#,
            key_id_hex, pk_hex, class,
        )
    }

    #[test]
    fn resolves_operator_key_against_endpoint() {
        let (pk, _) = test_key();
        let kid = key_id(&pk);
        let pk_hex = hex::encode(pk);

        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/operator/test-operator/keys")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(canonical_keys_response(&pk_hex, &kid, "operator"))
            .create();

        let resolver = EndpointResolver::new(server.url(), "test-operator");
        let resolved = resolver
            .resolve(&kid, KeyClass::Operator)
            .expect("resolver returns operator key");

        assert_eq!(resolved.public_key, pk);
        assert_eq!(resolved.key_class, KeyClass::Operator);
        assert!(matches!(resolved.inserted_at, InsertedAt::At(_)));
        if let InsertedAt::At(ts) = &resolved.inserted_at {
            assert_eq!(ts, "2026-04-01T00:00:00.000000Z");
        }
        mock.assert();
    }

    #[test]
    fn resolves_infrastructure_key_against_endpoint() {
        let (pk, _) = test_key();
        let kid = key_id(&pk);
        let pk_hex = hex::encode(pk);

        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/infrastructure/keys")
            .with_status(200)
            .with_body(canonical_keys_response(&pk_hex, &kid, "infrastructure"))
            .create();

        let resolver = EndpointResolver::new(server.url(), "irrelevant");
        let resolved = resolver
            .resolve(&kid, KeyClass::Infrastructure)
            .expect("resolver returns infrastructure key");

        assert_eq!(resolved.public_key, pk);
        assert_eq!(resolved.key_class, KeyClass::Infrastructure);
        mock.assert();
    }

    #[test]
    fn caches_per_class_and_re_uses_for_same_class() {
        let (pk, _) = test_key();
        let kid = key_id(&pk);
        let pk_hex = hex::encode(pk);

        let mut server = mockito::Server::new();
        // `expect(1)` — exactly one HTTP call, even though we resolve
        // twice. The cache is per-class; second call hits the cache.
        let mock = server
            .mock("GET", "/operator/test-operator/keys")
            .with_status(200)
            .with_body(canonical_keys_response(&pk_hex, &kid, "operator"))
            .expect(1)
            .create();

        let resolver = EndpointResolver::new(server.url(), "test-operator");
        resolver.resolve(&kid, KeyClass::Operator).unwrap();
        resolver.resolve(&kid, KeyClass::Operator).unwrap();
        mock.assert();
    }

    #[test]
    fn rejects_unknown_key_id_with_keynotfound() {
        let (pk, _) = test_key();
        let kid = key_id(&pk);
        let pk_hex = hex::encode(pk);

        let mut server = mockito::Server::new();
        server
            .mock("GET", "/operator/test-operator/keys")
            .with_status(200)
            .with_body(canonical_keys_response(&pk_hex, &kid, "operator"))
            .create();

        let resolver = EndpointResolver::new(server.url(), "test-operator");
        let err = resolver
            .resolve("ffffffff", KeyClass::Operator)
            .unwrap_err();
        assert_eq!(err, ResolutionError::KeyNotFound);
    }

    #[test]
    fn rejects_unsupported_schema_version_as_malformed() {
        let mut server = mockito::Server::new();
        server
            .mock("GET", "/infrastructure/keys")
            .with_status(200)
            .with_body(r#"{"schema_version":"2","keys":[]}"#)
            .create();

        let resolver = EndpointResolver::new(server.url(), "irrelevant");
        let err = resolver
            .resolve("deadbeef", KeyClass::Infrastructure)
            .unwrap_err();
        assert_eq!(err, ResolutionError::MalformedResponse);
    }

    #[test]
    fn rejects_inconsistent_keyring_row_with_inconsistent_row() {
        // Endpoint returns a key whose declared `key_id` does not hash
        // to its `public_key_hex`. Spec §4.2.4 keyring-row consistency
        // check: the verifier MUST reject without consulting the
        // signature.
        let (pk, _) = test_key();
        let pk_hex = hex::encode(pk);
        // Wrong key_id — not the hash of `pk`.
        let bogus_kid = "ffffffff";

        let mut server = mockito::Server::new();
        server
            .mock("GET", "/operator/acme/keys")
            .with_status(200)
            .with_body(canonical_keys_response(&pk_hex, bogus_kid, "operator"))
            .create();

        let resolver = EndpointResolver::new(server.url(), "acme");
        let err = resolver.resolve(bogus_kid, KeyClass::Operator).unwrap_err();
        assert_eq!(err, ResolutionError::InconsistentRow);
    }

    #[test]
    fn rejects_class_mismatch_in_response_as_malformed() {
        // Asking for an operator key but the endpoint returned a row
        // labelled `infrastructure`. Either the wrong endpoint was
        // queried or the response is corrupt; both are protocol
        // violations.
        let (pk, _) = test_key();
        let kid = key_id(&pk);
        let pk_hex = hex::encode(pk);

        let mut server = mockito::Server::new();
        server
            .mock("GET", "/operator/acme/keys")
            .with_status(200)
            .with_body(canonical_keys_response(&pk_hex, &kid, "infrastructure"))
            .create();

        let resolver = EndpointResolver::new(server.url(), "acme");
        let err = resolver.resolve(&kid, KeyClass::Operator).unwrap_err();
        assert_eq!(err, ResolutionError::MalformedResponse);
    }

    #[test]
    fn maps_http_5xx_to_malformed_response() {
        let mut server = mockito::Server::new();
        server
            .mock("GET", "/infrastructure/keys")
            .with_status(503)
            .with_body("upstream down")
            .create();

        let resolver = EndpointResolver::new(server.url(), "irrelevant");
        let err = resolver
            .resolve("deadbeef", KeyClass::Infrastructure)
            .unwrap_err();
        assert_eq!(err, ResolutionError::MalformedResponse);
    }

    #[test]
    fn maps_dns_failure_to_unreachable() {
        // Pointing at a non-routable address surfaces as a transport
        // error from ureq, which the resolver maps to `Unreachable`.
        let resolver = EndpointResolver::new(
            "http://this-host-should-never-resolve.invalid",
            "irrelevant",
        );
        let err = resolver
            .resolve("deadbeef", KeyClass::Infrastructure)
            .unwrap_err();
        assert_eq!(err, ResolutionError::Unreachable);
    }

    #[test]
    fn never_returns_sentinel_inserted_at() {
        // Spec §4.2.4: a non-bundle resolver returning `Sentinel` is
        // itself a protocol violation. EndpointResolver always wraps
        // the wire timestamp in `InsertedAt::At(_)`.
        let (pk, _) = test_key();
        let kid = key_id(&pk);
        let pk_hex = hex::encode(pk);

        let mut server = mockito::Server::new();
        server
            .mock("GET", "/operator/acme/keys")
            .with_status(200)
            .with_body(canonical_keys_response(&pk_hex, &kid, "operator"))
            .create();

        let resolver = EndpointResolver::new(server.url(), "acme");
        let resolved = resolver.resolve(&kid, KeyClass::Operator).unwrap();
        assert!(matches!(resolved.inserted_at, InsertedAt::At(_)));
        assert!(!matches!(resolved.inserted_at, InsertedAt::Sentinel));
    }

    #[test]
    fn trims_trailing_slash_on_base_url() {
        let (pk, _) = test_key();
        let kid = key_id(&pk);
        let pk_hex = hex::encode(pk);

        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/operator/acme/keys")
            .with_status(200)
            .with_body(canonical_keys_response(&pk_hex, &kid, "operator"))
            .create();

        // base_url with trailing slash must produce the same URL as
        // without — no double slash, no mismatch.
        let trailing = format!("{}/", server.url());
        let resolver = EndpointResolver::new(trailing, "acme");
        resolver.resolve(&kid, KeyClass::Operator).unwrap();
        mock.assert();
    }

    #[test]
    fn rejects_unknown_field_in_response_envelope() {
        // Spec §4.2.4 wire shape is closed-set: a v1 response carrying
        // an extra top-level field is itself a wire-contract violation.
        let mut server = mockito::Server::new();
        server
            .mock("GET", "/infrastructure/keys")
            .with_status(200)
            .with_body(r#"{"schema_version":"1","keys":[],"surprise":"evil"}"#)
            .create();

        let resolver = EndpointResolver::new(server.url(), "irrelevant");
        let err = resolver
            .resolve("deadbeef", KeyClass::Infrastructure)
            .unwrap_err();
        assert_eq!(err, ResolutionError::MalformedResponse);
    }

    #[test]
    fn rejects_unknown_field_in_key_row() {
        // Same closed-set rule applies per row. If a future producer
        // re-introduces `valid_from` on the wire (deliberately removed
        // in spec §4.2.4 to close the temporal-binding window), this
        // test catches it before the resolver silently ignores it.
        let (pk, _) = test_key();
        let kid = key_id(&pk);
        let pk_hex = hex::encode(pk);

        let mut server = mockito::Server::new();
        server
            .mock("GET", "/operator/acme/keys")
            .with_status(200)
            .with_body(format!(
                r#"{{"schema_version":"1","keys":[{{"key_id":"{kid}","public_key_hex":"{pk_hex}","inserted_at":"2026-04-01T00:00:00.000000Z","key_class":"operator","valid_from":"2026-04-01T00:00:00.000000Z"}}]}}"#,
            ))
            .create();

        let resolver = EndpointResolver::new(server.url(), "acme");
        let err = resolver.resolve(&kid, KeyClass::Operator).unwrap_err();
        assert_eq!(err, ResolutionError::MalformedResponse);
    }

    #[test]
    fn rejects_uppercase_hex_in_key_id() {
        // Spec §4.2.4 pins `key_id` as 8 lowercase hex chars. An
        // endpoint emitting uppercase hex would still hash-match (the
        // local `key_id(pk)` is lowercase too) but violates the wire
        // contract. Reject early so cross-implementation conformance
        // is asserted rather than implied.
        let (pk, _) = test_key();
        let kid_lower = key_id(&pk);
        let kid_upper = kid_lower.to_uppercase();
        let pk_hex = hex::encode(pk);

        let mut server = mockito::Server::new();
        server
            .mock("GET", "/operator/acme/keys")
            .with_status(200)
            .with_body(canonical_keys_response(&pk_hex, &kid_upper, "operator"))
            .create();

        let resolver = EndpointResolver::new(server.url(), "acme");
        let err = resolver
            .resolve(&kid_lower, KeyClass::Operator)
            .unwrap_err();
        assert_eq!(err, ResolutionError::MalformedResponse);
    }

    #[test]
    fn rejects_uppercase_hex_in_public_key_hex() {
        let (pk, _) = test_key();
        let kid = key_id(&pk);
        let pk_hex_upper = hex::encode(pk).to_uppercase();

        let mut server = mockito::Server::new();
        server
            .mock("GET", "/operator/acme/keys")
            .with_status(200)
            .with_body(canonical_keys_response(&pk_hex_upper, &kid, "operator"))
            .create();

        let resolver = EndpointResolver::new(server.url(), "acme");
        let err = resolver.resolve(&kid, KeyClass::Operator).unwrap_err();
        assert_eq!(err, ResolutionError::MalformedResponse);
    }

    #[test]
    fn rejects_response_exceeding_size_cap() {
        // Pad the keys array with garbage to exceed MAX_RESPONSE_BYTES.
        // The bounded reader truncates at 1 MiB; truncated JSON fails
        // to parse, surfacing as MalformedResponse.
        let huge_body = format!(
            r#"{{"schema_version":"1","keys":[{padding}]}}"#,
            padding = "0".repeat((MAX_RESPONSE_BYTES + 1024) as usize)
        );

        let mut server = mockito::Server::new();
        server
            .mock("GET", "/infrastructure/keys")
            .with_status(200)
            .with_body(huge_body)
            .create();

        let resolver = EndpointResolver::new(server.url(), "irrelevant");
        let err = resolver
            .resolve("deadbeef", KeyClass::Infrastructure)
            .unwrap_err();
        assert_eq!(err, ResolutionError::MalformedResponse);
    }

    #[test]
    fn url_accessors_return_canonicalised_paths() {
        // Trailing slash on the constructor input does not surface in
        // the accessor output; the report-printing path reads from
        // these accessors so the report names what the resolver
        // actually hit.
        let resolver = EndpointResolver::new("https://wallop.example.com/", "acme-prizes");
        assert_eq!(
            resolver.operator_keys_url(),
            "https://wallop.example.com/operator/acme-prizes/keys"
        );
        assert_eq!(
            resolver.infrastructure_keys_url(),
            "https://wallop.example.com/infrastructure/keys"
        );
    }
}
