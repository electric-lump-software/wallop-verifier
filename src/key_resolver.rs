//! Key resolution surface for the verifier pipeline.
//!
//! `KeyResolver` is the only interface through which the pipeline obtains a
//! public key for signature verification. The crate ships exactly one
//! built-in implementation: `BundleEmbeddedResolver` (legacy/self-consistency).
//! HTTP-backed resolvers (`EndpointResolver` for tier-2 attestable mode,
//! `PinnedResolver` for tier-1 attributable mode) are consumer-side — they
//! ship in the CLI binary and the WASM JS bridge, not in the verifier crate
//! itself, so the WASM build does not pull `reqwest` or similar.
//!
//! See spec §4.2.4 for the verifier mode taxonomy and design rationale.

use crate::bundle::ProofBundle;
use crate::protocol::receipts::{
    ParsedExecutionReceipt, ParsedLockReceipt, parse_execution_receipt, parse_lock_receipt,
};

/// Resolve a `(key_id, key_class)` pair to a public key plus the metadata
/// required for temporal binding (spec §4.2.4). Failure is terminal: the
/// verifier pipeline MUST NOT fall back to inline receipt-block keys when
/// the resolver returns an error.
pub trait KeyResolver {
    fn resolve(&self, key_id: &str, key_class: KeyClass) -> Result<ResolvedKey, ResolutionError>;
}

/// Successful key resolution. `inserted_at` is the comparison point for
/// the temporal-binding check in spec §4.2.4 — the moment the resolver's
/// trust root first observed this key.
///
/// Carried as a string-backed enum rather than a typed `DateTime` to
/// avoid pulling `chrono` into the verifier crate (which compiles to
/// WASM); the existing `chrono_parse_canonical` in `verify_steps` is the
/// canonical parser. The two variants exist because `BundleEmbeddedResolver`
/// has no out-of-band first-existence timestamp to return — see the
/// `InsertedAt` doc.
#[derive(Debug, Clone)]
pub struct ResolvedKey {
    pub public_key: [u8; 32],
    pub inserted_at: InsertedAt,
    pub key_class: KeyClass,
}

/// Comparison point for the temporal-binding check.
///
/// - `At(timestamp)` — the resolver's trust root committed this timestamp
///   independently of the bundle. The verifier MUST evaluate the
///   temporal-binding rule (`inserted_at <= receipt.binding_timestamp`).
/// - `Sentinel` — the resolver has no out-of-band first-existence
///   timestamp to return (i.e. `BundleEmbeddedResolver`, where the keys
///   are read directly from the bundle and the bundle does not carry
///   such a timestamp). The verifier MUST skip the temporal-binding rule
///   when this variant is paired with `VerifierMode::SelfConsistencyOnly`,
///   and MUST reject when paired with any other mode (a non-bundle
///   resolver returning `Sentinel` is itself a protocol violation).
///
/// Verifier-side V-02 enforcement is not yet wired in; the variant is in
/// place so the wiring PR can dispatch on shape rather than string-compare
/// a magic value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertedAt {
    Sentinel,
    At(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyClass {
    Operator,
    Infrastructure,
}

impl std::fmt::Display for KeyClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            KeyClass::Operator => "operator",
            KeyClass::Infrastructure => "infrastructure",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionError {
    /// The trust root could not be reached (network error, DNS failure,
    /// connection timeout).
    Unreachable,
    /// The trust root responded but does not list the requested `key_id`.
    KeyNotFound,
    /// The trust root's response contradicts a pinned reference (tier-1
    /// attributable mode only).
    PinMismatch,
    /// The trust root's response did not parse as a valid keyring document.
    MalformedResponse,
    /// The resolver detected an internal inconsistency in a keyring row —
    /// `public_key_hex` does not hash to the row's claimed `key_id`.
    /// Indicates either tampering or a producer-side bug.
    InconsistentRow,
}

impl std::fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ResolutionError::Unreachable => "trust root unreachable",
            ResolutionError::KeyNotFound => "key_id not found in trust root",
            ResolutionError::PinMismatch => "live response does not match pinned reference",
            ResolutionError::MalformedResponse => "trust root response did not parse",
            ResolutionError::InconsistentRow => "keyring row failed self-consistency check",
        })
    }
}

impl std::error::Error for ResolutionError {}

/// Resolves keys from the inline `public_key_hex` fields on the bundle's
/// receipt-block wrappers. Used for legacy v3/v4 receipts (which carry
/// inline keys per spec) and for `--mode self-consistency` debug runs of
/// any bundle.
///
/// **This resolver does not defend against MITM, hostile mirrors, or CDN
/// compromise** — it asserts only that the bytes inside the bundle are
/// internally consistent. A `VerificationReport` produced from this
/// resolver carries `VerifierMode::SelfConsistencyOnly` and the proof-page
/// UX MUST surface that mode to visitors. See spec §4.2.4 caveat-mode
/// disclosure.
///
/// On a v5 lock or v4 execution bundle (where the producer omitted
/// `public_key_hex` from the wrapper by protocol), this resolver returns
/// `KeyNotFound` for every request. That is the intended failure mode:
/// v5/v4 bundles must be verified with a tier-2 or tier-1 resolver to
/// produce any meaningful guarantee.
pub struct BundleEmbeddedResolver<'b> {
    bundle: &'b ProofBundle,
}

impl<'b> BundleEmbeddedResolver<'b> {
    pub fn from_bundle(bundle: &'b ProofBundle) -> Self {
        Self { bundle }
    }
}

impl<'b> KeyResolver for BundleEmbeddedResolver<'b> {
    fn resolve(&self, key_id: &str, key_class: KeyClass) -> Result<ResolvedKey, ResolutionError> {
        let (receipt_key_id, inline_key_hex) = match key_class {
            KeyClass::Operator => (
                signing_key_id_from_lock(&self.bundle.lock_receipt.payload_jcs),
                self.bundle.lock_receipt.public_key_hex.as_deref(),
            ),
            KeyClass::Infrastructure => (
                signing_key_id_from_exec(&self.bundle.execution_receipt.payload_jcs),
                self.bundle.execution_receipt.public_key_hex.as_deref(),
            ),
        };

        // The pipeline computes a real `key_id` for every resolver call,
        // including exec v2 (where the signed payload carries no
        // `signing_key_id`): the pipeline derives one by hashing the
        // inline pubkey via `crypto::key_id`. So both the requested and
        // receipt-side `key_id` are fully populated here, and the
        // resolver requires them to match — the same defence-in-depth
        // shape as the producer-side keyring-row consistency check
        // (spec §4.2.4).
        match receipt_key_id {
            Some(rk) if rk == key_id => {}
            // exec v2 has no signing_key_id; trust the pipeline's
            // synthesised key_id when the receipt does not carry one.
            None => {}
            _ => return Err(ResolutionError::KeyNotFound),
        }

        let hex_str = inline_key_hex.ok_or(ResolutionError::KeyNotFound)?;
        let bytes = hex::decode(hex_str).map_err(|_| ResolutionError::MalformedResponse)?;
        let public_key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ResolutionError::MalformedResponse)?;

        Ok(ResolvedKey {
            public_key,
            inserted_at: InsertedAt::Sentinel,
            key_class,
        })
    }
}

fn signing_key_id_from_lock(payload_jcs: &str) -> Option<String> {
    match parse_lock_receipt(payload_jcs).ok()? {
        ParsedLockReceipt::V4(p) => Some(p.signing_key_id),
        ParsedLockReceipt::V5(p) => Some(p.signing_key_id),
    }
}

fn signing_key_id_from_exec(payload_jcs: &str) -> Option<String> {
    match parse_execution_receipt(payload_jcs).ok()? {
        ParsedExecutionReceipt::V2(_) => None,
        ParsedExecutionReceipt::V3(p) => Some(p.signing_key_id),
        ParsedExecutionReceipt::V4(p) => Some(p.signing_key_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::_test_support::{build_valid_bundle, build_valid_v5_bundle};
    use crate::bundle::ProofBundle;
    use crate::{Entry, key_id};

    fn entries() -> Vec<Entry> {
        vec![
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
        ]
    }

    #[test]
    fn bundle_embedded_resolver_returns_inline_operator_key() {
        let json = build_valid_bundle(&entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let resolver = BundleEmbeddedResolver::from_bundle(&bundle);

        // The legacy v4 lock receipt's signing_key_id is the test key's
        // derived key_id (hash of the verifying key).
        let inline = bundle.lock_receipt.public_key_hex.as_deref().unwrap();
        let pk: [u8; 32] = hex::decode(inline).unwrap().try_into().unwrap();
        let test_kid = key_id(&pk);
        let resolved = resolver
            .resolve(&test_kid, KeyClass::Operator)
            .expect("resolver returns inline key");
        assert_eq!(resolved.key_class, KeyClass::Operator);
        assert_eq!(resolved.inserted_at, InsertedAt::Sentinel);

        // Round-trips: derived key_id matches the inline pubkey hex.
        let expected_pk: [u8; 32] =
            hex::decode(bundle.lock_receipt.public_key_hex.as_deref().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(resolved.public_key, expected_pk);
        assert_eq!(key_id(&resolved.public_key), key_id(&expected_pk));
    }

    #[test]
    fn bundle_embedded_resolver_rejects_mismatched_key_id() {
        let json = build_valid_bundle(&entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let resolver = BundleEmbeddedResolver::from_bundle(&bundle);

        let err = resolver
            .resolve("not-the-real-key-id", KeyClass::Operator)
            .unwrap_err();
        assert_eq!(err, ResolutionError::KeyNotFound);
    }

    #[test]
    fn bundle_embedded_resolver_returns_key_not_found_when_inline_pk_absent() {
        let (json, _, signing_key_id) = build_valid_v5_bundle(&entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let resolver = BundleEmbeddedResolver::from_bundle(&bundle);

        // Even with the right key_id, the v5 bundle wrapper has no inline
        // public_key_hex — `BundleEmbeddedResolver` cannot resolve.
        let err = resolver
            .resolve(&signing_key_id, KeyClass::Operator)
            .unwrap_err();
        assert_eq!(err, ResolutionError::KeyNotFound);
    }

    #[test]
    fn inserted_at_sentinel_is_reserved_for_bundle_embedded_resolver() {
        // Encoding-level guarantee: the two variants are distinct.
        // `BundleEmbeddedResolver` returns `Sentinel`; non-bundle
        // resolvers MUST return `At(_)`. The verifier-side V-02 wiring
        // dispatches on this variant rather than string-comparing a
        // magic value.
        let json = build_valid_bundle(&entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let resolver = BundleEmbeddedResolver::from_bundle(&bundle);

        let inline = bundle.lock_receipt.public_key_hex.as_deref().unwrap();
        let pk: [u8; 32] = hex::decode(inline).unwrap().try_into().unwrap();
        let kid = key_id(&pk);

        let resolved = resolver
            .resolve(&kid, KeyClass::Operator)
            .expect("resolver returns inline key");
        assert!(matches!(resolved.inserted_at, InsertedAt::Sentinel));
        assert!(!matches!(resolved.inserted_at, InsertedAt::At(_)));
    }

    #[test]
    fn bundle_embedded_resolver_handles_exec_v2_with_synthetic_key_id() {
        // Legacy bundles emit exec v2 (no signing_key_id on payload). The
        // pipeline derives a synthetic key_id by hashing the inline
        // pubkey and passes that to the resolver. The resolver accepts
        // any key_id when the receipt itself carries none, so the lookup
        // succeeds and returns the inline pk.
        let json = build_valid_bundle(&entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let resolver = BundleEmbeddedResolver::from_bundle(&bundle);

        let inline = bundle.execution_receipt.public_key_hex.as_deref().unwrap();
        let pk: [u8; 32] = hex::decode(inline).unwrap().try_into().unwrap();
        let synthetic_kid = key_id(&pk);

        let resolved = resolver
            .resolve(&synthetic_kid, KeyClass::Infrastructure)
            .expect("v2 exec resolves via inline pubkey under synthetic key_id");
        assert_eq!(resolved.public_key, pk);
    }
}
