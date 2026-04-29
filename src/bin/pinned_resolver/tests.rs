//! `PinnedResolver` tests.
//!
//! Most tests load the canonical cross-language vector at
//! `vendor/wallop/spec/vectors/pin/v1/valid.json` (committed via the
//! `vendor/wallop` submodule pin). The vector ships a deterministic
//! test keypair, a valid signed envelope, and five negative cases:
//!
//! 1. single-byte preimage mutation rejects
//! 2. single-byte signature mutation rejects
//! 3. wrong key rejects
//! 4. domain-separator-omitted rejects
//! 5. reversed-input key sort normalised by producer (producer-side
//!    test; not exercised here — that's a producer obligation)
//!
//! These tests assert the verifier-side behaviour matches the
//! producer-side behaviour byte-for-byte.

use super::*;

const VECTOR_BYTES: &[u8] = include_bytes!("../../../vendor/wallop/spec/vectors/pin/v1/valid.json");

#[derive(serde::Deserialize)]
struct Vector {
    domain_separator_hex: String,
    infrastructure_keypair: KeypairBlock,
    vectors: Vec<VectorCase>,
}

#[derive(serde::Deserialize)]
struct KeypairBlock {
    // Verifier-side tests don't sign — only verify against pre-computed
    // signatures. Field present in the source vector for symmetry with
    // the Elixir-side regenerator; declared with serde(default) as a
    // no-op keeper.
    #[serde(default, rename = "private_key_hex")]
    _private_key_hex: Option<String>,
    public_key_hex: String,
}

#[derive(serde::Deserialize)]
struct VectorCase {
    name: String,
    #[serde(default)]
    envelope: Option<serde_json::Value>,
    #[serde(default)]
    preimage_jcs_hex: Option<String>,
    // Same shape parity reason as `_private_key_hex`. The valid case's
    // signature lives in `signature_hex` for verifier-side tests; the
    // separate `expected_signature_hex` field exists in the producer-
    // emitted vector and is kept here for round-trip parity.
    #[serde(default, rename = "expected_signature_hex")]
    _expected_signature_hex: Option<String>,
    #[serde(default)]
    signature_hex: Option<String>,
    #[serde(default)]
    verify_against_public_key_hex: Option<String>,
}

fn load_vector() -> Vector {
    serde_json::from_slice(VECTOR_BYTES).expect("vector parses")
}

fn anchor_from_vector(v: &Vector) -> AnchorRecord {
    let pk_bytes: [u8; 32] = hex::decode(&v.infrastructure_keypair.public_key_hex)
        .expect("vector public_key_hex decodes")
        .try_into()
        .expect("vector public_key 32 bytes");

    AnchorRecord {
        key_id: wallop_verifier::key_id(&pk_bytes),
        public_key: pk_bytes,
        // Use a far-past inserted_at and no revoked_at so temporal
        // binding always passes for the vector's published_at. The
        // bundled-anchor temporal-window check has its own dedicated
        // tests further down; freeing this case from clock concerns
        // keeps each test orthogonal.
        inserted_at: "2020-01-01T00:00:00.000000Z".into(),
        revoked_at: None,
    }
}

fn dummy_endpoint_resolver() -> EndpointResolver {
    // Constructed but never actually called from these tests — they
    // exercise pin verification, which happens at PinnedResolver
    // construction time and does not touch the inner resolver.
    EndpointResolver::new("http://test.invalid", "test-operator")
}

fn far_future_now() -> String {
    // Pinned to keep the freshness check ("published_at <= now+60s")
    // deterministic across test runs. The vector's published_at is
    // 2026-04-29T19:36:58.252939Z; this is years later.
    "2099-01-01T00:00:00.000000Z".into()
}

#[test]
fn vector_domain_separator_matches_module_constant() {
    let v = load_vector();
    let from_vector = hex::decode(&v.domain_separator_hex).expect("hex decodes");
    assert_eq!(from_vector, DOMAIN_SEPARATOR);
}

#[test]
fn valid_vector_constructs_a_resolver() {
    let v = load_vector();
    let valid = v
        .vectors
        .iter()
        .find(|c| c.name == "valid sign + verify")
        .expect("valid case");
    let envelope_bytes = serde_json::to_vec(valid.envelope.as_ref().unwrap()).unwrap();

    let anchor = anchor_from_vector(&v);
    let resolver = PinnedResolver::verify_bytes(
        &envelope_bytes,
        &[anchor],
        dummy_endpoint_resolver(),
        far_future_now(),
    )
    .expect("valid envelope constructs a resolver");

    // The pin commits to "wallop-vector-operator" per the vector.
    assert_eq!(resolver.pin_operator_slug(), "wallop-vector-operator");
}

#[test]
fn vector_preimage_reconstruction_matches_recorded_bytes() {
    let v = load_vector();
    let valid = v
        .vectors
        .iter()
        .find(|c| c.name == "valid sign + verify")
        .expect("valid case");
    let envelope_bytes = serde_json::to_vec(valid.envelope.as_ref().unwrap()).unwrap();

    let recovered = reconstruct_preimage(&envelope_bytes).expect("preimage reconstructs");
    let expected =
        hex::decode(valid.preimage_jcs_hex.as_ref().unwrap()).expect("recorded hex decodes");
    assert_eq!(recovered, expected);
}

#[test]
fn negative_vector_single_byte_preimage_mutation_rejects() {
    let v = load_vector();
    let case = v
        .vectors
        .iter()
        .find(|c| c.name == "single-byte preimage mutation rejects")
        .expect("vector case present");

    // Build a fake envelope where the preimage is the mutated bytes
    // and the signature is the original signature. We can't go through
    // verify_bytes (which re-derives the preimage) for this — instead
    // we exercise the signature-verification primitive directly with
    // mutated bytes.
    let mutated_preimage = hex::decode(case.preimage_jcs_hex.as_ref().unwrap()).unwrap();
    let signature: [u8; 64] = hex::decode(case.signature_hex.as_ref().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    let anchor = anchor_from_vector(&v);
    let result = find_verifying_anchor(
        &mutated_preimage,
        &signature,
        std::slice::from_ref(&anchor),
        "2026-04-29T19:36:58.252939Z",
    );
    assert!(matches!(result, Err(PinError::AnchorNotFound)));
}

#[test]
fn negative_vector_single_byte_signature_mutation_rejects() {
    let v = load_vector();
    let case = v
        .vectors
        .iter()
        .find(|c| c.name == "single-byte signature mutation rejects")
        .expect("vector case present");

    let preimage = hex::decode(case.preimage_jcs_hex.as_ref().unwrap()).unwrap();
    let mutated_sig: [u8; 64] = hex::decode(case.signature_hex.as_ref().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    let anchor = anchor_from_vector(&v);
    let result = find_verifying_anchor(
        &preimage,
        &mutated_sig,
        std::slice::from_ref(&anchor),
        "2026-04-29T19:36:58.252939Z",
    );
    assert!(matches!(result, Err(PinError::AnchorNotFound)));
}

#[test]
fn negative_vector_wrong_key_signature_rejects() {
    let v = load_vector();
    let case = v
        .vectors
        .iter()
        .find(|c| c.name == "wrong key rejects")
        .expect("vector case present");

    let preimage = hex::decode(case.preimage_jcs_hex.as_ref().unwrap()).unwrap();
    let sig: [u8; 64] = hex::decode(case.signature_hex.as_ref().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    // Verify against the vector's *recorded* infrastructure public key
    // (not the wrong keypair's). The signature was produced by an
    // independent private key; verification against this public key
    // MUST fail.
    let against = case.verify_against_public_key_hex.as_ref().unwrap();
    let recorded = &v.infrastructure_keypair.public_key_hex;
    assert_eq!(
        against, recorded,
        "vector targets the recorded infra pubkey"
    );

    let anchor = anchor_from_vector(&v);
    let result = find_verifying_anchor(
        &preimage,
        &sig,
        std::slice::from_ref(&anchor),
        "2026-04-29T19:36:58.252939Z",
    );
    assert!(matches!(result, Err(PinError::AnchorNotFound)));
}

#[test]
fn negative_vector_domain_separator_omitted_rejects() {
    // The most likely cross-language bug: implementer reads
    // "Ed25519(payload)" and forgets to prepend the 14-byte domain
    // separator. find_verifying_anchor MUST reject because it always
    // prepends the domain separator before calling Ed25519 verify.
    let v = load_vector();
    let case = v
        .vectors
        .iter()
        .find(|c| c.name == "domain-separator-omitted rejects")
        .expect("vector case present");

    let preimage = hex::decode(case.preimage_jcs_hex.as_ref().unwrap()).unwrap();
    let sig: [u8; 64] = hex::decode(case.signature_hex.as_ref().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    let anchor = anchor_from_vector(&v);
    let result = find_verifying_anchor(
        &preimage,
        &sig,
        std::slice::from_ref(&anchor),
        "2026-04-29T19:36:58.252939Z",
    );
    assert!(matches!(result, Err(PinError::AnchorNotFound)));
}

#[test]
fn empty_anchor_set_refuses_attributable_mode() {
    let v = load_vector();
    let valid = v
        .vectors
        .iter()
        .find(|c| c.name == "valid sign + verify")
        .expect("valid case");
    let envelope_bytes = serde_json::to_vec(valid.envelope.as_ref().unwrap()).unwrap();

    let result = PinnedResolver::verify_bytes(
        &envelope_bytes,
        &[],
        dummy_endpoint_resolver(),
        far_future_now(),
    );
    assert!(matches!(result, Err(PinError::AnchorNotFound)));
}

#[test]
fn future_published_at_rejects() {
    let v = load_vector();
    let valid = v
        .vectors
        .iter()
        .find(|c| c.name == "valid sign + verify")
        .expect("valid case");
    let envelope_bytes = serde_json::to_vec(valid.envelope.as_ref().unwrap()).unwrap();

    // Set "now" to before the vector's published_at — the freshness
    // rule MUST reject.
    let result = PinnedResolver::verify_bytes(
        &envelope_bytes,
        std::slice::from_ref(&anchor_from_vector(&v)),
        dummy_endpoint_resolver(),
        "2020-01-01T00:00:00.000000Z".into(),
    );
    assert!(matches!(result, Err(PinError::PublishedInFuture)));
}

#[test]
fn anchor_outside_temporal_window_does_not_verify() {
    let v = load_vector();
    let valid = v
        .vectors
        .iter()
        .find(|c| c.name == "valid sign + verify")
        .expect("valid case");
    let envelope_bytes = serde_json::to_vec(valid.envelope.as_ref().unwrap()).unwrap();

    // Anchor inserted AFTER the pin's published_at — fails temporal
    // binding (anchor.inserted_at <= pin.published_at).
    let mut anchor = anchor_from_vector(&v);
    anchor.inserted_at = "2099-12-31T23:59:59.999999Z".into();

    let result = PinnedResolver::verify_bytes(
        &envelope_bytes,
        std::slice::from_ref(&anchor),
        dummy_endpoint_resolver(),
        far_future_now(),
    );
    let err = result.err().expect("expected error");
    assert_eq!(err, PinError::AnchorNotFound);
}

#[test]
fn anchor_revoked_before_published_at_does_not_verify() {
    let v = load_vector();
    let valid = v
        .vectors
        .iter()
        .find(|c| c.name == "valid sign + verify")
        .expect("valid case");
    let envelope_bytes = serde_json::to_vec(valid.envelope.as_ref().unwrap()).unwrap();

    let mut anchor = anchor_from_vector(&v);
    // Revoked before the pin's published_at: temporal-binding window
    // [inserted_at, revoked_at) does not contain published_at.
    anchor.revoked_at = Some("2020-12-31T23:59:59.999999Z".into());

    let result = PinnedResolver::verify_bytes(
        &envelope_bytes,
        std::slice::from_ref(&anchor),
        dummy_endpoint_resolver(),
        far_future_now(),
    );
    assert!(matches!(result, Err(PinError::AnchorNotFound)));
}

#[test]
fn schema_version_mismatch_rejects() {
    let v = load_vector();
    let valid = v
        .vectors
        .iter()
        .find(|c| c.name == "valid sign + verify")
        .expect("valid case");
    let mut envelope = valid.envelope.as_ref().unwrap().clone();
    envelope["schema_version"] = serde_json::json!("99");
    let envelope_bytes = serde_json::to_vec(&envelope).unwrap();

    let result = PinnedResolver::verify_bytes(
        &envelope_bytes,
        std::slice::from_ref(&anchor_from_vector(&v)),
        dummy_endpoint_resolver(),
        far_future_now(),
    );
    assert!(matches!(result, Err(PinError::SchemaMismatch(_))));
}

#[test]
fn empty_keys_array_rejects() {
    let v = load_vector();
    let valid = v
        .vectors
        .iter()
        .find(|c| c.name == "valid sign + verify")
        .expect("valid case");
    let mut envelope = valid.envelope.as_ref().unwrap().clone();
    envelope["keys"] = serde_json::json!([]);
    let envelope_bytes = serde_json::to_vec(&envelope).unwrap();

    let result = PinnedResolver::verify_bytes(
        &envelope_bytes,
        std::slice::from_ref(&anchor_from_vector(&v)),
        dummy_endpoint_resolver(),
        far_future_now(),
    );
    let err = result.err().expect("expected error");
    match err {
        PinError::SchemaMismatch(s) => assert!(s.contains("keys[] is empty"), "got {}", s),
        other => panic!("expected SchemaMismatch, got {:?}", other),
    }
}

#[test]
fn non_operator_key_class_rejects() {
    let v = load_vector();
    let valid = v
        .vectors
        .iter()
        .find(|c| c.name == "valid sign + verify")
        .expect("valid case");
    let mut envelope = valid.envelope.as_ref().unwrap().clone();
    envelope["keys"][0]["key_class"] = serde_json::json!("infrastructure");
    let envelope_bytes = serde_json::to_vec(&envelope).unwrap();

    let result = PinnedResolver::verify_bytes(
        &envelope_bytes,
        std::slice::from_ref(&anchor_from_vector(&v)),
        dummy_endpoint_resolver(),
        far_future_now(),
    );
    assert!(matches!(result, Err(PinError::SchemaMismatch(_))));
}
