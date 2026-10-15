use fair_pick_rs::{Entry, Winner};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::bundle::ProofBundle;
use crate::key_resolver::{InsertedAt, KeyClass, KeyResolver, ResolutionError, ResolvedKey};
use crate::protocol;
use crate::protocol::receipts::{ExecutionReceiptV2, LockReceiptV4};
use crate::verify_steps::{VerifierMode, verify_bundle_with};

/// WASM entry point for draw.
#[wasm_bindgen]
pub fn draw_wasm(entries_js: JsValue, seed_js: &[u8], count: u32) -> Result<JsValue, JsError> {
    let entries: Vec<Entry> =
        serde_wasm_bindgen::from_value(entries_js).map_err(|e| JsError::new(&e.to_string()))?;

    let seed: [u8; 32] = seed_js
        .try_into()
        .map_err(|_| JsError::new("seed must be exactly 32 bytes"))?;

    let result = fair_pick_rs::draw(&entries, &seed, count).map_err(|e| JsError::new(&e))?;
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// WASM entry point for entry_hash.
///
/// Takes `draw_id` (the public draw UUID) and an entries array. Each
/// entry's `id` field is interpreted as the public UUID at this
/// boundary. See `protocol::entry_hash` for the canonical form.
#[wasm_bindgen]
pub fn entry_hash_wasm(draw_id: &str, entries_js: JsValue) -> Result<JsValue, JsError> {
    let entries: Vec<Entry> =
        serde_wasm_bindgen::from_value(entries_js).map_err(|e| JsError::new(&e.to_string()))?;

    let (hash, jcs) = protocol::entry_hash(draw_id, &entries);

    let result = serde_json::json!({ "hash": hash, "jcs": jcs });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// WASM entry point for compute_seed.
#[wasm_bindgen]
pub fn compute_seed_wasm(
    entry_hash: &str,
    drand_randomness: &str,
    weather_value: &str,
) -> Result<JsValue, JsError> {
    let (seed_bytes, jcs) = protocol::compute_seed(entry_hash, drand_randomness, weather_value);

    let result = serde_json::json!({
        "seed": hex::encode(seed_bytes),
        "jcs": jcs,
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// WASM entry point for compute_seed (drand-only).
#[wasm_bindgen]
pub fn compute_seed_drand_only_wasm(
    entry_hash: &str,
    drand_randomness: &str,
) -> Result<JsValue, JsError> {
    let (seed_bytes, jcs) = protocol::compute_seed_drand_only(entry_hash, drand_randomness);

    let result = serde_json::json!({
        "seed": hex::encode(seed_bytes),
        "jcs": jcs,
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// WASM entry point for full verification pipeline.
#[wasm_bindgen]
pub fn verify_wasm(
    draw_id: &str,
    entries_js: JsValue,
    drand_randomness: &str,
    weather_value: Option<String>,
    count: u32,
    expected_results_js: JsValue,
) -> Result<bool, JsError> {
    let entries: Vec<Entry> =
        serde_wasm_bindgen::from_value(entries_js).map_err(|e| JsError::new(&e.to_string()))?;

    let expected: Vec<Winner> = serde_wasm_bindgen::from_value(expected_results_js)
        .map_err(|e| JsError::new(&e.to_string()))?;

    Ok(crate::verify(
        draw_id,
        &entries,
        drand_randomness,
        weather_value.as_deref(),
        count,
        &expected,
    ))
}

/// WASM entry point for verify_receipt.
#[wasm_bindgen]
pub fn verify_receipt_wasm(
    payload_jcs: &str,
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<bool, JsError> {
    let signature_bytes = hex::decode(signature_hex)
        .map_err(|e| JsError::new(&format!("invalid signature hex: {}", e)))?;
    let signature: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| JsError::new("signature must be exactly 64 bytes"))?;

    let key_bytes = hex::decode(public_key_hex)
        .map_err(|e| JsError::new(&format!("invalid public key hex: {}", e)))?;
    let public_key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| JsError::new("public key must be exactly 32 bytes"))?;

    Ok(protocol::crypto::verify_receipt(
        payload_jcs.as_bytes(),
        &signature,
        &public_key,
    ))
}

/// WASM entry point for key_id.
#[wasm_bindgen]
pub fn key_id_wasm(public_key_hex: &str) -> Result<String, JsError> {
    let key_bytes = hex::decode(public_key_hex)
        .map_err(|e| JsError::new(&format!("invalid public key hex: {}", e)))?;
    let public_key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| JsError::new("public key must be exactly 32 bytes"))?;

    Ok(protocol::crypto::key_id(&public_key))
}

/// WASM entry point for build_receipt_payload (lock receipt v2).
#[wasm_bindgen]
pub fn build_receipt_payload_wasm(input_js: JsValue) -> Result<String, JsError> {
    let input: LockReceiptV4 =
        serde_wasm_bindgen::from_value(input_js).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(protocol::receipts::build_receipt_payload(&input))
}

/// WASM entry point for build_execution_receipt_payload.
#[wasm_bindgen]
pub fn build_execution_receipt_payload_wasm(input_js: JsValue) -> Result<String, JsError> {
    let input: ExecutionReceiptV2 =
        serde_wasm_bindgen::from_value(input_js).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(protocol::receipts::build_execution_receipt_payload(&input))
}

/// WASM entry point for lock_receipt_hash.
#[wasm_bindgen]
pub fn lock_receipt_hash_wasm(payload_jcs: &str) -> String {
    protocol::receipts::lock_receipt_hash(payload_jcs)
}

/// WASM entry point for receipt_schema_version.
#[wasm_bindgen]
pub fn receipt_schema_version_wasm(payload_jcs: &str) -> Option<String> {
    protocol::receipts::receipt_schema_version(payload_jcs)
}

/// WASM entry point for merkle_root.
#[wasm_bindgen]
pub fn merkle_root_wasm(leaves_js: JsValue) -> Result<String, JsError> {
    let leaves_strs: Vec<String> =
        serde_wasm_bindgen::from_value(leaves_js).map_err(|e| JsError::new(&e.to_string()))?;

    let leaves_bytes: Vec<Vec<u8>> = leaves_strs.iter().map(|s| s.as_bytes().to_vec()).collect();
    let leaves_refs: Vec<&[u8]> = leaves_bytes.iter().map(|v| v.as_slice()).collect();

    Ok(hex::encode(protocol::merkle::merkle_root(&leaves_refs)))
}

/// WASM entry point for anchor_root.
#[wasm_bindgen]
pub fn anchor_root_wasm(op_root_hex: &str, exec_root_hex: &str) -> Result<String, JsError> {
    let op_bytes = hex::decode(op_root_hex)
        .map_err(|e| JsError::new(&format!("invalid operator root hex: {}", e)))?;
    let op_root: [u8; 32] = op_bytes
        .try_into()
        .map_err(|_| JsError::new("operator root must be exactly 32 bytes"))?;

    let exec_bytes = hex::decode(exec_root_hex)
        .map_err(|e| JsError::new(&format!("invalid execution root hex: {}", e)))?;
    let exec_root: [u8; 32] = exec_bytes
        .try_into()
        .map_err(|_| JsError::new("execution root must be exactly 32 bytes"))?;

    Ok(hex::encode(protocol::merkle::anchor_root(
        &op_root, &exec_root,
    )))
}

/// WASM entry point for the drand check on its own, so the proof page can
/// show it as a separate line. True iff the chain is the pinned quicknet
/// chain, the BLS signature is valid for `round`, and
/// sha256(signature) == randomness.
///
/// Pass every value from the signed execution receipt (`drand_chain`,
/// `drand_round`, `drand_signature`, `drand_randomness`), never from
/// unsigned page data such as the bundle's `entropy` block: a genuine
/// beacon for some other round proves nothing about this draw.
///
/// Hex inputs must be lower case, as the receipt carries them. The chain
/// hash and randomness are compared exactly, so upper case is rejected
/// (fails closed).
///
/// Never a gate: it does not check that the beacon belongs to this draw,
/// fed its seed, or published after the lock. The gate is
/// `verify_bundle_with_resolved_keys_wasm`.
#[wasm_bindgen]
pub fn verify_drand_wasm(
    chain_hash: &str,
    round: u64,
    signature_hex: &str,
    randomness_hex: &str,
) -> bool {
    crate::drand::verify_drand_round(chain_hash, round, signature_hex, randomness_hex).is_ok()
}

/// WASM entry point for `verify_full`.
///
/// **Deprecated: it checks less than the step pipeline.** It is not a
/// gate; the proof page gates on `verify_bundle_with_resolved_keys_wasm`.
/// See `verify_full` for exactly what it does and does not check.
///
/// `winner_count` is extracted from the signed lock receipt, not passed externally.
#[deprecated(note = "checks less than verify_bundle_with; use verify_bundle_with")]
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
#[allow(deprecated)] // wraps verify_full
pub fn verify_full_wasm(
    lock_receipt_jcs: &str,
    lock_signature_hex: &str,
    operator_public_key_hex: &str,
    execution_receipt_jcs: &str,
    execution_signature_hex: &str,
    infrastructure_public_key_hex: &str,
    entries_js: JsValue,
) -> Result<bool, JsError> {
    let lock_sig_bytes = hex::decode(lock_signature_hex)
        .map_err(|e| JsError::new(&format!("invalid lock signature hex: {}", e)))?;
    let lock_sig: [u8; 64] = lock_sig_bytes
        .try_into()
        .map_err(|_| JsError::new("lock signature must be exactly 64 bytes"))?;

    let op_key_bytes = hex::decode(operator_public_key_hex)
        .map_err(|e| JsError::new(&format!("invalid operator public key hex: {}", e)))?;
    let op_key: [u8; 32] = op_key_bytes
        .try_into()
        .map_err(|_| JsError::new("operator public key must be exactly 32 bytes"))?;

    let exec_sig_bytes = hex::decode(execution_signature_hex)
        .map_err(|e| JsError::new(&format!("invalid execution signature hex: {}", e)))?;
    let exec_sig: [u8; 64] = exec_sig_bytes
        .try_into()
        .map_err(|_| JsError::new("execution signature must be exactly 64 bytes"))?;

    let infra_key_bytes = hex::decode(infrastructure_public_key_hex)
        .map_err(|e| JsError::new(&format!("invalid infrastructure public key hex: {}", e)))?;
    let infra_key: [u8; 32] = infra_key_bytes
        .try_into()
        .map_err(|_| JsError::new("infrastructure public key must be exactly 32 bytes"))?;

    let entries: Vec<Entry> =
        serde_wasm_bindgen::from_value(entries_js).map_err(|e| JsError::new(&e.to_string()))?;

    crate::verify_full(
        lock_receipt_jcs,
        &lock_sig,
        &op_key,
        execution_receipt_jcs,
        &exec_sig,
        &infra_key,
        &entries,
    )
    .map_err(|e| JsError::new(&e))
}

/// JS-side representation of a pre-resolved key. The browser fetches the
/// keyring out-of-band (operator endpoint or pinned `.well-known`) and
/// hands the resolved entries in to WASM. Keeping the HTTP layer in JS
/// avoids dragging `reqwest` into the WASM binary.
#[derive(Deserialize)]
struct ResolvedKeyJs {
    key_id: String,
    public_key_hex: String,
    key_class: String,
    inserted_at: String,
}

/// Synthetic resolver wrapping a vector of pre-resolved keys. JS-driven
/// resolvers serialise their lookups across the WASM boundary in one
/// shot, so this lookup is linear over `keys` — fine for the small
/// keyring sizes we expect (<10 entries per operator).
///
/// Pre-resolved keys arrive from out-of-band resolution (the JS layer
/// fetched them from `/operator/:slug/keys` or a `.well-known` pin), so
/// every entry carries a concrete `InsertedAt::At(...)` timestamp; the
/// `Sentinel` variant is reserved for `BundleEmbeddedResolver` in the
/// verifier crate proper.
struct PreResolvedResolver {
    keys: Vec<(String, KeyClass, [u8; 32], String)>,
}

impl KeyResolver for PreResolvedResolver {
    fn resolve(&self, key_id: &str, key_class: KeyClass) -> Result<ResolvedKey, ResolutionError> {
        for (k_id, k_class, pk, inserted_at) in &self.keys {
            if k_id == key_id && *k_class == key_class {
                return Ok(ResolvedKey {
                    public_key: *pk,
                    inserted_at: InsertedAt::At(inserted_at.clone()),
                    key_class: *k_class,
                });
            }
        }
        Err(ResolutionError::KeyNotFound)
    }
}

fn parse_key_class(s: &str) -> Result<KeyClass, JsError> {
    match s {
        "operator" => Ok(KeyClass::Operator),
        "infrastructure" => Ok(KeyClass::Infrastructure),
        other => Err(JsError::new(&format!(
            "unknown key_class: {} (expected \"operator\" or \"infrastructure\")",
            other
        ))),
    }
}

fn parse_verifier_mode(s: &str) -> Result<VerifierMode, JsError> {
    match s {
        "attributable" => Ok(VerifierMode::Attributable),
        "attestable" => Ok(VerifierMode::Attestable),
        "self_consistency_only" => Ok(VerifierMode::SelfConsistencyOnly),
        other => Err(JsError::new(&format!(
            "unknown verifier mode: {} (expected \"attributable\", \"attestable\", \
             or \"self_consistency_only\")",
            other
        ))),
    }
}

/// Verify a whole v5/v4 (resolver-driven) proof bundle in the browser.
///
/// **This is the browser gate.** The proof page's green result must come
/// from this function returning `true` in attestable mode, and from
/// nothing else: not from `verify_drand_wasm`, not from the deprecated
/// `verify_full_wasm`, not from the per-line checks the page shows
/// alongside it.
///
/// It runs the full step pipeline (`verify_bundle_with`): the same checks
/// as the CLI, including the drand BLS signature, the entropy binding and
/// temporal binding.
///
/// Keys: the JS side fetches them out of band and passes them in as
/// `resolved_keys_js`, an array of
/// `{key_id, public_key_hex, key_class, inserted_at}`. For the attestable
/// gate (`mode = "attestable"`) they must come from wallop's
/// `/operator/:slug/keys` endpoint, never from the bundle or other page
/// data: keys taken from the bundle being verified prove only that the
/// bundle agrees with itself. `"attributable"` is for keys checked against
/// a pinned `.well-known` document.
///
/// The `mode` argument is recorded on the report and MUST match the trust
/// root the JS side actually consulted. The verifier crate does not police
/// this association — see `verify_bundle_with`.
///
/// Returns `true` iff the report passes (`VerificationReport::passed`).
/// A bundle that fails to parse, an unknown mode or a malformed key is an
/// `Err`. Per-step diagnostics are not surfaced from this entry point yet.
#[wasm_bindgen]
pub fn verify_bundle_with_resolved_keys_wasm(
    bundle_json: &str,
    resolved_keys_js: JsValue,
    mode: &str,
) -> Result<bool, JsError> {
    let bundle = ProofBundle::from_json(bundle_json).map_err(|e| JsError::new(&e))?;
    let parsed_mode = parse_verifier_mode(mode)?;

    let raw_keys: Vec<ResolvedKeyJs> = serde_wasm_bindgen::from_value(resolved_keys_js)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let mut keys = Vec::with_capacity(raw_keys.len());
    for entry in raw_keys {
        let key_class = parse_key_class(&entry.key_class)?;
        let pk_bytes = hex::decode(&entry.public_key_hex).map_err(|e| {
            JsError::new(&format!(
                "invalid public key hex for {}: {}",
                entry.key_id, e
            ))
        })?;
        let pk: [u8; 32] = pk_bytes.try_into().map_err(|_| {
            JsError::new(&format!("public key for {} is not 32 bytes", entry.key_id))
        })?;
        keys.push((entry.key_id, key_class, pk, entry.inserted_at));
    }

    let resolver = PreResolvedResolver { keys };
    let report = verify_bundle_with(&bundle, &resolver, parsed_mode);
    Ok(report.passed())
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_drand_export_tests {
    use super::verify_drand_wasm;
    use crate::_test_support::{BEACON_RANDOMNESS, BEACON_ROUND, BEACON_SIGNATURE};
    use crate::drand::QUICKNET_CHAIN_HASH;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn accepts_real_beacon() {
        assert!(verify_drand_wasm(
            QUICKNET_CHAIN_HASH,
            BEACON_ROUND,
            BEACON_SIGNATURE,
            BEACON_RANDOMNESS
        ));
    }

    #[wasm_bindgen_test]
    fn rejects_zero_signature() {
        assert!(!verify_drand_wasm(
            QUICKNET_CHAIN_HASH,
            BEACON_ROUND,
            &"00".repeat(48),
            BEACON_RANDOMNESS
        ));
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_resolved_keys_gate_tests {
    use super::verify_bundle_with_resolved_keys_wasm;
    use crate::_test_support::{BEACON_SIGNATURE, build_valid_v5_bundle, resign_exec};
    use crate::Entry;
    use serde::Serialize;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::*;

    fn entries() -> Vec<Entry> {
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

    /// The test key as the keys endpoint would list it, once per class.
    fn resolved_keys(pk_hex: &str, key_id: &str) -> JsValue {
        let keys = serde_json::json!([
            {"key_id": key_id, "public_key_hex": pk_hex, "key_class": "operator",
             "inserted_at": crate::_test_support::KEY_INSERTED_AT},
            {"key_id": key_id, "public_key_hex": pk_hex, "key_class": "infrastructure",
             "inserted_at": crate::_test_support::KEY_INSERTED_AT},
        ]);
        keys.serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .unwrap()
    }

    #[wasm_bindgen_test]
    fn valid_v5_bundle_with_correct_keys_passes() {
        let (json, pk_hex, kid) = build_valid_v5_bundle(&entries(), Some("1013"), 2);
        assert!(
            verify_bundle_with_resolved_keys_wasm(
                &json,
                resolved_keys(&pk_hex, &kid),
                "attestable"
            )
            .unwrap()
        );
    }

    #[wasm_bindgen_test]
    fn zero_drand_signature_fails() {
        // Zero signature in both the re-signed execution receipt and the
        // entropy block, so only the BLS check itself can reject it.
        let zero = "00".repeat(48);
        let (json, pk_hex, kid) = build_valid_v5_bundle(&entries(), Some("1013"), 2);
        let mut val = resign_exec(&json, |exec| {
            assert_eq!(exec["drand_signature"], BEACON_SIGNATURE);
            exec["drand_signature"] = serde_json::json!(zero.clone());
        });
        val["entropy"]["drand_signature"] = serde_json::json!(zero);
        assert!(
            !verify_bundle_with_resolved_keys_wasm(
                &val.to_string(),
                resolved_keys(&pk_hex, &kid),
                "attestable"
            )
            .unwrap()
        );
    }

    #[wasm_bindgen_test]
    fn v6_bundle_passes_the_browser_gate() {
        use crate::_test_support::{V6Params, build_v6_bundle};
        for p in [V6Params::weather(), V6Params::fallback()] {
            let (json, pk_hex, kid) = build_v6_bundle(&p);
            assert!(
                verify_bundle_with_resolved_keys_wasm(
                    &json,
                    resolved_keys(&pk_hex, &kid),
                    "attestable"
                )
                .unwrap()
            );
        }
    }

    #[wasm_bindgen_test]
    fn v6_late_lock_fails_the_browser_gate() {
        use crate::_test_support::{V6Params, build_v6_bundle};
        let p = V6Params {
            locked_at: V6Params::weather().weather_time,
            ..V6Params::weather()
        };
        let (json, pk_hex, kid) = build_v6_bundle(&p);
        assert!(
            !verify_bundle_with_resolved_keys_wasm(
                &json,
                resolved_keys(&pk_hex, &kid),
                "attestable"
            )
            .unwrap()
        );
    }
}
