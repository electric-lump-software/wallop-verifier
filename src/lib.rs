pub mod bundle;
pub mod key_resolver;
pub mod protocol;
pub mod verify_steps;
mod wasm;

#[cfg(feature = "cli")]
pub mod anchors;

pub mod drand;

/// Internal catalog infrastructure for the `wallop-verify selftest` command.
/// Not a stable API — exposed as `pub` only because the binary target needs
/// to reach `catalog::run_shipping_catalog()`. Do not depend on this module
/// from external crates.
#[cfg(feature = "cli")]
#[doc(hidden)]
pub mod catalog;

#[doc(hidden)]
pub mod _test_support;

// Re-export StepName at the crate root so library consumers can pattern-match
// on StepResult::name without drilling through the verify_steps module.
pub use verify_steps::StepName;

pub use protocol::crypto::{key_id, verify_receipt};
pub use protocol::merkle::{anchor_root, merkle_root};
pub use protocol::receipts::{
    EXECUTION_SCHEMA_VERSION, EXECUTION_SCHEMA_VERSION_V3, ExecutionReceiptV2, ExecutionReceiptV3,
    LOCK_SCHEMA_VERSION, LockReceiptV4, ParseExecutionReceiptError, ParsedExecutionReceipt,
    build_execution_receipt_payload, build_execution_receipt_payload_v3, build_receipt_payload,
    lock_receipt_hash, parse_execution_receipt, receipt_schema_version,
    validate_execution_receipt_tags, validate_execution_receipt_tags_v3,
    validate_lock_receipt_tags,
};
pub use protocol::{compute_seed, compute_seed_drand_only, entry_hash};

// Re-export fair_pick_rs types for convenience
pub use fair_pick_rs::{Entry, Winner, draw};

/// Receipt-level verification of a lock / execution receipt pair.
///
/// **Deprecated: it checks less than the step pipeline.** Use
/// `verify_steps::verify_bundle_with` (or `verify_bundle` for legacy
/// inline-key bundles) and gate on `VerificationReport::passed()`.
///
/// What it checks, in order: both Ed25519 signatures against the keys the
/// caller passes in; `lock_receipt_hash` linkage; `entry_hash` on both
/// receipts against the recomputed value; the seed, recomputed from the
/// execution receipt's `drand_randomness` and `weather_value`; the draw,
/// recomputed with the lock receipt's `winner_count` and compared with the
/// execution receipt's `results`; that both receipts name the same drand
/// round and chain; the drand BLS signature and randomness on the pinned
/// quicknet chain; and that the round published strictly after the lock
/// receipt's `locked_at`.
///
/// What it does not check, and the step pipeline does: receipt shape
/// (typed schema parse, algorithm tags, canonical timestamps), the other
/// cross-receipt fields (`draw_id`, `operator_id`, `sequence`,
/// `weather_station`), the weather observation window and fallback reason,
/// key resolution and temporal binding (it trusts whatever keys it is
/// given), and anything in the proof bundle outside the two receipts
/// (the `entropy` block, `results`).
///
/// Returns `Ok(true)` if every check above passes, `Ok(false)` if any
/// fails, and `Err` if the inputs are structurally invalid (unparseable
/// JSON or a missing field).
#[deprecated(note = "checks less than verify_bundle_with; use verify_bundle_with")]
#[allow(clippy::too_many_arguments)]
pub fn verify_full(
    lock_receipt_jcs: &str,
    lock_signature: &[u8; 64],
    operator_public_key: &[u8; 32],
    execution_receipt_jcs: &str,
    execution_signature: &[u8; 64],
    infrastructure_public_key: &[u8; 32],
    entries: &[Entry],
) -> Result<bool, String> {
    // Step 1: Verify lock receipt signature
    if !protocol::crypto::verify_receipt(
        lock_receipt_jcs.as_bytes(),
        lock_signature,
        operator_public_key,
    ) {
        return Ok(false);
    }

    // Step 2: Verify execution receipt signature
    if !protocol::crypto::verify_receipt(
        execution_receipt_jcs.as_bytes(),
        execution_signature,
        infrastructure_public_key,
    ) {
        return Ok(false);
    }

    // Step 3: Extract winner_count from the signed lock receipt
    let lock_parsed: serde_json::Value = serde_json::from_str(lock_receipt_jcs)
        .map_err(|e| format!("invalid lock receipt JSON: {}", e))?;

    let count = lock_parsed
        .get("winner_count")
        .and_then(|v| v.as_u64())
        .ok_or("missing or invalid winner_count in lock receipt")?;
    let count =
        u32::try_from(count).map_err(|_| format!("winner_count {} exceeds u32::MAX", count))?;

    // Step 4: Check lock_receipt_hash linkage
    let exec_parsed: serde_json::Value = serde_json::from_str(execution_receipt_jcs)
        .map_err(|e| format!("invalid execution receipt JSON: {}", e))?;

    let expected_lock_hash = protocol::receipts::lock_receipt_hash(lock_receipt_jcs);
    let actual_lock_hash = exec_parsed
        .get("lock_receipt_hash")
        .and_then(|v| v.as_str())
        .ok_or("missing lock_receipt_hash in execution receipt")?;

    if actual_lock_hash != expected_lock_hash {
        return Ok(false);
    }

    // Step 5: Extract fields from execution receipt
    let exec_entry_hash = exec_parsed
        .get("entry_hash")
        .and_then(|v| v.as_str())
        .ok_or("missing entry_hash in execution receipt")?;

    let drand_randomness = exec_parsed
        .get("drand_randomness")
        .and_then(|v| v.as_str())
        .ok_or("missing drand_randomness in execution receipt")?;

    // Absent or null means a drand-only draw. Any other non-string value
    // is malformed, not "no weather".
    let weather_value = match exec_parsed.get("weather_value").filter(|v| !v.is_null()) {
        None => None,
        Some(v) => Some(
            v.as_str()
                .ok_or("weather_value in execution receipt is not a string")?,
        ),
    };

    let exec_seed = exec_parsed
        .get("seed")
        .and_then(|v| v.as_str())
        .ok_or("missing seed in execution receipt")?;

    let exec_results = exec_parsed
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or("missing results in execution receipt")?;

    let expected_ids: Vec<&str> = exec_results
        .iter()
        .enumerate()
        .map(|(i, v)| v.as_str().ok_or(format!("results[{}] is not a string", i)))
        .collect::<Result<Vec<&str>, String>>()?;

    // Step 6: Verify entry_hash (both receipts)
    // draw_id is bound into the hash; pull it from the signed lock receipt.
    let draw_id = lock_parsed
        .get("draw_id")
        .and_then(|v| v.as_str())
        .ok_or("missing draw_id in lock receipt")?;
    let (computed_entry_hash, _) = entry_hash(draw_id, entries);

    let lock_entry_hash = lock_parsed
        .get("entry_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if computed_entry_hash != lock_entry_hash {
        return Ok(false);
    }

    if computed_entry_hash != exec_entry_hash {
        return Ok(false);
    }

    // Step 7: Recompute seed
    let (computed_seed, _) = match weather_value {
        Some(w) => compute_seed(&computed_entry_hash, drand_randomness, w),
        None => compute_seed_drand_only(&computed_entry_hash, drand_randomness),
    };

    if hex::encode(computed_seed) != exec_seed {
        return Ok(false);
    }

    // Step 8: Recompute draw
    let computed_results =
        draw(entries, &computed_seed, count).map_err(|e| format!("draw failed: {}", e))?;

    let computed_ids: Vec<&str> = computed_results
        .iter()
        .map(|w| w.entry_id.as_str())
        .collect();

    if computed_ids != expected_ids {
        return Ok(false);
    }

    // Step 9: drand. The randomness must be the genuine quicknet beacon
    // for the round the lock receipt committed to.
    let lock_round = lock_parsed
        .get("drand_round")
        .and_then(|v| v.as_u64())
        .ok_or("missing drand_round in lock receipt")?;
    let lock_chain = lock_parsed
        .get("drand_chain")
        .and_then(|v| v.as_str())
        .ok_or("missing drand_chain in lock receipt")?;
    let exec_round = exec_parsed
        .get("drand_round")
        .and_then(|v| v.as_u64())
        .ok_or("missing drand_round in execution receipt")?;
    let exec_chain = exec_parsed
        .get("drand_chain")
        .and_then(|v| v.as_str())
        .ok_or("missing drand_chain in execution receipt")?;
    let drand_signature = exec_parsed
        .get("drand_signature")
        .and_then(|v| v.as_str())
        .ok_or("missing drand_signature in execution receipt")?;

    if exec_round != lock_round || exec_chain != lock_chain {
        return Ok(false);
    }
    if crate::drand::verify_drand_round(exec_chain, exec_round, drand_signature, drand_randomness)
        .is_err()
    {
        return Ok(false);
    }

    // Step 10: the round must publish strictly after the lock. `locked_at`
    // is the lock signer's claim, so this is a consistency check.
    let locked_at = lock_parsed
        .get("locked_at")
        .and_then(|v| v.as_str())
        .ok_or("missing locked_at in lock receipt")?;
    if verify_steps::drand_round_after_lock(exec_round, locked_at).is_err() {
        return Ok(false);
    }

    Ok(true)
}

/// Verify a draw result by recomputing the full pipeline.
///
/// Chains: entry_hash → compute_seed → draw → compare.
/// Returns true if the recomputed results match `expected_results` exactly.
pub fn verify(
    draw_id: &str,
    entries: &[Entry],
    drand_randomness: &str,
    weather_value: Option<&str>,
    count: u32,
    expected_results: &[Winner],
) -> bool {
    let (ehash, _) = entry_hash(draw_id, entries);

    let (seed, _) = match weather_value {
        Some(w) => compute_seed(&ehash, drand_randomness, w),
        None => compute_seed_drand_only(&ehash, drand_randomness),
    };

    match draw(entries, &seed, count) {
        Ok(results) => results == expected_results,
        Err(_) => false,
    }
}

#[cfg(test)]
#[allow(deprecated)] // exercises verify_full
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const END_TO_END_VECTOR: &str = include_str!("../vendor/wallop/spec/vectors/end-to-end.json");

    fn entries_from_bundle_json(arr: &[serde_json::Value]) -> Vec<Entry> {
        arr.iter()
            .map(|e| Entry {
                id: e["uuid"].as_str().unwrap().into(),
                weight: e["weight"].as_u64().unwrap() as u32,
            })
            .collect()
    }

    #[test]
    fn verify_returns_true_for_matching_results() {
        let vector: serde_json::Value = serde_json::from_str(END_TO_END_VECTOR).unwrap();
        let input = &vector["input"];
        let expected = &vector["expected"];

        let draw_id = input["draw_id"].as_str().unwrap();
        let entries = entries_from_bundle_json(input["entries"].as_array().unwrap());
        let drand = input["drand_randomness"].as_str().unwrap();
        let weather = input["weather_value"].as_str().unwrap();
        let count = input["winner_count"].as_u64().unwrap() as u32;

        let expected_winners: Vec<Winner> = expected["winners"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, v)| Winner {
                position: (i + 1) as u32,
                entry_id: v.as_str().unwrap().into(),
            })
            .collect();

        assert!(verify(
            draw_id,
            &entries,
            drand,
            Some(weather),
            count,
            &expected_winners
        ));
    }

    #[test]
    fn verify_returns_false_for_wrong_results() {
        let vector: serde_json::Value = serde_json::from_str(END_TO_END_VECTOR).unwrap();
        let input = &vector["input"];
        let expected = &vector["expected"];

        let draw_id = input["draw_id"].as_str().unwrap();
        let entries = entries_from_bundle_json(input["entries"].as_array().unwrap());
        let drand = input["drand_randomness"].as_str().unwrap();
        let weather = input["weather_value"].as_str().unwrap();
        let count = input["winner_count"].as_u64().unwrap() as u32;

        // Reverse the expected winners to create wrong results
        let mut wrong: Vec<Winner> = expected["winners"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, v)| Winner {
                position: (i + 1) as u32,
                entry_id: v.as_str().unwrap().into(),
            })
            .collect();
        wrong.reverse();

        assert!(!verify(
            draw_id,
            &entries,
            drand,
            Some(weather),
            count,
            &wrong
        ));
    }

    #[test]
    fn verify_drand_only() {
        let draw_id = "11111111-1111-4111-8111-111111111111";
        let entries = vec![
            Entry {
                id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                weight: 1,
            },
            Entry {
                id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
                weight: 1,
            },
        ];
        let drand = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        // Compute expected results via the pipeline
        let (ehash, _) = entry_hash(draw_id, &entries);
        let (seed, _) = compute_seed_drand_only(&ehash, drand);
        let expected = fair_pick_rs::draw(&entries, &seed, 2).unwrap();

        assert!(verify(draw_id, &entries, drand, None, 2, &expected));
    }

    fn test_signing_key() -> SigningKey {
        let secret_bytes: [u8; 32] =
            hex::decode("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60")
                .unwrap()
                .try_into()
                .unwrap();
        SigningKey::from_bytes(&secret_bytes)
    }

    struct SignedPair {
        lock: String,
        lock_sig: [u8; 64],
        exec: String,
        exec_sig: [u8; 64],
        pk: [u8; 32],
        entries: Vec<Entry>,
    }

    impl SignedPair {
        fn run(&self) -> Result<bool, String> {
            verify_full(
                &self.lock,
                &self.lock_sig,
                &self.pk,
                &self.exec,
                &self.exec_sig,
                &self.pk,
                &self.entries,
            )
        }
    }

    fn signed_pair_with_randomness(
        randomness: &str,
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> SignedPair {
        signed_pair_edited(randomness, |_| {}, edit)
    }

    fn signed_pair_edited(
        randomness: &str,
        lock_edit: impl FnOnce(&mut serde_json::Value),
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> SignedPair {
        use crate::_test_support::{BEACON_ROUND, BEACON_SIGNATURE};
        let sk = test_signing_key();
        let pk = sk.verifying_key().to_bytes();
        let draw_id = "22222222-2222-2222-2222-222222222222";
        let entries = vec![
            Entry {
                id: "11111111-1111-1111-1111-111111111111".into(),
                weight: 1,
            },
            Entry {
                id: "33333333-3333-3333-3333-333333333333".into(),
                weight: 1,
            },
            Entry {
                id: "44444444-4444-4444-4444-444444444444".into(),
                weight: 1,
            },
        ];
        let (ehash, _) = entry_hash(draw_id, &entries);
        let (seed, _) = compute_seed(&ehash, randomness, "1013");
        let winners: Vec<String> = draw(&entries, &seed, 1)
            .unwrap()
            .into_iter()
            .map(|w| w.entry_id)
            .collect();

        let mut lock = serde_json::json!({
            "draw_id": draw_id,
            "winner_count": 1,
            "entry_hash": ehash,
            "drand_chain": crate::drand::QUICKNET_CHAIN_HASH,
            "drand_round": BEACON_ROUND,
            "locked_at": "2023-08-23T15:50:00.000000Z",
        });
        lock_edit(&mut lock);
        let lock = lock.to_string();
        let lock_sig = sk.sign(lock.as_bytes()).to_bytes();

        let mut exec = serde_json::json!({
            "lock_receipt_hash": protocol::receipts::lock_receipt_hash(&lock),
            "entry_hash": ehash,
            "drand_chain": crate::drand::QUICKNET_CHAIN_HASH,
            "drand_round": BEACON_ROUND,
            "drand_signature": BEACON_SIGNATURE,
            "drand_randomness": randomness,
            "weather_value": "1013",
            "seed": hex::encode(seed),
            "results": winners,
        });
        edit(&mut exec);
        let exec = exec.to_string();
        let exec_sig = sk.sign(exec.as_bytes()).to_bytes();

        SignedPair {
            lock,
            lock_sig,
            exec,
            exec_sig,
            pk,
            entries,
        }
    }

    fn signed_pair_with(edit: impl FnOnce(&mut serde_json::Value)) -> SignedPair {
        signed_pair_with_randomness(crate::_test_support::BEACON_RANDOMNESS, edit)
    }

    #[test]
    fn verify_full_rejects_fake_drand_signature() {
        let args = signed_pair_with(|exec| {
            exec["drand_signature"] = serde_json::json!("00".repeat(48));
        });
        assert_eq!(args.run(), Ok(false));
    }

    #[test]
    fn verify_full_rejects_randomness_not_from_signature() {
        // Genuine signature for round 1000, but randomness from round 1001,
        // with seed and winners recomputed from that randomness, so only
        // the drand check can catch it.
        let args = signed_pair_with_randomness(crate::_test_support::BEACON_2_RANDOMNESS, |_| {});
        assert_eq!(args.run(), Ok(false));
    }

    #[test]
    fn verify_full_rejects_exec_round_different_from_lock() {
        // Exec carries the genuine round-1001 beacon, but lock committed round 1000.
        let args = signed_pair_with_randomness(crate::_test_support::BEACON_2_RANDOMNESS, |exec| {
            exec["drand_round"] = serde_json::json!(crate::_test_support::BEACON_2_ROUND);
            exec["drand_signature"] = serde_json::json!(crate::_test_support::BEACON_2_SIGNATURE);
        });
        assert_eq!(args.run(), Ok(false));
    }

    #[test]
    fn verify_full_rejects_exec_chain_different_from_lock() {
        let args = signed_pair_with(|exec| {
            exec["drand_chain"] = serde_json::json!("00".repeat(32));
        });
        assert_eq!(args.run(), Ok(false));
    }

    #[test]
    fn verify_full_errors_when_lock_lacks_drand_round() {
        let args = signed_pair_edited(
            crate::_test_support::BEACON_RANDOMNESS,
            |lock| {
                lock.as_object_mut().unwrap().remove("drand_round");
            },
            |_| {},
        );
        let result = args.run();
        assert!(
            matches!(&result, Err(e) if e.contains("drand_round") && e.contains("lock receipt")),
            "got {result:?}"
        );
    }

    #[test]
    fn verify_full_errors_when_weather_value_is_not_a_string() {
        // A numeric weather_value must not be read as "no weather" and
        // fall through to the drand-only seed.
        let args = signed_pair_with(|exec| {
            exec["weather_value"] = serde_json::json!(1013);
        });
        let result = args.run();
        assert!(
            matches!(&result, Err(e) if e.contains("weather_value")),
            "got {result:?}"
        );
    }

    #[test]
    fn verify_full_rejects_round_published_before_lock() {
        // Round 1000 published at 2023-08-23T15:59:24Z.
        let pair = signed_pair_edited(
            crate::_test_support::BEACON_RANDOMNESS,
            |lock| lock["locked_at"] = serde_json::json!("2023-08-23T15:59:30.000000Z"),
            |_| {},
        );
        assert_eq!(pair.run(), Ok(false));
    }

    #[test]
    fn verify_full_errors_when_lock_lacks_locked_at() {
        let pair = signed_pair_edited(
            crate::_test_support::BEACON_RANDOMNESS,
            |lock| {
                lock.as_object_mut().unwrap().remove("locked_at");
            },
            |_| {},
        );
        let result = pair.run();
        assert!(
            matches!(&result, Err(e) if e.contains("locked_at")),
            "got {result:?}"
        );
    }

    #[test]
    fn verify_full_accepts_genuine_beacon() {
        assert_eq!(signed_pair_with(|_| {}).run(), Ok(true));
    }

    #[test]
    fn verify_full_extracts_winner_count_from_lock_receipt() {
        let sk = test_signing_key();
        let pk: [u8; 32] = sk.verifying_key().to_bytes();

        // Build a lock receipt with winner_count embedded
        let lock_jcs = serde_json::json!({
            "schema_version": "3",
            "draw_id": "22222222-2222-2222-2222-222222222222",
            "winner_count": 2,
            "sequence": 1
        })
        .to_string();
        let lock_sig: [u8; 64] = sk.sign(lock_jcs.as_bytes()).to_bytes();

        let lock_hash = protocol::receipts::lock_receipt_hash(&lock_jcs);

        // Build execution receipt — winner_count is NOT here, it comes from lock receipt
        let exec_jcs = serde_json::json!({
            "drand_randomness": "aa",
            "entry_hash": "bb",
            "lock_receipt_hash": lock_hash,
            "results": ["ticket-47", "ticket-49"],
            "seed": "cc",
            "weather_value": "1013"
        })
        .to_string();
        let exec_sig: [u8; 64] = sk.sign(exec_jcs.as_bytes()).to_bytes();

        let entries = vec![Entry {
            id: "x".into(),
            weight: 1,
        }];

        // No count parameter — verify_full should extract it from lock receipt
        let result = verify_full(
            &lock_jcs, &lock_sig, &pk, &exec_jcs, &exec_sig, &pk, &entries,
        );

        // Will return Ok(false) because entry_hash won't match, but the point is
        // it didn't need a count parameter and didn't error on winner_count extraction
        assert!(result.is_ok());
    }

    #[test]
    fn verify_full_errors_on_missing_winner_count() {
        let sk = test_signing_key();
        let pk: [u8; 32] = sk.verifying_key().to_bytes();

        // Lock receipt WITHOUT winner_count
        let lock_jcs = r#"{"draw_id":"22222222-2222-2222-2222-222222222222","schema_version":"3","sequence":1}"#;
        let lock_sig: [u8; 64] = sk.sign(lock_jcs.as_bytes()).to_bytes();

        let lock_hash = protocol::receipts::lock_receipt_hash(lock_jcs);

        let exec_jcs = serde_json::json!({
            "drand_randomness": "aa",
            "entry_hash": "bb",
            "lock_receipt_hash": lock_hash,
            "results": ["ticket-47"],
            "seed": "cc",
            "weather_value": "1013"
        })
        .to_string();
        let exec_sig: [u8; 64] = sk.sign(exec_jcs.as_bytes()).to_bytes();

        let entries = vec![Entry {
            id: "x".into(),
            weight: 1,
        }];

        let result = verify_full(
            lock_jcs, &lock_sig, &pk, &exec_jcs, &exec_sig, &pk, &entries,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("winner_count"));
    }

    #[test]
    fn verify_full_checks_lock_receipt_entry_hash() {
        let sk = test_signing_key();
        let pk: [u8; 32] = sk.verifying_key().to_bytes();

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
        let draw_id = "22222222-2222-2222-2222-222222222222";
        let (real_entry_hash, _) = entry_hash(draw_id, &entries);

        // Lock receipt with WRONG entry_hash (but exec receipt has correct one)
        let lock_jcs = serde_json::json!({
            "schema_version": "3",
            "draw_id": "22222222-2222-2222-2222-222222222222",
            "winner_count": 2,
            "sequence": 1,
            "entry_hash": "0000000000000000000000000000000000000000000000000000000000000000"
        })
        .to_string();
        let lock_sig: [u8; 64] = sk.sign(lock_jcs.as_bytes()).to_bytes();
        let lock_hash = protocol::receipts::lock_receipt_hash(&lock_jcs);

        let exec_jcs = serde_json::json!({
            "drand_randomness": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "entry_hash": &real_entry_hash,
            "lock_receipt_hash": lock_hash,
            "results": ["ticket-48", "ticket-47"],
            "seed": "cc",
            "weather_value": "1013"
        })
        .to_string();
        let exec_sig: [u8; 64] = sk.sign(exec_jcs.as_bytes()).to_bytes();

        let result = verify_full(
            &lock_jcs, &lock_sig, &pk, &exec_jcs, &exec_sig, &pk, &entries,
        );

        // Should fail because lock receipt entry_hash doesn't match
        assert_eq!(
            result,
            Ok(false),
            "verify_full should reject when lock receipt entry_hash differs from computed"
        );
    }

    #[test]
    fn verify_full_rejects_non_string_results() {
        let sk = test_signing_key();
        let pk: [u8; 32] = sk.verifying_key().to_bytes();

        // Build a lock receipt with winner_count and sign it
        let lock_jcs = serde_json::json!({
            "schema_version": "3",
            "draw_id": "22222222-2222-2222-2222-222222222222",
            "sequence": 1,
            "winner_count": 1
        })
        .to_string();
        let lock_sig: [u8; 64] = sk.sign(lock_jcs.as_bytes()).to_bytes();

        // Compute lock_receipt_hash
        let lock_hash = protocol::receipts::lock_receipt_hash(&lock_jcs);

        // Build execution receipt with a null in results
        let exec_jcs = serde_json::json!({
            "drand_randomness": "aa",
            "entry_hash": "bb",
            "lock_receipt_hash": lock_hash,
            "results": ["ticket-47", null, "ticket-49"],
            "seed": "cc",
            "weather_value": "1013"
        })
        .to_string();
        let exec_sig: [u8; 64] = sk.sign(exec_jcs.as_bytes()).to_bytes();

        let entries = vec![Entry {
            id: "x".into(),
            weight: 1,
        }];

        let result = verify_full(
            &lock_jcs, &lock_sig, &pk, &exec_jcs, &exec_sig, &pk, &entries,
        );

        assert!(
            result.is_err(),
            "expected Err for non-string results element, got {:?}",
            result
        );
        assert!(
            result.unwrap_err().contains("not a string"),
            "error should mention non-string element"
        );
    }
}
