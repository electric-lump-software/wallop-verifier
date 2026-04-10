pub mod protocol;
mod wasm;

pub use protocol::crypto::{key_id, verify_receipt};
pub use protocol::merkle::{anchor_root, merkle_root};
pub use protocol::receipts::{
    ExecutionReceiptV1, LockReceiptV2, build_execution_receipt_payload, build_receipt_payload,
    lock_receipt_hash, receipt_schema_version,
};
pub use protocol::{compute_seed, compute_seed_drand_only, entry_hash};

// Re-export fair_pick_rs types for convenience
pub use fair_pick_rs::{Entry, Winner, draw};

/// Full v2 verification pipeline.
///
/// Chains: sig checks → lock receipt parse → linkage → entry_hash → seed → draw → compare.
/// `winner_count` is extracted from the signed lock receipt, not passed externally.
/// Returns Ok(true) if all checks pass, Ok(false) if any check fails,
/// Err with reason if inputs are structurally invalid (unparseable JSON).
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

    let weather_value = exec_parsed.get("weather_value").and_then(|v| v.as_str());

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

    // Step 6: Verify entry_hash
    let (computed_entry_hash, _) = entry_hash(entries);
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

    Ok(true)
}

/// Verify a draw result by recomputing the full pipeline.
///
/// Chains: entry_hash → compute_seed → draw → compare.
/// Returns true if the recomputed results match `expected_results` exactly.
pub fn verify(
    entries: &[Entry],
    drand_randomness: &str,
    weather_value: Option<&str>,
    count: u32,
    expected_results: &[Winner],
) -> bool {
    let (ehash, _) = entry_hash(entries);

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
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const END_TO_END_VECTOR: &str = include_str!("../vendor/wallop/spec/vectors/end-to-end.json");

    fn entries_from_json(arr: &[serde_json::Value]) -> Vec<Entry> {
        arr.iter()
            .map(|e| Entry {
                id: e["id"].as_str().unwrap().into(),
                weight: e["weight"].as_u64().unwrap() as u32,
            })
            .collect()
    }

    #[test]
    fn verify_returns_true_for_matching_results() {
        let vector: serde_json::Value = serde_json::from_str(END_TO_END_VECTOR).unwrap();
        let input = &vector["input"];
        let expected = &vector["expected"];

        let entries = entries_from_json(input["entries"].as_array().unwrap());
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

        let entries = entries_from_json(input["entries"].as_array().unwrap());
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

        assert!(!verify(&entries, drand, Some(weather), count, &wrong));
    }

    #[test]
    fn verify_drand_only() {
        let entries = vec![
            Entry {
                id: "a".into(),
                weight: 1,
            },
            Entry {
                id: "b".into(),
                weight: 1,
            },
        ];
        let drand = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        // Compute expected results via the pipeline
        let (ehash, _) = entry_hash(&entries);
        let (seed, _) = compute_seed_drand_only(&ehash, drand);
        let expected = fair_pick_rs::draw(&entries, &seed, 2).unwrap();

        assert!(verify(&entries, drand, None, 2, &expected));
    }

    fn test_signing_key() -> SigningKey {
        let secret_bytes: [u8; 32] =
            hex::decode("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60")
                .unwrap()
                .try_into()
                .unwrap();
        SigningKey::from_bytes(&secret_bytes)
    }

    #[test]
    fn verify_full_extracts_winner_count_from_lock_receipt() {
        let sk = test_signing_key();
        let pk: [u8; 32] = sk.verifying_key().to_bytes();

        // Build a lock receipt with winner_count embedded
        let lock_jcs = serde_json::json!({
            "schema_version": "2",
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
        let lock_jcs = r#"{"schema_version":"2","sequence":1}"#;
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
    fn verify_full_rejects_non_string_results() {
        let sk = test_signing_key();
        let pk: [u8; 32] = sk.verifying_key().to_bytes();

        // Build a lock receipt with winner_count and sign it
        let lock_jcs = serde_json::json!({
            "schema_version": "2",
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
