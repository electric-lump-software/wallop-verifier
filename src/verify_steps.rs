use crate::bundle::ProofBundle;
use crate::protocol::crypto;
use crate::protocol::receipts::lock_receipt_hash;
use crate::{Entry, compute_seed, compute_seed_drand_only, draw, entry_hash};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable identifier for each verification step. Used by the tamper scenario
/// catalog to declare which step must reject a given scenario.
///
/// Always public, never feature-gated — library consumers may pattern-match
/// on `StepResult::name` from outside the crate.
///
/// Serde `rename_all = "snake_case"` means the JSON wire form is
/// `entry_hash`, `lock_signature`, etc. `Display` produces the human-friendly
/// form (`"Entry hash"`, `"Lock receipt signature"`) used in CLI output.
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StepName {
    EntryHash,
    LockSignature,
    ExecSignature,
    ReceiptLinkage,
    LockReceiptEntryHash,
    ExecReceiptEntryHash,
    SeedRecomputation,
    WinnerSelection,
    DrandBlsSignature,
}

impl StepName {
    /// Returns all variants in a stable order. Used by the catalog's runtime
    /// coverage check to iterate across every step without manual enumeration.
    pub const fn all() -> &'static [StepName] {
        &[
            StepName::EntryHash,
            StepName::LockSignature,
            StepName::ExecSignature,
            StepName::ReceiptLinkage,
            StepName::LockReceiptEntryHash,
            StepName::ExecReceiptEntryHash,
            StepName::SeedRecomputation,
            StepName::WinnerSelection,
            StepName::DrandBlsSignature,
        ]
    }
}

impl fmt::Display for StepName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            StepName::EntryHash => "Entry hash",
            StepName::LockSignature => "Lock receipt signature",
            StepName::ExecSignature => "Exec receipt signature",
            StepName::ReceiptLinkage => "Receipt linkage",
            StepName::LockReceiptEntryHash => "Entry hash (lock receipt)",
            StepName::ExecReceiptEntryHash => "Entry hash (exec receipt)",
            StepName::SeedRecomputation => "Seed recomputation",
            StepName::WinnerSelection => "Winner selection",
            StepName::DrandBlsSignature => "Drand BLS signature",
        };
        f.write_str(s)
    }
}

#[derive(Debug, PartialEq)]
pub enum StepStatus {
    Pass,
    Fail(String),
    Skip(String),
}

#[derive(Debug, PartialEq)]
pub enum StepDetail {
    HexMismatch { expected: String, computed: String },
}

#[derive(Debug)]
pub struct StepResult {
    pub name: StepName,
    pub status: StepStatus,
    pub detail: Option<StepDetail>,
}

pub struct VerificationReport {
    pub steps: Vec<StepResult>,
    pub operator_key_id: Option<String>,
    pub infra_key_id: Option<String>,
}

impl VerificationReport {
    pub fn passed(&self) -> bool {
        self.steps
            .iter()
            .all(|s| matches!(s.status, StepStatus::Pass | StepStatus::Skip(_)))
            && self
                .steps
                .iter()
                .any(|s| matches!(s.status, StepStatus::Pass))
    }

    pub fn error_count(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| matches!(s.status, StepStatus::Fail(_)))
            .count()
    }
}

pub fn verify_bundle(bundle: &ProofBundle) -> VerificationReport {
    let mut steps = Vec::new();

    // Decode keys for key_id display
    let op_pk = hex::decode(&bundle.lock_receipt.public_key_hex)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok());
    let infra_pk = hex::decode(&bundle.execution_receipt.public_key_hex)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok());

    let operator_key_id = op_pk.as_ref().map(crypto::key_id);
    let infra_key_id = infra_pk.as_ref().map(crypto::key_id);

    // Convert bundle entries to fair_pick Entry type
    let entries: Vec<Entry> = bundle
        .entries
        .iter()
        .map(|e| Entry {
            id: e.id.clone(),
            weight: e.weight,
        })
        .collect();

    // === Step 1: Entry hash ===
    let (computed_entry_hash, _) = entry_hash(&entries);
    steps.push(StepResult {
        name: StepName::EntryHash,
        status: StepStatus::Pass,
        detail: None,
    });

    // === Step 2: Lock receipt signature ===
    let lock_sig = hex::decode(&bundle.lock_receipt.signature_hex)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok());
    let step2_pass = match (&lock_sig, &op_pk) {
        (Some(sig), Some(pk)) => {
            crypto::verify_receipt(bundle.lock_receipt.payload_jcs.as_bytes(), sig, pk)
        }
        _ => false,
    };
    steps.push(StepResult {
        name: StepName::LockSignature,
        status: if step2_pass {
            StepStatus::Pass
        } else {
            StepStatus::Fail("Ed25519 signature invalid".into())
        },
        detail: None,
    });

    // === Step 3: Exec receipt signature ===
    let exec_sig = hex::decode(&bundle.execution_receipt.signature_hex)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok());
    let step3_pass = match (&exec_sig, &infra_pk) {
        (Some(sig), Some(pk)) => {
            crypto::verify_receipt(bundle.execution_receipt.payload_jcs.as_bytes(), sig, pk)
        }
        _ => false,
    };
    steps.push(StepResult {
        name: StepName::ExecSignature,
        status: if step3_pass {
            StepStatus::Pass
        } else {
            StepStatus::Fail("Ed25519 signature invalid".into())
        },
        detail: None,
    });

    // === Step 4: Receipt linkage ===
    if !step2_pass || !step3_pass {
        steps.push(StepResult {
            name: StepName::ReceiptLinkage,
            status: StepStatus::Skip("signature check failed".into()),
            detail: None,
        });
    } else {
        let computed_lrh = lock_receipt_hash(&bundle.lock_receipt.payload_jcs);
        let exec_parsed: serde_json::Value =
            serde_json::from_str(&bundle.execution_receipt.payload_jcs).unwrap_or_default();
        let exec_lrh = exec_parsed
            .get("lock_receipt_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let step4_pass = computed_lrh == exec_lrh;
        let step4_detail = if step4_pass {
            None
        } else {
            Some(StepDetail::HexMismatch {
                expected: computed_lrh.clone(),
                computed: exec_lrh.to_string(),
            })
        };
        steps.push(StepResult {
            name: StepName::ReceiptLinkage,
            status: if step4_pass {
                StepStatus::Pass
            } else {
                StepStatus::Fail(format!("expected {}, got {}", computed_lrh, exec_lrh))
            },
            detail: step4_detail,
        });
    }

    // === Step 5a: Lock receipt entry_hash ===
    if !step2_pass {
        steps.push(StepResult {
            name: StepName::LockReceiptEntryHash,
            status: StepStatus::Skip("lock signature failed".into()),
            detail: None,
        });
    } else {
        let lock_parsed: serde_json::Value =
            serde_json::from_str(&bundle.lock_receipt.payload_jcs).unwrap_or_default();
        let lock_eh = lock_parsed
            .get("entry_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let step5a_pass = computed_entry_hash == lock_eh;
        let step5a_detail = if step5a_pass {
            None
        } else {
            Some(StepDetail::HexMismatch {
                expected: computed_entry_hash.clone(),
                computed: lock_eh.to_string(),
            })
        };
        steps.push(StepResult {
            name: StepName::LockReceiptEntryHash,
            status: if step5a_pass {
                StepStatus::Pass
            } else {
                StepStatus::Fail(format!("expected {}, got {}", computed_entry_hash, lock_eh))
            },
            detail: step5a_detail,
        });
    }

    // === Step 5b: Exec receipt entry_hash ===
    if !step3_pass {
        steps.push(StepResult {
            name: StepName::ExecReceiptEntryHash,
            status: StepStatus::Skip("exec signature failed".into()),
            detail: None,
        });
    } else {
        let exec_parsed: serde_json::Value =
            serde_json::from_str(&bundle.execution_receipt.payload_jcs).unwrap_or_default();
        let exec_eh = exec_parsed
            .get("entry_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let step5b_pass = computed_entry_hash == exec_eh;
        let step5b_detail = if step5b_pass {
            None
        } else {
            Some(StepDetail::HexMismatch {
                expected: computed_entry_hash.clone(),
                computed: exec_eh.to_string(),
            })
        };
        steps.push(StepResult {
            name: StepName::ExecReceiptEntryHash,
            status: if step5b_pass {
                StepStatus::Pass
            } else {
                StepStatus::Fail(format!("expected {}, got {}", computed_entry_hash, exec_eh))
            },
            detail: step5b_detail,
        });
    }

    // === Step 6: Seed recomputation ===
    // IMPORTANT: detect drand-only from exec receipt weather_value (not bundle entropy)
    let exec_parsed: serde_json::Value =
        serde_json::from_str(&bundle.execution_receipt.payload_jcs).unwrap_or_default();
    let exec_weather = exec_parsed.get("weather_value").and_then(|v| v.as_str());
    let exec_seed = exec_parsed
        .get("seed")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let exec_drand = exec_parsed
        .get("drand_randomness")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let step6_pass;
    if !step3_pass {
        steps.push(StepResult {
            name: StepName::SeedRecomputation,
            status: StepStatus::Skip("exec signature failed".into()),
            detail: None,
        });
        step6_pass = false;
    } else {
        let (computed_seed, _) = match exec_weather {
            Some(w) => compute_seed(&computed_entry_hash, exec_drand, w),
            None => compute_seed_drand_only(&computed_entry_hash, exec_drand),
        };
        let computed_seed_hex = hex::encode(computed_seed);
        step6_pass = computed_seed_hex == exec_seed;
        let mode = if exec_weather.is_some() {
            "drand + weather"
        } else {
            "drand only"
        };
        let step6_detail = if step6_pass {
            None
        } else {
            Some(StepDetail::HexMismatch {
                expected: exec_seed.to_string(),
                computed: computed_seed_hex.clone(),
            })
        };
        steps.push(StepResult {
            name: StepName::SeedRecomputation,
            status: if step6_pass {
                StepStatus::Pass
            } else {
                StepStatus::Fail(format!(
                    "({mode}) expected {exec_seed}, got {computed_seed_hex}"
                ))
            },
            detail: step6_detail,
        });
    }

    // === Step 7: Winner selection ===
    if !step6_pass || !step3_pass {
        steps.push(StepResult {
            name: StepName::WinnerSelection,
            status: StepStatus::Skip("seed or exec signature failed".into()),
            detail: None,
        });
    } else {
        // Extract winner_count from lock receipt
        let lock_parsed: serde_json::Value =
            serde_json::from_str(&bundle.lock_receipt.payload_jcs).unwrap_or_default();
        let winner_count = lock_parsed
            .get("winner_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let (computed_seed, _) = match exec_weather {
            Some(w) => compute_seed(&computed_entry_hash, exec_drand, w),
            None => compute_seed_drand_only(&computed_entry_hash, exec_drand),
        };

        match draw(&entries, &computed_seed, winner_count) {
            Ok(computed_winners) => {
                // Compare against exec receipt results (the SIGNED source of truth, not bundle results)
                let exec_results = exec_parsed.get("results").and_then(|v| v.as_array());
                let receipt_ids: Vec<&str> = exec_results
                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();
                let computed_ids: Vec<&str> = computed_winners
                    .iter()
                    .map(|w| w.entry_id.as_str())
                    .collect();

                if computed_ids == receipt_ids {
                    steps.push(StepResult {
                        name: StepName::WinnerSelection,
                        status: StepStatus::Pass,
                        detail: None,
                    });
                } else {
                    steps.push(StepResult {
                        name: StepName::WinnerSelection,
                        status: StepStatus::Fail(format!(
                            "computed {:?}, receipt has {:?}",
                            computed_ids, receipt_ids
                        )),
                        detail: None,
                    });
                }
            }
            Err(e) => {
                steps.push(StepResult {
                    name: StepName::WinnerSelection,
                    status: StepStatus::Fail(format!("draw error: {e}")),
                    detail: None,
                });
            }
        }
    }

    // === Step 8: BLS drand verification ===
    #[cfg(feature = "cli")]
    {
        match crate::drand::verify_drand_round(
            &bundle.entropy.drand_chain_hash,
            bundle.entropy.drand_round,
            &bundle.entropy.drand_signature,
            &bundle.entropy.drand_randomness,
        ) {
            Ok(()) => steps.push(StepResult {
                name: StepName::DrandBlsSignature,
                status: StepStatus::Pass,
                detail: None,
            }),
            Err(e) => steps.push(StepResult {
                name: StepName::DrandBlsSignature,
                status: StepStatus::Fail(e.to_string()),
                detail: None,
            }),
        }
    }
    #[cfg(not(feature = "cli"))]
    {
        steps.push(StepResult {
            name: StepName::DrandBlsSignature,
            status: StepStatus::Skip("BLS verification requires cli feature".into()),
            detail: None,
        });
    }

    VerificationReport {
        steps,
        operator_key_id,
        infra_key_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::ProofBundle;
    use crate::protocol::receipts::lock_receipt_hash as compute_lock_hash;
    use crate::{Entry, compute_seed, draw, entry_hash};
    use ed25519_dalek::{Signer, SigningKey};

    fn test_signing_key() -> SigningKey {
        let secret_bytes: [u8; 32] =
            hex::decode("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60")
                .unwrap()
                .try_into()
                .unwrap();
        SigningKey::from_bytes(&secret_bytes)
    }

    /// Build a fully valid proof bundle with real Ed25519 signatures and correct protocol values.
    fn valid_signed_bundle() -> (String, String) {
        let sk = test_signing_key();
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());

        let entries = vec![
            Entry {
                id: "ticket-47".into(),
                weight: 1,
            },
            Entry {
                id: "ticket-48".into(),
                weight: 1,
            },
            Entry {
                id: "ticket-49".into(),
                weight: 1,
            },
        ];

        let (ehash, _) = entry_hash(&entries);
        let drand_randomness = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let weather_val = "1013";
        let (seed_bytes, _) = compute_seed(&ehash, drand_randomness, weather_val);
        let seed_hex = hex::encode(seed_bytes);
        let winners = draw(&entries, &seed_bytes, 2).unwrap();
        let results_array: Vec<String> = winners.iter().map(|w| w.entry_id.clone()).collect();

        // Build lock receipt JCS — use serde_json::json! which sorts keys alphabetically (BTreeMap)
        let lock_jcs = serde_json::json!({
            "commitment_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "drand_chain": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
            "drand_round": 12345,
            "draw_id": "22222222-2222-2222-2222-222222222222",
            "entry_hash": &ehash,
            "fair_pick_version": "0.1.0",
            "locked_at": "2026-04-09T12:00:00.000000Z",
            "operator_id": "11111111-1111-1111-1111-111111111111",
            "operator_slug": "acme-prizes",
            "schema_version": "2",
            "sequence": 1,
            "signing_key_id": "deadbeef",
            "wallop_core_version": "0.14.1",
            "weather_station": "middle-wallop",
            "weather_time": "2026-04-09T12:10:00.000000Z",
            "winner_count": 2
        })
        .to_string();
        let lock_sig = sk.sign(lock_jcs.as_bytes());
        let lock_sig_hex = hex::encode(lock_sig.to_bytes());

        let lrh = compute_lock_hash(&lock_jcs);

        let exec_jcs = serde_json::json!({
            "drand_chain": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
            "drand_randomness": drand_randomness,
            "drand_round": 12345,
            "drand_signature": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
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
            "weather_observation_time": "2026-04-09T12:10:00.000000Z",
            "weather_station": "middle-wallop",
            "weather_value": weather_val
        }).to_string();
        let exec_sig = sk.sign(exec_jcs.as_bytes());
        let exec_sig_hex = hex::encode(exec_sig.to_bytes());

        let bundle_json = serde_json::json!({
            "version": 1,
            "draw_id": "22222222-2222-2222-2222-222222222222",
            "entries": [
                {"id": "ticket-47", "weight": 1},
                {"id": "ticket-48", "weight": 1},
                {"id": "ticket-49", "weight": 1}
            ],
            "results": winners.iter().map(|w| serde_json::json!({"entry_id": &w.entry_id, "position": w.position})).collect::<Vec<_>>(),
            "entropy": {
                "drand_round": 12345,
                "drand_randomness": drand_randomness,
                "drand_signature": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "drand_chain_hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
                "weather_value": weather_val
            },
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
        }).to_string();

        (bundle_json, pk_hex)
    }

    #[test]
    fn verify_bundle_all_pass() {
        let (json, _) = valid_signed_bundle();
        let bundle = ProofBundle::from_json(&json).unwrap();
        let report = verify_bundle(&bundle);
        // Steps 1-7 should all be Pass
        for step in &report.steps[..7] {
            assert!(
                matches!(step.status, StepStatus::Pass),
                "step {} was {:?}",
                step.name,
                step.status
            );
        }
        // Without cli feature, step 8 is a skip and the report passes overall.
        // With cli feature, step 8 runs real BLS (the test bundle uses a fake signature so it fails).
        #[cfg(not(feature = "cli"))]
        assert!(
            report.passed(),
            "expected all pass (no cli), got: {:?}",
            report.steps
        );
    }

    #[test]
    fn verify_bundle_tampered_entry() {
        let (json, _) = valid_signed_bundle();
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        val["entries"][0]["weight"] = serde_json::json!(99);
        let bundle = ProofBundle::from_json(&val.to_string()).unwrap();
        let report = verify_bundle(&bundle);
        assert!(!report.passed());
        assert!(matches!(report.steps[0].status, StepStatus::Pass)); // entry hash computes
        assert!(matches!(report.steps[4].status, StepStatus::Fail(_))); // 5a lock
        assert!(matches!(report.steps[5].status, StepStatus::Fail(_))); // 5b exec
    }

    #[test]
    fn verify_bundle_bad_lock_sig() {
        let (json, _) = valid_signed_bundle();
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        val["lock_receipt"]["signature_hex"] = serde_json::json!("ff".repeat(64));
        let bundle = ProofBundle::from_json(&val.to_string()).unwrap();
        let report = verify_bundle(&bundle);
        assert!(!report.passed());
        assert!(matches!(report.steps[1].status, StepStatus::Fail(_))); // lock sig
        assert!(matches!(report.steps[3].status, StepStatus::Skip(_))); // linkage
        assert!(matches!(report.steps[4].status, StepStatus::Skip(_))); // 5a
    }

    #[test]
    fn verify_bundle_bad_exec_sig() {
        let (json, _) = valid_signed_bundle();
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        val["execution_receipt"]["signature_hex"] = serde_json::json!("ff".repeat(64));
        let bundle = ProofBundle::from_json(&val.to_string()).unwrap();
        let report = verify_bundle(&bundle);
        assert!(!report.passed());
        assert!(matches!(report.steps[2].status, StepStatus::Fail(_))); // exec sig
        assert!(matches!(report.steps[3].status, StepStatus::Skip(_))); // linkage
        assert!(matches!(report.steps[5].status, StepStatus::Skip(_))); // 5b
        assert!(matches!(report.steps[6].status, StepStatus::Skip(_))); // seed
        assert!(matches!(report.steps[7].status, StepStatus::Skip(_))); // winners
    }

    #[test]
    fn verify_bundle_wrong_seed() {
        let sk = test_signing_key();

        let (json, _) = valid_signed_bundle();
        let bundle = ProofBundle::from_json(&json).unwrap();
        // Tamper with the exec receipt's seed field (re-sign so sig passes)
        let mut exec_val: serde_json::Value =
            serde_json::from_str(&bundle.execution_receipt.payload_jcs).unwrap();
        exec_val["seed"] = serde_json::json!("ff".repeat(32));
        let new_exec_jcs = exec_val.to_string();
        let new_exec_sig = hex::encode(sk.sign(new_exec_jcs.as_bytes()).to_bytes());

        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        val["execution_receipt"]["payload_jcs"] = serde_json::json!(new_exec_jcs);
        val["execution_receipt"]["signature_hex"] = serde_json::json!(new_exec_sig);
        let bundle2 = ProofBundle::from_json(&val.to_string()).unwrap();
        let report = verify_bundle(&bundle2);
        assert!(!report.passed());
        assert!(
            matches!(report.steps[6].status, StepStatus::Fail(_)),
            "seed should fail"
        );
        assert!(
            matches!(report.steps[7].status, StepStatus::Skip(_)),
            "winners should skip"
        );
    }

    #[test]
    fn verify_bundle_altered_exec_results() {
        use ed25519_dalek::Signer;
        let sk = test_signing_key();

        let (json, _) = valid_signed_bundle();
        let bundle = ProofBundle::from_json(&json).unwrap();
        let mut exec_val: serde_json::Value =
            serde_json::from_str(&bundle.execution_receipt.payload_jcs).unwrap();
        let results = exec_val["results"].as_array().unwrap().clone();
        let reversed: Vec<serde_json::Value> = results.into_iter().rev().collect();
        exec_val["results"] = serde_json::json!(reversed);
        let new_exec_jcs = exec_val.to_string();
        let new_exec_sig = hex::encode(sk.sign(new_exec_jcs.as_bytes()).to_bytes());

        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        val["execution_receipt"]["payload_jcs"] = serde_json::json!(new_exec_jcs);
        val["execution_receipt"]["signature_hex"] = serde_json::json!(new_exec_sig);
        let bundle2 = ProofBundle::from_json(&val.to_string()).unwrap();
        let report = verify_bundle(&bundle2);
        assert!(!report.passed());
        assert!(
            matches!(report.steps[7].status, StepStatus::Fail(_)),
            "winners should fail"
        );
    }

    #[test]
    fn step_result_types_exist() {
        let r = StepResult {
            name: StepName::EntryHash,
            status: StepStatus::Pass,
            detail: None,
        };
        assert_eq!(r.status, StepStatus::Pass);

        let r2 = StepResult {
            name: StepName::LockSignature,
            status: StepStatus::Fail("bad".into()),
            detail: None,
        };
        assert!(matches!(r2.status, StepStatus::Fail(_)));

        let r3 = StepResult {
            name: StepName::ReceiptLinkage,
            status: StepStatus::Skip("upstream failed".into()),
            detail: None,
        };
        assert!(matches!(r3.status, StepStatus::Skip(_)));
    }

    #[test]
    fn report_passed_logic() {
        let report = VerificationReport {
            steps: vec![
                StepResult {
                    name: StepName::EntryHash,
                    status: StepStatus::Pass,
                    detail: None,
                },
                StepResult {
                    name: StepName::LockSignature,
                    status: StepStatus::Pass,
                    detail: None,
                },
            ],
            operator_key_id: None,
            infra_key_id: None,
        };
        assert!(report.passed());
        assert_eq!(report.error_count(), 0);
    }

    #[test]
    fn report_with_failure() {
        let report = VerificationReport {
            steps: vec![
                StepResult {
                    name: StepName::EntryHash,
                    status: StepStatus::Pass,
                    detail: None,
                },
                StepResult {
                    name: StepName::LockSignature,
                    status: StepStatus::Fail("mismatch".into()),
                    detail: None,
                },
                StepResult {
                    name: StepName::ReceiptLinkage,
                    status: StepStatus::Skip("b failed".into()),
                    detail: None,
                },
            ],
            operator_key_id: None,
            infra_key_id: None,
        };
        assert!(!report.passed());
        assert_eq!(report.error_count(), 1);
    }

    #[test]
    fn report_all_skipped_is_not_passed() {
        let report = VerificationReport {
            steps: vec![StepResult {
                name: StepName::EntryHash,
                status: StepStatus::Skip("no input".into()),
                detail: None,
            }],
            operator_key_id: None,
            infra_key_id: None,
        };
        assert!(!report.passed());
    }

    #[cfg(feature = "cli")]
    #[test]
    fn verify_bundle_bad_drand_chain() {
        let (json, _) = valid_signed_bundle();
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        val["entropy"]["drand_chain_hash"] = serde_json::json!("00".repeat(32));
        let bundle = ProofBundle::from_json(&val.to_string()).unwrap();
        let report = verify_bundle(&bundle);
        let bls_step = report
            .steps
            .iter()
            .find(|s| matches!(s.name, StepName::DrandBlsSignature))
            .unwrap();
        assert!(
            matches!(bls_step.status, StepStatus::Fail(_)),
            "BLS step should fail for unknown chain, got {:?}",
            bls_step.status
        );
    }

    // ==================== StepName unit tests (new in 0.5.0) ====================

    #[test]
    fn step_name_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&StepName::EntryHash).unwrap(),
            "\"entry_hash\""
        );
        assert_eq!(
            serde_json::to_string(&StepName::DrandBlsSignature).unwrap(),
            "\"drand_bls_signature\""
        );
        assert_eq!(
            serde_json::to_string(&StepName::LockReceiptEntryHash).unwrap(),
            "\"lock_receipt_entry_hash\""
        );
    }

    #[test]
    fn step_name_deserializes_from_snake_case() {
        let name: StepName = serde_json::from_str("\"lock_signature\"").unwrap();
        assert_eq!(name, StepName::LockSignature);

        let name: StepName = serde_json::from_str("\"receipt_linkage\"").unwrap();
        assert_eq!(name, StepName::ReceiptLinkage);

        let name: StepName = serde_json::from_str("\"drand_bls_signature\"").unwrap();
        assert_eq!(name, StepName::DrandBlsSignature);
    }

    #[test]
    fn step_name_display_produces_human_friendly_strings() {
        assert_eq!(StepName::EntryHash.to_string(), "Entry hash");
        assert_eq!(
            StepName::LockSignature.to_string(),
            "Lock receipt signature"
        );
        assert_eq!(StepName::ReceiptLinkage.to_string(), "Receipt linkage");
        assert_eq!(
            StepName::LockReceiptEntryHash.to_string(),
            "Entry hash (lock receipt)"
        );
        assert_eq!(
            StepName::DrandBlsSignature.to_string(),
            "Drand BLS signature"
        );
    }

    #[test]
    fn step_name_all_returns_every_variant() {
        let all = StepName::all();
        assert_eq!(all.len(), 9, "all() should return all 9 StepName variants");
        assert!(all.contains(&StepName::EntryHash));
        assert!(all.contains(&StepName::DrandBlsSignature));
    }

    #[test]
    fn step_name_unknown_string_fails_to_deserialize() {
        let result: Result<StepName, _> = serde_json::from_str("\"not_a_real_step\"");
        assert!(
            result.is_err(),
            "unknown step name should fail to deserialize"
        );
    }

    #[test]
    fn verify_bundle_fail_includes_hex_mismatch_detail() {
        let (json, _) = valid_signed_bundle();
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        val["entries"][0]["weight"] = serde_json::json!(99);
        let bundle = ProofBundle::from_json(&val.to_string()).unwrap();
        let report = verify_bundle(&bundle);
        let step_5a = &report.steps[4];
        assert!(matches!(step_5a.status, StepStatus::Fail(_)));
        assert!(
            matches!(step_5a.detail, Some(StepDetail::HexMismatch { .. })),
            "expected HexMismatch detail, got {:?}",
            step_5a.detail
        );
    }
}
