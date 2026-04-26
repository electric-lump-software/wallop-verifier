use crate::bundle::ProofBundle;
use crate::protocol::crypto;
use crate::protocol::receipts::{
    ParsedExecutionReceipt, lock_receipt_hash, parse_execution_receipt, parse_lock_receipt,
    validate_execution_receipt_tags, validate_execution_receipt_tags_v3,
    validate_lock_receipt_tags,
};
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
    /// Cross-receipt field consistency — every field appearing in both the
    /// lock and execution receipts MUST be byte-identical. Bundle-envelope
    /// `draw_id` MUST also match. Closes splice-attack class per spec
    /// §4.2.5. Appended rather than inserted mid-list so external
    /// consumers pinning step ordinals are not broken.
    ReceiptFieldConsistency,
    /// Weather observation window — execution receipt's
    /// `weather_observation_time` MUST fall in
    /// `[lock.weather_time, lock.weather_time + 3600s]`.
    /// Closes the weather-time splice vector per spec §4.2.5.
    WeatherObservationWindow,
    /// Bundle shape — both receipts MUST parse against the typed structs
    /// (`deny_unknown_fields`), MUST resolve via the schema_version
    /// dispatcher (terminal `UnknownSchemaVersion` on anything else), MUST
    /// pass the algorithm-identity-tag and `weather_station` charset
    /// validators, and every signed timestamp MUST be in canonical
    /// RFC 3339 form (`chrono_parse_canonical`). Closes the A1/A2/A3 air
    /// gaps named in the round-2 topology review — the typed parsers and
    /// validators ship in `protocol/receipts.rs` but until this step
    /// existed, the verifier never called them. Appended to the end of
    /// `StepName::all()` so external consumers pinning step ordinals are
    /// not broken; in pipeline execution order, this step runs FIRST and
    /// gates everything else.
    BundleShape,
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
            StepName::ReceiptFieldConsistency,
            StepName::WeatherObservationWindow,
            StepName::BundleShape,
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
            StepName::ReceiptFieldConsistency => "Receipt field consistency",
            StepName::WeatherObservationWindow => "Weather observation window",
            StepName::BundleShape => "Bundle shape",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum StepStatus {
    Pass,
    Fail(String),
    Skip(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum StepDetail {
    HexMismatch { expected: String, computed: String },
}

#[derive(Debug, Clone)]
pub struct StepResult {
    pub name: StepName,
    pub status: StepStatus,
    pub detail: Option<StepDetail>,
}

/// Trust mode under which a verification report was produced. Surfaced in
/// the report itself (CLI header, JSON top-level, WASM page UX) so the
/// guarantee a user is reading is never ambiguous.
///
/// Per ADR-0009, three tiers exist:
///
/// - `Attributable` — keys resolved against an operator-hosted
///   `.well-known` pin on a domain wallop_core does not control.
/// - `Attestable` — keys resolved from `/operator/:slug/keys` only.
///   Same-origin caveat: a CDN compromise can serve coherent forgeries.
/// - `SelfConsistencyOnly` — keys read from the bundle itself. Catches
///   accidents and casual tampering only; does not defend against MITM
///   or hostile mirrors. This is the spec §4.2.4 caveat mode.
///
/// As of 1.0.0 only `SelfConsistencyOnly` exists in this crate; the
/// `KeyResolver` work that lights up the other two ships in a follow-up.
/// The variant is wired in here so consumers can begin matching on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerifierMode {
    /// Keys resolved against an operator-hosted `.well-known` pin on a
    /// domain wallop_core does not control. **Not constructable in 1.0.0
    /// — pending the `KeyResolver` work in ADR-0009.**
    Attributable,
    /// Keys resolved from `/operator/:slug/keys` only. Same-origin caveat.
    /// **Not constructable in 1.0.0 — pending ADR-0009.**
    Attestable,
    /// Keys read from the bundle itself. The only reachable variant in
    /// 1.0.0; spec §4.2.4 caveat mode.
    SelfConsistencyOnly,
}

impl fmt::Display for VerifierMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            VerifierMode::Attributable => "attributable",
            VerifierMode::Attestable => "attestable",
            VerifierMode::SelfConsistencyOnly => "self_consistency_only",
        };
        f.write_str(s)
    }
}

#[derive(Clone)]
pub struct VerificationReport {
    pub steps: Vec<StepResult>,
    pub operator_key_id: Option<String>,
    pub infra_key_id: Option<String>,
    /// Trust mode under which this report was produced. See `VerifierMode`.
    pub mode: VerifierMode,
}

impl VerificationReport {
    /// Returns `true` iff the bundle is acceptable. **This is the
    /// authoritative gate for verification.** Callers MUST NOT infer
    /// acceptance from per-step results — a per-step `Pass` is a
    /// diagnostic about the bytes that step examined, not a claim about
    /// the bundle as a whole. A bundle with a malformed `signature_algorithm`
    /// can produce step-level `Pass` on the cryptographic checks (the
    /// signatures genuinely verify over the bytes presented) while still
    /// failing the `BundleShape` step that catches the protocol violation.
    /// `passed()` correctly returns `false` in that case.
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

    // Convert bundle entries to fair_pick Entry type. The bundle carries
    // each entry's wallop-assigned UUID in the `uuid` field — treated as
    // `id` in the FairPick / entry_hash layer below.
    let entries: Vec<Entry> = bundle
        .entries
        .iter()
        .map(|e| Entry {
            id: e.uuid.clone(),
            weight: e.weight,
        })
        .collect();

    // === Step 1: Entry hash ===
    let (computed_entry_hash, _) = entry_hash(&bundle.draw_id, &entries);
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

    // === Step 10: Cross-receipt field consistency ===
    //
    // Every field duplicated across the lock and execution receipts MUST be
    // byte-identical. Without this, an infrastructure-level attacker signing
    // a fraudulent exec receipt can pair it with a legitimate lock from a
    // different draw — `lock_receipt_hash` binds lock bytes INTO the exec
    // but does not bind the exec's own duplicated fields back to the lock.
    //
    // Fields checked (spec §4.2.5): draw_id, operator_id, sequence,
    // drand_chain, drand_round, weather_station. Bundle envelope draw_id
    // also cross-checked. signing_key_id deliberately NOT checked (lock =
    // operator key, exec = infra key; different by design). operator_slug
    // NOT checked (derivative of operator_id). Algorithm identity tags NOT
    // cross-checked (validated per-receipt against pinned values already).
    steps.push(check_receipt_field_consistency(bundle));

    // === Step 11: Weather observation window ===
    //
    // exec.weather_observation_time MUST fall in
    // [lock.weather_time, lock.weather_time + 3600s]. Prevents an
    // infrastructure-level attacker from fetching weather from any point
    // in time and attributing it to the draw's declared window.
    steps.push(check_weather_observation_window(bundle));

    // === Step 12: Bundle shape ===
    //
    // Although appended last in the step list (per the ordinal-stability
    // rule), the shape gate runs LOGICALLY FIRST: typed parser dispatch +
    // tag validators + canonical timestamp regex. We compute it here at
    // the end so it appears in the report, but the existing steps above
    // still run regardless. A future refactor may use a failed shape
    // result to skip the rest, but for now the existing steps are
    // resilient (they Skip on dependency failure or use unwrap_or_default).
    steps.push(check_bundle_shape(bundle));

    VerificationReport {
        steps,
        operator_key_id,
        infra_key_id,
        mode: VerifierMode::SelfConsistencyOnly,
    }
}

/// Step 12 — Bundle shape gate.
///
/// Runs the typed parsers (`parse_lock_receipt`, `parse_execution_receipt`),
/// the tag validators (`validate_lock_receipt_tags`,
/// `validate_execution_receipt_tags`/`_v3`), and a canonical RFC 3339
/// regex check (`chrono_parse_canonical`) on every signed timestamp. Closes
/// the A1/A2/A3 air gaps from the round-2 topology review — the validators
/// ship in `protocol/receipts.rs` but until this step existed, the verifier
/// never called them.
///
/// A bundle that passes this step is well-shaped per spec §4.2.1: closed
/// field set on receipts, recognised `schema_version`, pinned algorithm
/// tags, charset-conforming `weather_station`, canonical signed timestamps.
fn check_bundle_shape(bundle: &ProofBundle) -> StepResult {
    // Lock receipt — typed parse via dispatcher (deny_unknown_fields,
    // schema_version dispatch).
    let parsed_lock = match parse_lock_receipt(&bundle.lock_receipt.payload_jcs) {
        Ok(crate::protocol::receipts::ParsedLockReceipt::V4(p)) => p,
        Err(e) => {
            return StepResult {
                name: StepName::BundleShape,
                status: StepStatus::Fail(format!("lock receipt: {}", e)),
                detail: None,
            };
        }
    };

    // Lock receipt — algorithm identity tags + weather_station charset.
    if let Err(e) = validate_lock_receipt_tags(&parsed_lock) {
        return StepResult {
            name: StepName::BundleShape,
            status: StepStatus::Fail(format!("lock receipt validation: {}", e)),
            detail: None,
        };
    }

    // Lock receipt — canonical timestamps.
    if let Err(e) = chrono_parse_canonical(&parsed_lock.locked_at) {
        return StepResult {
            name: StepName::BundleShape,
            status: StepStatus::Fail(format!("lock.locked_at: {}", e)),
            detail: None,
        };
    }
    if let Err(e) = chrono_parse_canonical(&parsed_lock.weather_time) {
        return StepResult {
            name: StepName::BundleShape,
            status: StepStatus::Fail(format!("lock.weather_time: {}", e)),
            detail: None,
        };
    }

    // Execution receipt — typed parse via dispatcher.
    let parsed_exec = match parse_execution_receipt(&bundle.execution_receipt.payload_jcs) {
        Ok(p) => p,
        Err(e) => {
            return StepResult {
                name: StepName::BundleShape,
                status: StepStatus::Fail(format!("exec receipt: {}", e)),
                detail: None,
            };
        }
    };

    // Execution receipt — version-specific tag validators + canonical
    // timestamp checks. v2 and v3 share field shape modulo
    // `signing_key_id`; checks are otherwise identical.
    let (executed_at, weather_observation_time) = match &parsed_exec {
        ParsedExecutionReceipt::V2(p) => {
            if let Err(e) = validate_execution_receipt_tags(p) {
                return StepResult {
                    name: StepName::BundleShape,
                    status: StepStatus::Fail(format!("exec receipt validation: {}", e)),
                    detail: None,
                };
            }
            (p.executed_at.clone(), p.weather_observation_time.clone())
        }
        ParsedExecutionReceipt::V3(p) => {
            if let Err(e) = validate_execution_receipt_tags_v3(p) {
                return StepResult {
                    name: StepName::BundleShape,
                    status: StepStatus::Fail(format!("exec receipt validation: {}", e)),
                    detail: None,
                };
            }
            (p.executed_at.clone(), p.weather_observation_time.clone())
        }
    };

    if let Err(e) = chrono_parse_canonical(&executed_at) {
        return StepResult {
            name: StepName::BundleShape,
            status: StepStatus::Fail(format!("exec.executed_at: {}", e)),
            detail: None,
        };
    }
    if let Some(obs) = &weather_observation_time
        && let Err(e) = chrono_parse_canonical(obs)
    {
        return StepResult {
            name: StepName::BundleShape,
            status: StepStatus::Fail(format!("exec.weather_observation_time: {}", e)),
            detail: None,
        };
    }

    StepResult {
        name: StepName::BundleShape,
        status: StepStatus::Pass,
        detail: None,
    }
}

// Fields that MUST be byte-identical between lock and exec receipts per
// spec §4.2.5. draw_id is also cross-checked against the bundle envelope.
const CROSS_CHECKED_FIELDS: &[&str] = &[
    "draw_id",
    "operator_id",
    "sequence",
    "drand_chain",
    "drand_round",
    "weather_station",
];

fn check_receipt_field_consistency(bundle: &ProofBundle) -> StepResult {
    let lock: serde_json::Value = match serde_json::from_str(&bundle.lock_receipt.payload_jcs) {
        Ok(v) => v,
        Err(e) => {
            return StepResult {
                name: StepName::ReceiptFieldConsistency,
                status: StepStatus::Fail(format!("invalid lock receipt JSON: {}", e)),
                detail: None,
            };
        }
    };

    let exec: serde_json::Value = match serde_json::from_str(&bundle.execution_receipt.payload_jcs)
    {
        Ok(v) => v,
        Err(e) => {
            return StepResult {
                name: StepName::ReceiptFieldConsistency,
                status: StepStatus::Fail(format!("invalid exec receipt JSON: {}", e)),
                detail: None,
            };
        }
    };

    // Bundle envelope cross-check: envelope.draw_id == lock.draw_id.
    // Transitively envelope == exec too, because the field loop below
    // asserts lock.draw_id == exec.draw_id.
    let envelope_draw_id = bundle.draw_id.as_str();
    let lock_draw_id = lock.get("draw_id").and_then(|v| v.as_str()).unwrap_or("");

    if envelope_draw_id != lock_draw_id {
        return StepResult {
            name: StepName::ReceiptFieldConsistency,
            status: StepStatus::Fail(format!(
                "draw_id mismatch: bundle envelope ({}) vs lock receipt ({})",
                envelope_draw_id, lock_draw_id
            )),
            detail: None,
        };
    }

    // Every cross-checked field must match byte-identically.
    for field in CROSS_CHECKED_FIELDS {
        let lock_val = lock.get(field);
        let exec_val = exec.get(field);
        if lock_val != exec_val {
            return StepResult {
                name: StepName::ReceiptFieldConsistency,
                status: StepStatus::Fail(format!(
                    "receipt field mismatch: {} differs between lock ({:?}) and exec ({:?})",
                    field, lock_val, exec_val
                )),
                detail: None,
            };
        }
    }

    StepResult {
        name: StepName::ReceiptFieldConsistency,
        status: StepStatus::Pass,
        detail: None,
    }
}

fn check_weather_observation_window(bundle: &ProofBundle) -> StepResult {
    let lock: serde_json::Value = match serde_json::from_str(&bundle.lock_receipt.payload_jcs) {
        Ok(v) => v,
        Err(e) => {
            return StepResult {
                name: StepName::WeatherObservationWindow,
                status: StepStatus::Fail(format!("invalid lock receipt JSON: {}", e)),
                detail: None,
            };
        }
    };

    let exec: serde_json::Value = match serde_json::from_str(&bundle.execution_receipt.payload_jcs)
    {
        Ok(v) => v,
        Err(e) => {
            return StepResult {
                name: StepName::WeatherObservationWindow,
                status: StepStatus::Fail(format!("invalid exec receipt JSON: {}", e)),
                detail: None,
            };
        }
    };

    // Both fields may be absent on drand-only bundles. In that case the
    // window check is vacuous (there is no observation to window-bound);
    // pass.
    let lock_weather_time = match lock.get("weather_time").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return StepResult {
                name: StepName::WeatherObservationWindow,
                status: StepStatus::Skip("lock receipt has no weather_time".into()),
                detail: None,
            };
        }
    };

    let exec_observation_time = match exec
        .get("weather_observation_time")
        .and_then(|v| v.as_str())
    {
        Some(s) => s,
        None => {
            return StepResult {
                name: StepName::WeatherObservationWindow,
                status: StepStatus::Skip("exec receipt has no weather_observation_time".into()),
                detail: None,
            };
        }
    };

    let parsed_lock = match chrono_parse_canonical(lock_weather_time) {
        Ok(t) => t,
        Err(e) => {
            return StepResult {
                name: StepName::WeatherObservationWindow,
                status: StepStatus::Fail(format!(
                    "unparseable lock.weather_time ({}): {}",
                    lock_weather_time, e
                )),
                detail: None,
            };
        }
    };

    let parsed_exec = match chrono_parse_canonical(exec_observation_time) {
        Ok(t) => t,
        Err(e) => {
            return StepResult {
                name: StepName::WeatherObservationWindow,
                status: StepStatus::Fail(format!(
                    "unparseable exec.weather_observation_time ({}): {}",
                    exec_observation_time, e
                )),
                detail: None,
            };
        }
    };

    // Bound direction: Met Office publishes observations at hour
    // boundaries (XX:00:00 UTC). `lock.weather_time` is the declared
    // target; the entropy worker fetches the most recent observation
    // at or before the target, so `exec.weather_observation_time` is
    // typically earlier than `lock.weather_time` by up to 3600s.
    //
    // Correct bound: obs ∈ [lock.weather_time - 3600s, lock.weather_time].
    let delta = parsed_exec.timestamp() - parsed_lock.timestamp();
    if !(-3600..=0).contains(&delta) {
        return StepResult {
            name: StepName::WeatherObservationWindow,
            status: StepStatus::Fail(format!(
                "weather_observation_time outside [lock.weather_time - 3600s, lock.weather_time]: \
                 delta = {}s (lock.weather_time = {}, exec.weather_observation_time = {})",
                delta, lock_weather_time, exec_observation_time
            )),
            detail: None,
        };
    }

    StepResult {
        name: StepName::WeatherObservationWindow,
        status: StepStatus::Pass,
        detail: None,
    }
}

// Parses the canonical RFC 3339 timestamp form pinned in spec §4.2.1
// (`YYYY-MM-DDTHH:MM:SS.ffffffZ`, exactly 6 fractional digits, Z suffix).
// Produces a unix-second timestamp. This is a narrow parser, not a
// general-purpose RFC 3339 parser — the spec §4.2.1 note explicitly
// warns against general-purpose parsers that accept variable fractional
// digit counts or +00:00 offsets.
fn chrono_parse_canonical(s: &str) -> Result<ChronoStub, String> {
    // Manual check matching spec §4.2.1 regex
    // `\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\z`. No regex dep
    // needed — the positions are fixed.
    let b = s.as_bytes();
    if b.len() != 27 {
        return Err("does not match canonical RFC 3339 form (§4.2.1): wrong length".into());
    }
    let digits = |pos: usize, n: usize| -> Result<(), String> {
        for (offset, byte) in b[pos..pos + n].iter().enumerate() {
            if !byte.is_ascii_digit() {
                return Err(format!(
                    "does not match canonical RFC 3339 form (§4.2.1): non-digit at pos {}",
                    pos + offset
                ));
            }
        }
        Ok(())
    };
    let lit = |pos: usize, ch: u8| -> Result<(), String> {
        if b[pos] != ch {
            return Err(format!(
                "does not match canonical RFC 3339 form (§4.2.1): expected {:?} at pos {}",
                ch as char, pos
            ));
        }
        Ok(())
    };
    digits(0, 4)?; // YYYY
    lit(4, b'-')?;
    digits(5, 2)?; // MM
    lit(7, b'-')?;
    digits(8, 2)?; // DD
    lit(10, b'T')?;
    digits(11, 2)?; // HH
    lit(13, b':')?;
    digits(14, 2)?; // MM
    lit(16, b':')?;
    digits(17, 2)?; // SS
    lit(19, b'.')?;
    digits(20, 6)?; // microseconds
    lit(26, b'Z')?;

    let parse_slice = |start: usize, end: usize| -> Result<i64, String> {
        s[start..end]
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())
    };
    let y = parse_slice(0, 4)?;
    let mo = parse_slice(5, 7)?;
    let d = parse_slice(8, 10)?;
    let h = parse_slice(11, 13)?;
    let mi = parse_slice(14, 16)?;
    let se = parse_slice(17, 19)?;

    // Days-from-epoch via Rata Die (civil-from-days). The weather window
    // is 3600 seconds — we only need second-precision unix time for the
    // subtraction; we discard fractional microseconds.
    //
    // https://howardhinnant.github.io/date_algorithms.html#days_from_civil
    let y_adj = if mo <= 2 { y - 1 } else { y };
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = y_adj - era * 400;
    let mo_shift = if mo > 2 { mo - 3 } else { mo + 9 };
    let doy = (153 * mo_shift + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_from_epoch = era * 146_097 + doe - 719_468;

    Ok(ChronoStub {
        secs: days_from_epoch * 86_400 + h * 3600 + mi * 60 + se,
    })
}

struct ChronoStub {
    secs: i64,
}

impl ChronoStub {
    fn timestamp(&self) -> i64 {
        self.secs
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

        // Entry `id` here carries the wallop-assigned UUID. Using real UUIDs
        // (not operator-supplied strings) so the hash, sort, and bundle
        // parse round-trip cleanly.
        let uuid_a = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let uuid_b = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let uuid_c = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let entries = vec![
            Entry {
                id: uuid_a.into(),
                weight: 1,
            },
            Entry {
                id: uuid_b.into(),
                weight: 1,
            },
            Entry {
                id: uuid_c.into(),
                weight: 1,
            },
        ];

        let draw_id = "22222222-2222-2222-2222-222222222222";
        let (ehash, _) = entry_hash(draw_id, &entries);
        let drand_randomness = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let weather_val = "1013";
        let (seed_bytes, _) = compute_seed(&ehash, drand_randomness, weather_val);
        let seed_hex = hex::encode(seed_bytes);
        let winners = draw(&entries, &seed_bytes, 2).unwrap();
        let results_array: Vec<String> = winners.iter().map(|w| w.entry_id.clone()).collect();

        // Lock receipt JCS — field set matches `LockReceiptV4` exactly so
        // BundleShape passes. json! → BTreeMap → alphabetical key order
        // (consistent with JCS).
        let lock_jcs = serde_json::json!({
            "commitment_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "drand_chain": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
            "drand_round": 12345,
            "draw_id": "22222222-2222-2222-2222-222222222222",
            "entropy_composition": "drand-quicknet+openmeteo-v1",
            "entry_hash": &ehash,
            "fair_pick_version": "0.1.0",
            "jcs_version": "sha256-jcs-v1",
            "locked_at": "2026-04-09T12:00:00.000000Z",
            "operator_id": "11111111-1111-1111-1111-111111111111",
            "operator_slug": "acme-prizes",
            "schema_version": "4",
            "sequence": 1,
            "signature_algorithm": "ed25519",
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
            "drand_signature_algorithm": "bls12_381_g2",
            "draw_id": "22222222-2222-2222-2222-222222222222",
            "entropy_composition": "drand-quicknet+openmeteo-v1",
            "entry_hash": &ehash,
            "executed_at": "2026-04-09T12:15:00.000000Z",
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
                {"uuid": uuid_a, "weight": 1},
                {"uuid": uuid_b, "weight": 1},
                {"uuid": uuid_c, "weight": 1}
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
            mode: VerifierMode::SelfConsistencyOnly,
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
            mode: VerifierMode::SelfConsistencyOnly,
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
            mode: VerifierMode::SelfConsistencyOnly,
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
        assert_eq!(
            all.len(),
            12,
            "all() should return all 12 StepName variants"
        );
        assert!(all.contains(&StepName::EntryHash));
        assert!(all.contains(&StepName::DrandBlsSignature));
        assert!(all.contains(&StepName::ReceiptFieldConsistency));
        assert!(all.contains(&StepName::WeatherObservationWindow));
        assert!(all.contains(&StepName::BundleShape));
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

    // ── A1/A2/A3: BundleShape gate ─────────────────────────────────────

    /// Mutate the lock receipt's signed JCS payload by injecting/replacing a
    /// field. Re-signs the lock receipt so the signature step still passes;
    /// this isolates the BundleShape gate's behaviour from signature checks.
    fn rewrite_lock_payload(
        bundle_json: &str,
        mutator: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
    ) -> String {
        use ed25519_dalek::{Signer, SigningKey};

        let mut val: serde_json::Value = serde_json::from_str(bundle_json).unwrap();
        let lock_jcs_str = val["lock_receipt"]["payload_jcs"].as_str().unwrap();
        let mut lock_obj: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(lock_jcs_str).unwrap();
        mutator(&mut lock_obj);

        // Re-serialize via BTreeMap to keep alphabetical ordering (JCS).
        let sorted: std::collections::BTreeMap<String, serde_json::Value> =
            lock_obj.into_iter().collect();
        let new_jcs = serde_json::to_string(&sorted).unwrap();

        let secret_bytes: [u8; 32] =
            hex::decode("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60")
                .unwrap()
                .try_into()
                .unwrap();
        let sk = SigningKey::from_bytes(&secret_bytes);
        let new_sig_hex = hex::encode(sk.sign(new_jcs.as_bytes()).to_bytes());

        val["lock_receipt"]["payload_jcs"] = serde_json::json!(new_jcs);
        val["lock_receipt"]["signature_hex"] = serde_json::json!(new_sig_hex);
        val.to_string()
    }

    #[test]
    fn bundle_shape_passes_on_valid_bundle() {
        let (json, _) = valid_signed_bundle();
        let bundle = ProofBundle::from_json(&json).unwrap();
        let report = verify_bundle(&bundle);
        let shape = report
            .steps
            .iter()
            .find(|s| s.name == StepName::BundleShape)
            .expect("BundleShape step present");
        assert!(
            matches!(shape.status, StepStatus::Pass),
            "expected Pass, got {:?}",
            shape.status
        );
    }

    #[test]
    fn bundle_shape_rejects_unknown_field_on_lock_receipt() {
        let (json, _) = valid_signed_bundle();
        let tampered = rewrite_lock_payload(&json, |obj| {
            obj.insert("backdoor".into(), serde_json::Value::String("evil".into()));
        });
        let bundle = ProofBundle::from_json(&tampered).unwrap();
        let report = verify_bundle(&bundle);
        let shape = report
            .steps
            .iter()
            .find(|s| s.name == StepName::BundleShape)
            .expect("BundleShape step present");
        assert!(
            matches!(&shape.status, StepStatus::Fail(msg) if msg.contains("lock receipt")),
            "expected lock-receipt Fail, got {:?}",
            shape.status
        );
    }

    #[test]
    fn bundle_shape_rejects_unknown_lock_schema_version() {
        let (json, _) = valid_signed_bundle();
        let tampered = rewrite_lock_payload(&json, |obj| {
            obj.insert(
                "schema_version".into(),
                serde_json::Value::String("99".into()),
            );
        });
        let bundle = ProofBundle::from_json(&tampered).unwrap();
        let report = verify_bundle(&bundle);
        let shape = report
            .steps
            .iter()
            .find(|s| s.name == StepName::BundleShape)
            .expect("BundleShape step present");
        assert!(
            matches!(&shape.status, StepStatus::Fail(msg) if msg.contains("schema_version")),
            "expected schema_version Fail, got {:?}",
            shape.status
        );
    }

    #[test]
    fn bundle_shape_rejects_bad_algorithm_tag() {
        let (json, _) = valid_signed_bundle();
        let tampered = rewrite_lock_payload(&json, |obj| {
            obj.insert(
                "signature_algorithm".into(),
                serde_json::Value::String("evil".into()),
            );
        });
        let bundle = ProofBundle::from_json(&tampered).unwrap();
        let report = verify_bundle(&bundle);
        let shape = report
            .steps
            .iter()
            .find(|s| s.name == StepName::BundleShape)
            .expect("BundleShape step present");
        assert!(
            matches!(&shape.status, StepStatus::Fail(msg) if msg.contains("signature_algorithm")),
            "expected signature_algorithm Fail, got {:?}",
            shape.status
        );
    }

    #[test]
    fn bundle_shape_rejects_bad_weather_station_charset() {
        let (json, _) = valid_signed_bundle();
        let tampered = rewrite_lock_payload(&json, |obj| {
            obj.insert(
                "weather_station".into(),
                serde_json::Value::String("Middle-Wallop".into()),
            );
        });
        let bundle = ProofBundle::from_json(&tampered).unwrap();
        let report = verify_bundle(&bundle);
        let shape = report
            .steps
            .iter()
            .find(|s| s.name == StepName::BundleShape)
            .expect("BundleShape step present");
        assert!(
            matches!(&shape.status, StepStatus::Fail(msg) if msg.contains("weather_station")),
            "expected weather_station Fail, got {:?}",
            shape.status
        );
    }

    #[test]
    fn bundle_shape_rejects_non_canonical_locked_at() {
        let (json, _) = valid_signed_bundle();
        // Non-canonical: +00:00 instead of Z.
        let tampered = rewrite_lock_payload(&json, |obj| {
            obj.insert(
                "locked_at".into(),
                serde_json::Value::String("2026-04-09T12:00:00.000000+00:00".into()),
            );
        });
        let bundle = ProofBundle::from_json(&tampered).unwrap();
        let report = verify_bundle(&bundle);
        let shape = report
            .steps
            .iter()
            .find(|s| s.name == StepName::BundleShape)
            .expect("BundleShape step present");
        assert!(
            matches!(&shape.status, StepStatus::Fail(msg) if msg.contains("locked_at")),
            "expected locked_at Fail, got {:?}",
            shape.status
        );
    }

    #[test]
    fn verification_report_carries_self_consistency_mode() {
        let (json, _) = valid_signed_bundle();
        let bundle = ProofBundle::from_json(&json).unwrap();
        let report = verify_bundle(&bundle);
        assert_eq!(report.mode, VerifierMode::SelfConsistencyOnly);
    }
}
