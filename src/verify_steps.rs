use crate::bundle::ProofBundle;
use crate::key_resolver::{BundleEmbeddedResolver, InsertedAt, KeyClass, KeyResolver, ResolvedKey};
use crate::protocol::crypto;
use crate::protocol::receipts::{
    ENTROPY_COMPOSITION, EXECUTION_SCHEMA_VERSION, EXECUTION_SCHEMA_VERSION_V3,
    EXECUTION_SCHEMA_VERSION_V4, EXECUTION_SCHEMA_VERSION_V5, FAIR_PICK_VERSIONS,
    LOCK_SCHEMA_VERSION, LOCK_SCHEMA_VERSION_V5, LOCK_SCHEMA_VERSION_V6, ParsedExecutionReceipt,
    ParsedLockReceipt, lock_receipt_hash, parse_execution_receipt, parse_lock_receipt,
    validate_execution_receipt_tags, validate_execution_receipt_tags_v3,
    validate_execution_receipt_tags_v4, validate_execution_receipt_tags_v5,
    validate_execution_receipt_tags_v5_freq, validate_lock_receipt_tags,
    validate_lock_receipt_tags_v5, validate_lock_receipt_tags_v6,
    validate_lock_receipt_tags_v6_freq,
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
    /// The lock receipt's `entry_hash` equals the entry hash recomputed
    /// from the bundle. Under lock v6 (the Land Observations tag), its
    /// `commitment_hash` must equal that entry hash too.
    LockReceiptEntryHash,
    ExecReceiptEntryHash,
    SeedRecomputation,
    WinnerSelection,
    /// The drand beacon in the signed execution receipt: BLS signature
    /// valid on the pinned quicknet chain, `sha256(signature) ==
    /// randomness`, the bundle's `entropy` block equal to the receipt, and
    /// the round published strictly after the lock receipt's `locked_at`.
    /// Under lock v6 or execution v5 (either), also that the execution
    /// receipt's `executed_at` is not before the round published.
    DrandBlsSignature,
    /// Cross-receipt field consistency — the cross-checked fields listed in
    /// spec §4.2.5 MUST be byte-identical. Bundle-envelope `draw_id` MUST
    /// also match. Closes splice-attack class per spec §4.2.5. Appended
    /// rather than inserted mid-list so external consumers pinning step
    /// ordinals are not broken. Under lock v6 / execution v5,
    /// `weather_station` is checked against the Land Observations tag's
    /// station list instead: the lock names the primary station, the
    /// execution receipt names a listed station, and a fallback names the
    /// primary. Under lock v6 / execution v5, `operator_slug` and
    /// `fair_pick_version` are also byte-identical across the receipts, and
    /// `fair_pick_version` must be one this verifier implements. The rules
    /// are chosen by each receipt's `(schema_version, entropy_composition)`
    /// pair; a pair the verifier does not know fails this step.
    ReceiptFieldConsistency,
    /// Weather observation window. Lock v4/v5: the execution receipt's
    /// `weather_observation_time` falls in
    /// `[lock.weather_time - 3600s, lock.weather_time]`, and a fallback
    /// reason is present exactly when weather is missing; `NotApplicable`
    /// on a drand-only draw. Lock v6 / execution v5: `weather_time` is the
    /// observation hour the drand round implies, `locked_at` is at least
    /// 46 minutes before it, and the execution receipt carries either an
    /// observation of exactly that hour or the fallback reason
    /// `no_observation_by_deadline`, never a mix of the two. Always `Pass`
    /// or `Fail` under v6, fallback included, because the schedule is
    /// checked either way. On a fallback, `Pass` means the schedule holds.
    /// Whether the archive really had no observation is checked by
    /// `wallop-verify weather-attest`, not here. The rules are chosen by
    /// each receipt's `(schema_version, entropy_composition)` pair, never
    /// the schema alone; a pair the verifier does not know fails this step.
    WeatherObservationWindow,
    /// Bundle shape — both receipts MUST parse against the typed structs
    /// (`deny_unknown_fields`), MUST resolve via the schema_version
    /// dispatcher (terminal `UnknownSchemaVersion` on anything else), MUST
    /// pass the algorithm-identity-tag and `weather_station` charset
    /// validators, and every signed timestamp MUST be in canonical
    /// RFC 3339 form (`chrono_parse_canonical`). It covers lock receipt
    /// schema 4, 5 or 6 and execution receipt schema 2 to 5; under lock
    /// schema 6 / execution schema 5 it also checks the Land Observations
    /// tag pins (stations, fallback reason, `weather_value` grammar). Lock
    /// schema 6 must pair with execution schema 5 in both directions, and
    /// under lock schema 6 `weather_time`, `locked_at`, `executed_at` and
    /// `weather_observation_time` must be canonical and round-trip. The
    /// typed parsers and validators ship in `protocol/receipts.rs`; this
    /// step is the entry point that wires them into the verifier pipeline.
    /// Appended to the end of `StepName::all()` so external consumers
    /// pinning step ordinals are not broken; in pipeline execution order,
    /// this step runs FIRST and gates everything else.
    BundleShape,
    /// Temporal binding — every signed artefact is bound to the moment
    /// the signing key first appeared in the keyring (spec §4.2.4).
    /// After signature verification has resolved a key, this step
    /// asserts `resolved.inserted_at <= receipt.binding_timestamp`
    /// per receipt class:
    /// - operator key vs `lock.locked_at`
    /// - infrastructure key vs `execution.executed_at`
    ///
    /// Transparency-anchor binding is deferred to 1.x.
    ///
    /// Failure is terminal and surfaces a binding violation on a
    /// cryptographically-valid signature: the signature step passes
    /// (the key is the right key for its `key_id`, the signature is
    /// valid bytes-over-pk), but the key was not live when the
    /// receipt was signed.
    ///
    /// **Trust scope.** This step asserts the binding *given a
    /// trusted resolver*. A hostile tier-2 endpoint that lies about
    /// `inserted_at` in the earlier direction can bypass this check;
    /// only tier-1 pinning closes that. The step's strength is
    /// bounded by the resolver's trust root, not by the step itself.
    TemporalBinding,
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
            StepName::TemporalBinding,
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
            StepName::TemporalBinding => "Temporal binding",
        };
        f.write_str(s)
    }
}

/// Outcome of one verification step.
///
/// Non-exhaustive: a `match` outside this crate needs a wildcard arm, so a
/// new status can be added without a breaking change. Treat any status you
/// do not recognise as a failure, and use `VerificationReport::passed()`
/// for the overall verdict.
///
/// ```compile_fail
/// use wallop_verifier::verify_steps::StepStatus;
/// fn code(s: &StepStatus) -> u8 {
///     match s {
///         StepStatus::Pass => 0,
///         StepStatus::Fail(_) => 1,
///         StepStatus::Skip(_) => 2,
///         StepStatus::NotApplicable(_) => 3,
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum StepStatus {
    Pass,
    Fail(String),
    /// The step could not run. Never counts as a pass.
    Skip(String),
    /// The check genuinely does not apply to this bundle (e.g. no weather
    /// on a drand-only draw). Does not block a pass on its own.
    NotApplicable(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum StepDetail {
    HexMismatch {
        expected: String,
        computed: String,
    },
    /// Resolver-side failure surfaced on a downstream step
    /// (typically `LockSignature` / `ExecSignature`). Distinguishes
    /// `Unreachable` / `KeyNotFound` / `PinMismatch` /
    /// `MalformedResponse` / `InconsistentRow` / `SentinelRejected` /
    /// `LegacySentinelRejected` from the generic "Ed25519 signature
    /// invalid" message — without this, every resolver failure
    /// collapsed to the same opaque outcome.
    ResolutionFailure {
        class: KeyClass,
        kind: ResolutionFailureKind,
    },
}

/// Closed-set tag for a `ResolutionFailure` in a `StepDetail`. Wider
/// than `key_resolver::ResolutionError` because the verifier can
/// reject a syntactically-successful resolver result at the
/// call-site filter (Sentinel under non-self-consistency, or the
/// legacy sentinel string in `At(_)`).
///
/// Deliberately not `Copy` so a future variant carrying owned data
/// (e.g. `Unreachable { url }` for tier-2 diagnostics) doesn't break
/// every call site at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionFailureKind {
    /// The resolver could not reach its trust root (DNS, connection,
    /// timeout). Carried verbatim from `ResolutionError::Unreachable`.
    Unreachable,
    /// The trust root responded but did not list the requested
    /// `key_id`. Verbatim from `ResolutionError::KeyNotFound`.
    KeyNotFound,
    /// The trust root's response contradicted a pinned reference
    /// (tier-1 only). Verbatim from `ResolutionError::PinMismatch`.
    PinMismatch,
    /// The trust root's response did not parse as a valid keyring
    /// document. Verbatim from `ResolutionError::MalformedResponse`.
    MalformedResponse,
    /// A keyring row's `public_key_hex` did not hash to its claimed
    /// `key_id`. Verbatim from `ResolutionError::InconsistentRow`.
    InconsistentRow,
    /// The resolver returned `InsertedAt::Sentinel` under a
    /// non-self-consistency mode. `BundleEmbeddedResolver` is the
    /// only intended emitter; receiving this from a tier-2 / tier-1
    /// resolver is itself a protocol violation per spec §4.2.4.
    SentinelRejected,
    /// The resolver returned `InsertedAt::At` with the legacy
    /// sentinel literal `"0001-01-01T00:00:00.000000Z"`. Refused
    /// belt-and-braces — that string would silently pass any `<=`
    /// temporal-binding comparison.
    LegacySentinelRejected,
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
/// Per spec §4.2.4, three tiers exist:
///
/// - `Attributable` — keys resolved against an operator-hosted
///   `.well-known` pin on a domain the verifier crate does not control.
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
    /// domain the verifier crate does not control. **Not constructable
    /// in 1.0.0 — pending the resolver follow-up.**
    Attributable,
    /// Keys resolved from `/operator/:slug/keys` only. Same-origin caveat.
    /// **Not constructable in 1.0.0 — pending the resolver follow-up.**
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
    ///
    /// Every step must be `Pass`, and at least one must be. `NotApplicable`
    /// is accepted only on the steps that can genuinely not apply:
    /// `WeatherObservationWindow` (a drand-only draw has no observation)
    /// and `TemporalBinding` (vacuous against bundle-embedded keys). On any
    /// other step it counts as a failure. A `Skip` (a check that could not
    /// run) never counts as a pass.
    pub fn passed(&self) -> bool {
        self.steps.iter().all(|s| match s.status {
            StepStatus::Pass => true,
            StepStatus::NotApplicable(_) => matches!(
                s.name,
                StepName::WeatherObservationWindow | StepName::TemporalBinding
            ),
            _ => false,
        }) && self
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

/// Run the full verification pipeline using the bundle's inline keys
/// (legacy / self-consistency mode). Constructs a `BundleEmbeddedResolver`
/// internally; see `verify_bundle_with` for resolver-driven verification.
///
/// The returned report carries `mode = VerifierMode::SelfConsistencyOnly`,
/// which the proof page UX, CLI header, and JSON output MUST surface so a
/// reader of the report knows what the report's signature checks actually
/// proved (spec §4.2.4 caveat-mode disclosure).
pub fn verify_bundle(bundle: &ProofBundle) -> VerificationReport {
    let resolver = BundleEmbeddedResolver::from_bundle(bundle);
    verify_bundle_with(bundle, &resolver, VerifierMode::SelfConsistencyOnly)
}

/// Run the full verification pipeline against a caller-supplied
/// `KeyResolver`. The verifier reads keys exclusively via the resolver —
/// failure to resolve is terminal — the pipeline MUST NOT fall back to
/// receipt-inline keys (spec §4.2.4).
///
/// `mode` is recorded in the returned `VerificationReport.mode`. Callers
/// MUST pick a mode that matches the resolver's actual trust root —
/// `Attributable` for an operator-hosted `.well-known` pin,
/// `Attestable` for an unpinned `/operator/:slug/keys` endpoint,
/// `SelfConsistencyOnly` for `BundleEmbeddedResolver`. The verifier crate
/// does not police this association — it is the caller's contract with
/// the trust model. See spec §4.2.4.
pub fn verify_bundle_with<R: KeyResolver>(
    bundle: &ProofBundle,
    resolver: &R,
    mode: VerifierMode,
) -> VerificationReport {
    let mut steps = Vec::new();

    // Pre-parse receipts to extract `signing_key_id` for resolver lookups.
    // Parse failure is captured by `BundleShape` (which runs at the end of
    // the pipeline); when it occurs here, signature steps will fail too
    // because `resolver.resolve` cannot succeed without a key_id.
    let (lock_signing_key_id, lock_locked_at) =
        match parse_lock_receipt(&bundle.lock_receipt.payload_jcs).ok() {
            Some(ParsedLockReceipt::V4(r)) => (Some(r.signing_key_id), Some(r.locked_at)),
            Some(ParsedLockReceipt::V5(r)) => (Some(r.signing_key_id), Some(r.locked_at)),
            Some(ParsedLockReceipt::V6(r)) => (Some(r.signing_key_id), Some(r.locked_at)),
            Some(ParsedLockReceipt::V6Freq(r)) => (Some(r.signing_key_id), Some(r.locked_at)),
            None => (None, None),
        };
    let (exec_signing_key_id, exec_executed_at) =
        match parse_execution_receipt(&bundle.execution_receipt.payload_jcs).ok() {
            // exec v2 carries no signing_key_id on the signed payload.
            // The pipeline below derives a synthetic key_id by hashing
            // the inline pubkey, so every resolver call carries a real
            // key_id; tier-2 / tier-1 resolvers will not find it in
            // their keyring and return `KeyNotFound` — the correct
            // outcome (exec v2 has no out-of-band identity).
            Some(ParsedExecutionReceipt::V2(r)) => (None, Some(r.executed_at)),
            Some(ParsedExecutionReceipt::V3(r)) => (Some(r.signing_key_id), Some(r.executed_at)),
            Some(ParsedExecutionReceipt::V4(r)) => (Some(r.signing_key_id), Some(r.executed_at)),
            Some(ParsedExecutionReceipt::V5(r)) => (Some(r.signing_key_id), Some(r.executed_at)),
            Some(ParsedExecutionReceipt::V5Freq(r)) => {
                (Some(r.signing_key_id), Some(r.executed_at))
            }
            None => (None, None),
        };

    // Synthesise the exec key_id for v2 bundles: hash the inline pubkey.
    // This keeps every resolver call honest — the resolver receives a
    // real key_id in every call, never a sentinel.
    let exec_key_id_for_resolve: Option<String> = exec_signing_key_id.clone().or_else(|| {
        let inline = bundle.execution_receipt.public_key_hex.as_deref()?;
        let bytes = hex::decode(inline).ok()?;
        let pk: [u8; 32] = bytes.try_into().ok()?;
        Some(crypto::key_id(&pk))
    });

    // Resolve operator and infrastructure keys. Failure is terminal — the
    // signature step will simply fail to verify when `op_pk` / `infra_pk`
    // is `None`, and the verifier never inspects inline keys after this
    // point.
    //
    // After resolution, assert that `crypto::key_id(resolved.public_key)`
    // equals the requested key_id. A buggy or hostile resolver answering
    // a request for `key_id=X` with `pk_Y` (where Y != X) would otherwise
    // pass — the signature would verify against pk_Y. This is the
    // verifier-side mirror of the producer's keyring-row consistency
    // check (spec §4.2.4).
    // Resolve each class. Failures surface in two places:
    //   1. The signature step (LockSignature / ExecSignature) reports
    //      Fail with a `ResolutionFailure` detail naming the kind, so
    //      a `PinMismatch` / `Unreachable` is distinguishable from
    //      "Ed25519 signature invalid" in the report.
    //   2. The temporal-binding step skips with "no resolved key from
    //      previous step" because there's nothing to compare.
    let (op_resolved, op_resolution_err) = match resolve_with_filter(
        resolver,
        lock_signing_key_id.as_deref(),
        KeyClass::Operator,
        mode,
    ) {
        Ok(r) => (Some(r), None),
        Err(k) => (None, Some(k)),
    };
    let (infra_resolved, infra_resolution_err) = match resolve_with_filter(
        resolver,
        exec_key_id_for_resolve.as_deref(),
        KeyClass::Infrastructure,
        mode,
    ) {
        Ok(r) => (Some(r), None),
        Err(k) => (None, Some(k)),
    };

    let op_pk = op_resolved.as_ref().map(|r| r.public_key);
    let infra_pk = infra_resolved.as_ref().map(|r| r.public_key);

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
    let (lock_sig_status, lock_sig_detail) =
        signature_step_outcome(step2_pass, op_resolution_err.clone(), KeyClass::Operator);
    steps.push(StepResult {
        name: StepName::LockSignature,
        status: lock_sig_status,
        detail: lock_sig_detail,
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
    let (exec_sig_status, exec_sig_detail) = signature_step_outcome(
        step3_pass,
        infra_resolution_err.clone(),
        KeyClass::Infrastructure,
    );
    steps.push(StepResult {
        name: StepName::ExecSignature,
        status: exec_sig_status,
        detail: exec_sig_detail,
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
        if !step5a_pass {
            steps.push(StepResult {
                name: StepName::LockReceiptEntryHash,
                status: StepStatus::Fail(format!(
                    "expected {}, got {}",
                    computed_entry_hash, lock_eh
                )),
                detail: Some(StepDetail::HexMismatch {
                    expected: computed_entry_hash.clone(),
                    computed: lock_eh.to_string(),
                }),
            });
        } else {
            steps.push(check_lock_commitment_hash(
                &lock_parsed,
                &computed_entry_hash,
            ));
        }
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
    // The seed input is read from the signed execution receipt (never from
    // the bundle's unsigned `entropy` block), and its derivation is chosen
    // by the receipts' (schema, tag) pair, never by which field is present.
    let exec_parsed: serde_json::Value =
        serde_json::from_str(&bundle.execution_receipt.payload_jcs).unwrap_or_default();
    let lock_for_rules: serde_json::Value =
        serde_json::from_str(&bundle.lock_receipt.payload_jcs).unwrap_or_default();
    let seed_input = SeedInput::from_receipts(&lock_for_rules, &exec_parsed);
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
        match &seed_input {
            Err(reason) => {
                steps.push(StepResult {
                    name: StepName::SeedRecomputation,
                    status: StepStatus::Fail(reason.clone()),
                    detail: None,
                });
                step6_pass = false;
            }
            Ok(input) => {
                let computed_seed = input.seed(&computed_entry_hash, exec_drand);
                let computed_seed_hex = hex::encode(computed_seed);
                step6_pass = computed_seed_hex == exec_seed;
                let mode = input.mode();
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
        }
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

        // step6_pass implies the seed input was read.
        let computed_seed = match &seed_input {
            Ok(input) => input.seed(&computed_entry_hash, exec_drand),
            Err(_) => unreachable!("winner selection runs only after the seed step passed"),
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
                    // The bundle's unsigned `results` (what a proof page
                    // displays) must say exactly what the receipt signed.
                    steps.push(StepResult {
                        name: StepName::WinnerSelection,
                        status: match check_bundle_results(bundle, &receipt_ids) {
                            Ok(()) => StepStatus::Pass,
                            Err(reason) => StepStatus::Fail(reason),
                        },
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

    // === Step 8: BLS drand verification (every build, including WASM) ===
    //
    // The beacon is read from the SIGNED execution receipt — the same
    // payload whose drand_randomness feeds the seed — and the bundle's
    // unsigned `entropy` block (weather_value included) must match it
    // field for field. Verifying `entropy` alone would let a genuine
    // beacon for any round vouch for whatever randomness the receipt
    // claims.
    if !step3_pass {
        steps.push(StepResult {
            name: StepName::DrandBlsSignature,
            status: StepStatus::Skip("exec signature failed".into()),
            detail: None,
        });
    } else {
        steps.push(StepResult {
            name: StepName::DrandBlsSignature,
            status: match check_drand_beacon(bundle, &exec_parsed) {
                Ok(()) => StepStatus::Pass,
                Err(reason) => StepStatus::Fail(reason),
            },
            detail: None,
        });
    }

    // === Step 10: Cross-receipt field consistency ===
    //
    // The cross-checked fields below MUST be byte-identical. Without this,
    // an infrastructure-level attacker signing a fraudulent exec receipt
    // can pair it with a legitimate lock from a different draw —
    // `lock_receipt_hash` binds lock bytes INTO the exec but does not bind
    // the exec's own duplicated fields back to the lock.
    //
    // Fields checked (spec §4.2.5): draw_id, operator_id, sequence,
    // drand_chain, drand_round, weather_station, entropy_composition.
    // Bundle envelope draw_id also cross-checked. Lock v6 / exec v5:
    // `weather_station` is not compared for equality; it is checked
    // against the Land Observations tag's station list (`check_landobs_stations`). See
    // `StepName::ReceiptFieldConsistency`. signing_key_id deliberately NOT
    // checked (lock = operator key, exec = infra key; different by design).
    // Before lock v6 / exec v5, operator_slug and fair_pick_version are NOT
    // checked (operator_slug is derivative of operator_id). Lock v6 / exec
    // v5 compares both, and fair_pick_version must also be in
    // FAIR_PICK_VERSIONS. Algorithm identity tags NOT cross-checked
    // (validated per-receipt against pinned values already), except
    // entropy_composition, which also selects the rules both receipts are
    // checked under.
    steps.push(check_receipt_field_consistency(bundle));

    // === Step 11: Weather observation window ===
    //
    // Lock v4/v5: exec.weather_observation_time MUST fall in
    // [lock.weather_time - 3600s, lock.weather_time].
    // Lock v6 / exec v5: lock.weather_time is the hour the drand round
    // implies, the lock is at least 46 minutes before it, and the
    // observation (if any) is of exactly that hour.
    // See `StepName::WeatherObservationWindow` for the full rules.
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

    // === Step 13: Temporal binding ===
    //
    // After signature verification has resolved a key, assert that the
    // key was live when the receipt was signed:
    //   operator key:        resolved.inserted_at <= lock.locked_at
    //   infrastructure key:  resolved.inserted_at <= execution.executed_at
    //
    // No verifier-side skew tolerance per spec §4.2.4 — both timestamps
    // are operator-produced and committed before the verifier sees them.
    // Failure surfaces a binding violation on a cryptographically-valid
    // signature: the signature step passed, but the key was not yet
    // live when the receipt was signed.
    //
    // Skipped when there is no resolved key (signature step already
    // failed for an unrelated reason), and NotApplicable when the
    // resolver is `BundleEmbeddedResolver` running in
    // `VerifierMode::SelfConsistencyOnly` — the comparison is vacuous
    // there because the bundle is self-attesting (the trust root has
    // no out-of-band first-existence timestamp to compare against).
    steps.push(check_temporal_binding(
        op_resolved.as_ref(),
        infra_resolved.as_ref(),
        lock_locked_at.as_deref(),
        exec_executed_at.as_deref(),
    ));

    VerificationReport {
        steps,
        operator_key_id,
        infra_key_id,
        mode,
    }
}

/// Step 12 — Bundle shape gate.
///
/// Runs the typed parsers (`parse_lock_receipt`, `parse_execution_receipt`),
/// the tag validators (`validate_lock_receipt_tags`,
/// `validate_execution_receipt_tags`/`_v3`), and a canonical RFC 3339
/// regex check (`chrono_parse_canonical`) on every signed timestamp. Closes
/// the validators in `protocol/receipts.rs` and ensures the verifier
/// pipeline calls every one of them on every bundle.
///
/// A bundle that passes this step is well-shaped per spec §4.2.1: closed
/// field set on receipts, recognised `schema_version`, pinned algorithm
/// tags, charset-conforming `weather_station`, canonical signed timestamps.
/// Resolver call-site filter (spec §4.2.4): defines when a resolved
/// key's `inserted_at` is permitted to flow into the verification
/// pipeline.
///
/// - `Sentinel` is permitted **only** under `VerifierMode::SelfConsistencyOnly`.
///   `BundleEmbeddedResolver` is the only intended emitter; receiving
///   it from any other mode is a resolver-contract violation. Drop the
///   resolved key here so the signature step fails terminally rather
///   than letting `Sentinel` leak into the temporal-binding comparison.
/// - `At(timestamp)` is permitted unless the timestamp falls in the
///   sentinel year `0001`. The pre-0.13.0 magic-string sentinel was
///   `"0001-01-01T00:00:00.000000Z"`; rejecting only that exact literal
///   would let a hostile tier-2 endpoint backdate to year-0001 with a
///   one-microsecond perturbation (e.g.
///   `"0001-01-01T00:00:00.000001Z"`) and trivially pass any `<=`
///   comparison. Reject the entire sentinel-year prefix so any
///   year-0001 timestamp surfaces as `LegacySentinelRejected` rather
///   than silently disabling temporal binding.
///
/// Returns `Ok(())` if the resolved key may be used; `Err(kind)` to
/// drop it (which surfaces as a signature-step failure downstream
/// with the kind in `StepDetail`, and a temporal-binding skip).
fn accept_inserted_at_for_mode(
    inserted_at: &InsertedAt,
    mode: VerifierMode,
) -> Result<(), ResolutionFailureKind> {
    match inserted_at {
        InsertedAt::Sentinel => {
            if matches!(mode, VerifierMode::SelfConsistencyOnly) {
                Ok(())
            } else {
                Err(ResolutionFailureKind::SentinelRejected)
            }
        }
        InsertedAt::At(ts) => {
            if is_sentinel_year_timestamp(ts) {
                Err(ResolutionFailureKind::LegacySentinelRejected)
            } else {
                Ok(())
            }
        }
    }
}

/// Refuse any timestamp whose year-prefix is the sentinel year `0001`.
/// Matches the canonical RFC 3339 form (year occupies bytes 0..4 in
/// `YYYY-MM-DDTHH:MM:SS.ffffffZ`); a non-canonical timestamp slips
/// through here but `chrono_parse_canonical` rejects it later in the
/// step. Catches the perturbation surface a byte-equal check on the
/// pre-0.13.0 legacy literal misses — see `accept_inserted_at_for_mode`'s
/// doc for the threat model.
fn is_sentinel_year_timestamp(ts: &str) -> bool {
    ts.starts_with("0001-")
}

/// Resolve one key class, applying the keyring-row consistency check
/// (`crypto::key_id(resolved.public_key) == requested_key_id`) and the
/// `inserted_at` call-site filter. Captures the failure kind so the
/// downstream signature step can surface it as a `ResolutionFailure`
/// step detail rather than collapsing every failure into the generic
/// "Ed25519 signature invalid."
///
/// Returns `Ok(ResolvedKey)` for a usable resolution, `Err(kind)`
/// otherwise. `Err` cases:
///
/// - No `key_id` to look up (`requested_key_id` is `None`) → treated
///   as `KeyNotFound`. This happens when the receipt parse failed,
///   which `BundleShape` will already have caught — the verifier
///   reports both in the same run.
/// - `resolver.resolve` returned an error → the variant maps directly.
/// - Returned `public_key`'s key_id does not match the requested one
///   → `InconsistentRow` (the verifier-side mirror of the producer's
///   keyring-row consistency check; spec §4.2.4).
/// - Returned `inserted_at` was rejected by the call-site filter →
///   the corresponding `Sentinel` / `LegacySentinel` rejection kind.
fn resolve_with_filter<R: KeyResolver>(
    resolver: &R,
    requested_key_id: Option<&str>,
    class: KeyClass,
    mode: VerifierMode,
) -> Result<ResolvedKey, ResolutionFailureKind> {
    let kid = requested_key_id.ok_or(ResolutionFailureKind::KeyNotFound)?;
    let resolved = resolver
        .resolve(kid, class)
        .map_err(map_resolution_error_kind)?;
    if crypto::key_id(&resolved.public_key) != kid {
        return Err(ResolutionFailureKind::InconsistentRow);
    }
    accept_inserted_at_for_mode(&resolved.inserted_at, mode)?;
    Ok(resolved)
}

fn map_resolution_error_kind(err: crate::key_resolver::ResolutionError) -> ResolutionFailureKind {
    use crate::key_resolver::ResolutionError;
    match err {
        ResolutionError::Unreachable => ResolutionFailureKind::Unreachable,
        ResolutionError::KeyNotFound => ResolutionFailureKind::KeyNotFound,
        ResolutionError::PinMismatch => ResolutionFailureKind::PinMismatch,
        ResolutionError::MalformedResponse => ResolutionFailureKind::MalformedResponse,
        ResolutionError::InconsistentRow => ResolutionFailureKind::InconsistentRow,
    }
}

/// Compute the `(status, detail)` for a signature step (`LockSignature`
/// or `ExecSignature`).
///
/// Three outcomes:
/// - Signature passed: `(Pass, None)`.
/// - Signature failed AND a resolution failure kind is known
///   (resolver failed before signature verification could run, or
///   the call-site filter dropped the resolved key): `(Fail(kind.message), Some(ResolutionFailure))`.
/// - Signature failed with no known resolution failure (resolver
///   succeeded but the bytes don't verify): `(Fail("Ed25519 signature invalid"), None)`.
fn signature_step_outcome(
    sig_pass: bool,
    resolution_err: Option<ResolutionFailureKind>,
    class: KeyClass,
) -> (StepStatus, Option<StepDetail>) {
    if sig_pass {
        return (StepStatus::Pass, None);
    }
    match resolution_err {
        Some(kind) => (
            StepStatus::Fail(format!(
                "{} key resolution failed: {}",
                class,
                kind.message()
            )),
            Some(StepDetail::ResolutionFailure { class, kind }),
        ),
        None => (StepStatus::Fail("Ed25519 signature invalid".into()), None),
    }
}

impl ResolutionFailureKind {
    /// Human-readable rendering for `StepStatus::Fail` messages.
    /// Distinct strings per variant so a reader of the report can
    /// tell which failure mode produced the rejection.
    pub fn message(&self) -> &'static str {
        match self {
            ResolutionFailureKind::Unreachable => "resolver could not reach its trust root",
            ResolutionFailureKind::KeyNotFound => "trust root does not list the requested key_id",
            ResolutionFailureKind::PinMismatch => "live keyring contradicts pinned reference",
            ResolutionFailureKind::MalformedResponse => "trust root response did not parse",
            ResolutionFailureKind::InconsistentRow => {
                "keyring row's key_id does not hash to its public_key"
            }
            ResolutionFailureKind::SentinelRejected => {
                "resolver returned Sentinel inserted_at under a non-self-consistency mode \
                 (protocol violation per spec §4.2.4)"
            }
            ResolutionFailureKind::LegacySentinelRejected => {
                "resolver returned the legacy 0001-01-01 sentinel literal in inserted_at"
            }
        }
    }
}

/// What the seed is derived from, read from the signed execution receipt
/// and chosen by the receipts' (schema, tag) pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SeedInput<'a> {
    /// No entropy value: drand alone (a fallback, or a drand-only draw).
    DrandOnly,
    /// `compute_seed` with the signed `weather_value`.
    Weather(&'a str),
    /// `compute_seed_freq` with the signed `freq_value` (grid-frequency
    /// pair only).
    Freq(&'a str),
}

impl<'a> SeedInput<'a> {
    /// Under the grid-frequency pair the seed comes from `freq_value`, and a
    /// non-null `weather_value` is refused. Under every other pair it comes
    /// from `weather_value` as before (an unknown or mismatched pair fails
    /// the steps that pick their rules from the pair). Absent or null means
    /// drand only; any other non-string value fails.
    fn from_receipts(
        lock: &serde_json::Value,
        exec: &'a serde_json::Value,
    ) -> Result<SeedInput<'a>, String> {
        fn signed_text<'a>(
            exec: &'a serde_json::Value,
            key: &str,
        ) -> Result<Option<&'a str>, String> {
            match exec.get(key).filter(|v| !v.is_null()) {
                None => Ok(None),
                Some(v) => v
                    .as_str()
                    .map(Some)
                    .ok_or_else(|| format!("exec receipt {key} is neither a string nor null")),
            }
        }
        if weather_rules(lock, exec) == WeatherRules::Freq {
            if exec.get("weather_value").is_some_and(|v| !v.is_null()) {
                return Err(format!(
                    "exec receipt weather_value must be null under {}",
                    crate::protocol::freq_v1::ENTROPY_COMPOSITION
                ));
            }
            Ok(signed_text(exec, "freq_value")?.map_or(SeedInput::DrandOnly, SeedInput::Freq))
        } else {
            Ok(
                signed_text(exec, "weather_value")?
                    .map_or(SeedInput::DrandOnly, SeedInput::Weather),
            )
        }
    }

    fn seed(&self, entry_hash: &str, drand_randomness: &str) -> [u8; 32] {
        match self {
            SeedInput::DrandOnly => compute_seed_drand_only(entry_hash, drand_randomness).0,
            SeedInput::Weather(w) => compute_seed(entry_hash, drand_randomness, w).0,
            SeedInput::Freq(v) => {
                crate::protocol::compute_seed_freq(entry_hash, drand_randomness, v).0
            }
        }
    }

    fn mode(&self) -> &'static str {
        match self {
            SeedInput::DrandOnly => "drand only",
            SeedInput::Weather(_) => "drand + weather",
            SeedInput::Freq(_) => "drand + grid frequency",
        }
    }
}

/// Lock v6 / execution v5 carry one of two tags; both receipts must carry
/// the same one.
const TAG_PAIRING_ERROR: &str = "lock and execution receipts carry different entropy tags";

/// The tag a lock v6 / execution v5 receipt carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum V6Tag {
    LandObs,
    Freq,
}

fn check_bundle_shape(bundle: &ProofBundle) -> StepResult {
    // Lock receipt — typed parse via dispatcher (deny_unknown_fields,
    // schema_version dispatch). V4 and V5 carry byte-identical field sets;
    // version-specific tag validators differ only in the schema_version
    // constant they assert against.
    //
    // Schema-version-vs-bundle-shape consistency rule (spec §4.2.4): a v5
    // lock receipt MUST be paired with a wrapper that omits
    // `public_key_hex` (resolver-driven), and a v4 lock receipt MUST be
    // paired with a wrapper that includes one (inline-key legacy mode).
    // Mismatches reject as downgrade-relabel / upgrade-spoof attempts —
    // the same shape as the v2/v3 deny_unknown_fields defence (F2).
    let inline_lock_pk_present = bundle.lock_receipt.public_key_hex.is_some();
    let (lock_locked_at, lock_weather_time, lock_freq_start, lock_v6) =
        match parse_lock_receipt(&bundle.lock_receipt.payload_jcs) {
            Ok(ParsedLockReceipt::V4(p)) => {
                if let Err(e) = validate_lock_receipt_tags(&p) {
                    return StepResult {
                        name: StepName::BundleShape,
                        status: StepStatus::Fail(format!("lock receipt validation: {}", e)),
                        detail: None,
                    };
                }
                if !inline_lock_pk_present {
                    return StepResult {
                        name: StepName::BundleShape,
                        status: StepStatus::Fail(
                            "lock receipt schema_version=\"4\" requires inline \
                             public_key_hex on the bundle wrapper (upgrade-spoof check)"
                                .into(),
                        ),
                        detail: None,
                    };
                }
                (p.locked_at, Some(p.weather_time), None, None)
            }
            Ok(ParsedLockReceipt::V5(p)) => {
                if let Err(e) = validate_lock_receipt_tags_v5(&p) {
                    return StepResult {
                        name: StepName::BundleShape,
                        status: StepStatus::Fail(format!("lock receipt validation: {}", e)),
                        detail: None,
                    };
                }
                if inline_lock_pk_present {
                    return StepResult {
                        name: StepName::BundleShape,
                        status: StepStatus::Fail(
                            "lock receipt schema_version=\"5\" must not carry inline \
                             public_key_hex on the bundle wrapper (downgrade-relabel check)"
                                .into(),
                        ),
                        detail: None,
                    };
                }
                (p.locked_at, Some(p.weather_time), None, None)
            }
            Ok(ParsedLockReceipt::V6(p)) => {
                if let Err(e) = validate_lock_receipt_tags_v6(&p) {
                    return StepResult {
                        name: StepName::BundleShape,
                        status: StepStatus::Fail(format!("lock receipt validation: {}", e)),
                        detail: None,
                    };
                }
                if inline_lock_pk_present {
                    return StepResult {
                        name: StepName::BundleShape,
                        status: StepStatus::Fail(
                            "lock receipt schema_version=\"6\" must not carry inline \
                             public_key_hex on the bundle wrapper (downgrade-relabel check)"
                                .into(),
                        ),
                        detail: None,
                    };
                }
                (
                    p.locked_at,
                    Some(p.weather_time),
                    None,
                    Some(V6Tag::LandObs),
                )
            }
            Ok(ParsedLockReceipt::V6Freq(p)) => {
                if let Err(e) = validate_lock_receipt_tags_v6_freq(&p) {
                    return StepResult {
                        name: StepName::BundleShape,
                        status: StepStatus::Fail(format!("lock receipt validation: {}", e)),
                        detail: None,
                    };
                }
                if inline_lock_pk_present {
                    return StepResult {
                        name: StepName::BundleShape,
                        status: StepStatus::Fail(
                            "lock receipt schema_version=\"6\" must not carry inline \
                             public_key_hex on the bundle wrapper (downgrade-relabel check)"
                                .into(),
                        ),
                        detail: None,
                    };
                }
                (p.locked_at, None, Some(p.freq_start), Some(V6Tag::Freq))
            }
            Err(e) => {
                return StepResult {
                    name: StepName::BundleShape,
                    status: StepStatus::Fail(format!("lock receipt: {}", e)),
                    detail: None,
                };
            }
        };

    // Lock receipt — canonical timestamps.
    if let Err(e) = chrono_parse_canonical(&lock_locked_at) {
        return StepResult {
            name: StepName::BundleShape,
            status: StepStatus::Fail(format!("lock.locked_at: {}", e)),
            detail: None,
        };
    }
    if let Some(wt) = &lock_weather_time
        && let Err(e) = chrono_parse_canonical(wt)
    {
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
    // timestamp checks + schema-version-vs-wrapper consistency. v2/v3/v4
    // share field shape modulo `signing_key_id` (added in v3) and the
    // schema_version constant (v4 is byte-identical to v3 on the signed
    // payload; the bump signals resolver-driven verification).
    let inline_exec_pk_present = bundle.execution_receipt.public_key_hex.is_some();
    let (executed_at, weather_observation_time, exec_v5) = match &parsed_exec {
        ParsedExecutionReceipt::V2(p) => {
            if let Err(e) = validate_execution_receipt_tags(p) {
                return StepResult {
                    name: StepName::BundleShape,
                    status: StepStatus::Fail(format!("exec receipt validation: {}", e)),
                    detail: None,
                };
            }
            if !inline_exec_pk_present {
                return StepResult {
                    name: StepName::BundleShape,
                    status: StepStatus::Fail(
                        "execution receipt schema_version=\"2\" requires inline \
                         public_key_hex on the bundle wrapper (upgrade-spoof check)"
                            .into(),
                    ),
                    detail: None,
                };
            }
            (
                p.executed_at.clone(),
                p.weather_observation_time.clone(),
                None,
            )
        }
        ParsedExecutionReceipt::V3(p) => {
            if let Err(e) = validate_execution_receipt_tags_v3(p) {
                return StepResult {
                    name: StepName::BundleShape,
                    status: StepStatus::Fail(format!("exec receipt validation: {}", e)),
                    detail: None,
                };
            }
            if !inline_exec_pk_present {
                return StepResult {
                    name: StepName::BundleShape,
                    status: StepStatus::Fail(
                        "execution receipt schema_version=\"3\" requires inline \
                         public_key_hex on the bundle wrapper (upgrade-spoof check)"
                            .into(),
                    ),
                    detail: None,
                };
            }
            (
                p.executed_at.clone(),
                p.weather_observation_time.clone(),
                None,
            )
        }
        ParsedExecutionReceipt::V4(p) => {
            if let Err(e) = validate_execution_receipt_tags_v4(p) {
                return StepResult {
                    name: StepName::BundleShape,
                    status: StepStatus::Fail(format!("exec receipt validation: {}", e)),
                    detail: None,
                };
            }
            if inline_exec_pk_present {
                return StepResult {
                    name: StepName::BundleShape,
                    status: StepStatus::Fail(
                        "execution receipt schema_version=\"4\" must not carry inline \
                         public_key_hex on the bundle wrapper (downgrade-relabel check)"
                            .into(),
                    ),
                    detail: None,
                };
            }
            (
                p.executed_at.clone(),
                p.weather_observation_time.clone(),
                None,
            )
        }
        ParsedExecutionReceipt::V5(p) => {
            if let Err(e) = validate_execution_receipt_tags_v5(p) {
                return StepResult {
                    name: StepName::BundleShape,
                    status: StepStatus::Fail(format!("exec receipt validation: {}", e)),
                    detail: None,
                };
            }
            if inline_exec_pk_present {
                return StepResult {
                    name: StepName::BundleShape,
                    status: StepStatus::Fail(
                        "execution receipt schema_version=\"5\" must not carry inline \
                         public_key_hex on the bundle wrapper (downgrade-relabel check)"
                            .into(),
                    ),
                    detail: None,
                };
            }
            (
                p.executed_at.clone(),
                p.weather_observation_time.clone(),
                Some(V6Tag::LandObs),
            )
        }
        ParsedExecutionReceipt::V5Freq(p) => {
            if let Err(e) = validate_execution_receipt_tags_v5_freq(p) {
                return StepResult {
                    name: StepName::BundleShape,
                    status: StepStatus::Fail(format!("exec receipt validation: {}", e)),
                    detail: None,
                };
            }
            if inline_exec_pk_present {
                return StepResult {
                    name: StepName::BundleShape,
                    status: StepStatus::Fail(
                        "execution receipt schema_version=\"5\" must not carry inline \
                         public_key_hex on the bundle wrapper (downgrade-relabel check)"
                            .into(),
                    ),
                    detail: None,
                };
            }
            (p.executed_at.clone(), None, Some(V6Tag::Freq))
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

    if lock_v6.is_some() != exec_v5.is_some() {
        return StepResult {
            name: StepName::BundleShape,
            status: StepStatus::Fail(SCHEMA_PAIRING_ERROR.into()),
            detail: None,
        };
    }
    if lock_v6 != exec_v5 {
        return StepResult {
            name: StepName::BundleShape,
            status: StepStatus::Fail(TAG_PAIRING_ERROR.into()),
            detail: None,
        };
    }
    if let Some(tag) = lock_v6 {
        // Under lock 6 every signed timestamp must round-trip: a string
        // such as `17:99` that only normalises to a real time is rejected.
        let mut strict = vec![
            ("lock.locked_at", lock_locked_at.as_str()),
            ("exec.executed_at", executed_at.as_str()),
        ];
        if let Some(obs) = &weather_observation_time {
            strict.push(("exec.weather_observation_time", obs.as_str()));
        }
        for (field, value) in strict {
            if let Err(e) = chrono_parse_canonical_strict(value) {
                return StepResult {
                    name: StepName::BundleShape,
                    status: StepStatus::Fail(format!("{field}: {e}")),
                    detail: None,
                };
            }
        }
        let parsed = match tag {
            V6Tag::LandObs => crate::protocol::landobs_v1::parse_weather_time(
                lock_weather_time.as_deref().unwrap_or_default(),
            )
            .map_err(|e| format!("lock.weather_time: {e}")),
            V6Tag::Freq => crate::protocol::freq_v1::parse_freq_start(
                lock_freq_start.as_deref().unwrap_or_default(),
            )
            .map_err(|e| format!("lock.freq_start: {e}")),
        };
        if let Err(reason) = parsed {
            return StepResult {
                name: StepName::BundleShape,
                status: StepStatus::Fail(reason),
                detail: None,
            };
        }
    }

    StepResult {
        name: StepName::BundleShape,
        status: StepStatus::Pass,
        detail: None,
    }
}

/// Part of step 7 (`WinnerSelection`): the bundle's unsigned `results`
/// must equal the signed execution receipt's `results`, element by
/// element: `results[i].entry_id == receipt.results[i]` and
/// `results[i].position == i + 1`, with equal lengths.
fn check_bundle_results(bundle: &ProofBundle, receipt_ids: &[&str]) -> Result<(), String> {
    if bundle.results.len() != receipt_ids.len() {
        return Err(format!(
            "bundle results has {} entries, the signed execution receipt has {}",
            bundle.results.len(),
            receipt_ids.len()
        ));
    }
    for (i, (result, receipt_id)) in bundle.results.iter().zip(receipt_ids).enumerate() {
        if result.entry_id != *receipt_id {
            return Err(format!(
                "bundle results[{i}].entry_id ({}) does not match the signed execution receipt ({receipt_id})",
                result.entry_id
            ));
        }
        let expected_position = i as u64 + 1;
        if u64::from(result.position) != expected_position {
            return Err(format!(
                "bundle results[{i}].position is {}, expected {expected_position}",
                result.position
            ));
        }
    }
    Ok(())
}

/// Step 8 body (`DrandBlsSignature`). This step also owns the entropy
/// binding: take the drand beacon from the signed execution receipt,
/// require every field of the bundle's unsigned `entropy` block
/// (`drand_chain_hash`, `drand_round`, `drand_signature`,
/// `drand_randomness`, `weather_value`) to match the receipt exactly,
/// verify the BLS signature (and `sha256(signature) == randomness`), and
/// require the round to publish strictly after the lock receipt's
/// `locked_at` (`drand_round_after_lock`). Under lock v6 / execution v5
/// (either schema), also require `executed_at` not to precede the round's
/// publication (`drand_round_before_execution`).
fn check_drand_beacon(bundle: &ProofBundle, exec: &serde_json::Value) -> Result<(), String> {
    let exec_str = |field: &str| -> Result<&str, String> {
        exec.get(field)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("execution receipt {field} is missing or not a string"))
    };
    let chain = exec_str("drand_chain")?;
    let round = exec
        .get("drand_round")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "execution receipt drand_round is missing or not an integer".to_string())?;
    let signature = exec_str("drand_signature")?;
    let randomness = exec_str("drand_randomness")?;

    let entropy = &bundle.entropy;
    let mismatch = |field: &str,
                    bundle_val: &dyn std::fmt::Display,
                    exec_val: &dyn std::fmt::Display| {
        format!(
            "entropy.{field} ({bundle_val}) does not match the signed execution receipt ({exec_val})"
        )
    };
    if entropy.drand_chain_hash != chain {
        return Err(mismatch(
            "drand_chain_hash",
            &entropy.drand_chain_hash,
            &chain,
        ));
    }
    if entropy.drand_round != round {
        return Err(mismatch("drand_round", &entropy.drand_round, &round));
    }
    if entropy.drand_signature != signature {
        return Err(mismatch(
            "drand_signature",
            &entropy.drand_signature,
            &signature,
        ));
    }
    if entropy.drand_randomness != randomness {
        return Err(mismatch(
            "drand_randomness",
            &entropy.drand_randomness,
            &randomness,
        ));
    }

    // weather_value also feeds the seed. Bind the unsigned entropy copy to
    // the signed one (absent or null on both sides counts as equal), so
    // nothing shown from `entropy` can differ from what was verified.
    let exec_weather = match exec.get("weather_value").filter(|v| !v.is_null()) {
        None => None,
        Some(v) => Some(
            v.as_str()
                .ok_or_else(|| "execution receipt weather_value is not a string".to_string())?,
        ),
    };
    if entropy.weather_value.as_deref() != exec_weather {
        return Err(format!(
            "entropy.weather_value ({:?}) does not match the signed execution receipt ({:?})",
            entropy.weather_value, exec_weather
        ));
    }

    // The same binding for the grid-frequency value. A receipt without
    // `freq_value` (every other tag) allows no `entropy.freq_value`.
    let exec_freq = match exec.get("freq_value").filter(|v| !v.is_null()) {
        None => None,
        Some(v) => Some(
            v.as_str()
                .ok_or_else(|| "execution receipt freq_value is not a string".to_string())?,
        ),
    };
    if entropy.freq_value.as_deref() != exec_freq {
        return Err(format!(
            "entropy.freq_value ({:?}) does not match the signed execution receipt ({:?})",
            entropy.freq_value, exec_freq
        ));
    }

    crate::drand::verify_drand_round(chain, round, signature, randomness)
        .map_err(|e| e.to_string())?;

    // The beacon must not have existed when the draw locked, or whoever
    // locked could have known the randomness first.
    let lock: serde_json::Value =
        serde_json::from_str(&bundle.lock_receipt.payload_jcs).unwrap_or_default();
    let locked_at = lock
        .get("locked_at")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "lock receipt locked_at is missing or not a string".to_string())?;
    drand_round_after_lock(round, locked_at)?;

    // Under lock v6 / execution v5 the beacon must also have been public
    // when the execution receipt was signed. Either schema triggers it.
    // An unrecognised pair gets the stricter rule too; the steps that pick
    // their rules from the pair fail it outright.
    if weather_rules(&lock, exec) != WeatherRules::Legacy {
        drand_round_before_execution(round, exec_str("executed_at")?)?;
    }
    Ok(())
}

/// `executed_at` (canonical RFC 3339, parsed with
/// `chrono_parse_canonical_strict`, so a time that would normalise is
/// rejected) must not be earlier than the quicknet publish time of `round`.
/// Whole seconds suffice: for a whole number P, `executed_at >= P` iff
/// `floor(executed_at) >= P`.
pub(crate) fn drand_round_before_execution(round: u64, executed_at: &str) -> Result<(), String> {
    let executed = chrono_parse_canonical_strict(executed_at)
        .map_err(|e| format!("execution receipt executed_at ({executed_at}): {e}"))?;
    let published = crate::drand::quicknet_round_time(round)
        .ok_or_else(|| format!("drand round {round} has no quicknet publish time"))?;
    if executed.timestamp() >= published {
        Ok(())
    } else {
        Err(format!(
            "execution receipt executed_at {executed_at} is before drand round {round} was published (unix time {published})"
        ))
    }
}

/// The quicknet `round` must publish strictly after `locked_at` (canonical
/// RFC 3339, parsed with `chrono_parse_canonical`). Publish time is
/// `QUICKNET_GENESIS_TIME + (round - 1) * QUICKNET_PERIOD_SECS`.
///
/// `locked_at` is asserted by the operator's lock signature, so this is a
/// consistency check that trusts the lock signer's clock: it catches a
/// receipt that claims to have locked after its own beacon was public,
/// not an operator who lies about the time.
pub(crate) fn drand_round_after_lock(round: u64, locked_at: &str) -> Result<(), String> {
    let locked = chrono_parse_canonical(locked_at)
        .map_err(|e| format!("lock receipt locked_at ({locked_at}): {e}"))?;
    let published = crate::drand::quicknet_round_time(round)
        .ok_or_else(|| format!("drand round {round} has no quicknet publish time"))?;
    // Comparing whole seconds is exact: drand publishes on whole seconds,
    // and for a whole number P, P > locked_at iff P > floor(locked_at).
    if published > locked.timestamp() {
        Ok(())
    } else {
        Err(format!(
            "drand round {round} was published at unix time {published}, \
             not after lock receipt locked_at {locked_at}"
        ))
    }
}

/// Step 5a once the lock's `entry_hash` matches: under lock v6, either tag
/// (its `(schema_version, entropy_composition)` pair selects the Land
/// Observations or grid-frequency rules), `commitment_hash` must equal
/// that entry hash. Older lock schemas are not checked.
fn check_lock_commitment_hash(lock: &serde_json::Value, entry_hash: &str) -> StepResult {
    let pass = || StepResult {
        name: StepName::LockReceiptEntryHash,
        status: StepStatus::Pass,
        detail: None,
    };
    if !matches!(
        rule_set_for("lock", lock, LOCK_RULE_SETS),
        Ok(RuleSet::LandObs | RuleSet::Freq)
    ) {
        return pass();
    }
    match lock.get("commitment_hash").and_then(|v| v.as_str()) {
        Some(c) if c == entry_hash => pass(),
        other => StepResult {
            name: StepName::LockReceiptEntryHash,
            status: StepStatus::Fail(format!(
                "lock receipt commitment_hash ({}) is not its entry_hash ({entry_hash})",
                other.map_or_else(|| "missing or not a string".to_string(), str::to_string)
            )),
            detail: Some(StepDetail::HexMismatch {
                expected: entry_hash.to_string(),
                computed: other.unwrap_or("").to_string(),
            }),
        },
    }
}

/// Under lock v6 / execution v5 the cross-check has already made both
/// receipts' `fair_pick_version` identical; it must also name a `fair_pick`
/// release this verifier implements.
fn check_fair_pick_version(lock: &serde_json::Value) -> Result<(), String> {
    match lock.get("fair_pick_version").and_then(|v| v.as_str()) {
        Some(v) if FAIR_PICK_VERSIONS.contains(&v) => Ok(()),
        other => Err(format!(
            "fair_pick_version {} is not one this verifier implements ({})",
            other.map_or_else(
                || "missing or not a string".to_string(),
                |v| format!("{v:?}")
            ),
            FAIR_PICK_VERSIONS
                .iter()
                .map(|v| format!("{v:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// Lock receipt schema 6 and execution receipt schema 5 (either tag) may be
/// paired only with each other.
const SCHEMA_PAIRING_ERROR: &str = "lock receipt schema_version \"6\" and execution receipt schema_version \"5\" must be used together";

// Fields that MUST be byte-identical between lock and exec receipts per
// spec §4.2.5. draw_id is also cross-checked against the bundle envelope.
// entropy_composition is compared as well: it picks the rule set, so both
// receipts must name the same one. Today a differing tag already makes one
// receipt's (schema_version, entropy_composition) pair unknown, which fails
// first; the comparison guards a schema that later carries two tags.
const CROSS_CHECKED_FIELDS: &[&str] = &[
    "draw_id",
    "operator_id",
    "sequence",
    "drand_chain",
    "drand_round",
    "weather_station",
    "entropy_composition",
];

// Under lock v6 / execution v5, `weather_station` is not compared for
// equality: the lock names the primary station and the execution receipt
// names the station actually used (see `check_landobs_stations`).
// `operator_slug` and `fair_pick_version` are compared as well, and
// `fair_pick_version` must name a release this verifier implements (see
// `check_fair_pick_version`). Older schemas compare neither, so their
// verification is unchanged.
const CROSS_CHECKED_FIELDS_LANDOBS: &[&str] = &[
    "draw_id",
    "operator_id",
    "sequence",
    "drand_chain",
    "drand_round",
    "entropy_composition",
    "operator_slug",
    "fair_pick_version",
];

// Under the grid-frequency tag: the Land Observations v6 list
// (operator_slug and fair_pick_version included), plus weather_station,
// which both receipts carry as null.
const CROSS_CHECKED_FIELDS_FREQ: &[&str] = &[
    "draw_id",
    "operator_id",
    "sequence",
    "drand_chain",
    "drand_round",
    "entropy_composition",
    "operator_slug",
    "fair_pick_version",
    "weather_station",
];

fn check_landobs_stations(
    lock: &serde_json::Value,
    exec: &serde_json::Value,
) -> Result<(), String> {
    use crate::protocol::landobs_v1::{PRIMARY_STATION, STATIONS};
    // A station renders as its quoted string, or `missing or not a string`.
    fn station(receipt: &serde_json::Value) -> Option<&str> {
        receipt.get("weather_station").and_then(|v| v.as_str())
    }
    let render = |s: Option<&str>| {
        s.map_or_else(
            || "missing or not a string".to_string(),
            |s| format!("{s:?}"),
        )
    };
    let lock_station = station(lock);
    if lock_station != Some(PRIMARY_STATION) {
        return Err(format!(
            "lock weather_station {} is not the primary station {PRIMARY_STATION}",
            render(lock_station)
        ));
    }
    let exec_station = match station(exec) {
        Some(s) if STATIONS.contains(&s) => s,
        other => {
            let listed: Vec<String> = STATIONS.iter().map(|s| format!("{s:?}")).collect();
            return Err(format!(
                "exec weather_station {} is not one of {}",
                render(other),
                listed.join(", ")
            ));
        }
    };
    let fallback = exec.get("weather_value").is_none_or(|v| v.is_null());
    if fallback && exec_station != PRIMARY_STATION {
        return Err(format!(
            "a fallback execution receipt must name the primary station {PRIMARY_STATION}, not {exec_station}"
        ));
    }
    Ok(())
}

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

    let rules = weather_rules(&lock, &exec);
    let fields = match &rules {
        WeatherRules::Legacy => CROSS_CHECKED_FIELDS,
        WeatherRules::LandObs => CROSS_CHECKED_FIELDS_LANDOBS,
        WeatherRules::Freq => CROSS_CHECKED_FIELDS_FREQ,
        WeatherRules::Mismatched => {
            return StepResult {
                name: StepName::ReceiptFieldConsistency,
                status: StepStatus::Fail(mismatch_reason(&lock, &exec).into()),
                detail: None,
            };
        }
        WeatherRules::Unrecognised(reason) => {
            return StepResult {
                name: StepName::ReceiptFieldConsistency,
                status: StepStatus::Fail(reason.clone()),
                detail: None,
            };
        }
    };

    // Every cross-checked field must match byte-identically.
    for field in fields {
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

    if rules == WeatherRules::LandObs
        && let Err(reason) =
            check_landobs_stations(&lock, &exec).and_then(|()| check_fair_pick_version(&lock))
    {
        return StepResult {
            name: StepName::ReceiptFieldConsistency,
            status: StepStatus::Fail(reason),
            detail: None,
        };
    }
    if rules == WeatherRules::Freq
        && let Err(reason) = check_fair_pick_version(&lock)
    {
        return StepResult {
            name: StepName::ReceiptFieldConsistency,
            status: StepStatus::Fail(reason),
            detail: None,
        };
    }

    StepResult {
        name: StepName::ReceiptFieldConsistency,
        status: StepStatus::Pass,
        detail: None,
    }
}

/// Execution receipt schema versions that carry `weather_fallback_reason`
/// (all of them, as of v4). The fallback-reason rule applies only to these.
const EXEC_SCHEMAS_WITH_FALLBACK_REASON: &[&str] = &["2", "3", "4"];

/// The rule set one known `(schema_version, entropy_composition)` pair
/// selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleSet {
    /// The forecast tag on lock v4/v5 or execution v2/v3/v4.
    Legacy,
    /// The Land Observations tag on lock v6 or execution v5.
    LandObs,
    /// The grid-frequency tag on lock v6 or execution v5.
    Freq,
}

/// Every lock receipt `(schema_version, entropy_composition)` pair the
/// verifier knows. A schema may in future carry more than one tag, so the
/// rule set is chosen by the pair, never by the schema alone.
///
/// Schema 6 carries two tags, so the seed derivation is chosen by the
/// pair too, never by the schema or by which field is present: see
/// `SeedInput`, used by the seed recomputation and winner selection steps.
const LOCK_RULE_SETS: &[(&str, &str, RuleSet)] = &[
    (LOCK_SCHEMA_VERSION, ENTROPY_COMPOSITION, RuleSet::Legacy),
    (LOCK_SCHEMA_VERSION_V5, ENTROPY_COMPOSITION, RuleSet::Legacy),
    (
        LOCK_SCHEMA_VERSION_V6,
        crate::protocol::landobs_v1::ENTROPY_COMPOSITION,
        RuleSet::LandObs,
    ),
    (
        LOCK_SCHEMA_VERSION_V6,
        crate::protocol::freq_v1::ENTROPY_COMPOSITION,
        RuleSet::Freq,
    ),
];

/// Every execution receipt `(schema_version, entropy_composition)` pair
/// the verifier knows.
const EXEC_RULE_SETS: &[(&str, &str, RuleSet)] = &[
    (
        EXECUTION_SCHEMA_VERSION,
        ENTROPY_COMPOSITION,
        RuleSet::Legacy,
    ),
    (
        EXECUTION_SCHEMA_VERSION_V3,
        ENTROPY_COMPOSITION,
        RuleSet::Legacy,
    ),
    (
        EXECUTION_SCHEMA_VERSION_V4,
        ENTROPY_COMPOSITION,
        RuleSet::Legacy,
    ),
    (
        EXECUTION_SCHEMA_VERSION_V5,
        crate::protocol::landobs_v1::ENTROPY_COMPOSITION,
        RuleSet::LandObs,
    ),
    (
        EXECUTION_SCHEMA_VERSION_V5,
        crate::protocol::freq_v1::ENTROPY_COMPOSITION,
        RuleSet::Freq,
    ),
];

/// Which weather rules govern a receipt pair.
#[derive(Clone, Debug, PartialEq, Eq)]
enum WeatherRules {
    /// Lock v4/v5 with execution v2/v3/v4, both on the forecast tag: the
    /// rules before the Land Observations tag, unchanged.
    Legacy,
    /// Lock v6 with execution v5, both on the Land Observations tag.
    LandObs,
    /// Lock v6 with execution v5, both on the grid-frequency tag.
    Freq,
    /// Both receipts are known pairs, but they select different rule sets:
    /// one is v6/v5 and the other is not, or they carry different v6/v5
    /// tags. See `mismatch_reason`.
    Mismatched,
    /// A receipt's `(schema_version, entropy_composition)` pair is not one
    /// the verifier knows. Fails closed: every step that picks its rules
    /// from the pair fails with this reason.
    Unrecognised(String),
}

/// The rule set `receipt`'s `(schema_version, entropy_composition)` pair
/// selects from `known`, or why it selects none.
fn rule_set_for(
    which: &str,
    receipt: &serde_json::Value,
    known: &[(&str, &str, RuleSet)],
) -> Result<RuleSet, String> {
    let text = |field: &str| receipt.get(field).and_then(|v| v.as_str());
    let schema = text("schema_version")
        .ok_or_else(|| format!("{which} receipt schema_version is missing or not a string"))?;
    if !known.iter().any(|(s, _, _)| *s == schema) {
        return Err(format!(
            "{which} receipt schema_version {schema:?} is not one this verifier knows"
        ));
    }
    let tag = text("entropy_composition");
    known
        .iter()
        .find(|(s, t, _)| *s == schema && Some(*t) == tag)
        .map(|(_, _, rules)| *rules)
        .ok_or_else(|| {
            let shown = tag.map_or_else(
                || "missing or not a string".to_string(),
                |t| format!("{t:?}"),
            );
            format!(
                "{which} receipt schema_version {schema:?} with entropy_composition {shown} \
                 is not a combination this verifier knows"
            )
        })
}

fn weather_rules(lock: &serde_json::Value, exec: &serde_json::Value) -> WeatherRules {
    match (
        rule_set_for("lock", lock, LOCK_RULE_SETS),
        rule_set_for("execution", exec, EXEC_RULE_SETS),
    ) {
        (Err(reason), _) | (_, Err(reason)) => WeatherRules::Unrecognised(reason),
        (Ok(RuleSet::Legacy), Ok(RuleSet::Legacy)) => WeatherRules::Legacy,
        (Ok(RuleSet::LandObs), Ok(RuleSet::LandObs)) => WeatherRules::LandObs,
        (Ok(RuleSet::Freq), Ok(RuleSet::Freq)) => WeatherRules::Freq,
        (Ok(_), Ok(_)) => WeatherRules::Mismatched,
    }
}

/// Why a `WeatherRules::Mismatched` pair fails: two different v6/v5 tags,
/// or a v6/v5 receipt paired with an older schema.
fn mismatch_reason(lock: &serde_json::Value, exec: &serde_json::Value) -> &'static str {
    let v6_family = |r: Result<RuleSet, String>| matches!(r, Ok(RuleSet::LandObs | RuleSet::Freq));
    if v6_family(rule_set_for("lock", lock, LOCK_RULE_SETS))
        && v6_family(rule_set_for("execution", exec, EXEC_RULE_SETS))
    {
        TAG_PAIRING_ERROR
    } else {
        SCHEMA_PAIRING_ERROR
    }
}

/// The weather window under the Land Observations tag. The lock receipt's
/// `weather_time` must be the observation hour its drand round implies,
/// the lock must be at least `LOCK_OFFSET_SECS` before it (compared to the
/// microsecond), and the execution receipt must carry either an
/// observation of exactly that hour with no fallback reason, or no
/// observation with reason `no_observation_by_deadline`.
fn check_landobs_weather(lock: &serde_json::Value, exec: &serde_json::Value) -> Result<(), String> {
    use crate::protocol::landobs_v1;
    let lock_str = |field: &str| {
        lock.get(field)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("lock receipt {field} is missing or not a string"))
    };
    let weather_time = lock_str("weather_time")?;
    let weather_time_unix = landobs_v1::parse_weather_time(weather_time)
        .map_err(|e| format!("lock.weather_time: {e}"))?;
    let round = lock
        .get("drand_round")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "lock receipt drand_round is missing or not an integer".to_string())?;
    let expected = landobs_v1::weather_time_for_round(round)
        .ok_or_else(|| format!("drand round {round} has no quicknet publish time"))?;
    if weather_time_unix != expected {
        return Err(format!(
            "lock weather_time {weather_time} is not the observation hour for drand round {round}: expected {}",
            format_canonical(expected, 0)
        ));
    }

    let locked_at_str = lock_str("locked_at")?;
    let locked_at = chrono_parse_canonical_strict(locked_at_str)
        .map_err(|e| format!("lock.locked_at ({locked_at_str}): {e}"))?;
    let latest = landobs_v1::latest_lock_at(expected)
        .ok_or_else(|| format!("weather_time {weather_time} has no latest lock time"))?;
    let latest_micros = latest
        .checked_mul(1_000_000)
        .ok_or_else(|| format!("latest lock time {latest} is out of range"))?;
    if locked_at.timestamp_micros() > latest_micros {
        return Err(format!(
            "lock locked_at {locked_at_str} is later than weather_time minus {} minutes ({})",
            landobs_v1::LOCK_OFFSET_SECS / 60,
            format_canonical(latest, 0)
        ));
    }

    let field = |name: &str| exec.get(name).filter(|v| !v.is_null());
    let shown = |v: Option<&serde_json::Value>| if v.is_some() { "set" } else { "null" };
    match (
        field("weather_value"),
        field("weather_observation_time"),
        field("weather_fallback_reason"),
    ) {
        (Some(_), Some(observation), None) => {
            let observation = observation.as_str().ok_or_else(|| {
                "exec receipt weather_observation_time is not a string".to_string()
            })?;
            if observation == weather_time {
                Ok(())
            } else {
                Err(format!(
                    "exec weather_observation_time {observation} must equal lock weather_time {weather_time}"
                ))
            }
        }
        (None, None, Some(reason)) => {
            if reason.as_str() == Some(landobs_v1::FALLBACK_NO_OBSERVATION) {
                Ok(())
            } else {
                Err(format!(
                    "exec weather_fallback_reason {reason} is not \"{}\"",
                    landobs_v1::FALLBACK_NO_OBSERVATION
                ))
            }
        }
        (value, observation, reason) => Err(format!(
            "exec receipt must carry weather_value and weather_observation_time with no \
             weather_fallback_reason, or a weather_fallback_reason with neither; it has \
             weather_value {}, weather_observation_time {}, weather_fallback_reason {}",
            shown(value),
            shown(observation),
            shown(reason)
        )),
    }
}

/// The window under the grid-frequency tag: the lock's `freq_start` must be
/// the window start its drand round implies, the lock must be at least
/// `LOCK_GAP_SECS` before it (compared to the microsecond), and the
/// execution receipt must carry either a `freq_value` with no reason, or no
/// value with reason `no_frequency_by_deadline`.
fn check_freq_window(lock: &serde_json::Value, exec: &serde_json::Value) -> Result<(), String> {
    use crate::protocol::freq_v1;
    let lock_str = |field: &str| {
        lock.get(field)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("lock receipt {field} is missing or not a string"))
    };
    let freq_start = lock_str("freq_start")?;
    let start =
        freq_v1::parse_freq_start(freq_start).map_err(|e| format!("lock.freq_start: {e}"))?;
    let round = lock
        .get("drand_round")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "lock receipt drand_round is missing or not an integer".to_string())?;
    let expected = freq_v1::freq_start_for_round(round)
        .ok_or_else(|| format!("drand round {round} has no quicknet publish time"))?;
    if start != expected {
        return Err(format!(
            "lock freq_start {freq_start} is not the window start for drand round {round}: expected {}",
            freq_v1::format_freq_start(expected)
        ));
    }

    let locked_at_str = lock_str("locked_at")?;
    let locked_at = chrono_parse_canonical_strict(locked_at_str)
        .map_err(|e| format!("lock.locked_at ({locked_at_str}): {e}"))?;
    let latest = freq_v1::latest_lock_at(expected)
        .ok_or_else(|| format!("freq_start {freq_start} has no latest lock time"))?;
    let latest_micros = latest
        .checked_mul(1_000_000)
        .ok_or_else(|| format!("latest lock time {latest} is out of range"))?;
    if locked_at.timestamp_micros() > latest_micros {
        return Err(format!(
            "lock locked_at {locked_at_str} is later than freq_start minus {} seconds ({})",
            freq_v1::LOCK_GAP_SECS,
            freq_v1::format_freq_start(latest)
        ));
    }

    let field = |name: &str| exec.get(name).filter(|v| !v.is_null());
    let shown = |v: Option<&serde_json::Value>| if v.is_some() { "set" } else { "null" };
    match (field("freq_value"), field("freq_fallback_reason")) {
        (Some(_), None) => Ok(()),
        (None, Some(reason)) if reason.as_str() == Some(freq_v1::FALLBACK_NO_FREQUENCY) => Ok(()),
        (None, Some(reason)) => Err(format!(
            "exec freq_fallback_reason {reason} is not \"{}\"",
            freq_v1::FALLBACK_NO_FREQUENCY
        )),
        (value, reason) => Err(format!(
            "exec receipt must carry freq_value with no freq_fallback_reason, or a \
             freq_fallback_reason with no freq_value; it has freq_value {}, \
             freq_fallback_reason {}",
            shown(value),
            shown(reason)
        )),
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

    match weather_rules(&lock, &exec) {
        WeatherRules::Legacy => {}
        WeatherRules::Mismatched => {
            return StepResult {
                name: StepName::WeatherObservationWindow,
                status: StepStatus::Fail(mismatch_reason(&lock, &exec).into()),
                detail: None,
            };
        }
        WeatherRules::Freq => {
            return StepResult {
                name: StepName::WeatherObservationWindow,
                status: match check_freq_window(&lock, &exec) {
                    Ok(()) => StepStatus::Pass,
                    Err(reason) => StepStatus::Fail(reason),
                },
                detail: None,
            };
        }
        WeatherRules::Unrecognised(reason) => {
            return StepResult {
                name: StepName::WeatherObservationWindow,
                status: StepStatus::Fail(reason),
                detail: None,
            };
        }
        WeatherRules::LandObs => {
            return StepResult {
                name: StepName::WeatherObservationWindow,
                status: match check_landobs_weather(&lock, &exec) {
                    Ok(()) => StepStatus::Pass,
                    Err(reason) => StepStatus::Fail(reason),
                },
                detail: None,
            };
        }
    }

    // The exec receipt's weather_value and weather_observation_time travel
    // together. Neither present: weather fell back (drand-only), there is
    // no observation to window-bound, and the check is NotApplicable.
    // Exactly one present, or weather present without a locked
    // weather_time: the receipt is inconsistent, and since weather_value
    // feeds the seed the window cannot be waived, so it fails.
    //
    // Every execution receipt schema (v2, v3, v4) carries
    // `weather_fallback_reason`. It says why weather is missing, so it is
    // required exactly when there is no weather: a receipt with no weather
    // must carry a reason, and one with weather must not.
    let exec_field = |field: &str| exec.get(field).filter(|v| !v.is_null());
    let exec_weather_value = exec_field("weather_value");
    let exec_observation = exec_field("weather_observation_time");
    let has_fallback_field = matches!(
        exec.get("schema_version").and_then(|v| v.as_str()),
        Some(v) if EXEC_SCHEMAS_WITH_FALLBACK_REASON.contains(&v)
    );
    let fallback_reason = exec_field("weather_fallback_reason");

    if has_fallback_field && exec_weather_value.is_some() && fallback_reason.is_some() {
        return StepResult {
            name: StepName::WeatherObservationWindow,
            status: StepStatus::Fail(
                "exec receipt has weather_value and also a weather_fallback_reason".into(),
            ),
            detail: None,
        };
    }

    let exec_observation_time = match (exec_weather_value, exec_observation) {
        (None, None) => {
            if has_fallback_field && fallback_reason.is_none() {
                return StepResult {
                    name: StepName::WeatherObservationWindow,
                    status: StepStatus::Fail(
                        "exec receipt has no weather but no weather_fallback_reason".into(),
                    ),
                    detail: None,
                };
            }
            return StepResult {
                name: StepName::WeatherObservationWindow,
                status: StepStatus::NotApplicable(
                    "exec receipt has no weather_value or weather_observation_time".into(),
                ),
                detail: None,
            };
        }
        (Some(_), None) => {
            return StepResult {
                name: StepName::WeatherObservationWindow,
                status: StepStatus::Fail(
                    "exec receipt has weather_value but no weather_observation_time".into(),
                ),
                detail: None,
            };
        }
        (None, Some(_)) => {
            return StepResult {
                name: StepName::WeatherObservationWindow,
                status: StepStatus::Fail(
                    "exec receipt has weather_observation_time but no weather_value".into(),
                ),
                detail: None,
            };
        }
        (Some(_), Some(obs)) => match obs.as_str() {
            Some(s) => s,
            None => {
                return StepResult {
                    name: StepName::WeatherObservationWindow,
                    status: StepStatus::Fail(
                        "exec receipt weather_observation_time is not a string".into(),
                    ),
                    detail: None,
                };
            }
        },
    };

    let lock_weather_time = match lock.get("weather_time").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return StepResult {
                name: StepName::WeatherObservationWindow,
                status: StepStatus::Fail(
                    "exec receipt has weather_value but lock receipt has no weather_time".into(),
                ),
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

/// Step 13 — Temporal binding (spec §4.2.4).
///
/// Asserts `resolved.inserted_at <= receipt.binding_timestamp` per
/// receipt class. Three exits per class — `Pass`, `Fail(comparison)`,
/// `Fail(parse)` — and a fourth path that skips the whole step when
/// no key resolved.
///
/// The resolver call-site filter (`accept_inserted_at_for_mode`) has
/// already dropped `Sentinel`-from-non-self-consistency; by the time
/// we get here, an `op_resolved`/`infra_resolved` of `Some` paired
/// with `InsertedAt::Sentinel` can only mean self-consistency mode
/// (where the comparison is vacuous and the step is NotApplicable), and an `At(_)` is
/// guaranteed not to be the legacy sentinel literal. The
/// destructuring below relies on those invariants.
///
/// **Trust scope.** This check asserts the binding *given a trusted
/// resolver*. A hostile tier-2 endpoint that lies about `inserted_at`
/// in the earlier direction can bypass it; only tier-1 pinning closes
/// that gap. The step's strength is bounded by the resolver's trust
/// root.
fn check_temporal_binding(
    op_resolved: Option<&ResolvedKey>,
    infra_resolved: Option<&ResolvedKey>,
    lock_locked_at: Option<&str>,
    exec_executed_at: Option<&str>,
) -> StepResult {
    // No resolved keys at all — nothing to check, signature step has
    // already failed for an unrelated reason.
    if op_resolved.is_none() && infra_resolved.is_none() {
        return StepResult {
            name: StepName::TemporalBinding,
            status: StepStatus::Skip("no resolved key from previous step".into()),
            detail: None,
        };
    }

    // Per-class checks. Either class returning Sentinel means
    // self-consistency mode by the call-site filter's invariant — the
    // comparison is vacuous there. We track that explicitly so a
    // mixed bundle (e.g. one class resolved via a tier-2 path, the
    // other via the bundle) reports honestly.
    let mut any_evaluated = false;
    let op_outcome = check_one_class(
        op_resolved,
        lock_locked_at,
        "operator key",
        "lock.locked_at",
        &mut any_evaluated,
    );
    if let Err(reason) = op_outcome {
        return StepResult {
            name: StepName::TemporalBinding,
            status: StepStatus::Fail(reason),
            detail: None,
        };
    }
    let infra_outcome = check_one_class(
        infra_resolved,
        exec_executed_at,
        "infrastructure key",
        "execution.executed_at",
        &mut any_evaluated,
    );
    if let Err(reason) = infra_outcome {
        return StepResult {
            name: StepName::TemporalBinding,
            status: StepStatus::Fail(reason),
            detail: None,
        };
    }

    if any_evaluated {
        StepResult {
            name: StepName::TemporalBinding,
            status: StepStatus::Pass,
            detail: None,
        }
    } else {
        // Every resolved key was Sentinel — i.e. self-consistency
        // mode end-to-end. The comparison is vacuous; surface it
        // honestly as NotApplicable rather than a Pass that overstates
        // the guarantee.
        StepResult {
            name: StepName::TemporalBinding,
            status: StepStatus::NotApplicable(
                "self-consistency mode; binding check is vacuous against bundle-embedded keys"
                    .into(),
            ),
            detail: None,
        }
    }
}

/// Per-class temporal-binding check. Returns `Ok(())` for pass-or-skip,
/// `Err(reason)` for fail. Sets `any_evaluated` to `true` when an
/// `At(_)` actually got compared, so the caller can distinguish "all
/// classes were Sentinel-skipped" from "at least one class genuinely
/// passed."
///
/// Three exits per class:
/// - `Ok(())` — `Pass` (real comparison succeeded), or skip-equivalent
///   (no resolved key, or `Sentinel`).
/// - `Err(_)` — `Fail` from binding-comparison failure or from a
///   timestamp-parse failure.
fn check_one_class(
    resolved: Option<&ResolvedKey>,
    binding_timestamp: Option<&str>,
    class_label: &str,
    binding_label: &str,
    any_evaluated: &mut bool,
) -> Result<(), String> {
    let resolved = match resolved {
        Some(r) => r,
        // No resolved key for this class — either the receipt didn't
        // need one or the signature step failed. Skip this class
        // silently; the overall step's "no resolved key" branch
        // already reported when neither class resolved.
        None => return Ok(()),
    };

    let resolved_ts_str = match &resolved.inserted_at {
        InsertedAt::Sentinel => return Ok(()),
        InsertedAt::At(ts) => ts,
    };

    let binding_str = match binding_timestamp {
        Some(s) => s,
        // BundleShape gates this — an unparseable receipt cannot
        // reach here in a well-formed bundle. Defence-in-depth: if
        // somehow we do reach here without a binding timestamp, fail
        // loudly rather than silently skipping.
        None => {
            return Err(format!(
                "{class_label}: receipt is missing {binding_label}; \
                 BundleShape should already have rejected this bundle"
            ));
        }
    };

    let resolved_ts = chrono_parse_canonical(resolved_ts_str).map_err(|e| {
        format!("{class_label}: resolver-side inserted_at ({resolved_ts_str}) is malformed: {e}")
    })?;
    let binding_ts = chrono_parse_canonical(binding_str).map_err(|e| {
        format!("{class_label}: receipt-side {binding_label} ({binding_str}) is malformed: {e}")
    })?;

    *any_evaluated = true;

    if resolved_ts.timestamp() <= binding_ts.timestamp() {
        Ok(())
    } else {
        Err(format!(
            "{class_label}: inserted_at {resolved_ts_str} is after {binding_label} \
             {binding_str}; key was not live at signing time"
        ))
    }
}

// Parses the canonical RFC 3339 timestamp form pinned in spec §4.2.1
// (`YYYY-MM-DDTHH:MM:SS.ffffffZ`, exactly 6 fractional digits, Z suffix).
// Keeps whole unix seconds and the microseconds separately; use
// `timestamp_micros()` for any comparison that must not lose the
// fraction. This is a narrow parser, not a general-purpose RFC 3339
// parser — the spec §4.2.1 note explicitly warns against general-purpose
// parsers that accept variable fractional digit counts or +00:00 offsets.
pub(crate) fn chrono_parse_canonical(s: &str) -> Result<ChronoStub, String> {
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
    let us = parse_slice(20, 26)?;

    // Days-from-epoch via Rata Die (days-from-civil). The fractional
    // microseconds are kept in `micros`, not folded into `secs`.
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
        micros: us,
    })
}

/// `chrono_parse_canonical`, and the string must also be the canonical
/// rendering of the instant it parses to, so `17:99` or `09-31` is
/// rejected rather than normalised.
pub(crate) fn chrono_parse_canonical_strict(s: &str) -> Result<ChronoStub, String> {
    let t = chrono_parse_canonical(s)?;
    let micros = u32::try_from(t.micros).map_err(|e| e.to_string())?;
    if format_canonical(t.secs, micros) != s {
        return Err(format!("{s} is not a valid calendar time"));
    }
    Ok(t)
}

pub(crate) struct ChronoStub {
    secs: i64,
    micros: i64,
}

impl ChronoStub {
    pub(crate) fn timestamp(&self) -> i64 {
        self.secs
    }

    /// The microseconds field, 0..=999_999.
    pub(crate) fn subsec_micros(&self) -> i64 {
        self.micros
    }

    /// Microseconds since the unix epoch. Use this for comparisons that
    /// must not lose the fractional second.
    pub(crate) fn timestamp_micros(&self) -> i64 {
        self.secs * 1_000_000 + self.micros
    }
}

/// Render unix time in the canonical form `chrono_parse_canonical` accepts
/// (`YYYY-MM-DDTHH:MM:SS.ffffffZ`). Inverse of the parser for every valid
/// calendar instant from year 0 to 9999. `micros` must be below
/// 1_000_000; debug builds assert it.
pub(crate) fn format_canonical(unix_secs: i64, micros: u32) -> String {
    debug_assert!(micros < 1_000_000);
    // civil_from_days:
    // https://howardhinnant.github.io/date_algorithms.html#civil_from_days
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        secs_of_day / 3600,
        secs_of_day % 3600 / 60,
        secs_of_day % 60
    )
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
        let pk_bytes: [u8; 32] = sk.verifying_key().to_bytes();
        let pk_hex = hex::encode(pk_bytes);
        let kid = crate::protocol::crypto::key_id(&pk_bytes);

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
        let drand_randomness = crate::_test_support::BEACON_RANDOMNESS;
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
            "drand_round": crate::_test_support::BEACON_ROUND,
            "draw_id": "22222222-2222-2222-2222-222222222222",
            "entropy_composition": "drand-quicknet+openmeteo-v1",
            "entry_hash": &ehash,
            "fair_pick_version": "0.1.0",
            "jcs_version": "sha256-jcs-v1",
            "locked_at": "2023-08-23T15:50:00.000000Z",
            "operator_id": "11111111-1111-1111-1111-111111111111",
            "operator_slug": "acme-prizes",
            "schema_version": "4",
            "sequence": 1,
            "signature_algorithm": "ed25519",
            "signing_key_id": &kid,
            "wallop_core_version": "0.14.1",
            "weather_station": "middle-wallop",
            "weather_time": "2023-08-23T16:00:00.000000Z",
            "winner_count": 2
        })
        .to_string();
        let lock_sig = sk.sign(lock_jcs.as_bytes());
        let lock_sig_hex = hex::encode(lock_sig.to_bytes());

        let lrh = compute_lock_hash(&lock_jcs);

        let exec_jcs = serde_json::json!({
            "drand_chain": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
            "drand_randomness": drand_randomness,
            "drand_round": crate::_test_support::BEACON_ROUND,
            "drand_signature": crate::_test_support::BEACON_SIGNATURE,
            "drand_signature_algorithm": "bls12_381_g2",
            "draw_id": "22222222-2222-2222-2222-222222222222",
            "entropy_composition": "drand-quicknet+openmeteo-v1",
            "entry_hash": &ehash,
            "executed_at": "2023-08-23T16:05:00.000000Z",
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
            "weather_observation_time": "2023-08-23T16:00:00.000000Z",
            "weather_station": "middle-wallop",
            "weather_value": weather_val
        })
        .to_string();
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
                "drand_round": crate::_test_support::BEACON_ROUND,
                "drand_randomness": drand_randomness,
                "drand_signature": crate::_test_support::BEACON_SIGNATURE,
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
        // The fixture carries a real quicknet beacon, so the report passes
        // overall whether or not this build runs the BLS step.
        assert!(
            report.passed(),
            "expected all pass, got: {:?}",
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

    #[test]
    fn verify_bundle_bad_drand_chain() {
        // The unknown chain goes into BOTH the signed execution receipt
        // (re-signed) and the entropy block, so the entropy binding holds
        // and the drand step rejects the chain itself.
        let bad_chain = "00".repeat(32);
        let (json, _) = valid_signed_bundle();
        let mut val = resign_exec(&json, |exec| {
            exec["drand_chain"] = serde_json::json!(bad_chain.clone());
        });
        val["entropy"]["drand_chain_hash"] = serde_json::json!(bad_chain);
        let bundle = ProofBundle::from_json(&val.to_string()).unwrap();
        let report = verify_bundle(&bundle);
        let bls_step = report
            .steps
            .iter()
            .find(|s| matches!(s.name, StepName::DrandBlsSignature))
            .unwrap();
        assert!(
            matches!(&bls_step.status, StepStatus::Fail(r) if r.contains("unknown drand chain")),
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
            13,
            "all() should return all 13 StepName variants"
        );
        assert!(all.contains(&StepName::EntryHash));
        assert!(all.contains(&StepName::DrandBlsSignature));
        assert!(all.contains(&StepName::ReceiptFieldConsistency));
        assert!(all.contains(&StepName::WeatherObservationWindow));
        assert!(all.contains(&StepName::BundleShape));
        assert!(all.contains(&StepName::TemporalBinding));
    }

    /// Ordinal-stability snapshot for `StepName::all()`. Step ordinals
    /// are part of the verifier's wire contract — external consumers
    /// pin them, vector files reference them, and the
    /// `expected_catch_steps` machinery dispatches on them. Append-only
    /// is the rule. Reordering or inserting mid-list is a v2.0.0
    /// change. This test fails loud if anyone tries.
    ///
    /// The match arms below mirror every variant by Rust identifier,
    /// not by `Display` string — so this test ALSO catches a rename
    /// (e.g. `StepName::Foo → StepName::Bar` keeping the ordinal
    /// stable would still break external string-pinned consumers; the
    /// match arm would no longer compile until the test was updated).
    #[test]
    fn step_name_all_ordinal_snapshot() {
        let actual: Vec<&'static str> = StepName::all()
            .iter()
            .map(|s| match s {
                StepName::EntryHash => "EntryHash",
                StepName::LockSignature => "LockSignature",
                StepName::ExecSignature => "ExecSignature",
                StepName::ReceiptLinkage => "ReceiptLinkage",
                StepName::LockReceiptEntryHash => "LockReceiptEntryHash",
                StepName::ExecReceiptEntryHash => "ExecReceiptEntryHash",
                StepName::SeedRecomputation => "SeedRecomputation",
                StepName::WinnerSelection => "WinnerSelection",
                StepName::DrandBlsSignature => "DrandBlsSignature",
                StepName::ReceiptFieldConsistency => "ReceiptFieldConsistency",
                StepName::WeatherObservationWindow => "WeatherObservationWindow",
                StepName::BundleShape => "BundleShape",
                StepName::TemporalBinding => "TemporalBinding",
            })
            .collect();

        let expected = vec![
            "EntryHash",
            "LockSignature",
            "ExecSignature",
            "ReceiptLinkage",
            "LockReceiptEntryHash",
            "ExecReceiptEntryHash",
            "SeedRecomputation",
            "WinnerSelection",
            "DrandBlsSignature",
            "ReceiptFieldConsistency",
            "WeatherObservationWindow",
            "BundleShape",
            "TemporalBinding",
        ];

        assert_eq!(
            actual, expected,
            "StepName::all() ordering changed. Append-only is the rule; \
             reordering or inserting mid-list is a v2.0.0 change. If you \
             added a new variant, append it here too."
        );
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

    // ── BundleShape gate ───────────────────────────────────────────────

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
                serde_json::Value::String("2023-08-23T15:50:00.000000+00:00".into()),
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

    // ── v5/v4 resolver-driven verification ────────────────────────────────

    use crate::_test_support::{MockResolver, build_valid_v5_bundle};
    use crate::key_resolver::BundleEmbeddedResolver;

    fn three_uuid_entries() -> Vec<Entry> {
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
    fn verify_bundle_v5_with_bundle_embedded_resolver_fails_keynotfound() {
        // BundleEmbeddedResolver cannot resolve a v5 bundle (no inline pk
        // in the wrapper). Lock-signature step fails because op_pk is None.
        let (json, _, _) = build_valid_v5_bundle(&three_uuid_entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let report = verify_bundle(&bundle);
        assert!(!report.passed());
        let lock_sig = report
            .steps
            .iter()
            .find(|s| s.name == StepName::LockSignature)
            .unwrap();
        assert!(matches!(lock_sig.status, StepStatus::Fail(_)));
    }

    #[test]
    fn verify_bundle_with_mock_resolver_passes_v5() {
        let (json, pk_hex, signing_key_id) =
            build_valid_v5_bundle(&three_uuid_entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let pk: [u8; 32] = hex::decode(&pk_hex).unwrap().try_into().unwrap();
        let resolver = MockResolver::new(signing_key_id, pk);

        let report = verify_bundle_with(&bundle, &resolver, VerifierMode::Attestable);
        // Steps 1-7 should all be Pass under the resolver-driven path.
        for step in &report.steps[..7] {
            assert!(
                matches!(step.status, StepStatus::Pass),
                "step {} was {:?}",
                step.name,
                step.status
            );
        }
        // Real quicknet beacon: the report passes overall in every build.
        assert!(report.passed(), "expected pass; got {:?}", report.steps);
        // mode is plumbed through.
        assert_eq!(report.mode, VerifierMode::Attestable);
    }

    #[test]
    fn bundle_shape_rejects_v5_lock_with_inline_pubkey_downgrade_relabel() {
        let (json, pk_hex, _) = build_valid_v5_bundle(&three_uuid_entries(), Some("1013"), 2);
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Inject inline operator_public_key_hex into the v5 wrapper —
        // protocol violation; BundleShape MUST reject as downgrade-relabel.
        val["lock_receipt"]["operator_public_key_hex"] = serde_json::json!(pk_hex);
        let bundle = ProofBundle::from_json(&val.to_string()).unwrap();
        let report = verify_bundle(&bundle);
        let shape = report
            .steps
            .iter()
            .find(|s| s.name == StepName::BundleShape)
            .unwrap();
        assert!(
            matches!(&shape.status, StepStatus::Fail(msg) if msg.contains("downgrade-relabel")),
            "expected downgrade-relabel rejection; got {:?}",
            shape.status
        );
    }

    #[test]
    fn bundle_shape_rejects_v4_lock_without_inline_pubkey_upgrade_spoof() {
        let (json, _) = valid_signed_bundle();
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Strip the inline operator_public_key_hex from a legacy v4 bundle —
        // protocol violation; BundleShape MUST reject as upgrade-spoof.
        val["lock_receipt"]
            .as_object_mut()
            .unwrap()
            .remove("operator_public_key_hex");
        let bundle = ProofBundle::from_json(&val.to_string()).unwrap();
        let report = verify_bundle(&bundle);
        let shape = report
            .steps
            .iter()
            .find(|s| s.name == StepName::BundleShape)
            .unwrap();
        assert!(
            matches!(&shape.status, StepStatus::Fail(msg) if msg.contains("upgrade-spoof")),
            "expected upgrade-spoof rejection; got {:?}",
            shape.status
        );
    }

    #[test]
    fn bundle_shape_rejects_v2_exec_without_inline_pubkey_upgrade_spoof() {
        // Strip the infra public_key_hex from a legacy v2-exec bundle —
        // BundleShape MUST reject (v2 requires inline). Distinct lock
        // shape isolates the exec-side rule from the lock-side one.
        let (json, _) = valid_signed_bundle();
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        val["execution_receipt"]
            .as_object_mut()
            .unwrap()
            .remove("infrastructure_public_key_hex");
        let bundle = ProofBundle::from_json(&val.to_string()).unwrap();
        let report = verify_bundle(&bundle);
        let shape = report
            .steps
            .iter()
            .find(|s| s.name == StepName::BundleShape)
            .unwrap();
        assert!(
            matches!(&shape.status, StepStatus::Fail(msg) if msg.contains("upgrade-spoof")
                && msg.contains("execution receipt")),
            "expected exec upgrade-spoof rejection; got {:?}",
            shape.status
        );
    }

    #[test]
    fn bundle_embedded_resolver_v5_in_self_consistency_mode_fails() {
        // Direct construction: take a v5 bundle, run through default
        // verify_bundle (uses BundleEmbeddedResolver internally). All sig
        // steps fail because the resolver returns KeyNotFound.
        let (json, _, _) = build_valid_v5_bundle(&three_uuid_entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let resolver = BundleEmbeddedResolver::from_bundle(&bundle);
        let report = verify_bundle_with(&bundle, &resolver, VerifierMode::SelfConsistencyOnly);
        assert!(!report.passed());
        assert_eq!(report.mode, VerifierMode::SelfConsistencyOnly);
    }

    // ── Temporal binding (spec §4.2.4) ────────────────────────────────

    /// Resolver that returns a fixed pubkey + a caller-controlled
    /// `inserted_at`. Lets each test pin both halves of the
    /// temporal-binding comparison without conflating them with the
    /// row-consistency check.
    struct TimedResolver {
        signing_key_id: String,
        public_key: [u8; 32],
        inserted_at: InsertedAt,
    }

    impl crate::key_resolver::KeyResolver for TimedResolver {
        fn resolve(
            &self,
            key_id: &str,
            key_class: KeyClass,
        ) -> Result<crate::key_resolver::ResolvedKey, crate::key_resolver::ResolutionError>
        {
            if key_id != self.signing_key_id {
                return Err(crate::key_resolver::ResolutionError::KeyNotFound);
            }
            Ok(crate::key_resolver::ResolvedKey {
                public_key: self.public_key,
                inserted_at: self.inserted_at.clone(),
                key_class,
            })
        }
    }

    fn temporal_binding_step(report: &VerificationReport) -> &StepResult {
        report
            .steps
            .iter()
            .find(|s| s.name == StepName::TemporalBinding)
            .expect("TemporalBinding step present in every report")
    }

    #[test]
    fn temporal_binding_passes_when_inserted_at_predates_locked_at() {
        let (json, pk_hex, signing_key_id) =
            build_valid_v5_bundle(&three_uuid_entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let pk: [u8; 32] = hex::decode(&pk_hex).unwrap().try_into().unwrap();

        // build_valid_v5_bundle's lock.locked_at = 2023-08-23T15:50:00.000000Z.
        // Inserted_at well before that.
        let resolver = TimedResolver {
            signing_key_id,
            public_key: pk,
            inserted_at: InsertedAt::At("2023-08-01T00:00:00.000000Z".into()),
        };
        let report = verify_bundle_with(&bundle, &resolver, VerifierMode::Attestable);
        let step = temporal_binding_step(&report);
        assert!(
            matches!(step.status, StepStatus::Pass),
            "expected Pass, got {:?}",
            step.status
        );
    }

    #[test]
    fn temporal_binding_passes_when_inserted_at_equals_locked_at() {
        // Inclusive `<=`: equal timestamps pass. Spec says the key
        // existed at or before the moment of signing.
        let (json, pk_hex, signing_key_id) =
            build_valid_v5_bundle(&three_uuid_entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let pk: [u8; 32] = hex::decode(&pk_hex).unwrap().try_into().unwrap();

        let resolver = TimedResolver {
            signing_key_id,
            public_key: pk,
            inserted_at: InsertedAt::At("2023-08-23T15:50:00.000000Z".into()),
        };
        let report = verify_bundle_with(&bundle, &resolver, VerifierMode::Attestable);
        let step = temporal_binding_step(&report);
        assert!(
            matches!(step.status, StepStatus::Pass),
            "expected Pass on equal timestamps, got {:?}",
            step.status
        );
    }

    #[test]
    fn temporal_binding_fails_when_inserted_at_after_locked_at() {
        let (json, pk_hex, signing_key_id) =
            build_valid_v5_bundle(&three_uuid_entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let pk: [u8; 32] = hex::decode(&pk_hex).unwrap().try_into().unwrap();

        // Inserted_at one second after locked_at — backdating attempt.
        let resolver = TimedResolver {
            signing_key_id,
            public_key: pk,
            inserted_at: InsertedAt::At("2023-08-23T15:50:01.000000Z".into()),
        };
        let report = verify_bundle_with(&bundle, &resolver, VerifierMode::Attestable);
        let step = temporal_binding_step(&report);
        assert!(
            matches!(&step.status, StepStatus::Fail(reason) if reason.contains("not live at signing time")),
            "expected backdating Fail, got {:?}",
            step.status
        );
        assert!(!report.passed());
    }

    #[test]
    fn temporal_binding_not_applicable_under_self_consistency() {
        // BundleEmbeddedResolver always returns Sentinel; under
        // SelfConsistencyOnly the comparison is vacuous — the bundle
        // is self-attesting and there's no out-of-band timestamp.
        let (json, _) = valid_signed_bundle();
        let bundle = ProofBundle::from_json(&json).unwrap();
        let report = verify_bundle(&bundle);
        let step = temporal_binding_step(&report);
        assert!(
            matches!(&step.status, StepStatus::NotApplicable(reason) if reason.contains("self-consistency")),
            "expected NotApplicable under self-consistency, got {:?}",
            step.status
        );
    }

    #[test]
    fn temporal_binding_skips_when_no_resolved_key() {
        // v5 bundle + BundleEmbeddedResolver = both classes resolve
        // to None (KeyNotFound, since the wrapper has no inline key).
        // Temporal binding has nothing to compare; skip.
        let (json, _, _) = build_valid_v5_bundle(&three_uuid_entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let report = verify_bundle(&bundle);
        let step = temporal_binding_step(&report);
        assert!(
            matches!(&step.status, StepStatus::Skip(_)),
            "expected Skip with no resolved key, got {:?}",
            step.status
        );
    }

    #[test]
    fn resolver_callsite_drops_sentinel_under_attestable_mode() {
        // A resolver returning Sentinel under non-self-consistency
        // mode is itself a protocol violation. The call-site filter
        // drops the resolved key; signature step fails downstream;
        // temporal binding skips with "no resolved key."
        let (json, pk_hex, signing_key_id) =
            build_valid_v5_bundle(&three_uuid_entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let pk: [u8; 32] = hex::decode(&pk_hex).unwrap().try_into().unwrap();

        let resolver = TimedResolver {
            signing_key_id,
            public_key: pk,
            inserted_at: InsertedAt::Sentinel,
        };
        let report = verify_bundle_with(&bundle, &resolver, VerifierMode::Attestable);
        assert!(
            !report.passed(),
            "Sentinel-from-non-self-consistency must reject"
        );
        let lock_sig = report
            .steps
            .iter()
            .find(|s| s.name == StepName::LockSignature)
            .unwrap();
        assert!(
            matches!(lock_sig.status, StepStatus::Fail(_)),
            "lock signature step should fail when resolver Sentinel was rejected"
        );
    }

    #[test]
    fn resolver_callsite_drops_year_0001_perturbation_not_just_exact_legacy_literal() {
        // Defence-in-depth: a hostile tier-2 endpoint emitting a
        // year-0001 timestamp that isn't byte-equal to the pre-0.13.0
        // legacy literal (e.g. one microsecond off, or a different
        // sub-second / time component) MUST still reject. A byte-equal
        // check against the literal alone would let any year-0001
        // timestamp pass and trivially backdate the binding comparison.
        let (json, pk_hex, signing_key_id) =
            build_valid_v5_bundle(&three_uuid_entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let pk: [u8; 32] = hex::decode(&pk_hex).unwrap().try_into().unwrap();

        // One microsecond off the legacy literal — same year-0001
        // sentinel domain, different bytes.
        let resolver = TimedResolver {
            signing_key_id,
            public_key: pk,
            inserted_at: InsertedAt::At("0001-01-01T00:00:00.000001Z".into()),
        };
        let report = verify_bundle_with(&bundle, &resolver, VerifierMode::Attestable);

        let lock_sig = report
            .steps
            .iter()
            .find(|s| s.name == StepName::LockSignature)
            .unwrap();
        assert!(matches!(
            lock_sig.detail,
            Some(StepDetail::ResolutionFailure {
                kind: ResolutionFailureKind::LegacySentinelRejected,
                ..
            })
        ));
    }

    #[test]
    fn resolver_callsite_drops_legacy_sentinel_string_in_at_variant() {
        // Belt-and-braces (Colin Q5(b)): an upstream bug putting the
        // legacy "0001-01-01..." string into At(_) would silently
        // pass any <= comparison. The call-site filter refuses it.
        let (json, pk_hex, signing_key_id) =
            build_valid_v5_bundle(&three_uuid_entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let pk: [u8; 32] = hex::decode(&pk_hex).unwrap().try_into().unwrap();

        let resolver = TimedResolver {
            signing_key_id,
            public_key: pk,
            inserted_at: InsertedAt::At("0001-01-01T00:00:00.000000Z".into()),
        };
        let report = verify_bundle_with(&bundle, &resolver, VerifierMode::Attestable);
        assert!(!report.passed());
        let lock_sig = report
            .steps
            .iter()
            .find(|s| s.name == StepName::LockSignature)
            .unwrap();
        assert!(matches!(lock_sig.status, StepStatus::Fail(_)));
    }

    // ── ResolutionError surfacing in StepDetail ───────────────────────

    #[test]
    fn resolution_failure_surfaces_keynotfound_on_signature_step() {
        let (json, _, _) = build_valid_v5_bundle(&three_uuid_entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();

        // MockResolver with a different signing_key_id → KeyNotFound.
        let resolver = MockResolver::new("not-the-right-kid", [0u8; 32]);
        let report = verify_bundle_with(&bundle, &resolver, VerifierMode::Attestable);

        let lock_sig = report
            .steps
            .iter()
            .find(|s| s.name == StepName::LockSignature)
            .unwrap();
        assert!(matches!(
            lock_sig.detail,
            Some(StepDetail::ResolutionFailure {
                class: KeyClass::Operator,
                kind: ResolutionFailureKind::KeyNotFound,
            })
        ));
        assert!(matches!(&lock_sig.status, StepStatus::Fail(reason)
                if reason.contains("operator") && reason.contains("key_id")));
    }

    #[test]
    fn resolution_failure_surfaces_sentinel_rejection_distinctly() {
        let (json, pk_hex, signing_key_id) =
            build_valid_v5_bundle(&three_uuid_entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let pk: [u8; 32] = hex::decode(&pk_hex).unwrap().try_into().unwrap();

        let resolver = TimedResolver {
            signing_key_id,
            public_key: pk,
            inserted_at: InsertedAt::Sentinel,
        };
        let report = verify_bundle_with(&bundle, &resolver, VerifierMode::Attestable);

        let lock_sig = report
            .steps
            .iter()
            .find(|s| s.name == StepName::LockSignature)
            .unwrap();
        assert!(matches!(
            lock_sig.detail,
            Some(StepDetail::ResolutionFailure {
                kind: ResolutionFailureKind::SentinelRejected,
                ..
            })
        ));
    }

    #[test]
    fn resolution_failure_surfaces_legacy_sentinel_distinctly() {
        let (json, pk_hex, signing_key_id) =
            build_valid_v5_bundle(&three_uuid_entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let pk: [u8; 32] = hex::decode(&pk_hex).unwrap().try_into().unwrap();

        let resolver = TimedResolver {
            signing_key_id,
            public_key: pk,
            inserted_at: InsertedAt::At("0001-01-01T00:00:00.000000Z".into()),
        };
        let report = verify_bundle_with(&bundle, &resolver, VerifierMode::Attestable);

        let lock_sig = report
            .steps
            .iter()
            .find(|s| s.name == StepName::LockSignature)
            .unwrap();
        assert!(matches!(
            lock_sig.detail,
            Some(StepDetail::ResolutionFailure {
                kind: ResolutionFailureKind::LegacySentinelRejected,
                ..
            })
        ));
    }

    #[test]
    fn signature_failure_without_resolution_error_keeps_old_message() {
        // Tampered signature on a legacy v4-lock bundle: resolver
        // succeeds (inline pk found), but the signature bytes don't
        // verify. Should still report the generic message — no
        // resolution failure to surface.
        let (json, _) = valid_signed_bundle();
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        val["lock_receipt"]["signature_hex"] = serde_json::json!("ff".repeat(64));
        let bundle = ProofBundle::from_json(&val.to_string()).unwrap();
        let report = verify_bundle(&bundle);

        let lock_sig = report
            .steps
            .iter()
            .find(|s| s.name == StepName::LockSignature)
            .unwrap();
        assert!(
            matches!(&lock_sig.status, StepStatus::Fail(msg) if msg == "Ed25519 signature invalid")
        );
        assert!(lock_sig.detail.is_none());
    }

    #[test]
    fn temporal_binding_fails_on_malformed_resolver_timestamp() {
        // Resolver hands back an inserted_at that doesn't match the
        // canonical RFC 3339 form. Distinguished from a comparison
        // failure in the error message.
        let (json, pk_hex, signing_key_id) =
            build_valid_v5_bundle(&three_uuid_entries(), Some("1013"), 2);
        let bundle = ProofBundle::from_json(&json).unwrap();
        let pk: [u8; 32] = hex::decode(&pk_hex).unwrap().try_into().unwrap();

        let resolver = TimedResolver {
            signing_key_id,
            public_key: pk,
            inserted_at: InsertedAt::At("2026-04-01T00:00:00Z".into()), // missing microseconds
        };
        let report = verify_bundle_with(&bundle, &resolver, VerifierMode::Attestable);
        let step = temporal_binding_step(&report);
        assert!(
            matches!(&step.status, StepStatus::Fail(reason) if reason.contains("malformed")),
            "expected malformed-timestamp Fail, got {:?}",
            step.status
        );
    }

    // ── A skip is never a pass; BLS runs in every build ──────────────────

    fn report_of(statuses: Vec<StepStatus>) -> VerificationReport {
        VerificationReport {
            steps: statuses
                .into_iter()
                .map(|status| StepResult {
                    name: StepName::EntryHash,
                    status,
                    detail: None,
                })
                .collect(),
            operator_key_id: None,
            infra_key_id: None,
            mode: VerifierMode::SelfConsistencyOnly,
        }
    }

    #[test]
    fn a_skip_is_never_a_pass() {
        let report = report_of(vec![StepStatus::Pass, StepStatus::Skip("not run".into())]);
        assert!(!report.passed());
    }

    fn report_of_named(steps: Vec<(StepName, StepStatus)>) -> VerificationReport {
        let mut report = report_of(vec![]);
        report.steps = steps
            .into_iter()
            .map(|(name, status)| StepResult {
                name,
                status,
                detail: None,
            })
            .collect();
        report
    }

    #[test]
    fn not_applicable_does_not_block_a_pass() {
        let report = report_of_named(vec![
            (StepName::EntryHash, StepStatus::Pass),
            (
                StepName::WeatherObservationWindow,
                StepStatus::NotApplicable("no weather".into()),
            ),
            (
                StepName::TemporalBinding,
                StepStatus::NotApplicable("self-consistency".into()),
            ),
        ]);
        assert!(report.passed());
    }

    #[test]
    fn not_applicable_outside_the_allow_list_fails() {
        // Only WeatherObservationWindow and TemporalBinding may be waived.
        // Every other step must pass.
        for name in StepName::all() {
            if matches!(
                name,
                StepName::WeatherObservationWindow | StepName::TemporalBinding
            ) {
                continue;
            }
            let other = if *name == StepName::EntryHash {
                StepName::LockSignature
            } else {
                StepName::EntryHash
            };
            let report = report_of_named(vec![
                (other, StepStatus::Pass),
                (*name, StepStatus::NotApplicable("waived".into())),
            ]);
            assert!(!report.passed(), "NotApplicable on {name:?} must fail");
        }
    }

    #[test]
    fn all_not_applicable_is_not_a_pass() {
        let report = report_of(vec![StepStatus::NotApplicable("nothing".into())]);
        assert!(!report.passed());
    }

    fn drand_step(report: &VerificationReport) -> &StepResult {
        report
            .steps
            .iter()
            .find(|s| s.name == StepName::DrandBlsSignature)
            .unwrap()
    }

    #[test]
    fn genuine_beacon_passes_drand_step() {
        let (json, _) = valid_signed_bundle();
        let report = verify_bundle(&ProofBundle::from_json(&json).unwrap());
        assert_eq!(drand_step(&report).status, StepStatus::Pass);
    }

    use crate::_test_support::resign_exec;

    fn step_named(report: &VerificationReport, name: StepName) -> &StepResult {
        report.steps.iter().find(|s| s.name == name).unwrap()
    }

    fn failing_steps(report: &VerificationReport) -> Vec<StepName> {
        report
            .steps
            .iter()
            .filter(|s| matches!(s.status, StepStatus::Fail(_)))
            .map(|s| s.name)
            .collect()
    }

    #[test]
    fn zero_signature_fails_drand_step_and_report() {
        // The zero signature goes into BOTH the signed execution receipt
        // (re-signed, so the exec signature still verifies) and the
        // entropy block, so the entropy binding holds and the only thing
        // that can reject it is the BLS check itself.
        use crate::_test_support::BEACON_SIGNATURE;
        let zero = "00".repeat(48);
        let (json, _) = valid_signed_bundle();
        let mut val = resign_exec(&json, |exec| {
            assert_eq!(exec["drand_signature"], BEACON_SIGNATURE);
            exec["drand_signature"] = serde_json::json!(zero.clone());
        });
        assert_eq!(val["entropy"]["drand_signature"], BEACON_SIGNATURE);
        val["entropy"]["drand_signature"] = serde_json::json!(zero);
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert_eq!(
            step_named(&report, StepName::ExecSignature).status,
            StepStatus::Pass
        );
        assert!(
            matches!(&drand_step(&report).status, StepStatus::Fail(r) if r.contains("BLS")),
            "got {:?}",
            drand_step(&report).status
        );
        assert_eq!(failing_steps(&report), vec![StepName::DrandBlsSignature]);
        assert!(!report.passed());
    }

    #[test]
    fn entropy_swapped_to_another_genuine_beacon_fails() {
        // Only the unsigned entropy block changes; the signed exec receipt
        // still carries round 1000. A genuine beacon in entropy must not
        // vouch for the receipt's randomness.
        use crate::_test_support::{BEACON_2_RANDOMNESS, BEACON_2_ROUND, BEACON_2_SIGNATURE};
        let (json, _) = valid_signed_bundle();
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        val["entropy"]["drand_round"] = serde_json::json!(BEACON_2_ROUND);
        val["entropy"]["drand_signature"] = serde_json::json!(BEACON_2_SIGNATURE);
        val["entropy"]["drand_randomness"] = serde_json::json!(BEACON_2_RANDOMNESS);
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert!(
            matches!(&drand_step(&report).status,
                StepStatus::Fail(r) if r.contains("entropy.drand_round")),
            "got {:?}",
            drand_step(&report).status
        );
        assert!(!report.passed());
    }

    #[test]
    fn receipt_swapped_to_another_genuine_beacon_fails() {
        // The signed exec receipt carries BEACON_2 (re-signed); entropy
        // keeps BEACON. The mismatch must fail the drand step.
        use crate::_test_support::{BEACON_2_RANDOMNESS, BEACON_2_ROUND, BEACON_2_SIGNATURE};
        let (json, _) = valid_signed_bundle();
        let val = resign_exec(&json, |exec| {
            exec["drand_round"] = serde_json::json!(BEACON_2_ROUND);
            exec["drand_signature"] = serde_json::json!(BEACON_2_SIGNATURE);
            exec["drand_randomness"] = serde_json::json!(BEACON_2_RANDOMNESS);
        });
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert_eq!(
            step_named(&report, StepName::ExecSignature).status,
            StepStatus::Pass
        );
        assert!(
            matches!(&drand_step(&report).status,
                StepStatus::Fail(r) if r.contains("entropy.drand_round")),
            "got {:?}",
            drand_step(&report).status
        );
        assert!(!report.passed());
    }

    #[test]
    fn exec_receipt_missing_drand_signature_fails_drand_step() {
        let (json, _) = valid_signed_bundle();
        let val = resign_exec(&json, |exec| {
            exec.as_object_mut().unwrap().remove("drand_signature");
        });
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert!(
            matches!(&drand_step(&report).status,
                StepStatus::Fail(r) if r.contains("drand_signature")),
            "got {:?}",
            drand_step(&report).status
        );
        assert!(!report.passed());
    }

    #[test]
    fn exec_receipt_drand_round_wrong_type_fails_drand_step() {
        let (json, _) = valid_signed_bundle();
        let val = resign_exec(&json, |exec| {
            exec["drand_round"] = serde_json::json!("1000");
        });
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert!(
            matches!(&drand_step(&report).status,
                StepStatus::Fail(r) if r.contains("drand_round")),
            "got {:?}",
            drand_step(&report).status
        );
        assert!(!report.passed());
    }

    #[test]
    fn genuine_beacon_for_a_round_other_than_locked_fails() {
        // A fully self-consistent execution (exec receipt, entropy, seed
        // and winners all built from BEACON_2, round 1001) against a lock
        // receipt that committed to round 1000. The BLS check passes; the
        // lock/exec drand_round consistency check must still fail it.
        use crate::_test_support::{BEACON_2_RANDOMNESS, BEACON_2_ROUND, BEACON_2_SIGNATURE};
        let (json, _) = valid_signed_bundle();
        let entries: Vec<Entry> = [
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        ]
        .iter()
        .map(|id| Entry {
            id: (*id).into(),
            weight: 1,
        })
        .collect();
        let (ehash, _) = entry_hash("22222222-2222-2222-2222-222222222222", &entries);
        let (seed, _) = compute_seed(&ehash, BEACON_2_RANDOMNESS, "1013");
        let winners = draw(&entries, &seed, 2).unwrap();
        let mut val = resign_exec(&json, |exec| {
            exec["drand_round"] = serde_json::json!(BEACON_2_ROUND);
            exec["drand_signature"] = serde_json::json!(BEACON_2_SIGNATURE);
            exec["drand_randomness"] = serde_json::json!(BEACON_2_RANDOMNESS);
            exec["seed"] = serde_json::json!(hex::encode(seed));
            exec["results"] = serde_json::json!(
                winners
                    .iter()
                    .map(|w| w.entry_id.clone())
                    .collect::<Vec<_>>()
            );
        });
        val["entropy"]["drand_round"] = serde_json::json!(BEACON_2_ROUND);
        val["entropy"]["drand_signature"] = serde_json::json!(BEACON_2_SIGNATURE);
        val["entropy"]["drand_randomness"] = serde_json::json!(BEACON_2_RANDOMNESS);
        val["results"] = serde_json::json!(
            winners
                .iter()
                .map(|w| serde_json::json!({"entry_id": &w.entry_id, "position": w.position}))
                .collect::<Vec<_>>()
        );
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert_eq!(drand_step(&report).status, StepStatus::Pass);
        assert!(
            matches!(&step_named(&report, StepName::ReceiptFieldConsistency).status,
                StepStatus::Fail(r) if r.contains("drand_round")),
            "got {:?}",
            step_named(&report, StepName::ReceiptFieldConsistency).status
        );
        assert_eq!(
            failing_steps(&report),
            vec![StepName::ReceiptFieldConsistency]
        );
        assert!(!report.passed());
    }

    #[test]
    fn drand_only_bundle_weather_window_is_not_applicable_and_passes() {
        let (json, _) = crate::_test_support::build_valid_drand_only_bundle();
        let report = verify_bundle(&ProofBundle::from_json(&json).unwrap());
        let step = report
            .steps
            .iter()
            .find(|s| s.name == StepName::WeatherObservationWindow)
            .unwrap();
        assert!(
            matches!(step.status, StepStatus::NotApplicable(_)),
            "got {:?}",
            step.status
        );
        assert!(report.passed(), "steps: {:?}", report.steps);
    }

    // ── Weather window and weather binding ───────────────────────────────

    fn window_step(report: &VerificationReport) -> &StepResult {
        step_named(report, StepName::WeatherObservationWindow)
    }

    #[test]
    fn weather_value_without_observation_time_fails_window() {
        let (json, _) = valid_signed_bundle();
        let val = resign_exec(&json, |exec| {
            exec["weather_observation_time"] = serde_json::Value::Null;
        });
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert_eq!(
            step_named(&report, StepName::ExecSignature).status,
            StepStatus::Pass
        );
        assert!(
            matches!(&window_step(&report).status,
                StepStatus::Fail(r) if r.contains("weather_value") && r.contains("weather_observation_time")),
            "got {:?}",
            window_step(&report).status
        );
        assert!(!report.passed());
    }

    #[test]
    fn observation_time_without_weather_value_fails_window() {
        let (json, _) = crate::_test_support::build_valid_drand_only_bundle();
        let val = resign_exec(&json, |exec| {
            exec["weather_observation_time"] = serde_json::json!("2023-08-23T16:00:00.000000Z");
        });
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert_eq!(
            step_named(&report, StepName::ExecSignature).status,
            StepStatus::Pass
        );
        assert!(
            matches!(&window_step(&report).status,
                StepStatus::Fail(r) if r.contains("weather_value") && r.contains("weather_observation_time")),
            "got {:?}",
            window_step(&report).status
        );
        assert!(!report.passed());
    }

    #[test]
    fn exec_weather_without_lock_weather_time_fails_window() {
        // LockReceiptV4/V5 require weather_time, so a well-signed bundle
        // cannot reach this; exercise the step function directly.
        let (json, _) = valid_signed_bundle();
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        let mut lock: serde_json::Value =
            serde_json::from_str(val["lock_receipt"]["payload_jcs"].as_str().unwrap()).unwrap();
        lock.as_object_mut().unwrap().remove("weather_time");
        val["lock_receipt"]["payload_jcs"] = serde_json::json!(lock.to_string());
        let bundle = ProofBundle::from_json(&val.to_string()).unwrap();
        let step = check_weather_observation_window(&bundle);
        assert!(
            matches!(&step.status,
                StepStatus::Fail(r) if r.contains("weather_value") && r.contains("weather_time")),
            "got {:?}",
            step.status
        );
    }

    #[test]
    fn entropy_weather_value_swap_fails() {
        let (json, _) = valid_signed_bundle();
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["entropy"]["weather_value"], "1013");
        val["entropy"]["weather_value"] = serde_json::json!("1014");
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert!(
            matches!(&drand_step(&report).status,
                StepStatus::Fail(r) if r.contains("entropy.weather_value")),
            "got {:?}",
            drand_step(&report).status
        );
        assert!(!report.passed());
    }

    #[test]
    fn entropy_freq_value_on_a_bundle_without_one_fails() {
        for bundle in [
            valid_signed_bundle().0,
            crate::_test_support::build_valid_drand_only_bundle().0,
        ] {
            let mut val: serde_json::Value = serde_json::from_str(&bundle).unwrap();
            val["entropy"]["freq_value"] =
                serde_json::json!("50018;50012;49983;49980;49953;49912;49883;49887");
            let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
            assert!(
                matches!(&drand_step(&report).status,
                    StepStatus::Fail(r) if r.contains("entropy.freq_value")),
                "got {:?}",
                drand_step(&report).status
            );
            assert!(!report.passed());
            // A null copy is the same as none.
            val["entropy"]["freq_value"] = serde_json::Value::Null;
            let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
            assert_eq!(drand_step(&report).status, StepStatus::Pass);
        }
    }

    #[test]
    fn entropy_weather_value_removed_fails() {
        let (json, _) = valid_signed_bundle();
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        val["entropy"]
            .as_object_mut()
            .unwrap()
            .remove("weather_value");
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert!(
            matches!(&drand_step(&report).status,
                StepStatus::Fail(r) if r.contains("entropy.weather_value")),
            "got {:?}",
            drand_step(&report).status
        );
        assert!(!report.passed());
    }

    #[test]
    fn entropy_weather_value_added_when_receipt_has_none_fails() {
        // Drand-only draw: the signed exec receipt's weather_value is null
        // and entropy has none. Adding a weather_value to the unsigned
        // entropy block alone must fail the drand step.
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
        let json = crate::_test_support::build_valid_bundle(&entries, None, 1);
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        let exec: serde_json::Value =
            serde_json::from_str(val["execution_receipt"]["payload_jcs"].as_str().unwrap())
                .unwrap();
        assert!(exec["weather_value"].is_null());
        assert!(val["entropy"].get("weather_value").is_none());
        val["entropy"]["weather_value"] = serde_json::json!("1013");
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert!(
            matches!(&drand_step(&report).status,
                StepStatus::Fail(r) if r.contains("entropy.weather_value")),
            "got {:?}",
            drand_step(&report).status
        );
        assert!(!report.passed());
    }

    #[test]
    fn lock_exec_drand_chain_mismatch_fails() {
        let other_chain = "dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493";
        let (json, _) = valid_signed_bundle();
        let mut val = resign_exec(&json, |exec| {
            exec["drand_chain"] = serde_json::json!(other_chain);
        });
        val["entropy"]["drand_chain_hash"] = serde_json::json!(other_chain);
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert_eq!(
            step_named(&report, StepName::ExecSignature).status,
            StepStatus::Pass
        );
        assert!(
            matches!(&step_named(&report, StepName::ReceiptFieldConsistency).status,
                StepStatus::Fail(r) if r.contains("drand_chain")),
            "got {:?}",
            step_named(&report, StepName::ReceiptFieldConsistency).status
        );
        assert!(
            matches!(&drand_step(&report).status,
                StepStatus::Fail(r) if r.contains("unknown drand chain")),
            "got {:?}",
            drand_step(&report).status
        );
        assert!(!report.passed());
    }

    // ── Bundle results bound to the signed receipt ───────────────────────

    fn winner_step(report: &VerificationReport) -> &StepResult {
        step_named(report, StepName::WinnerSelection)
    }

    #[test]
    fn unsigned_results_swap_fails_winner_selection() {
        let (json, _) = valid_signed_bundle();
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        let first = val["results"][0]["entry_id"].clone();
        let second = val["results"][1]["entry_id"].clone();
        assert_ne!(first, second);
        val["results"][0]["entry_id"] = second;
        val["results"][1]["entry_id"] = first;
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert!(
            matches!(&winner_step(&report).status,
                StepStatus::Fail(r) if r.contains("results[0]")),
            "got {:?}",
            winner_step(&report).status
        );
        assert_eq!(failing_steps(&report), vec![StepName::WinnerSelection]);
        assert!(!report.passed());
    }

    #[test]
    fn unsigned_results_position_change_fails_winner_selection() {
        let (json, _) = valid_signed_bundle();
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["results"][1]["position"], 2);
        val["results"][1]["position"] = serde_json::json!(3);
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert!(
            matches!(&winner_step(&report).status,
                StepStatus::Fail(r) if r.contains("results[1]") && r.contains("position")),
            "got {:?}",
            winner_step(&report).status
        );
        assert!(!report.passed());
    }

    #[test]
    fn unsigned_results_length_change_fails_winner_selection() {
        let (json, _) = valid_signed_bundle();
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        val["results"].as_array_mut().unwrap().pop();
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert!(
            matches!(&winner_step(&report).status,
                StepStatus::Fail(r) if r.contains("results")),
            "got {:?}",
            winner_step(&report).status
        );
        assert!(!report.passed());
    }

    #[test]
    fn non_string_weather_value_fails_seed_recomputation() {
        // A drand-only bundle whose signed receipt carries a numeric
        // weather_value. Reading it as "no weather" would recompute the
        // drand-only seed and pass; the seed step must fail instead.
        let (json, _) = crate::_test_support::build_valid_drand_only_bundle();
        let val = resign_exec(&json, |exec| {
            exec["weather_value"] = serde_json::json!(1013);
        });
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert_eq!(
            step_named(&report, StepName::ExecSignature).status,
            StepStatus::Pass
        );
        assert!(
            matches!(&step_named(&report, StepName::SeedRecomputation).status,
                StepStatus::Fail(r) if r.contains("weather_value")),
            "got {:?}",
            step_named(&report, StepName::SeedRecomputation).status
        );
        assert!(!report.passed());
    }

    // ── Weather fallback reason ──────────────────────────────────────────

    #[test]
    fn no_weather_without_fallback_reason_fails_window() {
        let (json, _) = crate::_test_support::build_valid_drand_only_bundle();
        let val = resign_exec(&json, |exec| {
            exec["weather_fallback_reason"] = serde_json::Value::Null;
        });
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert!(
            matches!(&window_step(&report).status,
                StepStatus::Fail(r) if r.contains("weather_fallback_reason")),
            "got {:?}",
            window_step(&report).status
        );
        assert!(!report.passed());
    }

    #[test]
    fn no_weather_with_fallback_reason_key_absent_fails_window() {
        let (json, _) = crate::_test_support::build_valid_drand_only_bundle();
        let val = resign_exec(&json, |exec| {
            exec.as_object_mut()
                .unwrap()
                .remove("weather_fallback_reason");
        });
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert!(
            matches!(&window_step(&report).status,
                StepStatus::Fail(r) if r.contains("weather_fallback_reason")),
            "got {:?}",
            window_step(&report).status
        );
        assert!(!report.passed());
    }

    #[test]
    fn weather_with_fallback_reason_fails_window() {
        let (json, _) = valid_signed_bundle();
        let val = resign_exec(&json, |exec| {
            exec["weather_fallback_reason"] = serde_json::json!("unreachable");
        });
        let report = verify_bundle(&ProofBundle::from_json(&val.to_string()).unwrap());
        assert_eq!(
            step_named(&report, StepName::ExecSignature).status,
            StepStatus::Pass
        );
        assert!(
            matches!(&window_step(&report).status,
                StepStatus::Fail(r) if r.contains("weather_fallback_reason")),
            "got {:?}",
            window_step(&report).status
        );
        assert!(!report.passed());
    }

    #[test]
    fn fallback_rule_holds_for_every_exec_schema_version() {
        // v2 (valid_signed_bundle / build_valid_bundle) is covered above;
        // v4 via the resolver-driven fixture.
        let entries: Vec<Entry> = ["a", "b", "c"]
            .iter()
            .map(|id| Entry {
                id: (*id).into(),
                weight: 1,
            })
            .collect();
        let (json, pk_hex, kid) = build_valid_v5_bundle(&entries, None, 2);
        let pk: [u8; 32] = hex::decode(pk_hex).unwrap().try_into().unwrap();
        let resolver = MockResolver::new(kid, pk);
        let ok = verify_bundle_with(
            &ProofBundle::from_json(&json).unwrap(),
            &resolver,
            VerifierMode::Attestable,
        );
        assert!(ok.passed(), "steps: {:?}", ok.steps);
        let val = resign_exec(&json, |exec| {
            exec["weather_fallback_reason"] = serde_json::Value::Null;
        });
        let report = verify_bundle_with(
            &ProofBundle::from_json(&val.to_string()).unwrap(),
            &resolver,
            VerifierMode::Attestable,
        );
        assert!(
            matches!(&window_step(&report).status,
                StepStatus::Fail(r) if r.contains("weather_fallback_reason")),
            "got {:?}",
            window_step(&report).status
        );
    }

    // ── The drand round publishes after the lock ─────────────────────────

    /// Rewrite `locked_at` in the lock receipt, re-sign it, and re-link and
    /// re-sign the execution receipt, so every signature and the linkage
    /// still verify.
    fn with_locked_at(json: &str, locked_at: &str) -> String {
        let sk = test_signing_key();
        let mut val: serde_json::Value = serde_json::from_str(json).unwrap();
        let mut lock: serde_json::Value =
            serde_json::from_str(val["lock_receipt"]["payload_jcs"].as_str().unwrap()).unwrap();
        lock["locked_at"] = serde_json::json!(locked_at);
        let lock_jcs = lock.to_string();
        val["lock_receipt"]["signature_hex"] =
            serde_json::json!(hex::encode(sk.sign(lock_jcs.as_bytes()).to_bytes()));
        val["lock_receipt"]["payload_jcs"] = serde_json::json!(lock_jcs);
        let lrh = compute_lock_hash(&lock_jcs);
        resign_exec(&val.to_string(), |exec| {
            exec["lock_receipt_hash"] = serde_json::json!(lrh);
        })
        .to_string()
    }

    #[test]
    fn drand_round_published_before_lock_fails() {
        // Round 1000 published at 2023-08-23T15:59:24Z.
        let (json, _) = valid_signed_bundle();
        let json = with_locked_at(&json, "2023-08-23T15:59:30.000000Z");
        let report = verify_bundle(&ProofBundle::from_json(&json).unwrap());
        assert!(
            matches!(&drand_step(&report).status,
                StepStatus::Fail(r) if r.contains("locked_at")),
            "got {:?}",
            drand_step(&report).status
        );
        assert_eq!(failing_steps(&report), vec![StepName::DrandBlsSignature]);
        assert!(!report.passed());
    }

    #[test]
    fn drand_round_published_at_lock_time_fails() {
        // Strictly after: a round published in the same second as the
        // lock does not count.
        let (json, _) = valid_signed_bundle();
        let json = with_locked_at(&json, "2023-08-23T15:59:24.000000Z");
        let report = verify_bundle(&ProofBundle::from_json(&json).unwrap());
        assert!(
            matches!(&drand_step(&report).status,
                StepStatus::Fail(r) if r.contains("locked_at")),
            "got {:?}",
            drand_step(&report).status
        );
    }

    #[test]
    fn drand_round_published_after_lock_passes() {
        let (json, _) = valid_signed_bundle();
        let json = with_locked_at(&json, "2023-08-23T15:59:23.999999Z");
        let report = verify_bundle(&ProofBundle::from_json(&json).unwrap());
        assert_eq!(drand_step(&report).status, StepStatus::Pass);
        assert!(report.passed(), "steps: {:?}", report.steps);
    }
}

#[cfg(test)]
#[path = "verify_steps_landobs_tests.rs"]
mod landobs_tests;

#[cfg(test)]
#[path = "verify_steps_freq_tests.rs"]
mod freq_tests;
