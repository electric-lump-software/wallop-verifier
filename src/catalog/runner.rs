//! Per-scenario execution and coverage tracking for the tamper catalog.
//!
//! The runner generates a fresh valid bundle for each scenario via
//! `build_valid_bundle`, applies the declared tamper mutation, runs
//! `verify_bundle`, and determines whether the first-failing step matches
//! what the scenario declared in `expected_catch_steps`.
//!
//! After all scenarios run, a coverage check ensures every `StepName` variant
//! actually fired as the first-failing step in at least one scenario (runtime,
//! not just declared).

use crate::_test_support::build_valid_bundle;
use crate::catalog::keypairs::derive_keypair;
use crate::catalog::loader::{LoadError, load_catalog_from_str};
use crate::catalog::mutations::{CatalogContext, apply_field_op, apply_semantic_op};
use crate::catalog::schema::{Catalog, Defaults, Scenario, Tamper};
use crate::verify_steps::{StepStatus, verify_bundle};
use crate::{Entry, StepName};
use std::collections::HashSet;

/// Overall catalog run report.
#[derive(Debug)]
pub struct CatalogReport {
    pub total_scenarios: usize,
    pub passed: usize,
    pub failed_p0: usize,
    pub caught_by_wrong_step: usize,
    pub skipped: usize,
    pub coverage_complete: bool,
    pub covered_steps: HashSet<StepName>,
    pub results: Vec<ScenarioResult>,
}

/// Result of running a single scenario.
#[derive(Debug)]
pub struct ScenarioResult {
    pub name: String,
    pub outcome: ScenarioOutcome,
}

/// Outcome of a single scenario execution.
#[derive(Debug)]
pub enum ScenarioOutcome {
    /// The scenario was caught by an expected step.
    Passed { caught_at: StepName },
    /// The verifier accepted the tampered bundle — a P0 finding.
    FailedP0,
    /// The scenario was caught, but by the wrong step.
    CaughtByWrongStep {
        expected: Vec<StepName>,
        actual: StepName,
    },
    /// The mutation itself failed (catalog bug, not a verifier issue).
    MutationError(String),
}

/// Error from running the catalog.
#[derive(Debug)]
pub enum RunError {
    Load(LoadError),
}

impl From<LoadError> for RunError {
    fn from(e: LoadError) -> Self {
        RunError::Load(e)
    }
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Load(e) => write!(f, "catalog load error: {e}"),
        }
    }
}

/// Load a catalog from JSON and run every scenario.
pub(crate) fn run_catalog_from_str(json: &str) -> Result<CatalogReport, RunError> {
    let catalog = load_catalog_from_str(json)?;
    Ok(run_catalog(&catalog))
}

/// Run every scenario in a pre-loaded catalog.
pub(crate) fn run_catalog(catalog: &Catalog) -> CatalogReport {
    let ctx = build_context(catalog);
    let mut covered: HashSet<StepName> = HashSet::new();
    let mut results = Vec::with_capacity(catalog.scenarios.len());
    let mut passed = 0;
    let mut failed_p0 = 0;
    let mut caught_by_wrong_step = 0;
    let mut skipped = 0;

    for scenario in &catalog.scenarios {
        let result = run_single(scenario, catalog, &ctx);
        match &result.outcome {
            ScenarioOutcome::Passed { caught_at } => {
                covered.insert(*caught_at);
                passed += 1;
            }
            ScenarioOutcome::FailedP0 => failed_p0 += 1,
            ScenarioOutcome::CaughtByWrongStep { .. } => caught_by_wrong_step += 1,
            ScenarioOutcome::MutationError(_) => skipped += 1,
        }
        results.push(result);
    }

    // EntryHash is excluded from coverage because it's a computation step that
    // always passes — it computes the hash, it doesn't validate anything. The
    // actual entry-hash comparisons happen at LockReceiptEntryHash and
    // ExecReceiptEntryHash. Requiring EntryHash to fire as a first-failure is
    // structurally impossible.
    let coverage_complete = StepName::all()
        .iter()
        .filter(|s| **s != StepName::EntryHash)
        .all(|s| covered.contains(s));

    CatalogReport {
        total_scenarios: catalog.scenarios.len(),
        passed,
        failed_p0,
        caught_by_wrong_step,
        skipped,
        coverage_complete,
        covered_steps: covered,
        results,
    }
}

fn build_context(catalog: &Catalog) -> CatalogContext {
    let mut ctx = CatalogContext::new();
    for (name, kp) in &catalog.test_keypairs {
        ctx.keypairs.insert(name.clone(), derive_keypair(&kp.seed));
    }
    // Add the original signing key used by build_valid_bundle so scenarios
    // can re-sign payloads with it after modification (modify_payload_and_resign).
    ctx.keypairs.insert(
        "original_signer".to_string(),
        crate::_test_support::test_signing_key(),
    );
    // fixture_bundles loading deferred — first scenario that references
    // a fixture bundle drives this code.
    ctx
}

fn run_single(scenario: &Scenario, catalog: &Catalog, ctx: &CatalogContext) -> ScenarioResult {
    // 1. Resolve effective bundle parameters
    let (entries, weather, winner_count) = resolve_params(scenario, &catalog.defaults);

    // 2. Build the base bundle
    let bundle_json_str = build_valid_bundle(&entries, weather.as_deref(), winner_count);

    // 3. Parse into mutable JSON Value
    let mut bundle_value: serde_json::Value = match serde_json::from_str(&bundle_json_str) {
        Ok(v) => v,
        Err(e) => {
            return ScenarioResult {
                name: scenario.name.clone(),
                outcome: ScenarioOutcome::MutationError(format!("base bundle parse error: {e}")),
            };
        }
    };

    // 4. Apply the tamper
    let tamper_result = match &scenario.tamper {
        Tamper::FieldOp(op) => apply_field_op(&mut bundle_value, op).map_err(|e| e.to_string()),
        Tamper::SemanticOp(op) => {
            apply_semantic_op(&mut bundle_value, op, ctx).map_err(|e| e.to_string())
        }
    };
    if let Err(e) = tamper_result {
        return ScenarioResult {
            name: scenario.name.clone(),
            outcome: ScenarioOutcome::MutationError(e),
        };
    }

    // 5. Re-serialize and parse as ProofBundle, then verify
    let mutated_json = bundle_value.to_string();
    let bundle = match crate::bundle::ProofBundle::from_json(&mutated_json) {
        Ok(b) => b,
        Err(e) => {
            // Mutation broke the bundle structure. For now treat as a
            // scenario error rather than a pass — the catalog should use
            // mutations that produce parseable output so verify_bundle
            // can run and a specific step can be identified.
            return ScenarioResult {
                name: scenario.name.clone(),
                outcome: ScenarioOutcome::MutationError(format!(
                    "mutated bundle failed to parse: {e}"
                )),
            };
        }
    };

    let report = verify_bundle(&bundle);

    // 6. Determine the first-failing step (runtime execution order)
    let first_failing = report
        .steps
        .iter()
        .find(|s| matches!(s.status, StepStatus::Fail(_)))
        .map(|s| s.name);

    // 7. Compare against expected
    let expected: Vec<StepName> = scenario
        .expected_catch_steps
        .iter()
        .filter_map(|s| {
            let json = format!("\"{s}\"");
            serde_json::from_str(&json).ok()
        })
        .collect();

    let outcome = match first_failing {
        Some(actual) if expected.contains(&actual) => ScenarioOutcome::Passed { caught_at: actual },
        Some(actual) => ScenarioOutcome::CaughtByWrongStep { expected, actual },
        None => ScenarioOutcome::FailedP0,
    };

    ScenarioResult {
        name: scenario.name.clone(),
        outcome,
    }
}

fn resolve_params(scenario: &Scenario, defaults: &Defaults) -> (Vec<Entry>, Option<String>, u32) {
    let params = scenario.bundle_params.as_ref();

    // Resolve entries
    let entries: Vec<Entry> = match params.and_then(|p| p.entries.as_ref()) {
        Some(explicit) => explicit
            .iter()
            .map(|e| Entry {
                id: e.id.clone(),
                weight: e.weight,
            })
            .collect(),
        None => {
            let count = params
                .and_then(|p| p.entry_count)
                .unwrap_or(defaults.entry_count);
            (1..=count)
                .map(|i| Entry {
                    id: format!("ticket-{i}"),
                    weight: 1,
                })
                .collect()
        }
    };

    // Resolve weather — three-way: absent (inherit), null (drand-only), string (explicit)
    let weather = match params.and_then(|p| p.weather.as_ref()) {
        Some(None) => None,               // explicit null → drand-only
        Some(Some(s)) => Some(s.clone()), // explicit string value
        None => defaults.weather.clone(), // inherit from defaults
    };

    let winner_count = params
        .and_then(|p| p.winner_count)
        .unwrap_or(defaults.winner_count);

    (entries, weather, winner_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SINGLE_SCENARIO_CATALOG: &str = r#"{
        "catalog_schema_version": "1",
        "protocol_version": "1",
        "defaults": { "entry_count": 3, "weather": "1013", "winner_count": 2 },
        "test_keypairs": {},
        "fixture_bundles": {},
        "scenarios": [
            {
                "name": "lock_sig_byte_flip",
                "category": "lock_signature",
                "description": "flip a byte in the lock receipt signature",
                "severity": "critical",
                "tamper": {
                    "kind": "field_op",
                    "op": "byte_flip",
                    "path": "lock_receipt.signature_hex",
                    "offset": 0
                },
                "expected_catch_steps": ["lock_signature"]
            }
        ]
    }"#;

    #[test]
    fn single_scenario_runs_and_passes() {
        let report = run_catalog_from_str(SINGLE_SCENARIO_CATALOG).unwrap();
        assert_eq!(report.total_scenarios, 1);
        assert_eq!(
            report.passed, 1,
            "byte-flipping the lock sig should trip LockSignature"
        );
        assert_eq!(report.failed_p0, 0);
        assert_eq!(report.caught_by_wrong_step, 0);
    }

    #[test]
    fn coverage_is_incomplete_with_one_scenario() {
        let report = run_catalog_from_str(SINGLE_SCENARIO_CATALOG).unwrap();
        assert!(
            !report.coverage_complete,
            "one scenario cannot cover all 9 StepName variants"
        );
        assert!(report.covered_steps.contains(&StepName::LockSignature));
    }

    #[test]
    fn drand_only_scenario_runs() {
        let json = r#"{
            "catalog_schema_version": "1",
            "protocol_version": "1",
            "defaults": { "entry_count": 3, "weather": "1013", "winner_count": 2 },
            "test_keypairs": {},
            "fixture_bundles": {},
            "scenarios": [
                {
                    "name": "drand_only_exec_sig_flip",
                    "category": "exec_signature",
                    "description": "drand-only bundle with exec sig flip",
                    "severity": "critical",
                    "tamper": {
                        "kind": "field_op",
                        "op": "byte_flip",
                        "path": "execution_receipt.signature_hex",
                        "offset": 0
                    },
                    "expected_catch_steps": ["exec_signature"],
                    "bundle_params": { "weather": null }
                }
            ]
        }"#;
        let report = run_catalog_from_str(json).unwrap();
        assert_eq!(report.passed, 1, "drand-only scenario should also work");
    }
}
