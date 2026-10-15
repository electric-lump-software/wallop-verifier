//! Tamper vectors: lock v6 / execution v5 proof bundles from wallop_core,
//! each with exactly one signed field changed and re-signed, so only the
//! semantic checks can refuse it.
//!
//! The vector file is `spec/vectors/proof-bundle-v6-tamper.json` in the
//! wallop repo. It is not vendored yet, so this test reads it from the
//! path in `WALLOP_TAMPER_VECTORS` and skips, saying so, when that is unset.

use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::key_resolver::{
    InsertedAt, KeyClass, KeyResolver, ResolutionError, ResolvedKey,
};
use wallop_verifier::verify_steps::{
    StepStatus, VerificationReport, VerifierMode, verify_bundle_with,
};

const ENV: &str = "WALLOP_TAMPER_VECTORS";

/// The vector file, or `None` (with a message) when `WALLOP_TAMPER_VECTORS` is unset.
fn vector() -> Option<serde_json::Value> {
    let Ok(path) = std::env::var(ENV) else {
        eprintln!("skipping: set {ENV} to the path of proof-bundle-v6-tamper.json to run");
        return None;
    };
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    Some(serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}")))
}

/// Resolves from the vector's inline `keys: [{key_id, public_key_hex, key_class, inserted_at}]`.
struct ListResolver(Vec<(String, [u8; 32], KeyClass, String)>);

impl ListResolver {
    fn from_keys(keys: &serde_json::Value) -> Self {
        Self(
            keys.as_array()
                .expect("keys is a list")
                .iter()
                .map(|k| {
                    let class = match k["key_class"].as_str().unwrap() {
                        "operator" => KeyClass::Operator,
                        "infrastructure" => KeyClass::Infrastructure,
                        other => panic!("unknown key_class {other}"),
                    };
                    (
                        k["key_id"].as_str().unwrap().to_string(),
                        hex::decode(k["public_key_hex"].as_str().unwrap())
                            .unwrap()
                            .try_into()
                            .unwrap(),
                        class,
                        k["inserted_at"].as_str().unwrap().to_string(),
                    )
                })
                .collect(),
        )
    }
}

impl KeyResolver for ListResolver {
    fn resolve(&self, key_id: &str, key_class: KeyClass) -> Result<ResolvedKey, ResolutionError> {
        self.0
            .iter()
            .find(|(id, _, class, _)| id == key_id && *class == key_class)
            .map(|(_, pk, class, at)| ResolvedKey {
                public_key: *pk,
                inserted_at: InsertedAt::At(at.clone()),
                key_class: *class,
            })
            .ok_or(ResolutionError::KeyNotFound)
    }
}

/// A bundle given as a JSON string or as a JSON object.
fn bundle_json(bundle: &serde_json::Value) -> String {
    bundle
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| bundle.to_string())
}

fn verify(bundle: &serde_json::Value, resolver: &ListResolver) -> VerificationReport {
    verify_bundle_with(
        &ProofBundle::from_json(&bundle_json(bundle)).unwrap(),
        resolver,
        VerifierMode::Attestable,
    )
}

/// The snake_case names of every failing step, sorted.
fn failing_steps(report: &VerificationReport) -> Vec<String> {
    let mut got: Vec<String> = report
        .steps
        .iter()
        .filter(|s| matches!(s.status, StepStatus::Fail(_)))
        .map(|s| {
            serde_json::to_value(s.name)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    got.sort();
    got
}

#[test]
fn tamper_vector_bases_pass_every_step() {
    let Some(v) = vector() else { return };
    let resolver = ListResolver::from_keys(&v["keys"]);
    let bases = v["bases"].as_array().expect("bases is a list");
    assert!(!bases.is_empty());
    for base in bases {
        let name = base["name"].as_str().unwrap();
        assert_eq!(base["expected_passed"], true, "{name}");
        let report = verify(&base["bundle"], &resolver);
        assert!(report.passed(), "base {name}: {:?}", report.steps);
        for step in &report.steps {
            assert_eq!(
                step.status,
                StepStatus::Pass,
                "base {name}: {:?}",
                step.name
            );
        }
    }
}

#[test]
fn every_tampered_bundle_fails_exactly_its_named_steps() {
    let Some(v) = vector() else { return };
    let resolver = ListResolver::from_keys(&v["keys"]);
    let cases = v["cases"].as_array().expect("cases is a list");
    assert!(!cases.is_empty());
    let mut mismatches = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let report = verify(&case["bundle"], &resolver);
        assert!(!report.passed(), "{name} passed: {:?}", report.steps);
        let mut expected: Vec<String> = case["expected_failing_steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        expected.sort();
        assert!(!expected.is_empty(), "{name} names no failing step");
        let got = failing_steps(&report);
        if got != expected {
            mismatches.push(format!(
                "{name}: expected {expected:?}, got {got:?}: {:?}",
                report.steps
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} cases differ:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches.join("\n")
    );
}

#[test]
fn tamper_case_names_are_unique() {
    let Some(v) = vector() else { return };
    let mut names: Vec<&str> = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), total, "duplicate case names");
}
