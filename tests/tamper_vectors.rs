//! Tamper vectors: lock v6 / execution v5 proof bundles from wallop_core,
//! each with exactly one signed field changed and re-signed, so only the
//! semantic checks can refuse it.
//!
//! There is one vector file per entropy tag in the wallop repo's
//! `spec/vectors`: `proof-bundle-v6-tamper.json` (Land Observations) and
//! `proof-bundle-v6-tamper-freq.json` (grid frequency). For each, this test
//! reads the vendored copy under `vendor/wallop`. Only when that file is
//! missing does it read the path in the file's environment variable
//! (`WALLOP_TAMPER_VECTORS`, `WALLOP_TAMPER_FREQ_VECTORS`), and it skips
//! that file, saying so, when neither exists. It prints which file it used.

use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::key_resolver::{
    InsertedAt, KeyClass, KeyResolver, ResolutionError, ResolvedKey,
};
use wallop_verifier::verify_steps::{
    StepStatus, VerificationReport, VerifierMode, verify_bundle_with,
};

/// Each vector file: `(environment variable, vendored path)`.
const FILES: [(&str, &str); 2] = [
    (
        "WALLOP_TAMPER_VECTORS",
        "vendor/wallop/spec/vectors/proof-bundle-v6-tamper.json",
    ),
    (
        "WALLOP_TAMPER_FREQ_VECTORS",
        "vendor/wallop/spec/vectors/proof-bundle-v6-tamper-freq.json",
    ),
];

/// One vector file: the vendored copy, else the path in `env`, else
/// `None` (with a message).
fn vector_file(env: &str, vendored: &str) -> Option<serde_json::Value> {
    let vendored = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(vendored);
    let path = if vendored.is_file() {
        eprintln!(
            "tamper vectors: using the vendored file {}",
            vendored.display()
        );
        vendored
    } else if let Ok(path) = std::env::var(env) {
        eprintln!(
            "tamper vectors: {} is missing; using {env}={path}",
            vendored.display()
        );
        path.into()
    } else {
        eprintln!(
            "skipping: {} is missing and {env} is unset; set {env} to the path of \
             {} to run",
            vendored.display(),
            vendored.file_name().unwrap().to_string_lossy()
        );
        return None;
    };
    let shown = path.display();
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{shown}: {e}"));
    Some(serde_json::from_str(&text).unwrap_or_else(|e| panic!("{shown}: {e}")))
}

/// Every vector file that could be read.
fn vectors() -> Vec<serde_json::Value> {
    FILES
        .iter()
        .filter_map(|(env, vendored)| vector_file(env, vendored))
        .collect()
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
    for v in vectors() {
        tamper_vector_bases_pass(&v);
    }
}

fn tamper_vector_bases_pass(v: &serde_json::Value) {
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
    for v in vectors() {
        tampered_bundles_fail_exactly_their_named_steps(&v);
    }
}

fn tampered_bundles_fail_exactly_their_named_steps(v: &serde_json::Value) {
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
    // Unique across every file, so a case name is enough to find it.
    let all = vectors();
    let mut names: Vec<&str> = all
        .iter()
        .flat_map(|v| v["cases"].as_array().unwrap())
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), total, "duplicate case names");
}
