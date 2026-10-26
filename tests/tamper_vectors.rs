//! Tamper vectors: lock v6 / execution v5 proof bundles from wallop_core,
//! each with exactly one signed field changed and re-signed, so only the
//! semantic checks can refuse it.
//!
//! There is one vector file per entropy tag in the wallop repo's
//! `spec/vectors`: `proof-bundle-v6-tamper.json` (Land Observations) and
//! `proof-bundle-v6-tamper-freq.json` (grid frequency). They are read under
//! the rules in `tests/common`: the vendored copy under `vendor/wallop`; a
//! failure if it is missing once any v6 vector is vendored; before that,
//! the path in `WALLOP_TAMPER_VECTORS` / `WALLOP_TAMPER_FREQ_VECTORS` or
//! `WALLOP_CORE_VECTORS_DIR`. It prints which file it used.

use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::key_resolver::{
    InsertedAt, KeyClass, KeyResolver, ResolutionError, ResolvedKey,
};
use wallop_verifier::verify_steps::{
    StepStatus, VerificationReport, VerifierMode, verify_bundle_with,
};

mod common;

/// Each vector file: `(name, environment variable)`.
const FILES: [(&str, &str); 2] = [
    ("proof-bundle-v6-tamper.json", "WALLOP_TAMPER_VECTORS"),
    (
        "proof-bundle-v6-tamper-freq.json",
        "WALLOP_TAMPER_FREQ_VECTORS",
    ),
];

/// Every vector file, read under `common`'s rules: a missing file is a
/// failure, never a skip.
fn vectors() -> Vec<serde_json::Value> {
    FILES
        .iter()
        .map(|(name, env)| common::core_vector(name, Some(env)))
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
    // Every file is checked before failing, so a mismatch in the first
    // file can't hide one in the next.
    let failures: Vec<String> = FILES
        .iter()
        .map(|(name, env)| (name, common::core_vector(name, Some(env))))
        .filter_map(|(name, v)| {
            tampered_bundles_fail_exactly_their_named_steps(&v).map(|e| format!("{name}: {e}"))
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

/// `None` when every case fails exactly its named steps, else the mismatches.
fn tampered_bundles_fail_exactly_their_named_steps(v: &serde_json::Value) -> Option<String> {
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
    (!mismatches.is_empty()).then(|| {
        format!(
            "{} of {} cases differ:\n{}",
            mismatches.len(),
            cases.len(),
            mismatches.join("\n")
        )
    })
}

#[test]
fn tamper_base_names_are_unique() {
    // Unique across every file, so a base name means one state of one tag.
    let all = vectors();
    let mut names: Vec<&str> = all
        .iter()
        .flat_map(|v| v["bases"].as_array().unwrap())
        .map(|b| b["name"].as_str().unwrap())
        .collect();
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), total, "duplicate base names");
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

/// Each tag's file carries its own bases and cases, so neither half can go
/// missing unnoticed. The Land Observations file has one base per execution
/// state: a reading, the grid-frequency window, drand alone.
#[test]
fn each_tamper_file_has_its_tag_bases_and_cases() {
    let land_obs: &[&str] = &["observed", "freq_window", "fallback"];
    let freq: &[&str] = &["freq_observed", "freq_fallback"];
    for ((name, env), bases) in FILES.iter().zip([land_obs, freq]) {
        let v = common::core_vector(name, Some(env));
        let got: Vec<&str> = v["bases"]
            .as_array()
            .expect("bases is a list")
            .iter()
            .map(|b| b["name"].as_str().unwrap())
            .collect();
        assert_eq!(got, bases, "{name}: bases");
        let cases = v["cases"].as_array().expect("cases is a list");
        for base in bases {
            assert!(
                cases.iter().any(|c| c["base"] == *base),
                "{name}: no case uses base {base}"
            );
        }
        assert!(
            cases
                .iter()
                .all(|c| bases.contains(&c["base"].as_str().unwrap())),
            "{name}: a case names a base from another file"
        );
    }
}
