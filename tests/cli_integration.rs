//! Integration tests for wallop-verify CLI pipeline.
//!
//! These tests verify that the step-by-step pipeline and verify_full()
//! agree on all inputs.

use wallop_verifier::_test_support::{build_valid_bundle, build_valid_drand_only_bundle};
use wallop_verifier::Entry;
use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::verify_steps::{StepStatus, verify_bundle};

fn run_verify_full(bundle: &ProofBundle) -> bool {
    let entries: Vec<Entry> = bundle
        .entries
        .iter()
        .map(|e| Entry {
            id: e.uuid.clone(),
            weight: e.weight,
        })
        .collect();
    let lock_sig: [u8; 64] = hex::decode(&bundle.lock_receipt.signature_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let op_pk: [u8; 32] = hex::decode(
        bundle
            .lock_receipt
            .public_key_hex
            .as_deref()
            .expect("legacy bundle in this test must carry inline operator key"),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let exec_sig: [u8; 64] = hex::decode(&bundle.execution_receipt.signature_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let infra_pk: [u8; 32] = hex::decode(
        bundle
            .execution_receipt
            .public_key_hex
            .as_deref()
            .expect("legacy bundle in this test must carry inline infra key"),
    )
    .unwrap()
    .try_into()
    .unwrap();

    wallop_verifier::verify_full(
        &bundle.lock_receipt.payload_jcs,
        &lock_sig,
        &op_pk,
        &bundle.execution_receipt.payload_jcs,
        &exec_sig,
        &infra_pk,
        &entries,
    )
    .unwrap_or(false)
}

/// Drift guard: the step-by-step report must agree with verify_full() on valid bundles.
#[test]
fn step_by_step_agrees_with_verify_full() {
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

    // Test with weather
    let json = build_valid_bundle(&entries, Some("1013"), 2);
    let bundle = ProofBundle::from_json(&json).unwrap();
    let report = verify_bundle(&bundle);
    // Fixtures carry a genuine quicknet beacon, so the drand BLS step
    // runs for real and the whole report must agree with verify_full.
    let report_pass = report.passed();
    let vf_pass = run_verify_full(&bundle);
    assert!(vf_pass, "valid bundle must pass verify_full");
    assert_eq!(
        report_pass, vf_pass,
        "drift detected: report passed={report_pass}, verify_full={vf_pass}"
    );

    // Test drand-only, in the shape wallop_core emits on weather fallback
    let (json2, _) = build_valid_drand_only_bundle();
    let bundle2 = ProofBundle::from_json(&json2).unwrap();
    let report2 = verify_bundle(&bundle2);
    let report_pass2 = report2.passed();
    let vf_pass2 = run_verify_full(&bundle2);
    assert!(vf_pass2, "valid drand-only bundle must pass verify_full");
    assert_eq!(
        report_pass2, vf_pass2,
        "drift detected (drand-only): report passed={report_pass2}, verify_full={vf_pass2}"
    );
}

#[test]
fn drand_only_bundle_omits_weather() {
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
    let json = build_valid_bundle(&entries, None, 1);

    // Verify the bundle JSON has no weather_value key in entropy
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(
        val["entropy"].get("weather_value").is_none(),
        "drand-only bundle should not contain weather_value key"
    );

    let bundle = ProofBundle::from_json(&json).unwrap();
    assert!(bundle.is_drand_only());
    let report = verify_bundle(&bundle);
    // Steps 1-7 should pass
    for step in &report.steps[..7] {
        assert!(
            matches!(step.status, StepStatus::Pass),
            "step {} was {:?}",
            step.name,
            step.status
        );
    }
}
