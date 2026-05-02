//! Integration-level coverage of the §4.2.4 temporal-binding rule.
//!
//! Unit tests in `src/verify_steps.rs` cover the comparison logic in
//! isolation. This file exercises the same property end-to-end through
//! `verify_bundle_with` against a real `KeyResolver`, asserting the
//! pipeline routes the bundle through the `TemporalBinding` step,
//! the step rejects under a deliberately-late `inserted_at`, and the
//! overall verification verdict is reject. Catches the class of
//! regression where a future refactor accidentally bypasses the step
//! (e.g. an early-return on resolve, or a step-list reordering) —
//! something every unit test would still pass.

use wallop_verifier::_test_support::{MockResolver, build_valid_v5_bundle};
use wallop_verifier::Entry;
use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::key_resolver::InsertedAt;
use wallop_verifier::verify_steps::{StepName, StepStatus, VerifierMode, verify_bundle_with};

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
fn verify_bundle_with_rejects_when_inserted_at_postdates_locked_at() {
    // The default v5 bundle's lock receipt has
    // `locked_at = 2026-04-09T12:00:00.000000Z`. A resolver returning
    // `inserted_at` one second later violates §4.2.4
    // (`operator_signing_key.inserted_at <= lock.locked_at`); the
    // pipeline MUST reject.
    let (bundle_json, pk_hex, signing_key_id) =
        build_valid_v5_bundle(&three_uuid_entries(), Some("1013"), 2);
    let bundle = ProofBundle::from_json(&bundle_json).expect("bundle parses");
    let pk: [u8; 32] = hex::decode(&pk_hex).unwrap().try_into().unwrap();

    let mut resolver = MockResolver::new(signing_key_id, pk);
    resolver.inserted_at = InsertedAt::At("2026-04-09T12:00:01.000000Z".into());

    let report = verify_bundle_with(&bundle, &resolver, VerifierMode::Attestable);

    let temporal_step = report
        .steps
        .iter()
        .find(|s| s.name == StepName::TemporalBinding)
        .expect("TemporalBinding step is present in every report");

    match &temporal_step.status {
        StepStatus::Fail(message) => {
            assert!(
                message.contains("not live at signing time"),
                "TemporalBinding fail message should describe the binding violation, got: {message}"
            );
        }
        other => panic!("expected TemporalBinding to Fail, got {other:?}"),
    }

    assert!(
        !report.passed(),
        "overall verdict must be reject when the temporal binding step fails"
    );
}

#[test]
fn verify_bundle_with_passes_when_inserted_at_predates_locked_at() {
    // Mirror of the rejection case, but with `inserted_at` strictly
    // before `locked_at`. Pins the positive path so the rejection
    // assertion above doesn't silently turn into "always rejects".
    let (bundle_json, pk_hex, signing_key_id) =
        build_valid_v5_bundle(&three_uuid_entries(), Some("1013"), 2);
    let bundle = ProofBundle::from_json(&bundle_json).expect("bundle parses");
    let pk: [u8; 32] = hex::decode(&pk_hex).unwrap().try_into().unwrap();

    let mut resolver = MockResolver::new(signing_key_id, pk);
    resolver.inserted_at = InsertedAt::At("2026-01-01T00:00:00.000000Z".into());

    let report = verify_bundle_with(&bundle, &resolver, VerifierMode::Attestable);

    let temporal_step = report
        .steps
        .iter()
        .find(|s| s.name == StepName::TemporalBinding)
        .expect("TemporalBinding step is present in every report");

    assert!(
        matches!(temporal_step.status, StepStatus::Pass),
        "expected TemporalBinding to Pass when inserted_at predates locked_at, got {:?}",
        temporal_step.status
    );
}
