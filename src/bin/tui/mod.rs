mod app;
mod input;
mod render;
mod state;

use std::process::ExitCode;

use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::catalog::runner::ScenarioOutcome;
use wallop_verifier::verify_steps::{StepName, StepStatus, verify_bundle};

use state::{Mode, PinState, ScenarioEntry, VerificationSession};

// ── Bundle verification TUI ───────────────────────────────────────────────

pub(crate) fn run_verify_tui(path: &str, pins: &super::PinConfig) -> ExitCode {
    // 1. Read bundle JSON
    let json = match read_bundle_input(path) {
        Ok(s) => s,
        Err(code) => return code,
    };

    // 2. Parse ProofBundle
    let bundle = match ProofBundle::from_json(&json) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    // 3. Resolve pin states
    let op_pin = resolve_pin_state(&bundle.lock_receipt.public_key_hex, &pins.operator_key);
    let infra_pin = resolve_pin_state(&bundle.execution_receipt.public_key_hex, &pins.infra_key);

    // Bail on mismatch before entering TUI
    if matches!(op_pin, PinState::Mismatch { .. }) {
        eprintln!("KEY PIN MISMATCH (operator): embedded key does not match pinned value");
        return ExitCode::from(1);
    }
    if matches!(infra_pin, PinState::Mismatch { .. }) {
        eprintln!("KEY PIN MISMATCH (infra): embedded key does not match pinned value");
        return ExitCode::from(1);
    }

    // 4. Run verification, build session
    let report = verify_bundle(&bundle);
    let passed = report.passed();
    let session = VerificationSession::new_bundle_verify(report, op_pin, infra_pin);

    // 5. Run the TUI
    if let Err(e) = app::run(session) {
        eprintln!("TUI error: {e}");
        return ExitCode::from(2);
    }

    // 6. Exit code
    if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

// ── Selftest TUI ──────────────────────────────────────────────────────────

pub(crate) fn run_selftest_tui(demo: bool, record: Option<String>) -> ExitCode {
    // 1. Run the shipping catalog with per-scenario reports
    let (catalog_report, scenario_reports) =
        match wallop_verifier::catalog::run_shipping_catalog_with_reports() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("catalog load error: {e}");
                return ExitCode::from(3);
            }
        };

    // 2. Build scenario entries from catalog results
    let mut scenarios: Vec<ScenarioEntry> = catalog_report
        .results
        .iter()
        .map(|r| {
            let passed = match &r.outcome {
                ScenarioOutcome::Passed { .. } => Some(true),
                ScenarioOutcome::FailedP0 => Some(false),
                ScenarioOutcome::CaughtByWrongStep { .. } => Some(false),
                ScenarioOutcome::MutationError(_) => None,
            };
            ScenarioEntry {
                name: r.name.clone(),
                description: r.description.clone(),
                tamper_summary: r.tamper_summary.clone(),
                passed: if demo { None } else { passed },
                step_statuses: vec![],
            }
        })
        .collect();

    // 3. Override DrandBlsSignature to SKIP on scenario reports where BLS is NOT the
    //    expected catch step. For scenarios that specifically test BLS tampering,
    //    keep the real BLS result so the step panel shows the correct failure.
    let scenario_reports: Vec<Option<wallop_verifier::verify_steps::VerificationReport>> =
        scenario_reports
            .into_iter()
            .enumerate()
            .map(|(i, opt_report)| {
                let bls_is_catch_step = catalog_report
                    .results
                    .get(i)
                    .is_some_and(|r| matches!(&r.outcome, ScenarioOutcome::Passed { caught_at } if *caught_at == StepName::DrandBlsSignature));
                opt_report.map(|mut report| {
                    if !bls_is_catch_step {
                        for step in &mut report.steps {
                            if step.name == StepName::DrandBlsSignature {
                                step.status = StepStatus::Skip("test fixture".into());
                            }
                        }
                    }
                    report
                })
            })
            .collect();

    // Populate step_statuses from the (now-overridden) per-scenario reports
    for (i, scenario) in scenarios.iter_mut().enumerate() {
        if let Some(Some(report)) = scenario_reports.get(i) {
            scenario.step_statuses = report.steps.iter().map(|s| s.status.clone()).collect();
        }
    }

    // 4. Build initial verification report from the first scenario
    let initial_report = scenario_reports
        .first()
        .and_then(|r| r.clone())
        .unwrap_or_else(build_first_scenario_report);

    // 5. Create session
    let mut session = VerificationSession::new_selftest(initial_report, scenarios);
    if demo {
        session.mode = Mode::Demo;
    }

    // Pre-set passed counts for non-demo mode
    if !demo {
        session.scenarios_passed = catalog_report.passed;
    }

    // 6. Run the TUI with pre-computed reports
    if let Err(e) = app::run_with_reports(session, scenario_reports, record) {
        eprintln!("TUI error: {e}");
        return ExitCode::from(2);
    }

    // 7. Exit code based on catalog results
    if catalog_report.failed_p0 > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn read_bundle_input(path: &str) -> Result<String, ExitCode> {
    if path == "-" {
        use std::io::Read;
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("error reading stdin: {e}");
            return Err(ExitCode::from(2));
        }
        Ok(buf)
    } else {
        match std::fs::read_to_string(path) {
            Ok(s) => Ok(s),
            Err(e) => {
                eprintln!("error reading {path}: {e}");
                Err(ExitCode::from(2))
            }
        }
    }
}

fn resolve_pin_state(embedded_key_hex: &str, pin: &Option<String>) -> PinState {
    match pin {
        Some(pinned) => {
            if pinned.eq_ignore_ascii_case(embedded_key_hex) {
                let key_bytes: [u8; 32] = match hex::decode(embedded_key_hex)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                {
                    Some(k) => k,
                    None => {
                        return PinState::Pinned {
                            key_id: embedded_key_hex[..8].to_string(),
                        };
                    }
                };
                PinState::Pinned {
                    key_id: wallop_verifier::key_id(&key_bytes),
                }
            } else {
                let kid = if embedded_key_hex.len() >= 8 {
                    embedded_key_hex[..8].to_string()
                } else {
                    embedded_key_hex.to_string()
                };
                PinState::Mismatch { key_id: kid }
            }
        }
        None => PinState::Unpinned,
    }
}

fn build_first_scenario_report() -> wallop_verifier::verify_steps::VerificationReport {
    let entries = vec![
        wallop_verifier::Entry {
            id: "a".into(),
            weight: 1,
        },
        wallop_verifier::Entry {
            id: "b".into(),
            weight: 1,
        },
        wallop_verifier::Entry {
            id: "c".into(),
            weight: 1,
        },
    ];

    let bundle_json = wallop_verifier::_test_support::build_valid_bundle(&entries, Some("1013"), 2);
    let bundle = ProofBundle::from_json(&bundle_json).expect("generated bundle must parse");
    let mut report = verify_bundle(&bundle);

    // Override the DrandBlsSignature step to SKIP since this is a test fixture
    for step in &mut report.steps {
        if step.name == StepName::DrandBlsSignature {
            step.status = StepStatus::Skip("test fixture".into());
        }
    }

    report
}
