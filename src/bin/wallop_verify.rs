use clap::Parser;
use std::io::Read;
use std::process::ExitCode;

use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::verify_steps::{StepStatus, verify_bundle};

#[derive(Parser)]
#[command(
    name = "wallop-verify",
    version,
    about = "Verify a Wallop proof bundle"
)]
struct Cli {
    /// Path to proof bundle JSON file, or "-" for stdin
    path: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Read input
    let json = match cli.path.as_str() {
        "-" => {
            let mut buf = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
                eprintln!("error reading stdin: {e}");
                return ExitCode::from(2);
            }
            buf
        }
        path => match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error reading {path}: {e}");
                return ExitCode::from(2);
            }
        },
    };

    // Parse bundle
    let bundle = match ProofBundle::from_json(&json) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    // Run verification
    let report = verify_bundle(&bundle);

    // Print header
    let version = env!("CARGO_PKG_VERSION");
    println!("wallop-verify {version}");
    println!();
    println!("  Draw ................ {}", &bundle.draw_id);
    if let Some(ref kid) = report.operator_key_id {
        println!("  Operator key ........ {kid}");
    }
    if let Some(ref kid) = report.infra_key_id {
        println!("  Infrastructure key .. {kid}");
    }
    println!();

    // Print steps
    for step in &report.steps {
        let dots = ".".repeat(30_usize.saturating_sub(step.name.len()));
        match &step.status {
            StepStatus::Pass => println!("  {} {} PASS", step.name, dots),
            StepStatus::Fail(reason) => println!("  {} {} FAIL ({})", step.name, dots, reason),
            StepStatus::Skip(reason) => println!("  {} {} SKIP ({})", step.name, dots, reason),
        }
    }

    println!();

    // Belt-and-suspenders: run verify_full()
    let belt_check = run_verify_full_check(&bundle);

    if report.passed() && belt_check {
        println!("  RESULT: PASS");
        ExitCode::SUCCESS
    } else if report.passed() && !belt_check {
        eprintln!("  WARNING: step-by-step passed but verify_full() disagrees — possible drift");
        ExitCode::from(1)
    } else {
        println!("  RESULT: FAIL ({} errors)", report.error_count());
        ExitCode::from(1)
    }
}

fn run_verify_full_check(bundle: &ProofBundle) -> bool {
    let entries: Vec<wallop_verifier::Entry> = bundle
        .entries
        .iter()
        .map(|e| wallop_verifier::Entry {
            id: e.id.clone(),
            weight: e.weight,
        })
        .collect();

    let lock_sig = match hex::decode(&bundle.lock_receipt.signature_hex)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
    {
        Some(s) => s,
        None => return false,
    };
    let op_pk = match hex::decode(&bundle.lock_receipt.public_key_hex)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    {
        Some(k) => k,
        None => return false,
    };
    let exec_sig = match hex::decode(&bundle.execution_receipt.signature_hex)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
    {
        Some(s) => s,
        None => return false,
    };
    let infra_pk = match hex::decode(&bundle.execution_receipt.public_key_hex)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    {
        Some(k) => k,
        None => return false,
    };

    wallop_verifier::verify_full(
        &bundle.lock_receipt.payload_jcs,
        &lock_sig,
        &op_pk,
        &bundle.execution_receipt.payload_jcs,
        &exec_sig,
        &infra_pk,
        &entries,
    )
    .unwrap_or_default()
}
