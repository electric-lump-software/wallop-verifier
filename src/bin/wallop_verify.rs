use clap::{Parser, Subcommand, ValueEnum};
use std::io::Read;
use std::process::ExitCode;

use wallop_verifier::StepName;
use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::catalog::runner::ScenarioOutcome;
use wallop_verifier::verify_steps::{StepStatus, VerifierMode, verify_bundle};

#[cfg(feature = "tui")]
mod tui;

#[derive(Parser)]
#[command(
    name = "wallop-verify",
    version,
    about = "Verify a Wallop! proof bundle"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to proof bundle JSON file, or "-" for stdin
    path: Option<String>,

    /// Run in interactive TUI mode
    #[arg(long)]
    #[cfg(feature = "tui")]
    tui: bool,

    /// Pin the operator public key (64-char hex). If the bundle's embedded
    /// operator key doesn't match, verification fails before any step runs.
    #[arg(long, value_name = "HEX")]
    pin_operator_key: Option<String>,

    /// Pin the infrastructure signing key (64-char hex).
    #[arg(long, value_name = "HEX")]
    pin_infra_key: Option<String>,

    /// Read the operator key pin from a file (one hex line).
    #[arg(long, value_name = "PATH", conflicts_with = "pin_operator_key")]
    pin_operator_key_file: Option<String>,

    /// Extract the operator key from a previously trusted bundle (TOFU).
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["pin_operator_key", "pin_operator_key_file"]
    )]
    pin_from_bundle: Option<String>,

    /// Verification trust mode. `self-consistency` (default) uses the
    /// bundle's inline keys — catches accidents and casual tampering, no
    /// defence against tampered mirrors. `attestable` resolves keys
    /// against `/operator/:slug/keys` (same-origin). `attributable`
    /// resolves against an operator-hosted `.well-known` pin on a domain
    /// the operator controls independently. Tier-1 (attributable) and
    /// tier-2 (attestable) implementations ship in a follow-up release;
    /// use `self-consistency` for now.
    #[arg(long, value_enum, default_value_t = ModeFlag::SelfConsistency)]
    mode: ModeFlag,
}

/// CLI surface for `--mode`. Distinct from `wallop_verifier::VerifierMode`
/// so the kebab-case spelling (`self-consistency`) matches what users
/// type, while the library variant uses snake-case for serde wire form.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum ModeFlag {
    Attributable,
    Attestable,
    SelfConsistency,
}

impl ModeFlag {
    fn to_library(self) -> VerifierMode {
        match self {
            ModeFlag::Attributable => VerifierMode::Attributable,
            ModeFlag::Attestable => VerifierMode::Attestable,
            ModeFlag::SelfConsistency => VerifierMode::SelfConsistencyOnly,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Run the tamper scenario catalog against a generated known-good bundle
    Selftest {
        /// Run selftest in interactive TUI mode
        #[arg(long)]
        #[cfg(feature = "tui")]
        tui: bool,
        /// Run selftest with demo data (implies --tui)
        #[arg(long, conflicts_with = "tui")]
        #[cfg(feature = "tui")]
        demo: bool,
        /// Record the demo session to an asciicast v2 file (requires --demo)
        #[arg(long, value_name = "PATH", requires = "demo")]
        #[cfg(feature = "tui")]
        record: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match (cli.command, cli.path.as_deref()) {
        (
            Some(Commands::Selftest {
                #[cfg(feature = "tui")]
                    tui: use_tui,
                #[cfg(feature = "tui")]
                demo,
                #[cfg(feature = "tui")]
                record,
            }),
            _,
        ) => {
            #[cfg(feature = "tui")]
            if use_tui || demo {
                return tui::run_selftest_tui(demo, record);
            }
            run_selftest()
        }
        (None, Some(path)) => {
            // Tier-1 / tier-2 resolver implementations are CLI-side and
            // ship in a follow-up release. The library trait is in place;
            // the HTTP-backed implementations (EndpointResolver,
            // PinnedResolver) are not yet wired here. Reject explicitly
            // so users learn what's available now.
            match cli.mode {
                ModeFlag::Attestable | ModeFlag::Attributable => {
                    eprintln!(
                        "error: --mode {} is not yet implemented in this release.",
                        match cli.mode {
                            ModeFlag::Attestable => "attestable",
                            ModeFlag::Attributable => "attributable",
                            ModeFlag::SelfConsistency => unreachable!(),
                        }
                    );
                    eprintln!(
                        "       Use --mode self-consistency for now (default). The \
                         library `KeyResolver` trait is in place; the CLI's HTTP-backed \
                         resolver implementations land in a follow-up release."
                    );
                    return ExitCode::from(2);
                }
                ModeFlag::SelfConsistency => {}
            }
            let pins = PinConfig {
                operator_key: resolve_operator_pin(
                    cli.pin_operator_key.as_deref(),
                    cli.pin_operator_key_file.as_deref(),
                    cli.pin_from_bundle.as_deref(),
                ),
                infra_key: cli.pin_infra_key.clone(),
            };
            #[cfg(feature = "tui")]
            if cli.tui {
                return tui::run_verify_tui(path, &pins);
            }
            run_verify(path, &pins, cli.mode.to_library())
        }
        (None, None) => {
            eprintln!("error: no proof bundle path provided");
            eprintln!("Usage: wallop-verify <PATH> or wallop-verify selftest");
            ExitCode::from(2)
        }
    }
}

// ==================== selftest subcommand ====================

fn run_selftest() -> ExitCode {
    let version = env!("CARGO_PKG_VERSION");
    println!("wallop-verify {version} selftest");

    let report = match wallop_verifier::catalog::run_shipping_catalog() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("catalog load error: {e}");
            return ExitCode::from(3);
        }
    };

    println!();
    println!("Running {} tamper scenarios...", report.total_scenarios);
    println!();

    for result in &report.results {
        match &result.outcome {
            ScenarioOutcome::Passed { caught_at } => {
                println!("PASS: {} caught at {}", result.name, caught_at);
            }
            ScenarioOutcome::FailedP0 => {
                println!("FAIL: {} expected catch, got (no failure)", result.name);
                println!("      >>> P0: verifier accepted tampered bundle");
            }
            ScenarioOutcome::CaughtByWrongStep { expected, actual } => {
                let expected_str: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
                println!(
                    "FAIL: {} expected one of [{}], got {}",
                    result.name,
                    expected_str.join(", "),
                    actual
                );
            }
            ScenarioOutcome::MutationError(e) => {
                println!("SKIP: {} (mutation failed: {})", result.name, e);
            }
        }
    }

    println!();
    let total_step_names = StepName::all().len();
    let covered = report.covered_steps.len();
    println!("Coverage check: {covered}/{total_step_names} StepName variants covered at runtime");

    if !report.coverage_complete {
        println!();
        println!("UNCOVERED VARIANTS:");
        for variant in StepName::all() {
            if !report.covered_steps.contains(variant) {
                println!("  - {variant}");
            }
        }
    }

    println!();
    println!(
        "{} scenarios run, {} passed, {} P0 failures, {} caught by wrong step, {} skipped",
        report.total_scenarios,
        report.passed,
        report.failed_p0,
        report.caught_by_wrong_step,
        report.skipped
    );

    if report.failed_p0 > 0 {
        ExitCode::from(1)
    } else if report.caught_by_wrong_step > 0 || !report.coverage_complete {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

// ==================== pin-key support ====================

struct PinConfig {
    operator_key: Option<String>,
    infra_key: Option<String>,
}

fn resolve_operator_pin(
    hex: Option<&str>,
    file: Option<&str>,
    trust_bundle: Option<&str>,
) -> Option<String> {
    if let Some(h) = hex {
        return Some(h.to_string());
    }
    if let Some(path) = file {
        match std::fs::read_to_string(path) {
            Ok(contents) => return Some(contents.trim().to_string()),
            Err(e) => {
                eprintln!("warning: failed to read pin file {path}: {e}");
                return None;
            }
        }
    }
    if let Some(path) = trust_bundle {
        match std::fs::read_to_string(path) {
            Ok(contents) => match ProofBundle::from_json(&contents) {
                Ok(b) => match b.lock_receipt.public_key_hex {
                    Some(hex) => return Some(hex),
                    None => {
                        eprintln!(
                            "warning: trust bundle has no inline operator key \
                             (resolver-driven bundle); --pin-from-bundle requires \
                             a legacy bundle with an inline key"
                        );
                        return None;
                    }
                },
                Err(e) => {
                    eprintln!("warning: trust bundle is not valid: {e}");
                    return None;
                }
            },
            Err(e) => {
                eprintln!("warning: failed to read trust bundle {path}: {e}");
                return None;
            }
        }
    }
    None
}

fn compare_pin(embedded_key: &str, pin: &Option<String>, kind: &str) -> Result<(), String> {
    match pin {
        Some(pinned) if pinned.eq_ignore_ascii_case(embedded_key) => Ok(()),
        Some(pinned) => Err(format!(
            "KEY PIN MISMATCH ({kind})\n  Embedded key: {embedded_key}\n  Pinned key:   {pinned}\n\
             This bundle was signed with a key you do not trust."
        )),
        None => {
            eprintln!(
                "warning: No --pin-{kind}-key supplied. Trusting embedded public key. If you"
            );
            eprintln!("  do not control the bundle source, obtain the operator's key out of band");
            eprintln!("  and re-run with --pin-{kind}-key.");
            Ok(())
        }
    }
}

// ==================== verify subcommand (default) ====================

fn run_verify(path: &str, pins: &PinConfig, mode: VerifierMode) -> ExitCode {
    // Read input
    let json = match path {
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

    // Check pin-key constraints before running verification. The pin flags
    // only apply to bundles that carry an inline `public_key_hex` — i.e.
    // legacy v3/v4 bundles. v5 lock / v4 exec bundles need resolver-driven
    // pinning, which lives in the `--mode attributable` path (not yet
    // implemented in this release).
    if let Some(embedded) = bundle.lock_receipt.public_key_hex.as_deref()
        && let Err(e) = compare_pin(embedded, &pins.operator_key, "operator")
    {
        eprintln!("{e}");
        return ExitCode::from(1);
    }
    if let Some(embedded) = bundle.execution_receipt.public_key_hex.as_deref()
        && let Err(e) = compare_pin(embedded, &pins.infra_key, "infra")
    {
        eprintln!("{e}");
        return ExitCode::from(1);
    }

    // Run verification
    let report = verify_bundle(&bundle);

    // Print header. Mode is surfaced before any per-step output so a
    // reader of the report knows what the report's "PASS" actually proved
    // (spec §4.2.4 caveat-mode disclosure).
    let version = env!("CARGO_PKG_VERSION");
    println!("wallop-verify {version}");
    println!();
    println!("  Mode ................ {}", report.mode);
    println!("  Draw ................ {}", &bundle.draw_id);
    if let Some(ref kid) = report.operator_key_id {
        println!("  Operator key ........ {kid}");
    }
    if let Some(ref kid) = report.infra_key_id {
        println!("  Infrastructure key .. {kid}");
    }
    let _ = mode; // mode currently used only to inform the resolver choice
    // (BundleEmbeddedResolver in self-consistency mode); the
    // library report carries the same value in `report.mode`.
    println!();

    // Print steps
    for step in &report.steps {
        let name_str = step.name.to_string();
        let dots = ".".repeat(30_usize.saturating_sub(name_str.len()));
        match &step.status {
            StepStatus::Pass => println!("  {} {} PASS", name_str, dots),
            StepStatus::Fail(reason) => println!("  {} {} FAIL ({})", name_str, dots, reason),
            StepStatus::Skip(reason) => println!("  {} {} SKIP ({})", name_str, dots, reason),
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
            id: e.uuid.clone(),
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
    let op_pk = match bundle
        .lock_receipt
        .public_key_hex
        .as_deref()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    {
        Some(k) => k,
        // Resolver-driven bundles (v5 lock / v4 exec) have no inline key;
        // the belt-and-suspenders verify_full check is structurally
        // unavailable for them. Pipeline-side verification (`verify_bundle`)
        // is the authoritative gate in that case.
        None => return true,
    };
    let exec_sig = match hex::decode(&bundle.execution_receipt.signature_hex)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
    {
        Some(s) => s,
        None => return false,
    };
    let infra_pk = match bundle
        .execution_receipt
        .public_key_hex
        .as_deref()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    {
        Some(k) => k,
        None => return true,
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
