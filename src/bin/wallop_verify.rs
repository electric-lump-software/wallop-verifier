use clap::{Parser, Subcommand, ValueEnum};
use std::io::Read;
use std::process::ExitCode;

use wallop_verifier::StepName;
use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::catalog::runner::ScenarioOutcome;
use wallop_verifier::verify_steps::{StepStatus, VerifierMode, verify_bundle, verify_bundle_with};

mod endpoint_resolver;
mod pinned_resolver;
use endpoint_resolver::EndpointResolver;

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
    /// against the wallop instance's `/operator/:slug/keys` and
    /// `/infrastructure/keys` endpoints (same-origin caveat applies).
    /// `attributable` additionally pins keys to an operator-hosted
    /// `.well-known` document on a domain the operator controls
    /// independently of wallop. Tier-1 (attributable) ships in a
    /// follow-up release; use `attestable` or `self-consistency` for now.
    #[arg(long, value_enum, default_value_t = ModeFlag::SelfConsistency)]
    mode: ModeFlag,

    /// Wallop base URL used by `--mode attestable` and `--mode attributable`.
    /// The resolver fetches keys from `<URL>/operator/<slug>/keys` and
    /// `<URL>/infrastructure/keys`. Required for tier-2 / tier-1; ignored
    /// otherwise. Example: `--wallop-base-url https://wallop.example.com`.
    #[arg(long, value_name = "URL")]
    wallop_base_url: Option<String>,

    /// Operator-hosted (or wallop-hosted) URL of the signed keyring pin.
    /// Required when `--mode attributable` is selected; ignored otherwise.
    /// The verifier fetches the JSON envelope from this URL and verifies
    /// its signature against the bundled trust anchor (or the override set
    /// supplied via `--infra-key-pin`).
    #[arg(long, value_name = "URL")]
    pin_from_url: Option<String>,

    /// Override the bundled wallop infrastructure trust anchor with a
    /// caller-supplied anchor record (JSON). Repeatable. The override
    /// REPLACES the bundled set; it does not extend it. Used for
    /// historical re-verification beyond a yanked or unavailable
    /// `wallop_verifier` crate version.
    ///
    /// Each value MUST be a complete anchor record:
    /// `{"key_id":"...", "public_key_hex":"...", "inserted_at":"...", "revoked_at": null | "..."}`.
    ///
    /// Hex-only override is intentionally not accepted — the temporal-
    /// binding check (spec §4.2.4) requires `inserted_at` and the
    /// override path cannot bypass it.
    #[arg(long, value_name = "JSON")]
    infra_key_pin: Vec<String>,
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
        (None, Some(path)) => match cli.mode {
            ModeFlag::Attributable => {
                let base_url = match cli.wallop_base_url.as_deref() {
                    Some(url) => url.to_string(),
                    None => {
                        eprintln!("error: --mode attributable requires --wallop-base-url <URL>.");
                        eprintln!(
                            "       The verifier needs the live wallop instance to look up \
                             operator keys (cross-checked against the signed pin)."
                        );
                        return ExitCode::from(2);
                    }
                };
                if let Err(reason) = validate_wallop_base_url(&base_url) {
                    eprintln!("error: --wallop-base-url is invalid: {reason}");
                    return ExitCode::from(2);
                }
                let pin_url = match cli.pin_from_url.as_deref() {
                    Some(url) => url.to_string(),
                    None => {
                        eprintln!("error: --mode attributable requires --pin-from-url <URL>.");
                        eprintln!(
                            "       The pin URL hosts the signed keyring envelope wallop's \
                             infrastructure key has committed to. Verifier-side bundled \
                             anchors verify the signature."
                        );
                        return ExitCode::from(2);
                    }
                };
                run_verify_attributable(path, &base_url, &pin_url, &cli.infra_key_pin)
            }
            ModeFlag::Attestable => {
                let base_url = match cli.wallop_base_url.as_deref() {
                    Some(url) => url.to_string(),
                    None => {
                        eprintln!("error: --mode attestable requires --wallop-base-url <URL>.");
                        eprintln!(
                            "       The resolver fetches keys from \
                             <URL>/operator/<slug>/keys and <URL>/infrastructure/keys."
                        );
                        return ExitCode::from(2);
                    }
                };
                if let Err(reason) = validate_wallop_base_url(&base_url) {
                    eprintln!("error: --wallop-base-url is invalid: {reason}");
                    eprintln!(
                        "       Tier-2 attestable mode is a same-origin trust assertion; \
                         keys arriving over an unauthenticated channel collapse the trust \
                         model. Use https:// (or http://localhost / 127.0.0.1 for dev)."
                    );
                    return ExitCode::from(2);
                }
                run_verify_attestable(path, &base_url)
            }
            ModeFlag::SelfConsistency => {
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
        },
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

fn run_verify_attestable(path: &str, base_url: &str) -> ExitCode {
    // Read input — same shape as run_verify.
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

    let bundle = match ProofBundle::from_json(&json) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    // Extract the operator slug from the lock receipt's signed payload.
    // The slug is part of the receipt's signed bytes (spec §4.2.1 lock
    // receipt schema), so an attacker rewriting the bundle JSON wrapper
    // cannot redirect the resolver at a different operator's keyring
    // without invalidating the lock receipt's signature — which the
    // verifier catches at the lock-signature step.
    //
    // The slug is interpolated into the resolver URL before that
    // signature step runs, so we additionally validate it against the
    // producer-side charset (`^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`,
    // 2-63 chars; spec §4.2.1) before constructing any URL. A slug
    // containing `/`, `?`, `#`, `..`, CR/LF, or non-ASCII would
    // otherwise let a tampered (signature-invalid) bundle direct the
    // resolver at arbitrary URLs — bounded in outcome by the eventual
    // signature failure, but unbounded in the request shape it could
    // smuggle. Reject early.
    let operator_slug = match operator_slug_from_lock(&bundle.lock_receipt.payload_jcs) {
        Some(slug) => match validate_operator_slug(&slug) {
            Ok(()) => slug,
            Err(reason) => {
                eprintln!("error: lock receipt's `operator_slug` is invalid: {reason}");
                eprintln!(
                    "       attestable mode rejects malformed slugs before constructing \
                     any HTTP request. The producer-side rule is \
                     `^[a-z0-9][a-z0-9-]{{0,61}}[a-z0-9]$` (lowercase alphanumeric with \
                     hyphens, 2-63 chars; spec §4.2.1)."
                );
                return ExitCode::from(2);
            }
        },
        None => {
            eprintln!("error: could not read `operator_slug` from the lock receipt payload.");
            eprintln!(
                "       The bundle's lock receipt JCS payload is malformed or missing \
                 the slug field. attestable mode cannot proceed without an operator \
                 to look up."
            );
            return ExitCode::from(2);
        }
    };

    let resolver = EndpointResolver::new(base_url, operator_slug.clone());
    let report = verify_bundle_with(&bundle, &resolver, VerifierMode::Attestable);

    // Read the canonicalised URLs from the resolver so the report
    // surfaces what the resolver actually hit, not a re-formatted
    // version of the user's CLI input. Tightens the audit trail.
    let trust_root_urls = (
        resolver.operator_keys_url(),
        resolver.infrastructure_keys_url(),
    );
    print_report(&bundle, &report, Some(&trust_root_urls));

    if report.passed() {
        println!("  RESULT: PASS");
        ExitCode::SUCCESS
    } else {
        println!("  RESULT: FAIL ({} errors)", report.error_count());
        ExitCode::from(1)
    }
}

fn run_verify_attributable(
    path: &str,
    base_url: &str,
    pin_url: &str,
    infra_key_pin_overrides: &[String],
) -> ExitCode {
    use pinned_resolver::{AnchorRecord, PinError, PinnedResolver};
    use wallop_verifier::anchors::ANCHORS as BUNDLED_ANCHORS;

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

    let bundle = match ProofBundle::from_json(&json) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    let operator_slug = match operator_slug_from_lock(&bundle.lock_receipt.payload_jcs) {
        Some(slug) => match validate_operator_slug(&slug) {
            Ok(()) => slug,
            Err(reason) => {
                eprintln!("error: lock receipt's `operator_slug` is invalid: {reason}");
                return ExitCode::from(2);
            }
        },
        None => {
            eprintln!("error: could not read `operator_slug` from the lock receipt payload.");
            return ExitCode::from(2);
        }
    };

    // Anchor set: bundled by default, override if --infra-key-pin given.
    // The override REPLACES the bundled set per spec §4.2.4 — never extends.
    let anchors: Vec<AnchorRecord> = if infra_key_pin_overrides.is_empty() {
        BUNDLED_ANCHORS.iter().map(AnchorRecord::from).collect()
    } else {
        let mut parsed = Vec::with_capacity(infra_key_pin_overrides.len());
        for (i, raw) in infra_key_pin_overrides.iter().enumerate() {
            match parse_infra_key_pin_override(raw) {
                Ok(record) => parsed.push(record),
                Err(reason) => {
                    eprintln!("error: --infra-key-pin #{} is invalid: {reason}", i + 1);
                    eprintln!(
                        "       Expected JSON: \
                         {{\"key_id\":\"...\",\"public_key_hex\":\"...\",\
                         \"inserted_at\":\"...\",\"revoked_at\":null|\"...\"}}"
                    );
                    return ExitCode::from(2);
                }
            }
        }
        parsed
    };

    let endpoint = EndpointResolver::new(base_url, operator_slug.clone());
    let resolver = match PinnedResolver::fetch(pin_url, anchors, endpoint) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: pin verification failed: {e}");
            match e {
                PinError::Unreachable => {
                    eprintln!("       Could not reach {pin_url}.");
                }
                PinError::PublishedInFuture => {
                    eprintln!(
                        "       The pin's published_at is more than 60s ahead of \
                         this machine's clock. Check NTP on either side."
                    );
                }
                PinError::AnchorNotFound => {
                    eprintln!(
                        "       No bundled or override anchor verifies this pin's \
                         signature. If you're verifying a historical bundle whose \
                         signing anchor has aged out of this crate version, supply \
                         the historical anchor record via --infra-key-pin."
                    );
                }
                PinError::SignatureInvalid(_) | PinError::SchemaMismatch(_) => {}
            }
            return ExitCode::from(1);
        }
    };

    // Verifier obligation 5 (spec §4.2.4): the pin's operator_slug MUST
    // match the bundle's. Cross-checked here at the CLI level, since
    // PinnedResolver doesn't see the bundle.
    if resolver.pin_operator_slug() != operator_slug {
        eprintln!(
            "error: pin commits to operator_slug {:?} but the bundle's lock receipt \
             commits to {:?}.",
            resolver.pin_operator_slug(),
            operator_slug
        );
        return ExitCode::from(1);
    }

    // SHOULD-warn for stale pins (spec §4.2.4 freshness rule, advisory side)
    // is not yet implemented. When the warning lands, a `--no-stale-warn`
    // opt-out flag will be added at the same time. Pre-launch breaking
    // changes are free; shipping the flag as a wired no-op promised a
    // behaviour the binary did not have (goal-3 violation), so it is
    // deliberately absent until the warning ships.

    let report = verify_bundle_with(&bundle, &resolver, VerifierMode::Attributable);
    print_report(&bundle, &report, None);

    if report.passed() {
        println!("  RESULT: PASS");
        ExitCode::SUCCESS
    } else {
        println!("  RESULT: FAIL ({} errors)", report.error_count());
        ExitCode::from(1)
    }
}

/// Parse a `--infra-key-pin` JSON value into a verifier-side
/// `AnchorRecord`. Per spec §4.2.4 "Override carries a full record"
/// the override MUST supply the full anchor schema; hex-only is
/// rejected at the CLI surface.
fn parse_infra_key_pin_override(raw: &str) -> Result<pinned_resolver::AnchorRecord, String> {
    #[derive(serde::Deserialize)]
    struct Wire {
        key_id: String,
        public_key_hex: String,
        inserted_at: String,
        #[serde(default)]
        revoked_at: Option<String>,
    }

    let parsed: Wire = serde_json::from_str(raw).map_err(|e| format!("not JSON: {e}"))?;
    let pk_bytes =
        hex::decode(&parsed.public_key_hex).map_err(|e| format!("public_key_hex not hex: {e}"))?;
    let public_key: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| "public_key_hex must decode to 32 bytes".to_string())?;

    if wallop_verifier::key_id(&public_key) != parsed.key_id {
        return Err(format!(
            "key_id {:?} does not hash from public_key_hex (overrides MUST be self-consistent)",
            parsed.key_id
        ));
    }

    Ok(pinned_resolver::AnchorRecord {
        key_id: parsed.key_id,
        public_key,
        inserted_at: parsed.inserted_at,
        revoked_at: parsed.revoked_at,
    })
}

/// Extract `operator_slug` from a signed lock-receipt JCS payload.
/// Mirrors what the typed parsers in `wallop_verifier::protocol::receipts`
/// do but stays at the `serde_json::Value` level — the CLI doesn't need
/// to dispatch on `schema_version` for this one field, and an unknown
/// schema (rejected by `BundleShape` later in the pipeline) still
/// surfaces a usable slug here for the resolver to look up.
fn operator_slug_from_lock(payload_jcs: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(payload_jcs).ok()?;
    value
        .get("operator_slug")
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Validate an operator slug against the producer-side charset rule
/// pinned in spec §4.2.1: `^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`, 2-63
/// characters, lowercase ASCII alphanumeric with internal hyphens
/// allowed. Manual byte check (matches `validate_weather_station`'s
/// shape in `protocol/receipts.rs`) so the CLI does not pull `regex`
/// for one validator.
///
/// Belt-and-braces against URL-injection / path-traversal / SSRF: the
/// slug is interpolated into the resolver URL before the lock
/// signature is verified. A malformed slug whose signature is going to
/// fail later in the pipeline anyway should not be permitted to direct
/// the verifier at arbitrary URLs on the wallop host. Reject early.
fn validate_operator_slug(slug: &str) -> Result<(), String> {
    let bytes = slug.as_bytes();
    if !(2..=63).contains(&bytes.len()) {
        return Err(format!(
            "length {} is outside the 2-63 char range",
            bytes.len()
        ));
    }
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let inner = |b: u8| alnum(b) || b == b'-';
    if !alnum(bytes[0]) {
        return Err("must start with [a-z0-9]".into());
    }
    if !alnum(bytes[bytes.len() - 1]) {
        return Err("must end with [a-z0-9]".into());
    }
    for &b in &bytes[1..bytes.len() - 1] {
        if !inner(b) {
            return Err(format!(
                "invalid character {:?} (allowed: [a-z0-9-])",
                b as char
            ));
        }
    }
    Ok(())
}

/// Validate a `--wallop-base-url`. Tier-2 attestable mode is, by name,
/// a same-origin trust assertion: the entire trust model collapses if
/// the keys arrive over an unauthenticated channel. Require `https://`
/// for non-loopback hosts; allow `http://localhost`, `http://127.0.0.1`,
/// and `http://[::1]` for development convenience.
fn validate_wallop_base_url(url: &str) -> Result<(), String> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Ok(());
    }
    if lower.starts_with("http://localhost")
        || lower.starts_with("http://127.0.0.1")
        || lower.starts_with("http://[::1]")
    {
        return Ok(());
    }
    Err(
        "must use https:// (or http://localhost / http://127.0.0.1 / http://[::1] for local development)"
            .into(),
    )
}

/// Shared report-printing for both `run_verify` and
/// `run_verify_attestable`. Header (mode, draw, key_ids), per-step
/// breakdown, blank line. Caller appends the RESULT line.
///
/// `trust_root` is `Some((operator_url, infrastructure_url))` when the
/// verification ran against a non-bundle resolver and it's worth
/// surfacing the URLs the keys were resolved from. The caller passes
/// canonicalised URLs read from the resolver itself, so the report
/// names what the resolver actually hit.
fn print_report(
    bundle: &ProofBundle,
    report: &wallop_verifier::verify_steps::VerificationReport,
    trust_root: Option<&(String, String)>,
) {
    let version = env!("CARGO_PKG_VERSION");
    println!("wallop-verify {version}");
    println!();
    println!("  Mode ................ {}", report.mode);
    if let Some((operator_url, infra_url)) = trust_root {
        println!("  Trust root .......... {operator_url}");
        println!("  Trust root .......... {infra_url}");
    }
    println!("  Draw ................ {}", &bundle.draw_id);
    if let Some(ref kid) = report.operator_key_id {
        println!("  Operator key ........ {kid}");
    }
    if let Some(ref kid) = report.infra_key_id {
        println!("  Infrastructure key .. {kid}");
    }
    println!();

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

#[cfg(test)]
mod tests {
    use super::*;

    // ── operator_slug validation ───────────────────────────────────────

    #[test]
    fn validate_operator_slug_accepts_canonical_shapes() {
        assert!(validate_operator_slug("acme-prizes").is_ok());
        assert!(validate_operator_slug("ab").is_ok()); // 2-char minimum
        assert!(validate_operator_slug("a1").is_ok());
        assert!(validate_operator_slug("a-b").is_ok());
        assert!(validate_operator_slug(&"a".repeat(63)).is_ok()); // 63-char maximum
    }

    #[test]
    fn validate_operator_slug_rejects_short_or_long() {
        assert!(validate_operator_slug("").is_err());
        assert!(validate_operator_slug("a").is_err());
        assert!(validate_operator_slug(&"a".repeat(64)).is_err());
    }

    #[test]
    fn validate_operator_slug_rejects_path_traversal_and_url_injection() {
        // The whole point of the check: refuse anything the URL parser
        // could interpret as path traversal, query injection, or
        // request smuggling. Manual byte check, regex-equivalent.
        assert!(validate_operator_slug("../infrastructure").is_err());
        assert!(validate_operator_slug("acme/keys").is_err());
        assert!(validate_operator_slug("acme?x=y").is_err());
        assert!(validate_operator_slug("acme#frag").is_err());
        assert!(validate_operator_slug("acme%20").is_err());
        assert!(validate_operator_slug("acme\r\nX-Header: evil").is_err());
        assert!(validate_operator_slug("AcMe").is_err());
        assert!(validate_operator_slug("acme.prizes").is_err());
        assert!(validate_operator_slug("acme_prizes").is_err());
    }

    #[test]
    fn validate_operator_slug_rejects_leading_or_trailing_hyphen() {
        assert!(validate_operator_slug("-acme").is_err());
        assert!(validate_operator_slug("acme-").is_err());
        assert!(validate_operator_slug("-").is_err());
    }

    // ── --wallop-base-url validation ───────────────────────────────────

    #[test]
    fn validate_wallop_base_url_accepts_https() {
        assert!(validate_wallop_base_url("https://wallop.example.com").is_ok());
        assert!(validate_wallop_base_url("HTTPS://CASE-INSENSITIVE.EXAMPLE.COM").is_ok());
        assert!(validate_wallop_base_url("https://wallop.example.com/").is_ok());
    }

    #[test]
    fn validate_wallop_base_url_accepts_http_localhost_for_dev() {
        assert!(validate_wallop_base_url("http://localhost").is_ok());
        assert!(validate_wallop_base_url("http://localhost:4000").is_ok());
        assert!(validate_wallop_base_url("http://127.0.0.1").is_ok());
        assert!(validate_wallop_base_url("http://127.0.0.1:4000").is_ok());
        assert!(validate_wallop_base_url("http://[::1]").is_ok());
    }

    #[test]
    fn validate_wallop_base_url_rejects_http_for_non_loopback() {
        // Coffee-shop MITM substitution: the whole point of attestable
        // mode is the same-origin assertion. http:// for a public host
        // collapses the trust model.
        assert!(validate_wallop_base_url("http://wallop.example.com").is_err());
        assert!(validate_wallop_base_url("http://10.0.0.1").is_err());
        assert!(validate_wallop_base_url("http://192.168.1.1").is_err());
    }

    #[test]
    fn validate_wallop_base_url_rejects_unknown_schemes() {
        assert!(validate_wallop_base_url("file:///etc/passwd").is_err());
        assert!(validate_wallop_base_url("ftp://wallop.example.com").is_err());
        assert!(validate_wallop_base_url("wallop.example.com").is_err()); // no scheme
        assert!(validate_wallop_base_url("").is_err());
    }
}
