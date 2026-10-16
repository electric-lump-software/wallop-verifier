//! Offline paths of `wallop-verify weather-attest`. Network lookups are
//! covered by the binary's unit tests against a local mock server.

#![cfg(feature = "cli")]

use std::io::Write;
use std::process::{Command, Output, Stdio};

use wallop_verifier::_test_support::{build_valid_v5_bundle, v6_entries};

fn run(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wallop-verify"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn refuses_a_schema_5_bundle() {
    let (json, _, _) = build_valid_v5_bundle(&v6_entries(), Some("1013"), 2);
    let out = run(&["weather-attest", "-"], &json);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("schema_version \"6\""));
}

#[test]
fn refuses_unparseable_input() {
    let out = run(&["weather-attest", "-"], "not json");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn help_lists_the_subcommand() {
    let out = run(&["--help"], "");
    assert!(String::from_utf8_lossy(&out.stdout).contains("weather-attest"));
}

#[test]
fn subcommand_help_explains_the_key_flags_and_exit_codes() {
    let top = String::from_utf8_lossy(&run(&["--help"], "").stdout).into_owned();
    assert!(
        top.contains("Compare a bundle's weather details with public records"),
        "{top}"
    );
    let out = run(&["weather-attest", "--help"], "");
    let help = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for wanted in [
        "WALLOP_METOFFICE_KEY",
        "shell history",
        "--mode",
        "--pin-",
        "no mismatch was found",
        "not a failed verification",
    ] {
        assert!(help.contains(wanted), "{wanted:?} missing from: {help}");
    }
}

#[test]
fn refuses_a_frequency_lock_with_an_unusable_execution_receipt() {
    use wallop_verifier::_test_support::{FreqParams, build_freq_bundle};
    let p = FreqParams {
        exec_entropy_composition: wallop_verifier::protocol::landobs_v1::ENTROPY_COMPOSITION.into(),
        ..FreqParams::value()
    };
    let (json, _, _) = build_freq_bundle(&p);
    let out = run(&["weather-attest", "-"], &json);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        // The frequency path's own refusal: the bundle was dispatched by
        // its lock receipt's tag.
        String::from_utf8_lossy(&out.stderr).contains("the execution receipt is unusable"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Nothing was fetched or reported.
    assert!(out.stdout.is_empty());
}

#[test]
fn subcommand_help_names_the_grid_frequency_record() {
    let out = run(&["weather-attest", "--help"], "");
    let help = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(help.contains("Elexon's public BMRS FREQ record"), "{help}");
}
