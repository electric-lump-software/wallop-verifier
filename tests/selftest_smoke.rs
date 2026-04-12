//! End-to-end smoke test for `wallop-verify selftest`.
//!
//! Runs the compiled binary as a subprocess and checks the output format
//! and exit code against the shipping catalog.
//!
//! Requires the `cli` feature — the wallop-verify binary is only compiled
//! when that feature is active.

#![cfg(feature = "cli")]

use std::process::Command;

#[test]
fn selftest_runs_and_has_expected_output_format() {
    let output = Command::new(env!("CARGO_BIN_EXE_wallop-verify"))
        .arg("selftest")
        .output()
        .expect("failed to run wallop-verify selftest");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Print output on failure to aid debugging
    if !stdout.contains("PASS:") {
        eprintln!("=== stdout ===\n{stdout}");
        eprintln!("=== stderr ===\n{stderr}");
    }

    // Should contain at least one PASS: line (we have at least 2 scenarios)
    assert!(
        stdout.lines().any(|l| l.starts_with("PASS:")),
        "output should contain at least one PASS: line"
    );

    // Should contain a Coverage check line
    assert!(
        stdout.contains("Coverage check:"),
        "output should contain Coverage check line"
    );

    // Should not have any P0 failures
    assert!(
        !stdout
            .lines()
            .any(|l| l.starts_with("FAIL:") && l.contains("P0")),
        "shipping catalog should have no P0 failures"
    );

    // Exit code should be 0 (all pass, full coverage) or 2 (coverage incomplete).
    // With the initial catalog only covering 2/9 steps, expect exit code 2.
    let code = output.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 2,
        "selftest should exit 0 (full coverage) or 2 (incomplete coverage), got {code}"
    );
}

#[test]
fn verify_path_still_works_after_selftest_restructure() {
    // Ensure the default positional-path verify mode wasn't broken by
    // the subcommand restructure.
    let output = Command::new(env!("CARGO_BIN_EXE_wallop-verify"))
        .arg("/dev/null")
        .output()
        .expect("failed to run wallop-verify");

    // /dev/null is empty, so it should fail to parse
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "empty file should not verify successfully"
    );
    assert!(
        stderr.contains("invalid") || stderr.contains("error") || stderr.contains("parse"),
        "should get a parse error for empty input, got: {stderr}"
    );
}
