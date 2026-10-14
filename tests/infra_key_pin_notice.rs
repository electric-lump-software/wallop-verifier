//! Integration tests for the `--infra-key-pin` override notice.
//!
//! `--infra-key-pin` replaces the trust anchors compiled into the
//! binary. Anyone who copies a command containing it is trusting the
//! keys in that command instead, so the CLI says so on stderr before
//! it does anything else. The pin URL points at a closed local port:
//! the run fails at the fetch, after the notice has been printed.
//!
//! Requires the `cli` feature — the wallop-verify binary is only compiled
//! when that feature is active.

#![cfg(feature = "cli")]

use std::io::Write;
use std::process::{Command, Output, Stdio};

use wallop_verifier::_test_support::build_valid_bundle;
use wallop_verifier::Entry;

const NOTICE: &str = "--infra-key-pin replaces the trust anchors built into this binary";

fn bundle() -> String {
    let entries = vec![
        Entry {
            id: "ticket-1".into(),
            weight: 1,
        },
        Entry {
            id: "ticket-2".into(),
            weight: 1,
        },
    ];
    build_valid_bundle(&entries, Some("1013"), 1)
}

fn anchor_record(byte: u8) -> String {
    let public_key = [byte; 32];
    format!(
        r#"{{"key_id":"{}","public_key_hex":"{}","inserted_at":"2026-01-01T00:00:00.000000Z","revoked_at":null}}"#,
        wallop_verifier::key_id(&public_key),
        hex::encode(public_key)
    )
}

fn run(args: &[String]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wallop-verify"))
        .args(args)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // The CLI may exit before reading stdin (argument errors), so a
    // broken pipe here is expected rather than a failure.
    let _ = child.stdin.as_mut().unwrap().write_all(bundle().as_bytes());
    child.wait_with_output().unwrap()
}

fn run_attributable(extra_args: &[String]) -> Output {
    let mut args: Vec<String> = [
        "--mode",
        "attributable",
        "--wallop-base-url",
        "http://127.0.0.1:1",
        "--pin-from-url",
        "http://127.0.0.1:1/operator/acme-prizes/keyring-pin.json",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.extend_from_slice(extra_args);
    run(&args)
}

#[test]
fn override_prints_notice_naming_the_key_count() {
    let output = run_attributable(&[
        "--infra-key-pin".into(),
        anchor_record(7),
        "--infra-key-pin".into(),
        anchor_record(8),
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stderr.contains(NOTICE), "missing notice, got: {stderr}");
    assert!(
        stderr.contains("only the 2 keys you supplied"),
        "notice should name the key count, got: {stderr}"
    );
    // `None < Some(_)`, so this also fails if the fetch error is missing.
    assert!(
        stderr.find(NOTICE) < stderr.find("pin verification failed"),
        "notice must come before the run's own output, got: {stderr}"
    );
}

#[test]
fn single_override_uses_singular() {
    let output = run_attributable(&["--infra-key-pin".into(), anchor_record(7)]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("only the 1 key you supplied"),
        "got: {stderr}"
    );
}

#[test]
fn bundled_anchors_print_no_notice() {
    let output = run_attributable(&[]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!stderr.contains(NOTICE), "unexpected notice, got: {stderr}");
}

#[test]
fn invalid_override_prints_error_not_notice() {
    let output = run_attributable(&["--infra-key-pin".into(), "{}".into()]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("--infra-key-pin #1 is invalid"),
        "got: {stderr}"
    );
    assert!(!stderr.contains(NOTICE), "unexpected notice, got: {stderr}");
}

#[test]
fn duplicate_override_is_rejected() {
    let output = run_attributable(&[
        "--infra-key-pin".into(),
        anchor_record(7),
        "--infra-key-pin".into(),
        anchor_record(7),
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr.contains("--infra-key-pin #2 repeats key_id"),
        "got: {stderr}"
    );
    assert!(!stderr.contains(NOTICE), "unexpected notice, got: {stderr}");
}

#[test]
fn override_outside_attributable_mode_is_rejected() {
    for mode in ["self-consistency", "attestable"] {
        let output = run(&[
            "--mode".into(),
            mode.into(),
            "--wallop-base-url".into(),
            "http://127.0.0.1:1".into(),
            "--infra-key-pin".into(),
            anchor_record(7),
        ]);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert_eq!(output.status.code(), Some(2), "mode {mode}");
        assert!(
            stderr.contains("--infra-key-pin is only used by --mode attributable"),
            "mode {mode}, got: {stderr}"
        );
    }
}
