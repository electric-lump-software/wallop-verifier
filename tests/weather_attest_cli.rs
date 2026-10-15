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
