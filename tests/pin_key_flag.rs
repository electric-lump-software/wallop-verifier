//! Integration tests for the --pin-operator-key flag.
//!
//! Requires the `cli` feature — the wallop-verify binary is only compiled
//! when that feature is active.

#![cfg(feature = "cli")]

use std::io::Write;
use std::process::{Command, Stdio};

use wallop_verifier::_test_support::build_valid_bundle;
use wallop_verifier::Entry;

fn generate_test_bundle() -> String {
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

#[test]
fn pin_operator_key_mismatch_rejects_bundle() {
    let bundle = generate_test_bundle();
    let wrong_pin = "00".repeat(32); // 64 hex chars, clearly wrong

    let mut child = Command::new(env!("CARGO_BIN_EXE_wallop-verify"))
        .arg("--pin-operator-key")
        .arg(&wrong_pin)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(bundle.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        !output.status.success(),
        "pin mismatch must reject the bundle"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("KEY PIN MISMATCH") || stderr.contains("pin"),
        "output should explain the pin mismatch, got: {stderr}"
    );
}

#[test]
fn pin_operator_key_match_proceeds_normally() {
    let bundle_json = generate_test_bundle();

    // Extract the actual operator key from the bundle
    let bundle_val: serde_json::Value = serde_json::from_str(&bundle_json).unwrap();
    let actual_key = bundle_val["lock_receipt"]["operator_public_key_hex"]
        .as_str()
        .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_wallop-verify"))
        .arg("--pin-operator-key")
        .arg(actual_key)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(bundle_json.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    // With matching pin, verification should proceed and eventually report
    // steps. BLS will fail (test uses fake drand sig) but the pin check
    // itself should pass.
    assert!(
        stdout.contains("wallop-verify"),
        "output should contain the version header, got: {stdout}"
    );
    // Should NOT contain pin mismatch error
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("KEY PIN MISMATCH"),
        "matching pin should not trigger mismatch: {stderr}"
    );
}

#[test]
fn no_pin_prints_warning() {
    let bundle_json = generate_test_bundle();

    let mut child = Command::new(env!("CARGO_BIN_EXE_wallop-verify"))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(bundle_json.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No --pin-operator-key supplied"),
        "should warn about missing pin, got: {stderr}"
    );
}
