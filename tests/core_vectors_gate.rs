//! The rules `common::locate` uses to find wallop_core's shared vectors:
//! an explicit path first, then the vendored copy, and a hard failure,
//! never a skip, for any file missing from the vendored tree.

mod common;

use common::{DIR_ENV, locate, override_note};
use std::path::PathBuf;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wallop-vector-gate-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn no_env(_: &str) -> Option<String> {
    None
}

#[test]
fn a_vendored_file_is_read_and_a_missing_one_fails() {
    let dir = scratch("vendored");
    std::fs::write(dir.join("freq-window-v1.json"), "{}").unwrap();
    assert_eq!(
        locate(&dir, "freq-window-v1.json", None, no_env),
        Ok(dir.join("freq-window-v1.json"))
    );
    // A file the vendored tree lacks fails, with nothing set...
    let err = locate(&dir, "lock-receipt-v6-freq.json", None, no_env).unwrap_err();
    assert!(err.contains("is missing"), "{err}");
    // ...and even when an explicit path has it: an override never stands
    // in for a missing vendored file.
    let core = scratch("has-it");
    std::fs::write(core.join("lock-receipt-v6-freq.json"), "{}").unwrap();
    let core_s = core.to_string_lossy().into_owned();
    let err = locate(&dir, "lock-receipt-v6-freq.json", None, |v| {
        (v == DIR_ENV).then(|| core_s.clone())
    })
    .unwrap_err();
    assert!(err.contains("is missing"), "{err}");
    let given = core.join("lock-receipt-v6-freq.json");
    let given = given.to_string_lossy().into_owned();
    let err = locate(&dir, "lock-receipt-v6-freq.json", Some("X"), |v| {
        (v == "X").then(|| given.clone())
    })
    .unwrap_err();
    assert!(err.contains("is missing"), "{err}");
    // A vendored tree with no files at all fails too: there is no skip.
    let empty = scratch("empty");
    assert!(locate(&empty, "freq-window-v1.json", None, no_env).is_err());
}

#[test]
fn a_set_directory_without_the_file_fails() {
    let dir = scratch("vendored-for-dir");
    std::fs::write(dir.join("lock-receipt-v6-freq.json"), "{}").unwrap();
    let core = scratch("core-without");
    let core_s = core.to_string_lossy().into_owned();
    let err = locate(&dir, "lock-receipt-v6-freq.json", None, |v| {
        (v == DIR_ENV).then(|| core_s.clone())
    })
    .unwrap_err();
    assert!(err.contains("has no lock-receipt-v6-freq.json"), "{err}");
}

#[test]
#[should_panic(expected = "is missing")]
fn the_reader_fails_on_a_vector_the_vendored_tree_lacks() {
    common::core_vector("no-such-vector.json", None);
}

#[test]
fn every_v6_vector_is_vendored() {
    let dir = common::vendored_dir();
    let missing: Vec<&str> = common::V6_VECTORS
        .iter()
        .copied()
        .filter(|f| !dir.join(f).is_file())
        .collect();
    assert!(
        missing.is_empty(),
        "missing from {}: {missing:?}",
        dir.display()
    );
}

#[test]
fn an_explicit_path_overrides_the_vendored_copy_and_says_if_they_differ() {
    let dir = scratch("override-vendored");
    let name = "proof-bundle-v6-tamper.json";
    std::fs::write(dir.join(name), "{\"old\":1}").unwrap();
    let core = scratch("override-core");
    std::fs::write(core.join(name), "{\"new\":1}").unwrap();
    let core_s = core.to_string_lossy().into_owned();

    // The directory variable wins over the vendored file.
    let got = locate(&dir, name, Some("X"), |v| {
        (v == DIR_ENV).then(|| core_s.clone())
    });
    assert_eq!(got, Ok(core.join(name)));
    // So does the file's own variable.
    let given = core.join(name).to_string_lossy().into_owned();
    let got = locate(&dir, name, Some("X"), |v| (v == "X").then(|| given.clone()));
    assert_eq!(got, Ok(core.join(name)));
    // With nothing set, the vendored file.
    assert_eq!(locate(&dir, name, Some("X"), no_env), Ok(dir.join(name)));

    let note = override_note(&dir.join(name), &core.join(name)).unwrap();
    assert!(note.contains("DIFFERS"), "{note}");
    std::fs::write(core.join(name), "{\"old\":1}").unwrap();
    let note = override_note(&dir.join(name), &core.join(name)).unwrap();
    assert!(note.contains("identical"), "{note}");
    assert_eq!(override_note(&dir.join(name), &dir.join(name)), None);
    assert_eq!(
        override_note(&core.join("absent.json"), &core.join(name)),
        None
    );
}
