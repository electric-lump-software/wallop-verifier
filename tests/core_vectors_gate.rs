//! The rules `common::locate` uses to find wallop_core's shared vectors:
//! an explicit path first, then the vendored copy, a hard failure for an
//! incomplete vendor, and a skip only when nothing is vendored or set.

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
fn vendored_files_are_read_and_an_incomplete_vendor_fails() {
    let dir = scratch("vendored");
    std::fs::write(dir.join("freq-window-v1.json"), "{}").unwrap();
    assert_eq!(
        locate(&dir, "freq-window-v1.json", None, no_env),
        Ok(Some(dir.join("freq-window-v1.json")))
    );
    // Another v6 file is missing: a hard failure, even with a path set.
    let err = locate(&dir, "proof-bundle-v6-tamper-freq.json", Some("X"), |_| {
        Some("/elsewhere".into())
    })
    .unwrap_err();
    assert!(err.contains("incomplete"), "{err}");
}

#[test]
fn before_vendoring_the_paths_are_the_fallback_and_only_no_path_skips() {
    let dir = scratch("empty");
    assert_eq!(locate(&dir, "freq-window-v1.json", None, no_env), Ok(None));
    assert_eq!(
        locate(&dir, "freq-window-v1.json", Some("X"), |v| (v == "X")
            .then(|| "/given".into())),
        Ok(Some(PathBuf::from("/given")))
    );
    let core = scratch("core");
    std::fs::write(core.join("freq-window-v1.json"), "{}").unwrap();
    let core_s = core.to_string_lossy().into_owned();
    assert_eq!(
        locate(&dir, "freq-window-v1.json", None, |v| (v == DIR_ENV)
            .then(|| core_s.clone())),
        Ok(Some(core.join("freq-window-v1.json")))
    );
    // The directory is set but lacks the file: a hard failure.
    let err = locate(&dir, "lock-receipt-v6-freq.json", None, |v| {
        (v == DIR_ENV).then(|| core_s.clone())
    })
    .unwrap_err();
    assert!(err.contains("has no lock-receipt-v6-freq.json"), "{err}");
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
    assert_eq!(got, Ok(Some(core.join(name))));
    // So does the file's own variable.
    let given = core.join(name).to_string_lossy().into_owned();
    let got = locate(&dir, name, Some("X"), |v| (v == "X").then(|| given.clone()));
    assert_eq!(got, Ok(Some(core.join(name))));
    // With nothing set, the vendored file.
    assert_eq!(
        locate(&dir, name, Some("X"), no_env),
        Ok(Some(dir.join(name)))
    );

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
