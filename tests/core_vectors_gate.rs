//! The rules `common::locate` uses to find wallop_core's shared vectors:
//! vendored first, a hard failure for an incomplete vendor, then the
//! fallback paths, and a skip only when nothing is vendored or set.

mod common;

use common::{DIR_ENV, locate};
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
