//! Reading wallop_core's shared vectors (`spec/vectors` in the wallop repo)
//! from the integration tests, with no silent skips once they are vendored.
//!
//! Where a vector is read from, in order:
//!
//! 1. The vendored copy, `vendor/wallop/spec/vectors/<name>`.
//! 2. **Hard failure** if that file is missing but the vendored tree holds
//!    any lock 6 / execution 5 vector (`V6_VECTORS`). Those files come from
//!    one core release, so once one is vendored every one must be: a
//!    missing file means an incomplete vendor bump, and the test fails
//!    rather than skipping.
//! 3. The file's own environment variable, where it has one (for example
//!    `WALLOP_TAMPER_VECTORS`), or `WALLOP_CORE_VECTORS_DIR/<name>`. This is
//!    the documented fallback before the v6 vectors are vendored: point it
//!    at a core checkout's `spec/vectors`. A path that is set but can't be
//!    read fails the test.
//! 4. Only when the vendored tree has no v6 vector at all and no path is
//!    set does the test skip, saying so on stderr.
//!
//! The gate is decided per test run from the files on disk, not in
//! `build.rs`: `build.rs` also runs for crates that depend on this one,
//! which ship without `vendor/`, and its existing guard only checks that
//! the submodule is checked out.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// The vendored vector directory.
pub const VENDORED_DIR: &str = "vendor/wallop/spec/vectors";

/// The fallback directory variable: a core checkout's `spec/vectors`.
pub const DIR_ENV: &str = "WALLOP_CORE_VECTORS_DIR";

/// Every lock 6 / execution 5 vector the tests read. They are frozen in
/// one core release, so they are vendored together.
pub const V6_VECTORS: &[&str] = &[
    "proof-bundle-v6-tamper.json",
    "proof-bundle-v6-tamper-freq.json",
    "freq-window-v1.json",
    "frequency-schedule-elexon-v1.json",
    "frequency-value-elexon-v1.json",
    "lock-receipt-v6-freq.json",
    "execution-receipt-v5-freq.json",
    "execution-receipt-fallback-v5-freq.json",
    "proof-bundle-v6-freq.json",
    "proof-bundle-v6-freq-fallback.json",
    "schedule-boundaries-v1.json",
];

fn vendored_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(VENDORED_DIR)
}

/// Where `name` should be read from, or why it can't be, under the rules
/// in the module doc. `Ok(None)` is the pre-vendoring skip.
pub fn locate(
    vendored_dir: &Path,
    name: &str,
    file_env: Option<&str>,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Option<PathBuf>, String> {
    let vendored = vendored_dir.join(name);
    if vendored.is_file() {
        return Ok(Some(vendored));
    }
    let present: Vec<&str> = V6_VECTORS
        .iter()
        .copied()
        .filter(|f| vendored_dir.join(f).is_file())
        .collect();
    if !present.is_empty() {
        return Err(format!(
            "{} is missing, but the vendored vectors include {present:?}: the vendored \
             wallop commit is incomplete (vector files from one release are vendored together)",
            vendored.display()
        ));
    }
    if let Some(var) = file_env
        && let Some(path) = env(var)
    {
        return Ok(Some(path.into()));
    }
    if let Some(dir) = env(DIR_ENV) {
        let path = Path::new(&dir).join(name);
        if !path.is_file() {
            return Err(format!("{DIR_ENV}={dir} is set, but it has no {name}"));
        }
        return Ok(Some(path));
    }
    Ok(None)
}

/// The parsed vector `name`, or `None` (with a message) only before the v6
/// vectors are vendored and when no path is set. Panics otherwise if the
/// file is missing or unreadable.
pub fn core_vector(name: &str, file_env: Option<&str>) -> Option<serde_json::Value> {
    let path = match locate(&vendored_dir(), name, file_env, |v| std::env::var(v).ok()) {
        Ok(Some(path)) => path,
        Ok(None) => {
            let how = file_env.map_or_else(
                || format!("set {DIR_ENV} to a wallop checkout's spec/vectors"),
                |v| {
                    format!("set {v} to its path, or {DIR_ENV} to a wallop checkout's spec/vectors")
                },
            );
            eprintln!(
                "skipping: {name} is not vendored yet (no v6 vectors under {VENDORED_DIR}); {how} to run"
            );
            return None;
        }
        Err(reason) => panic!("{reason}"),
    };
    let shown = path.display();
    eprintln!("core vectors: reading {shown}");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{shown}: {e}"));
    Some(serde_json::from_str(&text).unwrap_or_else(|e| panic!("{shown}: {e}")))
}
