//! Reading wallop_core's shared vectors (`spec/vectors` in the wallop repo)
//! from the integration tests, with no silent skips once they are vendored.
//!
//! Where a vector is read from, in order:
//!
//! 1. An explicit path: the file's own environment variable, where it has
//!    one (for example `WALLOP_TAMPER_VECTORS`), or
//!    `WALLOP_CORE_VECTORS_DIR/<name>`. Point it at a core checkout's
//!    `spec/vectors` to confirm that checkout's vectors. It overrides the
//!    vendored copy when both exist, and the test says so on stderr, and
//!    says loudly when the two files differ. A directory that is set but
//!    lacks the file fails the test.
//! 2. The vendored copy, `vendor/wallop/spec/vectors/<name>`.
//! 3. **Hard failure** if that file is missing but the vendored tree holds
//!    any lock 6 / execution 5 vector (`V6_VECTORS`), even with a path set.
//!    Those files come from one core release, so once one is vendored
//!    every one must be: a missing file means an incomplete vendor bump,
//!    and the test fails rather than skipping.
//! 4. Only when the vendored tree has no v6 vector at all and no path is
//!    set does the test skip, saying so on stderr.
//!
//! The gate is decided per test run from the files on disk, not in
//! `build.rs`: `build.rs` also runs for crates that depend on this one,
//! which ship without `vendor/`, and its existing guard only checks that
//! the submodule is checked out.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use wallop_verifier::key_resolver::{
    InsertedAt, KeyClass, KeyResolver, ResolutionError, ResolvedKey,
};

/// The vendored vector directory.
pub const VENDORED_DIR: &str = "vendor/wallop/spec/vectors";

/// The fallback directory variable: a core checkout's `spec/vectors`.
pub const DIR_ENV: &str = "WALLOP_CORE_VECTORS_DIR";

/// Every lock 6 / execution 5 vector the tests read. They are frozen in
/// one core release, so they are vendored together.
pub const V6_VECTORS: &[&str] = &[
    // drand-quicknet+metoffice-landobs-v1 (Land Observations, Middle Wallop).
    "weather-schedule-landobs-v1.json",
    "weather-value-landobs-v1.json",
    "lock-receipt-v6.json",
    "execution-receipt-v5.json",
    "execution-receipt-freq-window-v5.json",
    "execution-receipt-fallback-v5.json",
    "proof-bundle-v6.json",
    "proof-bundle-v6-freq-window.json",
    "proof-bundle-v6-fallback.json",
    "proof-bundle-v6-tamper.json",
    // drand-quicknet+elexon-freq-v1 (grid frequency).
    "proof-bundle-v6-tamper-freq.json",
    "freq-window-v1.json",
    "frequency-schedule-elexon-v1.json",
    "frequency-value-elexon-v1.json",
    "lock-receipt-v6-freq.json",
    "execution-receipt-v5-freq.json",
    "execution-receipt-fallback-v5-freq.json",
    "proof-bundle-v6-freq.json",
    "proof-bundle-v6-freq-fallback.json",
    // Both tags.
    "schedule-boundaries-v1.json",
    "proof-bundle-v6-negative.json",
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
    let explicit = explicit_path(name, file_env, &env)?;
    let vendored = vendored_dir.join(name);
    if vendored.is_file() {
        return Ok(Some(explicit.unwrap_or(vendored)));
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
    Ok(explicit)
}

/// The path set for `name` in the environment, if any: the file's own
/// variable first, then `WALLOP_CORE_VECTORS_DIR/<name>`.
fn explicit_path(
    name: &str,
    file_env: Option<&str>,
    env: &impl Fn(&str) -> Option<String>,
) -> Result<Option<PathBuf>, String> {
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

/// What to say when `chosen` is not the vendored copy at `vendored` but
/// that copy exists: an explicit path overrides it, and whether the two
/// files differ. `None` when there is no vendored copy or it was chosen.
pub fn override_note(vendored: &Path, chosen: &Path) -> Option<String> {
    if chosen == vendored || !vendored.is_file() {
        return None;
    }
    let same = std::fs::read(vendored).ok() == std::fs::read(chosen).ok();
    Some(if same {
        format!(
            "core vectors: {} overrides the vendored {} (identical bytes)",
            chosen.display(),
            vendored.display()
        )
    } else {
        format!(
            "core vectors: WARNING {} DIFFERS from the vendored {}; reading the explicit path",
            chosen.display(),
            vendored.display()
        )
    })
}

/// The parsed vector `name`, or `None` (with a message) only before the v6
/// vectors are vendored and when no path is set. Panics otherwise if the
/// file is missing, unreadable or not JSON.
pub fn core_vector(name: &str, file_env: Option<&str>) -> Option<serde_json::Value> {
    let text = core_vector_text(name, file_env)?;
    Some(serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}")))
}

/// The text of vector `name`, found by the same rules as `core_vector`,
/// for a file that must be parsed typed rather than as a
/// `serde_json::Value` (for example one whose rows keep each number's JSON
/// text, which a `Value` would read through a float or refuse).
pub fn core_vector_text(name: &str, file_env: Option<&str>) -> Option<String> {
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
    if let Some(note) = override_note(&vendored_dir().join(name), &path) {
        eprintln!("{note}");
    }
    let shown = path.display();
    eprintln!("core vectors: reading {shown}");
    Some(std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{shown}: {e}")))
}

/// Resolves from a vector's inline
/// `keys: [{key_id, public_key_hex, key_class, inserted_at}]`.
pub struct ListResolver(Vec<(String, [u8; 32], KeyClass, String)>);

impl KeyResolver for ListResolver {
    fn resolve(&self, key_id: &str, key_class: KeyClass) -> Result<ResolvedKey, ResolutionError> {
        self.0
            .iter()
            .find(|(id, _, class, _)| id == key_id && *class == key_class)
            .map(|(_, pk, class, at)| ResolvedKey {
                public_key: *pk,
                inserted_at: InsertedAt::At(at.clone()),
                key_class: *class,
            })
            .ok_or(ResolutionError::KeyNotFound)
    }
}

/// The resolver for a vector's inline `keys` list.
pub fn resolver(keys: &serde_json::Value) -> ListResolver {
    ListResolver(
        keys.as_array()
            .expect("keys is a list")
            .iter()
            .map(|k| {
                let class = match k["key_class"].as_str().unwrap() {
                    "operator" => KeyClass::Operator,
                    "infrastructure" => KeyClass::Infrastructure,
                    other => panic!("unknown key_class {other}"),
                };
                (
                    k["key_id"].as_str().unwrap().to_string(),
                    hex::decode(k["public_key_hex"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    class,
                    k["inserted_at"].as_str().unwrap().to_string(),
                )
            })
            .collect(),
    )
}
