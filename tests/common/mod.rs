//! Reading wallop_core's shared vectors (`spec/vectors` in the wallop repo)
//! from the integration tests. A vector these tests read is never skipped.
//!
//! Where a vector is read from:
//!
//! 1. An explicit path: the file's own environment variable, where it has
//!    one (for example `WALLOP_TAMPER_VECTORS`), or
//!    `WALLOP_CORE_VECTORS_DIR/<name>`. Point it at a core checkout's
//!    `spec/vectors` to confirm that checkout's vectors. It overrides the
//!    vendored copy, and the test says so on stderr, and says loudly when
//!    the two files differ. A directory that is set but lacks the file
//!    fails the test.
//! 2. Otherwise the vendored copy, `vendor/wallop/spec/vectors/<name>`.
//!
//! **A file missing from the vendored tree always fails the test**, with or
//! without an explicit path: the pinned wallop commit must carry every
//! vector the tests read, so a vendor bump that drops one cannot pass. An
//! explicit path only overrides a vendored copy; it never stands in for a
//! missing one. `V6_VECTORS` lists the lock 6 / execution 5 files, and
//! `core_vectors_gate.rs` checks each one is vendored.
//!
//! There is no "submodule not checked out" case to handle here. In a git
//! checkout `build.rs` stops the build when the vendored vectors are
//! absent, and the library's own unit tests `include_str!` vendored files,
//! so `cargo test` cannot build without them.

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

pub fn vendored_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(VENDORED_DIR)
}

/// Where `name` should be read from, or why it can't be, under the rules
/// in the module doc.
pub fn locate(
    vendored_dir: &Path,
    name: &str,
    file_env: Option<&str>,
    env: impl Fn(&str) -> Option<String>,
) -> Result<PathBuf, String> {
    let explicit = explicit_path(name, file_env, &env)?;
    let vendored = vendored_dir.join(name);
    if !vendored.is_file() {
        return Err(format!(
            "{} is missing: the vendored wallop commit does not carry it, and every vector \
             the tests read must be vendored (an explicit path overrides a vendored copy, \
             never a missing one)",
            vendored.display()
        ));
    }
    Ok(explicit.unwrap_or(vendored))
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

/// The parsed vector `name`. Panics if it is missing, unreadable or not
/// JSON.
pub fn core_vector(name: &str, file_env: Option<&str>) -> serde_json::Value {
    let text = core_vector_text(name, file_env);
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// The text of vector `name`, found by the same rules as `core_vector`,
/// for a file that must be parsed typed rather than as a
/// `serde_json::Value` (for example one whose rows keep each number's JSON
/// text, which a `Value` would read through a float or refuse).
pub fn core_vector_text(name: &str, file_env: Option<&str>) -> String {
    let path = locate(&vendored_dir(), name, file_env, |v| std::env::var(v).ok())
        .unwrap_or_else(|reason| panic!("{reason}"));
    if let Some(note) = override_note(&vendored_dir().join(name), &path) {
        eprintln!("{note}");
    }
    let shown = path.display();
    eprintln!("core vectors: reading {shown}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{shown}: {e}"))
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
