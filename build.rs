use std::path::Path;

fn main() {
    let vectors_dir = Path::new("vendor/wallop/spec/vectors");

    // The submodule is only needed for the test suite (all include_str! of
    // vendor files live inside #[cfg(test)] modules). Published crates ship
    // without vendor/ via `exclude = ["vendor/"]` in Cargo.toml, so consumer
    // builds must not panic when it's absent. We gate the dev-time hint on
    // `.git` existence so contributors in a fresh clone still get a clear
    // "run git submodule update --init" message.
    if !vectors_dir.join("entry-hash.json").exists() && Path::new(".git").exists() {
        panic!(
            "\n\n\
            Shared test vectors not found at vendor/wallop/spec/vectors/.\n\
            Run: git submodule update --init\n\n"
        );
    }

    println!("cargo:rerun-if-changed=vendor/wallop/spec/vectors/");
}
