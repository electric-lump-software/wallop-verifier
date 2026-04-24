# Fuzz harnesses for wallop_verifier

Coverage-guided fuzzing via [`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html) for the three highest-value attack surfaces named in the round 2 vulnerability audit (V-19):

| Target | Function under test | Pass criteria |
|--------|---------------------|---------------|
| `fuzz_parse_execution_receipt` | `parse_execution_receipt(&str)` | Never panics; every invalid input returns `Err(_)`. |
| `fuzz_bundle_parse` | `ProofBundle::from_json(&str)` | Never panics; every invalid input returns `Err(_)`. |
| `fuzz_verify_full` | `verify_full(…)` full pipeline | Never panics; never returns `Ok(true)` on garbage input. |

A panic is a **P1** finding (can crash a consumer looping over untrusted input). An `Ok(true)` false-positive in `fuzz_verify_full` is a **P0** finding (would mean the verifier accepts a bundle that didn't actually verify — the worst possible verifier bug).

## One-time setup

```bash
cargo install cargo-fuzz
```

`cargo-fuzz` requires a nightly toolchain for the libFuzzer runtime (`cargo +nightly fuzz run <target>` below). `rustup toolchain install nightly` if needed.

## Running a single target

Bounded 8-hour run (recommended for an overnight pass):

```bash
cargo +nightly fuzz run fuzz_parse_execution_receipt -- -max_total_time=28800
```

Unbounded (will run forever; Ctrl+C to stop):

```bash
cargo +nightly fuzz run fuzz_parse_execution_receipt
```

Very short smoke test to confirm the harness is wired up:

```bash
cargo +nightly fuzz run fuzz_parse_execution_receipt -- -max_total_time=30
```

## Running all three overnight

```bash
cargo +nightly fuzz run fuzz_parse_execution_receipt -- -max_total_time=28800 &
cargo +nightly fuzz run fuzz_bundle_parse             -- -max_total_time=28800 &
cargo +nightly fuzz run fuzz_verify_full              -- -max_total_time=28800 &
wait
```

Run them serially if memory pressure is a concern. Each libFuzzer process is single-threaded by default but uses a lot of RAM for the coverage map.

## What to look for the next morning

The fuzzer writes to `fuzz/corpus/<target>/` (accepted inputs that expanded coverage) and `fuzz/artifacts/<target>/` (any crashing input it found). Both directories are gitignored.

- **`artifacts/<target>/crash-*`** — a crashing input. Inspect it, minimise with `cargo +nightly fuzz cmin <target>`, and open an issue with the reproducer bytes attached.
- **`corpus/<target>/` growth** — a healthy fuzz run grows the corpus continuously. If it plateaus immediately, the harness probably isn't exposing enough coverage; widen the target.

## Triage categories

1. **Panic** (`artifacts/*/crash-*`) → fix in a PR, add the crashing input as a regression test.
2. **Legitimate reject that took the fuzzer too long to discover** → widen the harness to reject earlier, or add a quick-reject path in the parser.
3. **`Ok(true)` false-positive on `fuzz_verify_full`** → P0, stop-the-line. File immediately with the minimised reproducer.
4. **Coverage never reaches a known branch** → not a finding itself, but add a hand-crafted seed input to `corpus/<target>/` to bootstrap coverage.

## Updating when the protocol changes

When a new schema version or verification step lands, add:

- Seed corpus inputs under `fuzz/corpus/<target>/` covering the new shape (valid and near-valid examples).
- A new fuzz target if the new surface has its own parser / validator.
