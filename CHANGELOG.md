# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.1] - 2026-04-14

### Added

- Demo mode visual polish: braille ripple animation on dots, status text
  scramble effect, step heatmap under selected scenario, victory ripple
  on all-pass completion.
- Demo completion screen: lists all scenarios with CAUGHT/MISSED status,
  per-scenario heatmaps, and a clear verdict summary.
- `--record <PATH>` flag for `selftest --demo`: writes an asciicast v2
  file for embedding in docs and READMEs.
- Tamper mutation spec shown in the TUI step panel header (e.g.
  `byte_flip lock_receipt.signature_hex offset 5`).

### Fixed

- Demo mode scenario pass/fail logic was inverted — step failures now
  correctly indicate the verifier caught the tamper (scenario pass).
- BLS step preserves real FAIL result for the drand tamper scenario
  instead of blanket SKIP across all scenarios.
- Last scenario in demo mode now properly marked before completion
  screen renders.

### Changed

- Release artifact renamed from `wallop-rs-wasm` to `wallop-verifier-wasm`.

## [0.6.0] - 2026-04-12

### Added

- Interactive TUI mode (`--tui` flag) for step-by-step verification inspection
  of proof bundles and the selftest tamper catalog. Requires the new `tui`
  feature flag (`ratatui` + `crossterm`). Plain CLI and WASM builds unaffected.
- Selftest scenario browser: selectable list with per-scenario verification
  results, j/k navigation, pass/fail counter.
- Demo sub-mode (`selftest --demo`): scripted animated playback of the tamper
  catalog with timed step reveals. Holds on summary screen until q is pressed.
- Byte-level hex diff on verification failures via `StepDetail::HexMismatch`
  on `StepResult`. Shows expected vs computed values inline for entry hash,
  receipt linkage, and seed recomputation mismatches.
- Key-pinning visualization in TUI footer: shows pin match/mismatch/unpinned
  status per key. Selftest mode shows dim "test" indicators to avoid false
  alarm fatigue.
- `tui` feature flag: `tui = ["cli", "dep:ratatui", "dep:crossterm"]`.
  Install with `cargo install wallop_verifier --features tui`.

### Changed

- `StepResult` gains a `pub detail: Option<StepDetail>` field. Existing code
  that constructs `StepResult` directly will need to add `detail: None`.
- `StepResult`, `StepStatus`, and `StepDetail` now implement `Clone`.
- `CatalogReport` results now include scenario descriptions.

## [0.5.0] - 2026-04-12

### Added

- `wallop-verify` CLI binary behind the `cli` feature flag for verifying
  Wallop! proof bundles end-to-end. Reads from a file path or `-` for stdin.
- `wallop-verify selftest` subcommand — runs a built-in tamper scenario
  catalog against a freshly-generated known-good bundle and confirms every
  scenario is caught by the expected verification step. Designed for CI and
  auditor pre-flight. Exit codes: 0=clean, 1=P0 failure, 2=wrong-step or
  incomplete coverage, 3=catalog load error.
- `--pin-operator-key`, `--pin-infra-key`, `--pin-operator-key-file`, and
  `--pin-from-bundle` flags for explicit out-of-band trust anchors. Warns
  when no pin is supplied.
- `StepName` enum — stable, always-public identifier for each of the 9
  verification steps. Serde snake_case serialization for catalog references,
  Display for human-friendly CLI output.
- Step-by-step verification pipeline (`verify_steps::verify_bundle`) with
  per-step PASS/FAIL/SKIP reporting and a belt-and-suspenders `verify_full()`
  drift guard.
- Drand BLS signature verification with pinned quicknet chain keys (behind
  `cli` feature).
- Tamper scenario catalog infrastructure: versioned JSON schema, field-level
  and semantic-level mutation dispatch, deterministic test-keypair derivation
  (SHA-256 seed → Ed25519), per-step runtime coverage tracking.
- CLI reference documentation at `docs/cli.md`.

### Changed

- `verify_full` now also checks that the `entry_hash` recorded inside the
  signed lock receipt matches the recomputed hash from the entries. Bundles
  with a tampered lock-receipt `entry_hash` that passed in 0.4.x will now
  fail — this closes a soundness gap.
- `StepResult.name` changed from `&'static str` to `StepName` enum. Library
  consumers pattern-matching on `step.name` should use enum variants instead
  of string comparisons.

## [0.4.0] - 2026-04-11

### Changed

- **Renamed crate from `wallop_rs` to `wallop_verifier`.** The old name implied
  a full Rust port of the Wallop! server; this crate only mirrors the protocol
  primitives (entry_hash, compute_seed, draw, receipt verification) plus WASM
  bindings. The new name matches the `wallop-verify` CLI and makes the crate's
  role as an independent second-language verifier obvious.
- GitHub repository renamed from `wallop_rs` to `wallop-verifier`. The old URL
  still redirects.

### Migration

Rename your dependency from `wallop_rs = "0.3"` to `wallop_verifier = "0.4"`.
Rust source identifiers (struct/function/module names) are unchanged, so a
blanket find-and-replace of `wallop_rs` → `wallop_verifier` in `use` statements
and WASM import paths is sufficient. Old `wallop_rs` versions on crates.io
have been yanked; existing `Cargo.lock` files still resolve.

## [0.3.0] - 2026-04-10

### Changed

- **Breaking:** `verify_full` and `verify_full_wasm` no longer accept a `count` parameter — `winner_count` is extracted from the signed lock receipt payload instead of trusting the caller
- `compute_seed` and `compute_seed_drand_only` use `BTreeMap` + `serde_json` instead of manual `format!()` for JCS construction
- Test suite loads frozen vectors from shared JSON files via git submodule (`vendor/wallop/spec/vectors/`)

### Fixed

- `verify_full` now rejects non-string elements in the execution receipt `results` array instead of silently dropping them

### Added

- `build.rs` guard with helpful error message when submodule is not initialised
- New test vectors: `entry_hash_weighted`, `entry_hash_single`

## [0.2.0] - 2026-04-09

### Added

- Full protocol parity with wallop_core 0.14.x
- Lock receipt v2 payload builder (16 fields, schema_version "2")
- Execution receipt v1 payload builder (20 fields, execution_schema_version "1")
- Ed25519 signature verification (`verify_receipt`)
- Key fingerprint derivation (`key_id`)
- RFC 6962 Merkle tree (`merkle_root`)
- Dual sub-tree anchor root (`anchor_root`)
- Cross-receipt linkage verification (`lock_receipt_hash`)
- `verify_full` — end-to-end verification pipeline with signature checks
- WASM bindings for all new functions

## [0.1.1] - 2026-04-04

### Changed

- Release workflow uses `--release` flag for optimised WASM builds

## [0.1.0] - 2026-04-04

### Added

- `entry_hash()` — SHA-256 of JCS-canonical entry list
- `compute_seed()` — seed derivation from entry hash, drand randomness, and weather value
- `compute_seed_drand_only()` — seed derivation without weather (domain-separated)
- `verify()` — full pipeline verification (entry_hash → compute_seed → draw → compare)
- WASM bindings for all public functions via wasm-bindgen
- Test vectors P-1, P-2, P-3 matching the reference implementation
