# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - unreleased

### Added

Dual v2+v3 execution receipt support. Matches `wallop_core` 0.17.0's
F2 closure — the execution receipt now commits `signing_key_id` for
the wallop infrastructure key.

- `ExecutionReceiptV3` struct — v2 fields plus required
  `signing_key_id`. `schema_version` is `"3"`.
- `build_execution_receipt_payload_v3` — canonical JCS builder for v3.
- `validate_execution_receipt_tags_v3` — tag validation for v3.
- `parse_execution_receipt(payload_jcs)` dispatcher — reads
  `schema_version`, routes to the V2 or V3 parser, and returns
  `Err(ParseExecutionReceiptError::UnknownSchemaVersion(v))` on any
  other value. Terminal: no retryable variant exists in the error
  enum.
- `ParsedExecutionReceipt` enum (V2 | V3) and
  `ParseExecutionReceiptError` enum with `Display` +
  `std::error::Error` impls.

### Hardening

- `#[serde(deny_unknown_fields)]` on both `ExecutionReceiptV2` and
  `ExecutionReceiptV3`. A v3 payload relabelled as schema `"2"` fails
  V2 deserialisation (unknown `signing_key_id` field). A v2 payload
  relabelled as `"3"` fails V3 deserialisation (missing required
  `signing_key_id`). Closes the downgrade and upgrade-spoof relabel
  attacks by construction.
- New v3 frozen vectors (`execution-receipt-v3.json`,
  `execution-receipt-drand-only-v3.json`) vendored via the
  `spec/vectors/` submodule. v2 vectors preserved byte-identically
  for historical-verification coverage.

### Compatibility

- v0.16.x-era v2 receipts continue to verify byte-identically.
- No changes to lock receipt parsing, transparency anchor
  construction, drand BLS verification, `entry_hash`,
  `compute_seed`, or the `verify_full` pipeline.

### Docs

- `README.md` updated: `entry_hash` / `verify` signatures include
  `draw_id`; JSON examples use `{uuid, weight}`; the Functions
  section covers the full verifier surface (dispatcher, `verify_full`,
  tag validators, ed25519 dependency).

## [0.8.0] - unreleased

### BREAKING

Receipt shape v4 (lock) / v2 (execution). Matches `wallop_core` 0.16.0
receipt hardening pass.

- `LockReceiptV3` → `LockReceiptV4`. `schema_version` bumps `"3"` → `"4"`.
  Adds three algorithm identity tags inside the signed payload:
  `jcs_version: "sha256-jcs-v1"`, `signature_algorithm: "ed25519"`,
  `entropy_composition: "drand-quicknet+openmeteo-v1"`.
- `ExecutionReceiptV1` → `ExecutionReceiptV2`. Key
  `"execution_schema_version"` renamed to `"schema_version"` and bumped
  `"1"` → `"2"`. Adds the three tags above plus
  `drand_signature_algorithm: "bls12_381_g2"` and
  `merkle_algorithm: "sha256-pairwise-v1"`.
- `weather_fallback_reason` is a frozen enum: `"station_down"`,
  `"stale"`, `"unreachable"`, or null. Verifier rejects unknown values.
  Upstream classifies raw weather-client errors into these four before
  writing to the receipt; a fifth value requires a schema bump.
- New `validate_lock_receipt_tags` / `validate_execution_receipt_tags`
  helpers that reject unknown schema versions and tag values.
- Frozen vectors regenerated: `lock-receipt.json`,
  `execution-receipt.json`, `execution-receipt-drand-only.json`,
  `cross-receipt-linkage.json`, `proof-bundle.json`,
  `proof-bundle-drand-only.json`.

Unchanged (zero-drift proof, byte-identical to v0.7.0):
`entry-hash.json`, `compute-seed.json`, `fair-pick.json`,
`merkle-root.json`, `ed25519.json`, `key-id.json`, `anchor-root.json`.

Verifiers pinned to v0.7.0 continue to verify historical receipts;
new receipts require v0.8.0+ to parse.

## [0.7.0] - unreleased

### BREAKING

Entry identifier refactor. Matches `wallop_core` 0.15.0.

- `entry_hash` signature changes from `entry_hash(entries)` to
  `entry_hash(draw_id, entries)`. `draw_id` is bound into the hash to
  prevent cross-draw confusion.
- Canonical form is now
  `SHA-256(JCS({draw_id, entries: [{uuid, weight} sorted by uuid]}))`.
  `operator_ref` is an operator-private sidecar on the upstream
  resource and is deliberately NOT committed in the hash — the
  canonical form must be reproducible from the public proof bundle
  alone. This fixes a verification gap where a v0.6.x verifier
  reading a bundle with non-null `operator_ref` values would silently
  fail to reproduce the committed hash.
- `BundleEntry.id` renamed to `BundleEntry.uuid`. Proof bundles now
  emit `{"uuid": "...", "weight": N}` per entry (not `{"id", ...}`).
- `LockReceiptV2` renamed to `LockReceiptV3`. `schema_version` in the
  signed lock receipt payload bumps `"2"` → `"3"`. Verifiers reject
  unknown `schema_version` values rather than attempting to
  reconstruct an older shape.
- `verify()` gains a `draw_id` first parameter.
- `verify_wasm()` gains a `draw_id` first parameter.
- `entry_hash_wasm()` gains a `draw_id` first parameter.
- `verify_full()` and `verify_full_wasm()` signatures unchanged —
  `draw_id` is extracted from the signed lock receipt internally.

### Notes

- The `Entry { id, weight }` shape from `fair_pick_rs` is unchanged.
  Where callers previously used `id` as an operator-supplied string,
  they now pass the wallop-assigned UUID. Semantics shift; the
  struct stays.
- The 2^53-1 weight boundary vector from the shared test vectors is
  not representable under `Entry::weight: u32`; its frozen
  `expected_hash` is cross-checked at the JCS-byte level instead of
  round-tripping through `entry_hash()`/`Entry`. Documented inline.

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
