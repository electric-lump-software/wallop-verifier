# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
