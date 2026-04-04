# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
