# wallop-verify CLI Reference

Command-line tool for verifying Wallop! proof bundles and running the built-in tamper scenario catalog. Part of the [`wallop_verifier`](https://crates.io/crates/wallop_verifier) crate, behind the `cli` feature flag.

## Installation

```bash
cargo install wallop_verifier --features cli
```

This installs the `wallop-verify` binary. The library crate is not affected — consumers who only use the protocol types (`entry_hash`, `compute_seed`, `verify_full`, etc.) don't need the `cli` feature and don't pay the binary-size cost.

## Verifying a proof bundle

```bash
# From a file
wallop-verify proof.json

# From stdin
curl -s https://example.com/proof/abc123.json | wallop-verify -
```

The verifier runs 9 steps in order:

1. **Entry hash** — recompute the SHA-256 hash of the canonicalised entry list
2. **Lock receipt signature** — verify the Ed25519 signature on the lock receipt
3. **Exec receipt signature** — verify the Ed25519 signature on the execution receipt
4. **Receipt linkage** — confirm `lock_receipt_hash` in the exec receipt matches the computed hash of the lock receipt
5. **Entry hash (lock receipt)** — confirm the lock receipt's `entry_hash` matches the computed value
6. **Entry hash (exec receipt)** — confirm the exec receipt's `entry_hash` matches the computed value
7. **Seed recomputation** — recompute the seed from `entry_hash` + `drand_randomness` (+ optional `weather_value`) and compare against the exec receipt's `seed`
8. **Winner selection** — re-run the draw algorithm with the recomputed seed and compare against the exec receipt's `results`
9. **Drand BLS signature** — verify the drand round's BLS signature against the pinned quicknet chain keys

Each step reports PASS, FAIL (with reason), or SKIP (when an upstream step failed).

## Trust anchors (`--pin-key`)

By default, the verifier trusts the public keys embedded in the bundle. If an attacker controls the bundle, they can substitute a different valid key paired with a forged signature — the bundle would verify against the wrong key.

Pin a trusted key to close this attack:

```bash
# Pin the operator's public key (obtained out of band)
wallop-verify --pin-operator-key=a1b2c3...64chars proof.json

# Pin the infrastructure signing key
wallop-verify --pin-infra-key=d4e5f6...64chars proof.json

# Read the pin from a file
wallop-verify --pin-operator-key-file=operator.pub proof.json

# TOFU: extract the key from a previously trusted bundle
wallop-verify --pin-from-bundle=trusted.json proof.json
```

**Without a pin**, the verifier prints a warning to stderr:

```
warning: No --pin-operator-key supplied. Trusting embedded public key. If you
  do not control the bundle source, obtain the operator's key out of band
  and re-run with --pin-operator-key.
```

**With a mismatching pin**, verification fails immediately:

```
KEY PIN MISMATCH (operator)
  Embedded key: a1b2c3...
  Pinned key:   ffffff...
This bundle was signed with a key you do not trust.
```

## Self-test (`wallop-verify selftest`)

The verifier ships with a built-in tamper scenario catalog — a set of known attacks, each declaring which verification step must catch it. The `selftest` subcommand runs every scenario and confirms the verifier catches what it claims to catch.

```bash
wallop-verify selftest
```

Example output:

```
wallop-verify 0.5.0 selftest

Running 9 tamper scenarios...

PASS: lock_signature_byte_flip caught at Lock receipt signature
PASS: exec_signature_byte_flip caught at Exec receipt signature
PASS: entry_set_add_entry caught at Entry hash
...

Coverage check: 9/9 StepName variants covered at runtime
9 scenarios run, 9 passed, 0 P0 failures, 0 caught by wrong step, 0 skipped
```

### What selftest proves

- Every known attack in the catalog is caught by the declared verification step
- Every verification step has at least one scenario that exercises it at runtime (not just declared — "declarations rot, runtime assertions don't")
- The binary you downloaded actually works

### When to run it

- **CI**: add `wallop-verify selftest` to your pipeline. Block releases if it fails.
- **Auditors**: run selftest first, before verifying any real bundle, to confirm the tool you have is trustworthy.
- **After updates**: run selftest after upgrading to a new version to confirm nothing regressed.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | All scenarios caught at the expected step; every step variant covered at runtime |
| 1 | At least one scenario passed when it should have been caught (**P0 finding**) |
| 2 | At least one scenario caught by an unexpected step, or coverage is incomplete |
| 3 | Catalog failed to load (version mismatch, malformed scenario file) |

### Output format

Each scenario result is prefixed with `PASS:`, `FAIL:`, or `SKIP:` on its own line. This prefix is a stable CI contract — you can `grep '^FAIL:'` reliably.

## Feature flag

All CLI functionality is gated behind the `cli` Cargo feature:

```toml
[dependencies]
wallop_verifier = { version = "0.5", features = ["cli"] }
```

Without the feature, the crate compiles as a library only — no binary target, no clap/drand-verify dependencies, no catalog code. WASM builds are unaffected.
