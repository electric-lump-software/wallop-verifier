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

> **Important — attributable authenticity vs self-consistency.** By default, `wallop-verify` validates a bundle against the public keys embedded in the bundle itself. This is *self-consistent* verification: the bytes and signatures agree internally. It is **not** *attributable authenticity*: an attacker serving a forged bundle can sign it with their own keypair and embed that keypair's public half, and every step of the verification pipeline will pass. The stderr warning below is the only sign that attributable authenticity was not checked. Use the `--pin-*` flags below whenever you want to assert "this bundle was signed by the specific party I expected," not just "this bundle's insides are internally consistent."
>
> **Note:** `--pin-from-bundle` is TOFU (trust-on-first-use) self-consistency, not attributable authenticity — it extracts a key from a previously trusted bundle, so it only carries whatever attribution the initial bundle itself carried.
>
> Spec reference: `wallop/spec/protocol.md` §4.2.4 "CLI-without-keyring caveat."

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

## Interactive TUI mode

The TUI adds visual step-by-step inspection to both bundle verification and the selftest catalog. Requires the `tui` feature flag.

### Installation

```bash
cargo install wallop_verifier --features tui
```

### Bundle verification

```bash
# Interactive step-through of a proof bundle
wallop-verify --tui proof.json

# Stdin does NOT work with --tui (the TUI needs a real TTY for keyboard input)
# Save to a file first:
curl -s https://wallop.run/proof/abc123.json > proof.json
wallop-verify --tui proof.json
```

Advance through steps with **space**, or press **c** to reveal all remaining steps at once. Use **arrow keys** to navigate between revealed steps — failed steps auto-expand a byte-level diff showing expected vs computed values.

The footer shows key-pin status: green for pinned and matching, yellow for unpinned, red for mismatch.

Press **q** to quit.

### Selftest scenario browser

```bash
wallop-verify selftest --tui
```

The left panel lists all tamper scenarios. The right panel shows step-by-step verification results for the selected scenario. The selected scenario shows a step heatmap underneath its name.

| Key | Action |
|---|---|
| space | Reveal next step |
| c | Reveal all remaining steps |
| j / k | Switch between scenarios |
| up / down | Navigate revealed steps |
| q | Quit |

### Demo mode

```bash
# Animated playback for presentations
wallop-verify selftest --demo

# Record to asciicast for embedding in docs
wallop-verify selftest --demo --record demo.cast
```

Demo mode runs through all scenarios automatically with animations: a braille ripple on the dots while computing, a character scramble on the PASS/FAIL status text as it resolves, and a completion screen summarising all results. Press **q** at any time to exit.

## Feature flag

All CLI functionality is gated behind the `cli` Cargo feature:

```toml
[dependencies]
wallop_verifier = { version = "0.6", features = ["cli"] }
```

Two feature flags are available:

| Feature | Includes | Install command |
|---|---|---|
| `cli` | Plain CLI: verify, selftest, pin-key | `cargo install wallop_verifier --features cli` |
| `tui` | Everything in `cli` + interactive TUI, demo mode, asciicast export | `cargo install wallop_verifier --features tui` |

Without either feature, the crate compiles as a library only — no binary target, no clap/ratatui/drand-verify dependencies. WASM builds are unaffected.
