# wallop_verifier

Protocol functions and verifier for the [Wallop!](https://wallop.run) provably fair draw system.

Wallop runs verifiably fair random draws where nobody controls the outcome. Entries are locked before the draw. The seed comes from public entropy — a [drand](https://drand.love) beacon and a live weather observation from Middle Wallop, Hampshire. The algorithm is open source and deterministic. Anyone can re-run it and verify the result.

This crate implements the cryptographic pipeline that ties it all together:

- Canonical entry serialisation (JCS + SHA-256), bound to the `draw_id`
- Seed derivation from drand randomness and an optional weather observation
- Full end-to-end verification against published proof bundles
- Lock receipt and execution receipt parsers (schema v4 and v2/v3 respectively), with exact-field-set schema enforcement and terminal rejection of unknown versions
- Ed25519 receipt signature verification and cross-receipt linkage checks
- WASM bindings for [in-browser verification](https://wallop.run/how-verification-works) via [wasm-bindgen](https://github.com/rustwasm/wasm-bindgen)

The draw algorithm itself lives in [`fair_pick_rs`](https://github.com/electric-lump-software/fair_pick_rs); this crate wraps it with the protocol layer. When you click "Verify independently" on a Wallop proof page, this is the code running in your browser — every check, every signature, no server round-trip.

---

## Getting started

```bash
git clone --recursive https://github.com/electric-lump-software/wallop-verifier.git
cd wallop-verifier
cargo test
```

If you've already cloned without `--recursive`:

```bash
git submodule update --init
```

This fetches the shared test vectors from the [wallop](https://github.com/electric-lump-software/wallop) repo. The build will tell you if they're missing.

---

## CLI verifier

A `wallop-verify` command-line binary is available behind the `cli` feature flag for verifying proof bundles, pinning trusted keys, and running the built-in tamper scenario self-test.

```bash
cargo install wallop_verifier --features cli
wallop-verify proof.json
wallop-verify selftest
```

See the [CLI reference](docs/cli.md) for full usage.

---

## Functions

### `entry_hash(draw_id: &str, entries: &[Entry]) -> (String, String)`

Returns `(hex_hash, jcs)`.

Entries are sorted by `id` (lexicographic), then serialised as:

```json
{"draw_id":"…","entries":[{"uuid":"…","weight":N},…]}
```

The hash is the lowercase hex SHA-256 of those UTF-8 bytes. The `draw_id` binding means the same entry set hashed against a different draw produces a different hash — an execution receipt cannot be replayed across draws.

On the wire each entry object carries exactly two fields, `uuid` and `weight`. The `Entry` struct's Rust-side `id` field holds the wire-level `uuid` string (see the usage example below).

---

### `compute_seed(entry_hash, drand_randomness, weather_value) -> ([u8; 32], String)`

Returns `(seed_bytes, jcs)`.

Canonical JSON (keys sorted alphabetically):

```json
{"drand_randomness":"…","entry_hash":"…","weather_value":"…"}
```

`seed_bytes` is the raw 32-byte SHA-256 of the JCS string.

---

### `compute_seed_drand_only(entry_hash, drand_randomness) -> ([u8; 32], String)`

Same as `compute_seed` but the `weather_value` key is omitted entirely, providing implicit domain separation — identical inputs will never produce the same seed as the weather variant.

---

### `verify(draw_id, entries, drand_randomness, weather_value, count, expected_results) -> bool`

Runs the inner algorithmic pipeline — `entry_hash → compute_seed → draw → compare` — and returns `true` if the recomputed winners match `expected_results` exactly. Does **not** verify receipt signatures; use `verify_full` for the complete end-to-end check.

---

### `verify_full(lock_receipt_jcs, lock_signature, operator_public_key, execution_receipt_jcs, execution_signature, infrastructure_public_key, entries) -> Result<bool, String>`

The complete signed-bundle verification pipeline. Verifies both receipt signatures, extracts `winner_count` from the signed lock receipt, confirms receipt linkage via `lock_receipt_hash`, cross-checks `entry_hash` on both receipts against the recomputed value, re-derives the seed from the signed entropy fields, re-runs the draw, and compares the recomputed winners against the execution receipt's committed results. Returns `Ok(true)` on success, `Ok(false)` on any verification mismatch, or `Err` on structurally invalid inputs.

---

### `parse_execution_receipt(payload_jcs) -> Result<ParsedExecutionReceipt, ParseExecutionReceiptError>`

Reads `schema_version` from a JCS execution-receipt payload and deserialises into the matching struct: `ParsedExecutionReceipt::V2(_)` for `"2"`, `ParsedExecutionReceipt::V3(_)` for `"3"`. Any other value returns `ParseExecutionReceiptError::UnknownSchemaVersion(v)` — this is **terminal**; a verifier receiving this error MUST upgrade, not retry the draw. Both version parsers use `#[serde(deny_unknown_fields)]` so a payload whose declared `schema_version` does not match its actual field set rejects with `PayloadShapeMismatch` (closes both the downgrade and upgrade-spoof attacks by construction).

---

### `validate_lock_receipt_tags` / `validate_execution_receipt_tags` / `validate_execution_receipt_tags_v3`

Check that the pinned algorithm identity tags (`jcs_version`, `signature_algorithm`, `entropy_composition`, `drand_signature_algorithm`, `merkle_algorithm`) and enum fields (`weather_fallback_reason`) match the frozen values. Verifiers call these after `parse_execution_receipt` and before using any committed field.

---

## Usage

### Rust

```rust
use wallop_verifier::{Entry, entry_hash, compute_seed, verify};

// Entries on the wire carry {uuid, weight}. The Rust `Entry` struct's
// `id` field holds the UUID string.
let entries = vec![
    Entry { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(), weight: 1 },
    Entry { id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(), weight: 1 },
    Entry { id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into(), weight: 1 },
];

let draw_id = "11111111-1111-4111-8111-111111111111";
let drand = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
let weather = "1013";

let (ehash, _jcs) = entry_hash(draw_id, &entries);
let (seed, _jcs) = compute_seed(&ehash, drand, weather);
// seed is [u8; 32], pass it to fair_pick_rs::draw or use verify()

let expected = fair_pick_rs::draw(&entries, &seed, 2).unwrap();
assert!(verify(draw_id, &entries, drand, Some(weather), 2, &expected));
```

For signed-bundle verification (receipts + signatures), use `verify_full` — it accepts the lock receipt JCS bytes, execution receipt JCS bytes, and their Ed25519 signatures and does the full pipeline end-to-end.

### WASM / JavaScript

```js
import init, {
  entry_hash_wasm,
  compute_seed_wasm,
  compute_seed_drand_only_wasm,
  verify_wasm,
} from "./pkg/wallop_verifier.js";

await init();

const entries = [
  { uuid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", weight: 1 },
  { uuid: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", weight: 1 },
  { uuid: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", weight: 1 },
];

const drawId = "11111111-1111-4111-8111-111111111111";

const { hash, jcs: entryJcs } = entry_hash_wasm(drawId, entries);

const { seed, jcs: seedJcs } = compute_seed_wasm(
  hash,
  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  "1013"
);

const ok = verify_wasm(
  drawId,
  entries,
  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  "1013",
  2,
  expectedWinners
);
```

---

## Building the WASM package

```bash
# Install wasm-pack (once)
cargo install wasm-pack

# Build for web — outputs to pkg/
wasm-pack build --target web
```

---

## Test vectors

Test vectors are shared with the Elixir implementation via a git submodule pointing at [`wallop/spec/vectors/`](https://github.com/electric-lump-software/wallop/tree/main/spec/vectors). Both implementations verify against the same frozen JSON files — a protocol change is one edit, and both CIs catch drift immediately.

See the [vector README](https://github.com/electric-lump-software/wallop/blob/main/spec/vectors/README.md) for the full list of covered scenarios.

---

## JCS implementation

JSON Canonicalisation Scheme ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) is implemented manually for the fixed schemas rather than as a general-purpose serialiser. This keeps the implementation minimal and auditable:

- **Entry list schema** — `{"draw_id":"…","entries":[{"uuid":"…","weight":N},…]}`
- **Seed input schema** — `{"drand_randomness":"…","entry_hash":"…","weather_value":"…"}` (or without `weather_value`)
- **Receipt payloads** — deserialised via `serde` with `#[serde(deny_unknown_fields)]` so unknown keys reject at ingest rather than silently passing through.

Top-level keys are sorted alphabetically at build time; there is no runtime key sorting.

---

## Dependencies

| Crate | Purpose |
|---|---|
| [`fair_pick_rs`](https://github.com/electric-lump-software/fair_pick_rs) | Draw algorithm |
| [`sha2`](https://crates.io/crates/sha2) | SHA-256 |
| [`hex`](https://crates.io/crates/hex) | Hex encoding |
| [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) | Ed25519 signature verification |
| [`wasm-bindgen`](https://crates.io/crates/wasm-bindgen) | WASM bindings |
| [`serde`](https://crates.io/crates/serde) + [`serde_json`](https://crates.io/crates/serde_json) | JSON (WASM boundary, receipt parsers) |
| [`serde-wasm-bindgen`](https://crates.io/crates/serde-wasm-bindgen) | JS ↔ Rust value conversion |

---

## License

MIT — see [LICENSE](LICENSE).
