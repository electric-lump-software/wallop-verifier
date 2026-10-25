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

### `compute_seed_freq(entry_hash, drand_randomness, freq_value) -> ([u8; 32], String)`

The seed for a grid-frequency draw: `SHA-256(JCS({"drand_randomness": ..., "entry_hash": ..., "freq_value": ...}))`. The `freq_value` key keeps it apart from `compute_seed` and `compute_seed_drand_only`, even for the same string. A grid-frequency draw that fell back uses `compute_seed_drand_only`.

---

### `verify(draw_id, entries, drand_randomness, weather_value, count, expected_results) -> bool`

Runs the inner algorithmic pipeline — `entry_hash → compute_seed → draw → compare` — and returns `true` if the recomputed winners match `expected_results` exactly. Does **not** verify receipt signatures or anything else about a proof bundle; to verify a bundle, use the step pipeline (`verify_steps::verify_bundle_with`) and gate on `VerificationReport::passed()`.

---

### `verify_freq(draw_id, entries, drand_randomness, freq_value, count, expected_results) -> bool`

`verify` for a grid-frequency draw: the seed is `compute_seed_freq` with `freq_value`, or drand alone when it is `None`. Choose it from the receipts' `entropy_composition`, never from which value happens to be present. In the browser: `verify_freq_wasm` and `compute_seed_freq_wasm`.

---

### `verify_full(lock_receipt_jcs, lock_signature, operator_public_key, execution_receipt_jcs, execution_signature, infrastructure_public_key, entries) -> Result<bool, String>`

**Deprecated: it checks less than the step pipeline.** Use `verify_steps::verify_bundle_with` and gate on `VerificationReport::passed()`.

A receipt-level check of a lock / execution receipt pair. It verifies both receipt signatures against the keys you pass in, confirms receipt linkage via `lock_receipt_hash`, cross-checks `entry_hash` on both receipts against the recomputed value, re-derives the seed from the execution receipt's entropy fields, re-runs the draw with the lock receipt's `winner_count` and compares the winners with the execution receipt's `results`, checks that both receipts name the same drand round and chain, verifies the drand BLS signature and randomness, and checks that the round published after the lock receipt's `locked_at`. Returns `Ok(true)` on success, `Ok(false)` on any mismatch, or `Err` on structurally invalid inputs.

It does **not** check receipt shape (schema, algorithm tags, canonical timestamps), the other cross-receipt fields, the weather observation window or fallback reason, key resolution or temporal binding (it trusts the keys it is given), or anything in the bundle outside the two receipts (the `entropy` block, `results`). The step pipeline checks all of these.

---

### `parse_execution_receipt(payload_jcs) -> Result<ParsedExecutionReceipt, ParseExecutionReceiptError>`

Reads `schema_version` from a JCS execution-receipt payload and deserialises into the matching struct: `ParsedExecutionReceipt::V2(_)` for `"2"`, `ParsedExecutionReceipt::V3(_)` for `"3"`. Any other value returns `ParseExecutionReceiptError::UnknownSchemaVersion(v)` — this is **terminal**; a verifier receiving this error MUST upgrade, not retry the draw. Both version parsers use `#[serde(deny_unknown_fields)]` so a payload whose declared `schema_version` does not match its actual field set rejects with `PayloadShapeMismatch` (closes both the downgrade and upgrade-spoof attacks by construction).

---

### `validate_lock_receipt_tags` / `validate_execution_receipt_tags` / `validate_execution_receipt_tags_v3`

Check that the pinned algorithm identity tags (`jcs_version`, `signature_algorithm`, `entropy_composition`, `drand_signature_algorithm`, `merkle_algorithm`) and enum fields (`weather_fallback_reason`) match the frozen values. Verifiers call these after `parse_execution_receipt` and before using any committed field.

---

## Grid frequency (lock schema 6)

Lock receipt schema 6 and execution receipt schema 5 carry one of two entropy tags. `drand-quicknet+metoffice-landobs-v1` uses a Met Office weather observation; `drand-quicknet+elexon-freq-v1` uses 8 readings of GB grid frequency from Elexon's public BMRS FREQ dataset, 15 seconds apart. Its rules live in `protocol::freq_v1`, and every value there is frozen by the tag:

- **The window.** The lock receipt signs `freq_start` (T), the first reading's time: `T = floor15(pub(R) - 105 s - W_freq - M)` for drand round R, with `W_freq = 240 s` and `M = 15 s`. So the readings are settled before the round exists. The lock must be signed at least 60 s before T, compared to the microsecond. `weather_station` and `weather_time` are null.
- **The value.** The execution receipt signs `freq_value`, the 8 readings in time order as whole mHz, 5 digits each, joined by `;` (for example `50018;50012;49983;49980;49953;49912;49883;49887`). Each reading is read from its JSON number text, never through a float, and must lie in [47000, 52999]. A run of 6 identical readings makes the window invalid (a stuck feed). With no valid window by the deadline, the receipt instead signs `freq_fallback_reason: "no_frequency_by_deadline"` and the seed is drand only. Exactly one of the two is set, and every weather field is null.
- **The receipts.** Their key sets are exact (`freq_v1::LOCK_KEYS`, 20 keys; `freq_v1::EXEC_KEYS`, 28 keys; checked by `freq_v1::exact_keys`). They parse as `ParsedLockReceipt::V6Freq` / `ParsedExecutionReceipt::V5Freq`.
- **The bundle.** `entropy.freq_value` is an additive key in the proof bundle's `entropy` block, present when the receipt's tag is the grid-frequency one. It must equal the signed `freq_value`. The seed is always chosen by the receipts' (schema, tag) pair from the signed execution receipt, never from the unsigned `entropy` block. A pair with no seed rule skips the seed and winner steps, and never passes.
- **Checking it against the record.** `wallop-verify weather-attest <BUNDLE>` re-fetches the window from Elexon (no key needed) and reports MATCH, MISMATCH or UNAVAILABLE. It is informational and never changes a verification result.

Contains BMRS data © Elexon Limited copyright and database right 2026.

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

For signed-bundle verification (receipts, signatures, drand and everything else), run the step pipeline and gate on `passed()`:

```rust,ignore
use wallop_verifier::bundle::ProofBundle;
use wallop_verifier::verify_steps::{VerifierMode, verify_bundle_with};

let bundle = ProofBundle::from_json(&bundle_json)?;
let report = verify_bundle_with(&bundle, &resolver, VerifierMode::Attestable);
assert!(report.passed());
```

`verify_full` is deprecated: it checks the two receipts only, and less than the pipeline does.

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

#### Verifying a proof bundle in the browser: the gate

`verify_bundle_with_resolved_keys_wasm(bundle_json, resolved_keys, mode) -> bool` is the browser gate. It runs the full step pipeline, the same checks as the CLI, drand included. A proof page's green result must come from this function returning `true`, and from nothing else.

```js
import init, { verify_bundle_with_resolved_keys_wasm } from "./pkg/wallop_verifier.js";

await init();

// Keys come from wallop's keys endpoint, never from the bundle itself.
const res = await fetch(`${wallopBaseUrl}/operator/${slug}/keys`);
const { keys } = await res.json(); // [{ key_id, public_key_hex, key_class, inserted_at }, ...]

const ok = verify_bundle_with_resolved_keys_wasm(bundleJson, keys, "attestable");
```

Fetch the keys from `/operator/:slug/keys` for attestable mode. Keys taken from the bundle being verified prove only that the bundle agrees with itself. A bundle that fails to parse, an unknown mode or a malformed key throws.

#### `verify_drand_wasm(chain_hash, round, signature_hex, randomness_hex) -> bool`

The drand check on its own, so a page can show it as a separate line: `true` only if the chain is the pinned quicknet chain, the BLS signature is valid for `round`, and `sha256(signature) == randomness`. `round` is a `u64`, so pass a `BigInt`.

- Pass values **only from the signed execution receipt** (`drand_chain`, `drand_round`, `drand_signature`, `drand_randomness`), never from the bundle's unsigned `entropy` block or other page data. A genuine beacon for some other round proves nothing about this draw.
- Pass hex in **lower case**, as the receipt carries it. Upper case is rejected.
- It is **never a gate.** It does not check that the beacon belongs to this draw, that it fed the seed, or that the round published after the lock. Only the gate above does.

`verify_full_wasm` is deprecated and is not a gate either.

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

The lock 6 / execution 5 vectors are read by the integration tests in `tests/`:

- both tags' tamper files (`proof-bundle-v6-tamper.json` and `proof-bundle-v6-tamper-freq.json`);
- the grid-frequency window (`freq-window-v1.json`), schedule, value, receipt and proof bundle vectors.
- the schedule boundaries (`schedule-boundaries-v1.json`): both tags' schedules for every whole minute from 22:00 to 02:59 UTC across both UK clock changes, a month end, a year end and February with and without a leap day.

These files come from one wallop release and are vendored together. Once any of them is vendored, a missing one fails the test suite; it is never skipped. Before they are vendored, point `WALLOP_CORE_VECTORS_DIR` at a wallop checkout's `spec/vectors`. The tamper, window and schedule boundary files also take their own paths: `WALLOP_TAMPER_VECTORS`, `WALLOP_TAMPER_FREQ_VECTORS`, `WALLOP_FREQ_WINDOW_VECTORS` and `WALLOP_SCHEDULE_BOUNDARY_VECTORS`. A path that is set overrides the vendored copy, so a wallop checkout can be confirmed after vendoring too; the test prints which file it read, and warns when that file differs from the vendored one. With nothing vendored and no path set, those tests skip and say so. The rules are in `tests/common/mod.rs`.

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
| [`drand-verify`](https://crates.io/crates/drand-verify) (Apache-2.0) | drand BLS beacon verification, in every build including WASM |

---

## License

MIT — see [LICENSE](LICENSE).
