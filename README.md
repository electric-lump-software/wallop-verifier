# wallop_verifier

Protocol functions and verifier for the [Wallop!](https://wallop.run) provably fair draw system.

Wallop runs verifiably fair random draws where nobody controls the outcome. Entries are locked before the draw. The seed comes from public entropy: a [drand](https://drand.love) beacon and, for current draws, a Met Office weather observation from Middle Wallop, Hampshire, taken after the entries are locked. The algorithm is open source and deterministic. Anyone can re-run it and verify the result.

This crate implements the cryptographic pipeline that ties it all together:

- Canonical entry serialisation (JCS + SHA-256), bound to the `draw_id`
- Seed derivation from drand randomness and an optional weather observation or grid-frequency window
- Full end-to-end verification against published proof bundles
- Lock receipt and execution receipt parsers (lock receipt schemas 4, 5 and 6 and execution receipt schemas 2 to 5), with exact-field-set schema enforcement and terminal rejection of unknown versions
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

A `wallop-verify` command-line binary is available behind the `cli` feature flag for verifying proof bundles, pinning trusted keys, running the built-in tamper scenario self-test, and comparing a lock schema 6 bundle's weather and grid-frequency details with public records.

```bash
cargo install wallop_verifier --features cli
wallop-verify proof.json
wallop-verify selftest
wallop-verify weather-attest proof.json
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

`verify` with the grid-frequency seed: `compute_seed_freq` with `freq_value`, or drand alone when it is `None`. Choose between `verify` and `verify_freq` from the signed execution receipt, never from which value happens to be present. Under the grid-frequency tag, use `verify_freq`. Under the weather tag, the receipt's state decides (`landobs_v1::exec_state`, or `landobs_exec_state_wasm` in the browser): `verify` with the value in state (a), `verify_freq` with the value in state (b), and either with no value in state (c). In the browser: `verify_freq_wasm` and `compute_seed_freq_wasm`.

---

### `verify_full(lock_receipt_jcs, lock_signature, operator_public_key, execution_receipt_jcs, execution_signature, infrastructure_public_key, entries) -> Result<bool, String>`

**Deprecated: it checks less than the step pipeline.** Use `verify_steps::verify_bundle_with` and gate on `VerificationReport::passed()`.

A receipt-level check of a lock / execution receipt pair. It verifies both receipt signatures against the keys you pass in, confirms receipt linkage via `lock_receipt_hash`, cross-checks `entry_hash` on both receipts against the recomputed value, re-derives the seed from the execution receipt's entropy fields, re-runs the draw with the lock receipt's `winner_count` and compares the winners with the execution receipt's `results`, checks that both receipts name the same drand round and chain, verifies the drand BLS signature and randomness, and checks that the round published after the lock receipt's `locked_at`. Returns `Ok(true)` on success, `Ok(false)` on any mismatch, or `Err` on structurally invalid inputs.

It does **not** check receipt shape (schema, algorithm tags, canonical timestamps), the other cross-receipt fields, the weather observation window or fallback reason, key resolution or temporal binding (it trusts the keys it is given), or anything in the bundle outside the two receipts (the `entropy` block, `results`). The step pipeline checks all of these.

---

### `parse_execution_receipt(payload_jcs) -> Result<ParsedExecutionReceipt, ParseExecutionReceiptError>`

Reads `schema_version` from a JCS execution-receipt payload and deserialises into the matching struct: `ParsedExecutionReceipt::V2(_)` for `"2"`, `V3(_)` for `"3"`, `V4(_)` for `"4"`, and for `"5"` either `V5(_)` or, under the grid-frequency tag, `V5Freq(_)`. `parse_lock_receipt` does the same for lock receipts: `V4`, `V5`, and for `"6"` either `V6` or `V6Freq`. Both enums are `#[non_exhaustive]`, so treat a variant you do not recognise as a failure. Any other value returns `ParseExecutionReceiptError::UnknownSchemaVersion(v)` — this is **terminal**; a verifier receiving this error MUST upgrade, not retry the draw. Every version parser uses `#[serde(deny_unknown_fields)]` so a payload whose declared `schema_version` does not match its actual field set rejects with `PayloadShapeMismatch` (closes both the downgrade and upgrade-spoof attacks by construction).

---

### `validate_lock_receipt_tags` / `validate_execution_receipt_tags` and their per-schema versions

Check that the pinned algorithm identity tags (`jcs_version`, `signature_algorithm`, `entropy_composition`, `drand_signature_algorithm`, `merkle_algorithm`) and enum fields (`weather_fallback_reason`) match the frozen values. Verifiers call these after `parse_execution_receipt` and before using any committed field.

There is one per schema: `validate_lock_receipt_tags_v5`, `validate_lock_receipt_tags_v6` and `validate_lock_receipt_tags_v6_freq` for lock receipts, and `validate_execution_receipt_tags_v3`, `_v4`, `_v5` and `_v5_freq` for execution receipts. Under lock schema 6 / execution schema 5 they also pin the station (`wmo-03749` under the weather tag), the fallback reasons and the `weather_value` and `freq_value` grammars.

---

## Lock schema 6: weather and grid frequency

Lock receipt schema 6 and execution receipt schema 5 carry one of two entropy tags:

- `drand-quicknet+metoffice-landobs-v1`: a Met Office weather observation from Middle Wallop. If that is late, the GB grid frequency; if that is missing too, drand alone.
- `drand-quicknet+elexon-freq-v1`: the GB grid frequency, or drand alone if that is missing.

What the two tags share:

- **The receipts.** Both tags' locks have the same 20 keys, `freq_start` (T) among them, and both execution receipts the same 28, `freq_value` and `freq_fallback_reason` among them (`freq_v1::LOCK_KEYS` and `freq_v1::EXEC_KEYS`, checked by `freq_v1::exact_keys`). Each lock 6 pairs only with an execution 5 under the same tag. Bundles carry no inline keys; verify them with `verify_bundle_with` (in the browser, `verify_bundle_with_resolved_keys_wasm`).
- **The rules.** The verifier picks its rules from each receipt's `(schema_version, entropy_composition)` pair. A pair it does not know, or two receipts with different tags, fails.
- **The seed.** It is always chosen from the signed execution receipt, never from which field happens to be present, and never from the bundle's unsigned `entropy` block. A pair with no seed rule skips the seed and winner steps, and a skip never passes.
- **The bundle.** `entropy.freq_value` is an additive key in the proof bundle's `entropy` block. It is present when the signed execution receipt carries a `freq_value` (a grid-frequency draw, or a weather draw in state (b) below), and must equal it. The bundle format version is unchanged.
- **The window.** T is the round's grid-frequency window start: `T = floor15(pub(R) - 105 s - W_freq - M)` for drand round R, with `W_freq = 240 s` and `M = 15 s`. So the readings are settled before the round exists. Both tags take T from the same round R.

### Weather observations (`drand-quicknet+metoffice-landobs-v1`)

The rules live in `protocol::landobs_v1`, and every value there is frozen by the tag.

- **The station.** Middle Wallop, Hampshire (`wmo-03749`), and no other. Both receipts name it in every state.
- **The value.** `weather_value` is `t;mslp;rh;vis`: temperature in tenths of a degree C, pressure in whole hPa, humidity in whole percent and visibility in decametres. Each part is a decimal integer with no leading zeros, only the temperature may be negative, and each must lie within its bounds (`parse_weather_value`; `row_to_value` builds one from a Land Observations row, from its decimal text and never through a float).
- **The schedule.** `weather_time` is the latest whole UTC hour h with h + 30 minutes + 60 s no later than the drand round's publication. The lock must be signed at least 46 minutes before `weather_time`, to the microsecond. That puts it well before T, so the grid-frequency tag's 60 s lock lead adds nothing here.
- **The three states.** The execution receipt is in exactly one of these. Any other combination is invalid.

  | State | `weather_value`, `weather_observation_time` | `weather_fallback_reason` | `freq_value` | `freq_fallback_reason` | Seed |
  |---|---|---|---|---|---|
  | (a) weather | set | null | null | null | `compute_seed(entry_hash, drand_randomness, weather_value)` |
  | (b) grid frequency | null | `no_observation_by_deadline` | set | null | `compute_seed_freq(entry_hash, drand_randomness, freq_value)` |
  | (c) drand only | null | `no_observation_by_deadline` | null | `no_frequency_by_deadline` | `compute_seed_drand_only(entry_hash, drand_randomness)` |

  `landobs_v1::exec_state` reads the table from a signed receipt, and in the browser `landobs_exec_state_wasm` returns `"weather"`, `"frequency"` or `"drand_only"`. That picks a seed formula; it is not a check.

**Checked from the bundle alone** (part of `passed()`):

- the entries were signed at least 46 minutes before the observation hour;
- the drand round published after the lock and no later than execution;
- the observation hour and T follow from the round by the published rules;
- the receipt is in one of the three states, and in state (a) the observation is of exactly that hour;
- the value follows the published grammar and bounds;
- both receipts name Middle Wallop and agree on the tag, the operator and the `fair_pick_version`;
- the seed and winners follow from all of this.

**Checked against public records** with `wallop-verify weather-attest` (see the [CLI reference](docs/cli.md#weather-attestation-wallop-verify-weather-attest)):

- in state (a), the value against the Met Office Land Observations record for that hour (exactly) and the WMO SYNOP via Ogimet (temperature and pressure);
- in states (b) and (c), whether Middle Wallop's record holds that hour now, and Elexon's readings from `freq_start` to 105 s after it: compared with the signed readings in state (b), present or absent in state (c).

When Middle Wallop's record holds the hour, its lines read `PRESENT (publication time unknown; a late reading can't be told from a withheld one)`, and a PRESENT Elexon line carries the same caveat. This needs network access and is never part of `passed()`. Exit 0 means no mismatch was found, not that anything is confirmed.

**What no bundle can show:** that a reading really was missing when a draw fell back. On its own, a dishonest wallop must decide to withhold a reading before the drand round publishes, so it chooses blind. Colluding with drand's network, it could choose among at most three candidate seeds (weather, grid frequency, drand only), so a favoured entry's odds rise at most threefold. So the fallback relies on fewer than drand's threshold of nodes colluding. See the protocol spec, [§4.4](https://github.com/electric-lump-software/wallop/blob/main/spec/protocol.md#44-historical-verifiability).

Draws on earlier schemas used a Met Office forecast, which can't be fetched again later, so no third party can check their weather value against a public record.

### Grid frequency (`drand-quicknet+elexon-freq-v1`)

This tag uses 8 readings of GB grid frequency from Elexon's public BMRS FREQ dataset, 15 seconds apart. Its rules live in `protocol::freq_v1`, and every value there is frozen by the tag. The weather tag's state (b) uses the same window and the same value rules.

- **The lock.** The lock receipt signs T and must be signed at least 60 s before it, compared to the microsecond. Its `weather_station` and `weather_time` are null.
- **The value.** The execution receipt signs `freq_value`, the 8 readings in time order as whole mHz, 5 digits each, joined by `;` (for example `50018;50012;49983;49980;49953;49912;49883;49887`). Each reading is read from its JSON number text, never through a float, and must lie in [47000, 52999]. A run of 6 identical readings makes the window invalid (a stuck feed). With no valid window by the deadline, the receipt instead signs `freq_fallback_reason: "no_frequency_by_deadline"` and the seed is drand only. Exactly one of the two is set, and every weather field is null.
- **The receipts.** They parse as `ParsedLockReceipt::V6Freq` / `ParsedExecutionReceipt::V5Freq`.
- **Checking it against the record.** `wallop-verify weather-attest <BUNDLE>` re-fetches the window from Elexon (no key needed) and reports MATCH, MISMATCH or UNAVAILABLE, or PRESENT or ABSENT on a fallback. It is informational and never changes a verification result.

Contains BMRS data © Elexon Limited copyright and database right 2026. This covers the grid-frequency readings of both tags.

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

The lock 6 / execution 5 vectors are read by the integration tests in `tests/` (`V6_VECTORS` in `tests/common/mod.rs` lists them):

- for the weather tag, the schedule, value, receipt and proof bundle vectors for all three states, and its tamper file (`proof-bundle-v6-tamper.json`);
- for the grid-frequency tag, the window (`freq-window-v1.json`), schedule, value, receipt and proof bundle vectors, and its tamper file (`proof-bundle-v6-tamper-freq.json`);
- for both, the negative cases (`proof-bundle-v6-negative.json`), each with the exact set of steps it must fail, and the schedule boundaries (`schedule-boundaries-v1.json`): both tags' schedules for every whole minute from 22:00 to 02:59 UTC across both UK clock changes, a month end, a year end and February with and without a leap day.

These files come from one wallop release and are vendored together. **A vector missing from the vendored tree fails the test suite; it is never skipped.** To confirm a wallop checkout, point `WALLOP_CORE_VECTORS_DIR` at its `spec/vectors`. The tamper, window and schedule boundary files also take their own paths: `WALLOP_TAMPER_VECTORS`, `WALLOP_TAMPER_FREQ_VECTORS`, `WALLOP_FREQ_WINDOW_VECTORS` and `WALLOP_SCHEDULE_BOUNDARY_VECTORS`. A path that is set overrides the vendored copy, but never stands in for a missing one; the test prints which file it read, and warns when that file differs from the vendored one.

The tamper files freeze one convention other verifiers must match: a receipt that fails its typed parse has no key id, so its signature step fails as well as `bundle_shape`. Whether the typed parse succeeds depends on `schema_version` alone: the parser may pick a struct by tag, but each receipt kind has one key set for both tags, and `entropy_composition` is checked after the parse (`bundle_shape`). So a receipt with the right shape and a wrong or unknown tag keeps its key id, and its signature step passes when the signature is valid. The rules are in `tests/common/mod.rs`.

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
