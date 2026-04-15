# wallop_verifier

Protocol functions and verifier for the [Wallop!](https://wallop.run) provably fair draw system.

Wallop runs verifiably fair random draws where nobody controls the outcome. Entries are locked before the draw. The seed comes from public entropy — a [drand](https://drand.love) beacon and a live weather observation from Middle Wallop, Hampshire. The algorithm is open source and deterministic. Anyone can re-run it and verify the result.

This crate implements the cryptographic pipeline that ties it all together:

- Canonical entry serialisation (JCS + SHA-256)
- Seed derivation from drand randomness and an optional weather observation
- Full end-to-end verification against published proof bundles
- Ed25519 receipt signature verification and chain integrity checks
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

### `entry_hash(entries: &[Entry]) -> (String, String)`

Returns `(hex_hash, jcs)`.

Entries are sorted by `id` (lexicographic), then serialised as:

```json
{"entries":[{"id":"…","weight":N},…]}
```

The hash is the lowercase hex SHA-256 of those UTF-8 bytes.

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

### `verify(entries, drand_randomness, weather_value, count, expected_results) -> bool`

Runs the full pipeline — `entry_hash → compute_seed → draw → compare` — and returns `true` if the recomputed winners match `expected_results` exactly.

---

## Usage

### Rust

```rust
use wallop_verifier::{Entry, entry_hash, compute_seed, verify};

let entries = vec![
    Entry { id: "ticket-47".into(), weight: 1 },
    Entry { id: "ticket-48".into(), weight: 1 },
    Entry { id: "ticket-49".into(), weight: 1 },
];

let drand = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
let weather = "1013";

let (ehash, _jcs) = entry_hash(&entries);
let (seed, _jcs) = compute_seed(&ehash, drand, weather);
// seed is [u8; 32], pass it to fair_pick_rs::draw or use verify()

let expected = fair_pick_rs::draw(&entries, &seed, 2).unwrap();
assert!(verify(&entries, drand, Some(weather), 2, &expected));
```

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
  { id: "ticket-47", weight: 1 },
  { id: "ticket-48", weight: 1 },
  { id: "ticket-49", weight: 1 },
];

const { hash, jcs: entryJcs } = entry_hash_wasm(entries);

const { seed, jcs: seedJcs } = compute_seed_wasm(
  hash,
  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  "1013"
);

const ok = verify_wasm(
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

JSON Canonicalisation Scheme ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) is implemented manually for two fixed schemas rather than as a general-purpose serialiser. This keeps the implementation minimal and auditable:

- **Entry list schema** — `{"entries":[{"id":"…","weight":N},…]}`
- **Seed input schema** — `{"drand_randomness":"…","entry_hash":"…","weather_value":"…"}` (or without `weather_value`)

Keys are sorted alphabetically at build time; there is no runtime key sorting.

---

## Dependencies

| Crate | Purpose |
|---|---|
| [`fair_pick_rs`](https://github.com/electric-lump-software/fair_pick_rs) | Draw algorithm |
| [`sha2`](https://crates.io/crates/sha2) | SHA-256 |
| [`hex`](https://crates.io/crates/hex) | Hex encoding |
| [`wasm-bindgen`](https://crates.io/crates/wasm-bindgen) | WASM bindings |
| [`serde`](https://crates.io/crates/serde) + [`serde_json`](https://crates.io/crates/serde_json) | JSON (WASM boundary) |
| [`serde-wasm-bindgen`](https://crates.io/crates/serde-wasm-bindgen) | JS ↔ Rust value conversion |

---

## License

MIT — see [LICENSE](LICENSE).
