# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.16.0] - unreleased

### Added — tier-1 attributable mode (`PinnedResolver`)

Closes the last "no holes" gap from the 0.15.0 release notes — the trust scope of `TemporalBinding` is no longer bounded by the resolver alone, because the resolver itself now anchors against compile-time-bundled wallop infrastructure public keys.

- `wallop_verifier::anchors` — bundled trust anchor for tier-1 attributable verification. Holds the wallop production infrastructure public keys plus their `inserted_at` timestamps; sourced via `mix wallop.export_infra_anchor` against production. N=2 cadence per spec §4.2.4 (current + previous within a 90-day grace window). `revoked_at` is `None` for currently-active anchors.
- `PinnedResolver` (binary-side) — wraps `EndpointResolver` and adds: pin envelope fetch + structural validation, JCS pre-image reconstruction, Ed25519 signature verification against the bundled (or override-supplied) anchor set with a `"wallop-pin-v1\n"` 14-byte domain separator, temporal-window check on the verifying anchor, freshness check (60s future-skew → `PinPublishedInFuture`), strict per-resolution equality between live `EndpointResolver` keys and pin keys (operator-class only), and direct anchor lookup for infrastructure-class signatures.
- CLI flags: `--mode attributable` no longer hard-errors; `--pin-from-url <URL>` (required); `--infra-key-pin <JSON>` (repeatable, REPLACES the bundled set, never extends). The `--no-stale-warn` opt-out flag (advisory side of the §4.2.4 freshness rule) is intentionally absent until the warning itself ships in a follow-up; shipping a wired no-op flag would promise a behaviour the binary does not have.
- Cross-language conformance: `vendor/wallop` submodule pinned at the wallop repo's keyring-pin-producer commit. Vector at `spec/vectors/pin/v1/valid.json` ships 1 valid + 5 negatives (preimage mutation, signature mutation, wrong key, domain-separator-omitted, reversed-input key sort) and is exercised by the new `pinned_resolver::tests` module.

### Changed

- `Cargo.toml` version bump 0.15.0 → 0.16.0.
- Bundled vendor/wallop submodule pin advances to include the new pin vector. No existing vector content changes.

### What this means for the proof page mode badge

Tier-1 attributable verification is now *constructable* in the CLI. The proof-page WASM build does not yet support it (no HTTP fetch in WASM, no bundled anchor under the WASM feature flag) — that remains a 1.x fast-follow. The CLI is the canonical way for an auditor to obtain a "this was signed by wallop's infrastructure under a key whose fingerprint is compiled into the verifier you are running" guarantee today.

## [0.15.0] - unreleased

### Added — `StepName::TemporalBinding`

A new 13th verification step asserting `resolved.inserted_at <= receipt.binding_timestamp` per receipt class (spec §4.2.4):

- operator key vs `lock.locked_at`
- infrastructure key vs `execution.executed_at`

Closes the last "no holes" gap on the verifier protocol surface. Producer side (wallop_core 0.18.0) had been enforcing the rule via a CHECK constraint and a sign-time keyring-presence assertion; the verifier-side carrier (`InsertedAt::At` / `Sentinel`) shipped in 0.13.0; the tier-2 `EndpointResolver` (0.14.0) populates the carrier with real `At(_)` data from the wallop endpoints. This release wires up the comparison.

**Trust scope.** This step asserts the binding *given a trusted resolver*. A hostile tier-2 endpoint that lies about `inserted_at` in the earlier direction (e.g. backdating to any time at or before the receipt's binding timestamp, including year-0001 timestamps that aren't byte-equal to the legacy sentinel literal) can bypass the check; only tier-1 pinning closes that gap. The step's strength is bounded by the resolver's trust root, not by the step itself.

The asymmetry matters: a hostile endpoint that lies in the *later* direction (claims a key was inserted *after* it actually was) is caught by the comparison. The vulnerability is one-directional, and tier-1 attributable mode is the existing answer.

Step semantics:

- `Pass` — `inserted_at <= binding_timestamp` for every resolved class.
- `Fail` — at least one class violated the binding; the message names which class, both timestamps, and that the signature is otherwise cryptographically valid ("key was not live at signing time").
- `Skip` — either no key was resolved (signature step already failed), or the resolver is `BundleEmbeddedResolver` running in `VerifierMode::SelfConsistencyOnly` (the comparison is vacuous against a bundle-self-attesting trust root).

The step is appended to `StepName::all()` (preserves ordinal stability for external consumers; same rule used when `BundleShape` was added). A new unit test pins the step ordering as a snapshot — appending is non-breaking, reordering or inserting mid-list is a v2.0.0 change.

The selftest catalog cannot trigger a `TemporalBinding` fail because it runs against `BundleEmbeddedResolver` in self-consistency mode (where the step skips). Coverage of this step lives in the verifier's unit tests, not the selftest catalog. The catalog's coverage check excludes `TemporalBinding` for that reason — same shape as the existing `EntryHash` exclusion.

### Added — resolver call-site filter

After every successful `KeyResolver::resolve`, the verification pipeline now refuses two classes of resolver result before the resolved key reaches signature verification:

1. `InsertedAt::Sentinel` paired with any `VerifierMode` other than `SelfConsistencyOnly`. `BundleEmbeddedResolver` is the only intended emitter; receiving it from a tier-2 / tier-1 resolver is a protocol violation per spec §4.2.4.
2. `InsertedAt::At(timestamp)` whose year-prefix is `0001`. The pre-0.13.0 magic-string sentinel was `"0001-01-01T00:00:00.000000Z"`; rejecting only that exact literal would let a hostile tier-2 endpoint backdate to year-0001 with a one-microsecond perturbation (e.g. `"0001-01-01T00:00:00.000001Z"`) and trivially pass any `<=` temporal-binding comparison. Reject the entire sentinel-year prefix so any year-0001 timestamp surfaces as `LegacySentinelRejected` rather than silently disabling the binding.

Both rejections drop the resolved key, surfacing as a signature-step failure with a `ResolutionFailure` step detail naming the rejection kind (see below) — and consequently a `TemporalBinding` skip for "no resolved key from previous step."

### Added — `ResolutionFailure` step detail

The signature steps (`LockSignature` / `ExecSignature`) now distinguish resolver failures from generic signature failures. Previously every resolver failure (`KeyNotFound`, `Unreachable`, `MalformedResponse`, `InconsistentRow`, etc.) collapsed to `"Ed25519 signature invalid"`. Now they surface a typed `StepDetail::ResolutionFailure { class, kind }` with seven distinct variants:

- `Unreachable` — resolver could not reach its trust root.
- `KeyNotFound` — trust root does not list the requested `key_id`.
- `PinMismatch` — live keyring contradicts pinned reference (tier-1 only).
- `MalformedResponse` — trust root response did not parse.
- `InconsistentRow` — keyring row's `key_id` does not hash to its `public_key`.
- `SentinelRejected` — resolver returned `Sentinel` under non-self-consistency mode (protocol violation).
- `LegacySentinelRejected` — resolver returned the legacy `0001-01-01` sentinel literal in `At(_)`.

A signature failure with no resolution failure recorded (resolver succeeded but the bytes don't verify) keeps the existing `"Ed25519 signature invalid"` message. CLI and TUI output render the `ResolutionFailure` distinctly.

### Public API additions

- `StepName::TemporalBinding` — new variant, appended.
- `StepDetail::ResolutionFailure { class, kind }` — new variant on the existing `StepDetail` enum.
- `ResolutionFailureKind` — new public enum (closed-set tag for the failure variant).

All additive; no breaking changes for downstream consumers that pattern-match exhaustively on the existing variants (`StepDetail` is already a closed set, so adding a variant is a minor bump under our pre-1.0 conventions).

## [0.14.0] - 2026-04-29

### Added — `EndpointResolver` (tier-2 attestable mode)

The CLI binary gains a tier-2 `KeyResolver` implementation that fetches operator and infrastructure keys from the wallop instance's HTTP endpoints documented in spec §4.2.4:

- `GET <base>/operator/<slug>/keys`
- `GET <base>/infrastructure/keys`

Both return the canonical four-field row shape pinned by spec §4.2.4: `{key_id, public_key_hex, inserted_at, key_class}`. The resolver validates the response's top-level `schema_version` (exact match `"1"`, terminal rejection on anything else), enforces verifier-side keyring-row consistency (`crypto::key_id(public_key) == key_id`), and caches per `KeyClass` for the lifetime of the resolver — at most two HTTP requests per verification, regardless of how many keys the bundle references.

Lives under `src/bin/endpoint_resolver/` (binary-private — `ureq` and TLS deps stay out of the verifier crate proper, which compiles to WASM).

### Added — `wallop-verify --mode attestable`

The CLI's `--mode attestable` option is now wired and functional. It requires a new `--wallop-base-url <URL>` flag identifying the wallop instance to resolve against; `<base>/operator/<slug>/keys` and `<base>/infrastructure/keys` are the canonical paths. The operator slug is read from the bundle's signed lock receipt — an attacker rewriting only the bundle JSON wrapper cannot redirect the resolver at a different operator's keyring without invalidating the lock signature.

The CLI's report header now surfaces `Trust root` lines naming the resolver URLs alongside the existing `Mode` line, so a reader of the report knows precisely which trust root produced the verdict.

`--mode attributable` (tier-1, operator-hosted `.well-known` pin) still exits with "not yet implemented in this release" — that lands in a follow-up.

### Added — HTTP dependency (CLI feature only)

`ureq 2.10` (with `tls` + `json` features, default-features-off) joins the dependency list behind the `cli` feature flag. Pure-Rust TLS via rustls — no OpenSSL system deps. Sync, blocking, no async runtime. The library crate's WASM build is unaffected.

`mockito 1` joins dev-dependencies for the resolver's integration tests, which run a local mock HTTP server and assert the resolver's behaviour against canned canonical / malformed / inconsistent / unreachable responses.

### Public API change

- `KeyClass` derives `Hash` (additive — was `Debug + Clone + Copy + PartialEq + Eq`). Allows downstream callers to use it as a map key. Non-breaking.

### Defence-in-depth on the resolver

- **Operator-slug charset validation.** The CLI extracts `operator_slug` from the bundle's signed lock receipt JCS payload before the lock signature is verified. A malformed slug whose signature is going to fail later in the pipeline anyway must not be permitted to direct the verifier at arbitrary URLs on the wallop host. The CLI now validates the slug against the producer-side rule (`^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`, 2-63 chars; spec §4.2.1) before any HTTP request is constructed. Path traversal, query injection, header smuggling, and similar URL-injection vectors are rejected with a clear error.
- **`--wallop-base-url` scheme allow-list.** Tier-2 attestable mode is by definition a same-origin trust assertion; keys arriving over an unauthenticated channel collapse the trust model. The CLI requires `https://` for non-loopback hosts and accepts `http://localhost`, `http://127.0.0.1`, and `http://[::1]` for development convenience. Any other scheme rejects.
- **Response size and shape caps.** `EndpointResolver` caps the response body at 1 MiB (read via a bounded `Read` adapter) and rejects responses with more than 10,000 keys per class. Defends the verifier against a misbehaving / hostile endpoint shipping a pathologically large body that would OOM the process.
- **`#[serde(deny_unknown_fields)]` on the wire structs.** Both `KeysResponse` (envelope) and `KeyEntry` (per-key row) are closed-set per spec §4.2.4. A future producer that re-introduces a removed field (e.g. `valid_from`, deliberately removed in spec §4.2.4 to close the temporal-binding window) under `schema_version: "1"` is itself a wire-contract violation; the resolver rejects rather than silently ignoring.
- **Strict lowercase-hex assertion** on `key_id` (8 chars) and `public_key_hex` (64 chars). `hex::decode` accepts mixed case; an endpoint emitting uppercase hex would still pass the row-consistency hash check (because `crypto::key_id(pk)` is lowercase too) but would violate the wire contract. Reject early so cross-implementation conformance is asserted, not implied.
- **Verifier-side keyring-row consistency check** at row-level, mirroring the verifier crate's pipeline-level check for defence in depth: the row's claimed `key_id` MUST equal `crypto::key_id(public_key)`. Mismatches surface as `ResolutionError::InconsistentRow`.
- **`User-Agent: wallop-verifier/<version>`** on outgoing requests. Operator-side rate limiting and abuse triage are much harder when verifiers' UA is anonymous.
- **Resolver exposes canonicalised URLs.** `operator_keys_url()` / `infrastructure_keys_url()` accessors return the exact URL the resolver hits; the CLI's `Trust root` report header reads from these, so the audit trail names what the resolver actually used (not a re-formatted version of the user's input).

### Documentation

- The `InsertedAt` enum and `ResolvedKey.inserted_at` field doc comments drop the internal "V-02" rule label in favour of the spec-level "temporal-binding" phrasing. The carrier shape is unchanged. Same change applied to the `InsertedAt` paragraph in `[0.13.0]` below.

## [0.13.0] - 2026-04-28

### Breaking

- **`ResolvedKey.inserted_at` is now `InsertedAt`** (was `String`). The new enum has two variants: `At(String)` carrying a canonical RFC 3339 timestamp from a non-bundle resolver's trust root, and `Sentinel` reserved for `BundleEmbeddedResolver` (which has no out-of-band first-existence timestamp to return). Verifier-side temporal-binding enforcement, when wired, will dispatch on the variant rather than string-comparing a magic value: `Sentinel` skips the temporal-binding check when paired with `VerifierMode::SelfConsistencyOnly`, and rejects when paired with any other mode (a non-bundle resolver returning `Sentinel` is itself a protocol violation).
- **The public constant `BUNDLE_EMBEDDED_INSERTED_AT_SENTINEL` is removed.** Callers that constructed `ResolvedKey` literals with this constant now use `InsertedAt::Sentinel` directly.

### Migration notes

External callers that constructed `ResolvedKey` literals or `KeyResolver` implementations need to update one field's type. The new shape:

```rust
ResolvedKey {
    public_key: [u8; 32],
    inserted_at: InsertedAt::At("2026-04-26T12:34:56.789012Z".into()),
    // or InsertedAt::Sentinel for bundle-self-attesting resolvers
    key_class: KeyClass::Operator,
}
```

JS callers of `verify_bundle_with_resolved_keys_wasm` are not affected — the WASM boundary still accepts a string `inserted_at` and wraps it in `InsertedAt::At(...)` internally. The `Sentinel` variant is reachable only from inside the verifier crate.

## [0.12.0] - 2026-04-28

### Breaking

- **`ReceiptBlock.public_key_hex` is now `Option<String>`** (was `String`). Bundles with v5 lock receipts and v4 execution receipts MUST omit the inline key from the wrapper; bundles with v3 / v4 lock and v2 / v3 execution receipts MUST continue to supply it. The `BundleShape` step enforces this consistency rule and rejects mismatches as downgrade-relabel or upgrade-spoof attempts. The serde aliases `operator_public_key_hex` and `infrastructure_public_key_hex` continue to work.
- **`verify_bundle` is now a thin wrapper around `verify_bundle_with(bundle, &resolver, mode)`.** The new function accepts any `KeyResolver`. The old `verify_bundle(bundle)` constructs a `BundleEmbeddedResolver` internally and runs the pipeline in `VerifierMode::SelfConsistencyOnly` — drop-in compatible for callers verifying legacy bundles. Callers that want resolver-driven verification (tier-1 attributable or tier-2 attestable) call `verify_bundle_with` directly.
- **Receipt schema versions accepted by the typed dispatchers:** `parse_lock_receipt` now accepts `"4"` and `"5"`; `parse_execution_receipt` now accepts `"2"`, `"3"`, and `"4"`. Unknown-schema-version errors carry the full set in their `Display` output.

### Added — `KeyResolver` trait surface

A new public module `key_resolver` defines the resolution surface used by `verify_bundle_with`:

- `KeyResolver` trait — single `resolve(key_id, key_class)` entry point. Failure is terminal; the verifier pipeline does not fall back to inline keys.
- `ResolvedKey { public_key, inserted_at, key_class }` — the resolved key plus the metadata required for spec §4.2.4 temporal-binding (verifier-side enforcement is not yet wired; the carrier is in place).
- `KeyClass::{Operator, Infrastructure}` — discriminator passed to the resolver.
- `ResolutionError::{Unreachable, KeyNotFound, PinMismatch, MalformedResponse, InconsistentRow}` — closed-set failure modes.
- `BundleEmbeddedResolver` — the only built-in implementation, used for legacy v3 / v4 bundles and for `--mode self-consistency` debug runs. Reads keys directly from the bundle's inline `public_key_hex` fields.

HTTP-backed implementations (`EndpointResolver` for tier-2 attestable, `PinnedResolver` for tier-1 attributable) are CLI-side concerns and ship in a follow-up release. The verifier crate stays free of HTTP dependencies so the WASM build remains lean.

### Added — `LockReceiptV5` and `ExecutionReceiptV4`

New typed structs in `protocol::receipts`. **Field set is byte-identical to their predecessors** (`LockReceiptV4` / `ExecutionReceiptV3`) — only the `schema_version` constant differs. The bump is a coordination flag: a v5 / v4 receipt signals to the verifier that the bundle wrapper omits inline keys and the pipeline MUST resolve via `KeyResolver`. New validators `validate_lock_receipt_tags_v5` and `validate_execution_receipt_tags_v4` mirror the v4 / v3 validators against the new schema-version constant.

### Added — schema-version-vs-bundle-shape consistency rule

`BundleShape` now enforces the producer-side protocol rule:

- v5 lock receipt + bundle wrapper carrying inline `public_key_hex` rejects (downgrade-relabel attempt).
- v4 lock receipt + bundle wrapper missing inline `public_key_hex` rejects (upgrade-spoof attempt).
- Symmetric rules for v4 / v3 / v2 execution receipts.

Mirrors the v2 / v3 deny_unknown_fields pattern one level out: producers cannot relabel one schema as another to elide or smuggle a field.

### Added — verifier-side keyring-row consistency check

After every successful `KeyResolver::resolve`, the pipeline asserts that `crypto::key_id(resolved.public_key) == requested_key_id`. A buggy or hostile resolver answering a request for `key_id=X` with `pk_Y` (where `Y != X`) would otherwise pass — the signature would verify against `pk_Y`. This is the verifier-side mirror of the producer's keyring-row consistency check; it makes the pipeline the chokepoint rather than relying on every resolver implementation to enforce it internally.

The exec-v2 path now derives a synthetic `key_id` by hashing the inline pubkey, so every resolver call carries a real `key_id`. The previous empty-string fallback (where `BundleEmbeddedResolver` substituted any requested `key_id` for the absent v2 `signing_key_id`) is gone — tier-2 / tier-1 resolvers now fail v2 bundles with `KeyNotFound` for the right reason.

### Added — `deny_unknown_fields` on bundle envelope and receipt wrapper

`ProofBundle`, `BundleEntry`, `BundleResult`, `Entropy`, and `ReceiptBlock` all gain `#[serde(deny_unknown_fields)]`. Brings the same closed-set discipline the receipt payloads already have one level out, to the bundle envelope itself. A future v2 bundle envelope field would need to be deserialised explicitly rather than silently absorbed by an old verifier. Supplying both `operator_public_key_hex` and `infrastructure_public_key_hex` aliases on the same wrapper now also rejects.

### Added — non-empty `signing_key_id` validation on v5 / v4 receipts

`validate_lock_receipt_tags_v5` and `validate_execution_receipt_tags_v4` now reject an empty `signing_key_id`. v5 / v4 receipts carry `signing_key_id` as load-bearing data (the value the resolver looks up); an empty string would conflate the resolver call with the v2 inline-pk fallback and is otherwise nonsensical.

### Added — selftest catalog scenarios

Four new scenarios cover `BundleShape` at runtime:

- `lock_v5_with_inline_pubkey_rejects` (downgrade-relabel)
- `lock_v4_without_inline_pubkey_rejects` (upgrade-spoof)
- `exec_v2_without_inline_pubkey_rejects` (upgrade-spoof)
- `unknown_lock_schema_version_rejects` (terminal `UnknownSchemaVersion`)

Selftest now reports 21 scenarios (was 17) and `BundleShape` is covered at runtime — bringing covered-step count to 11 / 12 (`EntryHash` is structurally excluded — it's a computation step that always passes).

### Added — `verify_bundle_with_resolved_keys_wasm`

New WASM entry point for resolver-driven verification on v5 / v4 bundles. Accepts the bundle JSON, a JS-side array of pre-resolved `{key_id, public_key_hex, key_class, inserted_at}` entries, and a verifier mode string. The JS layer fetches keys out of band (operator endpoint or `.well-known` pin) and hands them in as one shot — the WASM build does not pull `reqwest`. The legacy `verify_full_wasm` continues to work unchanged for v4 / v3 bundles.

### Added — `--mode` CLI flag

`wallop-verify` now accepts `--mode {self-consistency|attestable|attributable}` (default `self-consistency`). Self-consistency mode is current behaviour. Attestable and attributable modes parse correctly but exit with a "not yet implemented in this release" message — the CLI-side HTTP resolvers (`EndpointResolver`, `PinnedResolver`) ship in a follow-up release. The library `KeyResolver` trait is in place; the CLI's pin flags (`--pin-operator-key`, `--pin-from-bundle`) continue to apply to bundles that carry inline keys.

The CLI report header now includes a `Mode` line surfacing `report.mode` so a reader of the report knows what the report's "PASS" actually proved (spec §4.2.4 caveat-mode disclosure).

### Tests fixture update

- `src/bin/tui/state.rs` — fixture step counts and sample scenarios brought up to date with the 0.10.0 / 0.11.0 step additions (was failing under `cargo test --all-features`; the lib gate ran fine because the tests are behind the `tui` feature).

## [0.11.0] - 2026-04-26

### Breaking

- **`VerificationReport` gains a required `mode: VerifierMode` field.** External callers constructing a `VerificationReport` literal will fail to compile until they set the mode. The new field is needed to make the verifier's trust mode explicit in every report. In 1.0.0 the only constructible variant is `SelfConsistencyOnly`; `Attributable` and `Attestable` are reserved for the `KeyResolver` work in a follow-up release. The enum is `#[non_exhaustive]` so that future expansion is not itself a breaking change.
- **`StepName::all()` now returns 12 entries (was 11).** Callers that hard-code the count, iterate to a fixed offset, or pin a `Vec<_>` length will break. The new variant `StepName::BundleShape` is appended (preserves ordinal stability for existing entries).

### Added — `BundleShape` verification step

A new 12th verification step that wires the typed parsers and tag validators (which the crate has shipped since the receipts module landed) into the `verify_bundle` pipeline. The validators existed but `verify_bundle` never called them, so closed-set discipline, `schema_version` strict dispatch, algorithm-identity-tag pinning, `weather_station` charset, and canonical RFC 3339 timestamps were not enforced at runtime.

`BundleShape` runs `parse_lock_receipt` and `parse_execution_receipt` (both with `deny_unknown_fields` and schema-version dispatchers), then the version-specific tag validators, then `chrono_parse_canonical` on every signed timestamp (`locked_at`, `weather_time`, `executed_at`, and `weather_observation_time` when present). A bundle whose lock receipt contains an unknown field, declares an unsupported `schema_version`, names an algorithm tag that doesn't match the pinned constant, or carries a non-canonical timestamp now fails `BundleShape` rather than silently passing through `unwrap_or_default()` in the older steps.

The step is appended to `StepName::all()` rather than inserted mid-list so external consumers pinning step ordinals are not broken; in execution order it runs alongside the existing 11 steps and produces a per-step diagnostic on the report. `VerificationReport::passed()` is the authoritative acceptance gate — per-step `Pass` is a diagnostic about the bytes that step examined, not a claim that the bundle is well-formed; the `passed()` doc comment now states this explicitly so downstream callers can't infer acceptance from step counts.

### Added — typed parser surface

Pure-additive tightening of the typed surface ahead of `BundleShape` wiring (the wiring would have been incoherent without it):

- `LockReceiptV4` gains `#[serde(deny_unknown_fields)]`, matching the execution receipt structs. A lock receipt with an extra field now rejects at parse time (closed-set discipline, spec §4.2.1, §4.2.5).
- New `parse_lock_receipt` dispatcher with `ParsedLockReceipt` enum and `ParseLockReceiptError`, mirroring `parse_execution_receipt`. Currently routes only to v4; an unknown `schema_version` returns terminal `UnknownSchemaVersion` (spec §4.2.1 — verifiers MUST upgrade, MUST NOT retry).
- New `validate_weather_station(station: &str)` enforcing the spec §4.2.1 charset rule (`^[a-z][a-z0-9-]*$`), capped at `WEATHER_STATION_MAX_LEN = 64` bytes for defence-in-depth against pathologically long values. Wired into `validate_lock_receipt_tags`, `validate_execution_receipt_tags`, and `validate_execution_receipt_tags_v3`.

### Added — `VerifierMode` enum

A public, `#[non_exhaustive]` enum naming the three verifier trust modes: `Attributable` (operator-hosted `.well-known` pin — not constructable in 1.0.0), `Attestable` (`/operator/:slug/keys` endpoint resolution — not constructable in 1.0.0), and `SelfConsistencyOnly` (bundle-embedded keys — the only reachable variant in 1.0.0). `Display`, `Serialize`, and `Deserialize` use snake-case wire form. The enum is wired into `VerificationReport.mode` now so that the `KeyResolver` follow-up can light up the other two variants without a breaking change.

### Audit closure

- **Coverage-guided fuzz campaign completed.** 8-hour libFuzzer run
  against three targets covering the highest-value verifier attack
  surfaces. No panics, no `Ok(true)` false-positive verifications, no
  crashes. Corpus growth confirms healthy coverage (single-digit
  corpus would suggest the harness never reached interesting branches;
  these are well past that threshold).

  | Target | Corpus size after 8h |
  |---|---|
  | `fuzz_parse_execution_receipt` | 1,696 |
  | `fuzz_bundle_parse` | 2,938 |
  | `fuzz_verify_full` | 932 |

  This closes the fuzzing method gap.
  Re-run on protocol changes; add seed inputs to `fuzz/corpus/<target>/`
  when new schema shapes land.

### Fixed

- **Weather observation window bound direction.** The 0.10.0 verifier
  implemented the window as `obs ∈ [lock.weather_time, lock.weather_time + 3600s]`.
  That direction is wrong for production bundles: Met Office publishes
  observations at hour boundaries (XX:00:00 UTC), and the entropy worker
  fetches the most recent observation **at or before** the declared target.
  A real bundle with lock.weather_time = 13:41:57 and observation = 13:00:00
  would fail the 0.10.0 check. Corrected bound: `obs ∈ [lock.weather_time - 3600s, lock.weather_time]`.
  This is the first production bundle the 0.10.0 verifier was run against —
  0.10.0 was never published to crates.io.

### Added — selftest catalog

- `weather_window_violation_too_old` — observation more than 1 hour
  before the declared target. Covers the attack vector opposite to
  `weather_window_violation_future`.

### Tests fixture update

- `src/bin/tui/{state,render}.rs` — the `StepStatus::Pass` fixture lists
  were hardcoded at 9 and are now 11 to match the step count after the
  0.10.0 additions.

## [0.10.0] - unreleased

### Added

Two new verification steps closing the receipt-splice attack class per
the matching `wallop` spec update at §4.2.5.

- **Step 10: Receipt field consistency.** Every field duplicated across
  the lock and execution receipts MUST be byte-identical. Fields
  checked: `draw_id`, `operator_id`, `sequence`, `drand_chain`,
  `drand_round`, `weather_station`. Bundle envelope `draw_id` also
  cross-checked. `signing_key_id` deliberately NOT checked (different
  keys by design — operator vs infra). `operator_slug` NOT checked
  (derivative of `operator_id`). Algorithm identity tags NOT
  cross-checked (already validated per-receipt).
- **Step 11: Weather observation window.** Execution receipt's
  `weather_observation_time` MUST fall in the closed interval
  `[lock.weather_time, lock.weather_time + 3600s]`. Prevents an
  infrastructure-level attacker from fetching weather from any point
  in time and attributing it to the draw's declared window.

Both steps are appended — pre-existing StepName ordinals (1–9) are
unchanged so external consumers pinning step numbers are not broken.

### Added — selftest catalog

Seven new tamper scenarios under `cross_receipt_binding`:
- `splice_exec_draw_id_mismatch`
- `splice_exec_sequence_mismatch`
- `splice_exec_operator_id_mismatch`
- `splice_exec_drand_chain_mismatch`
- `splice_exec_drand_round_mismatch`
- `splice_exec_weather_station_mismatch`
- `weather_window_violation_future`

### Changed

The catalog runner now records a scenario as `Passed` if ANY failing
step is in the scenario's `expected_catch_steps` list, not just the
first failing step. The previous "first-failing" rule worked for
pre-v0.10 scenarios because their expected step was the first step
they broke, but it interacted poorly with the selftest's stub BLS
signature (`drand_signature: "00" * 48`) which always fails step 9
at runtime. With the new rule, scenarios whose expected catch step
runs after step 9 are reported correctly. No existing scenario
outcomes change — every pre-v0.10 scenario's first-failing step is
already in its expected set.

### Compatibility

- No wire-format change. No schema bump. No frozen-vector change.
- v0.9.x bundles verify identically under 0.10 modulo the two new
  steps, which pass cleanly on any bundle produced by a conformant
  `wallop_core` 0.17.x producer.
- Third-party consumers pinning `StepName::*` ordinals are unaffected
  (pre-existing variants stay at positions 1–9).

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
