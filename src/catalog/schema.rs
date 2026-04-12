//! Serde types for the tamper scenario catalog (`scenarios.json`).
//!
//! All structs use `deny_unknown_fields` so typos in scenario files fail loud
//! at load time rather than being silently ignored.

// These types are deserialized from JSON and consumed by sibling modules
// (loader, mutations, runner) that are added in later tasks. The dead_code
// allow will narrow as consumer code lands.
#![allow(dead_code)]

use serde::{Deserialize, Deserializer};
use std::collections::BTreeMap;

/// Custom deserializer to distinguish "field absent" from "field present as null"
/// for the `weather` override. When the field is absent, `#[serde(default)]` gives
/// `None`. When the field is present (including null), this deserializer wraps the
/// result in `Some(...)`, giving `Some(None)` for null and `Some(Some("..."))` for
/// a string value.
fn deserialize_nullable_override<'de, D>(
    deserializer: D,
) -> Result<Option<Option<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Some(Option::<String>::deserialize(deserializer)?))
}

/// Top-level catalog structure, deserialized from scenarios.json.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Catalog {
    pub catalog_schema_version: String,
    pub protocol_version: String,
    pub defaults: Defaults,
    #[serde(default)]
    pub test_keypairs: BTreeMap<String, TestKeypair>,
    #[serde(default)]
    pub fixture_bundles: BTreeMap<String, FixtureBundle>,
    pub scenarios: Vec<Scenario>,
}

/// Base bundle parameters for `build_valid_bundle()` that scenarios inherit.
/// Changes to these defaults are reviewable as data, not code.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Defaults {
    pub entry_count: u32,
    pub weather: Option<String>,
    pub winner_count: u32,
}

/// A named Ed25519 keypair derived from a seed string.
/// Derivation: SHA-256(seed_utf8) → first 32 bytes → Ed25519 seed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TestKeypair {
    pub seed: String,
}

/// A named cross-reference bundle for replay/splice scenarios.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FixtureBundle {
    pub source: String,
}

/// A single tamper scenario in the catalog.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Scenario {
    pub name: String,
    pub category: String,
    pub description: String,
    pub severity: Severity,
    pub tamper: Tamper,
    /// Step names that must reject this scenario. Validated against StepName
    /// at loader level (not during deserialization, so error messages can
    /// include the scenario name).
    pub expected_catch_steps: Vec<String>,
    #[serde(default)]
    pub bundle_params: Option<BundleParams>,
}

/// Scenario severity — informs report output and CI gating.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Severity {
    Critical,
    Informational,
}

/// Per-scenario override of the top-level `defaults` block.
/// Any field not mentioned inherits from `defaults`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BundleParams {
    #[serde(default)]
    pub entry_count: Option<u32>,
    #[serde(default)]
    pub entries: Option<Vec<BundleEntry>>,
    /// `None` = inherit from defaults (field absent in JSON).
    /// `Some(None)` = drand-only mode (field present as null in JSON).
    /// `Some(Some("1013"))` = explicit weather value.
    #[serde(default, deserialize_with = "deserialize_nullable_override")]
    pub weather: Option<Option<String>>,
    #[serde(default)]
    pub winner_count: Option<u32>,
}

/// An explicit entry for scenarios that need non-uniform weights.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BundleEntry {
    pub id: String,
    pub weight: u32,
}

/// The `tamper` field of a scenario. Two-layer vocabulary (Option Y):
/// `field_op` for uniform field-level edits, `semantic_op` for protocol-level
/// operations the field vocabulary cannot express.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Tamper {
    FieldOp(FieldOp),
    SemanticOp(SemanticOp),
}

/// Field-level operations — flat schema, uniform regardless of `op`.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(crate) enum FieldOp {
    ByteFlip {
        path: String,
        offset: usize,
    },
    SetValue {
        path: String,
        value: serde_json::Value,
    },
    Remove {
        path: String,
    },
    Add {
        path: String,
        value: serde_json::Value,
    },
    Reorder {
        path: String,
        ordering: Vec<usize>,
    },
}

/// Semantic operations — protocol-level manipulations. Closed enum: adding a
/// new variant requires a catalog schema version bump.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(crate) enum SemanticOp {
    RecanonicalizeJcs {
        target: String,
    },
    SubstituteSignature {
        target: String,
        source: String,
        #[serde(default)]
        pre_mutations: Vec<FieldOp>,
    },
    SubstitutePayload {
        target: String,
        source: String,
        #[serde(default)]
        pre_mutations: Vec<FieldOp>,
    },
    SubstituteKeyAndResign {
        target: String,
        keypair: String,
        #[serde(default)]
        pre_mutations: Vec<FieldOp>,
    },
    ReplayFrom {
        replace: ReplaySpec,
    },
    /// Modify fields inside a receipt's payload JCS string, re-serialize with
    /// canonical key ordering, then re-sign with the named keypair. Lets
    /// scenarios tamper semantic content while keeping the signature valid,
    /// so downstream steps (seed, winners, linkage) catch the change instead
    /// of the signature step.
    ModifyPayloadAndResign {
        target: String,
        keypair: String,
        /// Key-value pairs to set inside the parsed payload JSON.
        modifications: serde_json::Map<String, serde_json::Value>,
    },
}

/// Explicit target/source declaration for replay operations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReplaySpec {
    pub target: String,
    pub source: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_catalog_deserializes() {
        let json = r#"{
            "catalog_schema_version": "1",
            "protocol_version": "1",
            "defaults": {
                "entry_count": 3,
                "weather": "1013",
                "winner_count": 2
            },
            "test_keypairs": {},
            "fixture_bundles": {},
            "scenarios": []
        }"#;
        let catalog: Catalog = serde_json::from_str(json).unwrap();
        assert_eq!(catalog.catalog_schema_version, "1");
        assert_eq!(catalog.protocol_version, "1");
        assert_eq!(catalog.defaults.entry_count, 3);
        assert_eq!(catalog.defaults.weather.as_deref(), Some("1013"));
        assert_eq!(catalog.defaults.winner_count, 2);
    }

    #[test]
    fn field_op_byte_flip_deserializes() {
        let json = r#"{
            "kind": "field_op",
            "op": "byte_flip",
            "path": "lock_receipt.signature_hex",
            "offset": 5
        }"#;
        let tamper: Tamper = serde_json::from_str(json).unwrap();
        match tamper {
            Tamper::FieldOp(FieldOp::ByteFlip { path, offset }) => {
                assert_eq!(path, "lock_receipt.signature_hex");
                assert_eq!(offset, 5);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn semantic_op_with_pre_mutations_deserializes() {
        let json = r#"{
            "kind": "semantic_op",
            "op": "substitute_key_and_resign",
            "target": "lock_receipt",
            "keypair": "attacker_a",
            "pre_mutations": [
                {
                    "op": "set_value",
                    "path": "lock_receipt.payload_jcs.operator_pubkey",
                    "value": "from_keypair:attacker_a.public"
                }
            ]
        }"#;
        let tamper: Tamper = serde_json::from_str(json).unwrap();
        match tamper {
            Tamper::SemanticOp(SemanticOp::SubstituteKeyAndResign {
                target,
                keypair,
                pre_mutations,
            }) => {
                assert_eq!(target, "lock_receipt");
                assert_eq!(keypair, "attacker_a");
                assert_eq!(pre_mutations.len(), 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn unknown_field_is_rejected() {
        let json = r#"{
            "catalog_schema_version": "1",
            "protocol_version": "1",
            "defaults": { "entry_count": 3, "weather": null, "winner_count": 2 },
            "test_keypairs": {},
            "fixture_bundles": {},
            "scenarios": [],
            "extra_field_that_does_not_exist": "oops"
        }"#;
        let result: Result<Catalog, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra_field_that_does_not_exist"
        );
    }

    #[test]
    fn drand_only_catalog_with_null_weather_deserializes() {
        let json = r#"{
            "catalog_schema_version": "1",
            "protocol_version": "1",
            "defaults": { "entry_count": 3, "weather": null, "winner_count": 2 },
            "test_keypairs": {},
            "fixture_bundles": {},
            "scenarios": []
        }"#;
        let catalog: Catalog = serde_json::from_str(json).unwrap();
        assert!(catalog.defaults.weather.is_none());
    }

    #[test]
    fn scenario_with_bundle_params_deserializes() {
        let json = r#"{
            "name": "test_scenario",
            "category": "entry_set",
            "description": "test",
            "severity": "critical",
            "tamper": {
                "kind": "field_op",
                "op": "byte_flip",
                "path": "lock_receipt.signature_hex",
                "offset": 0
            },
            "expected_catch_steps": ["lock_signature"],
            "bundle_params": {
                "weather": null,
                "winner_count": 1
            }
        }"#;
        let scenario: Scenario = serde_json::from_str(json).unwrap();
        let params = scenario.bundle_params.unwrap();
        // weather: null in JSON → Some(None) (present, explicitly null = drand-only)
        assert_eq!(params.weather, Some(None));
        assert_eq!(params.winner_count, Some(1));
        assert!(params.entry_count.is_none());
        assert!(params.entries.is_none());
    }

    #[test]
    fn scenario_with_explicit_entries_deserializes() {
        let json = r#"{
            "name": "weighted_test",
            "category": "entry_set",
            "description": "test with explicit entries",
            "severity": "critical",
            "tamper": {
                "kind": "field_op",
                "op": "byte_flip",
                "path": "lock_receipt.signature_hex",
                "offset": 0
            },
            "expected_catch_steps": ["entry_hash"],
            "bundle_params": {
                "entries": [
                    { "id": "ticket-1", "weight": 5 },
                    { "id": "ticket-2", "weight": 1 }
                ],
                "winner_count": 1
            }
        }"#;
        let scenario: Scenario = serde_json::from_str(json).unwrap();
        let params = scenario.bundle_params.unwrap();
        let entries = params.entries.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, "ticket-1");
        assert_eq!(entries[0].weight, 5);
    }

    #[test]
    fn replay_from_deserializes() {
        let json = r#"{
            "kind": "semantic_op",
            "op": "replay_from",
            "replace": {
                "target": "$.lock_receipt.signature_hex",
                "source": "bundle_b.lock_receipt.signature_hex"
            }
        }"#;
        let tamper: Tamper = serde_json::from_str(json).unwrap();
        match tamper {
            Tamper::SemanticOp(SemanticOp::ReplayFrom { replace }) => {
                assert_eq!(replace.target, "$.lock_receipt.signature_hex");
                assert_eq!(replace.source, "bundle_b.lock_receipt.signature_hex");
            }
            _ => panic!("wrong variant"),
        }
    }
}
