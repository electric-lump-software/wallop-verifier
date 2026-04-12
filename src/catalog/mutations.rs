//! Field-op and semantic-op dispatch for catalog scenarios.
//!
//! Mutations operate on a `serde_json::Value` representation of the bundle
//! because the catalog is JSON-driven: scenarios reference fields by dotted
//! path, and the mutation round-trips through the same shape the bundle was
//! serialized from.

#![allow(dead_code)] // consumed by runner (added in a later task)

use crate::catalog::schema::{FieldOp, SemanticOp};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use std::collections::BTreeMap;

/// Error type for mutation failures.
#[derive(Debug)]
pub(crate) enum MutationError {
    PathNotFound(String),
    NonHexByteFlip(String),
    InvalidOffset {
        path: String,
        offset: usize,
        len: usize,
    },
    NotImplemented(String),
}

impl std::fmt::Display for MutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MutationError::PathNotFound(p) => {
                write!(f, "field path '{p}' not found in bundle")
            }
            MutationError::NonHexByteFlip(p) => {
                write!(f, "byte_flip target '{p}' is not a hex-encoded string")
            }
            MutationError::InvalidOffset { path, offset, len } => write!(
                f,
                "byte_flip offset {offset} is out of range for '{path}' (length {len} bytes)"
            ),
            MutationError::NotImplemented(msg) => write!(f, "not implemented: {msg}"),
        }
    }
}

impl std::error::Error for MutationError {}

/// Runtime context for semantic ops — provides test keypairs and fixture bundles.
pub(crate) struct CatalogContext {
    pub keypairs: BTreeMap<String, SigningKey>,
    pub fixture_bundles: BTreeMap<String, Value>,
}

impl CatalogContext {
    pub fn new() -> Self {
        Self {
            keypairs: BTreeMap::new(),
            fixture_bundles: BTreeMap::new(),
        }
    }
}

// ==================== Field operations ====================

pub(crate) fn apply_field_op(bundle: &mut Value, op: &FieldOp) -> Result<(), MutationError> {
    match op {
        FieldOp::ByteFlip { path, offset } => byte_flip(bundle, path, *offset),
        FieldOp::SetValue { path, value } => set_value(bundle, path, value.clone()),
        FieldOp::Remove { path } => remove(bundle, path),
        FieldOp::Add { path, value } => add(bundle, path, value.clone()),
        FieldOp::Reorder { path, ordering } => reorder(bundle, path, ordering),
    }
}

/// Walk a dotted path with optional bracket notation for array indices.
/// Returns a mutable reference to the target value, or None if the path
/// doesn't exist.
fn walk_path<'a>(value: &'a mut Value, path: &str) -> Option<&'a mut Value> {
    let mut current = value;
    for segment in path.split('.') {
        if let Some(open) = segment.find('[') {
            let field = &segment[..open];
            let close = segment.find(']')?;
            let index: usize = segment[open + 1..close].parse().ok()?;
            current = current.get_mut(field)?;
            current = current.get_mut(index)?;
        } else {
            current = current.get_mut(segment)?;
        }
    }
    Some(current)
}

fn byte_flip(bundle: &mut Value, path: &str, offset: usize) -> Result<(), MutationError> {
    let target =
        walk_path(bundle, path).ok_or_else(|| MutationError::PathNotFound(path.to_string()))?;
    let hex_str = target
        .as_str()
        .ok_or_else(|| MutationError::NonHexByteFlip(path.to_string()))?;
    let mut bytes =
        hex::decode(hex_str).map_err(|_| MutationError::NonHexByteFlip(path.to_string()))?;
    if offset >= bytes.len() {
        return Err(MutationError::InvalidOffset {
            path: path.to_string(),
            offset,
            len: bytes.len(),
        });
    }
    bytes[offset] ^= 0xFF;
    *target = Value::String(hex::encode(bytes));
    Ok(())
}

fn set_value(bundle: &mut Value, path: &str, new_value: Value) -> Result<(), MutationError> {
    let target =
        walk_path(bundle, path).ok_or_else(|| MutationError::PathNotFound(path.to_string()))?;
    *target = new_value;
    Ok(())
}

fn remove(bundle: &mut Value, path: &str) -> Result<(), MutationError> {
    let Some((parent_path, last)) = path.rsplit_once('.') else {
        if let Value::Object(map) = bundle
            && map.remove(path).is_some()
        {
            return Ok(());
        }
        return Err(MutationError::PathNotFound(path.to_string()));
    };
    let parent = walk_path(bundle, parent_path)
        .ok_or_else(|| MutationError::PathNotFound(path.to_string()))?;
    if let Value::Object(map) = parent
        && map.remove(last).is_some()
    {
        return Ok(());
    }
    Err(MutationError::PathNotFound(path.to_string()))
}

fn add(bundle: &mut Value, path: &str, new_value: Value) -> Result<(), MutationError> {
    let Some((parent_path, last)) = path.rsplit_once('.') else {
        // No dot in path — top-level key. If it already exists as an array, append.
        if let Value::Object(map) = bundle {
            if let Some(Value::Array(arr)) = map.get_mut(path) {
                arr.push(new_value);
                return Ok(());
            }
            map.insert(path.to_string(), new_value);
            return Ok(());
        }
        return Err(MutationError::PathNotFound(path.to_string()));
    };
    let parent = walk_path(bundle, parent_path)
        .ok_or_else(|| MutationError::PathNotFound(path.to_string()))?;
    if let Value::Object(map) = parent {
        map.insert(last.to_string(), new_value);
        return Ok(());
    }
    if let Value::Array(arr) = parent {
        arr.push(new_value);
        return Ok(());
    }
    Err(MutationError::PathNotFound(path.to_string()))
}

fn reorder(bundle: &mut Value, path: &str, ordering: &[usize]) -> Result<(), MutationError> {
    let target =
        walk_path(bundle, path).ok_or_else(|| MutationError::PathNotFound(path.to_string()))?;
    let arr = target
        .as_array_mut()
        .ok_or_else(|| MutationError::PathNotFound(path.to_string()))?;
    if ordering.len() != arr.len() {
        return Err(MutationError::PathNotFound(format!(
            "{path} (ordering length mismatch)"
        )));
    }
    let reordered: Vec<Value> = ordering.iter().map(|&i| arr[i].clone()).collect();
    *arr = reordered;
    Ok(())
}

// ==================== Semantic operations ====================

pub(crate) fn apply_semantic_op(
    bundle: &mut Value,
    op: &SemanticOp,
    ctx: &CatalogContext,
) -> Result<(), MutationError> {
    // Run pre_mutations first (if any)
    let pre_mutations: &[FieldOp] = match op {
        SemanticOp::SubstituteSignature { pre_mutations, .. } => pre_mutations,
        SemanticOp::SubstitutePayload { pre_mutations, .. } => pre_mutations,
        SemanticOp::SubstituteKeyAndResign { pre_mutations, .. } => pre_mutations,
        _ => &[],
    };
    for pm in pre_mutations {
        apply_field_op(bundle, pm)?;
    }

    match op {
        SemanticOp::RecanonicalizeJcs { target } => recanonicalize_jcs(bundle, target),
        SemanticOp::SubstituteKeyAndResign {
            target, keypair, ..
        } => substitute_key_and_resign(bundle, target, keypair, ctx),
        SemanticOp::SubstituteSignature { .. }
        | SemanticOp::SubstitutePayload { .. }
        | SemanticOp::ReplayFrom { .. } => Err(MutationError::NotImplemented(
            "substitute_signature/payload/replay_from — first scenario using this will drive the implementation".to_string(),
        )),
    }
}

fn recanonicalize_jcs(bundle: &mut Value, target: &str) -> Result<(), MutationError> {
    let jcs_path = format!("{target}.payload_jcs");
    let jcs_value = walk_path(bundle, &jcs_path)
        .ok_or_else(|| MutationError::PathNotFound(jcs_path.clone()))?;
    let jcs_str = jcs_value
        .as_str()
        .ok_or_else(|| MutationError::PathNotFound(format!("{jcs_path} (not a string)")))?;
    let parsed: Value = serde_json::from_str(jcs_str)
        .map_err(|_| MutationError::PathNotFound(format!("{jcs_path} (not valid JSON)")))?;
    let reserialized = non_canonical_serialize(&parsed);
    *jcs_value = Value::String(reserialized);
    Ok(())
}

/// Serialize JSON with keys in reverse alphabetical order — deliberately
/// non-canonical. A signature valid over the canonical form should fail
/// verification against this reordered form.
fn non_canonical_serialize(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| b.0.cmp(a.0)); // reverse alphabetical
            let parts: Vec<String> = entries
                .iter()
                .map(|(k, v)| format!("\"{}\":{}", k, non_canonical_serialize(v)))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(non_canonical_serialize).collect();
            format!("[{}]", parts.join(","))
        }
        _ => value.to_string(),
    }
}

fn substitute_key_and_resign(
    bundle: &mut Value,
    target: &str,
    keypair_name: &str,
    ctx: &CatalogContext,
) -> Result<(), MutationError> {
    let signing_key = ctx.keypairs.get(keypair_name).ok_or_else(|| {
        MutationError::PathNotFound(format!("keypair '{keypair_name}' not in context"))
    })?;

    let jcs_path = format!("{target}.payload_jcs");
    let sig_path = format!("{target}.signature_hex");

    // Read the JCS payload (pre_mutations may have already modified it)
    let jcs_str = walk_path(bundle, &jcs_path)
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .ok_or_else(|| MutationError::PathNotFound(jcs_path.clone()))?;

    // Sign with the attacker's key
    let new_sig_bytes = signing_key.sign(jcs_str.as_bytes()).to_bytes();
    let new_sig_hex = hex::encode(new_sig_bytes);

    // Write the new signature
    let sig_value = walk_path(bundle, &sig_path)
        .ok_or_else(|| MutationError::PathNotFound(sig_path.clone()))?;
    *sig_value = Value::String(new_sig_hex);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_bundle() -> Value {
        json!({
            "lock_receipt": {
                "signature_hex": "aabbccddeeff0011",
                "payload_jcs": "{\"a\":1,\"b\":2,\"c\":3}"
            },
            "entries": [
                { "id": "ticket-1", "weight": 1 },
                { "id": "ticket-2", "weight": 1 }
            ]
        })
    }

    // ==================== Field op tests ====================

    #[test]
    fn byte_flip_xors_hex_byte_at_offset() {
        let mut bundle = sample_bundle();
        let op = FieldOp::ByteFlip {
            path: "lock_receipt.signature_hex".to_string(),
            offset: 0,
        };
        apply_field_op(&mut bundle, &op).unwrap();
        // byte 0xaa XOR 0xff = 0x55
        assert_eq!(
            bundle["lock_receipt"]["signature_hex"].as_str().unwrap(),
            "55bbccddeeff0011"
        );
    }

    #[test]
    fn set_value_replaces_target_field() {
        let mut bundle = sample_bundle();
        let op = FieldOp::SetValue {
            path: "lock_receipt.signature_hex".to_string(),
            value: json!("ffff"),
        };
        apply_field_op(&mut bundle, &op).unwrap();
        assert_eq!(
            bundle["lock_receipt"]["signature_hex"].as_str().unwrap(),
            "ffff"
        );
    }

    #[test]
    fn remove_deletes_field() {
        let mut bundle = sample_bundle();
        let op = FieldOp::Remove {
            path: "lock_receipt.signature_hex".to_string(),
        };
        apply_field_op(&mut bundle, &op).unwrap();
        assert!(bundle["lock_receipt"].get("signature_hex").is_none());
    }

    #[test]
    fn add_inserts_new_field() {
        let mut bundle = sample_bundle();
        let op = FieldOp::Add {
            path: "lock_receipt.new_field".to_string(),
            value: json!("hello"),
        };
        apply_field_op(&mut bundle, &op).unwrap();
        assert_eq!(
            bundle["lock_receipt"]["new_field"].as_str().unwrap(),
            "hello"
        );
    }

    #[test]
    fn reorder_shuffles_array() {
        let mut bundle = sample_bundle();
        let op = FieldOp::Reorder {
            path: "entries".to_string(),
            ordering: vec![1, 0],
        };
        apply_field_op(&mut bundle, &op).unwrap();
        assert_eq!(bundle["entries"][0]["id"].as_str().unwrap(), "ticket-2");
        assert_eq!(bundle["entries"][1]["id"].as_str().unwrap(), "ticket-1");
    }

    #[test]
    fn unknown_path_is_an_error() {
        let mut bundle = sample_bundle();
        let op = FieldOp::SetValue {
            path: "does.not.exist".to_string(),
            value: json!("x"),
        };
        let err = apply_field_op(&mut bundle, &op).unwrap_err();
        assert!(err.to_string().contains("does.not.exist"));
    }

    #[test]
    fn byte_flip_offset_out_of_range() {
        let mut bundle = sample_bundle();
        let op = FieldOp::ByteFlip {
            path: "lock_receipt.signature_hex".to_string(),
            offset: 999,
        };
        let err = apply_field_op(&mut bundle, &op).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    // ==================== Semantic op tests ====================

    #[test]
    fn recanonicalize_jcs_reorders_object_keys() {
        let mut bundle = sample_bundle();
        let op = SemanticOp::RecanonicalizeJcs {
            target: "lock_receipt".to_string(),
        };
        apply_semantic_op(&mut bundle, &op, &CatalogContext::new()).unwrap();
        let new_jcs = bundle["lock_receipt"]["payload_jcs"].as_str().unwrap();
        // Should be reordered (reverse alphabetical)
        assert!(
            new_jcs.starts_with("{\"c\":"),
            "expected reverse-alpha ordering, got: {new_jcs}"
        );
        // Same content when parsed
        let parsed: Value = serde_json::from_str(new_jcs).unwrap();
        assert_eq!(parsed["a"], 1);
        assert_eq!(parsed["b"], 2);
        assert_eq!(parsed["c"], 3);
    }

    #[test]
    fn substitute_key_and_resign_produces_valid_signature() {
        use crate::catalog::keypairs::derive_keypair;

        let attacker_key = derive_keypair("attacker_a_v1");
        let mut ctx = CatalogContext::new();
        ctx.keypairs
            .insert("attacker_a".to_string(), attacker_key.clone());

        let mut bundle = sample_bundle();
        let op = SemanticOp::SubstituteKeyAndResign {
            target: "lock_receipt".to_string(),
            keypair: "attacker_a".to_string(),
            pre_mutations: vec![],
        };
        apply_semantic_op(&mut bundle, &op, &ctx).unwrap();

        // The signature should now be valid under the attacker's key
        let jcs = bundle["lock_receipt"]["payload_jcs"].as_str().unwrap();
        let sig_hex = bundle["lock_receipt"]["signature_hex"].as_str().unwrap();
        let sig_bytes: [u8; 64] = hex::decode(sig_hex).unwrap().try_into().unwrap();

        use ed25519_dalek::Verifier;
        attacker_key
            .verifying_key()
            .verify(
                jcs.as_bytes(),
                &ed25519_dalek::Signature::from_bytes(&sig_bytes),
            )
            .expect("signature should verify under attacker's key");
    }
}
