use super::*;
use sha2::{Digest, Sha256};

// V-9: empty list sentinel
#[test]
fn v9_merkle_root_empty() {
    let expected: [u8; 32] = Sha256::digest(b"").into();
    assert_eq!(merkle_root(&[]), expected);
}

// V-9: single leaf
#[test]
fn v9_merkle_root_single_leaf() {
    let leaf = b"abc";
    let mut input = vec![0u8];
    input.extend_from_slice(leaf);
    let expected: [u8; 32] = Sha256::digest(&input).into();
    assert_eq!(merkle_root(&[leaf.as_slice()]), expected);
}

// V-9: two leaves pinned
#[test]
fn v9_merkle_root_two_leaves() {
    let root = merkle_root(&[b"a", b"b"]);
    assert_eq!(
        hex::encode(root),
        "b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb"
    );
}

// V-9: 16 leaves pinned
#[test]
fn v9_merkle_root_16_leaves() {
    let strings: Vec<String> = (1..=16).map(|i| i.to_string()).collect();
    let leaves: Vec<&[u8]> = strings.iter().map(|s| s.as_bytes()).collect();
    let root = merkle_root(&leaves);
    assert_eq!(
        hex::encode(root),
        "5b20458a9dfa66ab1990467a95cbd7af502caf09cd2ff620725cdb314b52d443"
    );
}

// V-10: anchor combined root pinned
#[test]
fn v10_anchor_root_pinned() {
    let op_root: [u8; 32] = Sha256::digest(b"operator-receipts-sentinel").into();
    let exec_root: [u8; 32] = Sha256::digest(b"execution-receipts-sentinel").into();

    assert_eq!(
        hex::encode(op_root),
        "15608de04e527005cd03f96a456269aaf9dc068996612d7f5b2ea11d0bc453ac"
    );
    assert_eq!(
        hex::encode(exec_root),
        "f83eba0b2ff61a29603ce50f0a69573944108cc876a461e881d6dbb2270204c2"
    );

    let combined = anchor_root(&op_root, &exec_root);
    assert_eq!(
        hex::encode(combined),
        "3512c7c5af6f533c5acc9aa42b1368b9c42a7bf265229df5083166740d0e130f"
    );
}

// V-10: prefix is raw UTF-8 bytes, not length-prefixed
#[test]
fn v10_anchor_root_prefix_is_raw_utf8() {
    let dummy = [0u8; 32];
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(b"wallop-anchor-v1");
    hasher_input.extend_from_slice(&dummy);
    hasher_input.extend_from_slice(&dummy);
    let expected: [u8; 32] = Sha256::digest(&hasher_input).into();

    assert_eq!(anchor_root(&dummy, &dummy), expected);
}
