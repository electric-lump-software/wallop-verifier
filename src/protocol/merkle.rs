use sha2::{Digest, Sha256};

pub fn merkle_root(leaves: &[&[u8]]) -> [u8; 32] {
    if leaves.is_empty() {
        return Sha256::digest(b"").into();
    }

    let mut nodes: Vec<[u8; 32]> = leaves
        .iter()
        .map(|leaf| {
            let mut input = vec![0u8]; // 0x00 prefix for leaves
            input.extend_from_slice(leaf);
            Sha256::digest(&input).into()
        })
        .collect();

    while nodes.len() > 1 {
        nodes = pair_up(&nodes)
            .iter()
            .map(|(l, r)| {
                let mut input = vec![1u8]; // 0x01 prefix for internal nodes
                input.extend_from_slice(l);
                input.extend_from_slice(r);
                Sha256::digest(&input).into()
            })
            .collect();
    }

    nodes[0]
}

fn pair_up(nodes: &[[u8; 32]]) -> Vec<([u8; 32], [u8; 32])> {
    let mut pairs = Vec::new();
    let mut i = 0;
    while i < nodes.len() {
        if i + 1 < nodes.len() {
            pairs.push((nodes[i], nodes[i + 1]));
            i += 2;
        } else {
            // Odd node: duplicate (RFC 6962 §2.1)
            pairs.push((nodes[i], nodes[i]));
            i += 1;
        }
    }
    pairs
}

pub fn anchor_root(operator_root: &[u8; 32], execution_root: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(b"wallop-anchor-v1");
    input.extend_from_slice(operator_root);
    input.extend_from_slice(execution_root);
    Sha256::digest(&input).into()
}

#[cfg(test)]
#[path = "merkle_tests.rs"]
mod tests;
