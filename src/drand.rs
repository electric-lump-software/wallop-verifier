use sha2::{Digest, Sha256};

/// Drand quicknet (unchained, G1 sigs / G2 pubkey, RFC 9380) -- pinned at compile time.
pub const QUICKNET_CHAIN_HASH: &str =
    "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";

pub const QUICKNET_PUBLIC_KEY_HEX: &str =
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c\
     8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb\
     5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";

#[derive(Debug)]
pub enum DrandError {
    UnknownChain(String),
    InvalidSignature,
    RandomnessMismatch { expected: String, got: String },
    HexDecode(String),
}

impl std::fmt::Display for DrandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DrandError::UnknownChain(h) => write!(f, "unknown drand chain: {h}"),
            DrandError::InvalidSignature => write!(f, "BLS signature verification failed"),
            DrandError::RandomnessMismatch { expected, got } => {
                write!(f, "randomness mismatch: expected {expected}, got {got}")
            }
            DrandError::HexDecode(e) => write!(f, "hex decode error: {e}"),
        }
    }
}

/// Verify a drand round: check chain is known, BLS sig is valid, sha256(sig) == randomness.
pub fn verify_drand_round(
    chain_hash: &str,
    round: u64,
    signature_hex: &str,
    randomness_hex: &str,
) -> Result<(), DrandError> {
    // Step 1: Reject unknown chains
    if chain_hash != QUICKNET_CHAIN_HASH {
        return Err(DrandError::UnknownChain(chain_hash.to_string()));
    }

    // Step 2: Decode inputs
    let pk_bytes = hex::decode(QUICKNET_PUBLIC_KEY_HEX)
        .map_err(|e| DrandError::HexDecode(e.to_string()))?;
    let sig_bytes =
        hex::decode(signature_hex).map_err(|e| DrandError::HexDecode(e.to_string()))?;

    // Step 3: BLS verification using drand-verify
    // Quicknet uses scheme "bls-unchained-g1-rfc9380":
    //   - Public key lives on G2 (96 bytes) -> G2PubkeyRfc
    //   - Signatures live on G1 (48 bytes)
    //   - Unchained mode: previous_signature is empty
    use drand_verify::{G2PubkeyRfc, Pubkey};

    let pk_array: [u8; 96] = pk_bytes
        .try_into()
        .map_err(|_| DrandError::HexDecode("public key is not 96 bytes".to_string()))?;

    let pk = G2PubkeyRfc::from_fixed(pk_array).map_err(|_| DrandError::InvalidSignature)?;

    let valid = pk
        .verify(round, b"", &sig_bytes)
        .map_err(|_| DrandError::InvalidSignature)?;

    if !valid {
        return Err(DrandError::InvalidSignature);
    }

    // Step 4: Confirm sha256(signature) == randomness
    let computed_randomness = hex::encode(Sha256::digest(&sig_bytes));
    if computed_randomness != randomness_hex {
        return Err(DrandError::RandomnessMismatch {
            expected: randomness_hex.to_string(),
            got: computed_randomness,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_chain() {
        let result = verify_drand_round("0000", 1, "ab", "cd");
        assert!(matches!(result, Err(DrandError::UnknownChain(_))));
    }

    #[test]
    fn rejects_corrupted_signature() {
        let result = verify_drand_round(
            QUICKNET_CHAIN_HASH,
            1,
            &"ff".repeat(48),
            &"00".repeat(32),
        );
        assert!(matches!(result, Err(DrandError::InvalidSignature)));
    }
}
