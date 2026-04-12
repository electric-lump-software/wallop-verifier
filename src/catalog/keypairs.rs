//! Deterministic Ed25519 keypair derivation from seed strings.
//!
//! Algorithm (pinned by the catalog spec — must match across implementations):
//! 1. Hash the seed string's UTF-8 bytes with SHA-256
//! 2. Take the 32-byte hash output
//! 3. Use those 32 bytes as the Ed25519 signing key seed
//!
//! This must produce bit-identical keypairs in Rust, Elixir, and Python
//! implementations or scenario results will diverge silently.

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

/// Derive an Ed25519 signing key deterministically from a seed string.
pub(crate) fn derive_keypair(seed: &str) -> SigningKey {
    let hash = Sha256::digest(seed.as_bytes());
    let seed_bytes: [u8; 32] = hash.into();
    SigningKey::from_bytes(&seed_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let key1 = derive_keypair("attacker_a_v1");
        let key2 = derive_keypair("attacker_a_v1");
        assert_eq!(
            key1.to_bytes(),
            key2.to_bytes(),
            "same seed must produce same key"
        );
    }

    #[test]
    fn different_seeds_yield_different_keys() {
        let a = derive_keypair("attacker_a_v1");
        let b = derive_keypair("attacker_b_v1");
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn attacker_a_v1_public_key_is_pinned() {
        // Pinned snapshot. If this changes, every implementation's catalog
        // results diverge. Update only with cross-implementation coordination.
        let key = derive_keypair("attacker_a_v1");
        let pk_hex = hex::encode(key.verifying_key().to_bytes());
        assert_eq!(
            pk_hex.len(),
            64,
            "Ed25519 public key = 32 bytes = 64 hex chars"
        );
        assert_eq!(
            pk_hex, "ac2fadf21618e2239391105d9862145eb3ac48ed9fefe7fe96d744136da9e129",
            "pinned public key for attacker_a_v1 has changed — this breaks \
             cross-implementation catalog parity"
        );
    }
}
