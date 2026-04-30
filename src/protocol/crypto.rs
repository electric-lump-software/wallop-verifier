use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub fn verify_receipt(payload_jcs: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let signature = Signature::from_bytes(signature);
    use ed25519_dalek::Verifier;
    verifying_key.verify(payload_jcs, &signature).is_ok()
}

pub fn key_id(public_key: &[u8; 32]) -> String {
    let hash = Sha256::digest(public_key);
    hex::encode(&hash[..4])
}

#[cfg(test)]
#[path = "crypto_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "key_rotation_tests.rs"]
mod key_rotation_tests;
