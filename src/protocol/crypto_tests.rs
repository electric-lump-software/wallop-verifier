use super::*;
use sha2::{Digest, Sha256};

// RFC 8032 test keypair (same as Elixir frozen vectors)
const TEST_PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

// V-4: Ed25519 verify — fixed key + fixed payload produces fixed signature
#[test]
fn v4_verify_receipt_valid_signature() {
    let payload = r#"{"hello":"world"}"#;
    let signature_hex = "b86d1d6a0ac79fd8af966d14191c6dab4f85a16310d9b079ce2a0cabb6301e4e0f52c5c9c85053232eb46aa039f2cfcea0b669554e51c41c9cfef534cd2e570c";
    let signature: [u8; 64] = hex::decode(signature_hex).unwrap().try_into().unwrap();

    assert!(verify_receipt(
        payload.as_bytes(),
        &signature,
        &TEST_PUBLIC_KEY
    ));
}

// V-4: tampered payload does not verify
#[test]
fn v4_verify_receipt_tampered_payload() {
    let payload = r#"{"hello":"world"}"#;
    let tampered = format!("{}x", payload);
    let signature_hex = "b86d1d6a0ac79fd8af966d14191c6dab4f85a16310d9b079ce2a0cabb6301e4e0f52c5c9c85053232eb46aa039f2cfcea0b669554e51c41c9cfef534cd2e570c";
    let signature: [u8; 64] = hex::decode(signature_hex).unwrap().try_into().unwrap();

    assert!(!verify_receipt(
        tampered.as_bytes(),
        &signature,
        &TEST_PUBLIC_KEY
    ));
}

// V-4: wrong key does not verify
#[test]
fn v4_verify_receipt_wrong_key() {
    let payload = r#"{"hello":"world"}"#;
    let signature_hex = "b86d1d6a0ac79fd8af966d14191c6dab4f85a16310d9b079ce2a0cabb6301e4e0f52c5c9c85053232eb46aa039f2cfcea0b669554e51c41c9cfef534cd2e570c";
    let signature: [u8; 64] = hex::decode(signature_hex).unwrap().try_into().unwrap();

    let wrong_key = [0u8; 32];
    assert!(!verify_receipt(payload.as_bytes(), &signature, &wrong_key));
}

// V-8: key_id — deterministic 8-char hex fingerprint
#[test]
fn v8_key_id_pinned() {
    assert_eq!(key_id(&TEST_PUBLIC_KEY), "21fe31df");
}

// key_id is first 4 bytes of SHA-256(public_key) hex-encoded
#[test]
fn key_id_matches_sha256_prefix() {
    let hash = Sha256::digest(TEST_PUBLIC_KEY);
    let full_hex = hex::encode(hash);
    assert_eq!(key_id(&TEST_PUBLIC_KEY), &full_hex[..8]);
}
