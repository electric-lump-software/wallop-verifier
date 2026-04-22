use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ProofBundle {
    pub version: u32,
    pub draw_id: String,
    pub entries: Vec<BundleEntry>,
    pub results: Vec<BundleResult>,
    pub entropy: Entropy,
    pub lock_receipt: ReceiptBlock,
    pub execution_receipt: ReceiptBlock,
}

#[derive(Debug, Deserialize)]
pub struct BundleEntry {
    pub uuid: String,
    pub weight: u32,
}

#[derive(Debug, Deserialize)]
pub struct BundleResult {
    pub entry_id: String,
    pub position: u32,
}

#[derive(Debug, Deserialize)]
pub struct Entropy {
    pub drand_round: u64,
    pub drand_randomness: String,
    pub drand_signature: String,
    pub drand_chain_hash: String,
    pub weather_value: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReceiptBlock {
    pub payload_jcs: String,
    pub signature_hex: String,
    #[serde(
        alias = "operator_public_key_hex",
        alias = "infrastructure_public_key_hex"
    )]
    pub public_key_hex: String,
}

impl ProofBundle {
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("invalid proof bundle: {e}"))
    }

    pub fn is_drand_only(&self) -> bool {
        self.entropy.weather_value.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_bundle_json() -> String {
        serde_json::json!({
            "version": 1,
            "draw_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "entries": [
                {"uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "weight": 1},
                {"uuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "weight": 2}
            ],
            "results": [{"entry_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "position": 1}],
            "entropy": {
                "drand_round": 12345,
                "drand_randomness": "abababababababababababababababababababababababababababababababababab",
                "drand_signature": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                "drand_chain_hash": "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
                "weather_value": "1013"
            },
            "lock_receipt": {
                "payload_jcs": "{\"entry_hash\":\"abc\"}",
                "signature_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "operator_public_key_hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            },
            "execution_receipt": {
                "payload_jcs": "{\"seed\":\"def\"}",
                "signature_hex": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "infrastructure_public_key_hex": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            }
        }).to_string()
    }

    #[test]
    fn parses_valid_bundle() {
        let bundle = ProofBundle::from_json(&minimal_bundle_json()).unwrap();
        assert_eq!(bundle.version, 1);
        assert_eq!(bundle.entries.len(), 2);
        assert_eq!(
            bundle.results[0].entry_id,
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        );
        assert!(!bundle.is_drand_only());
    }

    #[test]
    fn parses_drand_only_bundle() {
        let mut val: serde_json::Value = serde_json::from_str(&minimal_bundle_json()).unwrap();
        val["entropy"]
            .as_object_mut()
            .unwrap()
            .remove("weather_value");
        let bundle = ProofBundle::from_json(&val.to_string()).unwrap();
        assert!(bundle.is_drand_only());
    }

    #[test]
    fn rejects_missing_field() {
        let result = ProofBundle::from_json(r#"{"version": 1}"#);
        assert!(result.is_err());
    }

    #[test]
    fn parses_operator_key_field() {
        let json = minimal_bundle_json();
        let bundle = ProofBundle::from_json(&json).unwrap();
        assert_eq!(
            bundle.lock_receipt.public_key_hex,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(
            bundle.execution_receipt.public_key_hex,
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );
    }
}
