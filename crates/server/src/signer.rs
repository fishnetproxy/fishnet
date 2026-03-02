use async_trait::async_trait;
use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use k256::ecdsa::{RecoveryId, SigningKey, signature::hazmat::PrehashSigner};
use serde::Serialize;
use sha3::{Digest, Keccak256};

use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
pub struct SignerInfo {
    pub mode: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FishnetPermit {
    pub wallet: String,
    pub chain_id: u64,
    pub nonce: u64,
    pub expiry: u64,
    pub target: String,
    pub value: String,
    pub calldata_hash: String,
    pub policy_hash: Option<String>,
    pub verifying_contract: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("invalid hex for {field}: {reason}")]
    HexDecode { field: &'static str, reason: String },
    #[error("invalid {field} length: expected {expected} bytes, got {actual}")]
    InvalidFieldLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("invalid permit value: {0}")]
    ParsePermitValue(String),
}

#[async_trait]
pub trait SignerTrait: Send + Sync {
    async fn sign_permit(&self, permit: &FishnetPermit) -> Result<Vec<u8>, SignerError>;
    fn status(&self) -> SignerInfo;
}

pub struct StubSigner {
    signing_key: SigningKey,
    address: [u8; 20],
}

impl Default for StubSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl StubSigner {
    pub fn new() -> Self {
        let secret_bytes: [u8; 32] = rand::random();
        Self::from_bytes(secret_bytes)
    }

    pub fn from_bytes(secret_bytes: [u8; 32]) -> Self {
        let signing_key =
            SigningKey::from_bytes((&secret_bytes).into()).expect("valid 32-byte key");
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_encoded_point(false);
        let hash = Keccak256::digest(&public_key_bytes.as_bytes()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        Self {
            signing_key,
            address,
        }
    }

    fn decode_hex_field(value: &str, field: &'static str) -> Result<Vec<u8>, SignerError> {
        hex::decode(value.strip_prefix("0x").unwrap_or(value)).map_err(|e| SignerError::HexDecode {
            field,
            reason: e.to_string(),
        })
    }

    fn eip712_hash(&self, permit: &FishnetPermit) -> Result<[u8; 32], SignerError> {
        let domain_type_hash = Keccak256::digest(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        let name_hash = Keccak256::digest(b"FishnetPermit");
        let version_hash = Keccak256::digest(b"1");

        let mut domain_data = Vec::new();
        domain_data.extend_from_slice(&domain_type_hash);
        domain_data.extend_from_slice(&name_hash);
        domain_data.extend_from_slice(&version_hash);

        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[24..].copy_from_slice(&permit.chain_id.to_be_bytes());
        domain_data.extend_from_slice(&chain_id_bytes);

        let vc_bytes = Self::decode_hex_field(&permit.verifying_contract, "verifying_contract")?;
        let mut vc_padded = [0u8; 32];
        if vc_bytes.len() <= 32 {
            vc_padded[32 - vc_bytes.len()..].copy_from_slice(&vc_bytes);
        }
        domain_data.extend_from_slice(&vc_padded);
        let domain_separator = Keccak256::digest(&domain_data);

        let permit_type_hash = Keccak256::digest(
            b"FishnetPermit(address wallet,uint256 chainId,uint256 nonce,uint256 expiry,address target,uint256 value,bytes32 calldataHash,bytes32 policyHash)"
        );

        let mut struct_data = Vec::new();
        struct_data.extend_from_slice(&permit_type_hash);

        let wallet_bytes = Self::decode_hex_field(&permit.wallet, "wallet")?;
        let mut wallet_padded = [0u8; 32];
        if wallet_bytes.len() <= 32 {
            wallet_padded[32 - wallet_bytes.len()..].copy_from_slice(&wallet_bytes);
        }
        struct_data.extend_from_slice(&wallet_padded);

        struct_data.extend_from_slice(&chain_id_bytes);

        let mut nonce_bytes = [0u8; 32];
        nonce_bytes[24..].copy_from_slice(&permit.nonce.to_be_bytes());
        struct_data.extend_from_slice(&nonce_bytes);

        let mut expiry_bytes = [0u8; 32];
        expiry_bytes[24..].copy_from_slice(&permit.expiry.to_be_bytes());
        struct_data.extend_from_slice(&expiry_bytes);

        let target_bytes = Self::decode_hex_field(&permit.target, "target")?;
        if target_bytes.len() != 20 {
            return Err(SignerError::InvalidFieldLength {
                field: "target",
                expected: 20,
                actual: target_bytes.len(),
            });
        }
        let mut target_padded = [0u8; 32];
        target_padded[12..].copy_from_slice(&target_bytes);
        struct_data.extend_from_slice(&target_padded);

        let value_u256 = alloy_primitives::U256::from_str_radix(&permit.value, 10)
            .map_err(|e| SignerError::ParsePermitValue(e.to_string()))?;
        struct_data.extend_from_slice(&value_u256.to_be_bytes::<32>());

        let calldata_hash_bytes = Self::decode_hex_field(&permit.calldata_hash, "calldata_hash")?;
        if calldata_hash_bytes.len() != 32 {
            return Err(SignerError::InvalidFieldLength {
                field: "calldata_hash",
                expected: 32,
                actual: calldata_hash_bytes.len(),
            });
        }
        let mut calldata_padded = [0u8; 32];
        calldata_padded.copy_from_slice(&calldata_hash_bytes);
        struct_data.extend_from_slice(&calldata_padded);

        let policy_padded = match &permit.policy_hash {
            Some(ph) => {
                let ph_bytes = Self::decode_hex_field(ph, "policy_hash")?;
                if ph_bytes.len() != 32 {
                    return Err(SignerError::InvalidFieldLength {
                        field: "policy_hash",
                        expected: 32,
                        actual: ph_bytes.len(),
                    });
                }
                let mut padded = [0u8; 32];
                padded.copy_from_slice(&ph_bytes);
                padded
            }
            None => [0u8; 32],
        };
        struct_data.extend_from_slice(&policy_padded);

        let struct_hash = Keccak256::digest(&struct_data);

        let mut final_data = Vec::with_capacity(66);
        final_data.push(0x19);
        final_data.push(0x01);
        final_data.extend_from_slice(&domain_separator);
        final_data.extend_from_slice(&struct_hash);

        let result = Keccak256::digest(&final_data);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Ok(hash)
    }
}

#[async_trait]
impl SignerTrait for StubSigner {
    async fn sign_permit(&self, permit: &FishnetPermit) -> Result<Vec<u8>, SignerError> {
        let hash = self.eip712_hash(permit)?;
        let (signature, recovery_id): (k256::ecdsa::Signature, RecoveryId) = self
            .signing_key
            .sign_prehash(&hash)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(&signature.to_bytes());
        sig_bytes.push(recovery_id.to_byte() + 27);
        Ok(sig_bytes)
    }

    fn status(&self) -> SignerInfo {
        SignerInfo {
            mode: "stub-secp256k1".to_string(),
            address: format!("0x{}", hex::encode(self.address)),
        }
    }
}

pub async fn status_handler(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.config();

    if !config.onchain.enabled {
        return Json(serde_json::json!({
            "enabled": false,
            "mode": null,
            "address": null,
            "chain_ids": [],
            "config": {},
            "stats": {},
        }));
    }

    let signer_info = state.signer.status();
    let stats = state
        .spend_store
        .get_onchain_stats()
        .await
        .unwrap_or_default();

    Json(serde_json::json!({
        "enabled": true,
        "mode": signer_info.mode,
        "address": signer_info.address,
        "chain_ids": config.onchain.chain_ids,
        "config": {
            "max_tx_value_usd": config.onchain.limits.max_tx_value_usd,
            "daily_spend_cap_usd": config.onchain.limits.daily_spend_cap_usd,
            "cooldown_seconds": config.onchain.limits.cooldown_seconds,
            "max_slippage_bps": config.onchain.limits.max_slippage_bps,
            "permit_expiry_seconds": config.onchain.permits.expiry_seconds,
        },
        "stats": {
            "total_permits_signed": stats.total_signed,
            "total_permits_denied": stats.total_denied,
            "spent_today_usd": stats.spent_today_usd,
            "last_permit_at": stats.last_permit_at,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_permit() -> FishnetPermit {
        FishnetPermit {
            wallet: "0x1111111111111111111111111111111111111111".to_string(),
            chain_id: 1,
            nonce: 1,
            expiry: 1_700_000_000,
            target: "0x2222222222222222222222222222222222222222".to_string(),
            value: "1".to_string(),
            calldata_hash: format!("0x{}", "aa".repeat(32)),
            policy_hash: Some(format!("0x{}", "bb".repeat(32))),
            verifying_contract: "0x3333333333333333333333333333333333333333".to_string(),
        }
    }

    #[tokio::test]
    async fn sign_permit_rejects_invalid_wallet_hex() {
        let signer = StubSigner::new();
        let mut permit = sample_permit();
        permit.wallet = "0xnothex".to_string();
        let err = signer.sign_permit(&permit).await.unwrap_err();
        match err {
            SignerError::HexDecode { field, .. } => assert_eq!(field, "wallet"),
            _ => panic!("expected hex decode error for wallet"),
        }
    }

    #[tokio::test]
    async fn sign_permit_rejects_invalid_calldata_hash_hex() {
        let signer = StubSigner::new();
        let mut permit = sample_permit();
        permit.calldata_hash = "0xzz".to_string();
        let err = signer.sign_permit(&permit).await.unwrap_err();
        match err {
            SignerError::HexDecode { field, .. } => assert_eq!(field, "calldata_hash"),
            _ => panic!("expected hex decode error for calldata_hash"),
        }
    }

    #[tokio::test]
    async fn sign_permit_rejects_invalid_calldata_hash_length() {
        let signer = StubSigner::new();
        let mut permit = sample_permit();
        permit.calldata_hash = format!("0x{}", "aa".repeat(31));
        let err = signer.sign_permit(&permit).await.unwrap_err();
        match err {
            SignerError::InvalidFieldLength {
                field,
                expected,
                actual,
            } => {
                assert_eq!(field, "calldata_hash");
                assert_eq!(expected, 32);
                assert_eq!(actual, 31);
            }
            _ => panic!("expected invalid field length error for calldata_hash"),
        }
    }

    #[tokio::test]
    async fn sign_permit_rejects_invalid_value() {
        let signer = StubSigner::new();
        let mut permit = sample_permit();
        permit.value = "not-a-number".to_string();
        let err = signer.sign_permit(&permit).await.unwrap_err();
        match err {
            SignerError::ParsePermitValue(_) => {}
            _ => panic!("expected parse permit value error"),
        }
    }

    #[tokio::test]
    async fn sign_permit_rejects_invalid_target_length() {
        let signer = StubSigner::new();
        let mut permit = sample_permit();
        permit.target = format!("0x{}", "22".repeat(19));
        let err = signer.sign_permit(&permit).await.unwrap_err();
        match err {
            SignerError::InvalidFieldLength {
                field,
                expected,
                actual,
            } => {
                assert_eq!(field, "target");
                assert_eq!(expected, 20);
                assert_eq!(actual, 19);
            }
            _ => panic!("expected invalid field length error for target"),
        }
    }

    #[tokio::test]
    async fn sign_permit_rejects_invalid_policy_hash_length() {
        let signer = StubSigner::new();
        let mut permit = sample_permit();
        permit.policy_hash = Some(format!("0x{}", "bb".repeat(31)));
        let err = signer.sign_permit(&permit).await.unwrap_err();
        match err {
            SignerError::InvalidFieldLength {
                field,
                expected,
                actual,
            } => {
                assert_eq!(field, "policy_hash");
                assert_eq!(expected, 32);
                assert_eq!(actual, 31);
            }
            _ => panic!("expected invalid field length error for policy_hash"),
        }
    }
}
