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
    #[error("invalid permit: {0}")]
    InvalidPermit(String),
}

const UINT48_MAX: u64 = (1u64 << 48) - 1;

impl FishnetPermit {
    pub fn validate(&self) -> Result<(), SignerError> {
        Self::validate_address(&self.wallet, "wallet")?;
        Self::validate_address(&self.target, "target")?;
        Self::validate_address(&self.verifying_contract, "verifying_contract")?;
        Self::validate_bytes32(&self.calldata_hash, "calldata_hash")?;
        if let Some(ref ph) = self.policy_hash {
            Self::validate_bytes32(ph, "policy_hash")?;
        }
        alloy_primitives::U256::from_str_radix(&self.value, 10)
            .map_err(|_| SignerError::InvalidPermit(
                format!("value '{}' is not a valid uint256", self.value)
            ))?;
        if self.expiry > UINT48_MAX {
            return Err(SignerError::InvalidPermit(
                format!(
                    "expiry {} exceeds uint48 max ({}), would be truncated by Solidity",
                    self.expiry, UINT48_MAX
                )
            ));
        }
        Ok(())
    }

    fn validate_address(field: &str, name: &str) -> Result<(), SignerError> {
        let stripped = field.strip_prefix("0x").unwrap_or(field);
        let bytes = hex::decode(stripped).map_err(|_|
            SignerError::InvalidPermit(format!("{name} '{}' is not valid hex", field))
        )?;
        if bytes.len() != 20 {
            return Err(SignerError::InvalidPermit(
                format!("{name} must be 20 bytes, got {}", bytes.len())
            ));
        }
        Ok(())
    }

    fn validate_bytes32(field: &str, name: &str) -> Result<(), SignerError> {
        let stripped = field.strip_prefix("0x").unwrap_or(field);
        let bytes = hex::decode(stripped).map_err(|_|
            SignerError::InvalidPermit(format!("{name} '{}' is not valid hex", field))
        )?;
        if bytes.len() != 32 {
            return Err(SignerError::InvalidPermit(
                format!("{name} must be 32 bytes, got {}", bytes.len())
            ));
        }
        Ok(())
    }
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

    fn eip712_hash(&self, permit: &FishnetPermit) -> [u8; 32] {
        let domain_type_hash = Keccak256::digest(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        let name_hash = Keccak256::digest(b"Fishnet");
        let version_hash = Keccak256::digest(b"1");

        let mut domain_data = Vec::new();
        domain_data.extend_from_slice(&domain_type_hash);
        domain_data.extend_from_slice(&name_hash);
        domain_data.extend_from_slice(&version_hash);

        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[24..].copy_from_slice(&permit.chain_id.to_be_bytes());
        domain_data.extend_from_slice(&chain_id_bytes);

        let vc_bytes = hex::decode(
            permit.verifying_contract.strip_prefix("0x").unwrap_or(&permit.verifying_contract),
        )
        .unwrap_or_default();
        let mut vc_padded = [0u8; 32];
        if vc_bytes.len() <= 32 {
            vc_padded[32 - vc_bytes.len()..].copy_from_slice(&vc_bytes);
        }
        domain_data.extend_from_slice(&vc_padded);
        let domain_separator = Keccak256::digest(&domain_data);

        let permit_type_hash = Keccak256::digest(
            b"FishnetPermit(address wallet,uint64 chainId,uint256 nonce,uint48 expiry,address target,uint256 value,bytes32 calldataHash,bytes32 policyHash)"
        );

        let mut struct_data = Vec::new();
        struct_data.extend_from_slice(&permit_type_hash);

        let wallet_bytes = hex::decode(permit.wallet.strip_prefix("0x").unwrap_or(&permit.wallet)).unwrap_or_default();
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

        let target_bytes = hex::decode(permit.target.strip_prefix("0x").unwrap_or(&permit.target)).unwrap_or_default();
        let mut target_padded = [0u8; 32];
        if target_bytes.len() <= 32 {
            target_padded[32 - target_bytes.len()..].copy_from_slice(&target_bytes);
        }
        struct_data.extend_from_slice(&target_padded);

        let value_u256 = alloy_primitives::U256::from_str_radix(&permit.value, 10)
            .unwrap_or(alloy_primitives::U256::ZERO);
        struct_data.extend_from_slice(&value_u256.to_be_bytes::<32>());

        let calldata_hash_bytes = hex::decode(permit.calldata_hash.strip_prefix("0x").unwrap_or(&permit.calldata_hash)).unwrap_or_default();
        let mut calldata_padded = [0u8; 32];
        if calldata_hash_bytes.len() == 32 {
            calldata_padded.copy_from_slice(&calldata_hash_bytes);
        }
        struct_data.extend_from_slice(&calldata_padded);

        let policy_padded = match &permit.policy_hash {
            Some(ph) => {
                let ph_bytes = hex::decode(ph.strip_prefix("0x").unwrap_or(ph)).unwrap_or_default();
                let mut padded = [0u8; 32];
                if ph_bytes.len() == 32 {
                    padded.copy_from_slice(&ph_bytes);
                }
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
        hash
    }
}

#[async_trait]
impl SignerTrait for StubSigner {
    async fn sign_permit(&self, permit: &FishnetPermit) -> Result<Vec<u8>, SignerError> {
        permit.validate()?;
        let hash = self.eip712_hash(permit);
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

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::VerifyingKey;

    /// Deterministic signer from a known private key for reproducible tests.
    fn test_signer() -> StubSigner {
        // Anvil account #1: 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
        let key_bytes: [u8; 32] = hex::decode(
            "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
        ).unwrap().try_into().unwrap();
        StubSigner::from_bytes(key_bytes)
    }

    fn test_permit() -> FishnetPermit {
        FishnetPermit {
            wallet: "0x1111111111111111111111111111111111111111".to_string(),
            chain_id: 31337,
            nonce: 1,
            expiry: 1700000000,
            target: "0x2222222222222222222222222222222222222222".to_string(),
            value: "0".to_string(),
            // keccak256(0xdeadbeef)
            calldata_hash: "0xd4fd4e189132273036449fc9e11198c739161b4c0116a9a2dccdfa1c492006f1".to_string(),
            // keccak256("policy-v1")
            policy_hash: Some("0xb2590ce26adfc7f2814ca4b72880660e2369b23d16ffb446362696d8186d6348".to_string()),
            verifying_contract: "0x3333333333333333333333333333333333333333".to_string(),
        }
    }

    #[test]
    fn test_address_derivation() {
        let signer = test_signer();
        let addr = format!("0x{}", hex::encode(signer.address));
        // Anvil account #1 address
        assert_eq!(
            addr.to_lowercase(),
            "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
            "Address derivation must match Anvil account #1"
        );
    }

    #[test]
    fn test_eip712_hash_matches_solidity_reference() {
        // Reference digest computed by `cast` and verified against the deployed contract.
        // See scripts/sc3-integration-test.sh for the full derivation.
        let expected_digest = hex::decode(
            "fab98461d60ccf4decb708d9176202165010b11b742597e64641146072ad2145"
        ).unwrap();

        let signer = test_signer();
        let permit = test_permit();
        let digest = signer.eip712_hash(&permit);

        assert_eq!(
            hex::encode(digest),
            hex::encode(&expected_digest),
            "EIP712 digest must match cast/Solidity reference value"
        );
    }

    #[test]
    fn test_eip712_hash_none_policy_is_zero_bytes() {
        // When policy_hash is None, Rust should encode bytes32(0).
        let expected_digest = hex::decode(
            "d61a0eb9e892785d7b2d77d28389cbad95c7d077cfedf6e9fba0d45b1267ef05"
        ).unwrap();

        let signer = test_signer();
        let mut permit = test_permit();
        permit.policy_hash = None;

        let digest = signer.eip712_hash(&permit);

        assert_eq!(
            hex::encode(digest),
            hex::encode(&expected_digest),
            "None policy_hash must encode as bytes32(0)"
        );
    }

    #[tokio::test]
    async fn test_sign_permit_is_65_bytes_rsv() {
        let signer = test_signer();
        let permit = test_permit();

        let sig = signer.sign_permit(&permit).await.unwrap();

        assert_eq!(sig.len(), 65, "Signature must be exactly 65 bytes (r:32 + s:32 + v:1)");
        let v = sig[64];
        assert!(v == 27 || v == 28, "v byte must be 27 or 28, got {}", v);
    }

    #[tokio::test]
    async fn test_sign_permit_recovers_to_signer_address() {
        let signer = test_signer();
        let permit = test_permit();
        let expected_address = signer.address;

        let sig_bytes = signer.sign_permit(&permit).await.unwrap();
        let digest = signer.eip712_hash(&permit);

        let r = &sig_bytes[0..32];
        let s = &sig_bytes[32..64];
        let v = sig_bytes[64];

        let mut rs_bytes = [0u8; 64];
        rs_bytes[..32].copy_from_slice(r);
        rs_bytes[32..].copy_from_slice(s);
        let signature = k256::ecdsa::Signature::from_slice(&rs_bytes)
            .expect("valid 64-byte r||s");
        let recovery_id = RecoveryId::from_byte(v - 27)
            .expect("valid recovery id");

        let recovered_key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
            .expect("recovery should succeed");

        let pub_bytes = recovered_key.to_encoded_point(false);
        let hash = Keccak256::digest(&pub_bytes.as_bytes()[1..]);
        let mut recovered_address = [0u8; 20];
        recovered_address.copy_from_slice(&hash[12..]);

        assert_eq!(
            recovered_address, expected_address,
            "Recovered address {} must match signer address {}",
            hex::encode(recovered_address),
            hex::encode(expected_address)
        );
    }

    #[test]
    fn test_domain_separator_components() {
        let domain_type_hash = Keccak256::digest(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
        assert_eq!(
            hex::encode(domain_type_hash),
            "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f",
            "Domain typehash must match EIP-712 spec"
        );

        let name_hash = Keccak256::digest(b"Fishnet");
        assert_eq!(
            hex::encode(name_hash),
            "a2ddc2821a1b38ba4750c0831d9a0107ca333ac3d21c113591207c3ad38692e1",
            "Name hash must match keccak256('Fishnet')"
        );

        let permit_type_hash = Keccak256::digest(
            b"FishnetPermit(address wallet,uint64 chainId,uint256 nonce,uint48 expiry,address target,uint256 value,bytes32 calldataHash,bytes32 policyHash)"
        );
        assert_eq!(
            hex::encode(permit_type_hash),
            "c9b0b9ae2da684ebdabf410d61b7a56935bff0fa4a926059abf894606ed05965",
            "Permit typehash must match Solidity PERMIT_TYPEHASH"
        );
    }

    #[test]
    fn test_status_returns_correct_info() {
        let signer = test_signer();
        let info = signer.status();
        assert_eq!(info.mode, "stub-secp256k1");
        assert_eq!(
            info.address.to_lowercase(),
            "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
        );
    }

    // =========================================================================
    // Type range: Rust u64 expiry vs Solidity uint48
    // =========================================================================

    #[test]
    fn test_expiry_at_uint48_max_passes_validation() {
        let mut permit = test_permit();
        permit.expiry = 281474976710655; // type(uint48).max
        assert!(permit.validate().is_ok(), "uint48 max should pass validation");
    }

    #[test]
    fn test_expiry_overflow_uint48_rejected_by_validation() {
        let mut permit = test_permit();
        permit.expiry = 281474976710656; // uint48_max + 1
        let err = permit.validate().unwrap_err();
        assert!(
            err.to_string().contains("exceeds uint48 max"),
            "Overflowing expiry must be rejected: {err}"
        );
    }

    #[tokio::test]
    async fn test_sign_rejects_overflowing_expiry() {
        let signer = test_signer();
        let mut permit = test_permit();
        permit.expiry = 281474976710656;

        let result = signer.sign_permit(&permit).await;
        assert!(result.is_err(), "sign_permit must reject overflowing expiry");
        assert!(result.unwrap_err().to_string().contains("uint48"));
    }

    #[test]
    fn test_nonce_u64_max_passes_validation() {
        let mut permit = test_permit();
        permit.nonce = u64::MAX;
        assert!(permit.validate().is_ok());
    }

    // =========================================================================
    // Input validation: malformed inputs rejected
    // =========================================================================

    #[test]
    fn test_empty_wallet_address_rejected() {
        let mut permit = test_permit();
        permit.wallet = "".to_string();
        let err = permit.validate().unwrap_err();
        assert!(err.to_string().contains("wallet"), "Should mention wallet: {err}");
    }

    #[test]
    fn test_invalid_hex_wallet_rejected() {
        let mut permit = test_permit();
        permit.wallet = "0xZZZZ".to_string();
        let err = permit.validate().unwrap_err();
        assert!(err.to_string().contains("wallet"), "Should mention wallet: {err}");
    }

    #[test]
    fn test_short_wallet_address_rejected() {
        let mut permit = test_permit();
        permit.wallet = "0x01".to_string();
        let err = permit.validate().unwrap_err();
        assert!(
            err.to_string().contains("20 bytes"),
            "Should reject short address: {err}"
        );
    }

    #[test]
    fn test_invalid_hex_calldata_hash_rejected() {
        let mut permit = test_permit();
        permit.calldata_hash = "not_valid_hex".to_string();
        let err = permit.validate().unwrap_err();
        assert!(err.to_string().contains("calldata_hash"), "{err}");
    }

    #[test]
    fn test_short_calldata_hash_rejected() {
        let mut permit = test_permit();
        permit.calldata_hash = "0xaabb".to_string();
        let err = permit.validate().unwrap_err();
        assert!(err.to_string().contains("32 bytes"), "{err}");
    }

    #[test]
    fn test_non_numeric_value_rejected() {
        let mut permit = test_permit();
        permit.value = "abc".to_string();
        let err = permit.validate().unwrap_err();
        assert!(err.to_string().contains("value"), "{err}");
    }

    #[test]
    fn test_malformed_target_address_rejected() {
        let mut permit = test_permit();
        permit.target = "0xZZZZ".to_string();
        let err = permit.validate().unwrap_err();
        assert!(err.to_string().contains("target"), "{err}");
    }

    #[test]
    fn test_malformed_verifying_contract_rejected() {
        let mut permit = test_permit();
        permit.verifying_contract = "bad".to_string();
        let err = permit.validate().unwrap_err();
        assert!(err.to_string().contains("verifying_contract"), "{err}");
    }

    #[test]
    fn test_invalid_policy_hash_rejected() {
        let mut permit = test_permit();
        permit.policy_hash = Some("!!!".to_string());
        let err = permit.validate().unwrap_err();
        assert!(err.to_string().contains("policy_hash"), "{err}");
    }

    #[test]
    fn test_none_policy_hash_passes_validation() {
        let mut permit = test_permit();
        permit.policy_hash = None;
        assert!(permit.validate().is_ok(), "None policy hash should be valid");
    }

    #[tokio::test]
    async fn test_sign_permit_rejects_all_garbage_inputs() {
        let signer = test_signer();
        let permit = FishnetPermit {
            wallet: "garbage".to_string(),
            chain_id: 0,
            nonce: 0,
            expiry: 0,
            target: "also_garbage".to_string(),
            value: "not_a_number".to_string(),
            calldata_hash: "???".to_string(),
            policy_hash: Some("!!!".to_string()),
            verifying_contract: "bad".to_string(),
        };

        let result = signer.sign_permit(&permit).await;
        assert!(result.is_err(), "sign_permit must reject garbage inputs");
        match result.unwrap_err() {
            SignerError::InvalidPermit(msg) => {
                assert!(!msg.is_empty(), "Error should have a message");
            }
            other => panic!("Expected InvalidPermit, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_valid_permit_still_signs_successfully() {
        let signer = test_signer();
        let permit = test_permit();
        let result = signer.sign_permit(&permit).await;
        assert!(result.is_ok(), "Valid permit must sign successfully");
        assert_eq!(result.unwrap().len(), 65);
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
