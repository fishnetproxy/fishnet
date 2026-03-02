use std::sync::atomic::{AtomicI64, Ordering};

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tokio::sync::Mutex;

use crate::alert::{AlertSeverity, AlertType};
use crate::audit::{self, NewAuditEntry};
use crate::signer::FishnetPermit;
use crate::state::AppState;
use crate::webhook;

pub struct OnchainStore {
    last_permit_at: AtomicI64,
    submit_lock: Mutex<()>,
}

impl Default for OnchainStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OnchainStore {
    pub fn new() -> Self {
        Self {
            last_permit_at: AtomicI64::new(0),
            submit_lock: Mutex::new(()),
        }
    }

    pub fn last_permit_at(&self) -> i64 {
        self.last_permit_at.load(Ordering::SeqCst)
    }

    pub fn set_last_permit_at(&self, ts: i64) {
        self.last_permit_at.store(ts, Ordering::SeqCst);
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SubmitRequest {
    pub target: String,
    pub calldata: String,
    pub value: String,
    pub chain_id: u64,
}

struct PolicyDenial {
    reason: String,
    limit: String,
}

#[derive(Clone)]
struct OnchainAuditContext {
    action: String,
    policy_version_hash: audit::merkle::H256,
    intent_hash: audit::merkle::H256,
}

fn check_policy(
    req: &SubmitRequest,
    config: &fishnet_types::config::OnchainConfig,
    onchain_spent_today: f64,
    last_permit_at: i64,
) -> Result<(), PolicyDenial> {
    if config.chain_ids.is_empty() || !config.chain_ids.contains(&req.chain_id) {
        return Err(PolicyDenial {
            reason: format!("chain_id {} not in allowed list", req.chain_id),
            limit: "chain_id".to_string(),
        });
    }

    let target_lower = req.target.to_lowercase();
    let whitelist_entry = config
        .whitelist
        .iter()
        .find(|(addr, _)| addr.to_lowercase() == target_lower);

    let allowed_selectors = match whitelist_entry {
        Some((_, selectors)) => selectors,
        None => {
            return Err(PolicyDenial {
                reason: format!("contract {} not in whitelist", req.target),
                limit: "whitelist".to_string(),
            });
        }
    };

    let calldata_hex = req.calldata.strip_prefix("0x").unwrap_or(&req.calldata);
    if calldata_hex.len() >= 8 {
        let fn_selector = &calldata_hex[..8];
        let selector_matches = allowed_selectors.iter().any(|sel| {
            let sel_trimmed = sel.strip_prefix("0x").unwrap_or(sel);
            if sel_trimmed.len() == 8 && sel_trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                sel_trimmed.to_lowercase() == fn_selector.to_lowercase()
            } else {
                let hash = Keccak256::digest(sel.as_bytes());
                let computed = hex::encode(&hash[..4]);
                computed == fn_selector.to_lowercase()
            }
        });

        if !selector_matches {
            return Err(PolicyDenial {
                reason: format!(
                    "function selector 0x{} not allowed for contract {}",
                    fn_selector, req.target
                ),
                limit: "function_selector".to_string(),
            });
        }
    } else if !calldata_hex.is_empty() {
        return Err(PolicyDenial {
            reason: "calldata too short to contain function selector".to_string(),
            limit: "calldata".to_string(),
        });
    }

    if config.limits.max_tx_value_usd > 0.0 {
        let tx_value: f64 = req.value.parse().unwrap_or(0.0);
        if tx_value > config.limits.max_tx_value_usd {
            return Err(PolicyDenial {
                reason: format!(
                    "tx value {} exceeds max_tx_value_usd {}",
                    tx_value, config.limits.max_tx_value_usd
                ),
                limit: "max_tx_value_usd".to_string(),
            });
        }
    }

    if config.limits.daily_spend_cap_usd > 0.0 {
        let tx_value: f64 = req.value.parse().unwrap_or(0.0);
        if onchain_spent_today + tx_value > config.limits.daily_spend_cap_usd {
            return Err(PolicyDenial {
                reason: format!(
                    "daily spend would exceed cap: {:.2} + {:.2} > {:.2}",
                    onchain_spent_today, tx_value, config.limits.daily_spend_cap_usd
                ),
                limit: "daily_spend_cap_usd".to_string(),
            });
        }
    }

    if config.limits.cooldown_seconds > 0 {
        let now = chrono::Utc::now().timestamp();
        let elapsed = now - last_permit_at;
        if last_permit_at > 0 && elapsed < config.limits.cooldown_seconds as i64 {
            return Err(PolicyDenial {
                reason: format!(
                    "cooldown active: {}s remaining",
                    config.limits.cooldown_seconds as i64 - elapsed
                ),
                limit: "cooldown".to_string(),
            });
        }
    }

    Ok(())
}

pub async fn submit_handler(
    State(state): State<AppState>,
    Json(req): Json<SubmitRequest>,
) -> impl IntoResponse {
    let config = state.config();
    let audit_ctx = build_onchain_audit_context(&state, &config, &req);

    if !config.onchain.enabled {
        log_onchain_audit_decision(
            &state,
            &audit_ctx,
            "denied",
            Some("Onchain module is disabled. Enable in fishnet.toml".to_string()),
            None,
            None,
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "error": "onchain_disabled",
                "message": "Onchain module is disabled. Enable in fishnet.toml"
            })),
        )
            .into_response();
    }

    {
        let vc = &config.onchain.permits.verifying_contract;
        let vc_hex = vc.strip_prefix("0x").unwrap_or(vc);
        if vc.is_empty() {
            log_onchain_audit_decision(
                &state,
                &audit_ctx,
                "denied",
                Some("verifying_contract not configured in [onchain.permits]".to_string()),
                None,
                None,
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "error",
                    "error": "verifying_contract_not_configured",
                    "message": "verifying_contract not configured in [onchain.permits]"
                })),
            )
                .into_response();
        }
        if vc_hex.len() != 40 || !vc_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            log_onchain_audit_decision(
                &state,
                &audit_ctx,
                "denied",
                Some(
                    "verifying_contract must be a valid Ethereum address (0x + 40 hex characters)"
                        .to_string(),
                ),
                None,
                None,
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "error",
                    "error": "invalid_verifying_contract",
                    "message": "verifying_contract must be a valid Ethereum address (0x + 40 hex characters)"
                })),
            )
                .into_response();
        }
    }

    let target_hex = req.target.strip_prefix("0x").unwrap_or(&req.target);
    if target_hex.len() != 40 || !target_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        log_onchain_audit_decision(
            &state,
            &audit_ctx,
            "denied",
            Some("target must be a valid Ethereum address (0x + 40 hex characters)".to_string()),
            None,
            None,
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "error": "invalid_target",
                "message": "target must be a valid Ethereum address (0x + 40 hex characters)"
            })),
        )
            .into_response();
    }

    let _submit_guard = state.onchain_store.submit_lock.lock().await;

    let onchain_spent_today = state
        .spend_store
        .get_onchain_spent_today()
        .await
        .unwrap_or(0.0);
    let last_permit_at = state.onchain_store.last_permit_at();

    if let Err(denial) = check_policy(&req, &config.onchain, onchain_spent_today, last_permit_at) {
        drop(_submit_guard);

        let _ = state
            .spend_store
            .record_permit(&crate::spend::PermitEntry {
                chain_id: req.chain_id,
                target: &req.target,
                value: &req.value,
                status: "denied",
                reason: Some(&denial.reason),
                permit_hash: None,
                cost_usd: 0.0,
            })
            .await;

        if config.alerts.onchain_denied {
            let alert_msg = format!("Denied tx to {}: {}", req.target, denial.reason);
            if state
                .alert_store
                .should_create_onchain_alert(&alert_msg)
                .await
            {
                webhook::create_alert_and_dispatch(
                    &state,
                    AlertType::OnchainDenied,
                    AlertSeverity::Warning,
                    "onchain",
                    alert_msg,
                    "onchain_denied",
                )
                .await;
            }
        }

        eprintln!(
            "[fishnet] onchain DENIED: {} (limit: {})",
            denial.reason, denial.limit
        );

        log_onchain_audit_decision(
            &state,
            &audit_ctx,
            "denied",
            Some(denial.reason.clone()),
            None,
            None,
        )
        .await;

        return Json(serde_json::json!({
            "status": "denied",
            "reason": denial.reason,
            "limit": denial.limit,
        }))
        .into_response();
    }

    let signer_info = state.signer.status();
    let wallet_hex = signer_info
        .address
        .strip_prefix("0x")
        .unwrap_or(&signer_info.address);
    let nonce = match state.spend_store.next_nonce().await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[fishnet] nonce generation failed: {e}");
            log_onchain_audit_decision(
                &state,
                &audit_ctx,
                "denied",
                Some(format!("nonce generation failed: {e}")),
                None,
                None,
            )
            .await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "status": "error",
                    "reason": format!("nonce generation failed: {e}")
                })),
            )
                .into_response();
        }
    };
    let now = chrono::Utc::now().timestamp() as u64;
    let expiry = now + config.onchain.permits.expiry_seconds;

    let calldata_bytes = match hex::decode(req.calldata.strip_prefix("0x").unwrap_or(&req.calldata))
    {
        Ok(bytes) => bytes,
        Err(_) => {
            log_onchain_audit_decision(
                &state,
                &audit_ctx,
                "denied",
                Some("calldata is not valid hex".to_string()),
                None,
                None,
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "error",
                    "error": "invalid_calldata",
                    "message": "calldata is not valid hex"
                })),
            )
                .into_response();
        }
    };
    let calldata_hash = Keccak256::digest(&calldata_bytes);
    let calldata_hash_hex = format!("0x{}", hex::encode(calldata_hash));

    if alloy_primitives::U256::from_str_radix(&req.value, 10).is_err() {
        log_onchain_audit_decision(
            &state,
            &audit_ctx,
            "denied",
            Some("value must be a valid uint256 decimal string".to_string()),
            None,
            None,
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "error": "invalid_value",
                "message": "value must be a valid uint256 decimal string"
            })),
        )
            .into_response();
    }

    let policy_hash = if config.onchain.permits.require_policy_hash {
        let policy_data = serde_json::to_string(&config.onchain).unwrap_or_default();
        let hash = Keccak256::digest(policy_data.as_bytes());
        Some(format!("0x{}", hex::encode(hash)))
    } else {
        None
    };

    let permit = FishnetPermit {
        wallet: format!("0x{wallet_hex}"),
        chain_id: req.chain_id,
        nonce,
        expiry,
        target: req.target.clone(),
        value: req.value.clone(),
        calldata_hash: calldata_hash_hex.clone(),
        policy_hash: policy_hash.clone(),
        verifying_contract: config.onchain.permits.verifying_contract.clone(),
    };

    let signature = match state.signer.sign_permit(&permit).await {
        Ok(sig) => format!("0x{}", hex::encode(&sig)),
        Err(e) => {
            eprintln!("[fishnet] signing failed: {e}");
            log_onchain_audit_decision(
                &state,
                &audit_ctx,
                "denied",
                Some(format!("signing failed: {e}")),
                None,
                None,
            )
            .await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "status": "error",
                    "reason": format!("signing failed: {e}")
                })),
            )
                .into_response();
        }
    };

    let permit_hash_str = format!("0x{}", hex::encode(Keccak256::digest(signature.as_bytes())));
    let tx_value: f64 = req.value.parse().unwrap_or(0.0);
    let _ = state
        .spend_store
        .record_permit(&crate::spend::PermitEntry {
            chain_id: req.chain_id,
            target: &req.target,
            value: &req.value,
            status: "approved",
            reason: None,
            permit_hash: Some(&permit_hash_str),
            cost_usd: tx_value,
        })
        .await;

    state
        .onchain_store
        .set_last_permit_at(chrono::Utc::now().timestamp());

    eprintln!(
        "[fishnet] onchain APPROVED: target={} chain_id={} nonce={}",
        req.target, req.chain_id, nonce
    );

    log_onchain_audit_decision(
        &state,
        &audit_ctx,
        "approved",
        None,
        Some(tx_value),
        Some(permit_hash_str.clone()),
    )
    .await;

    Json(serde_json::json!({
        "status": "approved",
        "permit": {
            "wallet": permit.wallet,
            "chainId": permit.chain_id,
            "nonce": permit.nonce,
            "expiry": permit.expiry,
            "target": permit.target,
            "value": permit.value,
            "calldataHash": permit.calldata_hash,
            "policyHash": permit.policy_hash,
            "verifyingContract": permit.verifying_contract,
        },
        "signature": signature,
    }))
    .into_response()
}

fn build_onchain_audit_context(
    state: &AppState,
    config: &fishnet_types::config::FishnetConfig,
    req: &SubmitRequest,
) -> OnchainAuditContext {
    let selector = extract_selector(&req.calldata).unwrap_or_else(|| "submit".to_string());
    let action = format!("{selector} @ {}", req.target);
    let payload = serde_json::to_value(req).unwrap_or_else(|_| serde_json::json!({}));

    OnchainAuditContext {
        action,
        policy_version_hash: audit::policy_version_hash(&state.config_path, config),
        intent_hash: audit::hash_json_intent(&payload),
    }
}

async fn log_onchain_audit_decision(
    state: &AppState,
    ctx: &OnchainAuditContext,
    decision: &str,
    reason: Option<String>,
    cost_usd: Option<f64>,
    permit_hash_hex: Option<String>,
) {
    let permit_hash = match permit_hash_hex.as_deref() {
        Some(raw) => match audit::merkle::h256_from_hex(raw) {
            Some(parsed) => Some(parsed),
            None => {
                eprintln!(
                    "[fishnet] warning: failed to parse permit_hash_hex into H256 (action: {}, value: {})",
                    ctx.action, raw
                );
                None
            }
        },
        None => None,
    };

    let entry = NewAuditEntry {
        intent_type: "onchain_tx".to_string(),
        service: "onchain".to_string(),
        action: ctx.action.clone(),
        decision: decision.to_string(),
        reason,
        cost_usd,
        policy_version_hash: ctx.policy_version_hash,
        intent_hash: ctx.intent_hash,
        permit_hash,
    };

    if let Err(e) = state.audit_store.append(entry).await {
        eprintln!("[fishnet] failed to append onchain audit entry: {e}");
    }
}

fn extract_selector(calldata: &str) -> Option<String> {
    let trimmed = calldata.strip_prefix("0x").unwrap_or(calldata);
    if trimmed.len() < 8 {
        return None;
    }
    let selector = &trimmed[..8];
    if selector.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(format!("0x{}", selector.to_ascii_lowercase()))
    } else {
        None
    }
}

pub async fn get_config(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.config();
    Json(serde_json::json!({
        "enabled": config.onchain.enabled,
        "chain_ids": config.onchain.chain_ids,
        "limits": {
            "max_tx_value_usd": config.onchain.limits.max_tx_value_usd,
            "daily_spend_cap_usd": config.onchain.limits.daily_spend_cap_usd,
            "cooldown_seconds": config.onchain.limits.cooldown_seconds,
            "max_slippage_bps": config.onchain.limits.max_slippage_bps,
            "max_leverage": config.onchain.limits.max_leverage,
        },
        "permits": {
            "expiry_seconds": config.onchain.permits.expiry_seconds,
            "require_policy_hash": config.onchain.permits.require_policy_hash,
            "verifying_contract": config.onchain.permits.verifying_contract,
        },
        "whitelist": config.onchain.whitelist,
    }))
}

#[derive(Debug, Deserialize)]
pub struct UpdateOnchainConfigRequest {
    pub enabled: Option<bool>,
    pub chain_ids: Option<Vec<u64>>,
    pub max_tx_value_usd: Option<f64>,
    pub daily_spend_cap_usd: Option<f64>,
    pub cooldown_seconds: Option<u64>,
    pub max_slippage_bps: Option<u64>,
    pub max_leverage: Option<u64>,
    pub expiry_seconds: Option<u64>,
    pub require_policy_hash: Option<bool>,
    pub verifying_contract: Option<String>,
    pub whitelist: Option<std::collections::HashMap<String, Vec<String>>>,
}

pub async fn update_config(
    State(state): State<AppState>,
    Json(req): Json<UpdateOnchainConfigRequest>,
) -> impl IntoResponse {
    let mut errors: Vec<&str> = Vec::new();

    if matches!(req.max_tx_value_usd, Some(v) if v < 0.0 || !v.is_finite()) {
        errors.push("max_tx_value_usd must be a non-negative finite number");
    }
    if matches!(req.daily_spend_cap_usd, Some(v) if v < 0.0 || !v.is_finite()) {
        errors.push("daily_spend_cap_usd must be a non-negative finite number");
    }
    if matches!(req.cooldown_seconds, Some(v) if v > 86400) {
        errors.push("cooldown_seconds must be at most 86400 (24 hours)");
    }
    if matches!(req.max_slippage_bps, Some(v) if v > 10000) {
        errors.push("max_slippage_bps must be at most 10000 (100%)");
    }
    if matches!(req.max_leverage, Some(v) if v == 0 || v > 200) {
        errors.push("max_leverage must be between 1 and 200");
    }
    if matches!(req.expiry_seconds, Some(v) if !(60..=3600).contains(&v)) {
        errors.push("expiry_seconds must be between 60 and 3600");
    }
    if let Some(ref v) = req.verifying_contract {
        let hex = v.strip_prefix("0x").unwrap_or(v);
        if !v.is_empty() && (hex.len() != 40 || !hex.chars().all(|c| c.is_ascii_hexdigit())) {
            errors.push(
                "verifying_contract must be a valid Ethereum address (0x + 40 hex characters)",
            );
        }
    }

    if !errors.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "errors": errors })),
        )
            .into_response();
    }

    let current = state.config();
    let mut updated = (*current).clone();

    if let Some(v) = req.enabled {
        updated.onchain.enabled = v;
    }
    if let Some(v) = req.chain_ids {
        updated.onchain.chain_ids = v;
    }
    if let Some(v) = req.max_tx_value_usd {
        updated.onchain.limits.max_tx_value_usd = v;
    }
    if let Some(v) = req.daily_spend_cap_usd {
        updated.onchain.limits.daily_spend_cap_usd = v;
    }
    if let Some(v) = req.cooldown_seconds {
        updated.onchain.limits.cooldown_seconds = v;
    }
    if let Some(v) = req.max_slippage_bps {
        updated.onchain.limits.max_slippage_bps = v;
    }
    if let Some(v) = req.max_leverage {
        updated.onchain.limits.max_leverage = v;
    }
    if let Some(v) = req.expiry_seconds {
        updated.onchain.permits.expiry_seconds = v;
    }
    if let Some(v) = req.require_policy_hash {
        updated.onchain.permits.require_policy_hash = v;
    }
    if let Some(v) = req.verifying_contract {
        updated.onchain.permits.verifying_contract = v;
    }
    if let Some(v) = req.whitelist {
        updated.onchain.whitelist = v;
    }

    match crate::config::save_config(&state.config_path, &updated) {
        Ok(()) => Json(serde_json::json!({
            "success": true,
            "enabled": updated.onchain.enabled,
            "chain_ids": updated.onchain.chain_ids,
            "limits": {
                "max_tx_value_usd": updated.onchain.limits.max_tx_value_usd,
                "daily_spend_cap_usd": updated.onchain.limits.daily_spend_cap_usd,
                "cooldown_seconds": updated.onchain.limits.cooldown_seconds,
                "max_slippage_bps": updated.onchain.limits.max_slippage_bps,
                "max_leverage": updated.onchain.limits.max_leverage,
            },
            "permits": {
                "expiry_seconds": updated.onchain.permits.expiry_seconds,
                "require_policy_hash": updated.onchain.permits.require_policy_hash,
                "verifying_contract": updated.onchain.permits.verifying_contract,
            },
            "whitelist": updated.onchain.whitelist,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("failed to save config: {e}") })),
        )
            .into_response(),
    }
}

pub async fn get_stats(State(state): State<AppState>) -> impl IntoResponse {
    match state.spend_store.get_onchain_stats().await {
        Ok(stats) => Json(serde_json::json!({
            "total_permits_signed": stats.total_signed,
            "total_permits_denied": stats.total_denied,
            "spent_today_usd": stats.spent_today_usd,
            "last_permit_at": stats.last_permit_at,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("database error: {e}") })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct PermitsQuery {
    pub days: Option<u32>,
    pub status: Option<String>,
}

pub async fn list_permits(
    State(state): State<AppState>,
    Query(query): Query<PermitsQuery>,
) -> impl IntoResponse {
    let days = query.days.unwrap_or(30);
    match state
        .spend_store
        .query_permits(days, query.status.as_deref())
        .await
    {
        Ok(permits) => Json(serde_json::json!({ "permits": permits })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("database error: {e}") })),
        )
            .into_response(),
    }
}
