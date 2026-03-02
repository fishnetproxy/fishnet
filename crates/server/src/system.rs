use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use axum::Json;
use axum::extract::{State, rejection::JsonRejection};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Serialize;

use crate::audit;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
struct PublicFishnetConfig {
    llm: fishnet_types::config::LlmConfig,
    http: fishnet_types::config::HttpClientConfig,
    dashboard: fishnet_types::config::DashboardConfig,
    alerts: fishnet_types::config::AlertsConfig,
    onchain: fishnet_types::config::OnchainConfig,
    binance: fishnet_types::config::BinanceConfig,
    custom: HashMap<String, PublicCustomServiceConfig>,
}

#[derive(Debug, Clone, Serialize)]
struct PublicCustomServiceConfig {
    base_url: String,
    auth_header: String,
    auth_value_prefix: String,
    auth_value_env: String,
    blocked_endpoints: Vec<String>,
    rate_limit: u32,
    rate_limit_window_seconds: u64,
}

pub async fn status(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.config();

    let services = discover_services(&state, &config).await;

    let mut today_spend: HashMap<String, f64> = services
        .iter()
        .map(|service| (service.clone(), 0.0))
        .collect();
    let mut today_requests: HashMap<String, u64> = services
        .iter()
        .map(|service| (service.clone(), 0))
        .collect();

    if let Ok(spend_rows) = state.spend_store.today_service_totals().await {
        for row in spend_rows {
            today_spend.insert(row.service.clone(), row.cost_usd);
            today_requests.entry(row.service).or_insert(0);
        }
    }

    if let Ok(request_rows) = state.audit_store.today_request_counts().await {
        for (service, count) in request_rows {
            today_requests.insert(service.clone(), count);
            today_spend.entry(service).or_insert(0.0);
        }
    }

    Json(serde_json::json!({
        "running": true,
        "uptime": format_uptime(state.started_at.elapsed()),
        "services": services.into_iter().collect::<Vec<_>>(),
        "today_spend": today_spend,
        "today_requests": today_requests,
    }))
}

pub async fn get_policies(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.config();
    Json(to_public_config(&config)).into_response()
}

pub async fn put_policies(
    State(state): State<AppState>,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> impl IntoResponse {
    let Json(payload) = match payload {
        Ok(v) => v,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("invalid JSON body: {err}") })),
            )
                .into_response();
        }
    };

    let mut updated = match serde_json::from_value::<fishnet_types::config::FishnetConfig>(payload)
    {
        Ok(cfg) => cfg,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("invalid policy object: {err}") })),
            )
                .into_response();
        }
    };

    if let Err(err) = updated.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("policy validation failed: {err}") })),
        )
            .into_response();
    }

    let previous = state.config();
    if state.update_config(Arc::new(updated.clone())).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "failed to activate config in running process"
            })),
        )
            .into_response();
    }

    if let Err(err) = crate::config::save_config(&state.config_path, &updated) {
        let rollback_err = state.update_config(previous).err();
        if let Some(ref rollback_err) = rollback_err {
            eprintln!(
                "[fishnet] failed to roll back in-memory config after save failure: {rollback_err}"
            );
        }
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": rollback_err.map_or_else(
                    || format!("failed to persist config after activation: {err}; in-memory config rolled back"),
                    |rollback| format!("failed to persist config after activation: {err}; rollback of in-memory config also failed: {rollback}")
                )
            })),
        )
            .into_response();
    }

    let policy_hash = audit::policy_version_hash(&state.config_path, &updated);
    Json(serde_json::json!({
        "saved": true,
        "policy_hash": audit::merkle::h256_to_hex(&policy_hash),
        "warning": "This endpoint overwrites fishnet.toml and does not preserve comments/formatting.",
    }))
    .into_response()
}

fn to_public_config(config: &fishnet_types::config::FishnetConfig) -> PublicFishnetConfig {
    let custom = config
        .custom
        .iter()
        .map(|(name, service)| {
            (
                name.clone(),
                PublicCustomServiceConfig {
                    base_url: service.base_url.clone(),
                    auth_header: service.auth_header.clone(),
                    auth_value_prefix: service.auth_value_prefix.clone(),
                    auth_value_env: service.auth_value_env.clone(),
                    blocked_endpoints: service.blocked_endpoints.clone(),
                    rate_limit: service.rate_limit,
                    rate_limit_window_seconds: service.rate_limit_window_seconds,
                },
            )
        })
        .collect();

    PublicFishnetConfig {
        llm: config.llm.clone(),
        http: config.http.clone(),
        dashboard: config.dashboard.clone(),
        alerts: config.alerts.clone(),
        onchain: config.onchain.clone(),
        binance: config.binance.clone(),
        custom,
    }
}

async fn discover_services(
    state: &AppState,
    config: &fishnet_types::config::FishnetConfig,
) -> BTreeSet<String> {
    let mut services = BTreeSet::new();

    if let Ok(credentials) = state.credential_store.list_credentials().await {
        for credential in credentials {
            if let Some(name) = credential.service.strip_prefix("custom.") {
                services.insert(name.to_string());
            } else {
                services.insert(credential.service);
            }
        }
    }

    services.insert("openai".to_string());
    services.insert("anthropic".to_string());

    if config.binance.enabled {
        services.insert("binance".to_string());
    }
    if config.onchain.enabled {
        services.insert("onchain".to_string());
    }
    for name in config.custom.keys() {
        services.insert(name.clone());
    }

    services
}

fn format_uptime(duration: std::time::Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;

    if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_formatter_works() {
        assert_eq!(format_uptime(std::time::Duration::from_secs(125)), "2m");
        assert_eq!(format_uptime(std::time::Duration::from_secs(7540)), "2h 5m");
    }
}
