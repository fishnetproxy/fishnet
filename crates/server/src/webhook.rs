use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::alert::{Alert, AlertType};
use crate::state::AppState;

const WEBHOOK_VAULT_SERVICE: &str = "alerts.webhooks";
const DISCORD_CREDENTIAL_NAME: &str = "discord_url";
const SLACK_CREDENTIAL_NAME: &str = "slack_url";
const WEBHOOK_TIMEOUT_SECS: u64 = 8;
const WEBHOOK_MAX_ATTEMPTS: usize = 3;
const WEBHOOK_BACKOFF_BASE_MS: u64 = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookProvider {
    Discord,
    Slack,
}

impl WebhookProvider {
    fn as_str(self) -> &'static str {
        match self {
            Self::Discord => "discord",
            Self::Slack => "slack",
        }
    }

    fn credential_name(self) -> &'static str {
        match self {
            Self::Discord => DISCORD_CREDENTIAL_NAME,
            Self::Slack => SLACK_CREDENTIAL_NAME,
        }
    }

    fn from_raw(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "discord" => Ok(Self::Discord),
            "slack" => Ok(Self::Slack),
            other => Err(format!(
                "invalid provider '{other}', expected one of: discord, slack"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookConfigStatus {
    pub discord_configured: bool,
    pub slack_configured: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookDispatchResult {
    pub provider: String,
    pub configured: bool,
    pub sent: bool,
    pub detail: String,
}

#[derive(Debug, Deserialize)]
pub struct WebhookTestRequest {
    pub provider: Option<String>,
    pub message: Option<String>,
}

pub async fn get_webhook_config(State(state): State<AppState>) -> impl IntoResponse {
    match get_webhook_config_status(&state).await {
        Ok(status) => Json(serde_json::json!({
            "discord_configured": status.discord_configured,
            "slack_configured": status.slack_configured,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn update_webhook_config(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let Some(obj) = body.as_object() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "request body must be a JSON object",
            })),
        )
            .into_response();
    };

    let discord_update = obj.get("discord_url").map(parse_webhook_update_value);
    let slack_update = obj.get("slack_url").map(parse_webhook_update_value);

    if discord_update.is_none() && slack_update.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "at least one of discord_url or slack_url must be provided",
            })),
        )
            .into_response();
    }

    let discord_parsed = match discord_update {
        Some(Ok(v)) => Some(v),
        Some(Err(e)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("discord_url: {e}") })),
            )
                .into_response();
        }
        None => None,
    };

    let slack_parsed = match slack_update {
        Some(Ok(v)) => Some(v),
        Some(Err(e)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("slack_url: {e}") })),
            )
                .into_response();
        }
        None => None,
    };

    if let Some(ref url) = discord_parsed {
        if let Err(e) = set_webhook_url(&state, WebhookProvider::Discord, url.as_deref()).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response();
        }
    }

    if let Some(ref url) = slack_parsed {
        if let Err(e) = set_webhook_url(&state, WebhookProvider::Slack, url.as_deref()).await {
            if discord_parsed.is_some() {
                eprintln!(
                    "[fishnet] slack webhook update failed after discord succeeded; \
                     discord change was already applied: {e}"
                );
            }
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response();
        }
    }

    match get_webhook_config_status(&state).await {
        Ok(status) => Json(serde_json::json!({
            "saved": true,
            "discord_configured": status.discord_configured,
            "slack_configured": status.slack_configured,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

pub async fn test_webhook(
    State(state): State<AppState>,
    Json(req): Json<WebhookTestRequest>,
) -> impl IntoResponse {
    let provider = match req.provider.as_deref() {
        Some(raw) => match WebhookProvider::from_raw(raw) {
            Ok(provider) => Some(provider),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": e })),
                )
                    .into_response();
            }
        },
        None => None,
    };

    let message = req.message.unwrap_or_else(|| {
        format!(
            "Fishnet webhook test message at {}",
            chrono::Utc::now().to_rfc3339()
        )
    });

    let results = dispatch_message(state.clone(), provider, &message).await;
    let configured_any = results.iter().any(|result| result.configured);
    let all_configured_sent = results
        .iter()
        .filter(|result| result.configured)
        .all(|result| result.sent);
    let ok = configured_any && all_configured_sent;

    Json(serde_json::json!({
        "ok": ok,
        "configured_any": configured_any,
        "results": results,
    }))
    .into_response()
}

pub async fn get_webhook_config_status(state: &AppState) -> Result<WebhookConfigStatus, String> {
    let credentials = state
        .credential_store
        .list_credentials()
        .await
        .map_err(|e| format!("failed to read vault metadata: {e}"))?;

    Ok(WebhookConfigStatus {
        discord_configured: credentials
            .iter()
            .any(|c| c.service == WEBHOOK_VAULT_SERVICE && c.name == DISCORD_CREDENTIAL_NAME),
        slack_configured: credentials
            .iter()
            .any(|c| c.service == WEBHOOK_VAULT_SERVICE && c.name == SLACK_CREDENTIAL_NAME),
    })
}

pub async fn set_webhook_url(
    state: &AppState,
    provider: WebhookProvider,
    url: Option<&str>,
) -> Result<(), String> {
    let validated = match url {
        Some(raw) => Some(validate_webhook_url(raw)?),
        None => None,
    };

    let old_value = state
        .credential_store
        .decrypt_for_service_and_name(WEBHOOK_VAULT_SERVICE, provider.credential_name())
        .await
        .map_err(|e| format!("failed to read current {} webhook URL: {e}", provider.as_str()))?
        .map(|c| c.key.to_string());

    clear_webhook_url(state, provider).await?;

    if let Some(url) = validated {
        if let Err(e) = state
            .credential_store
            .add_credential(WEBHOOK_VAULT_SERVICE, provider.credential_name(), &url)
            .await
        {
            if let Some(ref old_url) = old_value {
                let _ = state
                    .credential_store
                    .add_credential(WEBHOOK_VAULT_SERVICE, provider.credential_name(), old_url)
                    .await;
            }
            return Err(format!(
                "failed to store {} webhook URL in vault: {e}",
                provider.as_str()
            ));
        }
    }
    Ok(())
}

pub async fn dispatch_alert_webhooks(
    state: &AppState,
    alert: &Alert,
) -> Vec<WebhookDispatchResult> {
    if !should_dispatch_alert(alert.alert_type) {
        return Vec::new();
    }
    dispatch_message(state.clone(), None, &format_alert_message(alert)).await
}

fn parse_webhook_update_value(value: &serde_json::Value) -> Result<Option<String>, String> {
    if value.is_null() {
        return Ok(None);
    }

    let Some(raw) = value.as_str() else {
        return Err("must be a string or null".to_string());
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

fn validate_webhook_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("URL cannot be empty".to_string());
    }
    let parsed = url::Url::parse(trimmed).map_err(|e| format!("invalid URL: {e}"))?;

    let allow_http = cfg!(test)
        || std::env::var("FISHNET_DEV").map_or(false, |v| v == "1" || v == "true");
    if allow_http {
        if !matches!(parsed.scheme(), "https" | "http") {
            return Err("URL scheme must be http or https".to_string());
        }
    } else if parsed.scheme() != "https" {
        return Err("URL scheme must be https (set FISHNET_DEV=1 to allow http)".to_string());
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "URL host is required".to_string())?;

    if !allow_http {
        reject_internal_host(host)?;
    }

    Ok(trimmed.to_string())
}

fn reject_internal_host(host: &str) -> Result<(), String> {
    if host.eq_ignore_ascii_case("localhost") {
        return Err("webhook URL must not point to localhost".to_string());
    }

    let lower = host.to_ascii_lowercase();
    if lower.ends_with(".local")
        || lower.ends_with(".internal")
        || lower.ends_with(".localhost")
    {
        return Err(format!(
            "webhook URL must not point to an internal host ({host})"
        ));
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_private_or_reserved(ip) {
            return Err(format!(
                "webhook URL must not point to a private/reserved IP ({host})"
            ));
        }
    }

    Ok(())
}

fn is_private_or_reserved(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()            // 127.0.0.0/8
                || v4.is_private()      // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()   // 169.254/16 (cloud metadata)
                || v4.is_unspecified()  // 0.0.0.0
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64 // 100.64/10 CGNAT
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()        // ::1
                || v6.is_unspecified()  // ::
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
    }
}

fn should_dispatch_alert(alert_type: AlertType) -> bool {
    matches!(
        alert_type,
        AlertType::PromptDrift
            | AlertType::PromptSize
            | AlertType::BudgetWarning
            | AlertType::BudgetExceeded
            | AlertType::OnchainDenied
            | AlertType::RateLimitHit
            | AlertType::AnomalousVolume
            | AlertType::NewEndpoint
            | AlertType::TimeAnomaly
            | AlertType::HighSeverityDeniedAction
    )
}

fn format_alert_type(alert_type: AlertType) -> &'static str {
    match alert_type {
        AlertType::PromptDrift => "prompt_drift",
        AlertType::PromptSize => "prompt_size",
        AlertType::BudgetWarning => "budget_warning",
        AlertType::BudgetExceeded => "budget_exceeded",
        AlertType::OnchainDenied => "onchain_denied",
        AlertType::RateLimitHit => "rate_limit_hit",
        AlertType::AnomalousVolume => "anomalous_volume",
        AlertType::NewEndpoint => "new_endpoint",
        AlertType::TimeAnomaly => "time_anomaly",
        AlertType::HighSeverityDeniedAction => "high_severity_denied_action",
    }
}

fn format_alert_message(alert: &Alert) -> String {
    let timestamp = chrono::DateTime::<chrono::Utc>::from_timestamp(alert.timestamp, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| alert.timestamp.to_string());
    format!(
        "Fishnet alert [{}] type={} service={} time={} message={}",
        match alert.severity {
            crate::alert::AlertSeverity::Critical => "critical",
            crate::alert::AlertSeverity::Warning => "warning",
        },
        format_alert_type(alert.alert_type),
        alert.service,
        timestamp,
        alert.message
    )
}

async fn clear_webhook_url(state: &AppState, provider: WebhookProvider) -> Result<(), String> {
    let credentials = state
        .credential_store
        .list_credentials()
        .await
        .map_err(|e| format!("failed to read vault metadata: {e}"))?;

    for credential in credentials.into_iter().filter(|credential| {
        credential.service == WEBHOOK_VAULT_SERVICE && credential.name == provider.credential_name()
    }) {
        state
            .credential_store
            .delete_credential(&credential.id)
            .await
            .map_err(|e| {
                format!(
                    "failed to remove existing {} webhook URL from vault: {e}",
                    provider.as_str()
                )
            })?;
    }

    Ok(())
}

async fn dispatch_message(
    state: AppState,
    provider: Option<WebhookProvider>,
    message: &str,
) -> Vec<WebhookDispatchResult> {
    let providers = match provider {
        Some(provider) => vec![provider],
        None => vec![WebhookProvider::Discord, WebhookProvider::Slack],
    };

    let mut results = Vec::new();
    for provider in providers {
        let url = match load_webhook_url(&state, provider).await {
            Ok(value) => value,
            Err(e) => {
                results.push(WebhookDispatchResult {
                    provider: provider.as_str().to_string(),
                    configured: false,
                    sent: false,
                    detail: e,
                });
                continue;
            }
        };

        let Some(url) = url else {
            results.push(WebhookDispatchResult {
                provider: provider.as_str().to_string(),
                configured: false,
                sent: false,
                detail: "not configured".to_string(),
            });
            continue;
        };

        match send_webhook(&state, provider, &url, message).await {
            Ok(()) => results.push(WebhookDispatchResult {
                provider: provider.as_str().to_string(),
                configured: true,
                sent: true,
                detail: "sent".to_string(),
            }),
            Err(e) => results.push(WebhookDispatchResult {
                provider: provider.as_str().to_string(),
                configured: true,
                sent: false,
                detail: e,
            }),
        }
    }

    results
}

async fn load_webhook_url(
    state: &AppState,
    provider: WebhookProvider,
) -> Result<Option<String>, String> {
    let credential = state
        .credential_store
        .decrypt_for_service_and_name(WEBHOOK_VAULT_SERVICE, provider.credential_name())
        .await
        .map_err(|e| {
            format!(
                "failed to read {} webhook URL from vault: {e}",
                provider.as_str()
            )
        })?;

    let Some(credential) = credential else {
        return Ok(None);
    };

    if let Err(e) = state.credential_store.touch_last_used(&credential.id).await {
        eprintln!(
            "[fishnet] failed to update last_used for {} webhook credential: {e}",
            provider.as_str()
        );
    }

    Ok(Some(credential.key.to_string()))
}

async fn send_webhook(
    state: &AppState,
    provider: WebhookProvider,
    url: &str,
    message: &str,
) -> Result<(), String> {
    let payload = match provider {
        WebhookProvider::Discord => serde_json::json!({ "content": message }),
        WebhookProvider::Slack => serde_json::json!({ "text": message }),
    };

    let mut last_error = String::new();
    for attempt in 1..=WEBHOOK_MAX_ATTEMPTS {
        let send_result = tokio::time::timeout(
            Duration::from_secs(WEBHOOK_TIMEOUT_SECS),
            state.http_client.post(url).json(&payload).send(),
        )
        .await;

        let should_retry = match send_result {
            Ok(Ok(response)) => {
                if response.status().is_success() {
                    return Ok(());
                }

                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                last_error = if body.is_empty() {
                    format!("HTTP {status}")
                } else {
                    format!("HTTP {status}: {}", truncate_for_log(&body, 240))
                };

                should_retry_status(status)
            }
            Ok(Err(e)) => {
                last_error = format!("request failed: {e}");
                true
            }
            Err(_) => {
                last_error = format!("request timed out after {WEBHOOK_TIMEOUT_SECS}s");
                true
            }
        };

        if should_retry && attempt < WEBHOOK_MAX_ATTEMPTS {
            tokio::time::sleep(backoff_delay(attempt)).await;
            continue;
        }

        break;
    }

    if last_error.is_empty() {
        Err("webhook request failed".to_string())
    } else {
        Err(last_error)
    }
}

fn should_retry_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn backoff_delay(attempt: usize) -> Duration {
    // attempt=1 -> 250ms, attempt=2 -> 500ms
    let shift = attempt.saturating_sub(1) as u32;
    let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let millis = WEBHOOK_BACKOFF_BASE_MS.saturating_mul(multiplier);
    Duration::from_millis(millis)
}

fn truncate_for_log(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_string();
    }
    if max_len == 0 {
        return String::new();
    }
    let cut = max_len.saturating_sub(1);
    let boundary = value
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|&i| i <= cut)
        .last()
        .unwrap_or(0);
    let mut out = value[..boundary].to_string();
    out.push('~');
    out
}

pub async fn create_alert_and_dispatch(
    state: &AppState,
    alert_type: AlertType,
    severity: crate::alert::AlertSeverity,
    service: &str,
    message: String,
    context: &str,
) {
    match state
        .alert_store
        .create(alert_type, severity, service, message)
        .await
    {
        Ok(alert) => dispatch_alert_webhooks_with_logging(state, &alert, context).await,
        Err(e) => eprintln!("[fishnet] failed to create {context} alert: {e}"),
    }
}

pub async fn dispatch_alert_webhooks_with_logging(
    state: &AppState,
    alert: &Alert,
    context: &str,
) {
    for result in dispatch_alert_webhooks(state, alert).await {
        if result.configured && !result.sent {
            eprintln!(
                "[fishnet] webhook dispatch failed ({context}, provider: {}): {}",
                result.provider, result.detail
            );
        }
    }
}
