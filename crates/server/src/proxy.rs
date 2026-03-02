use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use hmac::{Hmac, Mac};
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::{Decimal, RoundingStrategy};
use sha2::Sha256;
use std::collections::HashSet;
use std::str::FromStr;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use url::form_urlencoded;
use zeroize::Zeroizing;

use crate::alert::{AlertSeverity, AlertType};
use crate::anomaly::AnomalyKind;
use crate::audit::{self, NewAuditEntry};
use crate::constants;
use crate::llm_guard::{
    GuardDecision, check_prompt_drift, check_prompt_size, count_prompt_chars, extract_system_prompt,
};
use crate::state::AppState;
use crate::vault::DecryptedCredential;
use crate::webhook;
use fishnet_types::config::ModelPricing;

type HmacSha256 = Hmac<Sha256>;
const USD_MICROS_SCALE: i64 = 1_000_000;

#[derive(Clone)]
struct AuditContext {
    intent_type: String,
    service: String,
    action: String,
    policy_version_hash: audit::merkle::H256,
    intent_hash: audit::merkle::H256,
}

#[derive(Debug, Clone, Default)]
struct LlmRequestMeta {
    model: Option<String>,
    stream_requested: bool,
}

#[derive(Debug, Clone, Copy)]
struct TokenUsage {
    input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
}

#[derive(Debug, Default)]
struct StreamUsageCollector {
    line_buffer: Vec<u8>,
    event_data: String,
    model: Option<String>,
    usage: Option<TokenUsage>,
    anthropic_input_tokens: Option<u64>,
    anthropic_output_tokens: Option<u64>,
}

pub async fn handler(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    body: axum::body::Bytes,
) -> Response {
    let config = state.config();
    let raw_action = format!("{} {}", method, uri.path());

    let path = uri.path();
    let path = path
        .strip_prefix(constants::PROXY_PATH_PREFIX)
        .unwrap_or(path);
    let (provider, rest) = match path.split_once('/') {
        Some((p, r)) => (p.to_string(), format!("/{r}")),
        None => {
            let ctx = build_api_audit_context(
                &state,
                &config,
                "unknown",
                &raw_action,
                &method,
                uri.query(),
                &body,
            );
            return audited_json_error(&state, &ctx, StatusCode::BAD_REQUEST, "invalid proxy path")
                .await;
        }
    };

    let action = format!("{} {}", method, rest);
    let audit_ctx = build_api_audit_context(
        &state,
        &config,
        &provider,
        &action,
        &method,
        uri.query(),
        &body,
    );

    let upstream_base = match provider.as_str() {
        "openai" => std::env::var(constants::ENV_OPENAI_API_BASE)
            .unwrap_or_else(|_| constants::OPENAI_API_BASE.to_string()),
        "anthropic" => std::env::var(constants::ENV_ANTHROPIC_API_BASE)
            .unwrap_or_else(|_| constants::ANTHROPIC_API_BASE.to_string()),
        _ => {
            return audited_json_error(
                &state,
                &audit_ctx,
                StatusCode::BAD_REQUEST,
                &format!("unknown provider: {provider}"),
            )
            .await;
        }
    };

    if config.llm.rate_limit_per_minute > 0
        && let Err(retry_after) = state
            .proxy_rate_limiter
            .check_and_record(&provider, config.llm.rate_limit_per_minute)
            .await
    {
        if config.alerts.rate_limit_hit {
            create_alert_and_dispatch(
                &state,
                AlertType::RateLimitHit,
                AlertSeverity::Warning,
                &provider,
                format!("Rate limit exceeded for {provider}. Retry after {retry_after}s."),
                "rate_limit_hit",
            )
            .await;
        }
        let message = format!("rate limit exceeded, retry after {retry_after}s");
        log_audit_decision(
            &state,
            &audit_ctx,
            "denied",
            Some(message.clone()),
            None,
            None,
        )
        .await;
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": message,
                "retry_after_seconds": retry_after
            })),
        )
            .into_response();
    }

    let llm_meta = match enforce_llm_guards(&state, &provider, &headers, &body).await {
        Ok(meta) => meta,
        Err((status, message)) => {
            return audited_json_error(&state, &audit_ctx, status, &message).await;
        }
    };

    let target_url = with_query(&upstream_base, &rest, uri.query());
    let (extra_headers, credential_id) = {
        let credential = match state.credential_store.decrypt_for_service(&provider).await {
            Ok(Some(cred)) => cred,
            Ok(None) => {
                return audited_json_error(
                    &state,
                    &audit_ctx,
                    StatusCode::BAD_REQUEST,
                    &format!("credential not found for service: {provider}"),
                )
                .await;
            }
            Err(e) => {
                eprintln!("[fishnet] failed to decrypt credential for {provider}: {e}");
                return audited_json_error(
                    &state,
                    &audit_ctx,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to access credential vault",
                )
                .await;
            }
        };

        let mut extra_headers: Vec<(String, HeaderValue)> = Vec::new();
        match provider.as_str() {
            "openai" => {
                let auth_header = format!("Bearer {}", credential.key.as_str());
                let auth_value = match HeaderValue::from_str(&auth_header) {
                    Ok(v) => v,
                    Err(_) => {
                        return audited_json_error(
                            &state,
                            &audit_ctx,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "invalid credential format for openai",
                        )
                        .await;
                    }
                };
                extra_headers.push(("authorization".to_string(), auth_value));
            }
            "anthropic" => {
                let api_key_value = match HeaderValue::from_str(credential.key.as_str()) {
                    Ok(v) => v,
                    Err(_) => {
                        return audited_json_error(
                            &state,
                            &audit_ctx,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "invalid credential format for anthropic",
                        )
                        .await;
                    }
                };
                extra_headers.push(("x-api-key".to_string(), api_key_value));
            }
            _ => {}
        }

        (extra_headers, credential.id)
    };

    if let Err(e) = state.credential_store.touch_last_used(&credential_id).await {
        eprintln!("[fishnet] failed to update credential last_used_at: {e}");
    }

    let request_stream_requested = llm_meta.stream_requested
        || request_body_stream_requested(&headers, &body).unwrap_or(false);
    let outbound_body = if provider == "openai" && openai_stream_include_usage_supported_path(&rest)
    {
        ensure_openai_stream_include_usage(&headers, &body, request_stream_requested)
    } else {
        body
    };

    let skip_headers = vec!["authorization".to_string(), "x-api-key".to_string()];
    let incoming_request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    let upstream_resp = match send_upstream(
        &state,
        &provider,
        method,
        &headers,
        &target_url,
        Some(outbound_body),
        &skip_headers,
        &extra_headers,
    )
    .await
    {
        Ok(resp) => resp,
        Err(resp) => {
            log_audit_decision(
                &state,
                &audit_ctx,
                "denied",
                Some("upstream provider is unavailable".to_string()),
                None,
                None,
            )
            .await;
            return resp;
        }
    };

    if llm_meta.stream_requested || response_is_event_stream(&upstream_resp) {
        let upstream_request_id = upstream_resp
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        let request_id = incoming_request_id
            .as_deref()
            .or(upstream_request_id.as_deref())
            .unwrap_or("unknown");
        let model_name = llm_meta.model.as_deref().unwrap_or("unknown");
        eprintln!(
            "[fishnet] warning: streaming cost is tracked only when usage appears in stream events (provider: {provider}, model: {model_name}, request_id: {request_id}); interrupted streams may miss cost"
        );

        let response = match build_streaming_proxy_response_with_usage(
            state.clone(),
            provider.clone(),
            llm_meta.model.clone(),
            upstream_resp,
            request_id.to_string(),
        ) {
            Ok(response) => response,
            Err(resp) => {
                log_audit_decision(
                    &state,
                    &audit_ctx,
                    "denied",
                    Some("failed to build streaming response".to_string()),
                    None,
                    None,
                )
                .await;
                return resp;
            }
        };
        log_audit_decision(&state, &audit_ctx, "approved", None, None, None).await;
        return response;
    }

    let (response, cost_usd) =
        finalize_llm_response(&state, &provider, llm_meta.model.as_deref(), upstream_resp).await;
    log_audit_decision(&state, &audit_ctx, "approved", None, cost_usd, None).await;
    response
}

pub async fn binance_handler(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    body: axum::body::Bytes,
) -> Response {
    let config = state.config();
    let fallback_action = format!("{} {}", method, uri.path());
    let fallback_ctx = build_api_audit_context(
        &state,
        &config,
        "binance",
        &fallback_action,
        &method,
        uri.query(),
        &body,
    );
    if !config.binance.enabled {
        return audited_json_error(
            &state,
            &fallback_ctx,
            StatusCode::FORBIDDEN,
            "binance proxy is disabled",
        )
        .await;
    }

    let Some(rest) = uri.path().strip_prefix("/binance") else {
        return audited_json_error(
            &state,
            &fallback_ctx,
            StatusCode::BAD_REQUEST,
            "invalid binance proxy path",
        )
        .await;
    };
    if rest.is_empty() || !rest.starts_with('/') {
        return audited_json_error(
            &state,
            &fallback_ctx,
            StatusCode::BAD_REQUEST,
            "invalid binance proxy path",
        )
        .await;
    }

    let route_path = rest.to_string();
    let action = format!("{} {}", method, route_path);
    let audit_ctx = build_api_audit_context(
        &state,
        &config,
        "binance",
        &action,
        &method,
        uri.query(),
        &body,
    );
    if !(route_path.starts_with("/api/") || route_path.starts_with("/sapi/")) {
        return audited_json_error(
            &state,
            &audit_ctx,
            StatusCode::BAD_REQUEST,
            "binance path must start with /api or /sapi",
        )
        .await;
    }

    maybe_emit_request_anomalies(&state, "binance", &action).await;

    if method == Method::POST && route_path.starts_with("/sapi/v1/capital/withdraw/") {
        emit_high_severity_denied_action_alert(
            &state,
            "binance",
            &action,
            "hard-blocked endpoint: withdrawals are disabled",
        )
        .await;
        return audited_json_error(
            &state,
            &audit_ctx,
            StatusCode::FORBIDDEN,
            "endpoint is hard-blocked by fishnet policy: withdrawals are disabled",
        )
        .await;
    }

    let is_read_only = method == Method::GET
        && (route_path.starts_with("/api/v3/ticker/") || route_path == "/api/v3/klines");
    let is_order = method == Method::POST && route_path == "/api/v3/order";
    let is_delete_open_orders = method == Method::DELETE && route_path == "/api/v3/openOrders";

    if is_delete_open_orders && !config.binance.allow_delete_open_orders {
        emit_high_severity_denied_action_alert(
            &state,
            "binance",
            &action,
            "blocked-by-default endpoint: DELETE /api/v3/openOrders",
        )
        .await;
        return audited_json_error(
            &state,
            &audit_ctx,
            StatusCode::FORBIDDEN,
            "endpoint blocked by default policy: DELETE /api/v3/openOrders",
        )
        .await;
    }

    if !is_read_only && !is_order && !is_delete_open_orders {
        return audited_json_error(
            &state,
            &audit_ctx,
            StatusCode::FORBIDDEN,
            "binance endpoint is not allowed by policy",
        )
        .await;
    }

    let mut parsed_params: Vec<(String, String)> = Vec::new();
    let mut seen_param_keys: HashSet<String> = HashSet::new();
    if let Some(query) = uri.query() {
        if let Err(msg) = append_unique_form_pairs(&mut parsed_params, &mut seen_param_keys, query)
        {
            return audited_json_error(&state, &audit_ctx, StatusCode::BAD_REQUEST, &msg).await;
        }
    }

    if !body.is_empty() {
        let body_str = match std::str::from_utf8(&body) {
            Ok(s) => s,
            Err(_) => {
                return audited_json_error(
                    &state,
                    &audit_ctx,
                    StatusCode::BAD_REQUEST,
                    "binance request body must be UTF-8 form data",
                )
                .await;
            }
        };
        if let Err(msg) =
            append_unique_form_pairs(&mut parsed_params, &mut seen_param_keys, body_str)
        {
            return audited_json_error(&state, &audit_ctx, StatusCode::BAD_REQUEST, &msg).await;
        }
    }

    let _order_guard = if is_order {
        Some(state.binance_order_lock.lock().await)
    } else {
        None
    };

    let mut order_value_micros = None;
    if is_order {
        let value_micros = match parse_binance_order_value_usd(&parsed_params) {
            Ok(v) => v,
            Err(msg) => {
                return audited_json_error(&state, &audit_ctx, StatusCode::BAD_REQUEST, &msg).await;
            }
        };

        let max_order_micros = config_usd_to_micros(config.binance.max_order_value_usd);
        if max_order_micros > 0 && value_micros > max_order_micros {
            return audited_json_error(
                &state,
                &audit_ctx,
                StatusCode::FORBIDDEN,
                &format!(
                    "order value ${} exceeds max_order_value_usd ${}",
                    format_usd_micros(value_micros),
                    format_usd_micros(max_order_micros),
                ),
            )
            .await;
        }

        let daily_cap_micros = config_usd_to_micros(config.binance.daily_volume_cap_usd);
        if daily_cap_micros > 0 {
            let spent_today_micros = match state.spend_store.get_spent_today_micros("binance").await
            {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "[fishnet] failed to read binance spend state while enforcing daily cap: {e}"
                    );
                    return audited_json_error(
                        &state,
                        &audit_ctx,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to evaluate daily binance volume cap",
                    )
                    .await;
                }
            };
            let projected_micros = match spent_today_micros.checked_add(value_micros) {
                Some(total) => total,
                None => {
                    return audited_json_error(
                        &state,
                        &audit_ctx,
                        StatusCode::FORBIDDEN,
                        "daily binance volume cap exceeded: projected volume overflowed supported range",
                    )
                    .await;
                }
            };
            if projected_micros > daily_cap_micros {
                return audited_json_error(
                    &state,
                    &audit_ctx,
                    StatusCode::FORBIDDEN,
                    &format!(
                        "daily binance volume cap exceeded: ${} + ${} > ${}",
                        format_usd_micros(spent_today_micros),
                        format_usd_micros(value_micros),
                        format_usd_micros(daily_cap_micros),
                    ),
                )
                .await;
            }
        }

        order_value_micros = Some(value_micros);
    }

    let mut extra_headers: Vec<(String, HeaderValue)> = Vec::new();
    let skip_headers = vec![
        "authorization".to_string(),
        "x-api-key".to_string(),
        "x-mbx-apikey".to_string(),
    ];
    let binance_base_url = if config.binance.base_url.trim().is_empty() {
        constants::BINANCE_API_BASE.to_string()
    } else {
        config.binance.base_url.trim_end_matches('/').to_string()
    };

    let mut target_url = with_query(&binance_base_url, &route_path, uri.query());
    let mut outbound_body = if is_read_only {
        Some(body.clone())
    } else {
        None
    };

    if !is_read_only {
        let (api_key, api_secret) = match load_binance_credentials(&state).await {
            Ok(creds) => creds,
            Err(resp) => {
                log_audit_decision(
                    &state,
                    &audit_ctx,
                    "denied",
                    Some("failed to access credential vault".to_string()),
                    None,
                    None,
                )
                .await;
                return resp;
            }
        };

        if !parsed_params.iter().any(|(k, _)| k == "timestamp") {
            parsed_params.push((
                "timestamp".to_string(),
                chrono::Utc::now().timestamp_millis().to_string(),
            ));
        }
        if config.binance.recv_window_ms > 0
            && !parsed_params.iter().any(|(k, _)| k == "recvWindow")
        {
            parsed_params.push((
                "recvWindow".to_string(),
                config.binance.recv_window_ms.to_string(),
            ));
        }

        let unsigned_query = serialize_form_pairs(&parsed_params);
        let signature = match hmac_sha256_hex(api_secret.key.as_bytes(), unsigned_query.as_bytes())
        {
            Ok(sig) => sig,
            Err(msg) => {
                return audited_json_error(
                    &state,
                    &audit_ctx,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &msg,
                )
                .await;
            }
        };
        parsed_params.push(("signature".to_string(), signature));
        let signed_query = serialize_form_pairs(&parsed_params);
        target_url = format!("{binance_base_url}{route_path}?{signed_query}");

        let api_key_value = match HeaderValue::from_str(api_key.key.as_str()) {
            Ok(v) => v,
            Err(_) => {
                return audited_json_error(
                    &state,
                    &audit_ctx,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid credential format for binance api key",
                )
                .await;
            }
        };
        extra_headers.push(("x-mbx-apikey".to_string(), api_key_value));

        if let Err(e) = state.credential_store.touch_last_used(&api_key.id).await {
            eprintln!("[fishnet] failed to update binance api key last_used_at: {e}");
        }
        if let Err(e) = state.credential_store.touch_last_used(&api_secret.id).await {
            eprintln!("[fishnet] failed to update binance api secret last_used_at: {e}");
        }
        drop(api_secret);
        drop(api_key);
    } else if !body.is_empty() {
        outbound_body = Some(body.clone());
    }

    let upstream_resp = match send_upstream(
        &state,
        "binance",
        method,
        &headers,
        &target_url,
        outbound_body,
        &skip_headers,
        &extra_headers,
    )
    .await
    {
        Ok(resp) => resp,
        Err(resp) => {
            log_audit_decision(
                &state,
                &audit_ctx,
                "denied",
                Some("upstream provider is unavailable".to_string()),
                None,
                None,
            )
            .await;
            return resp;
        }
    };

    let mut audit_cost = None;
    if is_order
        && upstream_resp.status().is_success()
        && let Some(cost_micros) = order_value_micros
    {
        let today = chrono::Utc::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        if let Err(e) = state
            .spend_store
            .record_spend_micros("binance", &today, cost_micros)
            .await
        {
            eprintln!("[fishnet] failed to record binance spend: {e}");
        }
        audit_cost = Some(micros_to_usd(cost_micros));
    }

    let response = build_proxy_response(upstream_resp);
    log_audit_decision(&state, &audit_ctx, "approved", None, audit_cost, None).await;
    response
}

pub async fn custom_handler(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    body: axum::body::Bytes,
) -> Response {
    let config = state.config();
    let fallback_action = format!("{} {}", method, uri.path());
    let fallback_ctx = build_api_audit_context(
        &state,
        &config,
        "custom",
        &fallback_action,
        &method,
        uri.query(),
        &body,
    );

    let path = uri.path();
    let path = path.strip_prefix("/custom/").unwrap_or(path);
    let (name, rest) = match path.split_once('/') {
        Some((name, rest)) if !name.is_empty() => (name.to_string(), format!("/{rest}")),
        _ => {
            return audited_json_error(
                &state,
                &fallback_ctx,
                StatusCode::BAD_REQUEST,
                "invalid custom proxy path",
            )
            .await;
        }
    };

    let action = format!("{} {}", method, rest);
    let custom_service = format!("custom.{name}");
    let audit_ctx =
        build_api_audit_context(&state, &config, &name, &action, &method, uri.query(), &body);

    let Some(service_cfg) = config.custom.get(&name).cloned() else {
        return audited_json_error(
            &state,
            &audit_ctx,
            StatusCode::BAD_REQUEST,
            &format!("unknown custom service: {name}"),
        )
        .await;
    };

    if service_cfg.base_url.trim().is_empty() {
        return audited_json_error(
            &state,
            &audit_ctx,
            StatusCode::BAD_REQUEST,
            &format!("custom service {name} has empty base_url"),
        )
        .await;
    }

    maybe_emit_request_anomalies(&state, &custom_service, &action).await;

    if service_cfg.rate_limit > 0
        && let Err(retry_after) = state
            .proxy_rate_limiter
            .check_and_record_with_window(
                &format!("custom:{name}"),
                service_cfg.rate_limit,
                service_cfg.rate_limit_window_seconds,
            )
            .await
    {
        let message = format!("rate limit exceeded, retry after {retry_after}s");
        log_audit_decision(
            &state,
            &audit_ctx,
            "denied",
            Some(message.clone()),
            None,
            None,
        )
        .await;
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": message,
                "retry_after_seconds": retry_after
            })),
        )
            .into_response();
    }

    if service_cfg
        .blocked_endpoints
        .iter()
        .any(|pattern| endpoint_pattern_matches(pattern, &method, &rest))
    {
        emit_high_severity_denied_action_alert(
            &state,
            &custom_service,
            &action,
            "blocked by custom policy",
        )
        .await;
        return audited_json_error(
            &state,
            &audit_ctx,
            StatusCode::FORBIDDEN,
            "endpoint blocked by custom policy",
        )
        .await;
    }

    let mut extra_headers: Vec<(String, HeaderValue)> = Vec::new();
    let mut skip_headers = vec!["authorization".to_string(), "x-api-key".to_string()];

    let auth_header_name = service_cfg.auth_header.trim().to_string();
    if !auth_header_name.is_empty() {
        let (auth_secret, credential_id) = match load_custom_credential(&state, &name).await {
            Ok(Some(cred)) => (cred.key, Some(cred.id)),
            Ok(None) => {
                let env_name = service_cfg.auth_value_env.trim();
                if env_name.is_empty() {
                    return audited_json_error(
                        &state,
                        &audit_ctx,
                        StatusCode::BAD_REQUEST,
                        &format!(
                            "credential not found for custom service: {name}; configure vault credential or custom.{name}.auth_value_env"
                        ),
                    )
                    .await;
                }
                match std::env::var(env_name) {
                    Ok(value) if !value.trim().is_empty() => (Zeroizing::new(value), None),
                    Ok(_) => {
                        return audited_json_error(
                            &state,
                            &audit_ctx,
                            StatusCode::BAD_REQUEST,
                            &format!(
                                "custom service {name} auth env var {env_name} is set but empty"
                            ),
                        )
                        .await;
                    }
                    Err(_) => {
                        return audited_json_error(
                            &state,
                            &audit_ctx,
                            StatusCode::BAD_REQUEST,
                            &format!(
                                "credential not found for custom service: {name}; env var {env_name} is not set"
                            ),
                        )
                        .await;
                    }
                }
            }
            Err(resp) => {
                log_audit_decision(
                    &state,
                    &audit_ctx,
                    "denied",
                    Some("failed to access credential vault".to_string()),
                    None,
                    None,
                )
                .await;
                return resp;
            }
        };

        let header_name = match HeaderName::from_bytes(auth_header_name.as_bytes()) {
            Ok(v) => v,
            Err(_) => {
                return audited_json_error(
                    &state,
                    &audit_ctx,
                    StatusCode::BAD_REQUEST,
                    &format!("invalid auth_header for custom service: {name}"),
                )
                .await;
            }
        };
        let header_name_str = header_name.as_str().to_string();
        skip_headers.push(header_name_str.to_ascii_lowercase());

        let header_value = format!("{}{}", service_cfg.auth_value_prefix, auth_secret.as_str());
        let header_value = match HeaderValue::from_str(&header_value) {
            Ok(v) => v,
            Err(_) => {
                return audited_json_error(
                    &state,
                    &audit_ctx,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("invalid credential value for custom service: {name}"),
                )
                .await;
            }
        };
        extra_headers.push((header_name_str, header_value));

        if let Some(credential_id) = credential_id
            && let Err(e) = state.credential_store.touch_last_used(&credential_id).await
        {
            eprintln!("[fishnet] failed to update custom credential last_used_at: {e}");
        }
    }

    let base_url = service_cfg.base_url.trim_end_matches('/');
    let target_url = with_query(base_url, &rest, uri.query());
    let upstream_resp = match send_upstream(
        &state,
        &custom_service,
        method,
        &headers,
        &target_url,
        Some(body),
        &skip_headers,
        &extra_headers,
    )
    .await
    {
        Ok(resp) => resp,
        Err(resp) => {
            log_audit_decision(
                &state,
                &audit_ctx,
                "denied",
                Some("upstream provider is unavailable".to_string()),
                None,
                None,
            )
            .await;
            return resp;
        }
    };

    let response = build_proxy_response(upstream_resp);
    log_audit_decision(&state, &audit_ctx, "approved", None, None, None).await;
    response
}

async fn enforce_llm_guards(
    state: &AppState,
    provider: &str,
    headers: &HeaderMap,
    body: &axum::body::Bytes,
) -> Result<LlmRequestMeta, (StatusCode, String)> {
    let config = state.config();
    let model_restriction_enabled = !config.llm.allowed_models.is_empty();
    let needs_guards = config.llm.prompt_drift.enabled
        || config.llm.prompt_size_guard.enabled
        || model_restriction_enabled;

    let is_json_body = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("application/json"));

    let body_json: Option<serde_json::Value> = if needs_guards && !body.is_empty() && is_json_body {
        match serde_json::from_slice(body) {
            Ok(val) => Some(val),
            Err(e) => {
                eprintln!("[fishnet] invalid JSON body: {e}");
                return Err((
                    StatusCode::BAD_REQUEST,
                    "request body is not valid JSON".to_string(),
                ));
            }
        }
    } else {
        None
    };

    let model = body_json
        .as_ref()
        .and_then(extract_model_name)
        .map(|s| s.to_string());
    let stream_requested = body_json
        .as_ref()
        .and_then(extract_stream_requested)
        .unwrap_or(false);
    if model_restriction_enabled {
        let requested_model = model.clone().unwrap_or_else(|| "<missing>".to_string());
        if !model
            .as_deref()
            .is_some_and(|m| model_allowed(m, &config.llm.allowed_models))
        {
            return Err((
                StatusCode::FORBIDDEN,
                format!("model not in allowlist: {requested_model}"),
            ));
        }
    }

    if let Some(ref body_val) = body_json {
        let system_prompt = extract_system_prompt(provider, body_val);
        let drift_alert_snapshot = snapshot_alert_ids(state).await;
        let drift_result = check_prompt_drift(
            &state.baseline_store,
            &state.alert_store,
            provider,
            system_prompt.as_deref(),
            &config.llm.prompt_drift,
            config.alerts.prompt_drift,
        )
        .await;
        dispatch_new_alerts_of_type(state, drift_alert_snapshot, AlertType::PromptDrift).await;

        if let GuardDecision::Deny(msg) = drift_result {
            return Err((StatusCode::FORBIDDEN, msg));
        }

        let total_chars = count_prompt_chars(provider, body_val);
        let size_alert_snapshot = snapshot_alert_ids(state).await;
        let size_result = check_prompt_size(
            &state.alert_store,
            provider,
            total_chars,
            &config.llm.prompt_size_guard,
            config.alerts.prompt_size,
        )
        .await;
        dispatch_new_alerts_of_type(state, size_alert_snapshot, AlertType::PromptSize).await;

        if let GuardDecision::Deny(msg) = size_result {
            return Err((StatusCode::FORBIDDEN, msg));
        }
    }

    Ok(LlmRequestMeta {
        model,
        stream_requested,
    })
}

fn build_api_audit_context(
    state: &AppState,
    config: &fishnet_types::config::FishnetConfig,
    service: &str,
    action: &str,
    method: &Method,
    query: Option<&str>,
    body: &[u8],
) -> AuditContext {
    AuditContext {
        intent_type: "api_call".to_string(),
        service: service.to_string(),
        action: action.to_string(),
        policy_version_hash: audit::policy_version_hash(&state.config_path, config),
        intent_hash: audit::hash_api_intent(method.as_str(), service, action, query, body),
    }
}

async fn audited_json_error(
    state: &AppState,
    ctx: &AuditContext,
    status: StatusCode,
    message: &str,
) -> Response {
    log_audit_decision(state, ctx, "denied", Some(message.to_string()), None, None).await;
    json_error(status, message)
}

async fn log_audit_decision(
    state: &AppState,
    ctx: &AuditContext,
    decision: &str,
    reason: Option<String>,
    cost_usd: Option<f64>,
    permit_hash: Option<audit::merkle::H256>,
) {
    let entry = NewAuditEntry {
        intent_type: ctx.intent_type.clone(),
        service: ctx.service.clone(),
        action: ctx.action.clone(),
        decision: decision.to_string(),
        reason,
        cost_usd,
        policy_version_hash: ctx.policy_version_hash,
        intent_hash: ctx.intent_hash,
        permit_hash,
    };

    if let Err(e) = state.audit_store.append(entry).await {
        eprintln!("[fishnet] failed to append audit entry: {e}");
    }
}

async fn finalize_llm_response(
    state: &AppState,
    provider: &str,
    request_model: Option<&str>,
    upstream_resp: reqwest::Response,
) -> (Response, Option<f64>) {
    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let upstream_headers = upstream_resp.headers().clone();

    let body_bytes = match upstream_resp.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("[fishnet] failed to read upstream response body: {e}");
            return (
                json_error(StatusCode::BAD_GATEWAY, "upstream provider is unavailable"),
                None,
            );
        }
    };

    let config = state.config();
    let mut recorded_cost = None;

    if status.is_success()
        && config.llm.track_spend
        && let Some(cost_usd) = parse_llm_usage_and_cost(
            provider,
            request_model,
            &body_bytes,
            &config.llm.model_pricing,
        )
    {
        if record_provider_spend(state, provider, cost_usd).await {
            recorded_cost = Some(cost_usd);
        }
    }

    let mut response_builder = Response::builder().status(status);
    for (name, value) in &upstream_headers {
        let name_str = name.as_str();
        if matches!(name_str, "transfer-encoding" | "connection" | "keep-alive") {
            continue;
        }
        if let Ok(header_value) = HeaderValue::from_bytes(value.as_bytes()) {
            response_builder = response_builder.header(name.clone(), header_value);
        }
    }

    let response = match response_builder.body(Body::from(body_bytes)) {
        Ok(response) => response,
        Err(e) => {
            eprintln!("[fishnet] failed to build llm proxy response: {e}");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal proxy error")
        }
    };

    (response, recorded_cost)
}

async fn record_provider_spend(state: &AppState, provider: &str, cost_usd: f64) -> bool {
    let cost_micros = (cost_usd * USD_MICROS_SCALE as f64).round() as i64;
    if cost_micros < 0 {
        return false;
    }

    let today = chrono::Utc::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    if let Err(e) = state
        .spend_store
        .record_spend_micros(provider, &today, cost_micros)
        .await
    {
        eprintln!("[fishnet] failed to record {provider} spend: {e}");
        false
    } else {
        maybe_emit_budget_threshold_alerts(state, provider).await;
        true
    }
}

async fn maybe_emit_budget_threshold_alerts(state: &AppState, provider: &str) {
    if !matches!(provider, "openai" | "anthropic") {
        return;
    }

    let config = state.config();
    let daily_budget_usd = config.llm.daily_budget_usd;
    if !daily_budget_usd.is_finite() || daily_budget_usd <= 0.0 {
        return;
    }

    let rows = match state.spend_store.today_service_totals().await {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("[fishnet] failed to read spend totals for budget alerting: {e}");
            return;
        }
    };

    let spent_today_usd = rows
        .into_iter()
        .filter(|row| matches!(row.service.as_str(), "openai" | "anthropic"))
        .map(|row| row.cost_usd)
        .sum::<f64>();
    let today = chrono::Utc::now().date_naive();

    let alerts = match state.alert_store.list().await {
        Ok(alerts) => alerts,
        Err(e) => {
            eprintln!("[fishnet] failed to read alert store for budget alerting: {e}");
            return;
        }
    };

    let has_today_warning = alerts.iter().any(|alert| {
        alert.alert_type == AlertType::BudgetWarning
            && alert.service == "llm"
            && is_timestamp_in_utc_day(alert.timestamp, today)
    });
    let has_today_exceeded = alerts.iter().any(|alert| {
        alert.alert_type == AlertType::BudgetExceeded
            && alert.service == "llm"
            && is_timestamp_in_utc_day(alert.timestamp, today)
    });

    if config.alerts.budget_exceeded && spent_today_usd >= daily_budget_usd && !has_today_exceeded {
        create_alert_and_dispatch(
            state,
            AlertType::BudgetExceeded,
            AlertSeverity::Critical,
            "llm",
            format!(
                "LLM daily budget exceeded: spent ${spent_today_usd:.4} (limit ${daily_budget_usd:.4})"
            ),
            "budget_exceeded",
        )
        .await;
        return;
    }

    if !config.alerts.budget_warning || has_today_warning || config.llm.budget_warning_pct == 0 {
        return;
    }

    let warning_threshold =
        daily_budget_usd * (f64::from(config.llm.budget_warning_pct).clamp(0.0, 100.0) / 100.0);
    if spent_today_usd >= warning_threshold {
        create_alert_and_dispatch(
            state,
            AlertType::BudgetWarning,
            AlertSeverity::Warning,
            "llm",
            format!(
                "LLM daily budget warning: spent ${spent_today_usd:.4} reached {}% of limit ${daily_budget_usd:.4}",
                config.llm.budget_warning_pct
            ),
            "budget_warning",
        )
        .await;
    }
}

fn is_timestamp_in_utc_day(timestamp: i64, day: chrono::NaiveDate) -> bool {
    chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp, 0)
        .is_some_and(|dt| dt.date_naive() == day)
}

async fn maybe_emit_request_anomalies(state: &AppState, service: &str, action: &str) {
    let config = state.config();
    if !(config.alerts.anomalous_volume || config.alerts.new_endpoint || config.alerts.time_anomaly)
    {
        return;
    }

    let events = {
        let mut tracker = state.anomaly_tracker.lock().await;
        tracker.observe(service, action, chrono::Utc::now())
    };

    for event in events {
        match event.kind {
            AnomalyKind::NewEndpoint if config.alerts.new_endpoint => {
                create_alert_and_dispatch(
                    state,
                    AlertType::NewEndpoint,
                    AlertSeverity::Warning,
                    service,
                    format!("New endpoint detected: {}", event.detail),
                    "anomaly_new_endpoint",
                )
                .await;
            }
            AnomalyKind::VolumeSpike if config.alerts.anomalous_volume => {
                create_alert_and_dispatch(
                    state,
                    AlertType::AnomalousVolume,
                    AlertSeverity::Warning,
                    service,
                    format!("Anomalous request volume detected: {}", event.detail),
                    "anomaly_volume",
                )
                .await;
            }
            AnomalyKind::TimeAnomaly if config.alerts.time_anomaly => {
                create_alert_and_dispatch(
                    state,
                    AlertType::TimeAnomaly,
                    AlertSeverity::Warning,
                    service,
                    format!("Time anomaly detected: {}", event.detail),
                    "anomaly_time",
                )
                .await;
            }
            _ => {}
        }
    }
}

async fn emit_high_severity_denied_action_alert(
    state: &AppState,
    service: &str,
    action: &str,
    reason: &str,
) {
    let config = state.config();
    if !config.alerts.high_severity_denied_action {
        return;
    }

    create_alert_and_dispatch(
        state,
        AlertType::HighSeverityDeniedAction,
        AlertSeverity::Critical,
        service,
        format!("Denied high-severity action {action}: {reason}"),
        "high_severity_denied_action",
    )
    .await;
}

async fn create_alert_and_dispatch(
    state: &AppState,
    alert_type: AlertType,
    severity: AlertSeverity,
    service: &str,
    message: String,
    context: &str,
) {
    webhook::create_alert_and_dispatch(state, alert_type, severity, service, message, context)
        .await;
}

async fn snapshot_alert_ids(state: &AppState) -> Option<HashSet<String>> {
    match state.alert_store.list().await {
        Ok(alerts) => Some(alerts.into_iter().map(|alert| alert.id).collect()),
        Err(e) => {
            eprintln!("[fishnet] failed to snapshot alerts for webhook dispatch: {e}");
            None
        }
    }
}

async fn dispatch_new_alerts_of_type(
    state: &AppState,
    before: Option<HashSet<String>>,
    alert_type: AlertType,
) {
    let Some(before_ids) = before else {
        return;
    };

    let alerts = match state.alert_store.list().await {
        Ok(alerts) => alerts,
        Err(e) => {
            eprintln!("[fishnet] failed to read alerts for webhook dispatch: {e}");
            return;
        }
    };

    for alert in alerts
        .into_iter()
        .filter(|alert| alert.alert_type == alert_type && !before_ids.contains(&alert.id))
    {
        dispatch_alert_webhooks_with_logging(state, &alert, "llm_guard").await;
    }
}

async fn dispatch_alert_webhooks_with_logging(
    state: &AppState,
    alert: &crate::alert::Alert,
    context: &str,
) {
    webhook::dispatch_alert_webhooks_with_logging(state, alert, context).await;
}

fn parse_llm_usage_and_cost(
    provider: &str,
    request_model: Option<&str>,
    body: &[u8],
    model_pricing: &std::collections::HashMap<String, ModelPricing>,
) -> Option<f64> {
    let body_json: serde_json::Value = serde_json::from_slice(body).ok()?;
    let usage = match provider {
        "openai" => parse_openai_usage(&body_json),
        "anthropic" => parse_anthropic_usage(&body_json),
        _ => None,
    }?;

    let model = body_json
        .get("model")
        .and_then(|v| v.as_str())
        .or(request_model)?;
    compute_usage_cost(model, usage, model_pricing)
}

fn parse_openai_usage(body: &serde_json::Value) -> Option<TokenUsage> {
    let usage = body.get("usage")?;
    let prompt_tokens = usage.get("prompt_tokens").and_then(|v| v.as_u64())?;
    let completion_tokens = usage.get("completion_tokens").and_then(|v| v.as_u64())?;
    let total_tokens = usage
        .get("total_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(prompt_tokens + completion_tokens);
    Some(TokenUsage {
        input_tokens: prompt_tokens,
        output_tokens: completion_tokens,
        total_tokens,
    })
}

fn parse_anthropic_usage(body: &serde_json::Value) -> Option<TokenUsage> {
    let usage = body.get("usage")?;
    let input_tokens = usage.get("input_tokens").and_then(|v| v.as_u64())?;
    let output_tokens = usage.get("output_tokens").and_then(|v| v.as_u64())?;
    Some(TokenUsage {
        input_tokens,
        output_tokens,
        total_tokens: input_tokens + output_tokens,
    })
}

fn compute_usage_cost(
    model: &str,
    usage: TokenUsage,
    model_pricing: &std::collections::HashMap<String, ModelPricing>,
) -> Option<f64> {
    let pricing = lookup_model_pricing(model, model_pricing)?;
    if usage.total_tokens == 0 {
        return Some(0.0);
    }

    let input_cost = usage.input_tokens as f64 * pricing.input_per_million_usd / 1_000_000.0;
    let output_cost = usage.output_tokens as f64 * pricing.output_per_million_usd / 1_000_000.0;
    let total = input_cost + output_cost;

    if total.is_finite() && total >= 0.0 {
        Some(total)
    } else {
        None
    }
}

fn lookup_model_pricing<'a>(
    model: &str,
    model_pricing: &'a std::collections::HashMap<String, ModelPricing>,
) -> Option<&'a ModelPricing> {
    if let Some(pricing) = model_pricing.get(model) {
        return Some(pricing);
    }

    let model_lower = model.to_ascii_lowercase();
    model_pricing
        .iter()
        .filter(|(key, _)| {
            let key_lower = key.to_ascii_lowercase();
            model_lower == key_lower
                || model_lower.starts_with(&format!("{key_lower}-"))
                || model_lower.starts_with(&format!("{key_lower}:"))
        })
        .max_by_key(|(key, _)| key.len())
        .map(|(_, pricing)| pricing)
}

fn extract_model_name(body: &serde_json::Value) -> Option<&str> {
    body.get("model").and_then(|v| v.as_str())
}

fn extract_stream_requested(body: &serde_json::Value) -> Option<bool> {
    body.get("stream").and_then(|v| v.as_bool())
}

fn is_json_request(headers: &HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("application/json"))
}

fn request_body_stream_requested(headers: &HeaderMap, body: &axum::body::Bytes) -> Option<bool> {
    if body.is_empty() || !is_json_request(headers) {
        return None;
    }
    let body_json: serde_json::Value = serde_json::from_slice(body).ok()?;
    extract_stream_requested(&body_json)
}

fn openai_stream_include_usage_supported_path(path: &str) -> bool {
    matches!(path, "/v1/chat/completions" | "/chat/completions")
}

fn ensure_openai_stream_include_usage(
    headers: &HeaderMap,
    body: &axum::body::Bytes,
    stream_requested: bool,
) -> axum::body::Bytes {
    if !stream_requested || body.is_empty() || !is_json_request(headers) {
        return body.clone();
    }

    let Ok(mut body_json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return body.clone();
    };
    let Some(body_obj) = body_json.as_object_mut() else {
        return body.clone();
    };

    let stream_options = body_obj
        .entry("stream_options")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let Some(options_obj) = stream_options.as_object_mut() else {
        return body.clone();
    };
    if options_obj.contains_key("include_usage") {
        return body.clone();
    }

    options_obj.insert("include_usage".to_string(), serde_json::Value::Bool(true));
    match serde_json::to_vec(&body_json) {
        Ok(updated) => axum::body::Bytes::from(updated),
        Err(_) => body.clone(),
    }
}

fn model_allowed(model: &str, allowed_models: &[String]) -> bool {
    allowed_models
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(model))
}

fn micros_to_usd(value_micros: i64) -> f64 {
    value_micros as f64 / USD_MICROS_SCALE as f64
}

fn parse_form_pairs(input: &str) -> Vec<(String, String)> {
    form_urlencoded::parse(input.as_bytes())
        .into_owned()
        .collect()
}

fn append_unique_form_pairs(
    parsed_params: &mut Vec<(String, String)>,
    seen_keys: &mut HashSet<String>,
    input: &str,
) -> Result<(), String> {
    for (key, value) in parse_form_pairs(input) {
        if !seen_keys.insert(key.clone()) {
            return Err(format!("duplicate parameter key is not allowed: {key}"));
        }
        parsed_params.push((key, value));
    }
    Ok(())
}

fn serialize_form_pairs(params: &[(String, String)]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (k, v) in params {
        serializer.append_pair(k, v);
    }
    serializer.finish()
}

fn parse_binance_order_value_usd(params: &[(String, String)]) -> Result<i64, String> {
    let symbol = lookup_param(params, "symbol")
        .ok_or_else(|| "missing symbol in binance order request".to_string())?;

    if !is_usd_quoted_symbol(symbol) {
        return Err(format!(
            "unsupported symbol for USD valuation: {symbol}. use a USD-quoted pair (USDT/USDC/BUSD/FDUSD)"
        ));
    }

    if let Some(quote_qty) = lookup_param(params, "quoteOrderQty") {
        let value = parse_positive_decimal(quote_qty)
            .ok_or_else(|| "quoteOrderQty must be a positive number".to_string())?;
        return decimal_to_micros(value, RoundingStrategy::ToPositiveInfinity);
    }

    let price_raw = lookup_param(params, "price");
    let quantity_raw = lookup_param(params, "quantity");
    if price_raw.is_none() && quantity_raw.is_some() {
        return Err(
            "missing price: for MARKET orders please provide quoteOrderQty to express USD value"
                .to_string(),
        );
    }

    let price = price_raw
        .and_then(parse_positive_decimal)
        .ok_or_else(|| "missing or invalid price in binance order request".to_string())?;
    let quantity = quantity_raw
        .and_then(parse_positive_decimal)
        .ok_or_else(|| "missing or invalid quantity in binance order request".to_string())?;

    decimal_to_micros(price * quantity, RoundingStrategy::ToPositiveInfinity)
}

fn parse_positive_decimal(raw: &str) -> Option<Decimal> {
    let value = Decimal::from_str(raw).ok()?;
    if value.is_sign_positive() && !value.is_zero() {
        Some(value)
    } else {
        None
    }
}

fn config_usd_to_micros(raw: f64) -> i64 {
    if !raw.is_finite() || raw <= 0.0 {
        return 0;
    }
    let as_decimal = Decimal::from_str(&raw.to_string()).unwrap_or(Decimal::ZERO);
    decimal_to_micros(as_decimal, RoundingStrategy::ToZero).unwrap_or(0)
}

fn decimal_to_micros(value: Decimal, rounding: RoundingStrategy) -> Result<i64, String> {
    if value.is_sign_negative() {
        return Err("value cannot be negative".to_string());
    }
    let scaled = value * Decimal::from(USD_MICROS_SCALE);
    let rounded = scaled.round_dp_with_strategy(0, rounding);
    rounded
        .to_i64()
        .ok_or_else(|| "value is outside supported range".to_string())
}

fn format_usd_micros(micros: i64) -> String {
    format!("{:.2}", micros as f64 / USD_MICROS_SCALE as f64)
}

fn lookup_param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .rev()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn is_usd_quoted_symbol(symbol: &str) -> bool {
    let symbol = symbol.to_ascii_uppercase();
    symbol.ends_with("USDT")
        || symbol.ends_with("USDC")
        || symbol.ends_with("BUSD")
        || symbol.ends_with("FDUSD")
}

fn endpoint_pattern_matches(pattern: &str, method: &Method, path: &str) -> bool {
    let mut parts = pattern.splitn(2, ' ');
    let Some(pattern_method) = parts.next() else {
        return false;
    };
    let Some(pattern_path) = parts.next() else {
        return false;
    };

    if !pattern_method.trim().eq_ignore_ascii_case(method.as_str()) {
        return false;
    }
    wildcard_path_match(pattern_path.trim(), path)
}

fn wildcard_path_match(pattern: &str, path: &str) -> bool {
    if !pattern.is_empty() && pattern.chars().all(|c| c == '*') {
        return true;
    }

    let chunks: Vec<&str> = pattern.split('*').filter(|p| !p.is_empty()).collect();
    if chunks.is_empty() {
        if pattern.contains('*') {
            return true;
        }
        return pattern == path;
    }

    let mut cursor = 0usize;
    let mut chunk_idx = 0usize;

    if !pattern.starts_with('*') {
        let first = chunks[0];
        if !path.starts_with(first) {
            return false;
        }
        cursor = first.len();
        chunk_idx = 1;
    }

    while chunk_idx < chunks.len() {
        let chunk = chunks[chunk_idx];
        if let Some(found) = path[cursor..].find(chunk) {
            cursor += found + chunk.len();
            chunk_idx += 1;
        } else {
            return false;
        }
    }

    if !pattern.ends_with('*')
        && let Some(last) = chunks.last()
    {
        return path.ends_with(last);
    }

    true
}

async fn load_binance_credentials(
    state: &AppState,
) -> Result<(DecryptedCredential, DecryptedCredential), Response> {
    let api_key = match state
        .credential_store
        .decrypt_for_service_and_name("binance", "api_key")
        .await
    {
        Ok(found) => found,
        Err(e) => {
            eprintln!("[fishnet] failed to read binance api key credential: {e}");
            return Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to access credential vault",
            ));
        }
    };

    let api_secret = match state
        .credential_store
        .decrypt_for_service_and_name("binance", "api_secret")
        .await
    {
        Ok(found) => found,
        Err(e) => {
            eprintln!("[fishnet] failed to read binance api secret credential: {e}");
            return Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to access credential vault",
            ));
        }
    };

    let Some(api_key) = api_key else {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "credential not found for service: binance (expected name=api_key)",
        ));
    };
    let Some(api_secret) = api_secret else {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "credential not found for service: binance (expected name=api_secret)",
        ));
    };

    Ok((api_key, api_secret))
}

async fn load_custom_credential(
    state: &AppState,
    service_name: &str,
) -> Result<Option<DecryptedCredential>, Response> {
    let namespaced = format!("custom.{service_name}");
    match state
        .credential_store
        .decrypt_for_service(&namespaced)
        .await
    {
        Ok(found) => Ok(found),
        Err(e) => {
            eprintln!("[fishnet] failed to decrypt custom credential for {service_name}: {e}");
            Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to access credential vault",
            ))
        }
    }
}

fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> Result<String, String> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| "invalid HMAC key length".to_string())?;
    mac.update(message);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

async fn send_upstream(
    state: &AppState,
    service: &str,
    method: Method,
    headers: &HeaderMap,
    target_url: &str,
    body: Option<axum::body::Bytes>,
    skip_headers: &[String],
    extra_headers: &[(String, HeaderValue)],
) -> Result<reqwest::Response, Response> {
    let mut upstream_req = state
        .http_client_for_service(service)
        .request(method, target_url);

    for (name, value) in headers {
        if should_skip_header(name.as_str(), skip_headers) {
            continue;
        }
        upstream_req = upstream_req.header(name.clone(), value.clone());
    }

    for (name, value) in extra_headers {
        upstream_req = upstream_req.header(name, value.clone());
    }

    if let Some(body) = body
        && !body.is_empty()
    {
        upstream_req = upstream_req.body(body);
    }

    match upstream_req.send().await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            eprintln!("[fishnet] upstream request failed: {e}");
            Err(json_error(
                StatusCode::BAD_GATEWAY,
                "upstream provider is unavailable",
            ))
        }
    }
}

fn should_skip_header(name: &str, extra_skip: &[String]) -> bool {
    let name = name.to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "host" | "transfer-encoding" | "connection" | "keep-alive" | "content-length"
    ) {
        return true;
    }

    extra_skip.iter().any(|h| h == &name)
}

fn response_is_event_stream(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|content_type| content_type.contains("text/event-stream"))
}

fn build_streaming_proxy_response_with_usage(
    state: AppState,
    provider: String,
    request_model: Option<String>,
    mut upstream_resp: reqwest::Response,
    request_id: String,
) -> Result<Response, Response> {
    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let upstream_headers = upstream_resp.headers().clone();
    let (tx, rx) = mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(16);

    let mut response_builder = Response::builder().status(status);
    for (name, value) in &upstream_headers {
        let name_str = name.as_str();
        if matches!(name_str, "transfer-encoding" | "connection" | "keep-alive") {
            continue;
        }
        if let Ok(header_value) = HeaderValue::from_bytes(value.as_bytes()) {
            response_builder = response_builder.header(name.clone(), header_value);
        }
    }

    let body_stream = ReceiverStream::new(rx);
    let body = Body::from_stream(body_stream);
    let response = match response_builder.body(body) {
        Ok(response) => response,
        Err(e) => {
            eprintln!("[fishnet] failed to build streaming response: {e}");
            return Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal proxy error",
            ));
        }
    };

    tokio::spawn(async move {
        let mut usage_collector = StreamUsageCollector::new(request_model);
        let mut stream_completed = true;
        while let Some(next_chunk) = upstream_resp.chunk().await.transpose() {
            match next_chunk {
                Ok(chunk) => {
                    usage_collector.consume_chunk(&provider, &chunk);
                    if tx.send(Ok(chunk)).await.is_err() {
                        stream_completed = false;
                        break;
                    }
                }
                Err(e) => {
                    stream_completed = false;
                    eprintln!(
                        "[fishnet] failed to read streaming response chunk (provider: {provider}, request_id: {request_id}): {e}"
                    );
                    let _ = tx
                        .send(Err(std::io::Error::other("failed to read upstream stream")))
                        .await;
                    break;
                }
            }
        }
        drop(tx);
        usage_collector.finish(&provider);

        if status.is_success() {
            let config = state.config();
            if config.llm.track_spend {
                let (model, usage) = usage_collector.into_parts();
                match (model.as_deref(), usage) {
                    (Some(model), Some(usage)) => {
                        if let Some(cost_usd) =
                            compute_usage_cost(model, usage, &config.llm.model_pricing)
                        {
                            if !record_provider_spend(&state, &provider, cost_usd).await {
                                eprintln!(
                                    "[fishnet] warning: failed to record stream spend (provider: {provider}, model: {model}, request_id: {request_id})"
                                );
                            }
                        } else {
                            eprintln!(
                                "[fishnet] warning: unable to compute stream cost from parsed usage (provider: {provider}, model: {model}, request_id: {request_id})"
                            );
                        }
                    }
                    _ => {
                        eprintln!(
                            "[fishnet] warning: stream ended without complete usage data (provider: {provider}, request_id: {request_id})"
                        );
                    }
                }
            }
        }

        if !stream_completed {
            eprintln!(
                "[fishnet] warning: stream did not complete cleanly; usage/cost may be missing (provider: {provider}, request_id: {request_id})"
            );
        }
    });

    Ok(response)
}

impl StreamUsageCollector {
    fn new(request_model: Option<String>) -> Self {
        Self {
            model: request_model,
            ..Self::default()
        }
    }

    fn consume_chunk(&mut self, provider: &str, chunk: &[u8]) {
        self.line_buffer.extend_from_slice(chunk);
        while let Some(newline_idx) = self.line_buffer.iter().position(|b| *b == b'\n') {
            let mut line_bytes: Vec<u8> = self.line_buffer.drain(..=newline_idx).collect();
            if line_bytes.last() == Some(&b'\n') {
                line_bytes.pop();
            }
            if line_bytes.last() == Some(&b'\r') {
                line_bytes.pop();
            }
            let line = String::from_utf8_lossy(&line_bytes);
            self.handle_line(provider, &line);
        }
    }

    fn finish(&mut self, provider: &str) {
        if !self.line_buffer.is_empty() {
            let mut trailing_line = std::mem::take(&mut self.line_buffer);
            if trailing_line.last() == Some(&b'\r') {
                trailing_line.pop();
            }
            let trailing_line = String::from_utf8_lossy(&trailing_line);
            self.handle_line(provider, &trailing_line);
        }
        self.flush_event(provider);
    }

    fn into_parts(self) -> (Option<String>, Option<TokenUsage>) {
        (self.model, self.usage)
    }

    fn handle_line(&mut self, provider: &str, line: &str) {
        if line.is_empty() {
            self.flush_event(provider);
            return;
        }
        if let Some(data) = line.strip_prefix("data:") {
            if !self.event_data.is_empty() {
                self.event_data.push('\n');
            }
            self.event_data.push_str(data.trim_start());
        }
    }

    fn flush_event(&mut self, provider: &str) {
        if self.event_data.is_empty() {
            return;
        }
        let payload = std::mem::take(&mut self.event_data);
        self.consume_event_payload(provider, payload.trim());
    }

    fn consume_event_payload(&mut self, provider: &str, payload: &str) {
        if payload.is_empty() || payload == "[DONE]" {
            return;
        }
        let Ok(body_json) = serde_json::from_str::<serde_json::Value>(payload) else {
            return;
        };

        if self.model.is_none()
            && let Some(model) = extract_stream_model(provider, &body_json)
        {
            self.model = Some(model.to_string());
        }

        match provider {
            "openai" => {
                if let Some(usage) = parse_openai_usage(&body_json) {
                    self.usage = Some(usage);
                }
            }
            "anthropic" => {
                if let Some(usage) = parse_anthropic_usage(&body_json) {
                    self.usage = Some(usage);
                }
                if let Some(input_tokens) = extract_anthropic_stream_input_tokens(&body_json) {
                    self.anthropic_input_tokens = Some(input_tokens);
                }
                if let Some(output_tokens) = extract_anthropic_stream_output_tokens(&body_json) {
                    self.anthropic_output_tokens = Some(output_tokens);
                }
                if let (Some(input_tokens), Some(output_tokens)) =
                    (self.anthropic_input_tokens, self.anthropic_output_tokens)
                {
                    self.usage = Some(TokenUsage {
                        input_tokens,
                        output_tokens,
                        total_tokens: input_tokens + output_tokens,
                    });
                }
            }
            _ => {}
        }
    }
}

fn extract_stream_model<'a>(provider: &str, body: &'a serde_json::Value) -> Option<&'a str> {
    match provider {
        "anthropic" => body.get("model").and_then(|v| v.as_str()).or_else(|| {
            body.get("message")
                .and_then(|message| message.get("model"))
                .and_then(|v| v.as_str())
        }),
        _ => body.get("model").and_then(|v| v.as_str()),
    }
}

fn extract_anthropic_stream_input_tokens(body: &serde_json::Value) -> Option<u64> {
    body.get("usage")
        .and_then(|usage| usage.get("input_tokens"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            body.get("message")
                .and_then(|message| message.get("usage"))
                .and_then(|usage| usage.get("input_tokens"))
                .and_then(|v| v.as_u64())
        })
}

fn extract_anthropic_stream_output_tokens(body: &serde_json::Value) -> Option<u64> {
    body.get("usage")
        .and_then(|usage| usage.get("output_tokens"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            body.get("message")
                .and_then(|message| message.get("usage"))
                .and_then(|usage| usage.get("output_tokens"))
                .and_then(|v| v.as_u64())
        })
}

fn build_proxy_response(upstream_resp: reqwest::Response) -> Response {
    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response_builder = Response::builder().status(status);

    for (name, value) in upstream_resp.headers() {
        let name_str = name.as_str();
        if matches!(name_str, "transfer-encoding" | "connection" | "keep-alive") {
            continue;
        }
        if let Ok(header_value) = HeaderValue::from_bytes(value.as_bytes()) {
            response_builder = response_builder.header(name.clone(), header_value);
        }
    }

    let body_stream = upstream_resp.bytes_stream();
    let body = Body::from_stream(body_stream);
    match response_builder.body(body) {
        Ok(response) => response,
        Err(e) => {
            eprintln!("[fishnet] failed to build response: {e}");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal proxy error")
        }
    }
}

fn with_query(base: &str, path: &str, query: Option<&str>) -> String {
    match query {
        Some(query) if !query.is_empty() => format!("{base}{path}?{query}"),
        _ => format!("{base}{path}"),
    }
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_path_match_cases() {
        assert!(wildcard_path_match("/repos/*", "/repos/fishnet"));
        assert!(wildcard_path_match("/repos/*", "/repos/owner/repo"));
        assert!(wildcard_path_match(
            "/repos/*/admin/*",
            "/repos/org/admin/teams"
        ));
        assert!(!wildcard_path_match("/repos/*", "/orgs/openai"));
        assert!(wildcard_path_match("*", "/anything"));
        assert!(wildcard_path_match("**", "/repos/owner/repo"));
        assert!(wildcard_path_match("***", "/orgs/openai/teams/devs"));
    }

    #[test]
    fn endpoint_pattern_matching_checks_method() {
        assert!(endpoint_pattern_matches(
            "DELETE /repos/*",
            &Method::DELETE,
            "/repos/fishnet"
        ));
        assert!(!endpoint_pattern_matches(
            "DELETE /repos/*",
            &Method::GET,
            "/repos/fishnet"
        ));
    }

    #[test]
    fn parse_binance_value_from_quote_qty() {
        let params = vec![
            ("symbol".to_string(), "BTCUSDT".to_string()),
            ("quoteOrderQty".to_string(), "125.5".to_string()),
        ];
        let value = parse_binance_order_value_usd(&params).unwrap();
        assert_eq!(value, 125_500_000);
    }

    #[test]
    fn parse_binance_value_from_price_times_qty() {
        let params = vec![
            ("symbol".to_string(), "ETHUSDC".to_string()),
            ("price".to_string(), "2000".to_string()),
            ("quantity".to_string(), "0.1".to_string()),
        ];
        let value = parse_binance_order_value_usd(&params).unwrap();
        assert_eq!(value, 200_000_000);
    }

    #[test]
    fn parse_binance_value_rounds_up_to_micros_for_policy_safety() {
        let params = vec![
            ("symbol".to_string(), "BTCUSDT".to_string()),
            ("quoteOrderQty".to_string(), "0.0000001".to_string()),
        ];
        let value = parse_binance_order_value_usd(&params).unwrap();
        assert_eq!(value, 1);
    }

    #[test]
    fn parse_binance_market_order_requires_quote_qty_when_price_missing() {
        let params = vec![
            ("symbol".to_string(), "BTCUSDT".to_string()),
            ("quantity".to_string(), "0.01".to_string()),
        ];
        let err = parse_binance_order_value_usd(&params).unwrap_err();
        assert!(err.contains("quoteOrderQty"));
    }

    #[test]
    fn append_unique_form_pairs_rejects_duplicate_keys() {
        let mut parsed = Vec::new();
        let mut seen = HashSet::new();
        append_unique_form_pairs(&mut parsed, &mut seen, "price=10").unwrap();
        let err = append_unique_form_pairs(&mut parsed, &mut seen, "price=12").unwrap_err();
        assert!(err.contains("duplicate parameter key"));
    }

    #[test]
    fn content_length_header_is_always_skipped() {
        assert!(should_skip_header("content-length", &[]));
    }

    #[test]
    fn model_allowlist_check_is_case_insensitive() {
        let allowed = vec!["gpt-4o-mini".to_string(), "claude-sonnet".to_string()];
        assert!(model_allowed("GPT-4O-MINI", &allowed));
        assert!(!model_allowed("gpt-4o", &allowed));
    }

    #[test]
    fn openai_include_usage_injection_is_scoped_to_chat_completions_path() {
        assert!(openai_stream_include_usage_supported_path(
            "/v1/chat/completions"
        ));
        assert!(openai_stream_include_usage_supported_path(
            "/chat/completions"
        ));
        assert!(!openai_stream_include_usage_supported_path("/v1/responses"));
        assert!(!openai_stream_include_usage_supported_path(
            "/v1/embeddings"
        ));
    }

    #[test]
    fn ensure_openai_stream_include_usage_injects_when_missing() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        let body = axum::body::Bytes::from(
            r#"{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}"#,
        );

        let updated = ensure_openai_stream_include_usage(&headers, &body, true);
        let json: serde_json::Value = serde_json::from_slice(&updated).unwrap();
        assert_eq!(
            json["stream_options"]["include_usage"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn ensure_openai_stream_include_usage_preserves_existing_value() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        let body = axum::body::Bytes::from(
            r#"{"model":"gpt-4o-mini","stream":true,"stream_options":{"include_usage":false}}"#,
        );

        let updated = ensure_openai_stream_include_usage(&headers, &body, true);
        let json: serde_json::Value = serde_json::from_slice(&updated).unwrap();
        assert_eq!(
            json["stream_options"]["include_usage"].as_bool(),
            Some(false)
        );
    }

    #[test]
    fn parse_openai_usage_and_compute_cost() {
        let mut pricing = std::collections::HashMap::new();
        pricing.insert(
            "gpt-4o-mini".to_string(),
            ModelPricing {
                input_per_million_usd: 0.15,
                output_per_million_usd: 0.60,
            },
        );

        let body = serde_json::json!({
            "model": "gpt-4o-mini",
            "usage": {
                "prompt_tokens": 1000,
                "completion_tokens": 2000,
                "total_tokens": 3000
            }
        });
        let cost = parse_llm_usage_and_cost(
            "openai",
            None,
            &serde_json::to_vec(&body).unwrap(),
            &pricing,
        )
        .unwrap();

        let expected = (1000.0 * 0.15 / 1_000_000.0) + (2000.0 * 0.60 / 1_000_000.0);
        assert!((cost - expected).abs() < 1e-12);
    }

    #[test]
    fn parse_anthropic_usage_and_compute_cost() {
        let mut pricing = std::collections::HashMap::new();
        pricing.insert(
            "claude-sonnet".to_string(),
            ModelPricing {
                input_per_million_usd: 3.0,
                output_per_million_usd: 15.0,
            },
        );

        let body = serde_json::json!({
            "model": "claude-sonnet-4-5",
            "usage": {
                "input_tokens": 500,
                "output_tokens": 250
            }
        });
        let cost = parse_llm_usage_and_cost(
            "anthropic",
            None,
            &serde_json::to_vec(&body).unwrap(),
            &pricing,
        )
        .unwrap();

        let expected = (500.0 * 3.0 / 1_000_000.0) + (250.0 * 15.0 / 1_000_000.0);
        assert!((cost - expected).abs() < 1e-12);
    }

    #[test]
    fn collect_openai_stream_usage_from_sse_events() {
        let mut collector = StreamUsageCollector::new(Some("gpt-4o-mini".to_string()));
        collector.consume_chunk(
            "openai",
            br#"data: {"id":"chatcmpl-1","model":"gpt-4o-mini","choices":[{"delta":{"content":"Hi"}}]}

"#,
        );
        collector.consume_chunk(
            "openai",
            br#"data: {"id":"chatcmpl-1","model":"gpt-4o-mini","choices":[],"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20}}

data: [DONE]

"#,
        );
        collector.finish("openai");

        let (model, usage) = collector.into_parts();
        assert_eq!(model.as_deref(), Some("gpt-4o-mini"));
        let usage = usage.expect("usage should be parsed");
        assert_eq!(usage.input_tokens, 12);
        assert_eq!(usage.output_tokens, 8);
        assert_eq!(usage.total_tokens, 20);
    }

    #[test]
    fn collect_anthropic_stream_usage_across_message_events() {
        let mut collector = StreamUsageCollector::new(Some("claude-sonnet".to_string()));
        collector.consume_chunk(
            "anthropic",
            br#"data: {"type":"message_start","message":{"model":"claude-sonnet-4-5","usage":{"input_tokens":33,"output_tokens":0}}}

"#,
        );
        collector.consume_chunk(
            "anthropic",
            br#"data: {"type":"message_delta","usage":{"output_tokens":17}}

data: {"type":"message_stop"}

"#,
        );
        collector.finish("anthropic");

        let (model, usage) = collector.into_parts();
        assert_eq!(model.as_deref(), Some("claude-sonnet"));
        let usage = usage.expect("usage should be parsed");
        assert_eq!(usage.input_tokens, 33);
        assert_eq!(usage.output_tokens, 17);
        assert_eq!(usage.total_tokens, 50);
    }
}
