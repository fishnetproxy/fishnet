pub mod alert;
pub mod anomaly;
pub mod audit;
pub mod auth;
pub mod config;
pub mod constants;
#[cfg(feature = "embed-dashboard")]
pub mod dashboard;
pub mod llm_guard;
pub mod middleware;
pub mod onchain;
pub mod password;
pub mod proxy;
pub mod rate_limit;
#[cfg(feature = "dev-seed")]
pub mod seed;
pub mod session;
pub mod signer;
pub mod spend;
pub mod state;
pub mod system;
pub mod vault;
pub mod watch;
pub mod webhook;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware as axum_middleware,
    routing::{any, delete, get, post},
};
use tower_http::cors::CorsLayer;

use crate::state::AppState;

pub fn create_router(state: AppState) -> Router {
    let public_routes = Router::new()
        .route("/api/auth/status", get(auth::status))
        .route("/api/auth/setup", post(auth::setup))
        .route("/api/auth/login", post(auth::login));

    let protected_routes = Router::new()
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/status", get(system::status))
        .route(
            "/api/policies",
            get(system::get_policies).put(system::put_policies),
        )
        .route("/api/alerts", get(alert::list_alerts))
        .route("/api/alerts/dismiss", post(alert::dismiss_alert))
        .route(
            "/api/alerts/config",
            get(alert::get_alert_config).put(alert::update_alert_config),
        )
        .route(
            "/api/alerts/webhook-config",
            get(webhook::get_webhook_config).post(webhook::update_webhook_config),
        )
        .route("/api/alerts/webhook-test", post(webhook::test_webhook))
        .route("/api/spend", get(spend::get_spend))
        .route(
            "/api/spend/budgets",
            get(spend::get_budgets).put(spend::set_budget),
        )
        .route(
            "/api/credentials",
            get(vault::list_credentials).post(vault::create_credential),
        )
        .route("/api/credentials/{id}", delete(vault::delete_credential))
        .route("/api/signer/status", get(signer::status_handler))
        .route(
            "/api/onchain/config",
            get(onchain::get_config).put(onchain::update_config),
        )
        .route("/api/onchain/stats", get(onchain::get_stats))
        .route("/api/onchain/permits", get(onchain::list_permits))
        .route("/api/audit", get(audit::list_audit))
        .route("/api/audit/export", get(audit::export_audit_csv))
        .route("/onchain/submit", post(onchain::submit_handler))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::require_auth,
        ));

    let proxy_routes = Router::new()
        .route("/proxy/{provider}/{*rest}", any(proxy::handler))
        .route("/binance/{*rest}", any(proxy::binance_handler))
        .route("/custom/{name}/{*rest}", any(proxy::custom_handler))
        .layer(DefaultBodyLimit::max(constants::MAX_BODY_SIZE));

    let router = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .merge(proxy_routes)
        .layer(CorsLayer::permissive())
        .with_state(state);

    #[cfg(feature = "embed-dashboard")]
    let router = router.fallback(dashboard::static_handler);

    router
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{HeaderMap, Request, StatusCode, Uri};
    use axum::response::IntoResponse;
    use axum::routing::any as any_route;
    use axum::{Json, Router as AxumRouter};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use alert::AlertStore;
    use audit::{AuditStore, NewAuditEntry, merkle};
    use llm_guard::BaselineStore;
    use onchain::OnchainStore;
    use password::FilePasswordStore;
    use rate_limit::{LoginRateLimiter, ProxyRateLimiter};
    use session::SessionStore;
    use signer::StubSigner;
    use spend::SpendStore;
    use vault::CredentialStore;

    fn test_state(dir: &std::path::Path) -> AppState {
        let (config_tx, config_rx) =
            tokio::sync::watch::channel(Arc::new(fishnet_types::config::FishnetConfig::default()));
        let credential_store =
            Arc::new(CredentialStore::open_in_memory("test-master-password").unwrap());
        credential_store
            .insert_plaintext_for_test("openai", "openai-test", "test_openai_key")
            .unwrap();
        credential_store
            .insert_plaintext_for_test("anthropic", "anthropic-test", "test_anthropic_key")
            .unwrap();

        AppState::new(
            Arc::new(FilePasswordStore::new(dir.join("auth.json"))),
            Arc::new(SessionStore::new()),
            Arc::new(LoginRateLimiter::new()),
            Arc::new(ProxyRateLimiter::new()),
            config_tx,
            config_rx,
            dir.join("fishnet.toml"),
            Arc::new(AlertStore::open_in_memory().unwrap()),
            Arc::new(AuditStore::open_in_memory().unwrap()),
            Arc::new(BaselineStore::new()),
            Arc::new(SpendStore::open_in_memory().unwrap()),
            credential_store,
            Arc::new(tokio::sync::Mutex::new(())),
            reqwest::Client::new(),
            std::collections::HashMap::new(),
            Arc::new(tokio::sync::Mutex::new(anomaly::AnomalyTracker::default())),
            Arc::new(OnchainStore::new()),
            Arc::new(StubSigner::new()),
            std::time::Instant::now(),
        )
    }

    async fn body_json(body: Body) -> serde_json::Value {
        let bytes = body.collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn body_text(body: Body) -> String {
        let bytes = body.collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&bytes).to_string()
    }

    fn status_request() -> Request<Body> {
        Request::builder()
            .uri("/api/auth/status")
            .body(Body::empty())
            .unwrap()
    }

    fn setup_request(password: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/auth/setup")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"password":"{password}","confirm":"{password}"}}"#
            )))
            .unwrap()
    }

    fn login_request(password: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"password":"{password}"}}"#)))
            .unwrap()
    }

    fn logout_request(token: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/auth/logout")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_full_auth_flow() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));

        let resp = app.clone().oneshot(status_request()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["initialized"], false);
        assert_eq!(body["authenticated"], false);

        let resp = app
            .clone()
            .oneshot(setup_request("test1234"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["success"], true);

        let resp = app.clone().oneshot(status_request()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["initialized"], true);

        let resp = app
            .clone()
            .oneshot(login_request("test1234"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        let token = body["token"].as_str().unwrap().to_string();
        assert!(token.starts_with("fn_sess_"));
        assert!(body["expires_at"].is_string());

        let resp = app.clone().oneshot(logout_request(&token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["success"], true);

        let resp = app.clone().oneshot(logout_request(&token)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_setup_only_once() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));

        let resp = app
            .clone()
            .oneshot(setup_request("test1234"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .clone()
            .oneshot(setup_request("other123"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));

        app.clone()
            .oneshot(setup_request("test1234"))
            .await
            .unwrap();

        let resp = app
            .clone()
            .oneshot(login_request("wrongpwd"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["error"], "invalid password");
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));

        app.clone()
            .oneshot(setup_request("test1234"))
            .await
            .unwrap();

        for _ in 0..5 {
            let resp = app
                .clone()
                .oneshot(login_request("wrongpwd"))
                .await
                .unwrap();
            assert!(
                resp.status() == StatusCode::UNAUTHORIZED
                    || resp.status() == StatusCode::TOO_MANY_REQUESTS
            );
        }

        let resp = app
            .clone()
            .oneshot(login_request("wrongpwd"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = body_json(resp.into_body()).await;
        assert!(body["retry_after_seconds"].is_number());
    }

    #[tokio::test]
    async fn test_protected_without_token() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/logout")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    fn test_state_with_config(
        dir: &std::path::Path,
        config: fishnet_types::config::FishnetConfig,
    ) -> (
        AppState,
        tokio::sync::watch::Sender<Arc<fishnet_types::config::FishnetConfig>>,
    ) {
        let (tx, config_rx) = tokio::sync::watch::channel(Arc::new(config));
        let credential_store =
            Arc::new(CredentialStore::open_in_memory("test-master-password").unwrap());
        credential_store
            .insert_plaintext_for_test("openai", "openai-test", "test_openai_key")
            .unwrap();
        credential_store
            .insert_plaintext_for_test("anthropic", "anthropic-test", "test_anthropic_key")
            .unwrap();

        let state = AppState::new(
            Arc::new(FilePasswordStore::new(dir.join("auth.json"))),
            Arc::new(SessionStore::new()),
            Arc::new(LoginRateLimiter::new()),
            Arc::new(ProxyRateLimiter::new()),
            tx.clone(),
            config_rx,
            dir.join("fishnet.toml"),
            Arc::new(AlertStore::open_in_memory().unwrap()),
            Arc::new(AuditStore::open_in_memory().unwrap()),
            Arc::new(BaselineStore::new()),
            Arc::new(SpendStore::open_in_memory().unwrap()),
            credential_store,
            Arc::new(tokio::sync::Mutex::new(())),
            reqwest::Client::new(),
            std::collections::HashMap::new(),
            Arc::new(tokio::sync::Mutex::new(anomaly::AnomalyTracker::default())),
            Arc::new(OnchainStore::new()),
            Arc::new(StubSigner::new()),
            std::time::Instant::now(),
        );
        (state, tx)
    }

    fn openai_proxy_request(system_prompt: &str, user_msg: &str) -> Request<Body> {
        let body = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_msg}
            ]
        });
        Request::builder()
            .method("POST")
            .uri("/proxy/openai/v1/chat/completions")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    async fn mock_upstream_handler(
        headers: HeaderMap,
        uri: Uri,
        body: axum::body::Bytes,
    ) -> Json<serde_json::Value> {
        let authorization = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let x_mbx_apikey = headers
            .get("x-mbx-apikey")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        Json(serde_json::json!({
            "authorization": authorization,
            "x_mbx_apikey": x_mbx_apikey,
            "query": uri.query().unwrap_or(""),
            "body": String::from_utf8_lossy(&body).to_string(),
        }))
    }

    async fn spawn_mock_upstream() -> (String, tokio::task::JoinHandle<()>) {
        let router = AxumRouter::new()
            .route("/api/v3/order", any_route(mock_upstream_handler))
            .route("/api/v3/openOrders", any_route(mock_upstream_handler))
            .route("/api/v3/klines", any_route(mock_upstream_handler))
            .route("/api/v3/ticker/{*rest}", any_route(mock_upstream_handler))
            .route("/v1/repos", any_route(mock_upstream_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{addr}"), handle)
    }

    async fn spawn_mock_webhook_target() -> (String, tokio::task::JoinHandle<()>) {
        async fn webhook_handler(_: HeaderMap, _: Uri, _: axum::body::Bytes) -> StatusCode {
            StatusCode::NO_CONTENT
        }

        let router = AxumRouter::new().route("/hook", any_route(webhook_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{addr}/hook"), handle)
    }

    async fn spawn_flaky_webhook_target() -> (String, tokio::task::JoinHandle<()>) {
        let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&call_count);

        let router = AxumRouter::new().route(
            "/hook",
            any_route(move |_: HeaderMap, _: Uri, _: axum::body::Bytes| {
                let counter = Arc::clone(&counter);
                async move {
                    let call_index = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if call_index == 0 {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"error":"temporary failure"})),
                        )
                            .into_response()
                    } else {
                        StatusCode::NO_CONTENT.into_response()
                    }
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{addr}/hook"), handle)
    }

    #[tokio::test]
    async fn test_proxy_drift_deny_blocks_request() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.prompt_drift.mode = fishnet_types::config::GuardMode::Deny;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        let resp = app
            .clone()
            .oneshot(openai_proxy_request("You are helpful.", "Hi"))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);

        let resp = app
            .clone()
            .oneshot(openai_proxy_request("You are evil.", "Hi"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = body_json(resp.into_body()).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("System prompt drift detected")
        );

        let alerts = state.alert_store.list().await.unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, alert::AlertType::PromptDrift);
    }

    #[tokio::test]
    async fn test_proxy_size_guard_deny_blocks_oversized() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.prompt_drift.enabled = false;
        config.llm.prompt_size_guard.max_prompt_tokens = 100;
        config.llm.prompt_size_guard.action = fishnet_types::config::GuardAction::Deny;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        let big_content = "x".repeat(500);
        let resp = app
            .clone()
            .oneshot(openai_proxy_request(&big_content, "Hi"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = body_json(resp.into_body()).await;
        assert!(body["error"].as_str().unwrap().contains("exceeds limit"));
    }

    #[tokio::test]
    async fn test_proxy_size_guard_alert_allows_but_creates_alert() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.prompt_drift.enabled = false;
        config.llm.prompt_size_guard.max_prompt_tokens = 100;
        config.llm.prompt_size_guard.action = fishnet_types::config::GuardAction::Alert;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        let big_content = "x".repeat(500);
        let resp = app
            .clone()
            .oneshot(openai_proxy_request(&big_content, "Hi"))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);

        let alerts = state.alert_store.list().await.unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, alert::AlertType::PromptSize);
    }

    #[tokio::test]
    async fn test_proxy_guards_disabled_passes_through() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.prompt_drift.enabled = false;
        config.llm.prompt_size_guard.enabled = false;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        let big_content = "x".repeat(10000);
        let resp = app
            .clone()
            .oneshot(openai_proxy_request(&big_content, "Hi"))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
        assert!(state.alert_store.list().await.unwrap().is_empty());
        assert!(state.baseline_store.is_empty().await);
    }

    #[tokio::test]
    async fn test_proxy_hot_reload_toggle_off() {
        let dir = tempfile::tempdir().unwrap();
        let config = fishnet_types::config::FishnetConfig::default();
        let (state, tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        let resp = app
            .clone()
            .oneshot(openai_proxy_request("hello", "Hi"))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);

        let mut new_config = fishnet_types::config::FishnetConfig::default();
        new_config.llm.prompt_drift.enabled = false;
        tx.send(Arc::new(new_config)).unwrap();

        let resp = app
            .clone()
            .oneshot(openai_proxy_request("totally different", "Hi"))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
        assert!(state.alert_store.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_proxy_unknown_provider() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = create_router(state);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/proxy/unknown/v1/chat")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_binance_withdraw_is_hard_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.binance.enabled = true;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/binance/sapi/v1/capital/withdraw/apply")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let alerts = state.alert_store.list().await.unwrap();
        assert!(
            alerts
                .iter()
                .any(|alert| alert.alert_type == alert::AlertType::HighSeverityDeniedAction)
        );
    }

    #[tokio::test]
    async fn test_binance_delete_open_orders_blocked_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.binance.enabled = true;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/binance/api/v3/openOrders")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let alerts = state.alert_store.list().await.unwrap();
        assert!(
            alerts
                .iter()
                .any(|alert| alert.alert_type == alert::AlertType::HighSeverityDeniedAction)
        );
    }

    #[tokio::test]
    async fn test_binance_delete_open_orders_allowed_when_policy_enabled() {
        let (base_url, mock_handle) = spawn_mock_upstream().await;

        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.binance.enabled = true;
        config.binance.allow_delete_open_orders = true;
        config.binance.base_url = base_url;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        state
            .credential_store
            .insert_plaintext_for_test("binance", "api_key", "binance_key_delete")
            .unwrap();
        state
            .credential_store
            .insert_plaintext_for_test("binance", "api_secret", "binance_secret_delete")
            .unwrap();
        let app = create_router(state);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/binance/api/v3/openOrders?symbol=BTCUSDT")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_json(resp.into_body()).await;
        let query = body["query"].as_str().unwrap();
        assert_eq!(body["x_mbx_apikey"], "binance_key_delete");
        assert!(query.contains("symbol=BTCUSDT"));
        assert!(query.contains("timestamp="));
        assert!(query.contains("signature="));

        mock_handle.abort();
    }

    #[tokio::test]
    async fn test_binance_read_only_endpoints_allowed_without_credentials() {
        let (base_url, mock_handle) = spawn_mock_upstream().await;

        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.binance.enabled = true;
        config.binance.base_url = base_url;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);

        let ticker_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/binance/api/v3/ticker/price?symbol=BTCUSDT")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ticker_resp.status(), StatusCode::OK);
        let ticker_body = body_json(ticker_resp.into_body()).await;
        let ticker_query = ticker_body["query"].as_str().unwrap();
        assert_eq!(ticker_body["x_mbx_apikey"], "");
        assert_eq!(ticker_query, "symbol=BTCUSDT");
        assert!(!ticker_query.contains("signature="));

        let klines_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/binance/api/v3/klines?symbol=BTCUSDT&interval=1m")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(klines_resp.status(), StatusCode::OK);
        let klines_body = body_json(klines_resp.into_body()).await;
        let klines_query = klines_body["query"].as_str().unwrap();
        assert_eq!(klines_body["x_mbx_apikey"], "");
        assert!(klines_query.contains("symbol=BTCUSDT"));
        assert!(klines_query.contains("interval=1m"));
        assert!(!klines_query.contains("signature="));

        mock_handle.abort();
    }

    #[tokio::test]
    async fn test_anomaly_alerts_for_new_endpoint_and_volume_spike() {
        let (base_url, mock_handle) = spawn_mock_upstream().await;

        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.binance.enabled = true;
        config.binance.base_url = base_url;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        for _ in 0..12 {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/binance/api/v3/ticker/price?symbol=BTCUSDT")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        let alerts = state.alert_store.list().await.unwrap();
        assert!(
            alerts
                .iter()
                .any(|alert| alert.alert_type == alert::AlertType::NewEndpoint)
        );
        assert!(
            alerts
                .iter()
                .any(|alert| alert.alert_type == alert::AlertType::AnomalousVolume)
        );

        mock_handle.abort();
    }

    #[tokio::test]
    async fn test_binance_order_limit_rejected_before_upstream() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.binance.enabled = true;
        config.binance.max_order_value_usd = 100.0;
        let (state, _tx) = test_state_with_config(dir.path(), config);

        state
            .credential_store
            .insert_plaintext_for_test("binance", "api_key", "test_key")
            .unwrap();
        state
            .credential_store
            .insert_plaintext_for_test("binance", "api_secret", "test_secret")
            .unwrap();

        let app = create_router(state);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/binance/api/v3/order")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("symbol=BTCUSDT&quoteOrderQty=150"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_custom_unknown_service_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = create_router(state);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/custom/not-configured/repos")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_custom_blocked_endpoint_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.custom.insert(
            "github".to_string(),
            fishnet_types::config::CustomServiceConfig {
                base_url: "https://api.github.com".to_string(),
                auth_header: "Authorization".to_string(),
                auth_value_prefix: "Bearer ".to_string(),
                auth_value_env: "GITHUB_TOKEN".to_string(),
                blocked_endpoints: vec!["DELETE /repos/*".to_string()],
                rate_limit: 100,
                rate_limit_window_seconds: 3600,
            },
        );

        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/custom/github/repos/example/fishnet")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let alerts = state.alert_store.list().await.unwrap();
        assert!(
            alerts
                .iter()
                .any(|alert| alert.alert_type == alert::AlertType::HighSeverityDeniedAction)
        );
    }

    #[tokio::test]
    async fn test_custom_proxy_does_not_fallback_to_first_class_credential() {
        let (base_url, mock_handle) = spawn_mock_upstream().await;

        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.custom.insert(
            "openai".to_string(),
            fishnet_types::config::CustomServiceConfig {
                base_url,
                auth_header: "Authorization".to_string(),
                auth_value_prefix: "Bearer ".to_string(),
                auth_value_env: "OPENAI_TOKEN".to_string(),
                blocked_endpoints: vec![],
                rate_limit: 100,
                rate_limit_window_seconds: 3600,
            },
        );

        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/custom/openai/v1/repos")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = body_json(resp.into_body()).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("credential not found for custom service: openai")
        );

        mock_handle.abort();
    }

    #[tokio::test]
    async fn test_custom_proxy_injects_auth_header_to_upstream() {
        let (base_url, mock_handle) = spawn_mock_upstream().await;

        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.custom.insert(
            "github".to_string(),
            fishnet_types::config::CustomServiceConfig {
                base_url,
                auth_header: "Authorization".to_string(),
                auth_value_prefix: "Bearer ".to_string(),
                auth_value_env: "GITHUB_TOKEN".to_string(),
                blocked_endpoints: vec![],
                rate_limit: 100,
                rate_limit_window_seconds: 3600,
            },
        );
        let (state, _tx) = test_state_with_config(dir.path(), config);
        state
            .credential_store
            .insert_plaintext_for_test("custom.github", "token", "ghp_mock")
            .unwrap();
        let app = create_router(state);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/custom/github/v1/repos")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_json(resp.into_body()).await;
        assert_eq!(body["authorization"], "Bearer ghp_mock");

        mock_handle.abort();
    }

    #[tokio::test]
    async fn test_custom_proxy_overrides_client_auth_header_with_vault_key() {
        let (base_url, mock_handle) = spawn_mock_upstream().await;

        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.custom.insert(
            "github".to_string(),
            fishnet_types::config::CustomServiceConfig {
                base_url,
                auth_header: "Authorization".to_string(),
                auth_value_prefix: "Bearer ".to_string(),
                auth_value_env: "GITHUB_TOKEN".to_string(),
                blocked_endpoints: vec![],
                rate_limit: 100,
                rate_limit_window_seconds: 3600,
            },
        );
        let (state, _tx) = test_state_with_config(dir.path(), config);
        state
            .credential_store
            .insert_plaintext_for_test("custom.github", "token", "ghp_vault_value")
            .unwrap();
        let app = create_router(state);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/custom/github/v1/repos")
                    .header("authorization", "Bearer attacker_supplied")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_json(resp.into_body()).await;
        assert_eq!(body["authorization"], "Bearer ghp_vault_value");
        assert_ne!(body["authorization"], "Bearer attacker_supplied");

        mock_handle.abort();
    }

    #[tokio::test]
    async fn test_binance_proxy_signs_and_injects_api_key() {
        let (base_url, mock_handle) = spawn_mock_upstream().await;

        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.binance.enabled = true;
        config.binance.base_url = base_url;
        config.binance.max_order_value_usd = 1000.0;
        config.binance.daily_volume_cap_usd = 5000.0;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        state
            .credential_store
            .insert_plaintext_for_test("binance", "api_key", "binance_key_123")
            .unwrap();
        state
            .credential_store
            .insert_plaintext_for_test("binance", "api_secret", "binance_secret_456")
            .unwrap();
        let app = create_router(state.clone());

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/binance/api/v3/order")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("symbol=BTCUSDT&quoteOrderQty=10"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_json(resp.into_body()).await;
        let query = body["query"].as_str().unwrap();
        assert_eq!(body["x_mbx_apikey"], "binance_key_123");
        assert!(query.contains("symbol=BTCUSDT"));
        assert!(query.contains("quoteOrderQty=10"));
        assert!(query.contains("timestamp="));
        assert!(query.contains("recvWindow="));
        assert!(query.contains("signature="));
        assert_eq!(body["body"], "");
        let spent_today = state.spend_store.get_spent_today("binance").await.unwrap();
        assert!((spent_today - 10.0).abs() < 1e-9);

        mock_handle.abort();
    }

    #[tokio::test]
    async fn test_binance_daily_volume_cap_enforced_under_concurrency() {
        let (base_url, mock_handle) = spawn_mock_upstream().await;

        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.binance.enabled = true;
        config.binance.base_url = base_url;
        config.binance.max_order_value_usd = 1_000.0;
        config.binance.daily_volume_cap_usd = 15.0;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        state
            .credential_store
            .insert_plaintext_for_test("binance", "api_key", "binance_key_concurrent")
            .unwrap();
        state
            .credential_store
            .insert_plaintext_for_test("binance", "api_secret", "binance_secret_concurrent")
            .unwrap();
        let app = create_router(state.clone());

        let req1 = Request::builder()
            .method("POST")
            .uri("/binance/api/v3/order")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("symbol=BTCUSDT&quoteOrderQty=10"))
            .unwrap();
        let req2 = Request::builder()
            .method("POST")
            .uri("/binance/api/v3/order")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("symbol=BTCUSDT&quoteOrderQty=10"))
            .unwrap();

        let (resp1, resp2) = tokio::join!(app.clone().oneshot(req1), app.clone().oneshot(req2));
        let resp1 = resp1.unwrap();
        let resp2 = resp2.unwrap();
        let statuses = [resp1.status(), resp2.status()];

        let ok_count = statuses.iter().filter(|s| **s == StatusCode::OK).count();
        let forbidden_count = statuses
            .iter()
            .filter(|s| **s == StatusCode::FORBIDDEN)
            .count();
        assert_eq!(ok_count, 1);
        assert_eq!(forbidden_count, 1);

        let body1 = body_json(resp1.into_body()).await;
        let body2 = body_json(resp2.into_body()).await;
        let err1 = body1["error"].as_str().unwrap_or_default();
        let err2 = body2["error"].as_str().unwrap_or_default();
        assert!(
            err1.contains("daily binance volume cap exceeded")
                || err2.contains("daily binance volume cap exceeded")
        );

        let spent_today = state.spend_store.get_spent_today("binance").await.unwrap();
        assert!((spent_today - 10.0).abs() < 1e-9);

        mock_handle.abort();
    }

    #[tokio::test]
    async fn test_binance_proxy_overrides_client_api_key_header() {
        let (base_url, mock_handle) = spawn_mock_upstream().await;

        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.binance.enabled = true;
        config.binance.base_url = base_url;
        config.binance.max_order_value_usd = 1000.0;
        config.binance.daily_volume_cap_usd = 5000.0;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        state
            .credential_store
            .insert_plaintext_for_test("binance", "api_key", "binance_vault_key")
            .unwrap();
        state
            .credential_store
            .insert_plaintext_for_test("binance", "api_secret", "binance_vault_secret")
            .unwrap();
        let app = create_router(state);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/binance/api/v3/order")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("x-mbx-apikey", "attacker_key")
                    .body(Body::from("symbol=BTCUSDT&quoteOrderQty=10"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_json(resp.into_body()).await;
        assert_eq!(body["x_mbx_apikey"], "binance_vault_key");
        assert_ne!(body["x_mbx_apikey"], "attacker_key");

        mock_handle.abort();
    }

    #[tokio::test]
    async fn test_proxy_invalid_json_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = create_router(state);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/proxy/openai/v1/chat/completions")
                    .header("content-type", "application/json")
                    .body(Body::from("not valid json {{{"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp.into_body()).await;
        assert!(body["error"].as_str().unwrap().contains("not valid JSON"));
    }

    #[tokio::test]
    async fn test_proxy_non_json_body_passes_through() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = create_router(state);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/proxy/openai/v1/files")
                    .header("content-type", "multipart/form-data; boundary=abc")
                    .body(Body::from("--abc\r\ncontent\r\n--abc--"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::BAD_REQUEST);
    }

    async fn setup_and_login(app: &Router) -> String {
        app.clone()
            .oneshot(setup_request("test1234"))
            .await
            .unwrap();
        let resp = app
            .clone()
            .oneshot(login_request("test1234"))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        body["token"].as_str().unwrap().to_string()
    }

    fn authed_get(uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    fn authed_put(uri: &str, token: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("PUT")
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn authed_post(uri: &str, token: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn authed_delete(uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_credentials_api_crud_does_not_leak_keys() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(authed_get("/api/credentials", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        let credentials = body.as_array().unwrap();
        assert!(!credentials.is_empty());
        for credential in credentials {
            assert!(credential["id"].is_string());
            assert!(credential["service"].is_string());
            assert!(credential["name"].is_string());
            assert!(credential["created_at"].is_number());
            assert!(credential.get("key").is_none());
            assert!(credential.get("encrypted_key").is_none());
        }

        let resp = app
            .clone()
            .oneshot(authed_post(
                "/api/credentials",
                &token,
                serde_json::json!({
                    "service": "custom.github",
                    "name": "primary",
                    "key": "ghp_super_secret"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let created = body_json(resp.into_body()).await;
        let created_id = created["id"].as_str().unwrap().to_string();
        assert_eq!(created["service"], "custom.github");
        assert_eq!(created["name"], "primary");
        assert!(created.get("key").is_none());
        assert!(created.get("encrypted_key").is_none());

        let resp = app
            .clone()
            .oneshot(authed_delete(
                &format!("/api/credentials/{created_id}"),
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["deleted"], true);
    }

    #[tokio::test]
    async fn test_alerts_require_auth() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/alerts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_list_alerts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(authed_get("/api/alerts", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["alerts"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_list_alerts_with_data_and_dismiss() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        state
            .alert_store
            .create(
                alert::AlertType::PromptDrift,
                alert::AlertSeverity::Critical,
                "openai",
                "drift detected".to_string(),
            )
            .await
            .unwrap();
        state
            .alert_store
            .create(
                alert::AlertType::PromptSize,
                alert::AlertSeverity::Warning,
                "anthropic",
                "too big".to_string(),
            )
            .await
            .unwrap();

        let resp = app
            .clone()
            .oneshot(authed_get("/api/alerts", &token))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["alerts"].as_array().unwrap().len(), 2);

        assert_eq!(body["alerts"][0]["service"], "openai");
        assert_eq!(body["alerts"][0]["type"], "prompt_drift");
        assert_eq!(body["alerts"][1]["service"], "anthropic");
        assert_eq!(body["alerts"][1]["type"], "prompt_size");

        let resp = app
            .clone()
            .oneshot(authed_get("/api/alerts?type=prompt_drift", &token))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        let alerts = body["alerts"].as_array().unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0]["type"], "prompt_drift");

        let resp = app
            .clone()
            .oneshot(authed_get("/api/alerts?dismissed=false", &token))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["alerts"].as_array().unwrap().len(), 2);

        let alert_id = "alert_001";
        let resp = app
            .clone()
            .oneshot(authed_post(
                "/api/alerts/dismiss",
                &token,
                serde_json::json!({"id": alert_id}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["success"], true);

        let resp = app
            .clone()
            .oneshot(authed_get("/api/alerts?dismissed=true", &token))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        let alerts = body["alerts"].as_array().unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0]["dismissed"], true);

        let resp = app
            .clone()
            .oneshot(authed_get("/api/alerts?dismissed=false", &token))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["alerts"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_list_alerts_pagination() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        for i in 0..5 {
            state
                .alert_store
                .create(
                    alert::AlertType::PromptDrift,
                    alert::AlertSeverity::Warning,
                    "openai",
                    format!("alert {i}"),
                )
                .await
                .unwrap();
        }

        let resp = app
            .clone()
            .oneshot(authed_get("/api/alerts?limit=2", &token))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["alerts"].as_array().unwrap().len(), 2);

        let resp = app
            .clone()
            .oneshot(authed_get("/api/alerts?skip=3", &token))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["alerts"].as_array().unwrap().len(), 2);

        let resp = app
            .clone()
            .oneshot(authed_get("/api/alerts?skip=2&limit=2", &token))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["alerts"].as_array().unwrap().len(), 2);

        let resp = app
            .clone()
            .oneshot(authed_get("/api/alerts?skip=100", &token))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["alerts"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_dismiss_nonexistent_alert() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(authed_post(
                "/api/alerts/dismiss",
                &token,
                serde_json::json!({"id": "alert_999"}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_alert_config() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(authed_get("/api/alerts/config", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;

        assert_eq!(body["toggles"]["prompt_drift"], true);
        assert_eq!(body["toggles"]["prompt_size"], true);
        assert_eq!(body["toggles"]["budget_warning"], true);
        assert_eq!(body["toggles"]["budget_exceeded"], true);
        assert_eq!(body["toggles"]["onchain_denied"], true);
        assert_eq!(body["toggles"]["rate_limit_hit"], true);
        assert_eq!(body["retention_days"], 30);
    }

    #[tokio::test]
    async fn test_update_alert_config_partial() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        let config_path = dir.path().join("fishnet.toml");
        std::fs::write(&config_path, "").unwrap();

        let resp = app
            .clone()
            .oneshot(authed_put(
                "/api/alerts/config",
                &token,
                serde_json::json!({"prompt_drift": false}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["success"], true);
        assert_eq!(body["toggles"]["prompt_drift"], false);
        assert_eq!(body["toggles"]["prompt_size"], true);
        assert_eq!(body["toggles"]["budget_warning"], true);

        let content = std::fs::read_to_string(&config_path).unwrap();
        let reloaded: fishnet_types::config::FishnetConfig = toml::from_str(&content).unwrap();
        assert!(!reloaded.alerts.prompt_drift);
        assert!(reloaded.alerts.prompt_size);
    }

    #[tokio::test]
    async fn test_webhook_config_and_test_send() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));
        let token = setup_and_login(&app).await;
        let (hook_url, hook_handle) = spawn_mock_webhook_target().await;

        let resp = app
            .clone()
            .oneshot(authed_post(
                "/api/alerts/webhook-config",
                &token,
                serde_json::json!({ "discord_url": hook_url }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["saved"], true);
        assert_eq!(body["discord_configured"], true);

        let resp = app
            .clone()
            .oneshot(authed_post(
                "/api/alerts/webhook-test",
                &token,
                serde_json::json!({ "provider": "discord", "message": "ping" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["configured_any"], true);
        assert_eq!(body["results"][0]["provider"], "discord");
        assert_eq!(body["results"][0]["sent"], true);

        hook_handle.abort();
    }

    #[tokio::test]
    async fn test_webhook_config_clear_with_null() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));
        let token = setup_and_login(&app).await;
        let (hook_url, hook_handle) = spawn_mock_webhook_target().await;

        let resp = app
            .clone()
            .oneshot(authed_post(
                "/api/alerts/webhook-config",
                &token,
                serde_json::json!({ "discord_url": hook_url }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .clone()
            .oneshot(authed_post(
                "/api/alerts/webhook-config",
                &token,
                serde_json::json!({ "discord_url": null }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["discord_configured"], false);

        hook_handle.abort();
    }

    #[tokio::test]
    async fn test_webhook_test_retries_after_temporary_failure() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));
        let token = setup_and_login(&app).await;
        let (hook_url, hook_handle) = spawn_flaky_webhook_target().await;

        let resp = app
            .clone()
            .oneshot(authed_post(
                "/api/alerts/webhook-config",
                &token,
                serde_json::json!({ "discord_url": hook_url }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .clone()
            .oneshot(authed_post(
                "/api/alerts/webhook-test",
                &token,
                serde_json::json!({ "provider": "discord", "message": "retry me" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["results"][0]["sent"], true);

        hook_handle.abort();
    }

    #[tokio::test]
    async fn test_spend_requires_auth() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/spend")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_spend_track_spend_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.track_spend = false;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(authed_get("/api/spend", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["enabled"], false);
        assert!(body.get("daily").is_none());
    }

    #[tokio::test]
    async fn test_spend_empty_data() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(authed_get("/api/spend", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["enabled"], true);
        assert_eq!(body["daily"].as_array().unwrap().len(), 0);
        assert_eq!(body["config"]["track_spend"], true);
        assert_eq!(body["config"]["spend_history_days"], 30);
    }

    #[tokio::test]
    async fn test_spend_with_data() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        let today = chrono::Utc::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        state
            .spend_store
            .record_spend("openai", &today, 4.20)
            .await
            .unwrap();
        state
            .spend_store
            .record_spend("anthropic", &today, 1.80)
            .await
            .unwrap();

        let resp = app
            .clone()
            .oneshot(authed_get("/api/spend", &token))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["enabled"], true);
        assert_eq!(body["daily"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_spend_days_param_capped() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.dashboard.spend_history_days = 7;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(authed_get("/api/spend?days=365", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_spend_budgets_crud() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(authed_get("/api/spend/budgets", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["budgets"].as_array().unwrap().len(), 0);

        let resp = app
            .clone()
            .oneshot(authed_put(
                "/api/spend/budgets",
                &token,
                serde_json::json!({
                    "service": "openai",
                    "daily_budget_usd": 20.0,
                    "monthly_budget_usd": 500.0
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["success"], true);
        assert_eq!(body["budget"]["service"], "openai");
        assert_eq!(body["budget"]["daily_budget_usd"], 20.0);

        let resp = app
            .clone()
            .oneshot(authed_get("/api/spend/budgets", &token))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        let budgets = body["budgets"].as_array().unwrap();
        assert_eq!(budgets.len(), 1);
        assert_eq!(budgets[0]["service"], "openai");

        let resp = app
            .clone()
            .oneshot(authed_put(
                "/api/spend/budgets",
                &token,
                serde_json::json!({
                    "service": "openai",
                    "daily_budget_usd": 30.0
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .clone()
            .oneshot(authed_get("/api/spend/budgets", &token))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["budgets"][0]["daily_budget_usd"], 30.0);
    }

    #[tokio::test]
    async fn test_spend_budget_warning_active() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.budget_warning_pct = 80;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        state
            .spend_store
            .set_budget(&spend::ServiceBudget {
                service: "openai".to_string(),
                daily_budget_usd: 10.0,
                monthly_budget_usd: None,
                updated_at: 0,
            })
            .await
            .unwrap();

        let today = chrono::Utc::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        state
            .spend_store
            .record_spend("openai", &today, 9.0)
            .await
            .unwrap();

        let resp = app
            .clone()
            .oneshot(authed_get("/api/spend", &token))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["budgets"]["openai"]["warning_active"], true);
        assert_eq!(body["budgets"]["openai"]["daily_limit"], 10.0);
        assert_eq!(body["budgets"]["openai"]["spent_today"], 9.0);
    }

    #[tokio::test]
    async fn test_spend_budget_warning_inactive_when_pct_zero() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.budget_warning_pct = 0;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        state
            .spend_store
            .set_budget(&spend::ServiceBudget {
                service: "openai".to_string(),
                daily_budget_usd: 10.0,
                monthly_budget_usd: None,
                updated_at: 0,
            })
            .await
            .unwrap();

        let today = chrono::Utc::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        state
            .spend_store
            .record_spend("openai", &today, 9.0)
            .await
            .unwrap();

        let resp = app
            .clone()
            .oneshot(authed_get("/api/spend", &token))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["budgets"]["openai"]["warning_active"], false);
    }

    #[tokio::test]
    async fn test_proxy_rate_limit_returns_429() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.rate_limit_per_minute = 2;
        config.llm.prompt_drift.enabled = false;
        config.llm.prompt_size_guard.enabled = false;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        for _ in 0..2 {
            let resp = app
                .clone()
                .oneshot(openai_proxy_request("hello", "Hi"))
                .await
                .unwrap();
            assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        }

        let resp = app
            .clone()
            .oneshot(openai_proxy_request("hello", "Hi"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = body_json(resp.into_body()).await;
        assert!(body["retry_after_seconds"].is_number());
        assert!(body["error"].as_str().unwrap().contains("rate limit"));

        let alerts = state.alert_store.list().await.unwrap();
        assert!(
            alerts
                .iter()
                .any(|a| a.alert_type == alert::AlertType::RateLimitHit)
        );
    }

    #[tokio::test]
    async fn test_proxy_rate_limit_zero_disables() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.rate_limit_per_minute = 0;
        config.llm.prompt_drift.enabled = false;
        config.llm.prompt_size_guard.enabled = false;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        for _ in 0..10 {
            let resp = app
                .clone()
                .oneshot(openai_proxy_request("hello", "Hi"))
                .await
                .unwrap();
            assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }

    #[tokio::test]
    async fn test_proxy_rate_limit_alert_toggle_off() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.rate_limit_per_minute = 1;
        config.llm.prompt_drift.enabled = false;
        config.llm.prompt_size_guard.enabled = false;
        config.alerts.rate_limit_hit = false;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        app.clone()
            .oneshot(openai_proxy_request("hello", "Hi"))
            .await
            .unwrap();

        let resp = app
            .clone()
            .oneshot(openai_proxy_request("hello", "Hi"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        assert!(state.alert_store.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_proxy_drift_alert_toggle_off_still_denies() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.prompt_drift.mode = fishnet_types::config::GuardMode::Deny;
        config.alerts.prompt_drift = false;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        app.clone()
            .oneshot(openai_proxy_request("You are helpful.", "Hi"))
            .await
            .unwrap();

        let resp = app
            .clone()
            .oneshot(openai_proxy_request("You are evil.", "Hi"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        assert!(state.alert_store.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_proxy_size_alert_toggle_off_still_denies() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.llm.prompt_drift.enabled = false;
        config.llm.prompt_size_guard.max_prompt_tokens = 100;
        config.llm.prompt_size_guard.action = fishnet_types::config::GuardAction::Deny;
        config.alerts.prompt_size = false;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());

        let big_content = "x".repeat(500);
        let resp = app
            .clone()
            .oneshot(openai_proxy_request(&big_content, "Hi"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        assert!(state.alert_store.list().await.unwrap().is_empty());
    }

    fn onchain_config_enabled() -> fishnet_types::config::FishnetConfig {
        let mut config = fishnet_types::config::FishnetConfig::default();
        config.onchain.enabled = true;
        config.onchain.chain_ids = vec![8453, 42161];
        config.onchain.limits.cooldown_seconds = 0;
        config.onchain.permits.verifying_contract =
            "0x00000000000000000000000000000000DeaDBeef".to_string();
        config.onchain.whitelist.insert(
            "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD".to_string(),
            vec!["execute(bytes,bytes[],uint256)".to_string()],
        );
        config
    }

    fn onchain_submit_request(
        target: &str,
        calldata: &str,
        value: &str,
        chain_id: u64,
        token: &str,
    ) -> Request<Body> {
        let body = serde_json::json!({
            "target": target,
            "calldata": calldata,
            "value": value,
            "chain_id": chain_id,
        });
        Request::builder()
            .method("POST")
            .uri("/onchain/submit")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn valid_calldata() -> String {
        "0x3593564c0000000000000000000000000000000000000000".to_string()
    }

    #[tokio::test]
    async fn test_onchain_submit_requires_auth() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));

        let body = serde_json::json!({
            "target": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
            "calldata": valid_calldata(),
            "value": "0",
            "chain_id": 8453,
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/onchain/submit")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_onchain_disabled_returns_400() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["error"], "onchain_disabled");
    }

    #[tokio::test]
    async fn test_onchain_disabled_signer_status() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(authed_get("/api/signer/status", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["enabled"], false);
        assert!(body["mode"].is_null());
        assert!(body["address"].is_null());
    }

    #[tokio::test]
    async fn test_onchain_enabled_signer_status() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(authed_get("/api/signer/status", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["enabled"], true);
        assert_eq!(body["mode"], "stub-secp256k1");
        assert!(body["address"].as_str().unwrap().starts_with("0x"));
        assert_eq!(body["chain_ids"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_onchain_hot_reload_toggle() {
        let dir = tempfile::tempdir().unwrap();
        let config = fishnet_types::config::FishnetConfig::default();
        let (state, tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let new_config = onchain_config_enabled();
        tx.send(Arc::new(new_config)).unwrap();

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_onchain_empty_chain_ids_denies_all() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = onchain_config_enabled();
        config.onchain.chain_ids = vec![];
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "denied");
        assert_eq!(body["limit"], "chain_id");
    }

    #[tokio::test]
    async fn test_onchain_wrong_chain_id_denied() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                1,
                &token,
            ))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "denied");
        assert_eq!(body["limit"], "chain_id");
    }

    #[tokio::test]
    async fn test_onchain_whitelisted_contract_approved() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "approved");
        assert!(body["permit"]["wallet"].as_str().unwrap().starts_with("0x"));
        assert_eq!(body["permit"]["chainId"], 8453);
        assert!(body["signature"].as_str().unwrap().starts_with("0x"));
    }

    #[tokio::test]
    async fn test_onchain_unknown_contract_denied() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0xDEAD000000000000000000000000000000000000",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "denied");
        assert_eq!(body["limit"], "whitelist");
    }

    #[tokio::test]
    async fn test_onchain_wrong_function_selector_denied() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                "0xdeadbeef0000000000000000000000000000000000000000",
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "denied");
        assert_eq!(body["limit"], "function_selector");
    }

    #[tokio::test]
    async fn test_onchain_max_tx_value_exceeded() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = onchain_config_enabled();
        config.onchain.limits.max_tx_value_usd = 100.0;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "200",
                8453,
                &token,
            ))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "denied");
        assert_eq!(body["limit"], "max_tx_value_usd");
    }

    #[tokio::test]
    async fn test_onchain_max_tx_value_zero_disables() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = onchain_config_enabled();
        config.onchain.limits.max_tx_value_usd = 0.0;
        config.onchain.limits.daily_spend_cap_usd = 0.0;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "999999",
                8453,
                &token,
            ))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "approved");
    }

    #[tokio::test]
    async fn test_onchain_daily_spend_cap_exceeded() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = onchain_config_enabled();
        config.onchain.limits.max_tx_value_usd = 0.0;
        config.onchain.limits.daily_spend_cap_usd = 500.0;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        state
            .spend_store
            .record_permit(&spend::PermitEntry {
                chain_id: 8453,
                target: "0x3fC9",
                value: "450",
                status: "approved",
                reason: None,
                permit_hash: None,
                cost_usd: 450.0,
            })
            .await
            .unwrap();

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "100",
                8453,
                &token,
            ))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "denied");
        assert_eq!(body["limit"], "daily_spend_cap_usd");
    }

    #[tokio::test]
    async fn test_onchain_daily_spend_cap_zero_disables() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = onchain_config_enabled();
        config.onchain.limits.daily_spend_cap_usd = 0.0;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "approved");
    }

    #[tokio::test]
    async fn test_onchain_cooldown_blocks_rapid_fire() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = onchain_config_enabled();
        config.onchain.limits.cooldown_seconds = 60;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "approved");

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "denied");
        assert_eq!(body["limit"], "cooldown");
    }

    #[tokio::test]
    async fn test_onchain_cooldown_zero_allows_rapid_fire() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = onchain_config_enabled();
        config.onchain.limits.cooldown_seconds = 0;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        for _ in 0..3 {
            let resp = app
                .clone()
                .oneshot(onchain_submit_request(
                    "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                    &valid_calldata(),
                    "0",
                    8453,
                    &token,
                ))
                .await
                .unwrap();
            let body = body_json(resp.into_body()).await;
            assert_eq!(body["status"], "approved");
        }
    }

    #[tokio::test]
    async fn test_onchain_permit_expiry_matches_config() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = onchain_config_enabled();
        config.onchain.permits.expiry_seconds = 120;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let before = chrono::Utc::now().timestamp() as u64;
        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "approved");

        let expiry = body["permit"]["expiry"].as_u64().unwrap();
        assert!(expiry >= before + 120);
        assert!(expiry <= before + 125);
    }

    #[tokio::test]
    async fn test_onchain_policy_hash_included_when_required() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = onchain_config_enabled();
        config.onchain.permits.require_policy_hash = true;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "approved");
        assert!(
            body["permit"]["policyHash"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );
    }

    #[tokio::test]
    async fn test_onchain_policy_hash_null_when_not_required() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = onchain_config_enabled();
        config.onchain.permits.require_policy_hash = false;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "approved");
        assert!(body["permit"]["policyHash"].is_null());
    }

    #[tokio::test]
    async fn test_onchain_denial_creates_alert() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0xDEAD000000000000000000000000000000000000",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "denied");

        let alerts = state.alert_store.list().await.unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, alert::AlertType::OnchainDenied);
    }

    #[tokio::test]
    async fn test_onchain_denial_alert_dedup() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        for _ in 0..3 {
            app.clone()
                .oneshot(onchain_submit_request(
                    "0xDEAD000000000000000000000000000000000000",
                    &valid_calldata(),
                    "0",
                    8453,
                    &token,
                ))
                .await
                .unwrap();
        }

        let alerts = state.alert_store.list().await.unwrap();
        assert_eq!(alerts.len(), 1);
    }

    #[tokio::test]
    async fn test_onchain_denial_alert_toggle_off() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = onchain_config_enabled();
        config.alerts.onchain_denied = false;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        app.clone()
            .oneshot(onchain_submit_request(
                "0xDEAD000000000000000000000000000000000000",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();

        assert!(state.alert_store.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_onchain_stats_match_audit() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        app.clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "50",
                8453,
                &token,
            ))
            .await
            .unwrap();

        app.clone()
            .oneshot(onchain_submit_request(
                "0xDEAD000000000000000000000000000000000000",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();

        let resp = app
            .clone()
            .oneshot(authed_get("/api/signer/status", &token))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["stats"]["total_permits_signed"], 1);
        assert_eq!(body["stats"]["total_permits_denied"], 1);
        assert!((body["stats"]["spent_today_usd"].as_f64().unwrap() - 50.0).abs() < 0.01);
        assert!(body["stats"]["last_permit_at"].is_number());
    }

    #[tokio::test]
    async fn test_onchain_config_get() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(authed_get("/api/onchain/config", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["enabled"], true);
        assert_eq!(body["chain_ids"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_onchain_config_update_partial() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let config_path = dir.path().join("fishnet.toml");
        std::fs::write(&config_path, "").unwrap();

        let resp = app
            .clone()
            .oneshot(authed_put(
                "/api/onchain/config",
                &token,
                serde_json::json!({"cooldown_seconds": 120}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["success"], true);
        assert_eq!(body["limits"]["cooldown_seconds"], 120);
        assert_eq!(body["enabled"], true);
    }

    #[tokio::test]
    async fn test_onchain_config_update_rejects_invalid_values() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let config_path = dir.path().join("fishnet.toml");
        std::fs::write(&config_path, "").unwrap();

        let resp = app
            .clone()
            .oneshot(authed_put(
                "/api/onchain/config",
                &token,
                serde_json::json!({"max_tx_value_usd": -10.0}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp.into_body()).await;
        assert!(
            body["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e.as_str().unwrap().contains("max_tx_value_usd"))
        );

        let resp = app
            .clone()
            .oneshot(authed_put(
                "/api/onchain/config",
                &token,
                serde_json::json!({"daily_spend_cap_usd": -1.0}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = app
            .clone()
            .oneshot(authed_put(
                "/api/onchain/config",
                &token,
                serde_json::json!({"max_slippage_bps": 10001}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = app
            .clone()
            .oneshot(authed_put(
                "/api/onchain/config",
                &token,
                serde_json::json!({"max_leverage": 0}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = app
            .clone()
            .oneshot(authed_put(
                "/api/onchain/config",
                &token,
                serde_json::json!({"cooldown_seconds": 86401}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = app
            .clone()
            .oneshot(authed_put(
                "/api/onchain/config",
                &token,
                serde_json::json!({"expiry_seconds": 10}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = app
            .clone()
            .oneshot(authed_put(
                "/api/onchain/config",
                &token,
                serde_json::json!({"max_tx_value_usd": -5.0, "max_slippage_bps": 99999}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["errors"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_onchain_permits_list() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        app.clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();

        let resp = app
            .clone()
            .oneshot(authed_get("/api/onchain/permits", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        let permits = body["permits"].as_array().unwrap();
        assert_eq!(permits.len(), 1);
        assert_eq!(permits[0]["status"], "approved");
    }

    #[tokio::test]
    async fn test_onchain_permits_filter_by_status() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        app.clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();

        app.clone()
            .oneshot(onchain_submit_request(
                "0xDEAD000000000000000000000000000000000000",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();

        let resp = app
            .clone()
            .oneshot(authed_get("/api/onchain/permits?status=approved", &token))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["permits"].as_array().unwrap().len(), 1);

        let resp = app
            .clone()
            .oneshot(authed_get("/api/onchain/permits?status=denied", &token))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["permits"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_onchain_stats_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(authed_get("/api/onchain/stats", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["total_permits_signed"], 0);
        assert_eq!(body["total_permits_denied"], 0);
    }

    #[tokio::test]
    async fn test_onchain_signer_status_requires_auth() {
        let dir = tempfile::tempdir().unwrap();
        let app = create_router(test_state(dir.path()));

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/signer/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_onchain_missing_verifying_contract() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = onchain_config_enabled();
        config.onchain.permits.verifying_contract = String::new();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["error"], "verifying_contract_not_configured");
    }

    #[tokio::test]
    async fn test_onchain_verifying_contract_in_permit() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let expected_vc = config.onchain.permits.verifying_contract.clone();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "approved");
        assert_eq!(body["permit"]["verifyingContract"], expected_vc);
    }

    #[tokio::test]
    async fn test_onchain_malformed_verifying_contract() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = onchain_config_enabled();
        config.onchain.permits.verifying_contract = "0xZZZZnotvalidhex".to_string();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["error"], "invalid_verifying_contract");
    }

    #[tokio::test]
    async fn test_onchain_invalid_calldata_hex_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                "0x3593564cZZZZinvalidhex",
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["error"], "invalid_calldata");
    }

    #[tokio::test]
    async fn test_onchain_invalid_target_address_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x1234",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["error"], "invalid_target");

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["error"], "invalid_target");

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "0",
                8453,
                &token,
            ))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_onchain_invalid_value_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let config = onchain_config_enabled();
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                "not_a_number",
                8453,
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["error"], "invalid_value");
    }

    #[tokio::test]
    async fn test_onchain_large_uint256_value_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = onchain_config_enabled();
        config.onchain.limits.max_tx_value_usd = 0.0;
        config.onchain.limits.daily_spend_cap_usd = 0.0;
        let (state, _tx) = test_state_with_config(dir.path(), config);
        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let large_value = "340282366920938463463374607431768211457";
        let resp = app
            .clone()
            .oneshot(onchain_submit_request(
                "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                &valid_calldata(),
                large_value,
                8453,
                &token,
            ))
            .await
            .unwrap();
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "approved");
        assert_eq!(body["permit"]["value"], large_value);
    }

    #[tokio::test]
    async fn test_status_endpoint_returns_runtime_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let today = chrono::Utc::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        state
            .spend_store
            .record_spend("openai", &today, 1.25)
            .await
            .unwrap();
        state
            .audit_store
            .append(NewAuditEntry {
                intent_type: "api_call".to_string(),
                service: "openai".to_string(),
                action: "POST /v1/chat/completions".to_string(),
                decision: "approved".to_string(),
                reason: None,
                cost_usd: Some(1.25),
                policy_version_hash: merkle::keccak256(b"policy"),
                intent_hash: merkle::keccak256(b"intent"),
                permit_hash: None,
            })
            .await
            .unwrap();

        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(authed_get("/api/status", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["running"], true);
        assert!(!body["uptime"].as_str().unwrap_or_default().is_empty());
        assert!(body["today_spend"]["openai"].as_f64().unwrap_or(0.0) >= 1.25);
        assert!(body["today_requests"]["openai"].as_u64().unwrap_or(0) >= 1);
    }

    #[tokio::test]
    async fn test_policies_put_and_get() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = create_router(state.clone());
        let token = setup_and_login(&app).await;

        let mut updated = (*state.config()).clone();
        updated.llm.allowed_models = vec!["gpt-4o".to_string()];

        let resp = app
            .clone()
            .oneshot(authed_put(
                "/api/policies",
                &token,
                serde_json::to_value(updated).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["saved"], true);
        assert!(
            body["policy_hash"]
                .as_str()
                .unwrap_or_default()
                .starts_with("0x")
        );
        let persisted = crate::config::load_config(Some(&state.config_path)).unwrap();
        assert_eq!(persisted.llm.allowed_models, vec!["gpt-4o".to_string()]);
    }

    #[tokio::test]
    async fn test_audit_query_and_export_endpoints() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());

        for i in 0..3 {
            state
                .audit_store
                .append(NewAuditEntry {
                    intent_type: "api_call".to_string(),
                    service: "openai".to_string(),
                    action: format!("POST /v1/chat/completions/{i}"),
                    decision: "approved".to_string(),
                    reason: None,
                    cost_usd: Some(0.1),
                    policy_version_hash: merkle::keccak256(b"policy"),
                    intent_hash: merkle::keccak256(format!("intent-{i}").as_bytes()),
                    permit_hash: None,
                })
                .await
                .unwrap();
        }

        let app = create_router(state);
        let token = setup_and_login(&app).await;

        let resp = app
            .clone()
            .oneshot(authed_get("/api/audit?page=1&page_size=2", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["total"], 3);
        assert_eq!(body["entries"].as_array().unwrap().len(), 2);

        let resp = app
            .clone()
            .oneshot(authed_get("/api/audit/export", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
            "text/csv; charset=utf-8"
        );
        let csv = body_text(resp.into_body()).await;
        assert!(
            csv.starts_with("id,timestamp,intent_type,service,action,decision,reason,cost_usd")
        );
    }
}
