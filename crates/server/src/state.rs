use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use fishnet_types::config::FishnetConfig;
use tokio::sync::watch;

use crate::alert::AlertStore;
use crate::anomaly::AnomalyTracker;
use crate::audit::AuditStore;
use crate::llm_guard::BaselineStore;
use crate::onchain::OnchainStore;
use crate::password::PasswordVerifier;
use crate::rate_limit::{LoginRateLimiter, ProxyRateLimiter};
use crate::session::SessionStore;
use crate::signer::SignerTrait;
use crate::spend::SpendStore;
use crate::vault::CredentialStore;

#[derive(Clone)]
pub struct AppState {
    pub password_store: Arc<dyn PasswordVerifier>,
    pub session_store: Arc<SessionStore>,
    pub rate_limiter: Arc<LoginRateLimiter>,
    pub proxy_rate_limiter: Arc<ProxyRateLimiter>,
    config_tx: watch::Sender<Arc<FishnetConfig>>,
    pub config_rx: watch::Receiver<Arc<FishnetConfig>>,
    pub config_path: PathBuf,
    pub alert_store: Arc<AlertStore>,
    pub audit_store: Arc<AuditStore>,
    pub baseline_store: Arc<BaselineStore>,
    pub spend_store: Arc<SpendStore>,
    pub credential_store: Arc<CredentialStore>,
    pub binance_order_lock: Arc<tokio::sync::Mutex<()>>,
    pub http_client: reqwest::Client,
    pub http_clients_by_service: Arc<HashMap<String, reqwest::Client>>,
    pub anomaly_tracker: Arc<tokio::sync::Mutex<AnomalyTracker>>,
    pub onchain_store: Arc<OnchainStore>,
    pub signer: Arc<dyn SignerTrait>,
    pub started_at: std::time::Instant,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        password_store: Arc<dyn PasswordVerifier>,
        session_store: Arc<SessionStore>,
        rate_limiter: Arc<LoginRateLimiter>,
        proxy_rate_limiter: Arc<ProxyRateLimiter>,
        config_tx: watch::Sender<Arc<FishnetConfig>>,
        config_rx: watch::Receiver<Arc<FishnetConfig>>,
        config_path: PathBuf,
        alert_store: Arc<AlertStore>,
        audit_store: Arc<AuditStore>,
        baseline_store: Arc<BaselineStore>,
        spend_store: Arc<SpendStore>,
        credential_store: Arc<CredentialStore>,
        binance_order_lock: Arc<tokio::sync::Mutex<()>>,
        http_client: reqwest::Client,
        http_clients_by_service: HashMap<String, reqwest::Client>,
        anomaly_tracker: Arc<tokio::sync::Mutex<AnomalyTracker>>,
        onchain_store: Arc<OnchainStore>,
        signer: Arc<dyn SignerTrait>,
        started_at: std::time::Instant,
    ) -> Self {
        Self {
            password_store,
            session_store,
            rate_limiter,
            proxy_rate_limiter,
            config_tx,
            config_rx,
            config_path,
            alert_store,
            audit_store,
            baseline_store,
            spend_store,
            credential_store,
            binance_order_lock,
            http_client,
            http_clients_by_service: Arc::new(http_clients_by_service),
            anomaly_tracker,
            onchain_store,
            signer,
            started_at,
        }
    }

    pub fn config(&self) -> Arc<FishnetConfig> {
        self.config_rx.borrow().clone()
    }

    pub fn update_config(
        &self,
        new_config: Arc<FishnetConfig>,
    ) -> Result<(), watch::error::SendError<Arc<FishnetConfig>>> {
        self.config_tx.send(new_config)
    }

    pub fn http_client_for_service(&self, service: &str) -> &reqwest::Client {
        if let Some(client) = self.http_clients_by_service.get(service) {
            return client;
        }

        if let Some(name) = service.strip_prefix("custom.") {
            if let Some(client) = self.http_clients_by_service.get(name) {
                return client;
            }
            if let Some(client) = self.http_clients_by_service.get("custom") {
                return client;
            }
        }

        &self.http_client
    }
}
