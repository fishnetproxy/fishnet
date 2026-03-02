use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use crate::constants;
use crate::state::AppState;

#[derive(Debug, thiserror::Error)]
pub enum AlertError {
    #[error("{0}")]
    Db(#[from] rusqlite::Error),
    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("state poisoned: {0}")]
    Poisoned(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertType {
    PromptDrift,
    PromptSize,
    BudgetWarning,
    BudgetExceeded,
    OnchainDenied,
    RateLimitHit,
    AnomalousVolume,
    NewEndpoint,
    TimeAnomaly,
    HighSeverityDeniedAction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Critical,
    Warning,
}

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub id: String,
    #[serde(rename = "type")]
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub service: String,
    pub message: String,
    pub timestamp: i64,
    pub dismissed: bool,
}

fn alert_type_to_str(t: AlertType) -> &'static str {
    match t {
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

fn str_to_alert_type(s: &str) -> AlertType {
    match s {
        "prompt_drift" => AlertType::PromptDrift,
        "prompt_size" => AlertType::PromptSize,
        "budget_warning" => AlertType::BudgetWarning,
        "budget_exceeded" => AlertType::BudgetExceeded,
        "onchain_denied" => AlertType::OnchainDenied,
        "rate_limit_hit" => AlertType::RateLimitHit,
        "anomalous_volume" => AlertType::AnomalousVolume,
        "new_endpoint" => AlertType::NewEndpoint,
        "time_anomaly" => AlertType::TimeAnomaly,
        "high_severity_denied_action" => AlertType::HighSeverityDeniedAction,
        _ => AlertType::PromptDrift,
    }
}

fn severity_to_str(s: AlertSeverity) -> &'static str {
    match s {
        AlertSeverity::Critical => "critical",
        AlertSeverity::Warning => "warning",
    }
}

fn str_to_severity(s: &str) -> AlertSeverity {
    match s {
        "critical" => AlertSeverity::Critical,
        "warning" => AlertSeverity::Warning,
        _ => AlertSeverity::Warning,
    }
}

const CLEANUP_INTERVAL_SECS: i64 = 7 * 24 * 60 * 60;

pub struct AlertStore {
    conn: Arc<Mutex<Connection>>,
    last_cleanup_at: AtomicI64,
}

fn poison_to_sqlite_error(resource: &str) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(format!(
        "{resource} mutex is poisoned"
    ))))
}

impl AlertStore {
    pub fn open(path: PathBuf) -> Result<Self, rusqlite::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(&path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            last_cleanup_at: AtomicI64::new(0),
        };
        store.migrate()?;
        Ok(store)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            last_cleanup_at: AtomicI64::new(0),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), rusqlite::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| poison_to_sqlite_error("alerts database connection"))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                service TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                dismissed INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);",
        )?;
        Ok(())
    }

    pub async fn create(
        &self,
        alert_type: AlertType,
        severity: AlertSeverity,
        service: &str,
        message: String,
    ) -> Result<Alert, AlertError> {
        let conn = self.conn.clone();
        let service = service.to_string();
        let type_str = alert_type_to_str(alert_type).to_string();
        let severity_str = severity_to_str(severity).to_string();
        let now = chrono::Utc::now().timestamp();

        let svc = service.clone();
        let msg = message.clone();
        let rowid = tokio::task::spawn_blocking(move || -> Result<i64, AlertError> {
            let conn = conn
                .lock()
                .map_err(|_| AlertError::Poisoned("alerts database connection".to_string()))?;
            conn.execute(
                "INSERT INTO alerts (alert_type, severity, service, message, timestamp, dismissed)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                params![type_str, severity_str, svc, msg, now],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await??;

        Ok(Alert {
            id: format!("alert_{rowid}"),
            alert_type,
            severity,
            service,
            message,
            timestamp: now,
            dismissed: false,
        })
    }

    pub async fn list(&self) -> Result<Vec<Alert>, AlertError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<Alert>, AlertError> {
            let conn = conn
                .lock()
                .map_err(|_| AlertError::Poisoned("alerts database connection".to_string()))?;
            let mut stmt = conn.prepare(
                "SELECT id, alert_type, severity, service, message, timestamp, dismissed
                 FROM alerts ORDER BY id ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                let rowid: i64 = row.get(0)?;
                let type_str: String = row.get(1)?;
                let severity_str: String = row.get(2)?;
                let dismissed_int: i64 = row.get(6)?;
                Ok(Alert {
                    id: format!("alert_{rowid}"),
                    alert_type: str_to_alert_type(&type_str),
                    severity: str_to_severity(&severity_str),
                    service: row.get(3)?,
                    message: row.get(4)?,
                    timestamp: row.get(5)?,
                    dismissed: dismissed_int != 0,
                })
            })?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row?);
            }
            Ok(results)
        })
        .await?
    }

    pub async fn should_create_onchain_alert(&self, message: &str) -> bool {
        self.should_create_onchain_alert_inner(message)
            .await
            .unwrap_or(true)
    }

    async fn should_create_onchain_alert_inner(&self, message: &str) -> Result<bool, AlertError> {
        let conn = self.conn.clone();
        let message = message.to_string();
        let one_hour_ago = chrono::Utc::now().timestamp() - 3600;
        tokio::task::spawn_blocking(move || -> Result<bool, AlertError> {
            let conn = conn
                .lock()
                .map_err(|_| AlertError::Poisoned("alerts database connection".to_string()))?;
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM alerts
                 WHERE alert_type = 'onchain_denied' AND message = ?1 AND timestamp > ?2",
                params![message, one_hour_ago],
                |row| row.get(0),
            )?;
            Ok(count == 0)
        })
        .await?
    }

    pub async fn dismiss(&self, id: &str) -> Result<bool, AlertError> {
        let numeric_id: i64 = id
            .strip_prefix("alert_")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if numeric_id == 0 {
            return Ok(false);
        }
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<bool, AlertError> {
            let conn = conn
                .lock()
                .map_err(|_| AlertError::Poisoned("alerts database connection".to_string()))?;
            let updated = conn.execute(
                "UPDATE alerts SET dismissed = 1 WHERE id = ?1",
                params![numeric_id],
            )?;
            Ok(updated > 0)
        })
        .await?
    }

    pub async fn cleanup(&self, retention_days: u32) -> Result<(), AlertError> {
        let conn = self.conn.clone();
        let now = chrono::Utc::now().timestamp();
        let cutoff = now - (retention_days as i64 * 24 * 60 * 60);
        tokio::task::spawn_blocking(move || -> Result<(), AlertError> {
            let conn = conn
                .lock()
                .map_err(|_| AlertError::Poisoned("alerts database connection".to_string()))?;
            conn.execute("DELETE FROM alerts WHERE timestamp < ?1", params![cutoff])?;
            Ok(())
        })
        .await??;
        self.last_cleanup_at.store(now, Ordering::SeqCst);
        Ok(())
    }

    pub async fn cleanup_if_needed(&self, retention_days: u32) -> Result<(), AlertError> {
        let now = chrono::Utc::now().timestamp();
        let last = self.last_cleanup_at.load(Ordering::SeqCst);
        if now - last >= CLEANUP_INTERVAL_SECS {
            self.cleanup(retention_days).await?;
        }
        Ok(())
    }

    pub fn default_path() -> Option<PathBuf> {
        constants::default_data_file(constants::ALERTS_DB_FILE)
    }
}

#[derive(Debug, Deserialize)]
pub struct AlertQuery {
    #[serde(rename = "type")]
    pub alert_type: Option<AlertType>,
    pub dismissed: Option<bool>,
    pub limit: Option<usize>,
    pub skip: Option<usize>,
}

pub async fn list_alerts(
    State(state): State<AppState>,
    Query(query): Query<AlertQuery>,
) -> impl IntoResponse {
    let config = state.config();
    if let Err(e) = state
        .alert_store
        .cleanup_if_needed(config.alerts.retention_days)
        .await
    {
        eprintln!("[fishnet] alert cleanup failed: {e}");
    }

    let mut alerts = match state.alert_store.list().await {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("database error: {e}") })),
            )
                .into_response();
        }
    };

    if let Some(ref t) = query.alert_type {
        alerts.retain(|a| &a.alert_type == t);
    }

    if let Some(dismissed) = query.dismissed {
        alerts.retain(|a| a.dismissed == dismissed);
    }

    let skip = query.skip.unwrap_or(0);
    let alerts: Vec<Alert> = match query.limit {
        Some(limit) => alerts.into_iter().skip(skip).take(limit).collect(),
        None => alerts.into_iter().skip(skip).collect(),
    };

    Json(serde_json::json!({ "alerts": alerts })).into_response()
}

pub async fn dismiss_alert(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let id = match body.get("id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "missing alert id" })),
            )
                .into_response();
        }
    };

    match state.alert_store.dismiss(id).await {
        Ok(true) => Json(serde_json::json!({ "success": true })).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "alert not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("database error: {e}") })),
        )
            .into_response(),
    }
}

pub async fn get_alert_config(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.config();
    Json(serde_json::json!({
        "toggles": {
            "prompt_drift": config.alerts.prompt_drift,
            "prompt_size": config.alerts.prompt_size,
            "budget_warning": config.alerts.budget_warning,
            "budget_exceeded": config.alerts.budget_exceeded,
            "onchain_denied": config.alerts.onchain_denied,
            "rate_limit_hit": config.alerts.rate_limit_hit,
            "anomalous_volume": config.alerts.anomalous_volume,
            "new_endpoint": config.alerts.new_endpoint,
            "time_anomaly": config.alerts.time_anomaly,
            "high_severity_denied_action": config.alerts.high_severity_denied_action,
        },
        "retention_days": config.alerts.retention_days,
    }))
}

#[derive(Debug, Deserialize)]
pub struct UpdateAlertConfigRequest {
    pub prompt_drift: Option<bool>,
    pub prompt_size: Option<bool>,
    pub budget_warning: Option<bool>,
    pub budget_exceeded: Option<bool>,
    pub onchain_denied: Option<bool>,
    pub rate_limit_hit: Option<bool>,
    pub anomalous_volume: Option<bool>,
    pub new_endpoint: Option<bool>,
    pub time_anomaly: Option<bool>,
    pub high_severity_denied_action: Option<bool>,
    pub retention_days: Option<u32>,
}

pub async fn update_alert_config(
    State(state): State<AppState>,
    Json(req): Json<UpdateAlertConfigRequest>,
) -> impl IntoResponse {
    let current = state.config();
    let mut updated = (*current).clone();

    if let Some(v) = req.prompt_drift {
        updated.alerts.prompt_drift = v;
    }
    if let Some(v) = req.prompt_size {
        updated.alerts.prompt_size = v;
    }
    if let Some(v) = req.budget_warning {
        updated.alerts.budget_warning = v;
    }
    if let Some(v) = req.budget_exceeded {
        updated.alerts.budget_exceeded = v;
    }
    if let Some(v) = req.onchain_denied {
        updated.alerts.onchain_denied = v;
    }
    if let Some(v) = req.rate_limit_hit {
        updated.alerts.rate_limit_hit = v;
    }
    if let Some(v) = req.anomalous_volume {
        updated.alerts.anomalous_volume = v;
    }
    if let Some(v) = req.new_endpoint {
        updated.alerts.new_endpoint = v;
    }
    if let Some(v) = req.time_anomaly {
        updated.alerts.time_anomaly = v;
    }
    if let Some(v) = req.high_severity_denied_action {
        updated.alerts.high_severity_denied_action = v;
    }
    if let Some(v) = req.retention_days {
        updated.alerts.retention_days = v;
    }

    match crate::config::save_config(&state.config_path, &updated) {
        Ok(()) => Json(serde_json::json!({
            "success": true,
            "toggles": {
                "prompt_drift": updated.alerts.prompt_drift,
                "prompt_size": updated.alerts.prompt_size,
                "budget_warning": updated.alerts.budget_warning,
                "budget_exceeded": updated.alerts.budget_exceeded,
                "onchain_denied": updated.alerts.onchain_denied,
                "rate_limit_hit": updated.alerts.rate_limit_hit,
                "anomalous_volume": updated.alerts.anomalous_volume,
                "new_endpoint": updated.alerts.new_endpoint,
                "time_anomaly": updated.alerts.time_anomaly,
                "high_severity_denied_action": updated.alerts.high_severity_denied_action,
            },
            "retention_days": updated.alerts.retention_days,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("failed to save config: {e}") })),
        )
            .into_response(),
    }
}
