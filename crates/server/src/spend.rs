use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use crate::constants;
use crate::state::AppState;

const USD_MICROS_SCALE: i64 = 1_000_000;

#[derive(Debug, thiserror::Error)]
pub enum SpendError {
    #[error("{0}")]
    Db(#[from] rusqlite::Error),
    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("invalid spend amount: {0}")]
    InvalidAmount(String),
    #[error("state poisoned: {0}")]
    Poisoned(String),
}

pub struct SpendStore {
    conn: Arc<Mutex<Connection>>,
}

fn poison_to_sqlite_error(resource: &str) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(format!(
        "{resource} mutex is poisoned"
    ))))
}

#[derive(Debug, Clone, Serialize)]
pub struct SpendRecord {
    pub service: String,
    pub date: String,
    pub cost_usd: f64,
    pub request_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TodayServiceSpend {
    pub service: String,
    pub cost_usd: f64,
    pub request_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceBudget {
    pub service: String,
    pub daily_budget_usd: f64,
    pub monthly_budget_usd: Option<f64>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OnchainStats {
    pub total_signed: i64,
    pub total_denied: i64,
    pub spent_today_usd: f64,
    pub last_permit_at: Option<i64>,
}

impl Default for OnchainStats {
    fn default() -> Self {
        Self {
            total_signed: 0,
            total_denied: 0,
            spent_today_usd: 0.0,
            last_permit_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PermitRecord {
    pub id: i64,
    pub chain_id: i64,
    pub target: String,
    pub value: String,
    pub status: String,
    pub reason: Option<String>,
    pub permit_hash: Option<String>,
    pub cost_usd: f64,
    pub date: String,
    pub created_at: i64,
}

pub struct PermitEntry<'a> {
    pub chain_id: u64,
    pub target: &'a str,
    pub value: &'a str,
    pub status: &'a str,
    pub reason: Option<&'a str>,
    pub permit_hash: Option<&'a str>,
    pub cost_usd: f64,
}

impl SpendStore {
    pub fn open(path: PathBuf) -> Result<Self, rusqlite::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(&path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.migrate()?;
        Ok(store)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA busy_timeout=5000;")?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), rusqlite::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| poison_to_sqlite_error("spend database connection"))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS spend_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                date TEXT NOT NULL,
                cost_usd REAL NOT NULL,
                cost_micros INTEGER NOT NULL DEFAULT 0,
                request_count INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_spend_service_date
                ON spend_records(service, date);

            CREATE TABLE IF NOT EXISTS service_budgets (
                service TEXT PRIMARY KEY,
                daily_budget_usd REAL NOT NULL,
                monthly_budget_usd REAL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS onchain_permits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id INTEGER NOT NULL,
                target TEXT NOT NULL,
                value TEXT NOT NULL,
                status TEXT NOT NULL,
                reason TEXT,
                permit_hash TEXT,
                cost_usd REAL NOT NULL DEFAULT 0.0,
                date TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_onchain_date
                ON onchain_permits(date);
            CREATE INDEX IF NOT EXISTS idx_onchain_status
                ON onchain_permits(status);

            CREATE TABLE IF NOT EXISTS nonce_counter (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                value INTEGER NOT NULL DEFAULT 0
            );
            INSERT OR IGNORE INTO nonce_counter (id, value) VALUES (1, 0);",
        )?;
        Self::ensure_cost_micros_column(&conn)?;
        Ok(())
    }

    fn ensure_cost_micros_column(conn: &Connection) -> Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare("PRAGMA table_info(spend_records)")?;
        let mut rows = stmt.query([])?;
        let mut has_cost_micros = false;
        while let Some(row) = rows.next()? {
            let column_name: String = row.get(1)?;
            if column_name == "cost_micros" {
                has_cost_micros = true;
                break;
            }
        }

        if !has_cost_micros {
            conn.execute(
                "ALTER TABLE spend_records ADD COLUMN cost_micros INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }

        let mut stmt = conn.prepare(
            "SELECT rowid, cost_usd
             FROM spend_records
             WHERE cost_micros = 0 AND cost_usd != 0",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, f64>(1)?)))?;

        let mut updates: Vec<(i64, i64)> = Vec::new();
        for row in rows {
            let (row_id, cost_usd) = row?;
            let cost_micros = usd_f64_to_micros(cost_usd)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            updates.push((row_id, cost_micros));
        }

        for (row_id, cost_micros) in updates {
            conn.execute(
                "UPDATE spend_records SET cost_micros = ?1 WHERE rowid = ?2",
                params![cost_micros, row_id],
            )?;
        }

        Ok(())
    }

    pub async fn record_spend(
        &self,
        service: &str,
        date: &str,
        cost_usd: f64,
    ) -> Result<i64, SpendError> {
        let cost_micros = usd_f64_to_micros(cost_usd)?;
        self.record_spend_micros(service, date, cost_micros).await
    }

    pub async fn record_spend_micros(
        &self,
        service: &str,
        date: &str,
        cost_micros: i64,
    ) -> Result<i64, SpendError> {
        if cost_micros < 0 {
            return Err(SpendError::InvalidAmount(format!(
                "{cost_micros} micros is negative"
            )));
        }
        let conn = self.conn.clone();
        let service = service.to_string();
        let date = date.to_string();
        let cost_usd = micros_to_usd_f64(cost_micros);
        tokio::task::spawn_blocking(move || -> Result<_, SpendError> {
            let conn = conn
                .lock()
                .map_err(|_| SpendError::Poisoned("spend database connection".to_string()))?;
            let now = chrono::Utc::now().timestamp();
            conn.execute(
                "INSERT INTO spend_records (service, date, cost_usd, cost_micros, request_count, created_at)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                params![service, date, cost_usd, cost_micros, now],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await?
    }

    pub async fn query_spend(&self, days: u32) -> Result<Vec<SpendRecord>, SpendError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<_, SpendError> {
            let conn = conn
                .lock()
                .map_err(|_| SpendError::Poisoned("spend database connection".to_string()))?;
            let cutoff = chrono::Utc::now()
                .date_naive()
                .checked_sub_days(chrono::Days::new(days as u64))
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_default();

            let mut stmt = conn.prepare(
                "SELECT service, date, SUM(cost_usd) as total_cost, SUM(request_count) as total_requests
                 FROM spend_records
                 WHERE date >= ?1
                 GROUP BY service, date
                 ORDER BY date DESC, service ASC",
            )?;

            let rows = stmt.query_map(params![cutoff], |row| {
                Ok(SpendRecord {
                    service: row.get(0)?,
                    date: row.get(1)?,
                    cost_usd: row.get(2)?,
                    request_count: row.get(3)?,
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

    pub async fn get_spent_today(&self, service: &str) -> Result<f64, SpendError> {
        let conn = self.conn.clone();
        let service = service.to_string();
        tokio::task::spawn_blocking(move || -> Result<_, SpendError> {
            let conn = conn
                .lock()
                .map_err(|_| SpendError::Poisoned("spend database connection".to_string()))?;
            let today = chrono::Utc::now()
                .date_naive()
                .format("%Y-%m-%d")
                .to_string();
            let spent: f64 = conn.query_row(
                "SELECT COALESCE(SUM(cost_usd), 0.0) FROM spend_records WHERE service = ?1 AND date = ?2",
                params![service, today],
                |row| row.get(0),
            )?;
            Ok(spent)
        })
        .await?
    }

    pub async fn get_spent_today_micros(&self, service: &str) -> Result<i64, SpendError> {
        let conn = self.conn.clone();
        let service = service.to_string();
        tokio::task::spawn_blocking(move || -> Result<_, SpendError> {
            let conn = conn
                .lock()
                .map_err(|_| SpendError::Poisoned("spend database connection".to_string()))?;
            let today = chrono::Utc::now()
                .date_naive()
                .format("%Y-%m-%d")
                .to_string();
            let spent: i64 = conn.query_row(
                "SELECT COALESCE(SUM(cost_micros), 0) FROM spend_records WHERE service = ?1 AND date = ?2",
                params![service, today],
                |row| row.get(0),
            )?;
            Ok(spent)
        })
        .await?
    }

    pub async fn today_service_totals(&self) -> Result<Vec<TodayServiceSpend>, SpendError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<_, SpendError> {
            let conn = conn
                .lock()
                .map_err(|_| SpendError::Poisoned("spend database connection".to_string()))?;
            let today = chrono::Utc::now()
                .date_naive()
                .format("%Y-%m-%d")
                .to_string();
            let mut stmt = conn.prepare(
                "SELECT service, COALESCE(SUM(cost_usd), 0.0), COALESCE(SUM(request_count), 0)
                 FROM spend_records
                 WHERE date = ?1
                 GROUP BY service
                 ORDER BY service ASC",
            )?;

            let rows = stmt.query_map(params![today], |row| {
                Ok(TodayServiceSpend {
                    service: row.get(0)?,
                    cost_usd: row.get(1)?,
                    request_count: row.get(2)?,
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

    pub async fn set_budget(&self, budget: &ServiceBudget) -> Result<(), SpendError> {
        let conn = self.conn.clone();
        let budget = budget.clone();
        tokio::task::spawn_blocking(move || -> Result<_, SpendError> {
            let conn = conn
                .lock()
                .map_err(|_| SpendError::Poisoned("spend database connection".to_string()))?;
            conn.execute(
                "INSERT INTO service_budgets (service, daily_budget_usd, monthly_budget_usd, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(service) DO UPDATE SET
                    daily_budget_usd = excluded.daily_budget_usd,
                    monthly_budget_usd = excluded.monthly_budget_usd,
                    updated_at = excluded.updated_at",
                params![
                    budget.service,
                    budget.daily_budget_usd,
                    budget.monthly_budget_usd,
                    budget.updated_at
                ],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn get_budgets(&self) -> Result<Vec<ServiceBudget>, SpendError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<_, SpendError> {
            let conn = conn
                .lock()
                .map_err(|_| SpendError::Poisoned("spend database connection".to_string()))?;
            let mut stmt = conn.prepare(
                "SELECT service, daily_budget_usd, monthly_budget_usd, updated_at FROM service_budgets",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(ServiceBudget {
                    service: row.get(0)?,
                    daily_budget_usd: row.get(1)?,
                    monthly_budget_usd: row.get(2)?,
                    updated_at: row.get(3)?,
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

    pub async fn get_budget(&self, service: &str) -> Result<Option<ServiceBudget>, SpendError> {
        let conn = self.conn.clone();
        let service = service.to_string();
        tokio::task::spawn_blocking(move || -> Result<_, SpendError> {
            let conn = conn
                .lock()
                .map_err(|_| SpendError::Poisoned("spend database connection".to_string()))?;
            let mut stmt = conn.prepare(
                "SELECT service, daily_budget_usd, monthly_budget_usd, updated_at
                 FROM service_budgets WHERE service = ?1",
            )?;
            let mut rows = stmt.query_map(params![service], |row| {
                Ok(ServiceBudget {
                    service: row.get(0)?,
                    daily_budget_usd: row.get(1)?,
                    monthly_budget_usd: row.get(2)?,
                    updated_at: row.get(3)?,
                })
            })?;
            match rows.next() {
                Some(Ok(budget)) => Ok(Some(budget)),
                Some(Err(e)) => Err(e.into()),
                None => Ok(None),
            }
        })
        .await?
    }

    pub fn default_path() -> Option<PathBuf> {
        constants::default_data_file(constants::SPEND_DB_FILE)
    }

    pub async fn record_permit(&self, entry: &PermitEntry<'_>) -> Result<i64, SpendError> {
        let conn = self.conn.clone();
        let chain_id = entry.chain_id;
        let target = entry.target.to_string();
        let value = entry.value.to_string();
        let status = entry.status.to_string();
        let reason = entry.reason.map(|s| s.to_string());
        let permit_hash = entry.permit_hash.map(|s| s.to_string());
        let cost_usd = entry.cost_usd;
        tokio::task::spawn_blocking(move || -> Result<_, SpendError> {
            let conn = conn
                .lock()
                .map_err(|_| SpendError::Poisoned("spend database connection".to_string()))?;
            let now = chrono::Utc::now().timestamp();
            let today = chrono::Utc::now()
                .date_naive()
                .format("%Y-%m-%d")
                .to_string();
            conn.execute(
                "INSERT INTO onchain_permits (chain_id, target, value, status, reason, permit_hash, cost_usd, date, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![chain_id, target, value, status, reason, permit_hash, cost_usd, today, now],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await?
    }

    pub async fn get_onchain_stats(&self) -> Result<OnchainStats, SpendError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<_, SpendError> {
            let conn = conn
                .lock()
                .map_err(|_| SpendError::Poisoned("spend database connection".to_string()))?;
            let today = chrono::Utc::now()
                .date_naive()
                .format("%Y-%m-%d")
                .to_string();

            let total_signed: i64 = conn.query_row(
                "SELECT COUNT(*) FROM onchain_permits WHERE status = 'approved'",
                [],
                |row| row.get(0),
            )?;

            let total_denied: i64 = conn.query_row(
                "SELECT COUNT(*) FROM onchain_permits WHERE status = 'denied'",
                [],
                |row| row.get(0),
            )?;

            let spent_today_usd: f64 = conn.query_row(
                "SELECT COALESCE(SUM(cost_usd), 0.0) FROM onchain_permits WHERE status = 'approved' AND date = ?1",
                params![today],
                |row| row.get(0),
            )?;

            let last_permit_at: Option<i64> = conn.query_row(
                "SELECT MAX(created_at) FROM onchain_permits WHERE status = 'approved'",
                [],
                |row| row.get(0),
            )?;

            Ok(OnchainStats {
                total_signed,
                total_denied,
                spent_today_usd,
                last_permit_at,
            })
        })
        .await?
    }

    pub async fn get_onchain_spent_today(&self) -> Result<f64, SpendError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<_, SpendError> {
            let conn = conn
                .lock()
                .map_err(|_| SpendError::Poisoned("spend database connection".to_string()))?;
            let today = chrono::Utc::now()
                .date_naive()
                .format("%Y-%m-%d")
                .to_string();
            let spent: f64 = conn.query_row(
                "SELECT COALESCE(SUM(cost_usd), 0.0) FROM onchain_permits WHERE status = 'approved' AND date = ?1",
                params![today],
                |row| row.get(0),
            )?;
            Ok(spent)
        })
        .await?
    }

    pub async fn next_nonce(&self) -> Result<u64, SpendError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<_, SpendError> {
            let conn = conn
                .lock()
                .map_err(|_| SpendError::Poisoned("spend database connection".to_string()))?;
            let gap = (rand::random::<u64>() % 1024) + 1;
            conn.execute(
                "UPDATE nonce_counter SET value = value + ?1 WHERE id = 1",
                params![gap as i64],
            )?;
            let nonce: i64 =
                conn.query_row("SELECT value FROM nonce_counter WHERE id = 1", [], |row| {
                    row.get(0)
                })?;
            Ok(nonce as u64)
        })
        .await?
    }

    pub async fn query_permits(
        &self,
        days: u32,
        status_filter: Option<&str>,
    ) -> Result<Vec<PermitRecord>, SpendError> {
        let conn = self.conn.clone();
        let status_filter = status_filter.map(|s| s.to_string());
        tokio::task::spawn_blocking(move || -> Result<_, SpendError> {
            let conn = conn
                .lock()
                .map_err(|_| SpendError::Poisoned("spend database connection".to_string()))?;
            let cutoff = chrono::Utc::now()
                .date_naive()
                .checked_sub_days(chrono::Days::new(days as u64))
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_default();

            let (query, params_vec): (String, Vec<Box<dyn rusqlite::types::ToSql>>) =
                match status_filter {
                    Some(status) => (
                        "SELECT id, chain_id, target, value, status, reason, permit_hash, cost_usd, date, created_at
                         FROM onchain_permits WHERE date >= ?1 AND status = ?2
                         ORDER BY created_at DESC"
                            .to_string(),
                        vec![Box::new(cutoff), Box::new(status)],
                    ),
                    None => (
                        "SELECT id, chain_id, target, value, status, reason, permit_hash, cost_usd, date, created_at
                         FROM onchain_permits WHERE date >= ?1
                         ORDER BY created_at DESC"
                            .to_string(),
                        vec![Box::new(cutoff)],
                    ),
                };

            let mut stmt = conn.prepare(&query)?;
            let params_refs: Vec<&dyn rusqlite::types::ToSql> =
                params_vec.iter().map(|p| p.as_ref()).collect();
            let rows = stmt.query_map(params_refs.as_slice(), |row| {
                Ok(PermitRecord {
                    id: row.get(0)?,
                    chain_id: row.get(1)?,
                    target: row.get(2)?,
                    value: row.get(3)?,
                    status: row.get(4)?,
                    reason: row.get(5)?,
                    permit_hash: row.get(6)?,
                    cost_usd: row.get(7)?,
                    date: row.get(8)?,
                    created_at: row.get(9)?,
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
}

fn micros_to_usd_f64(micros: i64) -> f64 {
    micros as f64 / USD_MICROS_SCALE as f64
}

fn usd_f64_to_micros(usd: f64) -> Result<i64, SpendError> {
    if !usd.is_finite() || usd < 0.0 {
        return Err(SpendError::InvalidAmount(format!(
            "{usd} is not a valid non-negative finite USD amount"
        )));
    }
    let scaled = usd * USD_MICROS_SCALE as f64;
    let max_allowed = (i64::MAX as f64) - 0.5;
    if !scaled.is_finite() || scaled > max_allowed {
        return Err(SpendError::InvalidAmount(format!(
            "{usd} is outside supported range"
        )));
    }
    Ok(scaled.round() as i64)
}

#[derive(Debug, Deserialize)]
pub struct SpendQuery {
    pub days: Option<u32>,
}

pub async fn get_spend(
    State(state): State<AppState>,
    Query(query): Query<SpendQuery>,
) -> impl IntoResponse {
    let config = state.config();

    if !config.llm.track_spend {
        return Json(serde_json::json!({ "enabled": false })).into_response();
    }

    let days = query
        .days
        .unwrap_or(config.dashboard.spend_history_days)
        .min(config.dashboard.spend_history_days);

    match state.spend_store.query_spend(days).await {
        Ok(daily) => {
            let daily_payload: Vec<serde_json::Value> = daily
                .iter()
                .map(|entry| {
                    serde_json::json!({
                        "service": entry.service,
                        "date": entry.date,
                        "cost_usd": entry.cost_usd,
                        "amount": entry.cost_usd,
                        "request_count": entry.request_count,
                    })
                })
                .collect();
            let budgets = state.spend_store.get_budgets().await.unwrap_or_default();
            let mut budget_map = serde_json::Map::new();
            for b in &budgets {
                let spent_today = state
                    .spend_store
                    .get_spent_today(&b.service)
                    .await
                    .unwrap_or(0.0);
                let warning_active = config.llm.budget_warning_pct > 0
                    && b.daily_budget_usd > 0.0
                    && spent_today
                        >= b.daily_budget_usd * (config.llm.budget_warning_pct as f64 / 100.0);
                budget_map.insert(
                    b.service.clone(),
                    serde_json::json!({
                        "daily_limit": b.daily_budget_usd,
                        "spent_today": spent_today,
                        "warning_pct": config.llm.budget_warning_pct,
                        "warning_active": warning_active,
                    }),
                );
            }

            Json(serde_json::json!({
                "enabled": true,
                "config": {
                    "track_spend": config.llm.track_spend,
                    "spend_history_days": config.dashboard.spend_history_days,
                },
                "daily": daily_payload,
                "budgets": budget_map,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("database error: {e}") })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct SetBudgetRequest {
    pub service: String,
    pub daily_budget_usd: f64,
    pub monthly_budget_usd: Option<f64>,
}

pub async fn set_budget(
    State(state): State<AppState>,
    Json(req): Json<SetBudgetRequest>,
) -> impl IntoResponse {
    let budget = ServiceBudget {
        service: req.service,
        daily_budget_usd: req.daily_budget_usd,
        monthly_budget_usd: req.monthly_budget_usd,
        updated_at: chrono::Utc::now().timestamp(),
    };
    match state.spend_store.set_budget(&budget).await {
        Ok(()) => Json(serde_json::json!({ "success": true, "budget": budget })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("database error: {e}") })),
        )
            .into_response(),
    }
}

pub async fn get_budgets(State(state): State<AppState>) -> impl IntoResponse {
    match state.spend_store.get_budgets().await {
        Ok(budgets) => Json(serde_json::json!({ "budgets": budgets })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("database error: {e}") })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_open_in_memory() {
        let store = SpendStore::open_in_memory().unwrap();
        let records = store.query_spend(30).await.unwrap();
        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn test_record_and_query_spend() {
        let store = SpendStore::open_in_memory().unwrap();
        let today = chrono::Utc::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        store.record_spend("openai", &today, 1.50).await.unwrap();
        store.record_spend("openai", &today, 2.50).await.unwrap();
        store.record_spend("anthropic", &today, 3.00).await.unwrap();

        let records = store.query_spend(30).await.unwrap();
        assert_eq!(records.len(), 2);

        let openai = records.iter().find(|r| r.service == "openai").unwrap();
        assert!((openai.cost_usd - 4.0).abs() < 0.001);
        assert_eq!(openai.request_count, 2);

        let anthropic = records.iter().find(|r| r.service == "anthropic").unwrap();
        assert!((anthropic.cost_usd - 3.0).abs() < 0.001);
        assert_eq!(anthropic.request_count, 1);
    }

    #[tokio::test]
    async fn test_spent_today() {
        let store = SpendStore::open_in_memory().unwrap();
        let today = chrono::Utc::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        assert!((store.get_spent_today("openai").await.unwrap() - 0.0).abs() < 0.001);
        assert_eq!(store.get_spent_today_micros("openai").await.unwrap(), 0);

        store.record_spend("openai", &today, 5.25).await.unwrap();
        store.record_spend("openai", &today, 3.75).await.unwrap();

        assert!((store.get_spent_today("openai").await.unwrap() - 9.0).abs() < 0.001);
        assert_eq!(
            store.get_spent_today_micros("openai").await.unwrap(),
            9_000_000
        );
        assert!((store.get_spent_today("anthropic").await.unwrap() - 0.0).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_record_spend_micros_uses_exact_integer_math() {
        let store = SpendStore::open_in_memory().unwrap();
        let today = chrono::Utc::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        store
            .record_spend_micros("binance", &today, 123_456)
            .await
            .unwrap();
        store
            .record_spend_micros("binance", &today, 1_000_001)
            .await
            .unwrap();

        assert_eq!(
            store.get_spent_today_micros("binance").await.unwrap(),
            1_123_457
        );
        assert!((store.get_spent_today("binance").await.unwrap() - 1.123_457).abs() < 1e-9);
    }

    #[tokio::test]
    async fn test_budget_crud() {
        let store = SpendStore::open_in_memory().unwrap();

        let budget = ServiceBudget {
            service: "openai".to_string(),
            daily_budget_usd: 20.0,
            monthly_budget_usd: Some(500.0),
            updated_at: 1000,
        };
        store.set_budget(&budget).await.unwrap();

        let loaded = store.get_budget("openai").await.unwrap().unwrap();
        assert!((loaded.daily_budget_usd - 20.0).abs() < 0.001);
        assert!((loaded.monthly_budget_usd.unwrap() - 500.0).abs() < 0.001);

        assert!(store.get_budget("anthropic").await.unwrap().is_none());

        let all = store.get_budgets().await.unwrap();
        assert_eq!(all.len(), 1);

        let updated = ServiceBudget {
            service: "openai".to_string(),
            daily_budget_usd: 30.0,
            monthly_budget_usd: None,
            updated_at: 2000,
        };
        store.set_budget(&updated).await.unwrap();

        let loaded = store.get_budget("openai").await.unwrap().unwrap();
        assert!((loaded.daily_budget_usd - 30.0).abs() < 0.001);
        assert!(loaded.monthly_budget_usd.is_none());
    }

    #[tokio::test]
    async fn test_query_spend_respects_days() {
        let store = SpendStore::open_in_memory().unwrap();
        let today = chrono::Utc::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let old_date = "2020-01-01";

        store.record_spend("openai", &today, 1.0).await.unwrap();
        store.record_spend("openai", old_date, 5.0).await.unwrap();

        let recent = store.query_spend(30).await.unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].date, today);

        let all = store.query_spend(10000).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn test_migration_idempotent() {
        let store = SpendStore::open_in_memory().unwrap();
        store.migrate().unwrap();
    }
}
