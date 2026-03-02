use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter, types::Value as SqlValue};
use serde::{Deserialize, Serialize};

use crate::constants;
use crate::state::AppState;

pub mod merkle;
const MAX_EXPORT_ROWS: u32 = 100_000;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("{0}")]
    Db(#[from] rusqlite::Error),
    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("mutex poisoned: {0}")]
    Poisoned(String),
}

pub struct AuditStore {
    conn: Arc<Mutex<Connection>>,
    cached_root: Arc<Mutex<Option<merkle::H256>>>,
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: u64,
    pub timestamp: u64,
    pub intent_type: String,
    pub service: String,
    pub action: String,
    pub decision: String,
    pub reason: Option<String>,
    pub cost_usd: Option<f64>,
    pub policy_version_hash: merkle::H256,
    pub intent_hash: merkle::H256,
    pub permit_hash: Option<merkle::H256>,
    pub merkle_root: merkle::H256,
}

#[derive(Debug, Clone)]
pub struct NewAuditEntry {
    pub intent_type: String,
    pub service: String,
    pub action: String,
    pub decision: String,
    pub reason: Option<String>,
    pub cost_usd: Option<f64>,
    pub policy_version_hash: merkle::H256,
    pub intent_hash: merkle::H256,
    pub permit_hash: Option<merkle::H256>,
}

#[derive(Debug, Clone, Default)]
pub struct AuditQueryFilter {
    pub from: Option<u64>,
    pub to: Option<u64>,
    pub service: Option<String>,
    pub decision: Option<String>,
    pub page: u32,
    pub page_size: u32,
}

#[derive(Debug, Clone, Serialize)]
struct AuditEntryResponse {
    id: u64,
    timestamp: u64,
    intent_type: String,
    service: String,
    action: String,
    decision: String,
    reason: Option<String>,
    cost_usd: Option<f64>,
    policy_version_hash: String,
    intent_hash: String,
    permit_hash: Option<String>,
    merkle_root: String,
}

#[derive(Debug, Deserialize)]
pub struct AuditQueryParams {
    pub from: Option<u64>,
    pub to: Option<u64>,
    pub service: Option<String>,
    pub decision: Option<String>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

impl AuditStore {
    pub fn open(path: PathBuf) -> Result<Self, rusqlite::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(&path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;

        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            cached_root: Arc::new(Mutex::new(None)),
        };
        store.migrate()?;
        store.refresh_cached_root()?;
        Ok(store)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA busy_timeout=5000;")?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            cached_root: Arc::new(Mutex::new(None)),
        };
        store.migrate()?;
        store.refresh_cached_root()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), rusqlite::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| poison_to_sqlite_error("audit database connection"))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                intent_type TEXT NOT NULL,
                service TEXT NOT NULL,
                action TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT,
                cost_usd REAL,
                policy_version_hash BLOB NOT NULL,
                intent_hash BLOB NOT NULL,
                permit_hash BLOB,
                merkle_root BLOB NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_service ON audit_log(service);
            CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_log(decision);

            CREATE TABLE IF NOT EXISTS audit_merkle_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id INTEGER NOT NULL,
                level INTEGER NOT NULL,
                position INTEGER NOT NULL,
                is_leaf INTEGER NOT NULL,
                hash BLOB NOT NULL,
                UNIQUE(level, position)
            );

            CREATE INDEX IF NOT EXISTS idx_audit_merkle_entry ON audit_merkle_nodes(entry_id);
            CREATE INDEX IF NOT EXISTS idx_audit_merkle_leaf ON audit_merkle_nodes(is_leaf, position);",
        )?;
        Ok(())
    }

    fn refresh_cached_root(&self) -> Result<(), rusqlite::Error> {
        let latest = {
            let conn = self
                .conn
                .lock()
                .map_err(|_| poison_to_sqlite_error("audit database connection"))?;
            latest_merkle_root_from_conn(&conn)?
        };
        let mut cached_root = self
            .cached_root
            .lock()
            .map_err(|_| poison_to_sqlite_error("audit merkle root cache"))?;
        *cached_root = latest;
        Ok(())
    }

    pub async fn append(&self, new_entry: NewAuditEntry) -> Result<AuditEntry, AuditError> {
        let conn = self.conn.clone();
        let cached_root = self.cached_root.clone();

        tokio::task::spawn_blocking(move || -> Result<AuditEntry, AuditError> {
            let mut conn = conn
                .lock()
                .map_err(|_| AuditError::Poisoned("audit database connection".to_string()))?;
            let tx = conn.transaction()?;

            let now = chrono::Utc::now().timestamp_millis().max(0) as u64;
            let intent_type = new_entry.intent_type;
            let service = new_entry.service;
            let action = new_entry.action;
            let decision = new_entry.decision;
            let reason = new_entry.reason;
            let cost_usd = new_entry.cost_usd;
            let policy_version_hash = new_entry.policy_version_hash;
            let intent_hash = new_entry.intent_hash;
            let permit_hash = new_entry.permit_hash;

            tx.execute(
                "INSERT INTO audit_log (
                    timestamp,
                    intent_type,
                    service,
                    action,
                    decision,
                    reason,
                    cost_usd,
                    policy_version_hash,
                    intent_hash,
                    permit_hash,
                    merkle_root
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    now as i64,
                    &intent_type,
                    &service,
                    &action,
                    &decision,
                    reason.as_deref(),
                    cost_usd,
                    policy_version_hash.as_slice(),
                    intent_hash.as_slice(),
                    permit_hash.as_ref().map(|h| h.as_slice()),
                    merkle::ZERO_H256.as_slice(),
                ],
            )?;

            let id = tx.last_insert_rowid() as u64;
            let leaf_payload = merkle::LeafPayload {
                id,
                timestamp: now,
                intent_type: &intent_type,
                service: &service,
                action: &action,
                decision: &decision,
                reason: reason.as_deref(),
                cost_usd,
                policy_version_hash,
                intent_hash,
                permit_hash,
            };
            let leaf_hash = merkle::hash_audit_leaf(&leaf_payload);

            let incremental_root =
                merkle::insert_leaf_and_new_parents(&tx, id, id.saturating_sub(1), leaf_hash)?;
            let previous_root = if id > 1 {
                tx.query_row(
                    "SELECT merkle_root FROM audit_log WHERE id = ?1",
                    params![(id - 1) as i64],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?
                .map(|raw| parse_merkle_blob(&raw, "previous entry merkle_root"))
                .transpose()?
            } else {
                None
            };
            let cached = {
                let guard = cached_root
                    .lock()
                    .map_err(|_| AuditError::Poisoned("audit merkle root cache".to_string()))?;
                *guard
            };
            let cache_in_sync = if id == 1 {
                cached.is_none() || cached == Some(merkle::ZERO_H256)
            } else {
                matches!((cached, previous_root), (Some(cached_root), Some(prev_root)) if cached_root == prev_root)
            };
            let root = if cache_in_sync {
                incremental_root
            } else {
                merkle::compute_root_from_leaves(&tx)?
            };

            tx.execute(
                "UPDATE audit_log SET merkle_root = ?1 WHERE id = ?2",
                params![root.as_slice(), id as i64],
            )?;

            tx.commit()?;
            {
                let mut guard = cached_root
                    .lock()
                    .map_err(|_| AuditError::Poisoned("audit merkle root cache".to_string()))?;
                *guard = Some(root);
            }

            Ok(AuditEntry {
                id,
                timestamp: now,
                intent_type,
                service,
                action,
                decision,
                reason,
                cost_usd,
                policy_version_hash,
                intent_hash,
                permit_hash,
                merkle_root: root,
            })
        })
        .await?
    }

    pub async fn query(
        &self,
        filter: &AuditQueryFilter,
    ) -> Result<(Vec<AuditEntry>, u64), AuditError> {
        let conn = self.conn.clone();
        let filter = normalize_filter(filter.clone());

        tokio::task::spawn_blocking(move || -> Result<(Vec<AuditEntry>, u64), AuditError> {
            let conn = conn
                .lock()
                .map_err(|_| AuditError::Poisoned("audit database connection".to_string()))?;
            let (where_sql, where_values) = build_where_clause(
                filter.from,
                filter.to,
                filter.service.as_deref(),
                filter.decision.as_deref(),
            );

            let count_sql = format!("SELECT COUNT(*) FROM audit_log {where_sql}");
            let total: i64 =
                conn.query_row(&count_sql, params_from_iter(where_values.iter()), |row| {
                    row.get(0)
                })?;

            let mut values = where_values;
            let offset_u64 = u64::from(filter.page.saturating_sub(1))
                .saturating_mul(u64::from(filter.page_size));
            let offset = offset_u64.min(i64::MAX as u64) as i64;
            values.push(SqlValue::Integer(filter.page_size as i64));
            values.push(SqlValue::Integer(offset));

            let query_sql = format!(
                "SELECT id, timestamp, intent_type, service, action, decision, reason,
                        cost_usd, policy_version_hash, intent_hash, permit_hash, merkle_root
                 FROM audit_log
                 {where_sql}
                 ORDER BY id DESC
                 LIMIT ?{} OFFSET ?{}",
                values.len() - 1,
                values.len()
            );

            let mut stmt = conn.prepare(&query_sql)?;
            let rows = stmt.query_map(params_from_iter(values.iter()), row_to_entry)?;

            let mut entries = Vec::new();
            for row in rows {
                entries.push(row?);
            }

            Ok((entries, total.max(0) as u64))
        })
        .await?
    }

    pub async fn export(
        &self,
        from: Option<u64>,
        to: Option<u64>,
        service: Option<String>,
        decision: Option<String>,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        let conn = self.conn.clone();

        tokio::task::spawn_blocking(move || -> Result<Vec<AuditEntry>, AuditError> {
            let conn = conn
                .lock()
                .map_err(|_| AuditError::Poisoned("audit database connection".to_string()))?;
            let (where_sql, values) =
                build_where_clause(from, to, service.as_deref(), decision.as_deref());

            let query_sql = format!(
                "SELECT id, timestamp, intent_type, service, action, decision, reason,
                        cost_usd, policy_version_hash, intent_hash, permit_hash, merkle_root
                 FROM audit_log
                 {where_sql}
                 ORDER BY id DESC
                 LIMIT {}",
                MAX_EXPORT_ROWS
            );

            let mut stmt = conn.prepare(&query_sql)?;
            let rows = stmt.query_map(params_from_iter(values.iter()), row_to_entry)?;

            let mut entries = Vec::new();
            for row in rows {
                entries.push(row?);
            }

            Ok(entries)
        })
        .await?
    }

    pub async fn today_request_counts(&self) -> Result<HashMap<String, u64>, AuditError> {
        let conn = self.conn.clone();

        tokio::task::spawn_blocking(move || -> Result<HashMap<String, u64>, AuditError> {
            let conn = conn
                .lock()
                .map_err(|_| AuditError::Poisoned("audit database connection".to_string()))?;

            let day_start = chrono::Utc::now()
                .date_naive()
                .and_hms_opt(0, 0, 0)
                .unwrap_or_default()
                .and_utc()
                .timestamp_millis();
            let day_end = day_start + 24 * 60 * 60 * 1000;

            let mut stmt = conn.prepare(
                "SELECT service, COUNT(*)
                 FROM audit_log
                 WHERE timestamp >= ?1 AND timestamp < ?2
                 GROUP BY service",
            )?;

            let rows = stmt.query_map(params![day_start, day_end], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;

            let mut counts = HashMap::new();
            for row in rows {
                let (service, count) = row?;
                counts.insert(service, count.max(0) as u64);
            }

            Ok(counts)
        })
        .await?
    }

    pub async fn latest_merkle_root(&self) -> Result<Option<merkle::H256>, AuditError> {
        let conn = self.conn.clone();

        tokio::task::spawn_blocking(move || -> Result<Option<merkle::H256>, AuditError> {
            let conn = conn
                .lock()
                .map_err(|_| AuditError::Poisoned("audit database connection".to_string()))?;
            latest_merkle_root_from_conn(&conn).map_err(AuditError::from)
        })
        .await?
    }

    pub async fn verify_merkle_consistency(&self) -> Result<bool, AuditError> {
        let conn = self.conn.clone();

        tokio::task::spawn_blocking(move || -> Result<bool, AuditError> {
            let conn = conn
                .lock()
                .map_err(|_| AuditError::Poisoned("audit database connection".to_string()))?;
            let computed = recompute_root_from_log(&conn)?;
            let stored = conn
                .query_row(
                    "SELECT merkle_root FROM audit_log ORDER BY id DESC LIMIT 1",
                    [],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?;

            let stored = match stored {
                Some(raw) => parse_merkle_blob(&raw, "latest audit_log.merkle_root")?,
                None => merkle::ZERO_H256,
            };

            Ok(computed == stored)
        })
        .await?
    }

    pub async fn merkle_path(&self, entry_id: u64) -> Result<Vec<merkle::H256>, AuditError> {
        let conn = self.conn.clone();

        tokio::task::spawn_blocking(move || -> Result<Vec<merkle::H256>, AuditError> {
            let conn = conn
                .lock()
                .map_err(|_| AuditError::Poisoned("audit database connection".to_string()))?;
            if entry_id == 0 {
                return Ok(Vec::new());
            }
            merkle::merkle_path_for_leaf(&conn, entry_id - 1).map_err(AuditError::from)
        })
        .await?
    }

    pub fn default_path() -> Option<PathBuf> {
        constants::default_data_file(constants::AUDIT_DB_FILE)
    }
}

pub fn policy_version_hash(
    _path: &Path,
    config: &fishnet_types::config::FishnetConfig,
) -> merkle::H256 {
    let canonical = serde_json::to_value(config).map(canonicalize_json).ok();
    let bytes = canonical
        .as_ref()
        .and_then(|value| serde_json::to_vec(value).ok())
        .unwrap_or_else(|| b"{}".to_vec());
    merkle::keccak256(&bytes)
}

pub fn hash_api_intent(
    method: &str,
    service: &str,
    action: &str,
    query: Option<&str>,
    body: &[u8],
) -> merkle::H256 {
    let mut bytes = Vec::with_capacity(body.len() + 256);
    push_string(&mut bytes, method);
    push_string(&mut bytes, service);
    push_string(&mut bytes, action);
    push_string(&mut bytes, query.unwrap_or(""));
    bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
    bytes.extend_from_slice(body);
    merkle::keccak256(&bytes)
}

pub fn hash_json_intent(value: &serde_json::Value) -> merkle::H256 {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    merkle::keccak256(&bytes)
}

pub async fn list_audit(
    State(state): State<AppState>,
    Query(query): Query<AuditQueryParams>,
) -> impl IntoResponse {
    let filter = AuditQueryFilter {
        from: query.from,
        to: query.to,
        service: query.service,
        decision: query.decision,
        page: query.page.unwrap_or(1),
        page_size: query.page_size.unwrap_or(20),
    };

    match state.audit_store.query(&filter).await {
        Ok((entries, total)) => {
            let normalized = normalize_filter(filter);
            let pages = if total == 0 {
                0
            } else {
                ((total + normalized.page_size as u64 - 1) / normalized.page_size as u64) as u32
            };

            let payload: Vec<AuditEntryResponse> = entries.into_iter().map(Into::into).collect();
            Json(serde_json::json!({
                "entries": payload,
                "total": total,
                "page": normalized.page,
                "pages": pages,
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

pub async fn export_audit_csv(
    State(state): State<AppState>,
    Query(query): Query<AuditQueryParams>,
) -> impl IntoResponse {
    match state
        .audit_store
        .export(query.from, query.to, query.service, query.decision)
        .await
    {
        Ok(entries) => {
            let export_truncated = entries.len() as u32 >= MAX_EXPORT_ROWS;
            let export_row_limit = MAX_EXPORT_ROWS.to_string();
            let mut csv = String::from(
                "id,timestamp,intent_type,service,action,decision,reason,cost_usd,policy_version_hash,intent_hash,permit_hash,merkle_root\n",
            );

            for entry in entries {
                let reason = entry.reason.unwrap_or_default();
                let cost = entry
                    .cost_usd
                    .map(|v| format!("{v:.8}"))
                    .unwrap_or_default();
                let permit = entry
                    .permit_hash
                    .map(|h| merkle::h256_to_hex(&h))
                    .unwrap_or_default();

                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    entry.id,
                    entry.timestamp,
                    csv_cell(&entry.intent_type),
                    csv_cell(&entry.service),
                    csv_cell(&entry.action),
                    csv_cell(&entry.decision),
                    csv_cell(&reason),
                    csv_cell(&cost),
                    csv_cell(&merkle::h256_to_hex(&entry.policy_version_hash)),
                    csv_cell(&merkle::h256_to_hex(&entry.intent_hash)),
                    csv_cell(&permit),
                    csv_cell(&merkle::h256_to_hex(&entry.merkle_root)),
                ));
            }

            let filename = format!("audit-log-{}.csv", chrono::Utc::now().format("%Y%m%d"));
            let disposition = format!("attachment; filename=\"{filename}\"");

            (
                [
                    ("content-type", "text/csv; charset=utf-8"),
                    ("content-disposition", disposition.as_str()),
                    ("x-export-row-limit", export_row_limit.as_str()),
                    (
                        "x-export-truncated",
                        if export_truncated { "true" } else { "false" },
                    ),
                ],
                csv,
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("database error: {e}") })),
        )
            .into_response(),
    }
}

fn normalize_filter(mut filter: AuditQueryFilter) -> AuditQueryFilter {
    filter.page = filter.page.max(1);
    filter.page_size = filter.page_size.clamp(1, 200);
    filter
}

fn build_where_clause(
    from: Option<u64>,
    to: Option<u64>,
    service: Option<&str>,
    decision: Option<&str>,
) -> (String, Vec<SqlValue>) {
    let mut clauses = Vec::new();
    let mut values = Vec::new();

    if let Some(from) = from {
        clauses.push(format!("timestamp >= ?{}", values.len() + 1));
        values.push(SqlValue::Integer(from as i64));
    }
    if let Some(to) = to {
        clauses.push(format!("timestamp <= ?{}", values.len() + 1));
        values.push(SqlValue::Integer(to as i64));
    }
    if let Some(service) = service {
        clauses.push(format!("service = ?{}", values.len() + 1));
        values.push(SqlValue::Text(service.to_string()));
    }
    if let Some(decision) = decision {
        clauses.push(format!("decision = ?{}", values.len() + 1));
        values.push(SqlValue::Text(decision.to_string()));
    }

    let sql = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };

    (sql, values)
}

fn recompute_root_from_log(conn: &Connection) -> rusqlite::Result<merkle::H256> {
    let mut stmt = conn.prepare(
        "SELECT id, timestamp, intent_type, service, action, decision, reason,
                cost_usd, policy_version_hash, intent_hash, permit_hash
         FROM audit_log
         ORDER BY id ASC",
    )?;

    let rows = stmt.query_map([], |row| {
        let policy_hash_raw: Vec<u8> = row.get(8)?;
        let intent_hash_raw: Vec<u8> = row.get(9)?;
        let permit_hash_raw: Option<Vec<u8>> = row.get(10)?;
        let intent_type: String = row.get(2)?;
        let service: String = row.get(3)?;
        let action: String = row.get(4)?;
        let decision: String = row.get(5)?;
        let reason: Option<String> = row.get(6)?;

        let payload = merkle::LeafPayload {
            id: row.get::<_, i64>(0)?.max(0) as u64,
            timestamp: row.get::<_, i64>(1)?.max(0) as u64,
            intent_type: &intent_type,
            service: &service,
            action: &action,
            decision: &decision,
            reason: reason.as_deref(),
            cost_usd: row.get(7)?,
            policy_version_hash: parse_hash(8, policy_hash_raw)?,
            intent_hash: parse_hash(9, intent_hash_raw)?,
            permit_hash: parse_optional_hash(10, permit_hash_raw)?,
        };
        Ok(merkle::hash_audit_leaf(&payload))
    })?;

    let mut leaves = Vec::new();
    for row in rows {
        leaves.push(row?);
    }

    Ok(merkle::compute_root_from_hashes(leaves))
}

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
    let policy_hash_raw: Vec<u8> = row.get(8)?;
    let intent_hash_raw: Vec<u8> = row.get(9)?;
    let permit_hash_raw: Option<Vec<u8>> = row.get(10)?;
    let merkle_root_raw: Vec<u8> = row.get(11)?;

    Ok(AuditEntry {
        id: row.get::<_, i64>(0)?.max(0) as u64,
        timestamp: row.get::<_, i64>(1)?.max(0) as u64,
        intent_type: row.get(2)?,
        service: row.get(3)?,
        action: row.get(4)?,
        decision: row.get(5)?,
        reason: row.get(6)?,
        cost_usd: row.get(7)?,
        policy_version_hash: parse_hash(8, policy_hash_raw)?,
        intent_hash: parse_hash(9, intent_hash_raw)?,
        permit_hash: parse_optional_hash(10, permit_hash_raw)?,
        merkle_root: parse_hash(11, merkle_root_raw)?,
    })
}

fn parse_hash(col: usize, value: Vec<u8>) -> rusqlite::Result<merkle::H256> {
    parse_merkle_blob(&value, &format!("column {col}"))
}

fn parse_optional_hash(
    col: usize,
    value: Option<Vec<u8>>,
) -> rusqlite::Result<Option<merkle::H256>> {
    match value {
        Some(raw) => parse_hash(col, raw).map(Some),
        None => Ok(None),
    }
}

fn push_string(bytes: &mut Vec<u8>, text: &str) {
    bytes.extend_from_slice(&(text.len() as u64).to_le_bytes());
    bytes.extend_from_slice(text.as_bytes());
}

fn csv_cell(value: &str) -> String {
    let guarded = if value.starts_with('=')
        || value.starts_with('+')
        || value.starts_with('-')
        || value.starts_with('@')
        || value.starts_with('\t')
        || value.starts_with('\r')
    {
        format!("'{value}")
    } else {
        value.to_string()
    };

    if guarded.contains(',')
        || guarded.contains('"')
        || guarded.contains('\n')
        || guarded.contains('\r')
    {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

fn canonicalize_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(String, serde_json::Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut normalized = serde_json::Map::new();
            for (key, value) in entries {
                normalized.insert(key, canonicalize_json(value));
            }
            serde_json::Value::Object(normalized)
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(canonicalize_json).collect())
        }
        other => other,
    }
}

fn latest_merkle_root_from_conn(conn: &Connection) -> rusqlite::Result<Option<merkle::H256>> {
    let value = conn
        .query_row(
            "SELECT merkle_root FROM audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    value
        .as_deref()
        .map(|raw| parse_merkle_blob(raw, "latest merkle_root"))
        .transpose()
}

fn parse_merkle_blob(value: &[u8], context: &str) -> rusqlite::Result<merkle::H256> {
    merkle::h256_from_bytes(value).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "invalid H256 ({context}): expected 32 bytes, got {}",
                    value.len()
                ),
            )),
        )
    })
}

fn poison_to_sqlite_error(context: &str) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("poisoned mutex: {context}"),
    )))
}

impl From<AuditEntry> for AuditEntryResponse {
    fn from(value: AuditEntry) -> Self {
        Self {
            id: value.id,
            timestamp: value.timestamp,
            intent_type: value.intent_type,
            service: value.service,
            action: value.action,
            decision: value.decision,
            reason: value.reason,
            cost_usd: value.cost_usd,
            policy_version_hash: merkle::h256_to_hex(&value.policy_version_hash),
            intent_hash: merkle::h256_to_hex(&value.intent_hash),
            permit_hash: value.permit_hash.map(|h| merkle::h256_to_hex(&h)),
            merkle_root: merkle::h256_to_hex(&value.merkle_root),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn sample_entry(decision: &str) -> NewAuditEntry {
        NewAuditEntry {
            intent_type: "api_call".to_string(),
            service: "openai".to_string(),
            action: "POST /v1/chat/completions".to_string(),
            decision: decision.to_string(),
            reason: if decision == "denied" {
                Some("blocked".to_string())
            } else {
                None
            },
            cost_usd: Some(0.12),
            policy_version_hash: merkle::keccak256(b"policy"),
            intent_hash: merkle::keccak256(b"intent"),
            permit_hash: None,
        }
    }

    #[tokio::test]
    async fn append_populates_merkle_root() {
        let store = AuditStore::open_in_memory().unwrap();

        let first = store.append(sample_entry("approved")).await.unwrap();
        let second = store.append(sample_entry("denied")).await.unwrap();

        assert_eq!(first.id, 1);
        assert_eq!(second.id, 2);
        assert_ne!(first.merkle_root, merkle::ZERO_H256);
        assert_ne!(first.merkle_root, second.merkle_root);
        assert!(store.verify_merkle_consistency().await.unwrap());
    }

    #[tokio::test]
    async fn tampering_causes_merkle_divergence() {
        let store = AuditStore::open_in_memory().unwrap();
        store.append(sample_entry("approved")).await.unwrap();
        store.append(sample_entry("approved")).await.unwrap();

        {
            let conn = match store.conn.lock() {
                Ok(conn) => conn,
                Err(poisoned) => poisoned.into_inner(),
            };
            conn.execute(
                "UPDATE audit_log SET decision = 'denied', reason = 'tampered' WHERE id = 1",
                [],
            )
            .unwrap();
        }

        assert!(!store.verify_merkle_consistency().await.unwrap());
    }

    #[tokio::test]
    async fn query_supports_pagination() {
        let store = AuditStore::open_in_memory().unwrap();
        for _ in 0..5 {
            store.append(sample_entry("approved")).await.unwrap();
        }

        let (entries, total) = store
            .query(&AuditQueryFilter {
                page: 1,
                page_size: 2,
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(total, 5);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn policy_hash_is_stable_across_hashmap_insertion_order() {
        let mut a = fishnet_types::config::FishnetConfig::default();
        let mut b = fishnet_types::config::FishnetConfig::default();

        a.custom.insert(
            "alpha".to_string(),
            fishnet_types::config::CustomServiceConfig {
                base_url: "https://a.example.com".to_string(),
                ..Default::default()
            },
        );
        a.custom.insert(
            "beta".to_string(),
            fishnet_types::config::CustomServiceConfig {
                base_url: "https://b.example.com".to_string(),
                ..Default::default()
            },
        );

        b.custom.insert(
            "beta".to_string(),
            fishnet_types::config::CustomServiceConfig {
                base_url: "https://b.example.com".to_string(),
                ..Default::default()
            },
        );
        b.custom.insert(
            "alpha".to_string(),
            fishnet_types::config::CustomServiceConfig {
                base_url: "https://a.example.com".to_string(),
                ..Default::default()
            },
        );

        let hash_a = policy_version_hash(Path::new("unused"), &a);
        let hash_b = policy_version_hash(Path::new("unused"), &b);
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn csv_cell_guards_formula_injection() {
        assert_eq!(csv_cell("=SUM(1,2)"), "\"'=SUM(1,2)\"");
        assert_eq!(csv_cell("+1"), "'+1");
        assert_eq!(csv_cell("-2"), "'-2");
        assert_eq!(csv_cell("@cmd"), "'@cmd");
        assert_eq!(csv_cell("safe"), "safe");
    }
}
