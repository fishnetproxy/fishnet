use rusqlite::{Connection, OptionalExtension, params};
use tiny_keccak::{Hasher, Keccak};

pub type H256 = [u8; 32];
pub const ZERO_H256: H256 = [0u8; 32];

const USD_MICROS_SCALE: f64 = 1_000_000.0;

#[derive(Clone)]
pub struct LeafPayload<'a> {
    pub id: u64,
    pub timestamp: u64,
    pub intent_type: &'a str,
    pub service: &'a str,
    pub action: &'a str,
    pub decision: &'a str,
    pub reason: Option<&'a str>,
    pub cost_usd: Option<f64>,
    pub policy_version_hash: H256,
    pub intent_hash: H256,
    pub permit_hash: Option<H256>,
}

pub fn keccak256(data: &[u8]) -> H256 {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

pub fn hash_pair(left: &H256, right: &H256) -> H256 {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(left);
    bytes[32..].copy_from_slice(right);
    keccak256(&bytes)
}

pub fn h256_to_hex(hash: &H256) -> String {
    format!("0x{}", hex::encode(hash))
}

pub fn h256_from_hex(raw: &str) -> Option<H256> {
    let normalized = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(normalized).ok()?;
    h256_from_bytes(&bytes)
}

pub fn h256_from_bytes(raw: &[u8]) -> Option<H256> {
    if raw.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(raw);
    Some(hash)
}

pub fn hash_audit_leaf(payload: &LeafPayload<'_>) -> H256 {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(&payload.id.to_le_bytes());
    bytes.extend_from_slice(&payload.timestamp.to_le_bytes());
    push_string(&mut bytes, payload.intent_type);
    push_string(&mut bytes, payload.service);
    push_string(&mut bytes, payload.action);
    push_string(&mut bytes, payload.decision);

    match payload.reason {
        Some(reason) => {
            bytes.push(1);
            push_string(&mut bytes, reason);
        }
        None => bytes.push(0),
    }

    let max_cost = (i64::MAX as f64) / USD_MICROS_SCALE;
    match payload.cost_usd {
        Some(cost) if cost.is_finite() && cost >= 0.0 && cost <= max_cost => {
            bytes.push(1);
            let micros = (cost * USD_MICROS_SCALE).round() as i64;
            bytes.extend_from_slice(&micros.to_le_bytes());
        }
        _ => bytes.push(0),
    }

    bytes.extend_from_slice(&payload.policy_version_hash);
    bytes.extend_from_slice(&payload.intent_hash);

    if let Some(hash) = payload.permit_hash {
        bytes.push(1);
        bytes.extend_from_slice(&hash);
    } else {
        bytes.push(0);
    }

    keccak256(&bytes)
}

pub fn insert_leaf_and_new_parents(
    conn: &Connection,
    entry_id: u64,
    leaf_position: u64,
    leaf_hash: H256,
) -> rusqlite::Result<H256> {
    insert_node(conn, entry_id, 0, leaf_position, true, &leaf_hash)?;

    let mut current_hash = leaf_hash;
    let mut current_level = 0u32;
    let mut current_position = leaf_position;
    let target_height = tree_height_for_leaf_count(leaf_position.saturating_add(1));

    while current_level < target_height {
        let sibling_position = if current_position % 2 == 0 {
            current_position + 1
        } else {
            current_position.saturating_sub(1)
        };

        let sibling_hash =
            get_node_hash(conn, current_level, sibling_position)?.unwrap_or(current_hash);

        let (left, right) = if current_position % 2 == 0 {
            (current_hash, sibling_hash)
        } else {
            (sibling_hash, current_hash)
        };

        let parent_hash = hash_pair(&left, &right);
        current_level += 1;
        current_position /= 2;

        insert_node(
            conn,
            entry_id,
            current_level,
            current_position,
            false,
            &parent_hash,
        )?;

        current_hash = parent_hash;
    }

    Ok(current_hash)
}

pub fn compute_root_from_leaves(conn: &Connection) -> rusqlite::Result<H256> {
    Ok(compute_root_from_hashes(load_leaf_hashes(conn)?))
}

pub fn compute_root_from_hashes(mut layer: Vec<H256>) -> H256 {
    if layer.is_empty() {
        return ZERO_H256;
    }

    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = *layer.last().unwrap_or(&ZERO_H256);
            layer.push(last);
        }

        let mut next_layer = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            next_layer.push(hash_pair(&pair[0], &pair[1]));
        }
        layer = next_layer;
    }

    layer[0]
}

pub fn merkle_path_for_leaf(conn: &Connection, leaf_position: u64) -> rusqlite::Result<Vec<H256>> {
    let mut layer = load_leaf_hashes(conn)?;
    if layer.is_empty() {
        return Ok(Vec::new());
    }

    let mut index = leaf_position as usize;
    if index >= layer.len() {
        return Ok(Vec::new());
    }

    let mut path = Vec::new();

    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = *layer.last().unwrap_or(&ZERO_H256);
            layer.push(last);
        }

        let sibling = if index % 2 == 0 { index + 1 } else { index - 1 };
        path.push(layer[sibling]);

        let mut next_layer = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            next_layer.push(hash_pair(&pair[0], &pair[1]));
        }

        layer = next_layer;
        index /= 2;
    }

    Ok(path)
}

fn push_string(bytes: &mut Vec<u8>, text: &str) {
    bytes.extend_from_slice(&(text.len() as u64).to_le_bytes());
    bytes.extend_from_slice(text.as_bytes());
}

fn insert_node(
    conn: &Connection,
    entry_id: u64,
    level: u32,
    position: u64,
    is_leaf: bool,
    hash: &H256,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO audit_merkle_nodes (entry_id, level, position, is_leaf, hash)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(level, position) DO UPDATE SET
             entry_id = excluded.entry_id,
             is_leaf = excluded.is_leaf,
             hash = excluded.hash",
        params![
            entry_id as i64,
            level as i64,
            position as i64,
            is_leaf as i64,
            hash
        ],
    )?;
    Ok(())
}

fn get_node_hash(conn: &Connection, level: u32, position: u64) -> rusqlite::Result<Option<H256>> {
    let bytes = conn
        .query_row(
            "SELECT hash FROM audit_merkle_nodes WHERE level = ?1 AND position = ?2",
            params![level as i64, position as i64],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;

    match bytes {
        Some(raw) => h256_from_bytes(&raw)
            .map(Some)
            .ok_or_else(|| invalid_blob_error(&format!(
                "invalid merkle node hash length at level {level} position {position}: expected 32 bytes, got {}",
                raw.len()
            ))),
        None => Ok(None),
    }
}

fn load_leaf_hashes(conn: &Connection) -> rusqlite::Result<Vec<H256>> {
    let mut stmt = conn.prepare(
        "SELECT hash
         FROM audit_merkle_nodes
         WHERE is_leaf = 1
         ORDER BY position ASC",
    )?;

    let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let mut hashes = Vec::new();

    for row in rows {
        let raw = row?;
        let hash = h256_from_bytes(&raw).ok_or_else(|| {
            invalid_blob_error(&format!(
                "invalid leaf hash length at position {}: expected 32 bytes, got {}",
                hashes.len(),
                raw.len()
            ))
        })?;
        hashes.push(hash);
    }

    Ok(hashes)
}

fn tree_height_for_leaf_count(leaf_count: u64) -> u32 {
    if leaf_count <= 1 {
        0
    } else {
        u64::BITS - (leaf_count - 1).leading_zeros()
    }
}

fn invalid_blob_error(message: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Blob,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            message.to_string(),
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_hash_is_stable() {
        let a = keccak256(b"fishnet");
        let b = keccak256(b"fishnet");
        assert_eq!(a, b);
        assert_ne!(a, ZERO_H256);
    }

    #[test]
    fn hash_pair_changes_when_order_changes() {
        let left = keccak256(b"left");
        let right = keccak256(b"right");
        let ab = hash_pair(&left, &right);
        let ba = hash_pair(&right, &left);
        assert_ne!(ab, ba);
    }

    #[test]
    fn leaf_hash_changes_for_decision_change() {
        let base = LeafPayload {
            id: 1,
            timestamp: 1700000000000,
            intent_type: "api_call",
            service: "openai",
            action: "POST /v1/chat/completions",
            decision: "approved",
            reason: None,
            cost_usd: Some(0.012),
            policy_version_hash: keccak256(b"policy"),
            intent_hash: keccak256(b"intent"),
            permit_hash: None,
        };

        let denied = LeafPayload {
            decision: "denied",
            reason: Some("blocked"),
            ..base.clone()
        };

        assert_ne!(hash_audit_leaf(&base), hash_audit_leaf(&denied));
    }
}
