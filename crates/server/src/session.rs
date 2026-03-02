use std::collections::HashMap;

use chrono::{DateTime, TimeDelta, Utc};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

use crate::constants;

pub struct Session {
    pub token: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub struct SessionStore {
    sessions: RwLock<HashMap<String, Session>>,
    ttl: TimeDelta,
    max_sessions: usize,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            ttl: TimeDelta::hours(constants::SESSION_TTL_HOURS),
            max_sessions: constants::MAX_SESSIONS,
        }
    }

    pub async fn create(&self) -> Session {
        let token_bytes: [u8; constants::SESSION_TOKEN_BYTES] = rand::random();
        let hex: String = token_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let token = format!("{}{hex}", constants::SESSION_TOKEN_PREFIX);

        let now = Utc::now();
        let expires_at = now + self.ttl;

        let mut sessions = self.sessions.write().await;

        sessions.retain(|_, s| s.expires_at > now);

        if sessions.len() >= self.max_sessions
            && let Some(oldest_key) = sessions
                .iter()
                .min_by_key(|(_, s)| s.created_at)
                .map(|(k, _)| k.clone())
        {
            sessions.remove(&oldest_key);
        }

        sessions.insert(
            token.clone(),
            Session {
                token: token.clone(),
                created_at: now,
                expires_at,
            },
        );

        Session {
            token,
            created_at: now,
            expires_at,
        }
    }

    pub async fn validate(&self, token: &str) -> bool {
        let sessions = self.sessions.read().await;
        let now = Utc::now();

        for session in sessions.values() {
            if session.expires_at > now {
                let stored = session.token.as_bytes();
                let provided = token.as_bytes();
                if stored.len() == provided.len() && bool::from(stored.ct_eq(provided)) {
                    return true;
                }
            }
        }

        false
    }

    pub async fn remove(&self, token: &str) -> bool {
        let mut sessions = self.sessions.write().await;

        let key = sessions
            .keys()
            .find(|k| {
                let stored = k.as_bytes();
                let provided = token.as_bytes();
                stored.len() == provided.len() && bool::from(stored.ct_eq(provided))
            })
            .cloned();

        if let Some(key) = key {
            sessions.remove(&key);
            true
        } else {
            false
        }
    }
}
