use std::fs;
use std::path::PathBuf;
use std::sync::RwLock;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::constants;

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("password already initialized")]
    AlreadyInitialized,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub trait PasswordVerifier: Send + Sync {
    fn is_initialized(&self) -> Result<bool, PasswordError>;
    fn setup(&self, password: &str) -> Result<(), PasswordError>;
    fn verify(&self, password: &str) -> Result<bool, PasswordError>;
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct AuthFile {
    password_hash: String,
}

pub struct FilePasswordStore {
    path: PathBuf,
    cache: RwLock<Option<String>>,
}

impl FilePasswordStore {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            cache: RwLock::new(None),
        }
    }

    pub fn default_path() -> Option<PathBuf> {
        constants::default_data_file(constants::AUTH_FILE)
    }

    fn hash_password(password: &str) -> String {
        let hash = Sha256::digest(password.as_bytes());
        hash.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn read_hash(&self) -> Result<Option<String>, PasswordError> {
        // Check cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(ref hash) = *cache {
                return Ok(Some(hash.clone()));
            }
        }

        // Read from file
        if !self.path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&self.path)?;
        let auth_file: AuthFile = serde_json::from_str(&content)?;

        // Update cache
        {
            let mut cache = self.cache.write().unwrap();
            *cache = Some(auth_file.password_hash.clone());
        }

        Ok(Some(auth_file.password_hash))
    }
}

impl PasswordVerifier for FilePasswordStore {
    fn is_initialized(&self) -> Result<bool, PasswordError> {
        Ok(self.read_hash()?.is_some())
    }

    fn setup(&self, password: &str) -> Result<(), PasswordError> {
        if self.is_initialized()? {
            return Err(PasswordError::AlreadyInitialized);
        }

        let hash = Self::hash_password(password);
        let auth_file = AuthFile {
            password_hash: hash.clone(),
        };
        let json = serde_json::to_string_pretty(&auth_file)?;

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&self.path, json)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                &self.path,
                fs::Permissions::from_mode(constants::AUTH_FILE_MODE),
            )?;
        }

        let mut cache = self.cache.write().unwrap();
        *cache = Some(hash);

        Ok(())
    }

    fn verify(&self, password: &str) -> Result<bool, PasswordError> {
        let stored = match self.read_hash()? {
            Some(h) => h,
            None => return Ok(false),
        };

        let candidate = Self::hash_password(password);
        let stored_bytes = stored.as_bytes();
        let candidate_bytes = candidate.as_bytes();

        Ok(stored_bytes.len() == candidate_bytes.len()
            && bool::from(stored_bytes.ct_eq(candidate_bytes)))
    }
}
