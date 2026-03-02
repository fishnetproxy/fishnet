use std::path::{Path, PathBuf};
use std::sync::Arc;

use fishnet_types::config::FishnetConfig;
use thiserror::Error;
use tokio::sync::watch;

use crate::constants;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("invalid config in {path}: {message}")]
    Validation { path: PathBuf, message: String },
    #[error("failed to serialize config to {path}: {source}")]
    Serialize {
        path: PathBuf,
        source: toml::ser::Error,
    },
}

pub fn default_config_path() -> Option<PathBuf> {
    constants::default_data_file(constants::CONFIG_FILE)
}

pub fn resolve_config_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(path.to_path_buf());
    }

    if let Ok(raw) = std::env::var(constants::ENV_FISHNET_CONFIG) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }

    if let Some(default_config) = default_config_path()
        && default_config.exists()
    {
        return Some(default_config);
    }

    // Backward compatibility for existing local installs using ~/.fishnet/fishnet.toml.
    if let Some(mut legacy_home_config) = dirs::home_dir() {
        legacy_home_config.push(constants::FISHNET_DIR);
        legacy_home_config.push(constants::CONFIG_FILE);
        if legacy_home_config.exists() {
            return Some(legacy_home_config);
        }
    }

    None
}

pub fn load_config(path: Option<&Path>) -> Result<FishnetConfig, ConfigError> {
    match path {
        Some(path) => {
            let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
                path: path.to_path_buf(),
                source: e,
            })?;
            let mut config: FishnetConfig =
                toml::from_str(&content).map_err(|e| ConfigError::Parse {
                    path: path.to_path_buf(),
                    source: e,
                })?;
            config
                .validate()
                .map_err(|message| ConfigError::Validation {
                    path: path.to_path_buf(),
                    message,
                })?;
            Ok(config)
        }
        None => {
            let mut config = FishnetConfig::default();
            config
                .validate()
                .map_err(|message| ConfigError::Validation {
                    path: PathBuf::from("<defaults>"),
                    message,
                })?;
            Ok(config)
        }
    }
}

pub fn config_channel(
    initial: FishnetConfig,
) -> (
    watch::Sender<Arc<FishnetConfig>>,
    watch::Receiver<Arc<FishnetConfig>>,
) {
    watch::channel(Arc::new(initial))
}

pub fn save_config(path: &Path, config: &FishnetConfig) -> Result<(), ConfigError> {
    let toml_string = toml::to_string_pretty(config).map_err(|e| ConfigError::Serialize {
        path: path.to_path_buf(),
        source: e,
    })?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ConfigError::Read {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let tmp_path = path.with_extension(constants::CONFIG_TEMP_EXT);
    std::fs::write(&tmp_path, &toml_string).map_err(|e| ConfigError::Read {
        path: tmp_path.clone(),
        source: e,
    })?;
    std::fs::rename(&tmp_path, path).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn load_defaults_when_no_path() {
        let config = load_config(None).unwrap();
        assert!(config.llm.prompt_drift.enabled);
        assert!(config.llm.prompt_size_guard.enabled);
        assert_eq!(config.llm.prompt_size_guard.max_prompt_tokens, 50_000);
    }

    #[test]
    fn load_partial_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fishnet.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"
[llm.prompt_drift]
enabled = false
mode = "deny"
"#
        )
        .unwrap();

        let config = load_config(Some(&path)).unwrap();
        assert!(!config.llm.prompt_drift.enabled);
        assert_eq!(
            config.llm.prompt_drift.mode,
            fishnet_types::config::GuardMode::Deny
        );

        assert!(config.llm.prompt_drift.ignore_whitespace);
        assert!(config.llm.prompt_size_guard.enabled);
    }

    #[test]
    fn load_invalid_toml_returns_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fishnet.toml");
        std::fs::write(&path, "not valid toml [[[").unwrap();

        let err = load_config(Some(&path)).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn load_missing_file_returns_read_error() {
        let path = PathBuf::from("/tmp/does_not_exist_fishnet.toml");
        let err = load_config(Some(&path)).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
    }

    #[test]
    fn resolve_explicit_path() {
        let path = PathBuf::from("/some/explicit/path.toml");
        let resolved = resolve_config_path(Some(&path));
        assert_eq!(resolved, Some(path));
    }

    #[test]
    fn resolve_returns_none_when_no_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = std::env::set_current_dir(dir.path());
        let _ = resolve_config_path(None);
    }

    #[test]
    fn invalid_enum_value_returns_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fishnet.toml");
        std::fs::write(
            &path,
            r#"
[llm.prompt_drift]
mode = "invalid_mode"
"#,
        )
        .unwrap();

        let err = load_config(Some(&path)).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn load_rejects_recv_window_ms_above_binance_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fishnet.toml");
        std::fs::write(
            &path,
            r#"
[binance]
recv_window_ms = 70000
"#,
        )
        .unwrap();

        let err = load_config(Some(&path)).unwrap_err();
        assert!(matches!(err, ConfigError::Validation { .. }));
        assert!(err.to_string().contains("recv_window_ms"));
    }

    #[test]
    fn load_clamps_recv_window_ms_zero_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fishnet.toml");
        std::fs::write(
            &path,
            r#"
[binance]
recv_window_ms = 0
"#,
        )
        .unwrap();

        let config = load_config(Some(&path)).unwrap();
        assert_eq!(config.binance.recv_window_ms, 5_000);
    }

    #[test]
    fn load_rejects_custom_service_with_empty_base_url() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fishnet.toml");
        std::fs::write(
            &path,
            r#"
[custom.github]
auth_header = "Authorization"
"#,
        )
        .unwrap();

        let err = load_config(Some(&path)).unwrap_err();
        assert!(matches!(err, ConfigError::Validation { .. }));
        assert!(err.to_string().contains("custom.github.base_url"));
    }

    #[test]
    fn save_config_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fishnet.toml");

        let mut config = FishnetConfig::default();
        config.llm.track_spend = true;
        config.llm.daily_budget_usd = 42.5;
        config.llm.rate_limit_per_minute = 100;
        config.http.connect_timeout_ms = 7_500;
        config.http.request_timeout_ms = 45_000;
        config.http.pool_idle_timeout_secs = 120;
        config.http.pool_max_idle_per_host = 32;
        config
            .http
            .upstream_pool_max_idle_per_host
            .insert("openai".to_string(), 64);
        config.alerts.prompt_drift = false;
        config.alerts.retention_days = 7;
        config.dashboard.spend_history_days = 14;

        save_config(&path, &config).unwrap();

        let loaded = load_config(Some(&path)).unwrap();
        assert!(loaded.llm.track_spend);
        assert!((loaded.llm.daily_budget_usd - 42.5).abs() < f64::EPSILON);
        assert_eq!(loaded.llm.rate_limit_per_minute, 100);
        assert_eq!(loaded.http.connect_timeout_ms, 7_500);
        assert_eq!(loaded.http.request_timeout_ms, 45_000);
        assert_eq!(loaded.http.pool_idle_timeout_secs, 120);
        assert_eq!(loaded.http.pool_max_idle_per_host, 32);
        assert_eq!(
            loaded.http.upstream_pool_max_idle_per_host.get("openai"),
            Some(&64usize)
        );
        assert!(!loaded.alerts.prompt_drift);
        assert_eq!(loaded.alerts.retention_days, 7);
        assert_eq!(loaded.dashboard.spend_history_days, 14);
    }

    #[test]
    fn save_config_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("dir").join("fishnet.toml");

        let config = FishnetConfig::default();
        save_config(&path, &config).unwrap();

        let loaded = load_config(Some(&path)).unwrap();
        assert!(loaded.llm.prompt_drift.enabled);
    }

    #[test]
    fn load_dashboard_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fishnet.toml");
        std::fs::write(
            &path,
            r#"
[dashboard]
spend_history_days = 60
"#,
        )
        .unwrap();

        let config = load_config(Some(&path)).unwrap();
        assert_eq!(config.dashboard.spend_history_days, 60);
    }

    #[test]
    fn load_alerts_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fishnet.toml");
        std::fs::write(
            &path,
            r#"
[alerts]
prompt_drift = false
budget_warning = false
new_endpoint = false
retention_days = 7
"#,
        )
        .unwrap();

        let config = load_config(Some(&path)).unwrap();
        assert!(!config.alerts.prompt_drift);
        assert!(config.alerts.prompt_size);
        assert!(!config.alerts.budget_warning);
        assert!(config.alerts.budget_exceeded);
        assert!(!config.alerts.new_endpoint);
        assert_eq!(config.alerts.retention_days, 7);
    }

    #[test]
    fn load_llm_new_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fishnet.toml");
        std::fs::write(
            &path,
            r#"
[llm]
track_spend = true
daily_budget_usd = 10.0
budget_warning_pct = 90
rate_limit_per_minute = 50
"#,
        )
        .unwrap();

        let config = load_config(Some(&path)).unwrap();
        assert!(config.llm.track_spend);
        assert!((config.llm.daily_budget_usd - 10.0).abs() < f64::EPSILON);
        assert_eq!(config.llm.budget_warning_pct, 90);
        assert_eq!(config.llm.rate_limit_per_minute, 50);
    }

    #[test]
    fn load_http_client_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fishnet.toml");
        std::fs::write(
            &path,
            r#"
[http]
connect_timeout_ms = 8000
request_timeout_ms = 120000
pool_idle_timeout_secs = 45
pool_max_idle_per_host = 24

[http.upstream_pool_max_idle_per_host]
openai = 48
"custom.github" = 6
"#,
        )
        .unwrap();

        let config = load_config(Some(&path)).unwrap();
        assert_eq!(config.http.connect_timeout_ms, 8_000);
        assert_eq!(config.http.request_timeout_ms, 120_000);
        assert_eq!(config.http.pool_idle_timeout_secs, 45);
        assert_eq!(config.http.pool_max_idle_per_host, 24);
        assert_eq!(
            config.http.upstream_pool_max_idle_per_host.get("openai"),
            Some(&48usize)
        );
        assert_eq!(
            config
                .http
                .upstream_pool_max_idle_per_host
                .get("custom.github"),
            Some(&6usize)
        );
    }

    #[test]
    fn load_defaults_for_new_sections_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fishnet.toml");
        std::fs::write(
            &path,
            r#"
[llm.prompt_drift]
enabled = false
"#,
        )
        .unwrap();

        let config = load_config(Some(&path)).unwrap();
        assert_eq!(config.http.connect_timeout_ms, 5_000);
        assert_eq!(config.http.request_timeout_ms, 0);
        assert_eq!(config.http.pool_idle_timeout_secs, 90);
        assert_eq!(config.http.pool_max_idle_per_host, 16);
        assert!(config.http.upstream_pool_max_idle_per_host.is_empty());
        assert_eq!(config.dashboard.spend_history_days, 30);
        assert!(config.alerts.prompt_drift);
        assert!(config.alerts.prompt_size);
        assert!(config.alerts.anomalous_volume);
        assert!(config.alerts.new_endpoint);
        assert!(config.alerts.time_anomaly);
        assert!(config.alerts.high_severity_denied_action);
        assert_eq!(config.alerts.retention_days, 30);
        assert!(config.llm.track_spend);
        assert!((config.llm.daily_budget_usd - 20.0).abs() < f64::EPSILON);
        assert_eq!(config.llm.budget_warning_pct, 80);
        assert_eq!(config.llm.rate_limit_per_minute, 60);
    }
}
