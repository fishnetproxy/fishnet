use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FishnetConfig {
    pub llm: LlmConfig,
    pub http: HttpClientConfig,
    pub dashboard: DashboardConfig,
    pub alerts: AlertsConfig,
    pub onchain: OnchainConfig,
    pub binance: BinanceConfig,
    pub custom: HashMap<String, CustomServiceConfig>,
}

impl FishnetConfig {
    pub fn validate(&mut self) -> Result<(), String> {
        self.llm.validate()?;
        self.http.validate()?;
        self.binance.validate()?;
        for (name, service) in &self.custom {
            service.validate(name)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LlmConfig {
    pub prompt_drift: PromptDriftConfig,
    pub prompt_size_guard: PromptSizeGuardConfig,
    pub track_spend: bool,
    pub daily_budget_usd: f64,
    pub budget_warning_pct: u8,
    pub rate_limit_per_minute: u32,
    pub allowed_models: Vec<String>,
    pub model_pricing: HashMap<String, ModelPricing>,
}

impl Default for LlmConfig {
    fn default() -> Self {
        let mut model_pricing = HashMap::new();
        model_pricing.insert(
            "gpt-4o".to_string(),
            ModelPricing {
                input_per_million_usd: 2.50,
                output_per_million_usd: 10.0,
            },
        );
        model_pricing.insert(
            "gpt-4o-mini".to_string(),
            ModelPricing {
                input_per_million_usd: 0.15,
                output_per_million_usd: 0.60,
            },
        );
        model_pricing.insert(
            "claude-sonnet".to_string(),
            ModelPricing {
                input_per_million_usd: 3.0,
                output_per_million_usd: 15.0,
            },
        );

        Self {
            prompt_drift: PromptDriftConfig::default(),
            prompt_size_guard: PromptSizeGuardConfig::default(),
            track_spend: true,
            daily_budget_usd: 20.0,
            budget_warning_pct: 80,
            rate_limit_per_minute: 60,
            allowed_models: Vec::new(),
            model_pricing,
        }
    }
}

impl LlmConfig {
    pub fn validate(&mut self) -> Result<(), String> {
        for model in &mut self.allowed_models {
            *model = model.trim().to_string();
        }
        self.allowed_models.retain(|m| !m.is_empty());

        let mut normalized_pricing = HashMap::with_capacity(self.model_pricing.len());
        let mut normalized_sources = HashMap::with_capacity(self.model_pricing.len());
        for (model, pricing) in std::mem::take(&mut self.model_pricing) {
            let trimmed_model = model.trim().to_string();
            if trimmed_model.is_empty() {
                return Err("llm.model_pricing contains an empty model key".to_string());
            }
            if !pricing.input_per_million_usd.is_finite() || pricing.input_per_million_usd < 0.0 {
                return Err(format!(
                    "llm.model_pricing.{trimmed_model}.input_per_million_usd must be a non-negative finite number"
                ));
            }
            if !pricing.output_per_million_usd.is_finite() || pricing.output_per_million_usd < 0.0 {
                return Err(format!(
                    "llm.model_pricing.{trimmed_model}.output_per_million_usd must be a non-negative finite number"
                ));
            }

            if let Some(original) = normalized_sources.get(&trimmed_model) {
                return Err(format!(
                    "llm.model_pricing contains duplicate model keys after trimming: '{original}' and '{model}' both normalize to '{trimmed_model}'"
                ));
            }
            normalized_sources.insert(trimmed_model.clone(), model);
            normalized_pricing.insert(trimmed_model, pricing);
        }
        self.model_pricing = normalized_pricing;

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ModelPricing {
    pub input_per_million_usd: f64,
    pub output_per_million_usd: f64,
}

impl Default for ModelPricing {
    fn default() -> Self {
        Self {
            input_per_million_usd: 0.0,
            output_per_million_usd: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PromptDriftConfig {
    pub enabled: bool,
    pub mode: GuardMode,
    pub hash_chars: u64,
    pub hash_algorithm: HashAlgorithm,
    pub ignore_whitespace: bool,
    pub reset_baseline_on_restart: bool,
}

impl Default for PromptDriftConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: GuardMode::Alert,
            hash_chars: 0,
            hash_algorithm: HashAlgorithm::Keccak256,
            ignore_whitespace: true,
            reset_baseline_on_restart: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PromptSizeGuardConfig {
    pub enabled: bool,
    pub max_prompt_tokens: u64,
    pub max_prompt_chars: u64,
    pub action: GuardAction,
}

impl Default for PromptSizeGuardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_prompt_tokens: 50_000,
            max_prompt_chars: 0,
            action: GuardAction::Deny,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DashboardConfig {
    pub spend_history_days: u32,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            spend_history_days: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpClientConfig {
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub pool_idle_timeout_secs: u64,
    pub pool_max_idle_per_host: usize,
    pub upstream_pool_max_idle_per_host: HashMap<String, usize>,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 5_000,
            request_timeout_ms: 0,
            pool_idle_timeout_secs: 90,
            pool_max_idle_per_host: 16,
            upstream_pool_max_idle_per_host: HashMap::new(),
        }
    }
}

impl HttpClientConfig {
    pub fn validate(&mut self) -> Result<(), String> {
        if self.connect_timeout_ms == 0 {
            self.connect_timeout_ms = 5_000;
        }
        if self.pool_idle_timeout_secs == 0 {
            self.pool_idle_timeout_secs = 90;
        }
        if self.pool_max_idle_per_host == 0 {
            self.pool_max_idle_per_host = 16;
        }

        let mut normalized = HashMap::with_capacity(self.upstream_pool_max_idle_per_host.len());
        for (service, pool_size) in std::mem::take(&mut self.upstream_pool_max_idle_per_host) {
            let service = service.trim().to_string();
            if service.is_empty() {
                return Err(
                    "http.upstream_pool_max_idle_per_host contains an empty service key"
                        .to_string(),
                );
            }
            if pool_size == 0 {
                return Err(format!(
                    "http.upstream_pool_max_idle_per_host.{service} must be > 0"
                ));
            }
            if normalized.insert(service.clone(), pool_size).is_some() {
                return Err(format!(
                    "http.upstream_pool_max_idle_per_host contains duplicate service key '{service}' after normalization"
                ));
            }
        }
        self.upstream_pool_max_idle_per_host = normalized;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertsConfig {
    pub prompt_drift: bool,
    pub prompt_size: bool,
    pub budget_warning: bool,
    pub budget_exceeded: bool,
    pub onchain_denied: bool,
    pub rate_limit_hit: bool,
    pub anomalous_volume: bool,
    pub new_endpoint: bool,
    pub time_anomaly: bool,
    pub high_severity_denied_action: bool,
    pub retention_days: u32,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            prompt_drift: true,
            prompt_size: true,
            budget_warning: true,
            budget_exceeded: true,
            onchain_denied: true,
            rate_limit_hit: true,
            anomalous_volume: true,
            new_endpoint: true,
            time_anomaly: true,
            high_severity_denied_action: true,
            retention_days: 30,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OnchainConfig {
    pub enabled: bool,
    pub chain_ids: Vec<u64>,
    pub limits: OnchainLimits,
    pub permits: OnchainPermits,
    pub whitelist: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OnchainLimits {
    pub max_tx_value_usd: f64,
    pub daily_spend_cap_usd: f64,
    pub cooldown_seconds: u64,
    pub max_slippage_bps: u64,
    pub max_leverage: u64,
}

impl Default for OnchainLimits {
    fn default() -> Self {
        Self {
            max_tx_value_usd: 100.0,
            daily_spend_cap_usd: 500.0,
            cooldown_seconds: 30,
            max_slippage_bps: 50,
            max_leverage: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OnchainPermits {
    pub expiry_seconds: u64,
    pub require_policy_hash: bool,
    pub verifying_contract: String,
}

impl Default for OnchainPermits {
    fn default() -> Self {
        Self {
            expiry_seconds: 300,
            require_policy_hash: true,
            verifying_contract: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BinanceConfig {
    pub enabled: bool,
    pub base_url: String,
    pub max_order_value_usd: f64,
    pub daily_volume_cap_usd: f64,
    pub allow_delete_open_orders: bool,
    pub recv_window_ms: u64,
}

impl Default for BinanceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: "https://api.binance.com".to_string(),
            max_order_value_usd: 500.0,
            daily_volume_cap_usd: 2_500.0,
            allow_delete_open_orders: false,
            recv_window_ms: 5_000,
        }
    }
}

impl BinanceConfig {
    pub fn validate(&mut self) -> Result<(), String> {
        if !self.max_order_value_usd.is_finite() || self.max_order_value_usd < 0.0 {
            return Err(
                "binance.max_order_value_usd must be a non-negative finite number".to_string(),
            );
        }
        if !self.daily_volume_cap_usd.is_finite() || self.daily_volume_cap_usd < 0.0 {
            return Err(
                "binance.daily_volume_cap_usd must be a non-negative finite number".to_string(),
            );
        }
        if self.enabled && self.base_url.trim().is_empty() {
            return Err(
                "binance.base_url must be set and non-empty when binance is enabled".to_string(),
            );
        }

        if self.recv_window_ms == 0 {
            self.recv_window_ms = 5_000;
        }
        if self.recv_window_ms > 60_000 {
            return Err(format!(
                "binance.recv_window_ms must be <= 60000, got {}",
                self.recv_window_ms
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomServiceConfig {
    pub base_url: String,
    pub auth_header: String,
    pub auth_value_prefix: String,
    pub auth_value_env: String,
    pub blocked_endpoints: Vec<String>,
    pub rate_limit: u32,
    pub rate_limit_window_seconds: u64,
}

impl Default for CustomServiceConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            auth_header: "Authorization".to_string(),
            auth_value_prefix: "Bearer ".to_string(),
            auth_value_env: String::new(),
            blocked_endpoints: Vec::new(),
            rate_limit: 100,
            rate_limit_window_seconds: 3600,
        }
    }
}

impl CustomServiceConfig {
    pub fn validate(&self, service_name: &str) -> Result<(), String> {
        if self.base_url.trim().is_empty() {
            return Err(format!(
                "custom.{service_name}.base_url must be set and non-empty"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardMode {
    Alert,
    Deny,
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardAction {
    Deny,
    Alert,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    Keccak256,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn llm_model_pricing_keys_are_trimmed() {
        let mut cfg = LlmConfig::default();
        cfg.model_pricing.clear();
        cfg.model_pricing.insert(
            " gpt-4o-mini ".to_string(),
            ModelPricing {
                input_per_million_usd: 0.15,
                output_per_million_usd: 0.60,
            },
        );

        cfg.validate().unwrap();
        assert!(cfg.model_pricing.contains_key("gpt-4o-mini"));
    }

    #[test]
    fn llm_model_pricing_rejects_duplicate_keys_after_trim() {
        let mut cfg = LlmConfig::default();
        cfg.model_pricing.clear();
        cfg.model_pricing.insert(
            "gpt-4o-mini".to_string(),
            ModelPricing {
                input_per_million_usd: 0.15,
                output_per_million_usd: 0.60,
            },
        );
        cfg.model_pricing.insert(
            "  gpt-4o-mini  ".to_string(),
            ModelPricing {
                input_per_million_usd: 0.15,
                output_per_million_usd: 0.60,
            },
        );

        let err = cfg.validate().unwrap_err();
        assert!(err.contains("duplicate model keys after trimming"));
    }

    #[test]
    fn binance_validate_rejects_invalid_limits_and_requires_base_url_when_enabled() {
        let mut cfg = BinanceConfig {
            enabled: true,
            base_url: "   ".to_string(),
            max_order_value_usd: -1.0,
            daily_volume_cap_usd: 100.0,
            allow_delete_open_orders: false,
            recv_window_ms: 5_000,
        };

        let err = cfg.validate().unwrap_err();
        assert!(err.contains("max_order_value_usd"));

        cfg.max_order_value_usd = 100.0;
        cfg.daily_volume_cap_usd = f64::INFINITY;
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("daily_volume_cap_usd"));

        cfg.daily_volume_cap_usd = 100.0;
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("base_url"));
    }

    #[test]
    fn http_validate_normalizes_upstream_pool_overrides_and_rejects_zero() {
        let mut cfg = HttpClientConfig::default();
        cfg.upstream_pool_max_idle_per_host
            .insert(" openai ".to_string(), 32);
        cfg.upstream_pool_max_idle_per_host
            .insert("custom.github".to_string(), 4);
        cfg.validate().unwrap();
        assert_eq!(
            cfg.upstream_pool_max_idle_per_host.get("openai"),
            Some(&32usize)
        );
        assert_eq!(
            cfg.upstream_pool_max_idle_per_host.get("custom.github"),
            Some(&4usize)
        );

        let mut bad = HttpClientConfig::default();
        bad.upstream_pool_max_idle_per_host
            .insert("binance".to_string(), 0);
        let err = bad.validate().unwrap_err();
        assert!(err.contains("must be > 0"));
    }
}
