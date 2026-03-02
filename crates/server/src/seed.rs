use std::collections::HashMap;

use fishnet_types::config::FishnetConfig;

use crate::alert::{AlertSeverity, AlertStore, AlertType};
use crate::signer::StubSigner;
use crate::spend::{ServiceBudget, SpendStore};
use crate::state::AppState;

const DEV_PRIVATE_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // gitleaks:allow

pub fn dev_config() -> FishnetConfig {
    let mut config = FishnetConfig::default();

    config.onchain.enabled = true;
    config.onchain.chain_ids = vec![31337];
    config.onchain.limits.cooldown_seconds = 0;
    config.onchain.permits.verifying_contract =
        "0x5FbDB2315678afecb367f032d93F642f64180aa3".to_string();
    config.onchain.permits.expiry_seconds = 300;
    config.onchain.permits.require_policy_hash = true;
    config.onchain.whitelist = HashMap::from([(
        "0x5FbDB2315678afecb367f032d93F642f64180aa3".to_string(),
        vec!["execute(bytes,bytes[],uint256)".to_string()],
    )]);

    config.llm.prompt_drift.enabled = true;
    config.llm.prompt_size_guard.enabled = true;
    config.llm.track_spend = true;

    config.alerts.prompt_drift = true;
    config.alerts.prompt_size = true;
    config.alerts.budget_warning = true;
    config.alerts.budget_exceeded = true;
    config.alerts.onchain_denied = true;
    config.alerts.rate_limit_hit = true;

    config
}

pub fn dev_signer() -> StubSigner {
    let pk_bytes = hex::decode(DEV_PRIVATE_KEY).expect("valid hex");
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&pk_bytes);
    StubSigner::from_bytes(secret)
}

pub async fn run(state: &AppState) {
    eprintln!("[fishnet] dev-seed: populating sample data");
    seed_alerts(&state.alert_store).await;
    seed_spend(&state.spend_store).await;
    seed_budgets(&state.spend_store).await;
}

async fn seed_alerts(store: &AlertStore) {
    let alerts: &[(AlertType, AlertSeverity, &str, &str)] = &[
        (
            AlertType::PromptDrift,
            AlertSeverity::Critical,
            "openai",
            "System prompt changed. Previous: 0x3a1f…c8e2 Current: 0x91b4…d7f0",
        ),
        (
            AlertType::PromptDrift,
            AlertSeverity::Critical,
            "anthropic",
            "System prompt changed. Previous: 0x7e2d…a1b3 Current: 0xf4c8…52e9",
        ),
        (
            AlertType::PromptSize,
            AlertSeverity::Warning,
            "openai",
            "Oversized prompt: ~62,500 tokens (limit: 50,000). Action: alert only.",
        ),
        (
            AlertType::PromptSize,
            AlertSeverity::Warning,
            "anthropic",
            "Prompt size 210,000 chars exceeds limit of 200,000. Action: denied.",
        ),
        (
            AlertType::PromptDrift,
            AlertSeverity::Critical,
            "openai",
            "System prompt changed. Previous: 0x3a1f…c8e2 Current: 0xbb07…19d3 (hashing first 500 chars)",
        ),
        (
            AlertType::BudgetWarning,
            AlertSeverity::Warning,
            "openai",
            "Daily spend at 85% of $20.00 budget ($17.00 used).",
        ),
        (
            AlertType::BudgetExceeded,
            AlertSeverity::Critical,
            "openai",
            "Daily budget of $20.00 exceeded. Current spend: $23.47.",
        ),
        (
            AlertType::BudgetWarning,
            AlertSeverity::Warning,
            "anthropic",
            "Daily spend at 92% of $30.00 budget ($27.60 used).",
        ),
        (
            AlertType::RateLimitHit,
            AlertSeverity::Warning,
            "openai",
            "Rate limit exceeded for openai. Retry after 12s.",
        ),
        (
            AlertType::RateLimitHit,
            AlertSeverity::Warning,
            "anthropic",
            "Rate limit exceeded for anthropic. Retry after 8s.",
        ),
        (
            AlertType::OnchainDenied,
            AlertSeverity::Critical,
            "openai",
            "On-chain policy denied request: wallet 0xdead…beef not whitelisted.",
        ),
        (
            AlertType::PromptSize,
            AlertSeverity::Warning,
            "openai",
            "Oversized prompt: ~75,000 tokens (limit: 50,000). Action: alert only.",
        ),
    ];

    for (alert_type, severity, service, message) in alerts {
        if let Err(e) = store
            .create(*alert_type, *severity, service, message.to_string())
            .await
        {
            eprintln!("[fishnet] dev-seed: failed to create alert: {e}");
        }
    }

    if let Some(alert) = store.list().await.unwrap_or_default().first() {
        let _ = store.dismiss(&alert.id).await;
    }

    eprintln!(
        "[fishnet] dev-seed: created {} sample alerts (1 dismissed)",
        alerts.len()
    );
}

async fn seed_spend(store: &SpendStore) {
    let today = chrono::Utc::now().date_naive();

    let entries: &[(&str, u32, f64)] = &[
        ("openai", 0, 14.32),
        ("openai", 1, 18.75),
        ("openai", 2, 12.10),
        ("openai", 3, 22.40),
        ("openai", 4, 9.85),
        ("openai", 5, 16.20),
        ("openai", 6, 19.90),
        ("openai", 7, 11.45),
        ("openai", 8, 15.60),
        ("openai", 9, 20.30),
        ("openai", 10, 8.75),
        ("openai", 11, 13.20),
        ("openai", 12, 17.85),
        ("openai", 13, 21.10),
        ("anthropic", 0, 8.50),
        ("anthropic", 1, 12.30),
        ("anthropic", 2, 6.75),
        ("anthropic", 3, 15.20),
        ("anthropic", 4, 4.90),
        ("anthropic", 5, 10.40),
        ("anthropic", 6, 13.60),
        ("anthropic", 7, 7.25),
        ("anthropic", 8, 9.80),
        ("anthropic", 9, 14.50),
        ("anthropic", 10, 5.35),
        ("anthropic", 11, 8.90),
        ("anthropic", 12, 11.70),
        ("anthropic", 13, 16.00),
    ];

    let mut count = 0;
    for &(service, days_ago, cost) in entries {
        let date = today
            .checked_sub_days(chrono::Days::new(days_ago as u64))
            .unwrap()
            .format("%Y-%m-%d")
            .to_string();
        if let Err(e) = store.record_spend(service, &date, cost).await {
            eprintln!("[fishnet] dev-seed: failed to record spend: {e}");
        } else {
            count += 1;
        }
    }

    eprintln!("[fishnet] dev-seed: inserted {count} spend records (14 days, 2 services)");
}

async fn seed_budgets(store: &SpendStore) {
    let now = chrono::Utc::now().timestamp();

    let budgets = [
        ServiceBudget {
            service: "openai".to_string(),
            daily_budget_usd: 20.0,
            monthly_budget_usd: Some(500.0),
            updated_at: now,
        },
        ServiceBudget {
            service: "anthropic".to_string(),
            daily_budget_usd: 30.0,
            monthly_budget_usd: Some(800.0),
            updated_at: now,
        },
    ];

    for budget in &budgets {
        if let Err(e) = store.set_budget(budget).await {
            eprintln!("[fishnet] dev-seed: failed to set budget: {e}");
        }
    }

    eprintln!(
        "[fishnet] dev-seed: configured {} service budgets",
        budgets.len()
    );
}
