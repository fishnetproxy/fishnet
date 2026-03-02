use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use fishnet_server::config::load_config;
#[cfg(not(feature = "dev-seed"))]
use fishnet_server::signer::StubSigner;
use fishnet_server::{
    alert::{AlertSeverity, AlertStore},
    anomaly::AnomalyTracker,
    audit::{self, AuditQueryFilter, AuditStore},
    config::{config_channel, default_config_path, resolve_config_path, save_config},
    create_router,
    llm_guard::BaselineStore,
    onchain::OnchainStore,
    password::FilePasswordStore,
    rate_limit::{LoginRateLimiter, ProxyRateLimiter},
    session::SessionStore,
    signer::SignerTrait,
    spend::SpendStore,
    state::AppState,
    vault::{CredentialMetadata, CredentialStore},
    watch::spawn_config_watcher,
};
#[cfg(target_os = "macos")]
use security_framework::passwords::{get_generic_password, set_generic_password};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const PID_FILE_NAME: &str = "fishnet.pid";
const DEFAULT_AUDIT_LIMIT: u32 = 20;
const BACKUP_DIR_NAME: &str = "backups";
#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "fishnet";
const LAUNCH_AGENT_LABEL: &str = "dev.fishnet.local";

#[derive(Debug, Parser)]
#[command(
    name = "fishnet",
    version,
    about = "Fishnet local security gateway CLI"
)]
struct Cli {
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start the Fishnet server
    Start,
    /// Stop a running Fishnet process started via CLI
    Stop,
    /// First-time setup wizard
    Init(InitArgs),
    /// Show runtime status, spend, request counts, and active alerts
    Status,
    /// Validate local Fishnet + agent environment
    Doctor(DoctorArgs),
    /// Add an API credential to the encrypted vault
    AddKey(AddKeyArgs),
    /// List stored credentials (service + name only)
    ListKeys,
    /// Remove a credential by name
    RemoveKey(RemoveKeyArgs),
    /// Export encrypted vault backup
    Backup(BackupArgs),
    /// Restore encrypted vault backup
    Restore(RestoreArgs),
    /// Policy commands
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    /// Service install/uninstall commands
    Service {
        #[command(subcommand)]
        command: ServiceCommands,
    },
    /// Firewall lockdown commands
    Firewall {
        #[command(subcommand)]
        command: FirewallCommands,
    },
    /// Audit log commands
    Audit(AuditArgs),
}

#[derive(Debug, Args)]
struct InitArgs {
    #[arg(long)]
    master_password: Option<String>,
    #[arg(long, default_value_t = false)]
    store_derived_key_in_keychain: bool,
    #[arg(long)]
    first_service: Option<String>,
    #[arg(long)]
    first_name: Option<String>,
    #[arg(long)]
    first_key: Option<String>,
    #[arg(long)]
    daily_budget_usd: Option<f64>,
    #[arg(long)]
    rate_limit_per_minute: Option<u32>,
    /// Apply system-level user/permission setup commands (default: dry-run/print only)
    #[arg(long)]
    apply_system: bool,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct AddKeyArgs {
    #[arg(long)]
    service: Option<String>,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    key: Option<String>,
}

#[derive(Debug, Args)]
struct RemoveKeyArgs {
    /// Credential name to remove
    name: String,
    /// Optional service filter when names are reused
    #[arg(long)]
    service: Option<String>,
    /// Skip confirmation prompt
    #[arg(long)]
    yes: bool,
}

#[derive(Debug, Args)]
struct BackupArgs {
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct RestoreArgs {
    file: PathBuf,
    #[arg(long)]
    yes: bool,
}

#[derive(Debug, Subcommand)]
enum PolicyCommands {
    /// Open fishnet.toml in $EDITOR
    Edit,
}

#[derive(Debug, Subcommand)]
enum ServiceCommands {
    /// Install service auto-start integration
    Install(ServiceInstallArgs),
    /// Uninstall service auto-start integration
    Uninstall(ServiceUninstallArgs),
}

#[derive(Debug, Args)]
struct ServiceInstallArgs {
    /// Apply changes (default is dry-run)
    #[arg(long)]
    apply: bool,
}

#[derive(Debug, Args)]
struct ServiceUninstallArgs {
    /// Apply changes (default is dry-run)
    #[arg(long)]
    apply: bool,
}

#[derive(Debug, Subcommand)]
enum FirewallCommands {
    /// Enable local-only firewall policy for agent user
    Enable(FirewallArgs),
    /// Disable local-only firewall policy for agent user
    Disable(FirewallArgs),
}

#[derive(Debug, Args)]
struct FirewallArgs {
    /// Agent unix user to constrain
    #[arg(long)]
    agent_user: Option<String>,
    /// Apply changes (default is dry-run)
    #[arg(long)]
    apply: bool,
}

#[derive(Debug, Args)]
struct AuditArgs {
    #[command(subcommand)]
    command: Option<AuditCommands>,

    #[arg(long, default_value_t = DEFAULT_AUDIT_LIMIT)]
    limit: u32,
    #[arg(long)]
    service: Option<String>,
    #[arg(long)]
    decision: Option<String>,
    #[arg(long)]
    from: Option<u64>,
    #[arg(long)]
    to: Option<u64>,
}

#[derive(Debug, Subcommand)]
enum AuditCommands {
    /// Export audit entries as CSV to stdout or file
    Export(AuditExportArgs),
}

#[derive(Debug, Args)]
struct AuditExportArgs {
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    service: Option<String>,
    #[arg(long)]
    decision: Option<String>,
    #[arg(long)]
    from: Option<u64>,
    #[arg(long)]
    to: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PidFile {
    pid: i32,
    started_at_unix: i64,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorCheckResult {
    check: String,
    ok: bool,
    detail: String,
}

struct PidFileGuard {
    path: PathBuf,
}

impl PidFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        None | Some(Commands::Start) => cmd_start(cli.config).await,
        Some(Commands::Stop) => cmd_stop().await,
        Some(Commands::Init(args)) => cmd_init(cli.config, args).await,
        Some(Commands::Status) => cmd_status().await,
        Some(Commands::Doctor(args)) => cmd_doctor(args).await,
        Some(Commands::AddKey(args)) => cmd_add_key(args).await,
        Some(Commands::ListKeys) => cmd_list_keys().await,
        Some(Commands::RemoveKey(args)) => cmd_remove_key(args).await,
        Some(Commands::Backup(args)) => cmd_backup(args).await,
        Some(Commands::Restore(args)) => cmd_restore(args).await,
        Some(Commands::Policy { command }) => match command {
            PolicyCommands::Edit => cmd_policy_edit(cli.config),
        },
        Some(Commands::Service { command }) => match command {
            ServiceCommands::Install(args) => cmd_service_install(args),
            ServiceCommands::Uninstall(args) => cmd_service_uninstall(args),
        },
        Some(Commands::Firewall { command }) => match command {
            FirewallCommands::Enable(args) => cmd_firewall_enable(args),
            FirewallCommands::Disable(args) => cmd_firewall_disable(args),
        },
        Some(Commands::Audit(args)) => match args.command {
            Some(AuditCommands::Export(export)) => cmd_audit_export(export).await,
            None => cmd_audit_list(args).await,
        },
    };

    if let Err(e) = result {
        eprintln!("[fishnet] {e}");
        std::process::exit(1);
    }
}

async fn cmd_start(explicit_config: Option<PathBuf>) -> Result<(), String> {
    if let Some(existing) = read_pid_file()? {
        if process_alive(existing.pid) {
            return Err(format!(
                "already running (pid: {}). use `fishnet stop` first",
                existing.pid
            ));
        }
        remove_pid_file()?;
    }

    run_server(explicit_config).await
}

async fn cmd_stop() -> Result<(), String> {
    let Some(pid_file) = read_pid_file()? else {
        println!("Fishnet is not running.");
        return Ok(());
    };

    if !process_alive(pid_file.pid) {
        remove_pid_file()?;
        println!("Fishnet is not running (stale pid file removed).");
        return Ok(());
    }

    send_terminate_signal(pid_file.pid)?;

    for _ in 0..100 {
        if !process_alive(pid_file.pid) {
            remove_pid_file()?;
            println!("Fishnet stopped.");
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    Err(format!(
        "timed out waiting for process {} to stop",
        pid_file.pid
    ))
}

async fn cmd_init(explicit_config: Option<PathBuf>, args: InitArgs) -> Result<(), String> {
    let master_password = match args.master_password {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => {
            let first = prompt_input("Master password")?;
            let confirm = prompt_input("Confirm master password")?;
            if first != confirm {
                return Err("master password confirmation does not match".to_string());
            }
            if first.trim().is_empty() {
                return Err("master password cannot be empty".to_string());
            }
            first
        }
    };

    if master_password.len() < 8 {
        eprintln!(
            "[fishnet] warning: master password length is short; consider at least 12+ characters"
        );
    }

    let store = open_credential_store(vault_db_path()?, Some(&master_password))?;
    maybe_store_derived_key_in_keychain(&store, args.store_derived_key_in_keychain);

    let first_service = normalize_or_prompt(args.first_service, "First API service")?;
    let first_name = normalize_or_prompt(args.first_name, "First credential name")?;
    let first_key = normalize_or_prompt(args.first_key, "First API key")?;
    store
        .add_credential(&first_service, &first_name, &first_key)
        .await
        .map_err(|e| format!("failed to store first credential: {e}"))?;

    let config_path = resolve_config_path(explicit_config.as_deref())
        .or_else(default_config_path)
        .ok_or_else(|| "could not determine config path".to_string())?;
    let mut cfg = if config_path.exists() {
        load_config(Some(&config_path)).map_err(|e| format!("failed to load config: {e}"))?
    } else {
        fishnet_types::config::FishnetConfig::default()
    };

    let budget = match args.daily_budget_usd {
        Some(v) => v,
        None => {
            let default = cfg.llm.daily_budget_usd;
            prompt_f64_with_default("Daily LLM budget (USD)", default)?
        }
    };
    let rate_limit = match args.rate_limit_per_minute {
        Some(v) => v,
        None => {
            let default = cfg.llm.rate_limit_per_minute;
            prompt_u32_with_default("Rate limit per minute", default)?
        }
    };

    cfg.llm.daily_budget_usd = budget;
    cfg.llm.rate_limit_per_minute = rate_limit;
    cfg.validate()?;
    save_config(&config_path, &cfg).map_err(|e| format!("failed to save config: {e}"))?;

    ensure_local_data_dir_permissions()?;

    let system_setup_commands = default_system_user_setup_commands()?;
    execute_plan(
        "System user + permissions setup",
        &system_setup_commands,
        args.apply_system,
    )?;

    println!("Fishnet init complete.");
    println!(
        "Stored first credential '{}:{}', config written to {}",
        first_service,
        first_name,
        config_path.display()
    );
    println!("Run: fishnet start");
    Ok(())
}

async fn cmd_doctor(args: DoctorArgs) -> Result<(), String> {
    let mut checks = Vec::<DoctorCheckResult>::new();

    let running = read_pid_file()?
        .as_ref()
        .is_some_and(|p| process_alive(p.pid));
    checks.push(DoctorCheckResult {
        check: "fishnet_running".to_string(),
        ok: running,
        detail: if running {
            "process appears to be running".to_string()
        } else {
            "no active fishnet pid detected".to_string()
        },
    });

    let creds_check = match open_default_credential_store() {
        Ok(store) => match store.list_credentials().await {
            Ok(creds) => DoctorCheckResult {
                check: "credentials_present".to_string(),
                ok: !creds.is_empty(),
                detail: format!("{} credential(s) in vault", creds.len()),
            },
            Err(e) => DoctorCheckResult {
                check: "credentials_present".to_string(),
                ok: false,
                detail: format!("failed to list credentials: {e}"),
            },
        },
        Err(e) => DoctorCheckResult {
            check: "credentials_present".to_string(),
            ok: false,
            detail: format!("failed to unlock vault: {e}"),
        },
    };
    checks.push(creds_check);

    let openai_base = std::env::var("OPENAI_BASE_URL").ok();
    let openai_base_ok = openai_base
        .as_deref()
        .is_some_and(is_valid_local_openai_base_url);
    checks.push(DoctorCheckResult {
        check: "openai_base_url".to_string(),
        ok: openai_base_ok,
        detail: match openai_base {
            Some(v) => format!("OPENAI_BASE_URL={v}"),
            None => "OPENAI_BASE_URL is not set".to_string(),
        },
    });

    let anthropic_base = std::env::var("ANTHROPIC_BASE_URL").ok();
    let anthropic_base_ok = anthropic_base
        .as_deref()
        .is_some_and(is_valid_local_anthropic_base_url);
    checks.push(DoctorCheckResult {
        check: "anthropic_base_url".to_string(),
        ok: anthropic_base_ok,
        detail: match anthropic_base {
            Some(v) => format!("ANTHROPIC_BASE_URL={v}"),
            None => "ANTHROPIC_BASE_URL is not set".to_string(),
        },
    });

    let upstream_check = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(client) => {
            let req = client.get("https://api.openai.com/v1/models").send().await;
            match req {
                Ok(resp) => DoctorCheckResult {
                    check: "upstream_reachable".to_string(),
                    ok: true,
                    detail: format!("openai reachable (status {})", resp.status()),
                },
                Err(e) => DoctorCheckResult {
                    check: "upstream_reachable".to_string(),
                    ok: false,
                    detail: format!("failed to reach api.openai.com: {e}"),
                },
            }
        }
        Err(e) => DoctorCheckResult {
            check: "upstream_reachable".to_string(),
            ok: false,
            detail: format!("failed to build http client: {e}"),
        },
    };
    checks.push(upstream_check);

    let failed = checks.iter().filter(|c| !c.ok).count();

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": failed == 0,
                "failed": failed,
                "checks": checks,
            }))
            .map_err(|e| format!("failed to render doctor json: {e}"))?
        );
    } else {
        println!("Fishnet doctor report:");
        for check in &checks {
            println!(
                "  [{}] {:<24} {}",
                if check.ok { "PASS" } else { "FAIL" },
                check.check,
                check.detail
            );
        }
    }

    if failed > 0 {
        Err(format!("doctor found {failed} failing check(s)"))
    } else {
        Ok(())
    }
}

async fn cmd_backup(args: BackupArgs) -> Result<(), String> {
    let src = vault_db_path()?;
    if !src.exists() {
        return Err(format!("vault database not found at {}", src.display()));
    }

    let dst = match args.output {
        Some(path) => path,
        None => default_backup_path()?,
    };
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("failed to create backup dir: {e}"))?;
    }

    std::fs::copy(&src, &dst).map_err(|e| format!("failed to copy vault backup: {e}"))?;
    set_owner_only_file_permissions(&dst)?;

    println!("Backup written to {}", dst.display());
    Ok(())
}

async fn cmd_restore(args: RestoreArgs) -> Result<(), String> {
    if read_pid_file()?
        .as_ref()
        .is_some_and(|p| process_alive(p.pid))
    {
        return Err("fishnet appears to be running; stop it before restore".to_string());
    }

    if !args.file.exists() {
        return Err(format!(
            "backup file does not exist: {}",
            args.file.display()
        ));
    }

    if !args.yes
        && !prompt_confirm(&format!(
            "Restore vault from '{}' and overwrite current vault? [y/N]",
            args.file.display()
        ))?
    {
        println!("Aborted.");
        return Ok(());
    }

    let dst = vault_db_path()?;
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("failed to create vault dir: {e}"))?;
    }

    if dst.exists() {
        std::fs::remove_file(&dst)
            .map_err(|e| format!("failed to remove existing vault db: {e}"))?;
    }

    std::fs::copy(&args.file, &dst).map_err(|e| format!("failed to restore vault backup: {e}"))?;
    set_owner_only_file_permissions(&dst)?;

    println!("Vault restored from {}", args.file.display());
    Ok(())
}

fn cmd_service_install(args: ServiceInstallArgs) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("failed to resolve current exe: {e}"))?;
    let (unit_path, unit_contents, commands) = service_install_plan(&exe)?;

    if args.apply {
        if let Some(parent) = unit_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create service dir: {e}"))?;
        }
        std::fs::write(&unit_path, &unit_contents)
            .map_err(|e| format!("failed to write service unit: {e}"))?;
        for cmd in &commands {
            run_shell(cmd)?;
        }
        println!("Service installed at {}", unit_path.display());
    } else {
        println!("Dry-run: service install plan");
        println!("  unit path: {}", unit_path.display());
        for line in unit_contents.lines() {
            println!("    {line}");
        }
        println!("  apply commands:");
        for cmd in &commands {
            println!("    {cmd}");
        }
        println!("Use --apply to execute.");
    }

    Ok(())
}

fn cmd_service_uninstall(args: ServiceUninstallArgs) -> Result<(), String> {
    let (unit_path, commands) = service_uninstall_plan()?;

    if args.apply {
        for cmd in &commands {
            run_shell(cmd)?;
        }
        if unit_path.exists() {
            std::fs::remove_file(&unit_path)
                .map_err(|e| format!("failed to remove service unit: {e}"))?;
        }
        println!("Service uninstalled.");
    } else {
        println!("Dry-run: service uninstall plan");
        println!("  unit path: {}", unit_path.display());
        for cmd in &commands {
            println!("    {cmd}");
        }
        println!("Use --apply to execute.");
    }

    Ok(())
}

fn cmd_firewall_enable(args: FirewallArgs) -> Result<(), String> {
    let agent_user = args
        .agent_user
        .or_else(|| std::env::var("USER").ok())
        .ok_or_else(|| "agent user is required (--agent-user)".to_string())?;
    validate_unix_username(&agent_user)?;
    let commands = firewall_enable_commands(&agent_user)?;

    execute_plan("Firewall enable", &commands, args.apply)?;
    Ok(())
}

fn cmd_firewall_disable(args: FirewallArgs) -> Result<(), String> {
    let agent_user = args
        .agent_user
        .or_else(|| std::env::var("USER").ok())
        .ok_or_else(|| "agent user is required (--agent-user)".to_string())?;
    validate_unix_username(&agent_user)?;
    let commands = firewall_disable_commands(&agent_user)?;

    execute_plan("Firewall disable", &commands, args.apply)?;
    Ok(())
}

fn validate_unix_username(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 32 {
        return Err(format!(
            "invalid unix username '{}': must be 1-32 characters",
            name
        ));
    }
    let first = name.as_bytes()[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return Err(format!(
            "invalid unix username '{}': must start with a letter or underscore",
            name
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(format!(
            "invalid unix username '{}': only alphanumeric, underscore, and hyphen are allowed",
            name
        ));
    }
    Ok(())
}

async fn cmd_status() -> Result<(), String> {
    let pid_info = read_pid_file()?;
    let running = pid_info.as_ref().is_some_and(|p| process_alive(p.pid));

    let uptime = if running {
        pid_info
            .as_ref()
            .and_then(|p| format_uptime_from_unix(p.started_at_unix))
            .unwrap_or_else(|| "unknown".to_string())
    } else {
        "n/a".to_string()
    };

    let mut spend_map: BTreeMap<String, f64> = BTreeMap::new();
    let mut request_map: BTreeMap<String, u64> = BTreeMap::new();

    if let Ok(spend_store) = open_default_spend_store()
        && let Ok(rows) = spend_store.today_service_totals().await
    {
        for row in rows {
            spend_map.insert(row.service.clone(), row.cost_usd);
            request_map.entry(row.service).or_insert(0);
        }
    }

    if let Ok(audit_store) = open_default_audit_store()
        && let Ok(rows) = audit_store.today_request_counts().await
    {
        for (service, count) in rows {
            request_map.insert(service.clone(), count);
            spend_map.entry(service).or_insert(0.0);
        }
    }

    let (active_alerts, critical_alerts, warning_alerts) = if let Ok(alert_store) =
        open_default_alert_store()
        && let Ok(alerts) = alert_store.list().await
    {
        let active = alerts
            .into_iter()
            .filter(|a| !a.dismissed)
            .collect::<Vec<_>>();
        let critical = active
            .iter()
            .filter(|a| a.severity == AlertSeverity::Critical)
            .count();
        let warning = active
            .iter()
            .filter(|a| a.severity == AlertSeverity::Warning)
            .count();
        (active.len(), critical, warning)
    } else {
        (0usize, 0usize, 0usize)
    };

    println!("Status: {}", if running { "running" } else { "stopped" });
    if running {
        if let Some(pid) = pid_info.as_ref().map(|p| p.pid) {
            println!("PID: {pid}");
        }
    }
    println!("Uptime: {uptime}");
    println!(
        "Active alerts: {} (critical: {}, warning: {})",
        active_alerts, critical_alerts, warning_alerts
    );

    if spend_map.is_empty() {
        println!("Today's spend: none");
    } else {
        println!("Today's spend (USD):");
        for (service, amount) in &spend_map {
            println!("  {:<16} ${:.6}", service, amount);
        }
    }

    if request_map.is_empty() {
        println!("Today's requests: none");
    } else {
        println!("Today's requests:");
        for (service, count) in &request_map {
            println!("  {:<16} {}", service, count);
        }
    }

    Ok(())
}

async fn cmd_add_key(args: AddKeyArgs) -> Result<(), String> {
    let service = normalize_or_prompt(args.service, "Service")?;
    let name = normalize_or_prompt(args.name, "Credential name")?;
    let key = normalize_or_prompt(args.key, "API key")?;

    let store = open_default_credential_store()?;
    let created = store
        .add_credential(&service, &name, &key)
        .await
        .map_err(|e| format!("failed to add credential: {e}"))?;

    println!(
        "Stored credential '{}' for service '{}' (id: {}).",
        created.name, created.service, created.id
    );

    Ok(())
}

async fn cmd_list_keys() -> Result<(), String> {
    let store = open_default_credential_store()?;
    let mut creds = store
        .list_credentials()
        .await
        .map_err(|e| format!("failed to list credentials: {e}"))?;

    creds.sort_by(|a, b| {
        a.service
            .cmp(&b.service)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| b.created_at.cmp(&a.created_at))
    });

    if creds.is_empty() {
        println!("No credentials stored.");
        return Ok(());
    }

    println!("{: <20} {: <24} {: <12}", "SERVICE", "NAME", "LAST_USED");
    for c in creds {
        let last_used = c
            .last_used_at
            .map(format_unix_secs)
            .unwrap_or_else(|| "never".to_string());
        println!("{: <20} {: <24} {: <12}", c.service, c.name, last_used);
    }

    Ok(())
}

async fn cmd_remove_key(args: RemoveKeyArgs) -> Result<(), String> {
    let store = open_default_credential_store()?;
    let creds = store
        .list_credentials()
        .await
        .map_err(|e| format!("failed to list credentials: {e}"))?;

    let matches: Vec<CredentialMetadata> = creds
        .into_iter()
        .filter(|c| c.name == args.name)
        .filter(|c| {
            args.service
                .as_ref()
                .is_none_or(|service| service == &c.service)
        })
        .collect();

    let selected = match matches.as_slice() {
        [] => {
            return Err(match args.service {
                Some(ref service) => {
                    format!(
                        "no credential named '{}' for service '{}'",
                        args.name, service
                    )
                }
                None => format!("no credential named '{}'", args.name),
            });
        }
        [single] => single,
        many => {
            let services = many
                .iter()
                .map(|c| c.service.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "multiple credentials named '{}' found across services: {}. re-run with --service",
                args.name, services
            ));
        }
    };

    if !args.yes {
        let confirm = prompt_confirm(&format!(
            "Remove credential '{}' (service: {})? [y/N]",
            selected.name, selected.service
        ))?;
        if !confirm {
            println!("Aborted.");
            return Ok(());
        }
    }

    let deleted = store
        .delete_credential(&selected.id)
        .await
        .map_err(|e| format!("failed to delete credential: {e}"))?;

    if deleted {
        println!(
            "Removed credential '{}' for service '{}'.",
            selected.name, selected.service
        );
        Ok(())
    } else {
        Err("credential not found during deletion".to_string())
    }
}

fn cmd_policy_edit(explicit_config: Option<PathBuf>) -> Result<(), String> {
    let config_path = resolve_config_path(explicit_config.as_deref())
        .or_else(default_config_path)
        .ok_or_else(|| "could not determine config path".to_string())?;

    if !config_path.exists() {
        let mut default_cfg = fishnet_types::config::FishnetConfig::default();
        default_cfg.validate()?;
        save_config(&config_path, &default_cfg)
            .map_err(|e| format!("failed to create default config: {e}"))?;
    }

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let cmd = format!("{} {}", editor, shell_quote_path(&config_path));
    let status = std::process::Command::new("/bin/sh")
        .arg("-lc")
        .arg(cmd)
        .status()
        .map_err(|e| format!("failed to launch editor: {e}"))?;

    if !status.success() {
        return Err(format!("editor exited with status: {status}"));
    }

    println!("Policy file updated: {}", config_path.display());
    Ok(())
}

async fn cmd_audit_list(args: AuditArgs) -> Result<(), String> {
    let store = open_default_audit_store()?;
    let filter = AuditQueryFilter {
        from: args.from,
        to: args.to,
        service: args.service,
        decision: args.decision,
        page: 1,
        page_size: args.limit.clamp(1, 200),
    };

    let (entries, total) = store
        .query(&filter)
        .await
        .map_err(|e| format!("failed to query audit log: {e}"))?;

    if entries.is_empty() {
        println!("No audit entries found.");
        return Ok(());
    }

    println!("Showing {} of {} audit entries", entries.len(), total);
    println!(
        "{:<16} {:<12} {:<8} {:<10} {:<10} ACTION",
        "TIME", "SERVICE", "DECISION", "COST_USD", "REASON"
    );

    for entry in entries {
        let time = format_unix_millis(entry.timestamp);
        let cost = entry
            .cost_usd
            .map(|v| format!("{v:.6}"))
            .unwrap_or_else(|| "-".to_string());
        let reason = entry
            .reason
            .as_deref()
            .map(truncate_reason)
            .unwrap_or("-".to_string());
        println!(
            "{:<16} {:<12} {:<8} {:<10} {:<10} {}",
            time,
            truncate_field(&entry.service, 12),
            truncate_field(&entry.decision, 8),
            cost,
            reason,
            entry.action
        );
    }

    Ok(())
}

async fn cmd_audit_export(args: AuditExportArgs) -> Result<(), String> {
    let store = open_default_audit_store()?;
    let entries = store
        .export(args.from, args.to, args.service, args.decision)
        .await
        .map_err(|e| format!("failed to export audit log: {e}"))?;

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
            .map(|h| audit::merkle::h256_to_hex(&h))
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
            csv_cell(&audit::merkle::h256_to_hex(&entry.policy_version_hash)),
            csv_cell(&audit::merkle::h256_to_hex(&entry.intent_hash)),
            csv_cell(&permit),
            csv_cell(&audit::merkle::h256_to_hex(&entry.merkle_root)),
        ));
    }

    if let Some(path) = args.output {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create export directory: {e}"))?;
        }
        std::fs::write(&path, csv).map_err(|e| format!("failed to write export file: {e}"))?;
        println!("Audit CSV written to {}", path.display());
    } else {
        print!("{csv}");
    }

    Ok(())
}

async fn run_server(explicit_config: Option<PathBuf>) -> Result<(), String> {
    let config_path = resolve_config_path(explicit_config.as_deref());

    #[cfg(not(feature = "dev-seed"))]
    let config = match load_config(config_path.as_deref()) {
        Ok(c) => {
            match &config_path {
                Some(p) => eprintln!("[fishnet] config loaded from {}", p.display()),
                None => eprintln!("[fishnet] no config file found, using defaults"),
            }
            c
        }
        Err(e) => {
            return Err(format!("fatal: {e}"));
        }
    };

    #[cfg(feature = "dev-seed")]
    let config = {
        eprintln!("[fishnet] dev-seed: overriding config with dev defaults (anvil chain 31337)");
        fishnet_server::seed::dev_config()
    };

    let (http_client, http_clients_by_service) = build_upstream_http_clients(&config.http)?;

    let load_baselines = !config.llm.prompt_drift.reset_baseline_on_restart;

    let (config_tx, config_rx) = config_channel(config);

    let config_path_for_state = config_path
        .clone()
        .or_else(default_config_path)
        .unwrap_or_else(|| PathBuf::from(fishnet_server::constants::CONFIG_FILE));
    let _watcher_guard = config_path
        .clone()
        .map(|path| spawn_config_watcher(path, config_tx.clone()));

    let baseline_store = Arc::new(match BaselineStore::default_path() {
        Some(path) => BaselineStore::with_persistence(path, load_baselines),
        None => {
            eprintln!(
                "[fishnet] could not determine fishnet data directory, baselines will not be persisted"
            );
            BaselineStore::new()
        }
    });

    let spend_store = Arc::new(open_default_spend_store()?);
    let alert_store = Arc::new(open_default_alert_store()?);
    let audit_store = Arc::new(open_default_audit_store()?);

    let credential_store = Arc::new(
        open_default_credential_store()
            .map_err(|e| format!("failed to open vault database: {e}"))?,
    );

    #[cfg(feature = "dev-seed")]
    let signer: Arc<dyn SignerTrait> = {
        let s = fishnet_server::seed::dev_signer();
        eprintln!(
            "[fishnet] dev-seed: signer initialized with anvil account #0 (address: {})",
            s.status().address
        );
        Arc::new(s)
    };
    #[cfg(not(feature = "dev-seed"))]
    let signer: Arc<dyn SignerTrait> = {
        let s = StubSigner::new();
        eprintln!(
            "[fishnet] signer initialized (mode: stub-secp256k1, address: {})",
            s.status().address
        );
        Arc::new(s)
    };

    let state = AppState::new(
        Arc::new(FilePasswordStore::new(
            FilePasswordStore::default_path().ok_or_else(|| {
                "could not determine fishnet data directory for auth file".to_string()
            })?,
        )),
        Arc::new(SessionStore::new()),
        Arc::new(LoginRateLimiter::new()),
        Arc::new(ProxyRateLimiter::new()),
        config_tx,
        config_rx,
        config_path_for_state,
        alert_store,
        audit_store,
        baseline_store.clone(),
        spend_store,
        credential_store,
        Arc::new(tokio::sync::Mutex::new(())),
        http_client,
        http_clients_by_service,
        Arc::new(tokio::sync::Mutex::new(AnomalyTracker::default())),
        Arc::new(OnchainStore::new()),
        signer,
        std::time::Instant::now(),
    );

    spawn_baseline_config_watcher(state.config_rx.clone(), baseline_store);

    {
        let retention_days = state.config().alerts.retention_days;
        if let Err(e) = state.alert_store.cleanup(retention_days).await {
            eprintln!("[fishnet] startup alert cleanup failed: {e}");
        }
    }

    #[cfg(feature = "dev-seed")]
    fishnet_server::seed::run(&state).await;

    let app = create_router(state);

    let host = std::env::var(fishnet_server::constants::ENV_FISHNET_HOST)
        .unwrap_or_else(|_| fishnet_server::constants::DEFAULT_HOST.into());
    let port = match std::env::var(fishnet_server::constants::ENV_FISHNET_PORT) {
        Ok(raw) => match raw.parse::<u16>() {
            Ok(port) => port,
            Err(e) => {
                return Err(format!(
                    "fatal: invalid {}='{}': {e}",
                    fishnet_server::constants::ENV_FISHNET_PORT,
                    raw
                ));
            }
        },
        Err(_) => fishnet_server::constants::DEFAULT_PORT,
    };
    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("failed to bind {addr}: {e}"))?;

    let pid_path = pid_file_path()?;
    write_pid_file(std::process::id() as i32)?;
    let _pid_guard = PidFileGuard::new(pid_path);

    eprintln!("[fishnet] listening on http://{addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| format!("server error: {e}"))?;

    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = signal(SignalKind::terminate()).ok();
        let mut sigint = signal(SignalKind::interrupt()).ok();

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                if let Some(sig) = sigterm.as_mut() {
                    sig.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
            _ = async {
                if let Some(sig) = sigint.as_mut() {
                    sig.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn open_default_spend_store() -> Result<SpendStore, String> {
    let path = SpendStore::default_path().ok_or_else(|| {
        "could not determine fishnet data directory for spend database".to_string()
    })?;
    SpendStore::open(path.clone()).map_err(|e| format!("failed to open spend database: {e}"))
}

fn open_default_alert_store() -> Result<AlertStore, String> {
    let path = AlertStore::default_path().ok_or_else(|| {
        "could not determine fishnet data directory for alerts database".to_string()
    })?;
    AlertStore::open(path.clone()).map_err(|e| format!("failed to open alerts database: {e}"))
}

fn open_default_audit_store() -> Result<AuditStore, String> {
    let path = AuditStore::default_path().ok_or_else(|| {
        "could not determine fishnet data directory for audit database".to_string()
    })?;
    AuditStore::open(path.clone()).map_err(|e| format!("failed to open audit database: {e}"))
}

fn open_default_credential_store() -> Result<CredentialStore, String> {
    let path = CredentialStore::default_path().ok_or_else(|| {
        "could not determine fishnet data directory for vault database".to_string()
    })?;
    open_credential_store(path, None)
}

fn ensure_local_data_dir_permissions() -> Result<(), String> {
    let dir = fishnet_server::constants::default_data_dir()
        .ok_or_else(|| "could not determine fishnet data directory".to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create data dir: {e}"))?;
    set_owner_only_dir_permissions(&dir)
}

fn default_system_user_setup_commands() -> Result<Vec<String>, String> {
    #[cfg(target_os = "macos")]
    {
        let cmds = vec![
            "sudo dscl . -create /Users/_fishnet".to_string(),
            "sudo dscl . -create /Users/_fishnet UserShell /usr/bin/false".to_string(),
            "sudo dscl . -create /Users/_fishnet NFSHomeDirectory /var/empty".to_string(),
            "sudo mkdir -p '/Library/Application Support/Fishnet'".to_string(),
            "sudo chown _fishnet:wheel '/Library/Application Support/Fishnet'".to_string(),
            "sudo chmod 700 '/Library/Application Support/Fishnet'".to_string(),
        ];
        return Ok(cmds);
    }

    #[cfg(target_os = "linux")]
    {
        let cmds = vec![
            "sudo useradd -r -s /bin/false fishnet".to_string(),
            "sudo mkdir -p /var/lib/fishnet".to_string(),
            "sudo chown fishnet:fishnet /var/lib/fishnet".to_string(),
            "sudo chmod 700 /var/lib/fishnet".to_string(),
        ];
        return Ok(cmds);
    }

    #[allow(unreachable_code)]
    Err("system user setup is not supported on this OS".to_string())
}

fn execute_plan(title: &str, commands: &[String], apply: bool) -> Result<(), String> {
    if commands.is_empty() {
        println!("{title}: no actions required.");
        return Ok(());
    }

    if apply {
        println!("{title}: applying {} command(s)", commands.len());
        for cmd in commands {
            run_shell(cmd)?;
        }
        println!("{title}: complete.");
    } else {
        println!("{title}: dry-run");
        for cmd in commands {
            println!("  {cmd}");
        }
        println!("Re-run with --apply (or --apply-system) to execute.");
    }

    Ok(())
}

fn build_upstream_http_clients(
    config: &fishnet_types::config::HttpClientConfig,
) -> Result<(reqwest::Client, HashMap<String, reqwest::Client>), String> {
    let default_client = build_upstream_http_client(config, config.pool_max_idle_per_host)?;
    let mut clients_by_service = HashMap::new();
    for (service, pool_size) in &config.upstream_pool_max_idle_per_host {
        let client = build_upstream_http_client(config, *pool_size)?;
        clients_by_service.insert(service.clone(), client);
    }
    Ok((default_client, clients_by_service))
}

fn build_upstream_http_client(
    config: &fishnet_types::config::HttpClientConfig,
    pool_max_idle_per_host: usize,
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_millis(config.connect_timeout_ms))
        .pool_idle_timeout(std::time::Duration::from_secs(
            config.pool_idle_timeout_secs,
        ))
        .pool_max_idle_per_host(pool_max_idle_per_host);

    if config.request_timeout_ms > 0 {
        builder = builder.timeout(std::time::Duration::from_millis(config.request_timeout_ms));
    }

    builder
        .build()
        .map_err(|e| format!("failed to build upstream HTTP client: {e}"))
}

fn expected_fishnet_port() -> u16 {
    std::env::var(fishnet_server::constants::ENV_FISHNET_PORT)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fishnet_server::constants::DEFAULT_PORT)
}

fn is_valid_local_base_url(value: &str, suffix: &str) -> bool {
    let port = expected_fishnet_port();
    let trimmed = value.trim_end_matches('/');
    trimmed == format!("http://localhost:{port}{suffix}")
        || trimmed == format!("http://127.0.0.1:{port}{suffix}")
}

fn is_valid_local_openai_base_url(value: &str) -> bool {
    is_valid_local_base_url(value, "/proxy/openai")
}

fn is_valid_local_anthropic_base_url(value: &str) -> bool {
    is_valid_local_base_url(value, "/proxy/anthropic")
}

fn prompt_f64_with_default(prompt: &str, default: f64) -> Result<f64, String> {
    let input = prompt_input(&format!("{prompt} [{default}]"))?;
    if input.trim().is_empty() {
        return Ok(default);
    }
    let parsed = input
        .trim()
        .parse::<f64>()
        .map_err(|e| format!("invalid number for {prompt}: {e}"))?;
    if !parsed.is_finite() || parsed < 0.0 {
        return Err(format!("{prompt} must be a non-negative finite number"));
    }
    Ok(parsed)
}

fn prompt_u32_with_default(prompt: &str, default: u32) -> Result<u32, String> {
    let input = prompt_input(&format!("{prompt} [{default}]"))?;
    if input.trim().is_empty() {
        return Ok(default);
    }
    input
        .trim()
        .parse::<u32>()
        .map_err(|e| format!("invalid integer for {prompt}: {e}"))
}

fn vault_db_path() -> Result<PathBuf, String> {
    CredentialStore::default_path()
        .ok_or_else(|| "could not determine fishnet data directory for vault database".to_string())
}

fn default_backup_path() -> Result<PathBuf, String> {
    let mut path = fishnet_server::constants::default_data_dir()
        .ok_or_else(|| "could not determine fishnet data directory".to_string())?;
    path.push(BACKUP_DIR_NAME);
    let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    path.push(format!("vault-{ts}.db.bak"));
    Ok(path)
}

fn set_owner_only_dir_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(fishnet_server::constants::DATA_DIR_MODE),
        )
        .map_err(|e| format!("failed to chmod dir '{}': {e}", path.display()))?;
    }
    Ok(())
}

fn set_owner_only_file_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(fishnet_server::constants::AUTH_FILE_MODE),
        )
        .map_err(|e| format!("failed to chmod file '{}': {e}", path.display()))?;
    }
    Ok(())
}

fn service_install_plan(exe: &Path) -> Result<(PathBuf, String, Vec<String>), String> {
    #[cfg(target_os = "macos")]
    {
        let mut path =
            dirs::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;
        path.push("Library/LaunchAgents");
        path.push(format!("{LAUNCH_AGENT_LABEL}.plist"));
        fn escape_xml(s: &str) -> String {
            s.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&apos;")
        }
        let escaped_exe = escape_xml(&exe.to_string_lossy());
        let contents = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>{LAUNCH_AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
      <string>{escaped_exe}</string>
      <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
  </dict>
</plist>
"#
        );
        let commands = vec![
            format!(
                "launchctl unload -w {} >/dev/null 2>&1 || true",
                shell_quote_path(&path)
            ),
            format!("launchctl load -w {}", shell_quote_path(&path)),
        ];
        return Ok((path, contents, commands));
    }

    #[cfg(target_os = "linux")]
    {
        let exe_quoted = shell_quote_path(exe);
        let mut path =
            dirs::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;
        path.push(".config/systemd/user");
        path.push(format!("{SERVICE_NAME}.service"));
        let contents = format!(
            "[Unit]\nDescription=Fishnet local security proxy\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={} start\nRestart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=default.target\n",
            exe_quoted
        );
        let commands = vec![
            "systemctl --user daemon-reload".to_string(),
            format!("systemctl --user enable --now {SERVICE_NAME}.service"),
        ];
        return Ok((path, contents, commands));
    }

    #[allow(unreachable_code)]
    Err("service install is not supported on this OS".to_string())
}

fn service_uninstall_plan() -> Result<(PathBuf, Vec<String>), String> {
    #[cfg(target_os = "macos")]
    {
        let mut path =
            dirs::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;
        path.push("Library/LaunchAgents");
        path.push(format!("{LAUNCH_AGENT_LABEL}.plist"));
        let commands = vec![format!(
            "launchctl unload -w {} >/dev/null 2>&1 || true",
            shell_quote_path(&path)
        )];
        return Ok((path, commands));
    }

    #[cfg(target_os = "linux")]
    {
        let mut path =
            dirs::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;
        path.push(".config/systemd/user");
        path.push(format!("{SERVICE_NAME}.service"));
        let commands = vec![
            format!("systemctl --user disable --now {SERVICE_NAME}.service || true"),
            "systemctl --user daemon-reload".to_string(),
        ];
        return Ok((path, commands));
    }

    #[allow(unreachable_code)]
    Err("service uninstall is not supported on this OS".to_string())
}

fn firewall_enable_commands(agent_user: &str) -> Result<Vec<String>, String> {
    #[cfg(target_os = "macos")]
    {
        let commands = vec![
            format!(
                "echo 'block drop out quick user {} to any\\npass out quick on lo0 user {} to any' | sudo tee /etc/pf.anchors/com.fishnet.localonly >/dev/null",
                agent_user, agent_user
            ),
            "grep -q 'anchor \"com.fishnet.localonly\"' /etc/pf.conf || echo 'anchor \"com.fishnet.localonly\"' | sudo tee -a /etc/pf.conf >/dev/null".to_string(),
            "sudo pfctl -f /etc/pf.conf".to_string(),
            "sudo pfctl -e".to_string(),
        ];
        return Ok(commands);
    }

    #[cfg(target_os = "linux")]
    {
        let commands = vec![format!(
            "sudo iptables -C OUTPUT -m owner --uid-owner {} ! -o lo -j REJECT 2>/dev/null || sudo iptables -A OUTPUT -m owner --uid-owner {} ! -o lo -j REJECT",
            agent_user, agent_user
        )];
        return Ok(commands);
    }

    #[allow(unreachable_code)]
    Err("firewall command is not supported on this OS".to_string())
}

fn firewall_disable_commands(agent_user: &str) -> Result<Vec<String>, String> {
    #[cfg(target_os = "macos")]
    {
        let _ = agent_user;
        let commands = vec![
            "sudo rm -f /etc/pf.anchors/com.fishnet.localonly".to_string(),
            "sudo sed -i.bak '/anchor \"com.fishnet.localonly\"/d' /etc/pf.conf".to_string(),
            "sudo pfctl -f /etc/pf.conf".to_string(),
            "sudo pfctl -d || true".to_string(),
        ];
        return Ok(commands);
    }

    #[cfg(target_os = "linux")]
    {
        let commands = vec![format!(
            "sudo iptables -D OUTPUT -m owner --uid-owner {} ! -o lo -j REJECT 2>/dev/null || true",
            agent_user
        )];
        return Ok(commands);
    }

    #[allow(unreachable_code)]
    Err("firewall command is not supported on this OS".to_string())
}

fn run_shell(cmd: &str) -> Result<(), String> {
    let status = std::process::Command::new("/bin/sh")
        .arg("-lc")
        .arg(cmd)
        .status()
        .map_err(|e| format!("failed to run command `{cmd}`: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed ({status}): {cmd}"))
    }
}

fn pid_file_path() -> Result<PathBuf, String> {
    let mut path = fishnet_server::constants::default_data_dir()
        .ok_or_else(|| "could not determine fishnet data directory".to_string())?;
    std::fs::create_dir_all(&path).map_err(|e| format!("failed to create fishnet dir: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(fishnet_server::constants::DATA_DIR_MODE),
        );
    }
    path.push(PID_FILE_NAME);
    Ok(path)
}

fn read_pid_file() -> Result<Option<PidFile>, String> {
    let path = pid_file_path()?;
    if !path.exists() {
        return Ok(None);
    }

    let raw =
        std::fs::read_to_string(&path).map_err(|e| format!("failed to read pid file: {e}"))?;
    let parsed = serde_json::from_str::<PidFile>(&raw)
        .map_err(|e| format!("failed to parse pid file '{}': {e}", path.display()))?;
    Ok(Some(parsed))
}

fn write_pid_file(pid: i32) -> Result<(), String> {
    let path = pid_file_path()?;
    let content = serde_json::to_string_pretty(&PidFile {
        pid,
        started_at_unix: chrono::Utc::now().timestamp(),
    })
    .map_err(|e| format!("failed to serialize pid file: {e}"))?;
    std::fs::write(&path, content).map_err(|e| format!("failed to write pid file: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(fishnet_server::constants::AUTH_FILE_MODE),
        )
        .map_err(|e| format!("failed to chmod pid file: {e}"))?;
    }

    Ok(())
}

fn remove_pid_file() -> Result<(), String> {
    let path = pid_file_path()?;
    if path.exists() {
        std::fs::remove_file(path).map_err(|e| format!("failed to remove pid file: {e}"))?;
    }
    Ok(())
}

#[cfg(unix)]
fn process_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }

    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }

    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
fn process_alive(_pid: i32) -> bool {
    false
}

#[cfg(unix)]
fn send_terminate_signal(pid: i32) -> Result<(), String> {
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    if rc == 0 {
        return Ok(());
    }

    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(format!("failed to send SIGTERM to pid {pid}: {err}"))
}

#[cfg(not(unix))]
fn send_terminate_signal(_pid: i32) -> Result<(), String> {
    Err("stop is only supported on unix targets in this build".to_string())
}

fn normalize_or_prompt(value: Option<String>, prompt: &str) -> Result<String, String> {
    match value {
        Some(v) if !v.trim().is_empty() => Ok(v.trim().to_string()),
        _ => {
            let input = prompt_input(prompt)?;
            let trimmed = input.trim().to_string();
            if trimmed.is_empty() {
                Err(format!("{prompt} cannot be empty"))
            } else {
                Ok(trimmed)
            }
        }
    }
}

fn prompt_input(prompt: &str) -> Result<String, String> {
    print!("{prompt}: ");
    io::stdout()
        .flush()
        .map_err(|e| format!("failed to flush stdout: {e}"))?;
    let mut buf = String::new();
    io::stdin()
        .read_line(&mut buf)
        .map_err(|e| format!("failed to read input: {e}"))?;
    Ok(buf.trim_end_matches(['\n', '\r']).to_string())
}

fn prompt_confirm(prompt: &str) -> Result<bool, String> {
    let response = prompt_input(prompt)?;
    let normalized = response.trim().to_ascii_lowercase();
    Ok(matches!(normalized.as_str(), "y" | "yes"))
}

fn format_uptime_from_unix(started_at_unix: i64) -> Option<String> {
    let now = chrono::Utc::now().timestamp();
    if started_at_unix <= 0 || started_at_unix > now {
        return None;
    }

    let elapsed = (now - started_at_unix) as u64;
    let hours = elapsed / 3600;
    let minutes = (elapsed % 3600) / 60;

    Some(if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    })
}

fn format_unix_secs(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .map(|dt| dt.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| ts.to_string())
}

fn format_unix_millis(ts: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ts as i64)
        .map(|dt| dt.format("%m-%d %H:%M").to_string())
        .unwrap_or_else(|| ts.to_string())
}

fn truncate_field(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let mut out: String = value.chars().take(width.saturating_sub(1)).collect();
    out.push('~');
    out
}

fn truncate_reason(value: &str) -> String {
    truncate_field(value, 10)
}

fn shell_quote_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    format!("'{}'", raw.replace('\'', "'\\''"))
}

fn csv_cell(cell: &str) -> String {
    if cell.is_empty() {
        return String::new();
    }

    let first = cell.as_bytes()[0] as char;
    let mut sanitized = if matches!(first, '=' | '+' | '-' | '@') {
        let mut prefixed = String::with_capacity(cell.len() + 1);
        prefixed.push('\'');
        prefixed.push_str(cell);
        prefixed
    } else {
        cell.to_string()
    };

    if sanitized.contains(',') || sanitized.contains('"') || sanitized.contains('\n') {
        sanitized = sanitized.replace('"', "\"\"");
        format!("\"{sanitized}\"")
    } else {
        sanitized
    }
}

fn spawn_baseline_config_watcher(
    mut config_rx: tokio::sync::watch::Receiver<Arc<fishnet_types::config::FishnetConfig>>,
    baseline_store: Arc<BaselineStore>,
) {
    let initial = config_rx.borrow().clone();
    let mut prev_hash_chars = initial.llm.prompt_drift.hash_chars;
    let mut prev_ignore_ws = initial.llm.prompt_drift.ignore_whitespace;
    let mut prev_hash_algo = initial.llm.prompt_drift.hash_algorithm;

    tokio::spawn(async move {
        while config_rx.changed().await.is_ok() {
            let config: Arc<fishnet_types::config::FishnetConfig> = config_rx.borrow().clone();
            let new_hash_chars = config.llm.prompt_drift.hash_chars;
            let new_ignore_ws = config.llm.prompt_drift.ignore_whitespace;
            let new_hash_algo = config.llm.prompt_drift.hash_algorithm;

            if new_hash_chars != prev_hash_chars
                || new_ignore_ws != prev_ignore_ws
                || new_hash_algo != prev_hash_algo
            {
                eprintln!(
                    "[fishnet] drift config changed (hash_chars: {prev_hash_chars} → {new_hash_chars}, \
                     ignore_whitespace: {prev_ignore_ws} → {new_ignore_ws}, \
                     hash_algorithm: {prev_hash_algo:?} → {new_hash_algo:?}), clearing baselines"
                );
                baseline_store.clear().await;
                prev_hash_chars = new_hash_chars;
                prev_ignore_ws = new_ignore_ws;
                prev_hash_algo = new_hash_algo;
            }
        }
    });
}

fn open_credential_store(
    path: std::path::PathBuf,
    explicit_password: Option<&str>,
) -> Result<CredentialStore, String> {
    if let Some(password) = explicit_password {
        let password = Zeroizing::new(password.to_string());
        let store = CredentialStore::open(path, password.as_str())
            .map_err(|e| format!("failed to unlock vault with master password: {e}"))?;
        return Ok(store);
    }

    if let Ok(master_password) =
        std::env::var(fishnet_server::constants::ENV_FISHNET_MASTER_PASSWORD)
    {
        unsafe {
            std::env::remove_var(fishnet_server::constants::ENV_FISHNET_MASTER_PASSWORD);
        }
        let master_password = Zeroizing::new(master_password);
        let store = CredentialStore::open(path, master_password.as_str())
            .map_err(|e| format!("failed to unlock vault with master password: {e}"))?;
        let store_in_keychain =
            env_flag_enabled(fishnet_server::constants::ENV_FISHNET_STORE_DERIVED_KEY_IN_KEYCHAIN);
        maybe_store_derived_key_in_keychain(&store, store_in_keychain);
        return Ok(store);
    }

    #[cfg(target_os = "macos")]
    {
        match read_vault_material_from_keychain() {
            Ok(Some(KeychainVaultMaterial::DerivedKey(derived_key))) => {
                match CredentialStore::open_with_derived_key(path.clone(), derived_key.as_slice()) {
                    Ok(store) => {
                        eprintln!("[fishnet] loaded vault derived key from macOS Keychain");
                        return Ok(store);
                    }
                    Err(e) => {
                        eprintln!(
                            "[fishnet] warning: keychain derived key did not unlock vault: {e}"
                        );
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!(
                    "[fishnet] warning: could not load vault key material from keychain: {e}"
                );
            }
        }
    }

    Err(format!(
        "{} is not set and no usable keychain vault key was found",
        fishnet_server::constants::ENV_FISHNET_MASTER_PASSWORD
    ))
}

#[cfg(target_os = "macos")]
const KEYCHAIN_DERIVED_KEY_PREFIX: &str = "derived_hex:v1:";

#[cfg(target_os = "macos")]
enum KeychainVaultMaterial {
    DerivedKey(Zeroizing<Vec<u8>>),
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

#[cfg(target_os = "macos")]
fn keychain_service_account() -> (String, String) {
    let service = std::env::var(fishnet_server::constants::ENV_FISHNET_KEYCHAIN_SERVICE)
        .unwrap_or_else(|_| "fishnet".to_string());
    let account = std::env::var(fishnet_server::constants::ENV_FISHNET_KEYCHAIN_ACCOUNT)
        .unwrap_or_else(|_| "vault_derived_key".to_string());
    (service, account)
}

#[cfg(target_os = "macos")]
fn maybe_store_derived_key_in_keychain(store: &CredentialStore, allow: bool) {
    if !allow {
        return;
    }

    let wrapped = format!("{KEYCHAIN_DERIVED_KEY_PREFIX}{}", store.derived_key_hex());
    match store_keychain_value(&wrapped) {
        Ok(()) => {
            eprintln!("[fishnet] vault derived key stored in macOS Keychain");
        }
        Err(e) => {
            eprintln!("[fishnet] warning: failed to store vault derived key in keychain: {e}");
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn maybe_store_derived_key_in_keychain(_store: &CredentialStore, _allow: bool) {}

#[cfg(target_os = "macos")]
fn read_vault_material_from_keychain() -> Result<Option<KeychainVaultMaterial>, String> {
    let Some(value) = read_keychain_value()? else {
        return Ok(None);
    };
    parse_keychain_material(value).map(Some)
}

#[cfg(target_os = "macos")]
fn parse_keychain_material(value: String) -> Result<KeychainVaultMaterial, String> {
    if let Some(hex_key) = value.strip_prefix(KEYCHAIN_DERIVED_KEY_PREFIX) {
        let decoded = hex::decode(hex_key)
            .map_err(|e| format!("invalid derived key encoding in keychain: {e}"))?;
        return Ok(KeychainVaultMaterial::DerivedKey(Zeroizing::new(decoded)));
    }
    Err("unsupported keychain value format; expected derived_hex:v1:<hex>".to_string())
}

#[cfg(target_os = "macos")]
fn read_keychain_value() -> Result<Option<String>, String> {
    let (service, account) = keychain_service_account();
    match get_generic_password(&service, &account) {
        Ok(bytes) => {
            let value = String::from_utf8(bytes)
                .map_err(|e| format!("invalid UTF-8 from keychain: {e}"))?;
            if value.is_empty() {
                return Ok(None);
            }
            Ok(Some(value))
        }
        Err(e) => {
            // errSecItemNotFound
            if e.code() == -25300 {
                return Ok(None);
            }
            Err(format!("failed to read macOS keychain item: {e}"))
        }
    }
}

#[cfg(target_os = "macos")]
fn store_keychain_value(value: &str) -> Result<(), String> {
    let (service, account) = keychain_service_account();
    set_generic_password(&service, &account, value.as_bytes())
        .map_err(|e| format!("failed to write macOS keychain item: {e}"))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn parse_keychain_material_derived_key_roundtrip() {
        let raw = vec![0xAB, 0xCD, 0xEF, 0x01];
        let wrapped = format!("{KEYCHAIN_DERIVED_KEY_PREFIX}{}", hex::encode(&raw));
        let parsed = parse_keychain_material(wrapped).unwrap();
        match parsed {
            KeychainVaultMaterial::DerivedKey(bytes) => {
                assert_eq!(bytes.as_slice(), raw.as_slice())
            }
        }
    }

    #[test]
    fn parse_keychain_material_invalid_hex_rejected() {
        let wrapped = format!("{KEYCHAIN_DERIVED_KEY_PREFIX}not-hex-data");
        let err = match parse_keychain_material(wrapped) {
            Ok(_) => panic!("expected invalid derived key encoding error"),
            Err(e) => e,
        };
        assert!(err.contains("invalid derived key encoding"));
    }

    #[test]
    fn parse_keychain_material_legacy_value_rejected() {
        let legacy = "legacy-master-password".to_string();
        let err = match parse_keychain_material(legacy) {
            Ok(_) => panic!("expected unsupported keychain value format error"),
            Err(e) => e,
        };
        assert!(err.contains("unsupported keychain value format"));
    }
}
