import type { ServiceName } from "@/lib/constants";

// --- Auth ---
export interface AuthStatusResponse {
  initialized: boolean;
  authenticated: boolean;
}

export interface LoginResponse {
  token: string;
  expires_at: string;
}

export interface SetupResponse {
  success: boolean;
  message: string;
}

export interface LogoutResponse {
  success: boolean;
}

export interface AuthErrorResponse {
  error: string;
  retry_after_seconds?: number;
}

// --- Alerts ---
export type AlertType =
  | "prompt_drift"
  | "prompt_size"
  | "budget_warning"
  | "budget_exceeded"
  | "onchain_denied"
  | "rate_limit_hit";

export type AlertSeverity = "critical" | "warning";

export interface Alert {
  id: string;
  type: AlertType;
  severity: AlertSeverity;
  service: string;
  message: string;
  /** Unix timestamp in seconds */
  timestamp: number;
  dismissed: boolean;
}

export interface AlertsResponse {
  alerts: Alert[];
}

export interface DismissAlertResponse {
  success: boolean;
}

// --- Alert Query Params ---
export interface AlertsQueryParams {
  type?: AlertType;
  dismissed?: boolean;
  limit?: number;
  skip?: number;
}

// --- Alert Config ---
export interface AlertConfigToggles {
  prompt_drift: boolean;
  prompt_size: boolean;
  budget_warning: boolean;
  budget_exceeded: boolean;
  onchain_denied: boolean;
  rate_limit_hit: boolean;
}

export interface AlertConfigResponse {
  toggles: AlertConfigToggles;
  retention_days: number;
}

export interface AlertConfigUpdatePayload {
  prompt_drift?: boolean;
  prompt_size?: boolean;
  budget_warning?: boolean;
  budget_exceeded?: boolean;
  onchain_denied?: boolean;
  rate_limit_hit?: boolean;
  retention_days?: number;
}

export interface AlertConfigUpdateResponse {
  success: boolean;
  toggles: AlertConfigToggles;
  retention_days: number;
}

// --- Spend Analytics ---
export interface DailySpendEntry {
  date: string;
  service: ServiceName;
  cost_usd: number;
  request_count: number;
}

export interface ServiceBudget {
  daily_limit: number | null;
  spent_today: number;
  warning_active?: boolean;
  warning_pct?: number;
}

export interface SpendConfig {
  track_spend: boolean;
  spend_history_days: number;
}

export interface SpendAnalyticsResponse {
  enabled: boolean;
  daily: DailySpendEntry[];
  budgets: Record<string, ServiceBudget>;
  config: SpendConfig;
}

// --- Onchain / Signer ---

export interface SignerConfig {
  max_tx_value_usd: number;
  daily_spend_cap_usd: number;
  cooldown_seconds: number;
  max_slippage_bps: number;
  permit_expiry_seconds: number;
}

export interface SignerStats {
  total_permits_signed: number;
  total_permits_denied: number;
  spent_today_usd: number;
  last_permit_at: number | null;
}

export interface SignerStatusResponse {
  enabled: boolean;
  mode: string | null;
  address: string | null;
  chain_ids: number[];
  config: SignerConfig;
  stats: SignerStats;
}

export interface OnchainLimits {
  max_tx_value_usd: number;
  daily_spend_cap_usd: number;
  cooldown_seconds: number;
  max_slippage_bps: number;
  max_leverage: number;
}

export interface OnchainPermitConfig {
  expiry_seconds: number;
  require_policy_hash: boolean;
  verifying_contract: string;
}

export interface OnchainConfigResponse {
  enabled: boolean;
  chain_ids: number[];
  limits: OnchainLimits;
  permits: OnchainPermitConfig;
  whitelist: Record<string, string[]>;
}

export interface OnchainConfigUpdatePayload {
  enabled?: boolean;
  chain_ids?: number[];
  max_tx_value_usd?: number;
  daily_spend_cap_usd?: number;
  cooldown_seconds?: number;
  max_slippage_bps?: number;
  max_leverage?: number;
  expiry_seconds?: number;
  require_policy_hash?: boolean;
  verifying_contract?: string;
  whitelist?: Record<string, string[]>;
}

export type PermitStatus = "approved" | "denied";

export interface Permit {
  id: number;
  chain_id: number;
  target: string;
  value: string;
  status: PermitStatus;
  reason: string | null;
  permit_hash: string | null;
  cost_usd: number;
  date: string;
  /** Unix timestamp in seconds */
  created_at: number;
}

export interface PermitsResponse {
  permits: Permit[];
}

// --- Credentials ---
export interface Credential {
  id: string;
  service: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

export interface CredentialsResponse {
  credentials: Credential[];
}

export interface CreateCredentialPayload {
  service: string;
  name: string;
  api_key: string;
}

// --- Status ---
export interface StatusResponse {
  running: boolean;
  uptime_seconds: number;
  active_services: string[];
  proxy_port: number;
  dashboard_port: number;
  version: string;
}

// --- Webhook ---
export interface WebhookConfig {
  url: string;
  enabled: boolean;
}

export interface WebhookConfigResponse {
  webhook: WebhookConfig | null;
}

export interface WebhookTestResponse {
  success: boolean;
  message: string;
}

// --- Policy Quick Config (wizard) ---
export interface PolicyQuickConfigPayload {
  daily_budget_usd: number;
  rate_limit_rpm: number;
}

// --- Generic ---
export interface ApiError {
  error: string;
  code: number;
}
