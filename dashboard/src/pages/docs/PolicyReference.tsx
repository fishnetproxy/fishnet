export default function PolicyReference() {
  return (
    <article className="space-y-8">
      <header>
        <h1 className="text-3xl font-bold tracking-tight text-[#F5F5F7]">
          Policy Reference
        </h1>
        <p className="mt-3 text-base text-[#71717A]">
          Complete reference for <Mono>fishnet.toml</Mono> configuration. All
          policies follow a default-deny model.
        </p>
      </header>

      <Section title="Global Settings">
        <CodeBlock
          code={`[global]
proxy_port = 8472
dashboard_port = 8473
log_level = "info"          # debug | info | warn | error
audit_retention_days = 90`}
        />
      </Section>

      <Section title="LLM Policies">
        <p>Configure per-service policies for LLM API providers:</p>
        <CodeBlock
          code={`[policies.openai]
daily_budget_usd = 50.0
rate_limit_rpm = 60
max_prompt_tokens = 128000
allowed_models = ["gpt-4", "gpt-4o", "gpt-3.5-turbo"]
blocked_models = ["gpt-4-32k"]  # Explicitly block expensive models
prompt_drift_detection = true   # Alert on system prompt changes
max_response_tokens = 4096`}
        />
        <ConfigTable
          rows={[
            ["daily_budget_usd", "float", "Max daily spend in USD. Requests are blocked when exceeded."],
            ["rate_limit_rpm", "int", "Maximum requests per minute. Excess requests return 429."],
            ["max_prompt_tokens", "int", "Maximum input token count. Requests exceeding this are rejected."],
            ["allowed_models", "string[]", "Whitelist of allowed model IDs. Empty = all allowed."],
            ["blocked_models", "string[]", "Blacklist of blocked model IDs. Takes precedence over allowed."],
            ["prompt_drift_detection", "bool", "Alert when system prompt hash changes between requests."],
            ["max_response_tokens", "int", "Cap on max_tokens parameter in requests."],
          ]}
        />
      </Section>

      <Section title="Exchange Policies">
        <p>Configure policies for exchange API proxying:</p>
        <CodeBlock
          code={`[policies.binance]
daily_volume_cap_usd = 10000.0
max_order_value_usd = 1000.0
allowed_endpoints = ["GET /api/v3/*", "POST /api/v3/order"]
blocked_endpoints = ["POST /api/v3/withdraw"]
rate_limit_rpm = 120`}
        />
        <ConfigTable
          rows={[
            ["daily_volume_cap_usd", "float", "Maximum daily trading volume."],
            ["max_order_value_usd", "float", "Maximum single order value."],
            ["allowed_endpoints", "string[]", "Glob patterns for allowed API endpoints."],
            ["blocked_endpoints", "string[]", "Permanently blocked endpoints (e.g., withdrawals)."],
            ["rate_limit_rpm", "int", "Request rate limit per minute."],
          ]}
        />
      </Section>

      <Section title="Onchain Policies">
        <p>Configure policies for onchain transaction signing:</p>
        <CodeBlock
          code={`[onchain]
enabled = true
chain_ids = [1, 8453, 42161]

[onchain.limits]
max_tx_value_usd = 500.0
daily_spend_cap_usd = 5000.0
cooldown_seconds = 10
max_slippage_bps = 100
max_leverage = 1

[onchain.permits]
expiry_seconds = 300
require_policy_hash = true

[onchain.whitelist]
"0xContractA" = ["transfer", "approve"]
"0xContractB" = ["swap", "addLiquidity"]`}
        />
        <ConfigTable
          rows={[
            ["max_tx_value_usd", "float", "Maximum value per transaction."],
            ["daily_spend_cap_usd", "float", "Maximum daily onchain spend."],
            ["cooldown_seconds", "int", "Minimum seconds between permit signings."],
            ["max_slippage_bps", "int", "Maximum slippage in basis points (100 = 1%)."],
            ["expiry_seconds", "int", "EIP-712 permit expiration time."],
            ["require_policy_hash", "bool", "Include policy hash in signed permits for auditability."],
          ]}
        />
      </Section>

      <Section title="Custom API Configuration">
        <p>Proxy custom APIs beyond LLM providers and exchanges:</p>
        <CodeBlock
          code={`[custom.github]
base_url = "https://api.github.com"
auth_header = "Authorization"
auth_pattern = "Bearer {credential}"
rate_limit_rpm = 30`}
        />
      </Section>
    </article>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-3">
      <h2 className="text-xl font-bold text-[#F5F5F7]">{title}</h2>
      <div className="space-y-3 text-sm leading-relaxed text-[#A1A1AA]">
        {children}
      </div>
    </section>
  );
}

function CodeBlock({ code }: { code: string }) {
  return (
    <pre className="overflow-x-auto rounded-lg border border-[#1F1F23] bg-[#0A0A0B] p-4 font-mono text-[13px] leading-relaxed text-[#A1A1AA]">
      {code}
    </pre>
  );
}

function Mono({ children }: { children: React.ReactNode }) {
  return (
    <code className="rounded bg-[#1A1A1D] px-1.5 py-0.5 font-mono text-xs text-[#F5F5F7]">
      {children}
    </code>
  );
}

function ConfigTable({ rows }: { rows: [string, string, string][] }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-[#1F1F23]">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[#1F1F23] bg-[#111113]">
            <th className="px-4 py-2 text-left text-[11px] font-semibold uppercase tracking-wider text-[#71717A]">
              Option
            </th>
            <th className="px-4 py-2 text-left text-[11px] font-semibold uppercase tracking-wider text-[#71717A]">
              Type
            </th>
            <th className="px-4 py-2 text-left text-[11px] font-semibold uppercase tracking-wider text-[#71717A]">
              Description
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([option, type, desc]) => (
            <tr key={option} className="border-b border-[#1F1F23] last:border-0">
              <td className="px-4 py-2.5 font-mono text-xs text-[#F5F5F7]">
                {option}
              </td>
              <td className="px-4 py-2.5 text-xs text-[#71717A]">{type}</td>
              <td className="px-4 py-2.5 text-xs text-[#A1A1AA]">{desc}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
