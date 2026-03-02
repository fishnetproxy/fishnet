export default function GettingStarted() {
  return (
    <article className="docs-prose space-y-8">
      <header>
        <h1 className="text-3xl font-bold tracking-tight text-[#F5F5F7]">
          Getting Started
        </h1>
        <p className="mt-3 text-base text-[#71717A]">
          Install Fishnet, set up your first credential, and start proxying
          requests in under five minutes.
        </p>
      </header>

      <Section title="Installation">
        <p>Choose your preferred installation method:</p>
        <CodeBlock title="Homebrew (macOS/Linux)" code="brew install fishnet" />
        <CodeBlock
          title="Shell Script"
          code="curl -fsSL https://get.fishnet.dev | sh"
        />
        <CodeBlock title="Cargo" code="cargo install fishnet" />
        <CodeBlock
          title="Docker"
          code="docker run -p 8472:8472 -p 8473:8473 fishnet/fishnet"
        />
      </Section>

      <Section title="First Run">
        <p>
          Initialize Fishnet to create a configuration file and set your master
          password:
        </p>
        <CodeBlock
          code={`$ fishnet init
  Creating fishnet.toml...
  Set master password: ********
  Confirm: ********
  ✓ Initialized! Run 'fishnet start' to begin.`}
        />
        <p>
          This creates a <Mono>fishnet.toml</Mono> config file and an encrypted
          credential vault in <Mono>~/.fishnet/</Mono>.
        </p>
      </Section>

      <Section title="Add Your First Credential">
        <p>
          Store an API key in the vault. The key is encrypted at rest and
          injected into requests at proxy time.
        </p>
        <CodeBlock
          code={`$ fishnet credential add openai
  Name: Production Key
  API Key: sk-...
  ✓ Credential stored`}
        />
        <p>
          You can also add credentials through the dashboard UI at{" "}
          <Mono>http://localhost:8473</Mono>.
        </p>
      </Section>

      <Section title="Configure Policies">
        <p>
          Edit <Mono>fishnet.toml</Mono> to set spending limits, rate limits,
          and model restrictions:
        </p>
        <CodeBlock
          code={`[policies.openai]
daily_budget_usd = 50.0
rate_limit_rpm = 60
allowed_models = ["gpt-4", "gpt-4o", "gpt-3.5-turbo"]`}
        />
      </Section>

      <Section title="Start the Proxy">
        <CodeBlock
          code={`$ fishnet start
  ✓ Proxy listening on http://localhost:8472
  ✓ Dashboard at http://localhost:8473
  ✓ 1 credential loaded, 1 policy active`}
        />
        <p>
          Configure your agent to use{" "}
          <Mono>http://localhost:8472/openai</Mono> as the base URL instead of
          the direct API endpoint.
        </p>
      </Section>

      <Section title="Verify">
        <p>
          Run the built-in health check to ensure everything is configured
          correctly:
        </p>
        <CodeBlock
          code={`$ fishnet doctor
  ✓ Config file valid
  ✓ Vault unlocked
  ✓ Proxy reachable
  ✓ Dashboard reachable
  ✓ OpenAI credential configured`}
        />
      </Section>
    </article>
  );
}

/* ── Shared doc components ─────────────────────── */

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

function CodeBlock({ code, title }: { code: string; title?: string }) {
  return (
    <div className="overflow-hidden rounded-lg border border-[#1F1F23]">
      {title && (
        <div className="border-b border-[#1F1F23] bg-[#111113] px-4 py-2">
          <span className="text-xs text-[#71717A]">{title}</span>
        </div>
      )}
      <pre className="overflow-x-auto bg-[#0A0A0B] p-4 font-mono text-[13px] leading-relaxed text-[#A1A1AA]">
        {code}
      </pre>
    </div>
  );
}

function Mono({ children }: { children: React.ReactNode }) {
  return (
    <code className="rounded bg-[#1A1A1D] px-1.5 py-0.5 font-mono text-xs text-[#F5F5F7]">
      {children}
    </code>
  );
}
