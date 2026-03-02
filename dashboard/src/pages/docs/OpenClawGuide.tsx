export default function OpenClawGuide() {
  return (
    <article className="space-y-8">
      <header>
        <h1 className="text-3xl font-bold tracking-tight text-[#F5F5F7]">
          OpenClaw Integration
        </h1>
        <p className="mt-3 text-base text-[#71717A]">
          Configure OpenClaw to route all API calls through Fishnet for
          credential protection and policy enforcement.
        </p>
      </header>

      <Section title="Prerequisites">
        <ul className="list-disc space-y-1.5 pl-5">
          <li>Fishnet installed and running</li>
          <li>At least one API credential stored in the vault</li>
          <li>OpenClaw installed and configured</li>
        </ul>
      </Section>

      <Section title="1. Install the Fishnet Skill">
        <p>
          Install the Fishnet skill from ClawHub to enable automatic proxy
          routing:
        </p>
        <CodeBlock code="openclaw skill install fishnet" />
        <p>
          This skill configures OpenClaw to route all outbound API requests
          through the Fishnet proxy.
        </p>
      </Section>

      <Section title="2. Configure Environment Variables">
        <p>
          Add the following to your OpenClaw <Mono>.env</Mono> file or export
          them in your shell:
        </p>
        <CodeBlock
          code={`OPENAI_BASE_URL=http://localhost:8472/openai
ANTHROPIC_BASE_URL=http://localhost:8472/anthropic`}
        />
        <p>
          Fishnet acts as a transparent proxy — it accepts the same API format
          as the upstream service and injects credentials from the vault.
        </p>
      </Section>

      <Section title="3. Verify Routing">
        <p>
          Run a test request to confirm traffic flows through Fishnet:
        </p>
        <CodeBlock
          code={`$ curl http://localhost:8472/openai/v1/models
{
  "data": [{ "id": "gpt-4", ... }]
}`}
        />
        <p>
          Check the Fishnet dashboard at{" "}
          <Mono>http://localhost:8473</Mono> to see the request in the audit
          log and spend tracker.
        </p>
      </Section>

      <Section title="Troubleshooting">
        <div className="space-y-4">
          <TroubleItem
            problem="Connection refused on port 8472"
            solution="Ensure Fishnet is running with 'fishnet start'. Check 'fishnet doctor' for diagnostics."
          />
          <TroubleItem
            problem="401 Unauthorized from upstream API"
            solution="Verify the API credential is stored in the vault. Run 'fishnet credential list' to check."
          />
          <TroubleItem
            problem="Request blocked by policy"
            solution="Check your fishnet.toml policies. The dashboard Alerts page shows why requests were denied."
          />
          <TroubleItem
            problem="Slow response times"
            solution="Fishnet adds minimal latency (<5ms). If responses are slow, check your network connection to the upstream API."
          />
        </div>
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

function TroubleItem({
  problem,
  solution,
}: {
  problem: string;
  solution: string;
}) {
  return (
    <div className="rounded-lg border border-[#1F1F23] bg-[#111113] p-4">
      <p className="text-sm font-medium text-[#F5F5F7]">{problem}</p>
      <p className="mt-1 text-sm text-[#71717A]">{solution}</p>
    </div>
  );
}
