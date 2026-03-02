export default function SecurityModel() {
  return (
    <article className="space-y-8">
      <header>
        <h1 className="text-3xl font-bold tracking-tight text-[#F5F5F7]">
          Security Model
        </h1>
        <p className="mt-3 text-base text-[#71717A]">
          How Fishnet protects your credentials, enforces policies, and
          maintains auditability. Including an honest assessment of what
          it does <em>not</em> protect against.
        </p>
      </header>

      <Section title="Threat Model">
        <p>
          Fishnet is designed to protect against the following threats in
          autonomous agent deployments:
        </p>
        <ThreatTable
          rows={[
            ["Credential Theft", "Agent code or dependencies attempt to read API keys from environment or files.", "Keys never exist in agent process memory. Fishnet injects them at proxy time."],
            ["Credential Exfiltration", "Malicious skill sends credentials to an external server.", "Credentials are encrypted at rest and only decrypted within the Fishnet process."],
            ["Excessive Spending", "Prompt loops or bugs cause runaway API usage.", "Per-service daily budgets and request rate limits enforced at proxy layer."],
            ["Unauthorized Transactions", "Agent attempts to sign transactions to non-whitelisted contracts.", "Contract whitelist with function-level granularity. EIP-712 permits with expiry."],
            ["Prompt Injection", "Attacker modifies system prompt to change agent behavior.", "Prompt drift detection alerts when system prompt hash changes between requests."],
            ["Data Exfiltration", "Agent sends sensitive data to unauthorized endpoints.", "Network isolation mode blocks all outbound traffic except configured endpoints."],
          ]}
        />
      </Section>

      <Section title="Process Isolation">
        <p>
          Fishnet runs as a separate process from your AI agent, providing
          natural isolation boundaries:
        </p>
        <div className="space-y-3">
          <IsolationLevel
            level="Level 1: Process Isolation"
            description="Fishnet runs in its own process. The agent cannot read Fishnet's memory. Credentials are never shared across process boundaries."
          />
          <IsolationLevel
            level="Level 2: Network Isolation"
            description="When enabled, the firewall blocks all outbound traffic except configured proxy endpoints. The agent can only reach localhost."
          />
          <IsolationLevel
            level="Level 3: Cryptographic Isolation"
            description="Credentials are AES-256 encrypted at rest. The vault key is derived from the master password using Argon2id. Keys are decrypted only for the duration of a proxied request."
          />
        </div>
      </Section>

      <Section title="Credential Vault Design">
        <div className="space-y-3">
          <p>The credential vault uses industry-standard cryptographic primitives:</p>
          <ul className="list-disc space-y-1.5 pl-5">
            <li>
              <strong className="text-[#F5F5F7]">Key Derivation:</strong>{" "}
              Argon2id with configurable memory/iteration parameters
            </li>
            <li>
              <strong className="text-[#F5F5F7]">Encryption:</strong>{" "}
              AES-256-GCM with random nonces per entry
            </li>
            <li>
              <strong className="text-[#F5F5F7]">Storage:</strong>{" "}
              SQLite database in <Mono>~/.fishnet/vault.db</Mono>
            </li>
            <li>
              <strong className="text-[#F5F5F7]">Backup:</strong>{" "}
              Encrypted vault export for disaster recovery
            </li>
          </ul>
          <p>
            The master password is never stored. A wrong password produces
            a different decryption key, resulting in authentication failure
            rather than corrupted plaintext.
          </p>
        </div>
      </Section>

      <Section title="Audit Trail">
        <p>
          Every proxied request is logged in an append-only Merkle tree:
        </p>
        <ul className="list-disc space-y-1.5 pl-5">
          <li>Request method, endpoint, and response status</li>
          <li>Token usage and estimated cost</li>
          <li>Policy evaluation result (allow/deny with reason)</li>
          <li>Timestamp and request duration</li>
        </ul>
        <p>
          The Merkle tree structure allows generation of zero-knowledge
          compliance proofs, demonstrating that spending remained within
          policy limits without revealing individual request details.
        </p>
      </Section>

      <Section title="What Fishnet Does NOT Protect Against">
        <div className="rounded-lg border border-[#F59E0B]/20 bg-[#F59E0B]/5 p-5">
          <p className="mb-3 text-sm font-semibold text-[#F59E0B]">
            Honest Disclaimer
          </p>
          <ul className="list-disc space-y-2 pl-5 text-sm text-[#A1A1AA]">
            <li>
              <strong className="text-[#F5F5F7]">Compromised host machine:</strong>{" "}
              If an attacker has root access to your machine, they can read
              Fishnet's process memory and extract decrypted credentials.
            </li>
            <li>
              <strong className="text-[#F5F5F7]">Response content manipulation:</strong>{" "}
              Fishnet does not inspect or filter API response content. A
              compromised upstream API could return malicious content.
            </li>
            <li>
              <strong className="text-[#F5F5F7]">Side-channel attacks:</strong>{" "}
              Timing analysis of proxy requests could reveal usage patterns.
              Fishnet does not add random delays.
            </li>
            <li>
              <strong className="text-[#F5F5F7]">Social engineering:</strong>{" "}
              If an agent is tricked into performing harmful actions using
              allowed APIs, Fishnet cannot detect the intent.
            </li>
            <li>
              <strong className="text-[#F5F5F7]">Master password weakness:</strong>{" "}
              A weak master password undermines vault security. Use a strong,
              unique password.
            </li>
          </ul>
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

function Mono({ children }: { children: React.ReactNode }) {
  return (
    <code className="rounded bg-[#1A1A1D] px-1.5 py-0.5 font-mono text-xs text-[#F5F5F7]">
      {children}
    </code>
  );
}

function ThreatTable({ rows }: { rows: [string, string, string][] }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-[#1F1F23]">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[#1F1F23] bg-[#111113]">
            <th className="px-4 py-2 text-left text-[11px] font-semibold uppercase tracking-wider text-[#71717A]">
              Threat
            </th>
            <th className="px-4 py-2 text-left text-[11px] font-semibold uppercase tracking-wider text-[#71717A]">
              Attack Vector
            </th>
            <th className="px-4 py-2 text-left text-[11px] font-semibold uppercase tracking-wider text-[#71717A]">
              Mitigation
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([threat, vector, mitigation]) => (
            <tr
              key={threat}
              className="border-b border-[#1F1F23] last:border-0"
            >
              <td className="px-4 py-2.5 text-xs font-medium text-[#F5F5F7]">
                {threat}
              </td>
              <td className="px-4 py-2.5 text-xs text-[#A1A1AA]">{vector}</td>
              <td className="px-4 py-2.5 text-xs text-[#A1A1AA]">
                {mitigation}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function IsolationLevel({
  level,
  description,
}: {
  level: string;
  description: string;
}) {
  return (
    <div className="rounded-lg border border-[#1F1F23] bg-[#111113] p-4">
      <p className="text-sm font-medium text-[#F5F5F7]">{level}</p>
      <p className="mt-1 text-xs text-[#71717A]">{description}</p>
    </div>
  );
}
