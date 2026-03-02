import { useState, useCallback } from "react";
import { Link } from "react-router-dom";
import {
  Shield,
  Lock,
  Fingerprint,
  Activity,
  FileText,
  Copy,
  Check,
  Terminal,
  ArrowRight,
  ExternalLink,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { ROUTES } from "@/lib/constants";
import { ArchitectureDiagram } from "./ArchitectureDiagram";

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-[#08080A] text-[#F5F5F7]">
      <Navbar />
      <Hero />
      <ProblemSection />
      <FeaturesSection />
      <ArchitectureSection />
      <CodeSection />
      <InstallSection />
      <Footer />
    </div>
  );
}

/* ── Navbar ─────────────────────────────────────── */

function Navbar() {
  return (
    <nav className="fixed top-0 z-40 w-full border-b border-[#1F1F23] bg-[#08080A]/80 backdrop-blur-md">
      <div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-6">
        <Link to={ROUTES.WELCOME} className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[#E63946]">
            <Shield size={16} className="text-white" />
          </div>
          <span className="text-[15px] font-bold tracking-tight">Fishnet</span>
        </Link>
        <div className="flex items-center gap-4">
          <Link
            to={ROUTES.DOCS}
            className="text-sm text-[#A1A1AA] transition-colors hover:text-white"
          >
            Docs
          </Link>
          <Link
            to={ROUTES.LOGIN}
            className="rounded-lg bg-[#E63946] px-4 py-1.5 text-sm font-medium text-white transition-colors hover:bg-[#CC2D3B]"
          >
            Sign In
          </Link>
        </div>
      </div>
    </nav>
  );
}

/* ── Hero ───────────────────────────────────────── */

function Hero() {
  return (
    <section className="relative overflow-hidden pt-32 pb-20">
      {/* Background grid */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage: `
            linear-gradient(rgba(230,57,70,0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(230,57,70,0.03) 1px, transparent 1px)
          `,
          backgroundSize: "48px 48px",
        }}
      />
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(circle 600px at 50% 40%, rgba(230,57,70,0.06), transparent)",
        }}
      />

      <div className="relative mx-auto max-w-3xl px-6 text-center">
        <h1 className="text-[clamp(2rem,5vw,3.5rem)] font-bold leading-[1.1] tracking-[-0.03em]">
          The only door between your
          <br className="hidden sm:inline" /> AI agent{" "}
          <span className="text-[#E63946]">and the real world.</span>
        </h1>
        <p className="mx-auto mt-6 max-w-lg text-base leading-relaxed text-[#71717A]">
          Single Rust binary. Open source. Nothing leaves your machine.
          Credential vault, policy engine, and audit trail for autonomous agents.
        </p>

        <div className="mt-8 flex flex-col items-center gap-4 sm:flex-row sm:justify-center">
          <CopyInstallButton text="brew install fishnet" />
          <Link
            to={ROUTES.DOCS}
            className="flex items-center gap-1.5 text-sm text-[#A1A1AA] transition-colors hover:text-white"
          >
            Read the docs <ArrowRight size={14} />
          </Link>
        </div>
      </div>
    </section>
  );
}

/* ── Problem ────────────────────────────────────── */

function ProblemSection() {
  const problems = [
    {
      title: "API Key Leaks",
      description:
        "Plain-text secrets in env files. One compromised dependency and your keys are exposed.",
    },
    {
      title: "Malicious Skills",
      description:
        "Untrusted agent skills can exfiltrate credentials or make unauthorized API calls.",
    },
    {
      title: "Runaway Spend",
      description:
        "No budget guardrails. A single prompt loop can burn through hundreds of dollars.",
    },
  ];

  return (
    <section className="border-t border-[#1F1F23] py-20">
      <div className="mx-auto max-w-5xl px-6">
        <h2 className="text-center text-2xl font-bold">
          Agents are powerful. <span className="text-[#E63946]">And risky.</span>
        </h2>
        <div className="mt-10 grid grid-cols-1 gap-6 sm:grid-cols-3">
          {problems.map((p) => (
            <div
              key={p.title}
              className="rounded-xl border border-[#1F1F23] bg-[#111113] p-6"
            >
              <h3 className="text-sm font-semibold text-[#F5F5F7]">
                {p.title}
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-[#71717A]">
                {p.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ── Features ───────────────────────────────────── */

function FeaturesSection() {
  const features = [
    {
      icon: <Lock size={20} />,
      title: "API Key Protection",
      description:
        "Encrypted credential vault. Proxy injects keys at request time — your agent never sees them.",
      color: "text-[#22C55E]",
      bg: "bg-[#22C55E]/10",
    },
    {
      icon: <Fingerprint size={20} />,
      title: "Onchain Permits",
      description:
        "Contract whitelist, EIP-712 signed permits, and smart wallet integration.",
      color: "text-[#3B82F6]",
      bg: "bg-[#3B82F6]/10",
    },
    {
      icon: <Shield size={20} />,
      title: "Policy Engine",
      description:
        "Default-deny policies. Rate limits, model restrictions, spend caps — all configurable.",
      color: "text-[#E63946]",
      bg: "bg-[#E63946]/10",
    },
    {
      icon: <FileText size={20} />,
      title: "Audit Trail",
      description:
        "Merkle tree audit log with zero-knowledge compliance proofs for every request.",
      color: "text-[#8B5CF6]",
      bg: "bg-[#8B5CF6]/10",
    },
  ];

  return (
    <section className="border-t border-[#1F1F23] py-20">
      <div className="mx-auto max-w-5xl px-6">
        <h2 className="text-center text-2xl font-bold">
          Everything your agent needs.{" "}
          <span className="text-[#71717A]">Nothing it doesn't.</span>
        </h2>
        <div className="mt-10 grid grid-cols-1 gap-6 sm:grid-cols-2">
          {features.map((f) => (
            <div
              key={f.title}
              className="rounded-xl border border-[#1F1F23] bg-[#111113] p-6"
            >
              <div
                className={cn(
                  "mb-3 flex h-10 w-10 items-center justify-center rounded-lg",
                  f.bg,
                  f.color,
                )}
              >
                {f.icon}
              </div>
              <h3 className="text-sm font-semibold text-[#F5F5F7]">
                {f.title}
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-[#71717A]">
                {f.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ── Architecture ───────────────────────────────── */

function ArchitectureSection() {
  return (
    <section className="border-t border-[#1F1F23] py-20">
      <div className="mx-auto max-w-5xl px-6">
        <h2 className="text-center text-2xl font-bold">
          How it works
        </h2>
        <p className="mx-auto mt-3 max-w-md text-center text-sm text-[#71717A]">
          Fishnet sits between your agent and external services, enforcing
          policies and managing credentials.
        </p>
        <div className="mx-auto mt-10 max-w-sm">
          <ArchitectureDiagram />
        </div>
      </div>
    </section>
  );
}

/* ── Code ───────────────────────────────────────── */

function CodeSection() {
  const code = `# Install and start Fishnet
$ fishnet init
$ fishnet start

# Your agent's requests route through the proxy
$ curl http://localhost:8472/openai/v1/chat/completions \\
  -H "Content-Type: application/json" \\
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}'`;

  return (
    <section className="border-t border-[#1F1F23] py-20">
      <div className="mx-auto max-w-5xl px-6">
        <h2 className="text-center text-2xl font-bold">
          Up and running in <span className="text-[#E63946]">30 seconds</span>
        </h2>
        <div className="mx-auto mt-8 max-w-2xl overflow-hidden rounded-xl border border-[#1F1F23]">
          <div className="flex items-center gap-2 border-b border-[#1F1F23] bg-[#111113] px-4 py-2.5">
            <Terminal size={14} className="text-[#71717A]" />
            <span className="text-xs text-[#71717A]">Terminal</span>
          </div>
          <pre className="overflow-x-auto bg-[#0A0A0B] p-5 font-mono text-[13px] leading-relaxed text-[#A1A1AA]">
            {code}
          </pre>
        </div>
      </div>
    </section>
  );
}

/* ── Install ────────────────────────────────────── */

function InstallSection() {
  const methods = [
    { label: "Homebrew", cmd: "brew install fishnet" },
    { label: "curl", cmd: "curl -fsSL https://get.fishnet.dev | sh" },
    { label: "Cargo", cmd: "cargo install fishnet" },
    { label: "Docker", cmd: "docker run -p 8472:8472 fishnet/fishnet" },
  ];

  return (
    <section className="border-t border-[#1F1F23] py-20">
      <div className="mx-auto max-w-5xl px-6">
        <h2 className="text-center text-2xl font-bold">Install</h2>
        <div className="mx-auto mt-8 grid max-w-2xl grid-cols-1 gap-3 sm:grid-cols-2">
          {methods.map((m) => (
            <div
              key={m.label}
              className="flex items-center justify-between rounded-lg border border-[#1F1F23] bg-[#111113] px-4 py-3"
            >
              <div className="min-w-0">
                <p className="text-xs font-medium text-[#71717A]">{m.label}</p>
                <code className="mt-0.5 block truncate font-mono text-xs text-[#F5F5F7]">
                  {m.cmd}
                </code>
              </div>
              <CopyButton text={m.cmd} />
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ── Footer ─────────────────────────────────────── */

function Footer() {
  return (
    <footer className="border-t border-[#1F1F23] py-8">
      <div className="mx-auto flex max-w-5xl flex-col items-center gap-3 px-6 sm:flex-row sm:justify-between">
        <div className="flex items-center gap-2 text-sm text-[#71717A]">
          <Shield size={14} className="text-[#E63946]" />
          <span>Fishnet &middot; MIT License</span>
        </div>
        <a
          href="https://github.com/iamyxsh/fishnet"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1.5 text-sm text-[#71717A] transition-colors hover:text-white"
        >
          GitHub <ExternalLink size={12} />
        </a>
      </div>
    </footer>
  );
}

/* ── Reusable Components ────────────────────────── */

function CopyInstallButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* noop */
    }
  }, [text]);

  return (
    <button
      onClick={handleCopy}
      className="flex items-center gap-3 rounded-lg border border-[#2A2A2E] bg-[#111113] px-5 py-2.5 font-mono text-sm text-[#F5F5F7] transition-all hover:border-[#3a3a3f] hover:bg-[#1A1A1D]"
    >
      <span className="text-[#71717A]">$</span>
      {text}
      {copied ? (
        <Check size={14} className="text-[#22C55E]" />
      ) : (
        <Copy size={14} className="text-[#71717A]" />
      )}
    </button>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* noop */
    }
  }, [text]);

  return (
    <button
      onClick={handleCopy}
      className="shrink-0 rounded-md p-1.5 text-[#71717A] transition-colors hover:bg-[#222225] hover:text-white"
    >
      {copied ? <Check size={14} className="text-[#22C55E]" /> : <Copy size={14} />}
    </button>
  );
}
