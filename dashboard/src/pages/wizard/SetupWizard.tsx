import { useState, useCallback } from "react";
import { CheckCircle2, Lock, Rocket, ShieldCheck, X } from "lucide-react";
import { Link } from "react-router-dom";
import { cn } from "@/lib/cn";
import { ROUTES } from "@/lib/constants";
import { WizardProgress } from "./WizardProgress";
import { CredentialStep } from "./steps/CredentialStep";
import { PolicyStep } from "./steps/PolicyStep";

const STEPS = ["Password", "Credential", "Policies", "Ready"];

interface SetupWizardProps {
  onComplete: () => void;
}

export function SetupWizard({ onComplete }: SetupWizardProps) {
  const [step, setStep] = useState(0);

  const goNext = useCallback(() => setStep((s) => Math.min(s + 1, 3)), []);

  return (
    <div className="animate-fade-in-up">
      {/* Header */}
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-text">Welcome to Fishnet</h2>
          <p className="text-sm text-text-secondary">
            Let's get your instance configured in a few quick steps.
          </p>
        </div>
        <button
          onClick={onComplete}
          className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs text-text-tertiary transition-colors hover:bg-surface-hover hover:text-text"
        >
          <X size={14} />
          Skip Setup
        </button>
      </div>

      {/* Progress */}
      <div className="mb-10">
        <WizardProgress currentStep={step} steps={STEPS} />
      </div>

      {/* Step content */}
      <div className="rounded-xl border border-border bg-surface p-8">
        {step === 0 && <PasswordStep onNext={goNext} />}
        {step === 1 && (
          <CredentialStep onNext={goNext} onSkip={goNext} />
        )}
        {step === 2 && (
          <PolicyStep onNext={goNext} onSkip={goNext} />
        )}
        {step === 3 && <ReadyStep onComplete={onComplete} />}
      </div>
    </div>
  );
}

function PasswordStep({ onNext }: { onNext: () => void }) {
  return (
    <div className="mx-auto max-w-md text-center">
      <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-success-dim">
        <Lock size={24} className="text-success" />
      </div>
      <h2 className="text-xl font-bold text-text">Master Password Set</h2>
      <p className="mt-2 text-sm text-text-secondary">
        Your master password was configured during setup. It encrypts the
        credential vault and protects all stored API keys.
      </p>

      {/* Strength indicator */}
      <div className="mx-auto mt-5 max-w-xs">
        <div className="flex items-center justify-between text-xs">
          <span className="text-text-tertiary">Password Strength</span>
          <span className="flex items-center gap-1 font-medium text-success">
            <ShieldCheck size={12} />
            Strong
          </span>
        </div>
        <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-surface-hover">
          <div className="h-full w-full rounded-full bg-success" />
        </div>
      </div>

      <p className="mt-5 text-xs text-text-tertiary">Step 1 of 4</p>
      <button
        onClick={onNext}
        className="mt-6 rounded-lg bg-brand px-5 py-2.5 text-sm font-medium text-white transition-colors hover:bg-brand-hover"
      >
        Continue
      </button>
    </div>
  );
}

function ReadyStep({ onComplete }: { onComplete: () => void }) {
  return (
    <div className="mx-auto max-w-md text-center">
      <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-success-dim">
        <CheckCircle2 size={28} className="text-success" />
      </div>
      <h2 className="text-xl font-bold text-text">You're all set!</h2>
      <p className="mt-2 text-sm text-text-secondary">
        Fishnet is ready to proxy and protect your agent's API calls. Configure
        your agent to use the proxy endpoints below.
      </p>

      {/* Config snippet */}
      <div className="mt-6 rounded-lg border border-border bg-bg-tertiary p-4 text-left">
        <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
          Agent Configuration
        </p>
        <code className="block whitespace-pre font-mono text-xs leading-relaxed text-text">
          {`OPENAI_BASE_URL=http://localhost:8472/openai\nANTHROPIC_BASE_URL=http://localhost:8472/anthropic`}
        </code>
      </div>

      <div className="mt-8 flex items-center justify-center gap-3">
        <button
          onClick={onComplete}
          className={cn(
            "flex items-center gap-2 rounded-lg bg-brand px-5 py-2.5 text-sm font-medium text-white transition-colors hover:bg-brand-hover",
          )}
        >
          <Rocket size={14} />
          Go to Dashboard
        </button>
        <Link
          to={ROUTES.DOCS ?? "/docs"}
          onClick={onComplete}
          className="rounded-lg px-4 py-2.5 text-sm text-text-tertiary transition-colors hover:text-text"
        >
          Read Docs
        </Link>
      </div>
    </div>
  );
}
