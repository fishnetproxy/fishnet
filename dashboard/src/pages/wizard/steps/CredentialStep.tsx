import { useState, useCallback } from "react";
import { Key, ArrowRight, SkipForward, Loader2 } from "lucide-react";
import { cn } from "@/lib/cn";
import { SERVICES, SERVICE_LABELS } from "@/lib/constants";

interface CredentialStepProps {
  onNext: () => void;
  onSkip: () => void;
}

export function CredentialStep({ onNext, onSkip }: CredentialStepProps) {
  const [service, setService] = useState<string>(SERVICES[0]);
  const [name, setName] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (!name.trim() || !apiKey.trim()) {
        setError("Name and API key are required");
        return;
      }
      setError(null);
      setSubmitting(true);
      try {
        const { createCredential } = await import(
          "@/api/endpoints/credentials"
        );
        await createCredential({ service, name: name.trim(), api_key: apiKey });
        onNext();
      } catch {
        setError("Failed to save credential. You can add it later from Settings.");
        setSubmitting(false);
      }
    },
    [service, name, apiKey, onNext],
  );

  return (
    <div className="mx-auto max-w-md">
      <div className="mb-2 flex h-12 w-12 items-center justify-center rounded-xl bg-brand-muted">
        <Key size={22} className="text-brand" />
      </div>
      <h2 className="mt-4 text-xl font-bold text-text">
        Add your first API key
      </h2>
      <p className="mt-2 text-sm text-text-secondary">
        Store a credential so Fishnet can proxy requests on your agent's behalf.
      </p>

      <form onSubmit={handleSubmit} className="mt-6 space-y-4">
        {/* Service */}
        <div>
          <label className="mb-1.5 block text-xs font-medium text-text-secondary">
            Service
          </label>
          <select
            value={service}
            onChange={(e) => setService(e.target.value)}
            className="w-full rounded-lg border border-border bg-surface-input px-3 py-2 text-sm text-text focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand/20"
          >
            {SERVICES.map((s) => (
              <option key={s} value={s}>
                {SERVICE_LABELS[s]}
              </option>
            ))}
          </select>
        </div>

        {/* Name */}
        <div>
          <label className="mb-1.5 block text-xs font-medium text-text-secondary">
            Key Name
          </label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Production Key"
            className="w-full rounded-lg border border-border bg-surface-input px-3 py-2 text-sm text-text placeholder:text-text-tertiary/50 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand/20"
          />
        </div>

        {/* API Key */}
        <div>
          <label className="mb-1.5 block text-xs font-medium text-text-secondary">
            API Key
          </label>
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="sk-..."
            className="w-full rounded-lg border border-border bg-surface-input px-3 py-2 font-mono text-sm text-text placeholder:text-text-tertiary/50 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand/20"
          />
        </div>

        {error && (
          <p className="text-sm text-danger">{error}</p>
        )}

        <div className="flex items-center gap-3 pt-2">
          <button
            type="submit"
            disabled={submitting}
            className={cn(
              "flex items-center gap-2 rounded-lg bg-brand px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-brand-hover",
              submitting && "opacity-60",
            )}
          >
            {submitting ? (
              <Loader2 size={14} className="animate-spin" />
            ) : (
              <>
                Next <ArrowRight size={14} />
              </>
            )}
          </button>
          <button
            type="button"
            onClick={onSkip}
            className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm text-text-tertiary transition-colors hover:text-text"
          >
            <SkipForward size={14} />
            Skip
          </button>
        </div>
      </form>
    </div>
  );
}
