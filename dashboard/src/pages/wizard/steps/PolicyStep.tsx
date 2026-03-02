import { useState, useCallback } from "react";
import { Sliders, ArrowRight, SkipForward, Loader2 } from "lucide-react";
import { cn } from "@/lib/cn";
import { apiFetch } from "@/api/client";
import type { PolicyQuickConfigPayload } from "@/api/types";

interface PolicyStepProps {
  onNext: () => void;
  onSkip: () => void;
}

export function PolicyStep({ onNext, onSkip }: PolicyStepProps) {
  const [budget, setBudget] = useState("50");
  const [rateLimit, setRateLimit] = useState("60");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      const budgetNum = Number(budget);
      const rlNum = Number(rateLimit);
      if (budgetNum <= 0 || rlNum <= 0) {
        setError("Values must be greater than 0");
        return;
      }
      setError(null);
      setSubmitting(true);
      try {
        await apiFetch<{ success: boolean }>("/settings/policy", {
          method: "PUT",
          body: JSON.stringify({
            daily_budget_usd: budgetNum,
            rate_limit_rpm: rlNum,
          } satisfies PolicyQuickConfigPayload),
        });
        onNext();
      } catch {
        // Best-effort — endpoint may not exist yet
        onNext();
      }
    },
    [budget, rateLimit, onNext],
  );

  return (
    <div className="mx-auto max-w-md">
      <div className="mb-2 flex h-12 w-12 items-center justify-center rounded-xl bg-info-dim">
        <Sliders size={22} className="text-info" />
      </div>
      <h2 className="mt-4 text-xl font-bold text-text">
        Set basic guardrails
      </h2>
      <p className="mt-2 text-sm text-text-secondary">
        Configure a daily spending limit and request rate cap. You can adjust
        these later in Settings.
      </p>

      <form onSubmit={handleSubmit} className="mt-6 space-y-4">
        {/* Daily budget */}
        <div>
          <label className="mb-1.5 block text-xs font-medium text-text-secondary">
            Daily Budget (USD)
          </label>
          <div className="relative">
            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-sm text-text-tertiary">
              $
            </span>
            <input
              type="number"
              min={1}
              step={1}
              value={budget}
              onChange={(e) => setBudget(e.target.value)}
              className="w-full rounded-lg border border-border bg-surface-input py-2 pl-7 pr-3 text-sm text-text focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand/20"
            />
          </div>
          <p className="mt-1 text-xs text-text-tertiary">
            Spending beyond this limit will be blocked
          </p>
        </div>

        {/* Rate limit */}
        <div>
          <label className="mb-1.5 block text-xs font-medium text-text-secondary">
            Rate Limit (requests/min)
          </label>
          <input
            type="number"
            min={1}
            step={1}
            value={rateLimit}
            onChange={(e) => setRateLimit(e.target.value)}
            className="w-full rounded-lg border border-border bg-surface-input px-3 py-2 text-sm text-text focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand/20"
          />
          <p className="mt-1 text-xs text-text-tertiary">
            Requests exceeding this rate will be queued or rejected
          </p>
        </div>

        {error && <p className="text-sm text-danger">{error}</p>}

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
