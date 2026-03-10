import { useState, useCallback, useEffect } from "react";
import { X } from "lucide-react";
import type { AddExchangePayload } from "@/api/types";

interface AddExchangeModalProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (payload: AddExchangePayload) => Promise<boolean>;
}

const AUTH_PATTERNS = ["Bearer Token", "HMAC Signature", "API Key Header"] as const;

export function AddExchangeModal({ open, onClose, onSubmit }: AddExchangeModalProps) {
  const [name, setName] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [authPattern, setAuthPattern] = useState<string>(AUTH_PATTERNS[0]);
  const [blockedEndpoints, setBlockedEndpoints] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (open) {
      setName("");
      setBaseUrl("");
      setAuthPattern(AUTH_PATTERNS[0]);
      setBlockedEndpoints("");
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

  const canSubmit = name.trim().length > 0 && baseUrl.trim().length > 0;

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (!canSubmit || submitting) return;
      setSubmitting(true);
      const blocked = blockedEndpoints
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const ok = await onSubmit({
        name: name.trim(),
        base_url: baseUrl.trim(),
        auth_pattern: authPattern,
        blocked_endpoints: blocked,
      });
      setSubmitting(false);
      if (ok) onClose();
    },
    [name, baseUrl, authPattern, blockedEndpoints, canSubmit, submitting, onSubmit, onClose],
  );

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-md rounded-xl border border-border bg-surface p-6 shadow-2xl">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-text">Add Exchange</h2>
          <button
            onClick={onClose}
            className="rounded-md p-1 text-text-tertiary transition-colors hover:bg-surface-hover hover:text-text"
          >
            <X size={16} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="mt-5 space-y-4">
          <div>
            <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
              Exchange Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Binance"
              className="w-full rounded-lg border border-border bg-surface-input px-3 py-2 text-sm text-text placeholder:text-text-tertiary/50 focus:border-brand/50 focus:outline-none focus:ring-1 focus:ring-brand/20"
            />
          </div>

          <div>
            <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
              Base URL
            </label>
            <input
              type="text"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://api.binance.com"
              className="w-full rounded-lg border border-border bg-surface-input px-3 py-2 font-mono text-sm text-text placeholder:text-text-tertiary/50 focus:border-brand/50 focus:outline-none focus:ring-1 focus:ring-brand/20"
            />
          </div>

          <div>
            <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
              Auth Pattern
            </label>
            <select
              value={authPattern}
              onChange={(e) => setAuthPattern(e.target.value)}
              className="w-full rounded-lg border border-border bg-surface-input px-3 py-2 text-sm text-text focus:border-brand/50 focus:outline-none focus:ring-1 focus:ring-brand/20"
            >
              {AUTH_PATTERNS.map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
              Blocked Endpoints
            </label>
            <textarea
              value={blockedEndpoints}
              onChange={(e) => setBlockedEndpoints(e.target.value)}
              placeholder="POST /sapi/v1/capital/withdraw/*, DELETE /api/v3/openOrders"
              rows={3}
              className="w-full rounded-lg border border-border bg-surface-input px-3 py-2 font-mono text-xs text-text placeholder:text-text-tertiary/50 focus:border-brand/50 focus:outline-none focus:ring-1 focus:ring-brand/20"
            />
            <p className="mt-1 text-[11px] text-text-tertiary">Comma-separated endpoint patterns</p>
          </div>

          <div className="flex items-center justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg px-3 py-1.5 text-sm text-text-tertiary transition-colors hover:bg-surface-hover hover:text-text"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!canSubmit || submitting}
              className="rounded-lg bg-brand px-4 py-1.5 text-sm font-medium text-white transition-all duration-150 hover:bg-brand-hover disabled:opacity-40"
            >
              {submitting ? "Adding..." : "Add Exchange"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
