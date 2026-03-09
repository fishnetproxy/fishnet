import { useState, useCallback, useEffect } from "react";
import { X } from "lucide-react";
import { SERVICES, SERVICE_LABELS } from "@/lib/constants";
import type { CreateCredentialPayload } from "@/api/types";

interface AddCredentialModalProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (payload: CreateCredentialPayload) => Promise<boolean>;
}

export function AddCredentialModal({
  open,
  onClose,
  onSubmit,
}: AddCredentialModalProps) {
  const [service, setService] = useState<string>(SERVICES[0]);
  const [name, setName] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Reset form when modal opens
  useEffect(() => {
    if (open) {
      setService(SERVICES[0]);
      setName("");
      setApiKey("");
    }
  }, [open]);

  // Escape key closes modal
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

  const canSubmit = name.trim().length > 0 && apiKey.trim().length > 0;

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (!canSubmit || submitting) return;
      setSubmitting(true);
      const ok = await onSubmit({
        service,
        name: name.trim(),
        api_key: apiKey.trim(),
      });
      setSubmitting(false);
      if (ok) onClose();
    },
    [service, name, apiKey, canSubmit, submitting, onSubmit, onClose],
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
        {/* Header */}
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-text">Add Credential</h2>
          <button
            onClick={onClose}
            className="rounded-md p-1 text-text-tertiary transition-colors hover:bg-surface-hover hover:text-text"
          >
            <X size={16} />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="mt-5 space-y-4">
          {/* Service */}
          <div>
            <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
              Service
            </label>
            <select
              value={service}
              onChange={(e) => setService(e.target.value)}
              className="w-full rounded-lg border border-border bg-surface-input px-3 py-2 text-sm text-text focus:border-brand/50 focus:outline-none focus:ring-1 focus:ring-brand/20"
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
            <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
              Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Production API Key"
              className="w-full rounded-lg border border-border bg-surface-input px-3 py-2 text-sm text-text placeholder:text-text-tertiary/50 focus:border-brand/50 focus:outline-none focus:ring-1 focus:ring-brand/20"
            />
          </div>

          {/* API Key */}
          <div>
            <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
              API Key
            </label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="sk-..."
              className="w-full rounded-lg border border-border bg-surface-input px-3 py-2 font-mono text-sm text-text placeholder:text-text-tertiary/50 focus:border-brand/50 focus:outline-none focus:ring-1 focus:ring-brand/20"
            />
          </div>

          {/* Actions */}
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
              {submitting ? "Adding..." : "Add Credential"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
