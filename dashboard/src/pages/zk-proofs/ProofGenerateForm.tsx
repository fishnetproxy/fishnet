import { useState, useCallback } from "react";
import { ShieldCheck } from "lucide-react";
import { Card } from "@/components/ui/Card";

interface ProofGenerateFormProps {
  onGenerate: (from: string, to: string) => Promise<void>;
  generating: boolean;
}

export function ProofGenerateForm({ onGenerate, generating }: ProofGenerateFormProps) {
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");

  const canSubmit = fromDate.length > 0 && toDate.length > 0 && toDate >= fromDate && !generating;

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      if (!canSubmit) return;
      onGenerate(fromDate, toDate);
    },
    [fromDate, toDate, canSubmit, onGenerate],
  );

  return (
    <Card title="Generate Proof">
      <form onSubmit={handleSubmit} className="flex flex-wrap items-end gap-4">
        <div>
          <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
            From
          </label>
          <input
            type="date"
            value={fromDate}
            onChange={(e) => setFromDate(e.target.value)}
            className="rounded-lg border border-border bg-surface-input px-3 py-2 text-sm text-text focus:border-brand/50 focus:outline-none focus:ring-1 focus:ring-brand/20"
          />
        </div>
        <div>
          <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
            To
          </label>
          <input
            type="date"
            value={toDate}
            onChange={(e) => setToDate(e.target.value)}
            className="rounded-lg border border-border bg-surface-input px-3 py-2 text-sm text-text focus:border-brand/50 focus:outline-none focus:ring-1 focus:ring-brand/20"
          />
        </div>
        <button
          type="submit"
          disabled={!canSubmit}
          className="flex items-center gap-1.5 rounded-lg bg-brand px-4 py-2 text-sm font-medium text-white transition-all duration-150 hover:bg-brand-hover disabled:opacity-40"
        >
          <ShieldCheck size={14} />
          {generating ? "Generating..." : "Generate Proof"}
        </button>
      </form>
    </Card>
  );
}
