import { useState, useCallback } from "react";
import { Copy, Check } from "lucide-react";
import { useToast } from "@/context/toast-context";

const CONFIG_TEXT = `OPENAI_BASE_URL=http://localhost:8472/openai
ANTHROPIC_BASE_URL=http://localhost:8472/anthropic`;

export function CopyConfigCard() {
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(CONFIG_TEXT);
      setCopied(true);
      toast("Copied! Paste into your OpenClaw .env", "success");
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast("Failed to copy", "error");
    }
  }, [toast]);

  return (
    <div className="rounded-xl border border-border bg-surface p-5">
      <div className="flex items-center justify-between">
        <h3 className="text-[13px] font-semibold tracking-wide text-text">
          Agent Configuration
        </h3>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs font-medium text-text-secondary transition-colors hover:bg-surface-hover hover:text-text"
        >
          {copied ? (
            <>
              <Check size={13} className="text-success" />
              Copied
            </>
          ) : (
            <>
              <Copy size={13} />
              Copy to Clipboard
            </>
          )}
        </button>
      </div>
      <div className="mt-3 rounded-lg bg-bg-tertiary p-4">
        <code className="block whitespace-pre font-mono text-xs leading-relaxed text-text">
          {CONFIG_TEXT}
        </code>
      </div>
      <p className="mt-2 text-xs text-text-tertiary">
        Add these to your agent's environment to route API calls through Fishnet.
      </p>
    </div>
  );
}
