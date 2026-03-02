import { useState, useCallback } from "react";
import { Webhook, Send, Loader2, Check } from "lucide-react";
import { cn } from "@/lib/cn";
import { Card } from "@/components/ui/Card";
import { useFetch } from "@/hooks/use-fetch";
import {
  fetchWebhookConfig,
  updateWebhookConfig,
  testWebhook,
} from "@/api/endpoints/alerts";

export function WebhookConfigCard() {
  const { data, loading } = useFetch(fetchWebhookConfig);
  const [url, setUrl] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<"success" | "error" | null>(
    null,
  );

  const currentUrl = url ?? data?.webhook?.url ?? "";
  const configured = Boolean(data?.webhook?.url);

  const handleSave = useCallback(async () => {
    if (!currentUrl.trim() || saving) return;
    setSaving(true);
    try {
      await updateWebhookConfig(currentUrl.trim());
    } catch {
      // Best effort
    }
    setSaving(false);
  }, [currentUrl, saving]);

  const handleTest = useCallback(async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await testWebhook();
      setTestResult(res.success ? "success" : "error");
    } catch {
      setTestResult("error");
    }
    setTesting(false);
    setTimeout(() => setTestResult(null), 3000);
  }, []);

  return (
    <Card title="Webhook Notifications">
      <div className="space-y-4">
        <div className="flex items-center gap-2 text-sm text-text-secondary">
          <Webhook size={14} className="text-text-tertiary" />
          <span>
            Send alerts to Discord or Slack via webhook.
          </span>
          {configured && (
            <span className="ml-auto flex items-center gap-1.5 text-xs text-success">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-success" />
              Configured
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <input
            type="url"
            value={currentUrl}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://hooks.slack.com/services/..."
            disabled={loading}
            className="flex-1 rounded-lg border border-border bg-surface-input px-3 py-2 text-sm text-text placeholder:text-text-tertiary/50 focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand/20"
          />
          <button
            onClick={handleSave}
            disabled={saving || !currentUrl.trim()}
            className={cn(
              "shrink-0 rounded-lg bg-brand px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-brand-hover disabled:opacity-40",
            )}
          >
            {saving ? (
              <Loader2 size={14} className="animate-spin" />
            ) : (
              "Save"
            )}
          </button>
        </div>

        {configured && (
          <button
            onClick={handleTest}
            disabled={testing}
            className="flex items-center gap-1.5 text-xs text-text-tertiary transition-colors hover:text-text"
          >
            {testing ? (
              <Loader2 size={12} className="animate-spin" />
            ) : testResult === "success" ? (
              <Check size={12} className="text-success" />
            ) : (
              <Send size={12} />
            )}
            {testResult === "success"
              ? "Sent!"
              : testResult === "error"
                ? "Failed"
                : "Send Test"}
          </button>
        )}
      </div>
    </Card>
  );
}
