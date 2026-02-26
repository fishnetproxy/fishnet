import { useState, useCallback } from "react";
import { cn } from "@/lib/cn";
import { Card } from "@/components/ui/Card";
import { Toggle } from "@/components/ui/Toggle";
import { useFetch } from "@/hooks/use-fetch";
import { fetchNetworkIsolation, updateNetworkIsolation } from "@/api/endpoints/settings";

export function NetworkIsolationCard() {
  const { data, loading } = useFetch(fetchNetworkIsolation);
  const [localEnabled, setLocalEnabled] = useState<boolean | null>(null);

  const enabled = localEnabled ?? data?.enabled ?? false;
  const status = data?.status ?? "inactive";

  const handleToggle = useCallback(
    async (value: boolean) => {
      const prev = enabled;
      setLocalEnabled(value);
      try {
        await updateNetworkIsolation(value);
      } catch {
        setLocalEnabled(prev);
      }
    },
    [enabled],
  );

  return (
    <Card title="Network Isolation">
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span
              className={cn(
                "inline-block h-2 w-2 rounded-full",
                status === "active"
                  ? "bg-success shadow-[0_0_4px_rgba(34,197,94,0.4)]"
                  : status === "error"
                    ? "bg-danger"
                    : "bg-text-tertiary",
              )}
            />
            <div>
              <p className="text-sm font-medium text-text">Firewall</p>
              <p className="text-xs text-text-secondary capitalize">{status}</p>
            </div>
          </div>
          <Toggle
            checked={enabled}
            onChange={handleToggle}
            disabled={loading}
          />
        </div>

        <p className="text-xs leading-relaxed text-text-tertiary">
          When enabled, all outbound network traffic from the Fishnet proxy is blocked except
          for configured exchange endpoints and whitelisted addresses. Your AI agent can only
          reach localhost.
        </p>
      </div>
    </Card>
  );
}
