import { CircleCheck, Lock } from "lucide-react";
import { Toggle } from "@/components/ui/Toggle";
import { cn } from "@/lib/cn";
import type { ExchangeEndpoint, UpdateEndpointPayload } from "@/api/types";

const METHOD_COLORS: Record<string, string> = {
  GET: "bg-success/15 text-success",
  POST: "bg-info/15 text-info",
  PUT: "bg-warning/15 text-warning",
  DELETE: "bg-danger/15 text-danger",
};

interface EndpointRowProps {
  endpoint: ExchangeEndpoint;
  exchangeId: string;
  onToggle: (payload: UpdateEndpointPayload) => Promise<void>;
}

export function EndpointRow({ endpoint, exchangeId, onToggle }: EndpointRowProps) {
  const methodClass = METHOD_COLORS[endpoint.method] ?? "bg-bg-tertiary text-text-secondary";

  return (
    <div
      className={cn(
        "flex items-center gap-3 rounded-lg px-3 py-2.5 transition-colors",
        endpoint.permission === "permanently_blocked" && "opacity-40",
      )}
    >
      {/* Status icon */}
      {endpoint.permission === "always_allowed" && (
        <CircleCheck size={14} className="shrink-0 text-success" />
      )}
      {endpoint.permission === "permanently_blocked" && (
        <Lock size={14} className="shrink-0 text-danger" />
      )}
      {endpoint.permission === "toggleable" && (
        <Toggle
          checked={endpoint.enabled}
          onChange={(v) =>
            onToggle({
              exchange_id: exchangeId,
              endpoint_pattern: endpoint.pattern,
              enabled: v,
            })
          }
        />
      )}

      {/* Method badge */}
      <span
        className={cn(
          "shrink-0 rounded px-1.5 py-0.5 font-mono text-[10px] font-bold",
          methodClass,
        )}
      >
        {endpoint.method}
      </span>

      {/* Pattern */}
      <span className="flex-1 truncate font-mono text-xs text-text-secondary">
        {endpoint.pattern}
      </span>

      {/* Status label */}
      {endpoint.permission === "always_allowed" && (
        <span className="shrink-0 text-[11px] font-medium text-success">Always Allowed</span>
      )}
      {endpoint.permission === "permanently_blocked" && (
        <span
          className="shrink-0 text-[11px] font-medium text-danger"
          title="Withdrawals are hardcoded blocked and cannot be overridden. This is a core safety feature."
        >
          Blocked
        </span>
      )}
      {endpoint.permission === "toggleable" && (
        <span className={cn("shrink-0 text-[11px] font-medium", endpoint.enabled ? "text-success" : "text-text-tertiary")}>
          {endpoint.enabled ? "Allowed" : "Blocked"}
        </span>
      )}
    </div>
  );
}
