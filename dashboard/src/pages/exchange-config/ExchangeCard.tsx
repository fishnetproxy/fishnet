import { useState, useCallback } from "react";
import { Trash2 } from "lucide-react";
import { cn } from "@/lib/cn";
import { Card } from "@/components/ui/Card";
import { formatDollars } from "@/lib/format";
import { EndpointRow } from "./EndpointRow";
import { VolumeProgressBar } from "./VolumeProgressBar";
import type { Exchange, UpdateEndpointPayload, UpdateExchangeLimitsPayload } from "@/api/types";

interface ExchangeCardProps {
  exchange: Exchange;
  onToggleEndpoint: (payload: UpdateEndpointPayload) => Promise<void>;
  onUpdateLimits: (payload: UpdateExchangeLimitsPayload) => Promise<void>;
  onRemove: (id: string) => Promise<void>;
}

const STATUS_DOT: Record<string, string> = {
  connected: "bg-success shadow-[0_0_4px_rgba(34,197,94,0.4)]",
  disconnected: "bg-text-tertiary",
  error: "bg-danger shadow-[0_0_4px_rgba(239,68,68,0.4)]",
};

const STATUS_LABEL: Record<string, string> = {
  connected: "Connected",
  disconnected: "Disconnected",
  error: "Error",
};

export function ExchangeCard({
  exchange,
  onToggleEndpoint,
  onUpdateLimits,
  onRemove,
}: ExchangeCardProps) {
  const [confirming, setConfirming] = useState(false);

  const handleConfirmRemove = useCallback(() => {
    setConfirming(false);
    onRemove(exchange.id);
  }, [exchange.id, onRemove]);

  return (
    <Card hover={false}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className={cn("inline-block h-2 w-2 shrink-0 rounded-full", STATUS_DOT[exchange.status])} />
          <div>
            <h3 className="text-sm font-semibold text-text">{exchange.name}</h3>
            <p className="font-mono text-[11px] text-text-tertiary">{exchange.base_url}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-text-tertiary">{STATUS_LABEL[exchange.status]}</span>
          {confirming ? (
            <div className="flex items-center gap-2">
              <span className="text-[11px] text-danger">Remove?</span>
              <button
                onClick={handleConfirmRemove}
                className="rounded-md bg-danger/15 px-2 py-0.5 text-[11px] font-medium text-danger transition-colors hover:bg-danger/25"
              >
                Confirm
              </button>
              <button
                onClick={() => setConfirming(false)}
                className="rounded-md px-1.5 py-0.5 text-[11px] text-text-tertiary transition-colors hover:bg-surface-hover hover:text-text"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              onClick={() => setConfirming(true)}
              className="rounded-md p-1 text-text-tertiary transition-colors hover:bg-danger-dim hover:text-danger"
              title="Remove exchange"
            >
              <Trash2 size={13} />
            </button>
          )}
        </div>
      </div>

      {/* Endpoints */}
      <div className="mt-4 space-y-0.5 rounded-lg border border-border-subtle bg-bg-secondary/30 p-1">
        {exchange.endpoints.map((ep) => (
          <EndpointRow
            key={ep.pattern}
            endpoint={ep}
            exchangeId={exchange.id}
            onToggle={onToggleEndpoint}
          />
        ))}
      </div>

      {/* Volume + Limits */}
      <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
        <VolumeProgressBar
          current={exchange.volume.today_volume_usd}
          cap={exchange.volume.daily_cap_usd}
        />
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-xs">
            <span className="text-text-secondary">Max Order</span>
            <span className="font-mono text-text-tertiary">
              {formatDollars(exchange.limits.max_order_value_usd)}
            </span>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-text-secondary">Daily Cap</span>
            <span className="font-mono text-text-tertiary">
              {formatDollars(exchange.limits.daily_volume_cap_usd)}
            </span>
          </div>
        </div>
      </div>
    </Card>
  );
}
