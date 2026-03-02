import { useFetch } from "@/hooks/use-fetch";
import { fetchStatus } from "@/api/endpoints/status";
import { POLLING_INTERVALS } from "@/lib/constants";
import { Skeleton } from "@/components/ui/Skeleton";
import { cn } from "@/lib/cn";
import { Server, Clock, Activity, Wifi } from "lucide-react";

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

export function StatusCard() {
  const { data, loading, error } = useFetch(fetchStatus, {
    pollInterval: POLLING_INTERVALS.STATUS,
  });

  if (loading && !data) {
    return (
      <div className="rounded-xl border border-border bg-surface px-5 py-4">
        <div className="flex items-center gap-4">
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-4 w-20" />
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex items-center gap-2 rounded-xl border border-danger/20 bg-danger-dim px-5 py-3 text-sm text-danger">
        <Wifi size={14} />
        <span>Unable to reach proxy</span>
      </div>
    );
  }

  const statusColor = data.running ? "bg-success" : "bg-danger";

  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-2 rounded-xl border border-border bg-surface px-5 py-3">
      {/* Status */}
      <div className="flex items-center gap-2 text-sm">
        <span
          className={cn(
            "inline-block h-2 w-2 rounded-full",
            statusColor,
            data.running && "status-pulse",
          )}
        />
        <span className="font-medium text-text">
          {data.running ? "Running" : "Stopped"}
        </span>
      </div>

      {/* Uptime */}
      <div className="flex items-center gap-1.5 text-sm text-text-secondary">
        <Clock size={13} className="text-text-tertiary" />
        <span>{formatUptime(data.uptime_seconds)}</span>
      </div>

      {/* Services */}
      <div className="flex items-center gap-1.5 text-sm text-text-secondary">
        <Activity size={13} className="text-text-tertiary" />
        <span>
          {data.active_services.length} service{data.active_services.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Port */}
      <div className="flex items-center gap-1.5 text-sm text-text-secondary">
        <Server size={13} className="text-text-tertiary" />
        <code className="rounded bg-bg-tertiary/60 px-1.5 py-0.5 font-mono text-xs text-text">
          localhost:{data.proxy_port}
        </code>
      </div>

      {/* Version */}
      <span className="ml-auto font-mono text-xs text-text-tertiary">
        v{data.version}
      </span>
    </div>
  );
}
