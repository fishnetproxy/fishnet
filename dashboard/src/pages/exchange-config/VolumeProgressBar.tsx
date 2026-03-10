import { cn } from "@/lib/cn";
import { formatDollars } from "@/lib/format";

interface VolumeProgressBarProps {
  current: number;
  cap: number;
}

export function VolumeProgressBar({ current, cap }: VolumeProgressBarProps) {
  const pct = cap > 0 ? (current / cap) * 100 : 0;
  const barColor =
    pct > 90 ? "bg-danger" : pct > 70 ? "bg-warning" : "bg-brand";

  return (
    <div>
      <div className="flex items-center justify-between text-xs">
        <span className="text-text-secondary">Today's Volume</span>
        <span className="font-mono text-text-tertiary">
          {formatDollars(current)} / {formatDollars(cap)}
        </span>
      </div>
      <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-bg-tertiary">
        <div
          className={cn("h-full rounded-full transition-all duration-700 ease-out", barColor)}
          style={{ width: `${Math.min(pct, 100)}%` }}
        />
      </div>
    </div>
  );
}
