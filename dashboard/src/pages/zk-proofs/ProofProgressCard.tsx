import { CheckCircle2, XCircle, Loader2 } from "lucide-react";
import { cn } from "@/lib/cn";
import { Card } from "@/components/ui/Card";
import type { ProofJobStatus } from "@/api/types";

interface ProofProgressCardProps {
  progress: number;
  status: ProofJobStatus;
  error?: string | null;
}

export function ProofProgressCard({ progress, status, error }: ProofProgressCardProps) {
  const isActive = status === "pending" || status === "generating";
  const barColor =
    status === "failed"
      ? "bg-danger"
      : status === "completed"
        ? "bg-success"
        : "bg-brand";

  return (
    <Card>
      <div className="flex items-center gap-3">
        {isActive && <Loader2 size={16} className="shrink-0 animate-spin text-brand" />}
        {status === "completed" && <CheckCircle2 size={16} className="shrink-0 text-success" />}
        {status === "failed" && <XCircle size={16} className="shrink-0 text-danger" />}

        <div className="flex-1">
          <div className="flex items-center justify-between">
            <span
              className={cn(
                "text-sm font-medium",
                status === "completed" && "text-success",
                status === "failed" && "text-danger",
                isActive && "text-text",
              )}
            >
              {status === "pending" && "Pending..."}
              {status === "generating" && "Generating proof..."}
              {status === "completed" && "Proof ready"}
              {status === "failed" && "Generation failed"}
            </span>
            <span className="font-mono text-xs text-text-tertiary">{Math.round(progress)}%</span>
          </div>

          <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-bg-tertiary">
            <div
              className={cn(
                "h-full rounded-full transition-all duration-500 ease-out",
                barColor,
                isActive && "progress-glow-brand",
              )}
              style={{ width: `${Math.min(progress, 100)}%` }}
            />
          </div>

          {error && (
            <p className="mt-2 text-xs text-danger">{error}</p>
          )}
        </div>
      </div>
    </Card>
  );
}
