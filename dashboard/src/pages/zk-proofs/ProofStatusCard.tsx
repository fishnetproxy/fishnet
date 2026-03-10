import { useState, useCallback } from "react";
import { Download, Copy, Check } from "lucide-react";
import { cn } from "@/lib/cn";
import { Card } from "@/components/ui/Card";
import { Skeleton } from "@/components/ui/Skeleton";
import { timeAgoUnix, truncateHash } from "@/lib/format";
import type { ProofResult } from "@/api/types";

interface ProofStatusCardProps {
  proof: ProofResult | null;
  loading: boolean;
}

const SPEND_BADGE: Record<string, { label: string; cls: string }> = {
  within_budget: { label: "Within Budget", cls: "bg-success/15 text-success" },
  over_budget: { label: "Over Budget", cls: "bg-danger/15 text-danger" },
  no_data: { label: "No Data", cls: "bg-bg-tertiary text-text-tertiary" },
};

function CopyableHash({ hash }: { hash: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(hash);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, [hash]);

  return (
    <button onClick={handleCopy} className="group/hash flex items-center gap-1.5">
      <code className="font-mono text-xs text-text transition-colors group-hover/hash:text-brand">
        {truncateHash(hash, 8)}
      </code>
      {copied ? (
        <Check size={10} className="text-success" />
      ) : (
        <Copy size={10} className="text-text-tertiary opacity-0 transition-opacity group-hover/hash:opacity-100" />
      )}
    </button>
  );
}

export function ProofStatusCard({ proof, loading }: ProofStatusCardProps) {
  if (loading) {
    return (
      <Card title="Latest Proof">
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
          <Skeleton className="h-12" />
          <Skeleton className="h-12" />
          <Skeleton className="h-12" />
        </div>
      </Card>
    );
  }

  if (!proof) {
    return (
      <Card title="Latest Proof">
        <p className="text-sm text-text-tertiary">No proofs generated yet.</p>
      </Card>
    );
  }

  const badge = SPEND_BADGE[proof.spend_status] ?? SPEND_BADGE.no_data;

  return (
    <Card title="Latest Proof">
      <div className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-3">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">Last Generated</p>
          <p className="mt-1 text-sm text-text">{timeAgoUnix(proof.generated_at)}</p>
        </div>
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">Entries Covered</p>
          <p className="mt-1 font-mono text-sm text-text">{proof.entries_covered.toLocaleString()}</p>
        </div>
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">Spend Status</p>
          <span className={cn("mt-1 inline-block rounded-md px-2 py-0.5 text-[11px] font-medium", badge.cls)}>
            {badge.label}
          </span>
        </div>
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">Merkle Root</p>
          <div className="mt-1">
            <CopyableHash hash={proof.merkle_root} />
          </div>
        </div>
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">Policy Hash</p>
          <div className="mt-1">
            <CopyableHash hash={proof.policy_hash} />
          </div>
        </div>
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">Download</p>
          <a
            href={proof.download_url}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-1 inline-flex items-center gap-1 text-sm text-brand transition-colors hover:text-brand-hover"
          >
            <Download size={12} />
            proof.json
          </a>
        </div>
      </div>
    </Card>
  );
}
