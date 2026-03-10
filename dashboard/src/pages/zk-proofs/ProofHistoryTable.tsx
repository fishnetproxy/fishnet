import { FileSearch, Download } from "lucide-react";
import { cn } from "@/lib/cn";
import { Card } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useFetch } from "@/hooks/use-fetch";
import { fetchProofHistory, getProofDownloadUrl } from "@/api/endpoints/proofs";
import { truncateHash } from "@/lib/format";
import type { ProofResult } from "@/api/types";

const SPEND_BADGE: Record<string, { label: string; cls: string }> = {
  within_budget: { label: "Within Budget", cls: "bg-success/15 text-success" },
  over_budget: { label: "Over Budget", cls: "bg-danger/15 text-danger" },
  no_data: { label: "No Data", cls: "bg-bg-tertiary text-text-tertiary" },
};

function ProofHistoryRow({ proof }: { proof: ProofResult }) {
  const badge = SPEND_BADGE[proof.spend_status] ?? SPEND_BADGE.no_data;

  return (
    <tr className="border-b border-border-subtle transition-colors duration-150 hover:bg-surface-hover">
      <td className="py-3 pl-5 pr-3">
        <span className="text-sm text-text">
          {proof.from_date} — {proof.to_date}
        </span>
      </td>
      <td className="py-3 pr-3">
        <span className="font-mono text-xs text-text-secondary">
          {proof.entries_covered.toLocaleString()}
        </span>
      </td>
      <td className="py-3 pr-3">
        <code className="font-mono text-xs text-text-tertiary">
          {truncateHash(proof.merkle_root, 8)}
        </code>
      </td>
      <td className="py-3 pr-3">
        <span className={cn("inline-block rounded-md px-2 py-0.5 text-[10px] font-medium", badge.cls)}>
          {badge.label}
        </span>
      </td>
      <td className="py-3 pr-5">
        <a
          href={getProofDownloadUrl(proof.id)}
          target="_blank"
          rel="noopener noreferrer"
          className="rounded-md p-1 text-text-tertiary transition-colors hover:text-brand"
          title="Download proof"
        >
          <Download size={13} />
        </a>
      </td>
    </tr>
  );
}

export function ProofHistoryTable() {
  const { data, loading } = useFetch(fetchProofHistory);

  if (loading) return <SkeletonCard />;

  const proofs = data?.proofs ?? [];

  if (proofs.length === 0) {
    return (
      <EmptyState
        icon={<FileSearch size={24} className="text-text-tertiary" />}
        title="No proof history"
        subtitle="Generated proofs will appear here."
      />
    );
  }

  return (
    <Card
      title={`Proof History (${proofs.length})`}
      padding={false}
      hover={false}
    >
      <table className="w-full text-left">
        <thead>
          <tr className="border-b border-border-subtle">
            <th className="py-2.5 pl-5 pr-3 text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
              Date Range
            </th>
            <th className="py-2.5 pr-3 text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
              Entries
            </th>
            <th className="py-2.5 pr-3 text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
              Merkle Root
            </th>
            <th className="py-2.5 pr-3 text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
              Status
            </th>
            <th className="py-2.5 pr-5 text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
              <span className="sr-only">Download</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {proofs.map((proof) => (
            <ProofHistoryRow key={proof.id} proof={proof} />
          ))}
        </tbody>
      </table>
    </Card>
  );
}
