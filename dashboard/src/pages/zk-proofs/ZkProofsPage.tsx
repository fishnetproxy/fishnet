import { useFetch } from "@/hooks/use-fetch";
import { useProofGeneration } from "@/hooks/use-proof-generation";
import { fetchProofHistory } from "@/api/endpoints/proofs";
import { ProofGenerateForm } from "./ProofGenerateForm";
import { ProofProgressCard } from "./ProofProgressCard";
import { ProofStatusCard } from "./ProofStatusCard";
import { ProofHistoryTable } from "./ProofHistoryTable";

export default function ZkProofsPage() {
  const { generating, progress, status, error, generate } = useProofGeneration();
  const { data: history, loading: historyLoading } = useFetch(fetchProofHistory);

  const latestProof = history?.proofs?.[0] ?? null;

  return (
    <div className="space-y-6">
      <ProofGenerateForm onGenerate={generate} generating={generating} />

      {status && (
        <ProofProgressCard
          progress={progress}
          status={status}
          error={error}
        />
      )}

      <ProofStatusCard proof={latestProof} loading={historyLoading} />

      <ProofHistoryTable />
    </div>
  );
}
