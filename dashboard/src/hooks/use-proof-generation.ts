import { useState, useEffect, useCallback, useRef } from "react";
import { generateProof, fetchProofJobStatus } from "@/api/endpoints/proofs";
import { POLLING_INTERVALS } from "@/lib/constants";
import type { ProofJobStatus } from "@/api/types";

interface UseProofGenerationReturn {
  generating: boolean;
  jobId: string | null;
  progress: number;
  status: ProofJobStatus | null;
  error: string | null;
  generate: (from: string, to: string) => Promise<void>;
  reset: () => void;
}

export function useProofGeneration(): UseProofGenerationReturn {
  const [jobId, setJobId] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState<ProofJobStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // Poll for job status
  useEffect(() => {
    if (!jobId || status === "completed" || status === "failed") return;

    const poll = async () => {
      try {
        const res = await fetchProofJobStatus(jobId);
        if (!mountedRef.current) return;
        setProgress(res.progress_pct);
        setStatus(res.status);
        if (res.error) setError(res.error);
      } catch {
        // Swallow polling errors
      }
    };

    const id = setInterval(poll, POLLING_INTERVALS.PROOF_JOB);
    poll(); // immediate first poll
    return () => clearInterval(id);
  }, [jobId, status]);

  const generating = status === "pending" || status === "generating";

  const generate = useCallback(async (from: string, to: string) => {
    setError(null);
    setProgress(0);
    setStatus("pending");
    try {
      const res = await generateProof({ from_date: from, to_date: to });
      if (mountedRef.current) {
        setJobId(res.job_id);
      }
    } catch (err) {
      if (mountedRef.current) {
        setError(err instanceof Error ? err.message : "Failed to start proof generation");
        setStatus("failed");
      }
    }
  }, []);

  const reset = useCallback(() => {
    setJobId(null);
    setProgress(0);
    setStatus(null);
    setError(null);
  }, []);

  return { generating, jobId, progress, status, error, generate, reset };
}
