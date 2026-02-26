import { apiFetch } from "../client";
import { API_BASE } from "@/lib/constants";
import type {
  ProofGeneratePayload,
  ProofGenerateResponse,
  ProofJobStatusResponse,
  ProofHistoryResponse,
} from "../types";

export function generateProof(
  payload: ProofGeneratePayload,
): Promise<ProofGenerateResponse> {
  return apiFetch<ProofGenerateResponse>(
    `/proof/generate?from=${payload.from_date}&to=${payload.to_date}`,
    { method: "POST" },
  );
}

export function fetchProofJobStatus(
  jobId: string,
): Promise<ProofJobStatusResponse> {
  return apiFetch<ProofJobStatusResponse>(`/proof/${jobId}`);
}

export function fetchProofHistory(): Promise<ProofHistoryResponse> {
  return apiFetch<ProofHistoryResponse>("/proof/history");
}

export function getProofDownloadUrl(proofId: string): string {
  return `${API_BASE}/proof/${proofId}/download`;
}
