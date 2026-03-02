import { apiFetch } from "../client";
import type { StatusResponse } from "../types";

export function fetchStatus(): Promise<StatusResponse> {
  return apiFetch<StatusResponse>("/status");
}
