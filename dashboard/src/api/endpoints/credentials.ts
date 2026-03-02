import { apiFetch } from "../client";
import type {
  CredentialsResponse,
  CreateCredentialPayload,
  Credential,
} from "../types";

export function fetchCredentials(): Promise<CredentialsResponse> {
  return apiFetch<CredentialsResponse>("/credentials");
}

export function createCredential(
  payload: CreateCredentialPayload,
): Promise<Credential> {
  return apiFetch<Credential>("/credentials", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function deleteCredential(id: string): Promise<{ success: boolean }> {
  return apiFetch<{ success: boolean }>(`/credentials/${id}`, {
    method: "DELETE",
  });
}
