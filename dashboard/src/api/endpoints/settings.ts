import { apiFetch, TOKEN_KEY } from "../client";
import { API_BASE } from "@/lib/constants";
import type {
  ChangePasswordPayload,
  VaultBackupResponse,
  NetworkIsolationResponse,
  SignerModeResponse,
  SignerModeType,
  FactoryResetResponse,
} from "../types";

export function changePassword(
  payload: ChangePasswordPayload,
): Promise<{ success: boolean }> {
  return apiFetch("/settings/password", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function fetchVaultBackupUrl(): Promise<VaultBackupResponse> {
  return apiFetch<VaultBackupResponse>("/settings/vault/backup");
}

export async function restoreVault(
  file: File,
): Promise<{ success: boolean }> {
  const token = localStorage.getItem(TOKEN_KEY);
  const form = new FormData();
  form.append("file", file);

  const res = await fetch(`${API_BASE}/settings/vault/restore`, {
    method: "POST",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: form,
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(body.error ?? "Restore failed");
  }

  return res.json();
}

export function fetchNetworkIsolation(): Promise<NetworkIsolationResponse> {
  return apiFetch<NetworkIsolationResponse>("/settings/network-isolation");
}

export function updateNetworkIsolation(
  enabled: boolean,
): Promise<NetworkIsolationResponse> {
  return apiFetch<NetworkIsolationResponse>("/settings/network-isolation", {
    method: "PUT",
    body: JSON.stringify({ enabled }),
  });
}

export function fetchSignerMode(): Promise<SignerModeResponse> {
  return apiFetch<SignerModeResponse>("/settings/signer-mode");
}

export function updateSignerMode(
  mode: SignerModeType,
): Promise<SignerModeResponse> {
  return apiFetch<SignerModeResponse>("/settings/signer-mode", {
    method: "PUT",
    body: JSON.stringify({ mode }),
  });
}

export function factoryReset(
  confirmToken: string,
): Promise<FactoryResetResponse> {
  return apiFetch<FactoryResetResponse>("/settings/factory-reset", {
    method: "POST",
    body: JSON.stringify({ confirm: confirmToken }),
  });
}
