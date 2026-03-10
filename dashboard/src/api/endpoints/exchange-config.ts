import { apiFetch } from "../client";
import type {
  ExchangeConfigResponse,
  AddExchangePayload,
  UpdateEndpointPayload,
  UpdateExchangeLimitsPayload,
} from "../types";

export function fetchExchangeConfig(): Promise<ExchangeConfigResponse> {
  return apiFetch<ExchangeConfigResponse>("/exchange-config");
}

export function addExchange(
  payload: AddExchangePayload,
): Promise<{ success: boolean }> {
  return apiFetch("/exchange-config", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function removeExchange(
  id: string,
): Promise<{ success: boolean }> {
  return apiFetch(`/exchange-config/${id}`, { method: "DELETE" });
}

export function updateEndpointToggle(
  payload: UpdateEndpointPayload,
): Promise<{ success: boolean }> {
  return apiFetch("/exchange-config/endpoint", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function updateExchangeLimits(
  payload: UpdateExchangeLimitsPayload,
): Promise<{ success: boolean }> {
  return apiFetch(`/exchange-config/${payload.exchange_id}/limits`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}
