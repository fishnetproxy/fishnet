import { apiFetch } from "../client";
import type {
  AlertsResponse,
  AlertsQueryParams,
  DismissAlertResponse,
  AlertConfigResponse,
  AlertConfigUpdatePayload,
  AlertConfigUpdateResponse,
  WebhookConfigResponse,
  WebhookTestResponse,
} from "../types";

function buildAlertQuery(params?: AlertsQueryParams): string {
  if (!params) return "";
  const sp = new URLSearchParams();
  if (params.type !== undefined) sp.set("type", params.type);
  if (params.dismissed !== undefined) sp.set("dismissed", String(params.dismissed));
  if (params.limit !== undefined) sp.set("limit", String(params.limit));
  if (params.skip !== undefined) sp.set("skip", String(params.skip));
  const qs = sp.toString();
  return qs ? `?${qs}` : "";
}

export function fetchAlerts(params?: AlertsQueryParams): Promise<AlertsResponse> {
  return apiFetch<AlertsResponse>(`/alerts${buildAlertQuery(params)}`);
}

export function dismissAlert(id: string): Promise<DismissAlertResponse> {
  return apiFetch<DismissAlertResponse>("/alerts/dismiss", {
    method: "POST",
    body: JSON.stringify({ id }),
  });
}

export function fetchAlertConfig(): Promise<AlertConfigResponse> {
  return apiFetch<AlertConfigResponse>("/alerts/config");
}

export function updateAlertConfig(
  payload: AlertConfigUpdatePayload,
): Promise<AlertConfigUpdateResponse> {
  return apiFetch<AlertConfigUpdateResponse>("/alerts/config", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function fetchWebhookConfig(): Promise<WebhookConfigResponse> {
  return apiFetch<WebhookConfigResponse>("/alerts/webhook");
}

export function updateWebhookConfig(url: string): Promise<WebhookConfigResponse> {
  return apiFetch<WebhookConfigResponse>("/alerts/webhook", {
    method: "PUT",
    body: JSON.stringify({ url }),
  });
}

export function testWebhook(): Promise<WebhookTestResponse> {
  return apiFetch<WebhookTestResponse>("/alerts/webhook/test", {
    method: "POST",
  });
}
