import { useState, useMemo, useCallback } from "react";
import { Shield, X, ChevronLeft, ChevronRight } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Skeleton } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import { useFetch } from "@/hooks/use-fetch";
import { fetchAlerts } from "@/api/endpoints/alerts";
import { POLLING_INTERVALS } from "@/lib/constants";
import { useAlertsContext } from "@/context/alerts-context";
import { AlertRow } from "./AlertRow";
import { AlertFilters } from "./AlertFilters";
import { WebhookConfigCard } from "./WebhookConfigCard";
import type { StatusFilter } from "./AlertFilters";
import type { AlertType, AlertSeverity } from "@/api/types";

const PAGE_SIZE = 20;

export default function AlertsPage() {
  const {
    undismissed,
    dismiss: ctxDismiss,
    dismissBulk: ctxDismissBulk,
  } = useAlertsContext();

  // Filter state
  const [typeFilter, setTypeFilter] = useState<AlertType | "all">("all");
  const [severityFilter, setSeverityFilter] = useState<AlertSeverity | "all">(
    "all",
  );
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");

  // Pagination state
  const [page, setPage] = useState(0);

  // Selection state
  const [selected, setSelected] = useState<Set<string>>(new Set());

  // Local optimistic dismiss set (page-scoped)
  const [localDismissed, setLocalDismissed] = useState<Set<string>>(new Set());

  // Compute server-side params
  const apiType = typeFilter === "all" ? undefined : typeFilter;
  const apiDismissed =
    statusFilter === "all"
      ? undefined
      : statusFilter === "dismissed"
        ? true
        : false;

  // Page-local fetch with server-side filtering + pagination
  const { data, loading } = useFetch(
    () =>
      fetchAlerts({
        type: apiType,
        dismissed: apiDismissed,
        limit: PAGE_SIZE,
        skip: page * PAGE_SIZE,
      }),
    {
      deps: [apiType, apiDismissed, page],
      pollInterval: POLLING_INTERVALS.ALERTS,
    },
  );

  // Merge optimistic dismissals + apply client-side severity filter
  const pageAlerts = useMemo(() => {
    if (!data) return [];
    return data.alerts
      .map((a) => (localDismissed.has(a.id) ? { ...a, dismissed: true } : a))
      .filter((a) => severityFilter === "all" || a.severity === severityFilter)
      .sort((a, b) => {
        // Active alerts first, dismissed at the bottom
        if (a.dismissed !== b.dismissed) return a.dismissed ? 1 : -1;
        return b.timestamp - a.timestamp;
      });
  }, [data, localDismissed, severityFilter]);

  const hasNextPage = (data?.alerts.length ?? 0) === PAGE_SIZE;
  const hasPrevPage = page > 0;

  // --- Handlers ---

  const handleTypeChange = useCallback((v: AlertType | "all") => {
    setTypeFilter(v);
    setPage(0);
    setSelected(new Set());
    setLocalDismissed(new Set());
  }, []);

  const handleStatusChange = useCallback((v: StatusFilter) => {
    setStatusFilter(v);
    setPage(0);
    setSelected(new Set());
    setLocalDismissed(new Set());
  }, []);

  const handleSeverityChange = useCallback((v: AlertSeverity | "all") => {
    setSeverityFilter(v);
  }, []);

  const dismiss = useCallback(
    async (id: string) => {
      setLocalDismissed((prev) => new Set(prev).add(id));
      await ctxDismiss(id);
    },
    [ctxDismiss],
  );

  const handleBulkDismiss = useCallback(async () => {
    const ids = Array.from(selected);
    if (ids.length === 0) return;
    setLocalDismissed((prev) => {
      const next = new Set(prev);
      for (const id of ids) next.add(id);
      return next;
    });
    await ctxDismissBulk(ids);
    setSelected(new Set());
  }, [selected, ctxDismissBulk]);

  const toggleSelect = useCallback((id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const selectAllActive = useCallback(() => {
    const activeIds = pageAlerts.filter((a) => !a.dismissed).map((a) => a.id);
    setSelected(new Set(activeIds));
  }, [pageAlerts]);

  const clearSelection = useCallback(() => setSelected(new Set()), []);

  const goNextPage = useCallback(() => {
    setPage((p) => p + 1);
    setSelected(new Set());
  }, []);

  const goPrevPage = useCallback(() => {
    setPage((p) => p - 1);
    setSelected(new Set());
  }, []);

  const activeCount = undismissed.length;
  const hasActive = pageAlerts.some((a) => !a.dismissed);

  if (loading && !data) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-full rounded-lg" />
        <Skeleton className="h-[480px] w-full rounded-xl" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Webhook config */}
      <WebhookConfigCard />

      {/* Toolbar: count + bulk actions */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-text-secondary">
          {activeCount > 0 ? (
            <>
              <span className="font-semibold text-text">{activeCount}</span>{" "}
              active alert{activeCount !== 1 ? "s" : ""}
            </>
          ) : (
            "No active alerts"
          )}
        </p>

        {selected.size > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-text-tertiary">
              {selected.size} selected
            </span>
            <button
              onClick={handleBulkDismiss}
              className="rounded-lg bg-brand px-3 py-1.5 text-xs font-medium text-white transition-all duration-150 hover:bg-brand-hover"
            >
              Dismiss Selected
            </button>
            <button
              onClick={clearSelection}
              className="rounded-lg px-2 py-1.5 text-xs text-text-tertiary transition-all duration-150 hover:bg-surface-hover hover:text-text"
            >
              <X size={14} />
            </button>
          </div>
        )}
      </div>

      {/* Filter bar */}
      <AlertFilters
        typeFilter={typeFilter}
        severityFilter={severityFilter}
        statusFilter={statusFilter}
        onTypeChange={handleTypeChange}
        onSeverityChange={handleSeverityChange}
        onStatusChange={handleStatusChange}
        hasActive={hasActive}
        onSelectAllActive={selectAllActive}
      />

      {/* Alert table */}
      {pageAlerts.length === 0 ? (
        <EmptyState
          icon={<Shield size={24} className="text-text-tertiary" />}
          title="No alerts"
          subtitle="Fishnet is monitoring your agent."
        />
      ) : (
        <Card padding={false} hover={false}>
          {/* Scrollable table body with sticky header */}
          <div className="max-h-[calc(100vh-320px)] overflow-y-auto">
            <table className="w-full table-fixed">
              <colgroup>
                <col className="w-10" />
                <col className="w-8" />
                <col className="w-32" />
                <col />
                <col className="w-24" />
                <col className="w-24" />
                <col className="w-20" />
                <col className="w-20" />
              </colgroup>
              <thead className="sticky top-0 z-10 bg-surface">
                <tr className="border-b border-border">
                  <th className="py-3 pl-5 pr-0 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary" />
                  <th className="py-3 pr-0 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary" />
                  <th className="py-3 pr-3 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary">
                    Type
                  </th>
                  <th className="py-3 pr-3 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary">
                    Message
                  </th>
                  <th className="py-3 pr-3 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary">
                    Service
                  </th>
                  <th className="py-3 pr-3 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary">
                    Time
                  </th>
                  <th className="py-3 pr-3 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary">
                    Status
                  </th>
                  <th className="py-3 pr-5 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary" />
                </tr>
              </thead>
              <tbody>
                {pageAlerts.map((alert) => (
                  <AlertRow
                    key={alert.id}
                    alert={alert}
                    isSelected={selected.has(alert.id)}
                    onToggleSelect={toggleSelect}
                    onDismiss={dismiss}
                  />
                ))}
              </tbody>
            </table>
          </div>

          {/* Footer with pagination */}
          <div className="flex items-center justify-between border-t border-border px-5 py-3">
            <p className="text-xs tabular-nums text-text-tertiary">
              Showing {pageAlerts.length} alert
              {pageAlerts.length !== 1 ? "s" : ""}
            </p>

            <div className="flex items-center gap-1.5">
              <button
                onClick={goPrevPage}
                disabled={!hasPrevPage}
                className="flex items-center gap-0.5 rounded-md px-2 py-1 text-xs font-medium text-text-secondary transition-colors hover:bg-surface-hover disabled:pointer-events-none disabled:opacity-30"
              >
                <ChevronLeft size={14} />
                Prev
              </button>
              <span className="px-2 text-xs tabular-nums text-text-tertiary">
                Page {page + 1}
              </span>
              <button
                onClick={goNextPage}
                disabled={!hasNextPage}
                className="flex items-center gap-0.5 rounded-md px-2 py-1 text-xs font-medium text-text-secondary transition-colors hover:bg-surface-hover disabled:pointer-events-none disabled:opacity-30"
              >
                Next
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
