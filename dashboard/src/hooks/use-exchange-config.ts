import { useState, useCallback, useMemo } from "react";
import { useFetch } from "./use-fetch";
import {
  fetchExchangeConfig,
  addExchange,
  removeExchange,
  updateEndpointToggle,
  updateExchangeLimits,
} from "@/api/endpoints/exchange-config";
import type {
  Exchange,
  AddExchangePayload,
  UpdateEndpointPayload,
  UpdateExchangeLimitsPayload,
} from "@/api/types";

interface UseExchangeConfigReturn {
  exchanges: Exchange[];
  loading: boolean;
  error: Error | null;
  add: (payload: AddExchangePayload) => Promise<boolean>;
  remove: (id: string) => Promise<void>;
  toggleEndpoint: (payload: UpdateEndpointPayload) => Promise<void>;
  updateLimits: (payload: UpdateExchangeLimitsPayload) => Promise<void>;
  refetch: () => void;
}

export function useExchangeConfig(): UseExchangeConfigReturn {
  const { data, loading, error, refetch } = useFetch(fetchExchangeConfig);

  const [optimisticRemoved, setOptimisticRemoved] = useState<Set<string>>(
    new Set(),
  );

  const exchanges = useMemo(() => {
    if (!data) return [];
    return data.exchanges.filter((e) => !optimisticRemoved.has(e.id));
  }, [data, optimisticRemoved]);

  const add = useCallback(
    async (payload: AddExchangePayload): Promise<boolean> => {
      try {
        await addExchange(payload);
        refetch();
        return true;
      } catch {
        return false;
      }
    },
    [refetch],
  );

  const remove = useCallback(async (id: string) => {
    setOptimisticRemoved((prev) => new Set(prev).add(id));
    try {
      await removeExchange(id);
    } catch {
      setOptimisticRemoved((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  }, []);

  const toggleEndpoint = useCallback(
    async (payload: UpdateEndpointPayload) => {
      try {
        await updateEndpointToggle(payload);
        refetch();
      } catch {
        // silent fail — refetch to restore server state
        refetch();
      }
    },
    [refetch],
  );

  const updateLimitsHandler = useCallback(
    async (payload: UpdateExchangeLimitsPayload) => {
      try {
        await updateExchangeLimits(payload);
        refetch();
      } catch {
        refetch();
      }
    },
    [refetch],
  );

  return {
    exchanges,
    loading,
    error,
    add,
    remove,
    toggleEndpoint,
    updateLimits: updateLimitsHandler,
    refetch,
  };
}
