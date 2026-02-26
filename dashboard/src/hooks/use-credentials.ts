import { useState, useCallback, useMemo } from "react";
import { useFetch } from "./use-fetch";
import {
  fetchCredentials,
  createCredential,
  deleteCredential,
} from "@/api/endpoints/credentials";
import type { Credential, CreateCredentialPayload } from "@/api/types";

interface UseCredentialsReturn {
  credentials: Credential[];
  loading: boolean;
  error: Error | null;
  add: (payload: CreateCredentialPayload) => Promise<boolean>;
  remove: (id: string) => Promise<void>;
  refetch: () => void;
}

export function useCredentials(): UseCredentialsReturn {
  const { data, loading, error, refetch } = useFetch(fetchCredentials);

  const [optimisticRemoved, setOptimisticRemoved] = useState<Set<string>>(
    new Set(),
  );

  const credentials = useMemo(() => {
    if (!data) return [];
    return data.credentials
      .filter((c) => !optimisticRemoved.has(c.id))
      .sort(
        (a, b) =>
          new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
      );
  }, [data, optimisticRemoved]);

  const add = useCallback(
    async (payload: CreateCredentialPayload): Promise<boolean> => {
      try {
        await createCredential(payload);
        refetch();
        return true;
      } catch {
        return false;
      }
    },
    [refetch],
  );

  const remove = useCallback(
    async (id: string) => {
      setOptimisticRemoved((prev) => new Set(prev).add(id));
      try {
        await deleteCredential(id);
      } catch {
        setOptimisticRemoved((prev) => {
          const next = new Set(prev);
          next.delete(id);
          return next;
        });
      }
    },
    [],
  );

  return { credentials, loading, error, add, remove, refetch };
}
