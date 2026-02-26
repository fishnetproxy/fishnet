import { useState, useCallback } from "react";
import { Trash2 } from "lucide-react";
import { cn } from "@/lib/cn";
import { timeAgo } from "@/lib/format";
import { SERVICE_LABELS, SERVICE_DOT_CLASSES } from "@/lib/constants";
import type { Credential } from "@/api/types";

interface CredentialRowProps {
  credential: Credential;
  onRemove: (id: string) => void;
}

export function CredentialRow({ credential, onRemove }: CredentialRowProps) {
  const [confirming, setConfirming] = useState(false);

  const handleConfirmRemove = useCallback(() => {
    setConfirming(false);
    onRemove(credential.id);
  }, [credential.id, onRemove]);

  const serviceLabel =
    SERVICE_LABELS[credential.service as keyof typeof SERVICE_LABELS] ??
    credential.service;

  const dotClass =
    SERVICE_DOT_CLASSES[credential.service] ?? "bg-text-tertiary";

  return (
    <tr className="group border-b border-border-subtle transition-colors duration-150 hover:bg-surface-hover">
      {/* Service */}
      <td className="py-3 pl-5 pr-3">
        <div className="flex items-center gap-2.5">
          <span
            className={cn("inline-block h-2 w-2 shrink-0 rounded-full", dotClass)}
          />
          <span className="text-sm text-text">{serviceLabel}</span>
        </div>
      </td>

      {/* Name */}
      <td className="py-3 pr-3">
        <span className="text-sm text-text-secondary">{credential.name}</span>
      </td>

      {/* Created */}
      <td className="py-3 pr-3">
        <span className="font-mono text-xs text-text-tertiary">
          {timeAgo(credential.created_at)}
        </span>
      </td>

      {/* Last Used */}
      <td className="py-3 pr-3">
        <span className="font-mono text-xs text-text-tertiary">
          {credential.last_used_at ? timeAgo(credential.last_used_at) : "Never"}
        </span>
      </td>

      {/* Action */}
      <td className="py-3 pr-5">
        {confirming ? (
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-danger">Remove?</span>
            <button
              onClick={handleConfirmRemove}
              className="rounded-md bg-danger/15 px-2 py-0.5 text-[11px] font-medium text-danger transition-colors hover:bg-danger/25"
            >
              Confirm
            </button>
            <button
              onClick={() => setConfirming(false)}
              className="rounded-md px-1.5 py-0.5 text-[11px] text-text-tertiary transition-colors hover:bg-surface-hover hover:text-text"
            >
              Cancel
            </button>
          </div>
        ) : (
          <button
            onClick={() => setConfirming(true)}
            className="rounded-md p-1 text-text-tertiary opacity-0 transition-all group-hover:opacity-100 hover:bg-danger-dim hover:text-danger"
            title="Remove credential"
          >
            <Trash2 size={13} />
          </button>
        )}
      </td>
    </tr>
  );
}
