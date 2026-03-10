import { useState, useCallback } from "react";
import { Fingerprint, FileKey, Users } from "lucide-react";
import { cn } from "@/lib/cn";
import { Card } from "@/components/ui/Card";
import { useFetch } from "@/hooks/use-fetch";
import { fetchSignerMode, updateSignerMode } from "@/api/endpoints/settings";
import type { SignerModeType } from "@/api/types";

interface ModeOption {
  value: SignerModeType;
  label: string;
  description: string;
  icon: React.ReactNode;
}

const MODES: ModeOption[] = [
  {
    value: "secure_enclave",
    label: "Secure Enclave",
    description: "Hardware-backed key stored in the system's secure enclave (macOS only)",
    icon: <Fingerprint size={18} />,
  },
  {
    value: "encrypted_keyfile",
    label: "Encrypted Keyfile",
    description: "AES-256 encrypted key file on disk",
    icon: <FileKey size={18} />,
  },
  {
    value: "threshold",
    label: "Threshold (2-of-3)",
    description: "Distributed key shares requiring 2-of-3 signers (future)",
    icon: <Users size={18} />,
  },
];

export function SignerModeCard() {
  const { data, loading } = useFetch(fetchSignerMode);
  const [localMode, setLocalMode] = useState<SignerModeType | null>(null);
  const [updating, setUpdating] = useState(false);

  const currentMode = localMode ?? data?.current ?? "encrypted_keyfile";

  const handleSelect = useCallback(
    async (mode: SignerModeType) => {
      if (mode === currentMode || updating) return;
      const prev = currentMode;
      setLocalMode(mode);
      setUpdating(true);
      try {
        await updateSignerMode(mode);
      } catch {
        setLocalMode(prev);
      }
      setUpdating(false);
    },
    [currentMode, updating],
  );

  return (
    <Card title="Signer Mode">
      <div className="space-y-2">
        {MODES.map((mode) => {
          const selected = mode.value === currentMode;
          return (
            <button
              key={mode.value}
              onClick={() => handleSelect(mode.value)}
              disabled={loading || updating}
              className={cn(
                "flex w-full items-center gap-3 rounded-lg border p-3 text-left transition-all duration-150",
                selected
                  ? "border-brand bg-brand-muted"
                  : "border-border hover:border-border hover:bg-surface-hover",
                (loading || updating) && "opacity-60",
              )}
            >
              <div className={cn("shrink-0", selected ? "text-brand" : "text-text-tertiary")}>
                {mode.icon}
              </div>
              <div className="min-w-0">
                <p className={cn("text-sm font-medium", selected ? "text-brand" : "text-text")}>
                  {mode.label}
                </p>
                <p className="text-xs text-text-secondary">{mode.description}</p>
              </div>
              {selected && (
                <span className="ml-auto shrink-0 rounded-md bg-brand/15 px-2 py-0.5 text-[10px] font-bold text-brand">
                  Active
                </span>
              )}
            </button>
          );
        })}
      </div>
    </Card>
  );
}
