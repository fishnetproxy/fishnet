import { useState, useCallback } from "react";
import { AlertTriangle } from "lucide-react";
import { cn } from "@/lib/cn";
import { factoryReset } from "@/api/endpoints/settings";

type ConfirmStep = "idle" | "first" | "second";

export function DangerZoneCard() {
  const [step, setStep] = useState<ConfirmStep>("idle");
  const [resetInput, setResetInput] = useState("");
  const [resetting, setResetting] = useState(false);

  const handleFinalReset = useCallback(async () => {
    if (resetInput !== "RESET" || resetting) return;
    setResetting(true);
    try {
      await factoryReset("RESET");
      window.location.href = "/login";
    } catch {
      setResetting(false);
      setStep("idle");
      setResetInput("");
    }
  }, [resetInput, resetting]);

  return (
    <div className="rounded-xl border border-danger/20 bg-surface">
      <div className="px-6 py-4">
        <div className="flex items-center gap-2">
          <AlertTriangle size={16} className="text-danger" />
          <h3 className="text-[13px] font-semibold tracking-wide text-danger">Danger Zone</h3>
        </div>
      </div>

      <div className="border-t border-danger/10 px-6 py-5">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-text">Factory Reset</p>
            <p className="text-xs text-text-secondary">
              Permanently delete all data, credentials, and configuration. This cannot be undone.
            </p>
          </div>

          {step === "idle" && (
            <button
              onClick={() => setStep("first")}
              className="shrink-0 rounded-lg bg-danger px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-danger/90"
            >
              Reset Instance
            </button>
          )}
        </div>

        {/* First confirmation */}
        {step === "first" && (
          <div className="mt-4 rounded-lg border border-danger/20 bg-danger-dim p-4">
            <p className="text-sm font-medium text-text">
              Are you sure? This is irreversible.
            </p>
            <div className="mt-3 flex items-center gap-2">
              <button
                onClick={() => setStep("second")}
                className="rounded-lg bg-danger px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-danger/90"
              >
                Confirm Reset
              </button>
              <button
                onClick={() => setStep("idle")}
                className="rounded-lg px-3 py-1.5 text-sm text-text-tertiary transition-colors hover:bg-surface-hover hover:text-text"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Second confirmation — type RESET */}
        {step === "second" && (
          <div className="mt-4 rounded-lg border border-danger/20 bg-danger-dim p-4">
            <p className="text-sm font-medium text-text">
              Type <code className="rounded bg-bg-tertiary px-1.5 py-0.5 font-mono text-xs text-danger">RESET</code> to confirm.
            </p>
            <div className="mt-3 flex items-center gap-2">
              <input
                type="text"
                value={resetInput}
                onChange={(e) => setResetInput(e.target.value)}
                placeholder="RESET"
                className="w-32 rounded-lg border border-danger/30 bg-surface-input px-3 py-1.5 font-mono text-sm text-text placeholder:text-text-tertiary/50 focus:border-danger/50 focus:outline-none focus:ring-1 focus:ring-danger/20"
              />
              <button
                onClick={handleFinalReset}
                disabled={resetInput !== "RESET" || resetting}
                className={cn(
                  "rounded-lg bg-danger px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-danger/90 disabled:opacity-40",
                )}
              >
                {resetting ? "Resetting..." : "Reset Everything"}
              </button>
              <button
                onClick={() => {
                  setStep("idle");
                  setResetInput("");
                }}
                className="rounded-lg px-3 py-1.5 text-sm text-text-tertiary transition-colors hover:bg-surface-hover hover:text-text"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
