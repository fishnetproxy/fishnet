import { useState, useCallback, useMemo } from "react";
import { KeyRound } from "lucide-react";
import { cn } from "@/lib/cn";
import { Card } from "@/components/ui/Card";
import { changePassword } from "@/api/endpoints/settings";

function getPasswordStrength(pw: string): number {
  let score = 0;
  if (pw.length >= 8) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return score;
}

const STRENGTH_LABELS = ["", "Weak", "Fair", "Good", "Strong"];
const STRENGTH_COLORS = ["bg-bg-tertiary", "bg-danger", "bg-warning", "bg-warning", "bg-success"];

export function PasswordChangeCard() {
  const [current, setCurrent] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<{ text: string; error: boolean } | null>(null);

  const strength = useMemo(() => getPasswordStrength(newPw), [newPw]);
  const canSubmit = current.length > 0 && newPw.length >= 8 && newPw === confirm && !submitting;

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (!canSubmit) return;
      setSubmitting(true);
      setMessage(null);
      try {
        await changePassword({
          current_password: current,
          new_password: newPw,
          confirm_password: confirm,
        });
        setMessage({ text: "Password updated successfully.", error: false });
        setCurrent("");
        setNewPw("");
        setConfirm("");
      } catch (err) {
        setMessage({
          text: err instanceof Error ? err.message : "Failed to update password.",
          error: true,
        });
      }
      setSubmitting(false);
    },
    [current, newPw, confirm, canSubmit],
  );

  return (
    <Card title="Master Password">
      <form onSubmit={handleSubmit} className="max-w-md space-y-4">
        <div>
          <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
            Current Password
          </label>
          <input
            type="password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            className="w-full rounded-lg border border-border bg-surface-input px-3 py-2 text-sm text-text focus:border-brand/50 focus:outline-none focus:ring-1 focus:ring-brand/20"
          />
        </div>

        <div>
          <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
            New Password
          </label>
          <input
            type="password"
            value={newPw}
            onChange={(e) => setNewPw(e.target.value)}
            className="w-full rounded-lg border border-border bg-surface-input px-3 py-2 text-sm text-text focus:border-brand/50 focus:outline-none focus:ring-1 focus:ring-brand/20"
          />
          {/* Strength indicator */}
          {newPw.length > 0 && (
            <div className="mt-2">
              <div className="flex gap-1">
                {[1, 2, 3, 4].map((i) => (
                  <div
                    key={i}
                    className={cn(
                      "h-1 flex-1 rounded-full transition-colors",
                      i <= strength ? STRENGTH_COLORS[strength] : "bg-bg-tertiary",
                    )}
                  />
                ))}
              </div>
              <p className={cn("mt-1 text-[11px]", strength <= 1 ? "text-danger" : strength <= 2 ? "text-warning" : "text-success")}>
                {STRENGTH_LABELS[strength]}
              </p>
            </div>
          )}
        </div>

        <div>
          <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
            Confirm New Password
          </label>
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            className="w-full rounded-lg border border-border bg-surface-input px-3 py-2 text-sm text-text focus:border-brand/50 focus:outline-none focus:ring-1 focus:ring-brand/20"
          />
          {confirm.length > 0 && confirm !== newPw && (
            <p className="mt-1 text-[11px] text-danger">Passwords do not match</p>
          )}
        </div>

        {message && (
          <p className={cn("text-xs", message.error ? "text-danger" : "text-success")}>
            {message.text}
          </p>
        )}

        <button
          type="submit"
          disabled={!canSubmit}
          className="flex items-center gap-1.5 rounded-lg bg-brand px-4 py-1.5 text-sm font-medium text-white transition-all duration-150 hover:bg-brand-hover disabled:opacity-40"
        >
          <KeyRound size={14} />
          {submitting ? "Updating..." : "Update Password"}
        </button>
      </form>
    </Card>
  );
}
