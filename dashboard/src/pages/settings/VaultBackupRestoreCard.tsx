import { useState, useCallback, useRef } from "react";
import { HardDriveDownload, HardDriveUpload } from "lucide-react";
import { cn } from "@/lib/cn";
import { Card } from "@/components/ui/Card";
import { fetchVaultBackupUrl, restoreVault } from "@/api/endpoints/settings";

export function VaultBackupRestoreCard() {
  const [backingUp, setBackingUp] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const [confirmFile, setConfirmFile] = useState<File | null>(null);
  const [message, setMessage] = useState<{ text: string; error: boolean } | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const handleBackup = useCallback(async () => {
    setBackingUp(true);
    setMessage(null);
    try {
      const res = await fetchVaultBackupUrl();
      const a = document.createElement("a");
      a.href = res.download_url;
      a.download = res.filename;
      a.click();
    } catch (err) {
      setMessage({ text: err instanceof Error ? err.message : "Backup failed.", error: true });
    }
    setBackingUp(false);
  }, []);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) setConfirmFile(file);
    if (fileRef.current) fileRef.current.value = "";
  }, []);

  const handleRestore = useCallback(async () => {
    if (!confirmFile) return;
    setRestoring(true);
    setMessage(null);
    try {
      await restoreVault(confirmFile);
      setMessage({ text: "Vault restored successfully.", error: false });
    } catch (err) {
      setMessage({ text: err instanceof Error ? err.message : "Restore failed.", error: true });
    }
    setConfirmFile(null);
    setRestoring(false);
  }, [confirmFile]);

  return (
    <Card title="Vault Backup & Restore">
      <div className="space-y-5">
        {/* Backup */}
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-text">Download Backup</p>
            <p className="text-xs text-text-secondary">Export an encrypted copy of your vault</p>
          </div>
          <button
            onClick={handleBackup}
            disabled={backingUp}
            className="flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-sm text-text transition-colors hover:bg-surface-hover disabled:opacity-40"
          >
            <HardDriveDownload size={14} />
            {backingUp ? "Preparing..." : "Backup"}
          </button>
        </div>

        <div className="border-t border-border-subtle" />

        {/* Restore */}
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-text">Restore from Backup</p>
            <p className="text-xs text-text-secondary">Upload a vault backup file to restore</p>
          </div>
          <button
            onClick={() => fileRef.current?.click()}
            disabled={restoring}
            className="flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-sm text-text transition-colors hover:bg-surface-hover disabled:opacity-40"
          >
            <HardDriveUpload size={14} />
            Restore
          </button>
          <input
            ref={fileRef}
            type="file"
            className="hidden"
            accept=".json,.bak,.enc"
            onChange={handleFileSelect}
          />
        </div>

        {/* Restore confirmation */}
        {confirmFile && (
          <div className="rounded-lg border border-warning/30 bg-warning-dim p-4">
            <p className="text-sm font-medium text-text">
              This will replace your current vault with <span className="font-mono">{confirmFile.name}</span>.
            </p>
            <p className="mt-1 text-xs text-text-secondary">This action cannot be undone.</p>
            <div className="mt-3 flex items-center gap-2">
              <button
                onClick={handleRestore}
                disabled={restoring}
                className="rounded-lg bg-danger px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-danger/90 disabled:opacity-40"
              >
                {restoring ? "Restoring..." : "Confirm Restore"}
              </button>
              <button
                onClick={() => setConfirmFile(null)}
                className="rounded-lg px-3 py-1.5 text-sm text-text-tertiary transition-colors hover:bg-surface-hover hover:text-text"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {message && (
          <p className={cn("text-xs", message.error ? "text-danger" : "text-success")}>
            {message.text}
          </p>
        )}
      </div>
    </Card>
  );
}
