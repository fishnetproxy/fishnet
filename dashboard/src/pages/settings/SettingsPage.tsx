import { useTheme } from "@/hooks/use-theme";
import { Card } from "@/components/ui/Card";
import { Toggle } from "@/components/ui/Toggle";
import { AlertConfigPanel } from "@/pages/alerts/AlertConfigPanel";
import { PasswordChangeCard } from "./PasswordChangeCard";
import { VaultBackupRestoreCard } from "./VaultBackupRestoreCard";
import { NetworkIsolationCard } from "./NetworkIsolationCard";
import { SignerModeCard } from "./SignerModeCard";
import { DangerZoneCard } from "./DangerZoneCard";

export default function SettingsPage() {
  const { theme, toggle } = useTheme();

  return (
    <div className="space-y-6">
      <Card title="Appearance">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-text">Dark Mode</p>
            <p className="text-xs text-text-secondary">
              Toggle between light and dark theme
            </p>
          </div>
          <Toggle
            checked={theme === "dark"}
            onChange={toggle}
          />
        </div>
      </Card>

      <AlertConfigPanel />

      <PasswordChangeCard />

      <VaultBackupRestoreCard />

      <NetworkIsolationCard />

      <SignerModeCard />

      <Card title="Proxy Configuration">
        <div className="space-y-4">
          <div>
            <p className="text-sm font-medium text-text">Proxy Port</p>
            <p className="text-xs text-text-secondary">
              localhost:8472 (configured in fishnet.toml)
            </p>
          </div>
          <div>
            <p className="text-sm font-medium text-text">Dashboard Port</p>
            <p className="text-xs text-text-secondary">
              localhost:8473 (configured in fishnet.toml)
            </p>
          </div>
        </div>
      </Card>

      <Card title="About">
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="text-text-secondary">Version</span>
            <span className="font-mono text-text">0.1.0</span>
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className="text-text-secondary">License</span>
            <span className="text-text">MIT</span>
          </div>
        </div>
      </Card>

      <DangerZoneCard />
    </div>
  );
}
