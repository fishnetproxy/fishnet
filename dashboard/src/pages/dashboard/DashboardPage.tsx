import { useFetch } from "@/hooks/use-fetch";
import { useAlertsContext } from "@/context/alerts-context";
import { useFirstRun } from "@/hooks/use-first-run";
import { fetchSpend } from "@/api/endpoints/spend";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { MetricCards } from "./MetricCards";
import { AlertBanner } from "./AlertBanner";
import { SpendByService } from "./SpendByService";
import { StatusCard } from "./StatusCard";
import { CopyConfigCard } from "./CopyConfigCard";
import { QuickActions } from "./QuickActions";
import { SetupWizard } from "@/pages/wizard/SetupWizard";

export default function DashboardPage() {
  const { data: spend, loading: spendLoading } = useFetch(fetchSpend);
  const { latest, undismissed, dismiss } = useAlertsContext();
  const { isFirstRun, completeWizard } = useFirstRun();

  if (isFirstRun) {
    return <SetupWizard onComplete={completeWizard} />;
  }

  return (
    <div className="space-y-6">
      {/* Status bar */}
      <StatusCard />

      {/* Metric cards row */}
      {spendLoading || !spend ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </div>
      ) : (
        <MetricCards spend={spend} activeAlerts={undismissed.length} />
      )}

      {/* Agent config copy card */}
      <CopyConfigCard />

      {/* Quick actions */}
      <QuickActions />

      {/* Latest alert banner */}
      {latest && (
        <AlertBanner
          alert={latest}
          totalActive={undismissed.length}
          onDismiss={dismiss}
        />
      )}

      {/* Spend by Service */}
      {spendLoading || !spend ? (
        <SkeletonCard />
      ) : (
        <SpendByService spend={spend} />
      )}
    </div>
  );
}
