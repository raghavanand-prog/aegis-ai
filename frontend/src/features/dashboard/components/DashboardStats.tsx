import { Activity, Fingerprint, ShieldAlert, ShieldCheck } from "lucide-react";

import StatCard from "./StatCard";
import { useAnalyticsSummary } from "@/features/analytics/hooks/useAnalytics";
import { ErrorState, SkeletonBlock } from "@/components/ui";

export default function DashboardStats() {
  const { data, isLoading, isError, error, refetch } = useAnalyticsSummary();

  if (isLoading) {
    return (
      <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <SkeletonBlock key={index} className="h-32" />
        ))}
      </div>
    );
  }

  if (isError || !data) {
    return <ErrorState error={error} onRetry={() => void refetch()} />;
  }

  return (
    <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
      <StatCard
        title="Critical Events"
        value={data.criticalEvents}
        trend={`${data.highEvents} high severity`}
        trendColor="text-red-400"
        icon={<ShieldAlert size={22} />}
        delay={0}
      />

      <StatCard
        title="Open Incidents"
        value={data.openIncidents}
        trend={`${data.criticalIncidents} critical`}
        trendColor="text-amber-400"
        icon={<ShieldCheck size={22} />}
        delay={0.15}
      />

      <StatCard
        title="Events Ingested"
        value={data.totalEvents}
        trend={`${data.newEvents} awaiting triage`}
        trendColor="text-cyan-400"
        icon={<Activity size={22} />}
        delay={0.3}
      />

      <StatCard
        title="Tracked Indicators"
        value={data.totalIocs}
        trend={`mean risk ${data.meanRiskScore.toFixed(1)}/100`}
        trendColor="text-purple-400"
        icon={<Fingerprint size={22} />}
        delay={0.45}
      />
    </div>
  );
}
