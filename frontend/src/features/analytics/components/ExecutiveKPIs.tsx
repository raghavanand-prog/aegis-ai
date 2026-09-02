import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Fingerprint,
  Gauge,
  ShieldAlert,
} from "lucide-react";

import { useAnalyticsSummary } from "../hooks/useAnalytics";
import { ErrorState, SkeletonBlock } from "@/components/ui";

export default function ExecutiveKPIs() {
  const { data, isLoading, isError, error, refetch } = useAnalyticsSummary();

  if (isLoading) {
    return (
      <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
        {Array.from({ length: 6 }).map((_, index) => (
          <SkeletonBlock key={index} className="h-28" />
        ))}
      </div>
    );
  }

  if (isError || !data) {
    return <ErrorState error={error} onRetry={() => void refetch()} />;
  }

  const kpis = [
    {
      title: "Total Events",
      value: data.totalEvents.toLocaleString(),
      hint: `${data.newEvents} awaiting triage`,
      icon: Activity,
      color: "text-cyan-400",
    },
    {
      title: "Critical Events",
      value: data.criticalEvents.toLocaleString(),
      hint: `${data.highEvents} high severity`,
      icon: AlertTriangle,
      color: "text-red-400",
    },
    {
      title: "Open Incidents",
      value: data.openIncidents.toLocaleString(),
      hint: `${data.totalIncidents} opened in total`,
      icon: ShieldAlert,
      color: "text-orange-400",
    },
    {
      title: "Resolved Incidents",
      value: data.resolvedIncidents.toLocaleString(),
      hint: `${data.criticalIncidents} critical on the board`,
      icon: CheckCircle2,
      color: "text-emerald-400",
    },
    {
      title: "Tracked Indicators",
      value: data.totalIocs.toLocaleString(),
      hint: "Extracted from telemetry",
      icon: Fingerprint,
      color: "text-purple-400",
    },
    {
      title: "Mean Risk Score",
      value: data.meanRiskScore.toFixed(1),
      hint: "Across all stored events",
      icon: Gauge,
      color: "text-blue-400",
    },
  ];

  return (
    <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
      {kpis.map((kpi) => (
        <div
          key={kpi.title}
          className="rounded-xl border border-slate-800 bg-slate-900 p-5"
        >
          <div className="flex items-start justify-between">
            <div>
              <p className="text-sm text-slate-400">{kpi.title}</p>

              <h2 className="mt-2 text-3xl font-bold text-white">{kpi.value}</h2>

              <p className="mt-1 text-xs text-slate-500">{kpi.hint}</p>
            </div>

            <kpi.icon className={kpi.color} size={26} />
          </div>
        </div>
      ))}
    </div>
  );
}
