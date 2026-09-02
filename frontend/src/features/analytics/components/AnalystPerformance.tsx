import Card from "@/components/ui/Card";
import CardHeader from "@/components/ui/CardHeader";
import CardContent from "@/components/ui/CardContent";
import { EmptyState, ErrorState, SkeletonBlock } from "@/components/ui";

import { useAnalyticsSummary } from "../hooks/useAnalytics";

export default function AnalystPerformance() {
  const { data, isLoading, isError, error, refetch } = useAnalyticsSummary();

  const workload = data?.analystWorkload ?? [];

  return (
    <Card>
      <CardHeader
        title="Analyst Workload"
        subtitle="Incident ownership by status"
      />

      <CardContent>
        {isLoading ? (
          <SkeletonBlock className="h-64" />
        ) : isError ? (
          <ErrorState error={error} onRetry={() => void refetch()} />
        ) : workload.length === 0 ? (
          <EmptyState
            title="No incidents assigned"
            description="Promote an event to open the first incident."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-slate-800 text-left text-slate-400">
                <tr>
                  <th className="pb-3 pr-4 font-medium">Analyst</th>
                  <th className="pb-3 pr-4 font-medium">Open</th>
                  <th className="pb-3 pr-4 font-medium">Investigating</th>
                  <th className="pb-3 pr-4 font-medium">Contained</th>
                  <th className="pb-3 pr-4 font-medium">Resolved</th>
                  <th className="pb-3 font-medium">Total</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-slate-800/70">
                {workload.map((row) => (
                  <tr key={row.analyst} className="text-slate-300">
                    <td className="py-3 pr-4 font-medium text-white">{row.analyst}</td>
                    <td className="py-3 pr-4">{row.open}</td>
                    <td className="py-3 pr-4">{row.investigating}</td>
                    <td className="py-3 pr-4">{row.contained}</td>
                    <td className="py-3 pr-4 text-emerald-400">{row.resolved}</td>
                    <td className="py-3 font-semibold text-white">{row.total}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
