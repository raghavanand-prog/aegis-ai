import Card from "@/components/ui/Card";
import CardHeader from "@/components/ui/CardHeader";
import CardContent from "@/components/ui/CardContent";
import { ErrorState, SkeletonBlock } from "@/components/ui";

import { useAnalyticsSummary } from "../hooks/useAnalytics";

/**
 * Plain-language summary of the current window.
 *
 * Every figure here is read from the backend aggregation - nothing on this
 * panel is written by hand.
 */
export default function ExecutiveSummary() {
  const { data, isLoading, isError, error, refetch } = useAnalyticsSummary();

  if (isLoading) return <SkeletonBlock className="h-40" />;
  if (isError || !data) return <ErrorState error={error} onRetry={() => void refetch()} />;

  const triaged = data.totalEvents - data.newEvents;
  const triageRate =
    data.totalEvents > 0 ? Math.round((triaged / data.totalEvents) * 100) : 0;
  const closureRate =
    data.totalIncidents > 0
      ? Math.round((data.resolvedIncidents / data.totalIncidents) * 100)
      : 0;
  const topSource = data.eventsBySource[0];
  const topTechnique = data.mitreCoverage[0];

  return (
    <Card>
      <CardHeader
        title="Executive Summary"
        subtitle={`Rolling ${data.windowHours}-hour view`}
      />

      <CardContent className="space-y-4 text-sm leading-relaxed text-slate-300">
        <p>
          AEGISX has ingested{" "}
          <span className="font-semibold text-white">
            {data.totalEvents.toLocaleString()}
          </span>{" "}
          events, of which{" "}
          <span className="font-semibold text-red-400">{data.criticalEvents}</span> are
          critical and{" "}
          <span className="font-semibold text-orange-400">{data.highEvents}</span> are
          high severity. The mean risk score across all events is{" "}
          <span className="font-semibold text-white">
            {data.meanRiskScore.toFixed(1)}
          </span>
          /100.
        </p>

        <p>
          {data.totalIncidents === 0
            ? "No events have been promoted to incidents yet."
            : `${data.totalIncidents} incident(s) have been opened, ${data.openIncidents} of which are still open and ${data.resolvedIncidents} resolved (${closureRate}% closure rate).`}{" "}
          {triageRate}% of events have moved out of the New queue.
        </p>

        {topSource && (
          <p>
            The busiest source is{" "}
            <span className="font-semibold text-white">{topSource.key}</span> with{" "}
            {topSource.count.toLocaleString()} events
            {topTechnique
              ? `, and the most frequently mapped ATT&CK technique is ${topTechnique.key} (${topTechnique.count} detections).`
              : "."}
          </p>
        )}

        <p className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-xs text-slate-400">
          Figures are computed from stored events and incidents at query time. A
          detection here is a rule match, not a confirmed compromise - false
          positive rate is not yet measured, which is the first thing V2 needs to
          quantify.
        </p>
      </CardContent>
    </Card>
  );
}
