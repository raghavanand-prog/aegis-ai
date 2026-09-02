import { Lightbulb, Sparkles } from "lucide-react";

import Card from "@/components/ui/Card";
import CardHeader from "@/components/ui/CardHeader";
import CardContent from "@/components/ui/CardContent";
import { ErrorState, SkeletonBlock } from "@/components/ui";

import { useAnalyticsSummary } from "../hooks/useAnalytics";

interface Insight {
  title: string;
  detail: string;
}

/**
 * Derived insights.
 *
 * These are computed from the backend aggregates by simple heuristics - they
 * are deliberately NOT presented as model output, because V1 has no model
 * behind them. An LLM-assisted triage panel is a later milestone; until then
 * this panel says only what the data supports.
 */
function buildInsights(data: NonNullable<ReturnType<typeof useAnalyticsSummary>["data"]>): Insight[] {
  const insights: Insight[] = [];

  const topTechnique = data.mitreCoverage[0];
  if (topTechnique) {
    insights.push({
      title: `${topTechnique.key} is the dominant technique`,
      detail: `${topTechnique.count} detection(s) mapped to ${topTechnique.key} in the last ${data.windowHours}h. Confirm coverage for this technique before tuning anything else.`,
    });
  }

  const topSource = data.eventsBySource[0];
  if (topSource) {
    insights.push({
      title: `${topSource.key} produces the most telemetry`,
      detail: `${topSource.count.toLocaleString()} events. High volume from one source is where alert fatigue starts - check whether its detections are actionable.`,
    });
  }

  if (data.criticalEvents > 0 && data.openIncidents === 0) {
    insights.push({
      title: "Critical events with no open incident",
      detail: `${data.criticalEvents} critical event(s) are recorded but nothing has been promoted. Either the events are false positives worth tuning out, or triage is behind.`,
    });
  }

  if (data.newEvents > 0) {
    const share = Math.round((data.newEvents / Math.max(data.totalEvents, 1)) * 100);
    insights.push({
      title: `${share}% of events are still untriaged`,
      detail: `${data.newEvents.toLocaleString()} event(s) remain in the New queue. That backlog is the practical limit on how fast this SOC detects a real intrusion.`,
    });
  }

  if (data.meanRiskScore > 0 && data.meanRiskScore < 10) {
    insights.push({
      title: "Mean risk score is low",
      detail: `An average of ${data.meanRiskScore.toFixed(1)}/100 suggests most telemetry is benign, which is expected. Watch that rules stay sensitive enough to catch the rare malicious case.`,
    });
  }

  return insights.slice(0, 4);
}

export default function AIInsightsPanel() {
  const { data, isLoading, isError, error, refetch } = useAnalyticsSummary();

  return (
    <Card>
      <CardHeader
        title="Derived Insights"
        subtitle="Heuristics over the current aggregates"
        action={<Sparkles className="text-cyan-400" size={20} />}
      />

      <CardContent>
        {isLoading ? (
          <SkeletonBlock className="h-64" />
        ) : isError || !data ? (
          <ErrorState error={error} onRetry={() => void refetch()} />
        ) : (
          <>
            <div className="space-y-4">
              {buildInsights(data).map((insight) => (
                <div
                  key={insight.title}
                  className="rounded-xl border border-slate-800 bg-slate-900/70 p-4"
                >
                  <div className="flex items-center gap-2">
                    <Lightbulb size={16} className="text-cyan-400" />
                    <h3 className="text-sm font-semibold text-white">
                      {insight.title}
                    </h3>
                  </div>

                  <p className="mt-2 text-sm leading-6 text-slate-400">
                    {insight.detail}
                  </p>
                </div>
              ))}
            </div>

            <p className="mt-5 border-t border-slate-800 pt-4 text-xs text-slate-500">
              Rule-derived from stored events and incidents. No model is involved
              in these statements.
            </p>
          </>
        )}
      </CardContent>
    </Card>
  );
}
