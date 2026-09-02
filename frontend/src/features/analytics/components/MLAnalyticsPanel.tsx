import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Sparkles } from "lucide-react";

import Card from "@/components/ui/Card";
import CardContent from "@/components/ui/CardContent";
import CardHeader from "@/components/ui/CardHeader";
import { ErrorState, SkeletonBlock } from "@/components/ui";
import UnavailablePanel from "@/features/detection/components/UnavailablePanel";

import { useAnalyticsSummary } from "../hooks/useAnalytics";
import { AXIS, GRID, tooltipStyle } from "./chartTheme";

/**
 * ML detection analytics.
 *
 * Every number and every series here is counted from stored inference rows. The
 * panel has one job beyond display: when no model is running it must say so,
 * because a chart of zero anomalies and a chart of "we never looked" are the
 * same picture and mean opposite things.
 */

const OVERLAP_COLOURS: Record<string, string> = {
  ruleOnly: "#22d3ee",
  ruleAndMl: "#a78bfa",
  mlOnly: "#c084fc",
};

const OVERLAP_LABELS: Record<string, string> = {
  ruleOnly: "Rule only",
  ruleAndMl: "Rule + ML",
  mlOnly: "ML only",
};

export default function MLAnalyticsPanel() {
  const { data, isLoading, isError, error, refetch } = useAnalyticsSummary();

  if (isLoading) {
    return (
      <Card>
        <CardHeader title="ML Detection" subtitle="Anomaly model activity" />
        <CardContent>
          <SkeletonBlock className="h-64" />
        </CardContent>
      </Card>
    );
  }

  if (isError || !data) {
    return (
      <Card>
        <CardHeader title="ML Detection" />
        <CardContent>
          <ErrorState error={error} onRetry={() => void refetch()} />
        </CardContent>
      </Card>
    );
  }

  const ml = data.ml;

  if (!ml) {
    return (
      <Card>
        <CardHeader title="ML Detection" />
        <CardContent>
          <UnavailablePanel
            title="This backend does not report ML analytics"
            reason="The /analytics/summary response contains no `ml` section, which means the backend predates V3."
          />
        </CardContent>
      </Card>
    );
  }

  const overlap = Object.entries(ml.detectionOverlap ?? {})
    .filter(([, value]) => typeof value === "number")
    .map(([key, value]) => ({
      key,
      label: OVERLAP_LABELS[key] ?? key,
      count: value as number,
    }));

  const anomalyTrend = (ml.anomaliesOverTime ?? []).map((bucket) => ({
    bucket: bucket.bucket.slice(11, 16),
    count: bucket.count,
  }));

  return (
    <Card>
      <CardHeader
        title="ML Detection"
        subtitle={
          ml.modelAvailable
            ? `${ml.modelName} v${ml.modelVersion} · feature schema v${ml.featureSchemaVersion} · threshold ${ml.threshold}`
            : "No anomaly model is running"
        }
        action={<Sparkles className="text-violet-400" size={20} />}
      />

      <CardContent>
        {!ml.modelAvailable && (
          <div className="mb-5">
            <UnavailablePanel
              title="No anomaly model is running"
              reason={
                ml.reason ??
                "The anomaly detector is not loaded, so nothing has been scored."
              }
              hint="python -m app.ml.training.train_anomaly_model"
            />
          </div>
        )}

        {/* --- Counters ---------------------------------------------------- */}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          {[
            {
              label: "Events scored",
              value: ml.totalScoredEvents.toLocaleString(),
              hint: "Events the model produced a verdict for",
            },
            {
              label: "Anomalies",
              value: ml.anomaliesDetected.toLocaleString(),
              hint: "Scored at or above the anomaly threshold",
            },
            {
              label: "Anomaly rate",
              value:
                ml.anomalyRate == null
                  ? "n/a"
                  : `${(ml.anomalyRate * 100).toFixed(1)}%`,
              hint:
                ml.anomalyRate == null
                  ? "Nothing has been scored, so there is no rate to report"
                  : "Anomalies as a share of scored events",
            },
            {
              label: "ML-assisted incidents",
              value: ml.mlAssistedIncidents.toLocaleString(),
              hint: "Incidents containing at least one flagged event",
            },
          ].map((stat) => (
            <div
              key={stat.label}
              title={stat.hint}
              className="rounded-xl border border-slate-800 bg-slate-900/60 p-4"
            >
              <p className="text-xs text-slate-500">{stat.label}</p>
              <p className="mt-1 text-2xl font-bold text-white">{stat.value}</p>
            </div>
          ))}
        </div>

        {/* --- Rule vs ML overlap ------------------------------------------ */}
        {overlap.some((entry) => entry.count > 0) && (
          <div className="mt-6">
            <h4 className="text-sm font-semibold text-white">
              Where detections come from
            </h4>
            <p className="mt-1 text-xs leading-5 text-slate-500">
              The &quot;ML only&quot; column is the one that justifies running a
              second detector: events the anomaly model flagged that no rule
              matched.
            </p>
            <div className="mt-3 h-52">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={overlap}>
                  <CartesianGrid stroke={GRID} strokeDasharray="3 3" />
                  <XAxis dataKey="label" stroke={AXIS} fontSize={11} />
                  <YAxis stroke={AXIS} fontSize={11} allowDecimals={false} />
                  <Tooltip {...tooltipStyle} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {overlap.map((entry) => (
                      <Cell key={entry.key} fill={OVERLAP_COLOURS[entry.key] ?? "#64748b"} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* --- Anomalies over time ----------------------------------------- */}
        {anomalyTrend.some((point) => point.count > 0) && (
          <div className="mt-6">
            <h4 className="text-sm font-semibold text-white">
              Anomalies over the last {data.windowHours}h
            </h4>
            <div className="mt-3 h-52">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={anomalyTrend}>
                  <CartesianGrid stroke={GRID} strokeDasharray="3 3" />
                  <XAxis dataKey="bucket" stroke={AXIS} fontSize={11} />
                  <YAxis stroke={AXIS} fontSize={11} allowDecimals={false} />
                  <Tooltip {...tooltipStyle} />
                  <Line
                    type="monotone"
                    dataKey="count"
                    stroke="#a78bfa"
                    strokeWidth={2}
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* --- Score distribution ------------------------------------------ */}
        {ml.scoreDistribution?.some((bucket) => bucket.count > 0) && (
          <div className="mt-6">
            <h4 className="text-sm font-semibold text-white">
              Anomaly score distribution
            </h4>
            <p className="mt-1 text-xs text-slate-500">
              Every score the model has produced. A ranking, not a probability.
            </p>
            <div className="mt-3 h-44">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={ml.scoreDistribution}>
                  <CartesianGrid stroke={GRID} strokeDasharray="3 3" />
                  <XAxis dataKey="key" stroke={AXIS} fontSize={11} />
                  <YAxis stroke={AXIS} fontSize={11} allowDecimals={false} />
                  <Tooltip {...tooltipStyle} />
                  <Bar dataKey="count" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* --- Sources ------------------------------------------------------ */}
        {ml.anomaliesBySource?.length > 0 && (
          <div className="mt-6">
            <h4 className="text-sm font-semibold text-white">
              Anomalies by telemetry source
            </h4>
            <ul className="mt-3 space-y-1.5">
              {ml.anomaliesBySource.map((entry) => (
                <li
                  key={entry.key}
                  className="flex items-center justify-between rounded-lg bg-slate-900/60 px-3 py-2 text-sm"
                >
                  <span className="text-slate-300">{entry.key}</span>
                  <span className="font-mono text-slate-400">{entry.count}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        <p className="mt-5 border-t border-slate-800 pt-4 text-xs leading-5 text-slate-500">
          Counted from stored inference rows. Anomaly scores are rankings from an
          unsupervised model &mdash; they are not probabilities, not confidences,
          and the model identifies no attack technique. Labelled measurement of
          rules vs ML vs both is produced by{" "}
          <code className="text-slate-400">
            python -m app.ml.evaluation.run_ml_eval
          </code>
          .
        </p>
      </CardContent>
    </Card>
  );
}
