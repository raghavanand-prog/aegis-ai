import { useState } from "react";
import { AlertTriangle, FlaskConical, Play, ShieldQuestion } from "lucide-react";

import Card from "@/components/ui/Card";
import CardHeader from "@/components/ui/CardHeader";
import CardContent from "@/components/ui/CardContent";
import { ErrorState, SkeletonBlock } from "@/components/ui";
import { useAuth } from "@/features/auth/hooks/useAuth";

import {
  useDetectionQuality,
  useRunDetectionEvaluation,
} from "../hooks/useDetectionQuality";

function percent(value: number | null | undefined): string {
  return value === null || value === undefined ? "n/a" : `${(value * 100).toFixed(1)}%`;
}

/**
 * Detection Engine Evaluation.
 *
 * These are metrics for the deterministic rule engine measured against a
 * labelled dataset - not model metrics, and not derived from live traffic.
 * When no evaluation has been run the panel says so and shows the command,
 * because an empty measurement must never be rendered as a zero.
 */
export default function DetectionQualityPanel() {
  const { user } = useAuth();
  const { data, isLoading, isError, error, refetch } = useDetectionQuality();
  const runEvaluation = useRunDetectionEvaluation();
  const [showDetail, setShowDetail] = useState(false);

  const canRun = user?.permissions?.includes("detection:evaluate") ?? false;

  if (isLoading) return <SkeletonBlock className="h-72" />;

  if (isError) {
    return <ErrorState error={error} onRetry={() => void refetch()} />;
  }

  if (!data) {
    return (
      <Card>
        <CardHeader
          title="Detection Engine Evaluation"
          subtitle="Deterministic rules measured against labelled data"
          action={<FlaskConical className="text-cyan-400" size={20} />}
        />
        <CardContent>
          <div className="flex flex-col items-center rounded-xl border border-dashed border-slate-800 bg-slate-900/50 px-6 py-10 text-center">
            <ShieldQuestion className="mb-3 text-slate-600" size={32} />

            <h3 className="text-base font-semibold text-slate-200">
              No evaluation has been run yet
            </h3>

            <p className="mt-2 max-w-lg text-sm text-slate-500">
              Precision, recall and false positive rate are only shown once the rules have
              actually been measured. AEGISX does not display placeholder metrics.
            </p>

            <code className="mt-4 rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-cyan-300">
              python -m app.evaluation.run_detection_eval
            </code>

            {canRun && (
              <button
                onClick={() => runEvaluation.mutate(undefined)}
                disabled={runEvaluation.isPending}
                className="mt-5 inline-flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-cyan-500 disabled:opacity-60"
              >
                <Play size={15} />
                {runEvaluation.isPending ? "Running..." : "Run evaluation now"}
              </button>
            )}
          </div>
        </CardContent>
      </Card>
    );
  }

  const { overall, latency, volume, dataset, coverage, perClass, perRule } = data;

  const headline = [
    { label: "Precision", value: percent(overall.precision) },
    { label: "Recall", value: percent(overall.recall) },
    { label: "F1 score", value: percent(overall.f1) },
    { label: "False positive rate", value: percent(overall.falsePositiveRate) },
    { label: "False negative rate", value: percent(overall.falseNegativeRate) },
    { label: "Detection latency (mean)", value: `${latency.meanMs.toFixed(3)} ms` },
  ];

  const counts = [
    { label: "Events evaluated", value: volume.eventsProcessed },
    { label: "Detections fired", value: volume.detectionsTotal },
    { label: "True positives", value: overall.truePositives },
    { label: "False positives", value: overall.falsePositives },
    { label: "False negatives", value: overall.falseNegatives },
    { label: "True negatives", value: overall.trueNegatives },
  ];

  return (
    <Card>
      <CardHeader
        title="Detection Engine Evaluation"
        subtitle={`${dataset.name} v${dataset.version} · seed ${dataset.seed} · ${volume.eventsProcessed} labelled events`}
        action={<FlaskConical className="text-cyan-400" size={20} />}
      />

      <CardContent className="space-y-6">
        {data.stale && (
          <div className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3">
            <AlertTriangle size={16} className="mt-0.5 shrink-0 text-amber-400" />
            <p className="text-sm text-amber-100">
              The rules have changed since this evaluation was produced. Re-run it before
              trusting these numbers.
            </p>
          </div>
        )}

        {!overall.sufficientData && (
          <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
            Fewer than {coverage.minSamplesOverall} samples were evaluated - treat these
            rates as indicative only.
          </div>
        )}

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {headline.map((metric) => (
            <div
              key={metric.label}
              className="rounded-xl border border-slate-800 bg-slate-900 p-4"
            >
              <p className="text-sm text-slate-400">{metric.label}</p>
              <p className="mt-1 text-2xl font-bold text-white">{metric.value}</p>
            </div>
          ))}
        </div>

        <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
          {counts.map((count) => (
            <div key={count.label} className="rounded-lg border border-slate-800 p-3">
              <p className="text-xs text-slate-500">{count.label}</p>
              <p className="mt-1 text-lg font-semibold text-slate-200">{count.value}</p>
            </div>
          ))}
        </div>

        {coverage.uncoveredLabels.length > 0 && (
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
            <h4 className="text-sm font-semibold text-white">Known blind spots</h4>
            <p className="mt-1 text-sm text-slate-400">
              No rule targets{" "}
              <span className="font-mono text-amber-300">
                {coverage.uncoveredLabels.join(", ")}
              </span>
              . Those samples count as false negatives, which is why recall is not
              reported as perfect.
            </p>
          </div>
        )}

        <button
          onClick={() => setShowDetail((value) => !value)}
          className="text-sm text-cyan-400 transition hover:text-cyan-300"
        >
          {showDetail ? "Hide per-class and per-rule detail" : "Show per-class and per-rule detail"}
        </button>

        {showDetail && (
          <div className="grid gap-6 xl:grid-cols-2">
            <div className="overflow-x-auto">
              <h4 className="mb-2 text-sm font-semibold text-white">By attack class</h4>
              <table className="w-full text-sm">
                <thead className="border-b border-slate-800 text-left text-slate-400">
                  <tr>
                    <th className="pb-2 pr-3 font-medium">Class</th>
                    <th className="pb-2 pr-3 font-medium">n</th>
                    <th className="pb-2 pr-3 font-medium">Detected</th>
                    <th className="pb-2 font-medium">Rate</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {perClass.map((row) => (
                    <tr key={row.label} className="text-slate-300">
                      <td className="py-2 pr-3 font-mono text-xs">
                        {row.label}
                        {!row.coveredByRules && (
                          <span className="ml-2 text-amber-400">no rule</span>
                        )}
                      </td>
                      <td className="py-2 pr-3">{row.total}</td>
                      <td className="py-2 pr-3">{row.detected}</td>
                      <td className="py-2">{percent(row.detectionRate)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="overflow-x-auto">
              <h4 className="mb-2 text-sm font-semibold text-white">By rule</h4>
              <table className="w-full text-sm">
                <thead className="border-b border-slate-800 text-left text-slate-400">
                  <tr>
                    <th className="pb-2 pr-3 font-medium">Rule</th>
                    <th className="pb-2 pr-3 font-medium">Fires</th>
                    <th className="pb-2 pr-3 font-medium">On benign</th>
                    <th className="pb-2 font-medium">Precision</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {perRule.map((row) => (
                    <tr key={row.ruleId} className="text-slate-300">
                      <td className="py-2 pr-3">
                        <span className="font-mono text-xs">{row.ruleId}</span>
                        <span className="ml-2 text-xs text-slate-500">
                          v{row.ruleVersion}
                        </span>
                      </td>
                      <td className="py-2 pr-3">{row.fires}</td>
                      <td className="py-2 pr-3">
                        <span className={row.onBenign > 0 ? "text-amber-400" : ""}>
                          {row.onBenign}
                        </span>
                      </td>
                      <td className="py-2">{percent(row.rulePrecision)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-800 pt-4">
          <p className="max-w-2xl text-xs text-slate-500">
            Metrics for the deterministic rule engine, measured against a labelled synthetic
            dataset. Not a machine learning model, and not measured on live traffic.
            Latency covers rule evaluation only.
          </p>

          {canRun && (
            <button
              onClick={() => runEvaluation.mutate(undefined)}
              disabled={runEvaluation.isPending}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-slate-200 transition hover:border-slate-600 hover:bg-slate-800 disabled:opacity-60"
            >
              <Play size={15} />
              {runEvaluation.isPending ? "Running..." : "Re-run evaluation"}
            </button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
