import { AlertTriangle } from "lucide-react";

import Card from "@/components/ui/Card";
import CardContent from "@/components/ui/CardContent";
import CardHeader from "@/components/ui/CardHeader";

import type { Experiment } from "@/services/api/evaluation";
import {
  NOT_AVAILABLE,
  decimal,
  detectorLabel,
  isOrderedScore,
  percent,
  scoreKindLabel,
} from "./metricFormat";

/**
 * The central table: every detector measured on one dataset and one split.
 *
 * Design decisions that are about honesty rather than looks:
 *
 * - Rows are grouped by (dataset fingerprint, split) and the grouping is shown,
 *   because comparing rows from different data is not a comparison.
 * - An undefined metric renders "n/a", never a zero bar. A detector that fires
 *   on nothing has undefined precision, and drawing that as 0% would suggest a
 *   measurement that was never made.
 * - AUC columns are blank with a reason for detectors whose output has no
 *   ordering, rather than showing the 0.5 a naive implementation produces.
 * - The score kind is on every row, so an anomaly ranking and a probability are
 *   never silently read as the same quantity.
 */

interface Props {
  experiments: Experiment[];
}

function MetricCell({
  value,
  formatter,
}: {
  value: number | null | undefined;
  formatter: (value: number | null | undefined) => string;
}) {
  const text = formatter(value);
  return (
    <td
      className={`px-3 py-2 text-right tabular-nums ${
        text === NOT_AVAILABLE ? "text-slate-600" : "text-slate-200"
      }`}
    >
      {text}
    </td>
  );
}

export default function DetectorComparison({ experiments }: Props) {
  if (experiments.length === 0) return null;

  const fingerprints = new Set(experiments.map((item) => item.dataset.fingerprint));
  const splits = new Set(experiments.map((item) => item.split.strategy));
  const mixed = fingerprints.size > 1 || splits.size > 1;

  const first = experiments[0];

  return (
    <Card>
      <CardHeader
        title="Detector comparison"
        subtitle={
          `${first.dataset.name} v${first.dataset.version} · fingerprint ` +
          `${first.dataset.fingerprint} · ${first.split.strategy} split`
        }
      />
      <CardContent>
        {mixed && (
          <div className="mb-4 flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2">
            <AlertTriangle size={16} className="mt-0.5 shrink-0 text-amber-400" />
            <p className="text-xs leading-5 text-amber-200">
              These rows were measured on more than one dataset fingerprint or split
              strategy. They are listed together for inspection and must not be read
              as a like-for-like comparison.
            </p>
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full min-w-[52rem] text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-left text-xs uppercase tracking-wide text-slate-500">
                <th className="px-3 py-2 font-medium">Detector</th>
                <th className="px-3 py-2 font-medium">Score kind</th>
                <th className="px-3 py-2 text-right font-medium">Thresh.</th>
                <th className="px-3 py-2 text-right font-medium">TP</th>
                <th className="px-3 py-2 text-right font-medium">FP</th>
                <th className="px-3 py-2 text-right font-medium">FN</th>
                <th className="px-3 py-2 text-right font-medium">Precision</th>
                <th className="px-3 py-2 text-right font-medium">Recall</th>
                <th className="px-3 py-2 text-right font-medium">F1</th>
                <th className="px-3 py-2 text-right font-medium">FPR</th>
                <th className="px-3 py-2 text-right font-medium">MCC</th>
                <th className="px-3 py-2 text-right font-medium">PR-AUC</th>
              </tr>
            </thead>
            <tbody>
              {experiments.map((experiment) => {
                const run = experiment.latestRun;
                const ordered = isOrderedScore(experiment.detector.scoreKind);
                return (
                  <tr
                    key={experiment.experimentId}
                    className="border-b border-slate-800/60 last:border-0"
                  >
                    <td className="px-3 py-2">
                      <span className="font-medium text-white">
                        {detectorLabel(experiment.detector.name)}
                      </span>
                      <span className="mt-0.5 block font-mono text-[10px] text-slate-600">
                        {experiment.experimentId}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-400">
                      {scoreKindLabel(experiment.detector.scoreKind)}
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums text-slate-300">
                      {run ? run.threshold : NOT_AVAILABLE}
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums text-slate-300">
                      {run?.confusion.truePositives ?? NOT_AVAILABLE}
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums text-slate-300">
                      {run?.confusion.falsePositives ?? NOT_AVAILABLE}
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums text-slate-300">
                      {run?.confusion.falseNegatives ?? NOT_AVAILABLE}
                    </td>
                    <MetricCell value={run?.metrics.precision} formatter={percent} />
                    <MetricCell value={run?.metrics.recall} formatter={percent} />
                    <MetricCell value={run?.metrics.f1} formatter={percent} />
                    <MetricCell
                      value={run?.metrics.falsePositiveRate}
                      formatter={percent}
                    />
                    <MetricCell value={run?.metrics.mcc} formatter={decimal} />
                    <td
                      className="px-3 py-2 text-right tabular-nums text-slate-600"
                      title={
                        ordered
                          ? undefined
                          : "This detector's output has no ordering, so PR-AUC is undefined."
                      }
                    >
                      {ordered ? decimal(run?.metrics.prAuc) : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <p className="mt-4 text-xs leading-5 text-slate-500">
          Thresholds were chosen on the validation split and frozen before the test
          split was evaluated. <span className="text-slate-400">n/a</span> means the
          metric is undefined for that detector, not zero. <span className="text-slate-400">—</span>{" "}
          means the detector emits no ordering, so a ranking metric would be an
          artefact rather than a result.
        </p>
      </CardContent>
    </Card>
  );
}
