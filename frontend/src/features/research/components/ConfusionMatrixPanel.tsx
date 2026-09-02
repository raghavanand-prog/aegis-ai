import Card from "@/components/ui/Card";
import CardContent from "@/components/ui/CardContent";
import CardHeader from "@/components/ui/CardHeader";

import type { Experiment } from "@/services/api/evaluation";
import { NOT_AVAILABLE, count, detectorLabel, percent } from "./metricFormat";

/**
 * Confusion matrix as a 2x2 grid, counts and row-normalized rates together.
 *
 * Both are shown because they answer different questions and each is
 * misleading alone: on an 11%-positive corpus a large true-negative count makes
 * any detector look excellent, while a rate alone hides how few positives it
 * was computed from. The support for each row is printed for the same reason.
 *
 * Row normalization is stated explicitly on the panel. "Of the actual attacks,
 * what fraction did we catch" and "of our alerts, what fraction were real" are
 * different numbers, and an unlabelled normalized matrix routinely gets read as
 * whichever one flatters the system.
 */

interface Props {
  experiment: Experiment;
}

function Cell({
  label,
  value,
  rate,
  tone,
}: {
  label: string;
  value: number;
  rate: number | null | undefined;
  tone: "good" | "bad";
}) {
  return (
    <div
      className={`rounded-xl border p-4 ${
        tone === "good"
          ? "border-emerald-500/25 bg-emerald-500/5"
          : "border-rose-500/25 bg-rose-500/5"
      }`}
    >
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums text-white">
        {count(value)}
      </p>
      <p className="mt-0.5 text-xs tabular-nums text-slate-400">
        {rate === null || rate === undefined ? NOT_AVAILABLE : percent(rate)} of this
        true class
      </p>
    </div>
  );
}

export default function ConfusionMatrixPanel({ experiment }: Props) {
  const run = experiment.latestRun;
  if (!run) return null;

  const { truePositives, trueNegatives, falsePositives, falseNegatives } =
    run.confusion;
  const normalized = run.confusionNormalized;

  return (
    <Card>
      <CardHeader
        title={`Confusion matrix — ${detectorLabel(experiment.detector.name)}`}
        subtitle={`Test split at the frozen threshold ${run.threshold}`}
      />
      <CardContent>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Cell
            label="True positive — attack caught"
            value={truePositives}
            rate={normalized?.actualMalicious.predictedMalicious}
            tone="good"
          />
          <Cell
            label="False negative — attack missed"
            value={falseNegatives}
            rate={normalized?.actualMalicious.predictedBenign}
            tone="bad"
          />
          <Cell
            label="False positive — analyst time wasted"
            value={falsePositives}
            rate={normalized?.actualBenign.predictedMalicious}
            tone="bad"
          />
          <Cell
            label="True negative — correctly ignored"
            value={trueNegatives}
            rate={normalized?.actualBenign.predictedBenign}
            tone="good"
          />
        </div>

        <div className="mt-4 grid grid-cols-2 gap-3 text-xs text-slate-500">
          <p>
            Actual malicious:{" "}
            <span className="text-slate-300">
              {count(normalized?.actualMalicious.support)}
            </span>{" "}
            samples
          </p>
          <p>
            Actual benign:{" "}
            <span className="text-slate-300">
              {count(normalized?.actualBenign.support)}
            </span>{" "}
            samples
          </p>
        </div>

        <p className="mt-3 text-xs leading-5 text-slate-500">
          Percentages are {normalized?.normalization ?? "row (by true class)"} — each
          true class sums to 100%. They are not precision, which is computed down the
          predicted column instead.
        </p>
      </CardContent>
    </Card>
  );
}
