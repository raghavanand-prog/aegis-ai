import { AlertTriangle } from "lucide-react";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import Card from "@/components/ui/Card";
import CardContent from "@/components/ui/CardContent";
import CardHeader from "@/components/ui/CardHeader";
import UnavailablePanel from "@/features/detection/components/UnavailablePanel";

import { AXIS, GRID, tooltipStyle } from "@/features/analytics/components/chartTheme";
import type { Experiment } from "@/services/api/evaluation";
import { detectorLabel, scoreKindCaution } from "./metricFormat";

/**
 * The operational trade-off curve: recall against analyst workload.
 *
 * Two things this panel refuses to do:
 *
 * - It never draws a curve for a detector with no ordering. A rule either
 *   matched or it did not, so a "threshold curve" for it would be a straight
 *   line with no meaning, and the panel says that instead of drawing it.
 * - It marks the chosen threshold with a line labelled "chosen on validation",
 *   because the curve shown is the *validation* curve. Reading a frozen
 *   threshold off a test curve is the mistake this whole protocol exists to
 *   prevent, and the chart should not imply that is what happened.
 *
 * Alert volume is plotted alongside precision and recall on a second axis,
 * because "recall went up" and "the queue tripled" are the same decision.
 */

interface Props {
  experiment: Experiment;
}

export default function ThresholdAnalysis({ experiment }: Props) {
  const run = experiment.latestRun;
  const sweep = run?.thresholdSweep ?? [];
  const caution = scoreKindCaution(experiment.detector.scoreKind);

  if (!run || sweep.length === 0) {
    return (
      <Card>
        <CardHeader
          title="Threshold analysis"
          subtitle={detectorLabel(experiment.detector.name)}
        />
        <CardContent>
          <UnavailablePanel
            title="No threshold curve for this detector"
            reason={
              run?.thresholdSelection?.note ??
              "This detector emits no ordered score, so there is no threshold to sweep. A curve here would be decoration, not a measurement."
            }
          />
        </CardContent>
      </Card>
    );
  }

  const data = sweep.map((point) => ({
    threshold: point.threshold,
    precision: point.precision === null ? null : point.precision * 100,
    recall: point.recall === null ? null : point.recall * 100,
    f1: point.f1 === null ? null : point.f1 * 100,
    alertsPerThousand: point.alertsPerThousandEvents,
  }));

  const boundaryWarning = run.thresholdSelection?.warning;

  return (
    <Card>
      <CardHeader
        title="Threshold analysis"
        subtitle={`${detectorLabel(experiment.detector.name)} · measured on the validation split`}
      />
      <CardContent>
        {caution && (
          <p className="mb-3 rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs leading-5 text-slate-400">
            {caution}
          </p>
        )}

        {boundaryWarning && (
          <div className="mb-3 flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2">
            <AlertTriangle size={16} className="mt-0.5 shrink-0 text-amber-400" />
            <p className="text-xs leading-5 text-amber-200">{boundaryWarning}</p>
          </div>
        )}

        <div className="h-72 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
              <CartesianGrid stroke={GRID} strokeDasharray="3 3" />
              <XAxis
                dataKey="threshold"
                stroke={AXIS}
                tick={{ fontSize: 11 }}
                label={{
                  value: "Decision threshold",
                  position: "insideBottom",
                  offset: -4,
                  fill: AXIS,
                  fontSize: 11,
                }}
              />
              <YAxis
                yAxisId="rate"
                stroke={AXIS}
                tick={{ fontSize: 11 }}
                domain={[0, 100]}
                label={{
                  value: "%",
                  angle: -90,
                  position: "insideLeft",
                  fill: AXIS,
                  fontSize: 11,
                }}
              />
              <YAxis
                yAxisId="volume"
                orientation="right"
                stroke={AXIS}
                tick={{ fontSize: 11 }}
                label={{
                  value: "alerts / 1,000 events",
                  angle: 90,
                  position: "insideRight",
                  fill: AXIS,
                  fontSize: 11,
                }}
              />
              <Tooltip {...tooltipStyle} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <ReferenceLine
                yAxisId="rate"
                x={run.threshold}
                stroke="#f59e0b"
                strokeDasharray="4 4"
                label={{
                  value: "chosen on validation",
                  fill: "#f59e0b",
                  fontSize: 10,
                  position: "top",
                }}
              />
              <Line
                yAxisId="rate"
                type="monotone"
                dataKey="precision"
                name="Precision %"
                stroke="#22d3ee"
                dot={false}
                connectNulls={false}
              />
              <Line
                yAxisId="rate"
                type="monotone"
                dataKey="recall"
                name="Recall %"
                stroke="#a78bfa"
                dot={false}
                connectNulls={false}
              />
              <Line
                yAxisId="rate"
                type="monotone"
                dataKey="f1"
                name="F1 %"
                stroke="#34d399"
                dot={false}
                connectNulls={false}
              />
              <Line
                yAxisId="volume"
                type="monotone"
                dataKey="alertsPerThousand"
                name="Alerts / 1,000 events"
                stroke="#f97316"
                strokeDasharray="5 3"
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <p className="mt-3 text-xs leading-5 text-slate-500">
          {run.thresholdSelection?.method ?? "Threshold selected on validation."}{" "}
          Objective: {run.thresholdSelection?.objective ?? "n/a"}. The test split was
          evaluated once, afterwards, at this frozen value — it did not contribute to
          choosing it.
        </p>
      </CardContent>
    </Card>
  );
}
