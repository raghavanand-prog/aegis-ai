import Card from "@/components/ui/Card";
import CardContent from "@/components/ui/CardContent";
import CardHeader from "@/components/ui/CardHeader";
import UnavailablePanel from "@/features/detection/components/UnavailablePanel";

import type { Experiment } from "@/services/api/evaluation";
import { NOT_AVAILABLE, count, detectorLabel, percent } from "./metricFormat";

/**
 * Detection rate per attack class.
 *
 * The most useful panel on the page for an engineer, because an aggregate F1
 * hides which attacks a detector simply cannot see. A class with too few
 * samples to support a rate is marked as such rather than being drawn as a
 * confident 0% or 100% — with nine samples, either figure is noise.
 */

interface Props {
  experiment: Experiment;
}

export default function PerClassPanel({ experiment }: Props) {
  const run = experiment.latestRun;
  const perClass = run?.perClass ?? {};
  const entries = Object.entries(perClass).sort(([, a], [, b]) => b.total - a.total);

  if (entries.length === 0) {
    return (
      <Card>
        <CardHeader title="Detection by class" />
        <CardContent>
          <UnavailablePanel
            title="No per-class breakdown recorded"
            reason="This run did not record a per-class breakdown."
          />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader
        title="Detection by class"
        subtitle={`${detectorLabel(experiment.detector.name)} · test split`}
      />
      <CardContent>
        <div className="space-y-2.5">
          {entries.map(([label, entry]) => {
            const rate = entry.detectionRate;
            const width = rate === null ? 0 : Math.max(rate * 100, 0.5);
            return (
              <div key={label}>
                <div className="flex items-baseline justify-between gap-3">
                  <span className="truncate text-xs text-slate-300">{label}</span>
                  <span className="shrink-0 font-mono text-xs tabular-nums text-slate-400">
                    {entry.detected}/{count(entry.total)} ·{" "}
                    {rate === null ? NOT_AVAILABLE : percent(rate)}
                  </span>
                </div>
                <div className="mt-1 h-2 overflow-hidden rounded-full bg-slate-800">
                  <div
                    className={`h-full rounded-full ${
                      entry.sufficientData ? "bg-cyan-500/70" : "bg-slate-600"
                    }`}
                    style={{ width: `${width}%` }}
                  />
                </div>
                {!entry.sufficientData && (
                  <p className="mt-0.5 text-[11px] text-slate-600">
                    Fewer than 20 samples — this rate is indicative only.
                  </p>
                )}
              </div>
            );
          })}
        </div>

        <p className="mt-4 text-xs leading-5 text-slate-500">
          Bars in grey have too few samples for the rate to be reliable. A class this
          detector never catches is shown at 0%, which is a measurement; a class with
          no samples at all is absent rather than drawn as zero.
        </p>
      </CardContent>
    </Card>
  );
}
