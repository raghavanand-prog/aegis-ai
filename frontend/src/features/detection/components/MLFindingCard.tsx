import { Sparkles, TrendingDown, TrendingUp } from "lucide-react";

import type { ApiFeatureContribution } from "@/services/api/mlTypes";

/**
 * One anomaly-model verdict.
 *
 * Deliberate wording choices, because this is the panel most likely to be
 * misread as a confidence:
 *
 * - the number is labelled "Anomaly score", never "confidence" or "probability";
 * - the threshold is shown next to it, so the score has a reference point;
 * - the drivers are headed "furthest from normal", not "causes", because
 *   Isolation Forest gives no per-prediction attribution and claiming one would
 *   be inventing an explanation;
 * - a below-threshold score is rendered plainly, not hidden, so an analyst can
 *   see the model looked and did not object.
 */

interface MLFindingCardProps {
  model: string;
  modelVersion: string;
  anomalyScore: number;
  threshold: number;
  isAnomaly: boolean;
  topContributors?: ApiFeatureContribution[];
  inferredAt?: string;
  compact?: boolean;
}

function humanise(feature: string): string {
  return feature
    .replace(/_scaled$/, "")
    .replace(/_/g, " ")
    .replace(/\bis /, "");
}

export default function MLFindingCard({
  model,
  modelVersion,
  anomalyScore,
  threshold,
  isAnomaly,
  topContributors = [],
  inferredAt,
  compact = false,
}: MLFindingCardProps) {
  const percent = Math.round(anomalyScore * 100);
  const thresholdPercent = Math.round(threshold * 100);

  return (
    <div
      className={`rounded-xl border p-4 ${
        isAnomaly
          ? "border-violet-500/30 bg-violet-500/5"
          : "border-slate-800 bg-slate-900/60"
      }`}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <Sparkles
            size={16}
            className={isAnomaly ? "text-violet-400" : "text-slate-500"}
          />
          <div>
            <p className="text-sm font-semibold text-white">
              {isAnomaly ? "ML Anomaly" : "Scored, not anomalous"}
            </p>
            <p className="text-xs text-slate-500">
              {model} v{modelVersion}
            </p>
          </div>
        </div>

        <div className="text-right">
          <div className="flex items-baseline gap-1">
            <span
              className={`text-2xl font-bold ${
                isAnomaly ? "text-violet-300" : "text-slate-400"
              }`}
            >
              {percent}
            </span>
            <span className="text-xs text-slate-500">/ 100</span>
          </div>
          <p className="text-[11px] text-slate-500">
            Anomaly score · threshold {thresholdPercent}
          </p>
        </div>
      </div>

      {/* Score bar with the threshold marked, so the number has a reference. */}
      <div className="relative mt-3 h-1.5 overflow-hidden rounded-full bg-slate-800">
        <div
          className={`h-full ${isAnomaly ? "bg-violet-400" : "bg-slate-600"}`}
          style={{ width: `${percent}%` }}
        />
        <div
          className="absolute top-0 h-full w-px bg-slate-400"
          style={{ left: `${thresholdPercent}%` }}
          title={`Anomaly threshold: ${threshold}`}
        />
      </div>

      {!compact && (
        <p className="mt-3 text-xs leading-5 text-slate-500">
          A ranking from an unsupervised model, not a probability and not a
          confidence. It says this behaviour is unusual against the learned
          baseline &mdash; unusual is not the same as malicious, and the model
          identifies no attack technique.
        </p>
      )}

      {topContributors.length > 0 && (
        <div className="mt-4">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
            Features furthest from normal
          </p>
          <ul className="mt-2 space-y-1.5">
            {topContributors.map((contribution) => (
              <li
                key={contribution.name}
                className="flex items-center justify-between gap-3 rounded-lg bg-slate-950/60 px-3 py-1.5 text-xs"
              >
                <span className="flex items-center gap-1.5 text-slate-300">
                  {contribution.direction === "above" ? (
                    <TrendingUp size={12} className="text-violet-400" />
                  ) : (
                    <TrendingDown size={12} className="text-cyan-400" />
                  )}
                  {humanise(contribution.name)}
                </span>
                <span className="font-mono text-slate-500">
                  {contribution.deviation > 0 ? "+" : ""}
                  {contribution.deviation.toFixed(1)}&sigma;
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {inferredAt && !compact && (
        <p className="mt-3 text-[11px] text-slate-600">
          Scored {new Date(inferredAt).toLocaleString()}
        </p>
      )}
    </div>
  );
}
