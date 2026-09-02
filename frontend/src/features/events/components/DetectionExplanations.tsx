import { ShieldAlert } from "lucide-react";

import type { DetectionExplanation } from "../types";

const SEVERITY_TONE: Record<string, string> = {
  Critical: "border-red-500/30 bg-red-500/10 text-red-300",
  High: "border-orange-500/30 bg-orange-500/10 text-orange-300",
  Medium: "border-yellow-500/30 bg-yellow-500/10 text-yellow-300",
  Low: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
};

interface Props {
  detections?: DetectionExplanation[];
  /** V1 events stored only the rule ids; shown as a fallback. */
  ruleIds?: string[];
}

/**
 * Why the engine flagged this event.
 *
 * Each card is one rule match: which rule, which version of it, the condition
 * that matched in words, and what it contributed to the risk score. An analyst
 * should never have to read the rule source to understand an alert.
 */
export default function DetectionExplanations({ detections, ruleIds }: Props) {
  if (!detections?.length) {
    if (!ruleIds?.length) return null;

    // Event stored before V2: ids without reasons. Say that rather than
    // inventing an explanation after the fact.
    return (
      <div>
        <p className="text-sm text-slate-400">Detection Rules</p>
        <div className="mt-2 flex flex-wrap gap-2">
          {ruleIds.map((rule) => (
            <span
              key={rule}
              className="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-xs text-cyan-300"
            >
              {rule}
            </span>
          ))}
        </div>
        <p className="mt-2 text-xs text-slate-600">
          Recorded before rule explanations were stored.
        </p>
      </div>
    );
  }

  return (
    <div>
      <p className="text-sm text-slate-400">
        Why this fired ({detections.length} rule{detections.length === 1 ? "" : "s"})
      </p>

      <div className="mt-2 space-y-3">
        {detections.map((detection) => (
          <div
            key={`${detection.ruleId}-${detection.matchedAt}`}
            className="rounded-lg border border-slate-800 bg-slate-900 p-3"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2">
                <ShieldAlert size={15} className="shrink-0 text-cyan-400" />
                <span className="text-sm font-semibold text-white">
                  {detection.ruleName}
                </span>
              </div>

              <span
                className={`shrink-0 rounded-full border px-2 py-0.5 text-[11px] ${
                  SEVERITY_TONE[detection.severity] ?? SEVERITY_TONE.Low
                }`}
              >
                {detection.severity}
              </span>
            </div>

            <p className="mt-2 text-sm leading-6 text-slate-300">{detection.reason}</p>

            <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px]">
              <span className="rounded border border-slate-700 px-2 py-0.5 font-mono text-slate-400">
                {detection.ruleId} v{detection.ruleVersion}
              </span>

              <span className="rounded border border-slate-700 px-2 py-0.5 text-slate-400">
                risk +{detection.riskContribution}
              </span>

              {detection.mitreTechniques.map((technique) => (
                <span
                  key={technique}
                  className="rounded border border-purple-500/30 bg-purple-500/10 px-2 py-0.5 text-purple-300"
                >
                  {technique}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
