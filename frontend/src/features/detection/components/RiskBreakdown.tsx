import { useMemo } from "react";

import type { ApiRiskSignal } from "@/services/api/mlTypes";

import SignalBadge from "./SignalBadge";

/**
 * The answer to "why is this high risk?".
 *
 * Renders each contribution to a risk score as its own row, labelled with the
 * kind of evidence it came from and the number of points it added. The score is
 * never shown as a bare figure without this breakdown available next to it -
 * that is the whole point of storing `riskSignals` in the first place.
 */

interface RiskBreakdownProps {
  score: number;
  level?: string;
  signals: ApiRiskSignal[];
  /** Rendered when there are no signals at all. */
  emptyHint?: string;
  compact?: boolean;
}

function levelClass(level: string): string {
  switch (level) {
    case "Critical":
      return "border-red-500/40 bg-red-500/10 text-red-300";
    case "High":
      return "border-orange-500/40 bg-orange-500/10 text-orange-300";
    case "Medium":
      return "border-amber-500/40 bg-amber-500/10 text-amber-300";
    default:
      return "border-slate-600/50 bg-slate-700/30 text-slate-300";
  }
}

export default function RiskBreakdown({
  score,
  level,
  signals,
  emptyHint,
  compact = false,
}: RiskBreakdownProps) {
  const total = useMemo(
    () => signals.reduce((sum, signal) => sum + signal.contribution, 0),
    [signals],
  );

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-xs uppercase tracking-widest text-slate-500">
            Risk Score
          </p>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white">{score}</span>
            <span className="text-sm text-slate-500">/ 100</span>
            {level && (
              <span
                className={`ml-2 rounded-full border px-2.5 py-0.5 text-xs font-medium ${levelClass(level)}`}
              >
                {level}
              </span>
            )}
          </div>
        </div>

        {signals.length > 0 && (
          <p className="max-w-xs text-right text-xs leading-5 text-slate-500">
            Weighted sum of {signals.length} signal
            {signals.length === 1 ? "" : "s"}
            {total !== score && (
              <>
                {" "}
                ({total} before the 0-100 cap)
              </>
            )}
          </p>
        )}
      </div>

      {signals.length === 0 ? (
        <p className="mt-4 text-sm leading-6 text-slate-500">
          {emptyHint ??
            "No signal contributed to this score. Nothing has been detected, ranked or corroborated for this event."}
        </p>
      ) : (
        <ul className="mt-4 space-y-2.5">
          {signals
            .slice()
            .sort((a, b) => b.contribution - a.contribution)
            .map((signal, index) => (
              <li
                key={`${signal.type}-${signal.source}-${index}`}
                className="rounded-lg border border-slate-800 bg-slate-950/60 p-3"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <SignalBadge
                    kind={signal.type}
                    detail={signal.source}
                    size="sm"
                  />
                  <span className="font-mono text-sm font-semibold text-white">
                    +{signal.contribution}
                  </span>
                </div>

                {!compact && (
                  <p className="mt-2 text-sm leading-6 text-slate-400">
                    {signal.detail}
                  </p>
                )}

                {/* Proportional bar. Width is the share of the final score, so
                    a glance shows which evidence dominates. */}
                <div className="mt-2 h-1 overflow-hidden rounded-full bg-slate-800">
                  <div
                    className={`h-full ${
                      signal.type === "rule"
                        ? "bg-cyan-400"
                        : signal.type === "ml"
                          ? "bg-violet-400"
                          : signal.type === "threat_intel"
                            ? "bg-amber-400"
                            : signal.type === "correlation"
                              ? "bg-emerald-400"
                              : "bg-slate-500"
                    }`}
                    style={{
                      width: `${Math.min(
                        100,
                        (signal.contribution / Math.max(score, 1)) * 100,
                      )}%`,
                    }}
                  />
                </div>
              </li>
            ))}
        </ul>
      )}
    </div>
  );
}
