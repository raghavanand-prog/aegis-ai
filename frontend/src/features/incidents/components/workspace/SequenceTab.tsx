import { GitBranch, Network } from "lucide-react";

import SignalBadge from "@/features/detection/components/SignalBadge";
import type { ApiSequence } from "@/services/api/mlTypes";

/**
 * Correlated sequences the incident's events belong to.
 *
 * The section that matters most is "why these events were grouped": a
 * correlation an analyst cannot interrogate is just an assertion.
 */

export default function SequenceTab({ sequences }: { sequences: ApiSequence[] }) {
  if (sequences.length === 0) {
    return (
      <p className="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 px-5 py-10 text-center text-sm leading-6 text-slate-500">
        None of this incident&apos;s events are part of a correlated sequence.
        Correlation groups related activity by host, account or source address
        inside a time window.
      </p>
    );
  }

  return (
    <div className="space-y-5">
      {sequences.map((sequence) => (
        <article
          key={sequence.id}
          className="rounded-xl border border-emerald-500/20 bg-slate-900/70 p-5"
        >
          <header className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <Network size={15} className="text-emerald-400" />
                <h3 className="text-sm font-semibold text-white">{sequence.title}</h3>
              </div>
              <p className="mt-1 truncate font-mono text-[11px] text-slate-500">
                {sequence.id} · {sequence.pattern} · {sequence.correlationKey}
              </p>
            </div>
            <div className="shrink-0 text-right">
              <p className="text-lg font-bold text-white">{sequence.riskScore}</p>
              <p
                className="text-[11px] text-slate-500"
                title="How strongly the grouping itself is believed. Not a probability of compromise."
              >
                correlation confidence {sequence.confidence.toFixed(2)}
              </p>
            </div>
          </header>

          <p className="mt-3 text-sm leading-6 text-slate-400">{sequence.description}</p>

          {sequence.rationale.length > 0 && (
            <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950/60 p-3">
              <p className="flex items-center gap-1.5 text-xs font-medium uppercase tracking-wider text-slate-500">
                <GitBranch size={11} />
                Why these events were grouped
              </p>
              <ul className="mt-2 space-y-1">
                {sequence.rationale.map((reason, index) => (
                  <li key={index} className="text-sm leading-6 text-slate-300">
                    · {reason}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {sequence.riskSignals.length > 0 && (
            <div className="mt-4 flex flex-wrap gap-2">
              {sequence.riskSignals.map((signal, index) => (
                <SignalBadge
                  key={index}
                  kind={signal.type}
                  detail={`${signal.source} +${signal.contribution}`}
                  size="sm"
                />
              ))}
            </div>
          )}

          <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-2 text-xs sm:grid-cols-4">
            {Object.entries(sequence.entities)
              .filter(([, values]) => values.length > 0)
              .map(([kind, values]) => (
                <div key={kind} className="min-w-0">
                  <dt className="text-slate-500">{kind}</dt>
                  <dd className="mt-0.5 truncate text-slate-300" title={values.join(", ")}>
                    {values.slice(0, 3).join(", ")}
                    {values.length > 3 && ` +${values.length - 3}`}
                  </dd>
                </div>
              ))}
          </dl>

          <p className="mt-3 text-[11px] text-slate-600">
            {sequence.eventCount} events ·{" "}
            {new Date(sequence.startTime).toLocaleString()} to{" "}
            {new Date(sequence.endTime).toLocaleTimeString()}
          </p>
        </article>
      ))}
    </div>
  );
}
