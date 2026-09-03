import type { ReviewQueueResponse } from "@/services/api/adaptation";

import { decimal } from "./adaptiveFormat";

/**
 * The active-learning review queue.
 *
 * The interpretation line is rendered verbatim and first. A ranked list of
 * events reads as a worklist of confirmed findings unless something says
 * otherwise, and this ranking makes no claim about whether any of them is
 * malicious — only that a verdict would be informative.
 *
 * The selector weights are shown because the ordering is a policy choice, not
 * a measurement, and an analyst is entitled to disagree with it.
 */
export default function ReviewQueuePanel({ data }: { data: ReviewQueueResponse }) {
  return (
    <div className="space-y-4">
      <p className="rounded-lg border border-slate-800 bg-slate-900/40 p-4 text-sm text-slate-300">
        {data.interpretation}
      </p>

      <p className="text-xs text-slate-500">
        Ranking weights:{" "}
        {Object.entries(data.weights)
          .map(([name, weight]) => `${name} ${decimal(weight, 2)}`)
          .join(" · ")}
      </p>

      {data.candidates.length === 0 ? (
        <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-6 text-sm text-slate-300">
          Nothing is queued for review. Every recent event either already carries
          feedback or offers no signal worth an analyst&apos;s time.
        </div>
      ) : (
        <div className="space-y-2">
          {data.candidates.map((candidate) => (
            <article
              key={candidate.eventId}
              className="rounded-lg border border-slate-800 bg-slate-900/40 p-3"
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-sm text-slate-100">{candidate.title}</p>
                  <p className="mt-1 font-mono text-xs text-slate-500">{candidate.eventId}</p>
                </div>
                <span className="font-mono text-xs text-cyan-300">
                  {decimal(candidate.priority, 3)}
                </span>
              </div>
              <p className="mt-2 text-xs text-slate-400">{candidate.reason}</p>
              <p className="mt-2 font-mono text-[11px] text-slate-600">
                rules {candidate.ruleHit ? "hit" : "clear"} · ml{" "}
                {candidate.mlFlagged ? "flagged" : "clear"} · score{" "}
                {decimal(candidate.anomalyScore, 3)} · threshold{" "}
                {decimal(candidate.threshold, 2)}
              </p>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
