import type { Feedback } from "@/services/api/adaptation";

import { LABEL_TEXT, TRAINING_ELIGIBLE, decimal } from "./adaptiveFormat";

/**
 * Analyst feedback.
 *
 * Two things are shown that a naive table would drop. A confidence the analyst
 * never stated renders as `n/a`, not 0. And a label's training eligibility is
 * marked, because `suspicious` and `uncertain` describe a state of
 * investigation and never enter a training set — which is worth seeing next to
 * the label rather than discovering in a dataset card.
 */
export default function FeedbackPanel({ items }: { items: Feedback[] }) {
  if (items.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-6">
        <p className="text-sm text-slate-300">No analyst feedback has been recorded.</p>
        <p className="mt-2 text-xs text-slate-500">
          Feedback is submitted by an analyst against an event, incident or sequence.
          Every adaptation V5 can propose is built from it.
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-slate-800">
      <table className="min-w-full text-sm">
        <thead className="bg-slate-900/60 text-xs uppercase tracking-wide text-slate-400">
          <tr>
            <th className="px-4 py-3 text-left">Target</th>
            <th className="px-4 py-3 text-left">Label</th>
            <th className="px-4 py-3 text-right">Confidence</th>
            <th className="px-4 py-3 text-left">Analyst</th>
            <th className="px-4 py-3 text-left">Source</th>
            <th className="px-4 py-3 text-left">Schema</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800">
          {items.map((item) => (
            <tr key={item.id} className="text-slate-200">
              <td className="px-4 py-3 font-mono text-xs">{item.targetId}</td>
              <td className="px-4 py-3">
                <span>{LABEL_TEXT[item.label] ?? item.label}</span>
                {!TRAINING_ELIGIBLE.has(item.label) && (
                  <span
                    className="ml-2 rounded border border-slate-600 px-1.5 py-0.5 text-[10px] text-slate-400"
                    title="Describes a state of investigation, not a class. Never enters a training set."
                  >
                    not trainable
                  </span>
                )}
              </td>
              <td className="px-4 py-3 text-right font-mono">
                {decimal(item.confidence, 2)}
              </td>
              <td className="px-4 py-3 text-xs text-slate-400">{item.analyst}</td>
              <td className="px-4 py-3 text-xs text-slate-400">{item.source}</td>
              <td className="px-4 py-3 font-mono text-xs text-slate-500">
                v{item.featureSchemaVersion}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
