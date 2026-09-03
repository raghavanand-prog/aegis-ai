import type { DriftStatusResponse } from "@/services/api/adaptation";

import { DRIFT_STATUS_STYLE, decimal, statusText } from "./adaptiveFormat";

/**
 * Feature drift.
 *
 * The interpretation line from the API is rendered verbatim and prominently.
 * "Drift detected" reads as "the model has failed" unless something says
 * otherwise, and the measurement does not support that conclusion.
 *
 * Each row shows the bands that produced its status, because "significant" is
 * meaningless without them and they are configurable per deployment.
 */
export default function DriftPanel({ data }: { data: DriftStatusResponse }) {
  if (data.features.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-6">
        <p className="text-sm text-slate-300">No drift measurements have been recorded.</p>
        <p className="mt-2 text-xs text-slate-500">
          Drift is computed by an operator against a named baseline window. Until a
          comparison has been run there is nothing to show — which is different from
          having run one and found the distribution stable.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <p className="rounded-lg border border-slate-800 bg-slate-900/40 p-4 text-sm text-slate-300">
        {data.interpretation}
      </p>

      <div className="overflow-x-auto rounded-lg border border-slate-800">
        <table className="min-w-full text-sm">
          <thead className="bg-slate-900/60 text-xs uppercase tracking-wide text-slate-400">
            <tr>
              <th className="px-4 py-3 text-left">Feature</th>
              <th className="px-4 py-3 text-left">Kind</th>
              <th className="px-4 py-3 text-right">PSI</th>
              <th className="px-4 py-3 text-right">Wasserstein</th>
              <th className="px-4 py-3 text-right">Bands</th>
              <th className="px-4 py-3 text-right">Samples</th>
              <th className="px-4 py-3 text-left">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {data.features.map((reading) => (
              <tr key={reading.id} className="text-slate-200">
                <td className="px-4 py-3 font-mono text-xs">{reading.feature}</td>
                <td className="px-4 py-3 text-xs text-slate-400">{reading.kind}</td>
                <td className="px-4 py-3 text-right font-mono">
                  {decimal(reading.metricValue, 4)}
                </td>
                <td className="px-4 py-3 text-right font-mono text-slate-400">
                  {decimal(reading.secondaryMetricValue, 4)}
                </td>
                <td className="px-4 py-3 text-right font-mono text-xs text-slate-500">
                  {decimal(reading.moderateThreshold, 2)} / {decimal(reading.significantThreshold, 2)}
                </td>
                <td className="px-4 py-3 text-right font-mono text-xs text-slate-400">
                  {reading.referenceSamples} → {reading.currentSamples}
                </td>
                <td className="px-4 py-3">
                  <span
                    className={`rounded border px-2 py-1 text-xs ${
                      DRIFT_STATUS_STYLE[reading.status] ?? ""
                    }`}
                  >
                    {statusText(reading.status)}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
