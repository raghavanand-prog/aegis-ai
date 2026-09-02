import { BarChart3, RefreshCw } from "lucide-react";

import { useAnalyticsSummary } from "../hooks/useAnalytics";
import { formatDateTime } from "@/lib/time";

export default function AnalyticsHeader() {
  const { data, isFetching, refetch } = useAnalyticsSummary();

  return (
    <div className="flex flex-wrap items-center justify-between gap-4">
      <div>
        <h1 className="flex items-center gap-3 text-3xl font-bold text-white">
          <BarChart3 className="text-cyan-400" />
          Security Analytics
        </h1>

        <p className="mt-2 text-slate-400">
          {data
            ? `Aggregated from ${data.totalEvents.toLocaleString()} stored events over the last ${data.windowHours}h.`
            : "Aggregating detection and incident data from the backend."}
        </p>
      </div>

      <div className="flex items-center gap-4">
        {data && (
          <p className="text-xs text-slate-500">
            Updated {formatDateTime(data.generatedAt)}
          </p>
        )}

        <button
          onClick={() => void refetch()}
          disabled={isFetching}
          className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-slate-200 transition hover:border-slate-600 hover:bg-slate-800 disabled:opacity-60"
        >
          <RefreshCw size={15} className={isFetching ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>
    </div>
  );
}
