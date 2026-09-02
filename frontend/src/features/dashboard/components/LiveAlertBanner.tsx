import { ArrowRight, ShieldAlert, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";

import { useIncidentsQuery } from "@/features/incidents/hooks/useIncidents";
import { SkeletonBlock } from "@/components/ui";

/**
 * Highlights the most recent unresolved high-impact incident.
 *
 * Reads the real incident list - when nothing critical is open, it says so
 * rather than showing a stock alert.
 */
export default function LiveAlertBanner() {
  const { data, isLoading } = useIncidentsQuery({ limit: 50 });

  if (isLoading) return <SkeletonBlock className="mb-8 h-40" />;

  const incidents = data?.incidents ?? [];
  const priority = incidents.find(
    (incident) =>
      (incident.severity === "Critical" || incident.severity === "High") &&
      incident.status !== "Resolved",
  );

  if (!priority) {
    return (
      <div className="mb-8 overflow-hidden rounded-2xl border border-emerald-500/20 bg-gradient-to-r from-emerald-950/50 via-slate-900 to-slate-900 p-6">
        <div className="flex items-start gap-4">
          <div className="rounded-2xl bg-emerald-500/15 p-4 text-emerald-400">
            <ShieldCheck size={30} />
          </div>

          <div>
            <p className="text-sm font-semibold uppercase tracking-widest text-emerald-400">
              No active critical incidents
            </p>

            <h2 className="mt-1 text-2xl font-bold text-white">
              Queue is clear
            </h2>

            <p className="mt-2 text-slate-300">
              {incidents.length === 0
                ? "Nothing has been promoted from the event stream yet."
                : `${incidents.length} incident(s) on record, none open at high or critical severity.`}
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="mb-8 overflow-hidden rounded-2xl border border-red-500/20 bg-gradient-to-r from-red-950/60 via-red-900/40 to-slate-900 p-6">
      <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-start gap-4">
          <div className="rounded-2xl bg-red-500/15 p-4 text-red-400">
            <ShieldAlert size={30} />
          </div>

          <div>
            <p className="text-sm font-semibold uppercase tracking-widest text-red-400">
              Active Incident
            </p>

            <h2 className="mt-1 text-2xl font-bold text-white">{priority.title}</h2>

            <p className="mt-2 text-slate-300">{priority.description}</p>

            <div className="mt-4 flex flex-wrap gap-3">
              <span className="rounded-full bg-red-500/15 px-3 py-1 text-sm text-red-300">
                Severity: {priority.severity}
              </span>

              <span className="rounded-full bg-yellow-500/15 px-3 py-1 text-sm text-yellow-300">
                Risk score: {priority.riskScore ?? 0}/100
              </span>

              <span className="rounded-full bg-cyan-500/15 px-3 py-1 text-sm text-cyan-300">
                {priority.eventCount ?? priority.eventIds?.length ?? 0} linked event(s)
              </span>

              <span className="rounded-full bg-slate-500/15 px-3 py-1 text-sm text-slate-300">
                {priority.id} - {priority.created}
              </span>
            </div>
          </div>
        </div>

        <Link
          to="/dashboard/incidents"
          className="flex items-center gap-2 rounded-xl bg-red-600 px-5 py-3 font-semibold text-white transition hover:bg-red-500"
        >
          View Incident
          <ArrowRight size={18} />
        </Link>
      </div>
    </div>
  );
}
