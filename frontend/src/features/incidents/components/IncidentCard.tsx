import {
  ChevronRight,
  ShieldAlert,
} from "lucide-react";

import StatusBadge from "./StatusBadge";
import type { Incident } from "../types";

interface Props {
  incident: Incident;
  onClick: () => void;
}

export default function IncidentCard({
  incident,
  onClick,
}: Props) {
  return (
    <button
      onClick={onClick}
      className="w-full rounded-xl border border-slate-800 bg-slate-900 p-5 text-left transition hover:border-cyan-500/40 hover:bg-slate-800"
    >
      <div className="flex items-start justify-between">
        <div className="flex gap-4">
          <ShieldAlert className="mt-1 text-cyan-400" />

          <div>
            <h3 className="font-semibold text-white">
              {incident.title}
            </h3>

            <p className="mt-1 text-sm text-slate-400">
              {incident.id}
            </p>

            <p className="mt-3 text-sm text-slate-500">
              Assigned to{" "}
              <span className="text-slate-300">
                {incident.analyst}
              </span>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <StatusBadge severity={incident.severity} />

          <ChevronRight className="text-slate-500" />
        </div>
      </div>
    </button>
  );
}