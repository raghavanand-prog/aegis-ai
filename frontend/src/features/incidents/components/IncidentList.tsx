import IncidentCard from "./IncidentCard";
import type { Incident } from "../types";

interface IncidentListProps {
  incidents: Incident[];
  onIncidentClick: (incident: Incident) => void;
}

export default function IncidentList({
  incidents,
  onIncidentClick,
}: IncidentListProps) {
  return (
    <div className="space-y-4">
      {incidents.length > 0 ? (
        incidents.map((incident) => (
          <IncidentCard
            key={incident.id}
            incident={incident}
            onClick={() => onIncidentClick(incident)}
          />
        ))
      ) : (
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-10 text-center">
          <h3 className="text-lg font-semibold text-white">
            No Incidents Found
          </h3>

          <p className="mt-2 text-slate-400">
            Promoted events will appear here automatically.
          </p>
        </div>
      )}
    </div>
  );
}