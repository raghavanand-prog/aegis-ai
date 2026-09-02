import { X } from "lucide-react";

import IncidentTimeline from "./IncidentTimeline";
import MitrePanel from "./MitrePanel";
import InvestigationPanel from "./InvestigationPanel";
import EvidencePanel from "./EvidencePanel";
import IOCPanel from "./IOCPanel";
import AICopilot from "./AICopilot";
import AnalystNotes from "./AnalystNotes";
import ResponsePlaybook from "./ResponsePlaybook";
import type { Incident } from "../types";

interface IncidentDrawerProps {
  incident: Incident | null;
  open: boolean;
  onClose: () => void;
}

export default function IncidentDrawer({
  incident,
  open,
  onClose,
}: IncidentDrawerProps) {
  if (!open || !incident) return null;

  return (
    <>
      <div
        className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />

      <aside className="fixed right-0 top-0 z-50 h-screen w-full max-w-3xl overflow-y-auto border-l border-slate-800 bg-slate-950 shadow-2xl">
        <div className="sticky top-0 z-10 border-b border-slate-800 bg-slate-950/95 p-6 backdrop-blur">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs uppercase tracking-widest text-cyan-400">
                Incident Details
              </p>

              <h2 className="mt-2 text-2xl font-bold text-white">
                {incident.title}
              </h2>

              <div className="mt-3 flex flex-wrap gap-2 text-sm">
                <span className="rounded bg-slate-800 px-3 py-1 text-slate-300">
                  {incident.id}
                </span>

                <span className="rounded bg-red-500/20 px-3 py-1 text-red-400">
                  {incident.severity}
                </span>

                <span className="rounded bg-emerald-500/20 px-3 py-1 text-emerald-400">
                  {incident.status}
                </span>

                <span className="rounded bg-cyan-500/20 px-3 py-1 text-cyan-300">
                  Analyst: {incident.analyst}
                </span>
              </div>
            </div>

            <button
              onClick={onClose}
              className="rounded-lg border border-slate-700 p-2 text-slate-400 hover:bg-slate-800 hover:text-white"
            >
              <X size={20} />
            </button>
          </div>
        </div>

        <div className="space-y-6 p-6">
          <IncidentTimeline />
          <MitrePanel />
          <InvestigationPanel />
          <EvidencePanel />
          <IOCPanel />
          <AICopilot />
          <AnalystNotes />
          <ResponsePlaybook />
        </div>
      </aside>
    </>
  );
}
