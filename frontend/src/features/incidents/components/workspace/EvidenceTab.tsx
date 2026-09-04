import { Braces, Shield } from "lucide-react";

import MLFindingCard from "@/features/detection/components/MLFindingCard";
import RiskBreakdown from "@/features/detection/components/RiskBreakdown";
import type { SignalKind } from "@/features/detection/signalVocabulary";
import { SignalLegend } from "@/features/detection/components/SignalBadge";
import UnavailablePanel from "@/features/detection/components/UnavailablePanel";
import type { ApiEvidenceSet } from "@/services/api/evidence";
import type { IncidentMLFindings } from "@/services/api/ml";
import type { ApiIncident } from "@/services/api/types";

import EvidenceProvenance from "./EvidenceProvenance";

/**
 * Every piece of evidence behind the incident, grouped by where it came from.
 *
 * The grouping is the point. An analyst asking "why is this high risk?" needs
 * to see that a rule fired AND a model ranked it unusual AND a correlation
 * grouped it - three independent things - rather than one merged number.
 */

interface EvidenceTabProps {
  incident: ApiIncident;
  ml: IncidentMLFindings | undefined;
  /** V9: the same evidence with its provenance attached. */
  evidence: ApiEvidenceSet | undefined;
  evidenceLoading: boolean;
  evidenceError: boolean;
}

export default function EvidenceTab({
  incident,
  ml,
  evidence,
  evidenceLoading,
  evidenceError,
}: EvidenceTabProps) {
  const presentKinds = Array.from(
    new Set((incident.riskSignals ?? []).map((signal) => signal.type)),
  ) as SignalKind[];

  return (
    <div className="space-y-6">
      <RiskBreakdown
        score={incident.riskScore}
        level={incident.severity}
        signals={incident.riskSignals ?? []}
        emptyHint="No signal breakdown was recorded for this incident - it predates the hybrid scoring strategy. The rule detections on each linked event are still available."
      />

      {presentKinds.length > 0 && (
        <div>
          <p className="mb-2 text-xs font-medium uppercase tracking-wider text-slate-500">
            Evidence kinds present
          </p>
          <SignalLegend kinds={presentKinds} />
        </div>
      )}

      {/* --- ML ----------------------------------------------------------- */}
      <section>
        <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-white">
          <Shield size={15} className="text-violet-400" />
          ML findings
        </h3>

        {ml && !ml.modelAvailable && ml.findings.length === 0 ? (
          <UnavailablePanel
            title="No anomaly model is running"
            reason={ml.reason}
            hint="python -m app.ml.training.train_anomaly_model"
          />
        ) : (ml?.findings.length ?? 0) === 0 ? (
          <p className="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 px-4 py-6 text-center text-sm text-slate-500">
            The model scored no events in this incident.
          </p>
        ) : (
          <div className="grid gap-3 lg:grid-cols-2">
            {(ml?.findings ?? []).map((finding, index) => (
              <div key={`${finding.eventId}-${index}`}>
                <p className="mb-1.5 truncate font-mono text-[11px] text-slate-500">
                  {finding.eventId} · {finding.eventTitle}
                </p>
                <MLFindingCard
                  model={finding.model}
                  modelVersion={finding.modelVersion}
                  anomalyScore={finding.anomalyScore}
                  threshold={finding.threshold}
                  isAnomaly={finding.isAnomaly}
                  topContributors={finding.topContributors.map((contribution) => ({
                    name: contribution.name,
                    value: contribution.value,
                    deviation: contribution.deviation,
                    direction: contribution.direction === "below" ? "below" : "above",
                  }))}
                  compact
                />
              </div>
            ))}
          </div>
        )}
      </section>

      {/* --- Linked events ------------------------------------------------ */}
      <section>
        <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-white">
          <Braces size={15} className="text-cyan-400" />
          Linked events ({incident.events?.length ?? 0})
        </h3>
        <ul className="space-y-2">
          {(incident.events ?? []).map((event) => (
            <li
              key={event.id}
              className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2"
            >
              <div className="min-w-0">
                <p className="truncate text-sm text-slate-200">{event.title}</p>
                <p className="font-mono text-[11px] text-slate-500">
                  {event.id} · {event.source} ·{" "}
                  {new Date(event.timestamp).toLocaleString()}
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                {event.isAnomaly && (
                  <span
                    className="rounded-full border border-violet-500/30 bg-violet-500/10 px-2 py-0.5 text-[10px] text-violet-300"
                    title="Anomaly score, not a probability"
                  >
                    ML {Math.round((event.anomalyScore ?? 0) * 100)}
                  </span>
                )}
                <span className="text-xs text-slate-500">risk {event.riskScore}</span>
              </div>
            </li>
          ))}
        </ul>
      </section>

      {/* --- Provenance (V9) --------------------------------------------- */}
      <EvidenceProvenance
        evidence={evidence}
        isLoading={evidenceLoading}
        isError={evidenceError}
      />
    </div>
  );
}
