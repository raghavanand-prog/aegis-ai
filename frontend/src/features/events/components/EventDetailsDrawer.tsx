import { X } from "lucide-react";

import MLFindingCard from "@/features/detection/components/MLFindingCard";
import RiskBreakdown from "@/features/detection/components/RiskBreakdown";
import { formatDateTime } from "@/lib/time";

import type { Event } from "../types";
import DetectionExplanations from "./DetectionExplanations";

interface EventDrawerProps {
  event: Event | null;
  open: boolean;
  onClose: () => void;
  onPromote?: (event: Event) => void;
  isPromoting?: boolean;
}

/**
 * One sentence an analyst can act on, written from what actually happened.
 *
 * V3 makes this harder than it looks: "no rule matched" and "the model found
 * nothing" and "the model never ran" are three different statements, and the
 * summary has to pick the true one rather than the convenient one.
 */
function describeTriage(event: Event): string {
  const ruleCount = event.detectionRules?.length ?? 0;
  const anomalies = (event.mlFindings ?? []).filter((finding) => finding.isAnomaly);
  const scored = (event.mlFindings ?? []).length > 0;

  const parts: string[] = [];

  if (ruleCount > 0) {
    parts.push(
      `${ruleCount} deterministic rule${ruleCount === 1 ? "" : "s"} matched, and the reasons above are the conditions that matched.`,
    );
  } else {
    parts.push("No deterministic rule matched this event.");
  }

  if (anomalies.length > 0) {
    parts.push(
      "The anomaly model ranked this behaviour as unusual against its learned baseline - a statistical observation, not an attack technique.",
    );
  } else if (scored) {
    parts.push("The anomaly model scored it and did not find it unusual.");
  } else {
    parts.push(
      "The anomaly model did not score this event, so nothing is known either way about how usual it is.",
    );
  }

  parts.push(`Combined risk score: ${event.riskScore ?? 0}/100.`);
  return parts.join(" ");
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div>
      <p className="text-sm text-slate-400">{label}</p>
      <p className="break-words text-white">{value}</p>
    </div>
  );
}

export default function EventDetailsDrawer({
  event,
  open,
  onClose,
  onPromote,
  isPromoting = false,
}: EventDrawerProps) {
  if (!open || !event) return null;

  const alreadyPromoted = Boolean(event.incidentId);

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/50" onClick={onClose} />

      <div className="fixed right-0 top-0 z-50 h-full w-[500px] overflow-y-auto border-l border-slate-800 bg-slate-950 p-6 shadow-2xl">
        <div className="mb-6 flex items-center justify-between">
          <h2 className="text-2xl font-bold text-white">Event Details</h2>

          <button onClick={onClose}>
            <X className="text-slate-400 hover:text-white" />
          </button>
        </div>

        <div className="space-y-4">
          <Field label="Event ID" value={event.id} />
          <Field
            label="Time"
            value={event.timestamp ? formatDateTime(event.timestamp) : event.time}
          />
          <Field label="Source" value={event.source} />
          <Field label="Event" value={event.event} />
          <Field label="Severity" value={event.severity} />
          <Field label="Status" value={event.status} />

          <Field label="Event Type" value={event.eventType} />
          <Field label="Host" value={event.hostname} />
          <Field label="User" value={event.username} />
          <Field label="Source IP" value={event.sourceIp} />
          <Field
            label="Destination"
            value={
              event.destinationIp
                ? `${event.destinationIp}${
                    event.destinationPort ? `:${event.destinationPort}` : ""
                  }`
                : null
            }
          />
          <Field label="Process" value={event.process} />

          {event.commandLine && (
            <div>
              <p className="text-sm text-slate-400">Command Line</p>
              <pre className="mt-1 overflow-x-auto rounded-lg border border-slate-800 bg-slate-900 p-3 text-xs text-slate-300">
                {event.commandLine}
              </pre>
            </div>
          )}

          {/* V3: the score and the reasons behind it, together. A bare number
              with no breakdown is what makes a SOC score unarguable-with. */}
          {typeof event.riskScore === "number" && (
            <RiskBreakdown
              score={event.riskScore}
              level={event.riskLevel ?? event.severity}
              signals={event.riskSignals ?? []}
              emptyHint="No signal contributed to this score. No rule matched, the anomaly model did not flag it, and no external reputation or correlation applies."
            />
          )}

          <DetectionExplanations
            detections={event.detections}
            ruleIds={event.detectionRules}
          />

          {event.mlFindings && event.mlFindings.length > 0 && (
            <div>
              <p className="mb-2 text-sm text-slate-400">ML Analysis</p>
              <div className="space-y-3">
                {event.mlFindings.map((finding, index) => (
                  <MLFindingCard
                    key={`${finding.model}-${finding.modelVersion}-${index}`}
                    model={finding.model}
                    modelVersion={finding.modelVersion}
                    anomalyScore={finding.anomalyScore}
                    threshold={finding.threshold}
                    isAnomaly={finding.isAnomaly}
                    topContributors={finding.topContributors}
                    inferredAt={finding.inferredAt}
                  />
                ))}
              </div>
            </div>
          )}

          {event.mitreTechniques && event.mitreTechniques.length > 0 && (
            <div>
              <p className="text-sm text-slate-400">MITRE ATT&amp;CK</p>
              <div className="mt-2 flex flex-wrap gap-2">
                {event.mitreTechniques.map((technique) => (
                  <span
                    key={technique}
                    className="rounded-full border border-purple-500/30 bg-purple-500/10 px-3 py-1 text-xs text-purple-300"
                  >
                    {technique}
                  </span>
                ))}
              </div>
            </div>
          )}

          {event.iocs && event.iocs.length > 0 && (
            <div>
              <p className="text-sm text-slate-400">Indicators</p>
              <ul className="mt-2 space-y-2">
                {event.iocs.map((ioc) => (
                  <li
                    key={ioc.id}
                    className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-sm"
                  >
                    <span className="text-slate-300">
                      <span className="text-slate-500">{ioc.type}</span> {ioc.value}
                    </span>
                    <span className="text-xs text-slate-500">
                      seen {ioc.sightingCount}x
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {event.rawLog && (
            <div>
              <p className="text-sm text-slate-400">Raw Telemetry</p>
              <pre className="mt-1 overflow-x-auto rounded-lg border border-slate-800 bg-slate-900 p-3 text-xs text-slate-400">
                {event.rawLog}
              </pre>
            </div>
          )}

          <div className="mt-8 rounded-lg border border-slate-800 bg-slate-900 p-4">
            <h3 className="mb-2 font-semibold text-white">Triage Summary</h3>

            <p className="text-sm leading-6 text-slate-400">
              {describeTriage(event)}
            </p>

            {event.isSynthetic && (
              <p className="mt-3 text-xs text-amber-400/80">
                Synthetic telemetry - generated by the AEGISX simulator, not a real system.
              </p>
            )}
          </div>

          {alreadyPromoted ? (
            <div className="mt-6 rounded-lg border border-slate-800 bg-slate-900 p-4 text-center text-sm text-slate-400">
              Already promoted to{" "}
              <span className="font-semibold text-white">{event.incidentId}</span>
            </div>
          ) : (
            <button
              onClick={() => onPromote?.(event)}
              disabled={isPromoting || !onPromote}
              className="mt-6 flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 py-3 font-semibold text-white transition hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {isPromoting && (
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white" />
              )}
              {isPromoting ? "Promoting..." : "Promote to Incident"}
            </button>
          )}
        </div>
      </div>
    </>
  );
}
