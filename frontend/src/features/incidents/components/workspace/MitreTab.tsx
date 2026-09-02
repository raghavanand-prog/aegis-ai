import { Crosshair } from "lucide-react";

import type { ApiSequence, ApiTechnique } from "@/services/api/mlTypes";
import type { ApiIncident } from "@/services/api/types";

/**
 * MITRE ATT&CK context, with provenance kept visible.
 *
 * "mapped", "inferred" and "contextual" are three different strengths of claim.
 * Collapsing them into one row of technique badges is how a platform ends up
 * asserting it detected a technique it merely guessed at.
 */

const PROVENANCE_COPY: Record<
  string,
  { label: string; detail: string; className: string }
> = {
  mapped: {
    label: "Directly mapped",
    detail:
      "A deterministic rule declared this technique and stated the condition it matched.",
    className: "border-cyan-500/30 bg-cyan-500/10 text-cyan-300",
  },
  inferred: {
    label: "Inferred by correlation",
    detail:
      "Derived from the shape of a correlated sequence. An inference from event ordering, not a directly observed technique.",
    className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  },
  contextual: {
    label: "Contextual",
    detail:
      "Present on a member event without a rule declaring it. Background, not a finding.",
    className: "border-slate-600/50 bg-slate-700/30 text-slate-300",
  },
};

const ORDER = ["mapped", "inferred", "contextual"];

export default function MitreTab({
  incident,
  sequences,
}: {
  incident: ApiIncident;
  sequences: ApiSequence[];
}) {
  const withProvenance: ApiTechnique[] = sequences.flatMap((s) => s.techniques);
  const seen = new Set(withProvenance.map((t) => t.technique));
  const flatOnly = (incident.mitreTechniques ?? []).filter((t) => !seen.has(t));

  const grouped = withProvenance.reduce<Record<string, ApiTechnique[]>>(
    (acc, technique) => {
      (acc[technique.provenance] ??= []).push(technique);
      return acc;
    },
    {},
  );

  if (withProvenance.length === 0 && flatOnly.length === 0) {
    return (
      <p className="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 px-5 py-10 text-center text-sm text-slate-500">
        No ATT&amp;CK technique is associated with this incident.
      </p>
    );
  }

  return (
    <div className="space-y-6">
      <p className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-xs leading-5 text-slate-400">
        The anomaly model contributes no techniques. It identifies statistical
        outliers and has no concept of an attack technique, so nothing here is
        ever attributed to it.
      </p>

      {ORDER.filter((provenance) => grouped[provenance]?.length).map((provenance) => {
        const copy = PROVENANCE_COPY[provenance];
        return (
          <section key={provenance}>
            <h3 className="text-sm font-semibold text-white">{copy.label}</h3>
            <p className="mt-1 text-xs leading-5 text-slate-500">{copy.detail}</p>
            <ul className="mt-3 space-y-2">
              {grouped[provenance].map((technique) => (
                <li
                  key={`${technique.technique}-${technique.source}`}
                  className="flex flex-wrap items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2"
                >
                  <span className={`rounded border px-2 py-0.5 font-mono text-xs ${copy.className}`}>
                    {technique.technique}
                  </span>
                  <span className="min-w-0 flex-1 text-xs text-slate-400">
                    {technique.detail}
                  </span>
                  <span className="font-mono text-[11px] text-slate-600">
                    {technique.source}
                  </span>
                </li>
              ))}
            </ul>
          </section>
        );
      })}

      {flatOnly.length > 0 && (
        <section>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-white">
            <Crosshair size={14} className="text-purple-400" />
            Recorded on the incident
          </h3>
          <p className="mt-1 text-xs leading-5 text-slate-500">
            Carried on the incident record without provenance metadata &mdash;
            typically from an event ingested before V3, or supplied when the
            incident was created by hand.
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            {flatOnly.map((technique) => (
              <span
                key={technique}
                className="rounded border border-purple-500/30 bg-purple-500/10 px-2 py-1 font-mono text-xs text-purple-300"
              >
                {technique}
              </span>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
