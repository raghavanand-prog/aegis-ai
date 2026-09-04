import { AlertOctagon, CheckCircle2, PlusCircle, RefreshCw } from "lucide-react";

import type {
  ApiDecisionBinding,
  ApiDecisionList,
  DriftVerdict,
} from "@/services/api/decisions";

/**
 * Whether each decision on this incident still rests on the evidence it was
 * taken on.
 *
 * The four verdicts are styled apart deliberately. `refreshed` is the one worth
 * getting right: a threat-intelligence row is rewritten in place every time an
 * indicator is looked up again, so it happens routinely — and a routine *cause*
 * does not make a changed verdict a routine *consequence*. It is shown as
 * material, not as noise, because the vendor opinion behind a closure may now
 * say the opposite.
 *
 * Nothing here is computed in the browser. Every verdict comes from
 * `GET /incidents/{id}/decisions`, which recomputes the evidence server-side
 * and compares it with what was recorded at decision time.
 */

const VERDICTS: Record<
  DriftVerdict,
  {
    label: string;
    blurb: string;
    className: string;
    Icon: typeof CheckCircle2;
  }
> = {
  unchanged: {
    label: "Evidence unchanged",
    blurb: "Nothing behind this decision has moved since it was taken.",
    className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
    Icon: CheckCircle2,
  },
  extended: {
    label: "New evidence since",
    blurb:
      "Evidence was added after this decision. Nothing it rested on changed, but the picture is now larger than the one that was decided on.",
    className: "border-sky-500/30 bg-sky-500/10 text-sky-300",
    Icon: PlusCircle,
  },
  refreshed: {
    label: "Basis changed",
    blurb:
      "Evidence this decision rested on has been rewritten by its source — a re-looked-up vendor verdict, or an indicator seen again. Routine mechanically; the decision may no longer be supported.",
    className: "border-amber-500/30 bg-amber-500/10 text-amber-300",
    Icon: RefreshCw,
  },
  tampered: {
    label: "Unexpected change",
    blurb:
      "A record the application never rewrites has changed, or evidence was removed. No supported operation does either.",
    className: "border-red-500/40 bg-red-500/10 text-red-300",
    Icon: AlertOctagon,
  },
};

function VerdictBadge({ verdict }: { verdict: DriftVerdict }) {
  const style = VERDICTS[verdict] ?? VERDICTS.tampered;
  const { Icon } = style;
  return (
    <span
      title={style.blurb}
      className={`inline-flex shrink-0 items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium ${style.className}`}
    >
      <Icon size={11} />
      {style.label}
    </span>
  );
}

function DecisionRow({ binding }: { binding: ApiDecisionBinding }) {
  const { drift } = binding;
  const style = VERDICTS[drift.verdict] ?? VERDICTS.tampered;

  return (
    <li className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
      <div className="mb-1.5 flex flex-wrap items-start justify-between gap-2">
        <p className="min-w-0 flex-1 text-sm text-slate-200">
          {binding.fromState ? `${binding.fromState} → ` : ""}
          <span className="font-medium">{binding.toState}</span>
        </p>
        <VerdictBadge verdict={drift.verdict} />
      </div>

      <p className="text-[11px] text-slate-500">
        {binding.decidedBy}
        {binding.decidedByRole ? ` (${binding.decidedByRole})` : ""} ·{" "}
        {new Date(binding.decidedAt).toLocaleString()} · {binding.evidenceCount}{" "}
        evidence item{binding.evidenceCount === 1 ? "" : "s"}
      </p>

      {binding.reason && (
        <p className="mt-1 text-[11px] italic text-slate-400">“{binding.reason}”</p>
      )}

      {drift.verdict !== "unchanged" && (
        <p className="mt-2 text-[11px] text-slate-400">{style.blurb}</p>
      )}

      {drift.changed.length > 0 && (
        <ul className="mt-2 space-y-1">
          {drift.changed.map((entry) => (
            <li
              key={entry.evidenceId}
              className="rounded border border-slate-800 bg-slate-950/60 px-2 py-1 font-mono text-[10px] text-slate-400"
            >
              {entry.kind} · {entry.provider} · {entry.integrity}
              <span className="block text-slate-600">
                {entry.digestAtDecision.slice(0, 12)}… → {entry.digestNow.slice(0, 12)}…
              </span>
            </li>
          ))}
        </ul>
      )}

      {drift.added.length > 0 && (
        <p className="mt-1.5 text-[10px] text-sky-300/80">
          {drift.added.length} item{drift.added.length === 1 ? "" : "s"} added since
        </p>
      )}
      {drift.removed.length > 0 && (
        <p className="mt-1.5 text-[10px] text-red-300/80">
          {drift.removed.length} item{drift.removed.length === 1 ? "" : "s"} removed since
        </p>
      )}

      {drift.degradedAtDecision.length > 0 && (
        <p className="mt-1.5 text-[10px] text-amber-300/80">
          Decided while {drift.degradedAtDecision.length} provider
          {drift.degradedAtDecision.length === 1 ? " was" : "s were"} unreachable — this
          decision was taken on partial evidence.
        </p>
      )}

      {!drift.attributionComplete && (
        <p className="mt-1.5 text-[10px] text-amber-300/80">
          Too many evidence items to record individually, so which one moved cannot be
          shown. Detection is unaffected.
        </p>
      )}

      <p className="mt-1.5 font-mono text-[10px] text-slate-600">
        {binding.decisionRef} · manifest {binding.manifestDigest.slice(0, 16)}…
      </p>
    </li>
  );
}

interface Props {
  decisions: ApiDecisionList | undefined;
  isLoading: boolean;
  isError: boolean;
}

export default function DecisionIntegrity({ decisions, isLoading, isError }: Props) {
  if (isLoading) {
    return (
      <p className="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 px-4 py-6 text-center text-sm text-slate-500">
        Loading decision integrity…
      </p>
    );
  }

  const usable =
    decisions !== undefined &&
    Array.isArray(decisions.items) &&
    typeof decisions.total === "number";

  if (isError || !usable) {
    return (
      <p className="rounded-xl border border-dashed border-red-900/50 bg-red-950/20 px-4 py-6 text-center text-sm text-red-300">
        Decision integrity could not be loaded. This is not the same as the evidence
        being intact — nothing is claimed either way.
      </p>
    );
  }

  return (
    <section>
      <h3 className="mb-3 text-sm font-semibold text-white">
        Decisions ({decisions.total})
      </h3>

      {decisions.items.length === 0 ? (
        <p className="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 px-4 py-6 text-center text-sm text-slate-500">
          No consequential decision has been recorded against this incident. Containment,
          resolution and closure are recorded here with the evidence they were taken on;
          decisions taken before this was introduced have no record, which is not the same
          as their evidence being unchanged.
        </p>
      ) : (
        <ul className="space-y-2">
          {decisions.items.map((binding) => (
            <DecisionRow key={binding.decisionRef} binding={binding} />
          ))}
        </ul>
      )}
    </section>
  );
}
