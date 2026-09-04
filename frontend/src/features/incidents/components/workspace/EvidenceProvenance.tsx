import { AlertTriangle, Bot, Cpu, Database, Radio, ShieldQuestion } from "lucide-react";

import type {
  ApiEvidenceItem,
  ApiEvidenceSet,
  EvidenceOrigin,
} from "@/services/api/evidence";

/**
 * Where each piece of evidence came from.
 *
 * The Evidence tab above answers "what do we have?". This answers the question
 * an analyst asks next and could not previously ask at all: "where did each of
 * these come from, when did we learn it, and how much is it worth?"
 *
 * The origin badge is the important part of the design. A firewall's record of
 * a connection and a language model's reading of that record are both
 * "evidence" and are weighed completely differently, so they are never given
 * the same styling. Nothing here is fabricated: every field is served by
 * `GET /incidents/{id}/evidence`, and a provider that could not answer is shown
 * as a degraded provider rather than as an absence of evidence.
 */

const ORIGIN_STYLES: Record<
  EvidenceOrigin,
  { label: string; hint: string; className: string; Icon: typeof Radio }
> = {
  observed: {
    label: "Observed",
    hint: "Telemetry as it was recorded. The estate reported this.",
    className: "border-cyan-500/30 bg-cyan-500/10 text-cyan-300",
    Icon: Radio,
  },
  derived: {
    label: "Derived",
    hint: "Computed by AEGISX from observed data - a rule, a score, a correlation.",
    className: "border-violet-500/30 bg-violet-500/10 text-violet-300",
    Icon: Cpu,
  },
  reported: {
    label: "Reported",
    hint: "A third party's assertion, true or false independently of our telemetry.",
    className: "border-amber-500/30 bg-amber-500/10 text-amber-300",
    Icon: Database,
  },
  analytic: {
    label: "AI-generated",
    hint: "Produced by a language model. A reading of the evidence, never an observation.",
    className: "border-fuchsia-500/30 bg-fuchsia-500/10 text-fuchsia-300",
    Icon: Bot,
  },
  simulated: {
    label: "Simulated",
    hint: "Produced by a mock provider. Not activity on a real system.",
    className: "border-slate-500/30 bg-slate-500/10 text-slate-300",
    Icon: ShieldQuestion,
  },
};

function OriginBadge({ origin }: { origin: EvidenceOrigin }) {
  const style = ORIGIN_STYLES[origin] ?? ORIGIN_STYLES.observed;
  const { Icon } = style;
  return (
    <span
      title={style.hint}
      className={`inline-flex shrink-0 items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium ${style.className}`}
    >
      <Icon size={11} />
      {style.label}
    </span>
  );
}

function formatTime(value: string | null): string {
  if (!value) return "unknown";
  return new Date(value).toLocaleString();
}

function EvidenceRow({ item }: { item: ApiEvidenceItem }) {
  const { provenance } = item;

  return (
    <li className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
      <div className="mb-2 flex flex-wrap items-start justify-between gap-2">
        <p className="min-w-0 flex-1 truncate text-sm text-slate-200">{item.title}</p>
        <div className="flex shrink-0 flex-wrap items-center gap-1.5">
          <OriginBadge origin={provenance.origin} />
          {provenance.isSynthetic && (
            <span
              title="This record was produced by the AEGISX telemetry simulator. It does not describe activity on a real system."
              className="rounded-full border border-slate-600/40 bg-slate-700/30 px-2 py-0.5 text-[10px] text-slate-300"
            >
              Synthetic
            </span>
          )}
          {item.containsInjectionAttempt && (
            <span
              title="This text contains constructs used to steer a language model. It is shown unmodified because it is the evidence; it is neutralised before any model sees it."
              className="inline-flex items-center gap-1 rounded-full border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[10px] text-red-300"
            >
              <AlertTriangle size={11} />
              Injection text
            </span>
          )}
        </div>
      </div>

      <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] sm:grid-cols-3">
        <div>
          <dt className="text-slate-500">Provider</dt>
          <dd className="font-mono text-slate-300">{provenance.provider}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Source</dt>
          <dd className="truncate font-mono text-slate-300" title={provenance.sourceRef}>
            {provenance.sourceRef}
          </dd>
        </div>
        <div>
          <dt className="text-slate-500">Kind</dt>
          <dd className="font-mono text-slate-300">{item.kind}</dd>
        </div>
        <div>
          <dt className="text-slate-500" title="When the thing happened">
            Observed
          </dt>
          <dd className="text-slate-300">{formatTime(provenance.observedAt)}</dd>
        </div>
        <div>
          <dt className="text-slate-500" title="When AEGISX recorded it">
            Collected
          </dt>
          <dd className="text-slate-300">{formatTime(provenance.collectedAt)}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Record</dt>
          <dd
            className={
              provenance.tamperEvidentAtRest ? "text-slate-300" : "text-amber-300"
            }
            title={
              provenance.tamperEvidentAtRest
                ? "The stored row is not rewritten, so this content is stable."
                : "The stored row is updated in place. What this says can change after a decision was taken on it."
            }
          >
            {provenance.integrity.replace("_", " ")}
          </dd>
        </div>
      </dl>

      {provenance.confidence !== null && (
        <p
          className="mt-2 text-[11px] text-slate-400"
          title={provenance.confidenceBasis ?? undefined}
        >
          Confidence {Math.round(provenance.confidence * 100)}%
          {provenance.confidenceBasis && (
            <span className="text-slate-500"> — {provenance.confidenceBasis}</span>
          )}
        </p>
      )}

      <p
        className="mt-1.5 truncate font-mono text-[10px] text-slate-600"
        title={`SHA-256 of this item's content: ${item.contentDigest}`}
      >
        {item.evidenceId} · digest {item.contentDigest.slice(0, 16)}…
      </p>
    </li>
  );
}

interface Props {
  evidence: ApiEvidenceSet | undefined;
  isLoading: boolean;
  isError: boolean;
}

export default function EvidenceProvenance({ evidence, isLoading, isError }: Props) {
  if (isLoading) {
    return (
      <p className="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 px-4 py-6 text-center text-sm text-slate-500">
        Loading evidence provenance…
      </p>
    );
  }

  // A payload that does not match the contract is treated as unavailable
  // rather than rendered optimistically. Reaching into a field that is not
  // there would white-screen the whole investigation workspace, and a panel
  // that cannot show provenance must not take the evidence tab down with it.
  const usable =
    evidence !== undefined &&
    typeof evidence.manifestDigest === "string" &&
    Array.isArray(evidence.items) &&
    Array.isArray(evidence.degradedProviders);

  if (isError || !usable) {
    return (
      <p className="rounded-xl border border-dashed border-red-900/50 bg-red-950/20 px-4 py-6 text-center text-sm text-red-300">
        Evidence provenance could not be loaded. This is not the same as the
        incident having no evidence — nothing is claimed either way.
      </p>
    );
  }

  const set = evidence as ApiEvidenceSet;

  return (
    <section>
      <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-sm font-semibold text-white">
          Provenance ({set.total})
        </h3>
        <span
          className="font-mono text-[10px] text-slate-600"
          title="One digest over every item's identity and content. It changes if any evidence is added, removed or altered."
        >
          manifest {set.manifestDigest.slice(0, 16)}…
        </span>
      </div>

      {set.degradedProviders.length > 0 && (
        <div className="mb-3 rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2">
          <p className="text-xs font-medium text-amber-300">
            Some evidence could not be collected
          </p>
          <ul className="mt-1 space-y-0.5">
            {set.degradedProviders.map((provider) => (
              <li key={provider.provider} className="text-[11px] text-amber-200/80">
                <span className="font-mono">{provider.provider}</span> —{" "}
                {provider.reason ?? provider.status}
              </li>
            ))}
          </ul>
          <p className="mt-1 text-[10px] text-amber-200/60">
            This is a collection failure, not an absence of evidence.
          </p>
        </div>
      )}

      {set.items.length === 0 ? (
        <p className="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 px-4 py-6 text-center text-sm text-slate-500">
          No evidence is recorded against this incident.
        </p>
      ) : (
        <ul className="space-y-2">
          {set.items.map((item) => (
            <EvidenceRow key={item.evidenceId} item={item} />
          ))}
        </ul>
      )}
    </section>
  );
}
