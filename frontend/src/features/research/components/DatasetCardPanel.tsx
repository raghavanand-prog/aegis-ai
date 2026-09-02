import Card from "@/components/ui/Card";
import CardContent from "@/components/ui/CardContent";
import CardHeader from "@/components/ui/CardHeader";

import type { DatasetCard } from "@/services/api/evaluation";
import { count, percent } from "./metricFormat";

/**
 * The dataset card: what the numbers were measured on, and what that limits.
 *
 * The limitations list is rendered as prominently as the class counts, because
 * on this corpus they are the more important half. A reader who takes an F1
 * away from this page without the note that AEGISX's rules are structurally
 * unable to fire on flow telemetry has taken away the wrong thing.
 */

interface Props {
  dataset: DatasetCard;
}

export default function DatasetCardPanel({ dataset }: Props) {
  const card = dataset.card ?? {};
  const labelSchema = card.labelSchema ?? {};
  const provenance = card.provenance ?? {};
  const classCounts = card.classCounts ?? {};
  const excluded = labelSchema.excluded ?? {};
  const notes: string[] = [...(provenance.notes ?? []), ...(labelSchema.notes ?? [])];

  const total = dataset.totalSamples || 1;

  return (
    <Card>
      <CardHeader
        title={`${dataset.name} v${dataset.version}`}
        subtitle={dataset.description ?? undefined}
      />
      <CardContent>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div>
            <p className="text-xs uppercase tracking-wide text-slate-500">Samples</p>
            <p className="mt-1 text-xl font-semibold tabular-nums text-white">
              {count(dataset.totalSamples)}
            </p>
          </div>
          <div>
            <p className="text-xs uppercase tracking-wide text-slate-500">Malicious</p>
            <p className="mt-1 text-xl font-semibold tabular-nums text-white">
              {percent(dataset.maliciousSamples / total, 2)}
            </p>
            <p className="text-xs text-slate-500">
              {count(dataset.maliciousSamples)} samples
            </p>
          </div>
          <div>
            <p className="text-xs uppercase tracking-wide text-slate-500">
              Duplicate groups
            </p>
            <p className="mt-1 text-xl font-semibold tabular-nums text-white">
              {count(dataset.distinctGroups)}
            </p>
            <p className="text-xs text-slate-500">splits never break one apart</p>
          </div>
          <div>
            <p className="text-xs uppercase tracking-wide text-slate-500">
              Fingerprint
            </p>
            <p className="mt-1 font-mono text-sm text-white">{dataset.fingerprint}</p>
          </div>
        </div>

        {Object.keys(classCounts).length > 0 && (
          <div className="mt-6">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Class distribution
            </p>
            <div className="mt-2 space-y-1.5">
              {Object.entries(classCounts)
                .sort(([, a], [, b]) => b - a)
                .map(([label, value]) => (
                  <div key={label} className="flex items-center gap-3">
                    <span className="w-40 shrink-0 truncate text-xs text-slate-400">
                      {label}
                    </span>
                    <div className="h-2 flex-1 overflow-hidden rounded-full bg-slate-800">
                      <div
                        className={`h-full rounded-full ${
                          label === "benign" || label === "BENIGN"
                            ? "bg-emerald-500/60"
                            : "bg-cyan-500/60"
                        }`}
                        style={{ width: `${Math.max((value / total) * 100, 0.4)}%` }}
                      />
                    </div>
                    <span className="w-28 shrink-0 text-right font-mono text-xs tabular-nums text-slate-400">
                      {count(value)} ({percent(value / total, 2)})
                    </span>
                  </div>
                ))}
            </div>
          </div>
        )}

        <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Provenance
            </p>
            <dl className="mt-2 space-y-2 text-xs">
              <div>
                <dt className="text-slate-500">Source</dt>
                <dd className="break-all text-slate-300">{dataset.source ?? "n/a"}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Licence</dt>
                <dd className="text-slate-300">{dataset.license ?? "n/a"}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Citation</dt>
                <dd className="text-slate-300">{dataset.citation ?? "n/a"}</dd>
              </div>
            </dl>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Label schema
            </p>
            <p className="mt-2 text-xs text-slate-400">
              {labelSchema.name ?? "n/a"} v{labelSchema.version ?? "?"} ·{" "}
              {Object.keys(labelSchema.mapping ?? {}).length} original label(s) mapped
              ·{" "}
              {Object.keys(excluded).length === 0
                ? "nothing excluded"
                : `${Object.keys(excluded).length} excluded`}
            </p>
            {Object.keys(excluded).length > 0 && (
              <ul className="mt-2 space-y-1 text-xs text-amber-200">
                {Object.entries(excluded).map(([label, reason]) => (
                  <li key={label}>
                    <span className="font-mono">{label}</span>: {reason}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {notes.length > 0 && (
          <div className="mt-4 rounded-xl border border-amber-500/20 bg-amber-500/5 p-4">
            <p className="text-xs font-semibold uppercase tracking-wide text-amber-300">
              Limitations and caveats
            </p>
            <ul className="mt-2 list-disc space-y-1.5 pl-5 text-xs leading-5 text-amber-100/80">
              {notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
