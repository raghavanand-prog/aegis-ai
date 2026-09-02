import { ShieldCheck, ShieldAlert } from "lucide-react";

import Card from "@/components/ui/Card";
import CardContent from "@/components/ui/CardContent";
import CardHeader from "@/components/ui/CardHeader";

import type { Experiment } from "@/services/api/evaluation";
import { NOT_AVAILABLE, percent, splitLabel } from "./metricFormat";

/**
 * Provenance and the leakage audit, side by side.
 *
 * This panel exists because "94% accuracy" is not a result. A result is a
 * number plus the dataset fingerprint, split, feature schema, ruleset and model
 * digest that produced it, and everything needed to run it again. All of that
 * is shown here rather than being buried in a JSON blob.
 *
 * The leakage audit is displayed next to it deliberately: it bounds how much of
 * the metric above could be memorisation. Publishing the metric without it
 * would be publishing the flattering half.
 */

interface Props {
  experiment: Experiment;
}

function Row({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-slate-800/60 py-2 last:border-0">
      <span className="text-xs text-slate-500">{label}</span>
      <span className="truncate font-mono text-xs text-slate-300" title={value ?? ""}>
        {value ?? NOT_AVAILABLE}
      </span>
    </div>
  );
}

export default function ReproducibilityPanel({ experiment }: Props) {
  const run = experiment.latestRun;
  const audit = run?.leakageAudit;
  const concerning = audit?.concerning ?? false;

  return (
    <Card>
      <CardHeader
        title="Reproducibility and provenance"
        subtitle="Everything needed to run this experiment again and get this number"
      />
      <CardContent>
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <div>
            <Row label="Experiment id" value={experiment.experimentId} />
            <Row
              label="Dataset"
              value={`${experiment.dataset.name} v${experiment.dataset.version}`}
            />
            <Row label="Dataset fingerprint" value={experiment.dataset.fingerprint} />
            <Row label="Split strategy" value={splitLabel(experiment.split.strategy)} />
            <Row label="Split fingerprint" value={experiment.split.fingerprint} />
            <Row label="Split seed" value={String(experiment.split.seed)} />
            <Row
              label="Feature schema"
              value={`v${experiment.provenance.featureSchemaVersion}`}
            />
            <Row
              label="Ruleset fingerprint"
              value={experiment.provenance.rulesetFingerprint}
            />
            <Row
              label="Model"
              value={
                experiment.provenance.modelName
                  ? `${experiment.provenance.modelName}@${experiment.provenance.modelVersion ?? "?"}`
                  : null
              }
            />
            <Row
              label="Artifact SHA-256"
              value={experiment.provenance.modelArtifactSha256}
            />
            <Row
              label="Frozen threshold"
              value={run ? String(run.threshold) : null}
            />
            <Row label="Runs recorded" value={String(experiment.runCount)} />
          </div>

          <div>
            <div
              className={`rounded-xl border p-4 ${
                concerning
                  ? "border-amber-500/30 bg-amber-500/5"
                  : "border-emerald-500/25 bg-emerald-500/5"
              }`}
            >
              <div className="flex items-start gap-2">
                {concerning ? (
                  <ShieldAlert size={18} className="mt-0.5 shrink-0 text-amber-400" />
                ) : (
                  <ShieldCheck size={18} className="mt-0.5 shrink-0 text-emerald-400" />
                )}
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-white">Leakage audit</p>
                  {audit ? (
                    <>
                      <ul className="mt-2 space-y-1">
                        {Object.entries(audit.splits).map(([name, entry]) => (
                          <li key={name} className="text-xs text-slate-300">
                            <span className="text-slate-500">{name}:</span>{" "}
                            {entry.sharingATrainingFeatureVector} of {entry.samples}{" "}
                            samples share an exact training feature vector (
                            {percent(entry.share, 2)})
                          </li>
                        ))}
                      </ul>
                      <p className="mt-2 text-xs leading-5 text-slate-400">
                        {audit.interpretation ??
                          "A non-zero share bounds how much of the result could be memorisation."}
                      </p>
                    </>
                  ) : (
                    <p className="mt-1 text-xs leading-5 text-slate-400">
                      No leakage audit was recorded with this run.
                    </p>
                  )}
                </div>
              </div>
            </div>

            <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/60 p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                Reproduce this result
              </p>
              <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-all font-mono text-[11px] leading-5 text-slate-400">
{`python -m app.evaluation.run_experiments \\
  --dataset ${experiment.dataset.name} \\
  --split ${experiment.split.strategy} \\
  --seed ${experiment.split.seed} \\
  --persist`}
              </pre>
              <p className="mt-2 text-[11px] leading-5 text-slate-500">
                The dataset must hash to {experiment.dataset.fingerprint}. A different
                fingerprint means different data, and the numbers above do not apply
                to it.
              </p>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
