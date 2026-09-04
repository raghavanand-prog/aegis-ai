import { useState } from "react";

import type { AugmentationStatus, Proposal } from "@/services/api/adaptation";

/**
 * The evidence a V6 evaluation recorded and no approver could see.
 *
 * V6 wrote `rocAuc`, `perCategory` and the dataset identity onto every
 * validated proposal, and the V6 handoff closed by noting that none of it
 * reached the UI: "Three new evidence blocks are recorded on candidates and
 * invisible to approvers." An approver saw a title, a rationale and a
 * pass/fail badge — which is precisely the amount of information that makes a
 * safety gate feel ceremonial.
 *
 * Three deliberate choices, each one a V6 methodological finding made visual:
 *
 * ROC-AUC is shown **first and largest**, above anything measured at a
 * threshold. V6 §14 measured a frozen 0.65 sitting at the 53.6th percentile for
 * one model and the 99.2nd for another, so a fixed-threshold comparison between
 * differently-fitted models compares their calibrations. AUC is the portable
 * number; leading with it is the interface refusing to repeat that mistake.
 *
 * Per-category recall is a **table, not an average**. V6 §17.2's surviving
 * finding is that adaptation helps where the detector is weakest, and §8
 * measured a targeted attack costing 0.0685 of one category's AUC while the
 * aggregate barely moved. An approver who can only see the mean cannot see the
 * attack.
 *
 * The dataset's name, version and fingerprint sit beside the numbers rather
 * than in a detail view. V6's second standing rule: state a corpus's identity
 * before quoting any metric on it.
 *
 * Collapsed by default. This is the detail an approver opens deliberately, and
 * expanding every proposal in the queue would bury the queue.
 */

interface Props {
  proposal: Proposal;
}

interface RocAuc {
  candidate?: number | null;
  baseline?: number | null;
}

interface CategoryRow {
  maliciousSamples?: number | null;
  candidateRecall?: number | null;
  baselineRecall?: number | null;
}

interface DatasetIdentity {
  name?: string;
  version?: string;
  fingerprint?: string;
  samples?: number;
  malicious?: number;
}

function formatMetric(value: number | null | undefined): string {
  // "not measured" and "zero" are different facts. V4's rule, and the reason
  // this returns a dash rather than 0.000.
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return value.toFixed(4);
}

function formatDelta(
  candidate: number | null | undefined,
  baseline: number | null | undefined,
): { text: string; tone: string } {
  if (
    candidate === null ||
    candidate === undefined ||
    baseline === null ||
    baseline === undefined
  ) {
    return { text: "—", tone: "text-slate-500" };
  }
  const delta = candidate - baseline;
  const text = `${delta >= 0 ? "+" : ""}${delta.toFixed(4)}`;
  if (Math.abs(delta) < 0.0005) return { text, tone: "text-slate-400" };
  return { text, tone: delta > 0 ? "text-emerald-300" : "text-rose-300" };
}

/**
 * Why a proposal has no augmentation provenance, in the approver's language.
 *
 * Four causes, kept apart deliberately. "No feedback was admitted" and "nobody
 * recorded what was admitted" are opposite situations — the first is a
 * candidate trained on telemetry alone, the second is a blind spot — and one
 * shared dash would make them look the same.
 */
const AUGMENTATION_ABSENCE: Record<Exclude<AugmentationStatus, "recorded">, string> = {
  no_candidate_model:
    "This proposal does not train a model, so there is no fit set to describe.",
  candidate_model_unavailable:
    "The candidate model row is gone, so what it was trained on can no longer be read. Treat this proposal as unevidenced.",
  not_recorded:
    "No feedback augmentation was recorded for this candidate — it was fitted on telemetry alone, or trained before the provenance existed.",
};

function CountTable({
  title,
  counts,
  keyLabel,
  note,
}: {
  title: string;
  counts: Record<string, number>;
  keyLabel: string;
  note: string;
}) {
  const rows = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const total = rows.reduce((sum, [, n]) => sum + n, 0);
  return (
    <div>
      <h5 className="text-xs font-medium text-slate-400">{title}</h5>
      {rows.length === 0 ? (
        <p className="mt-1 text-xs text-slate-500">None admitted.</p>
      ) : (
        <div className="mt-1 overflow-x-auto">
          <table className="w-full min-w-[18rem] text-left text-xs">
            <thead className="text-slate-500">
              <tr>
                <th className="pb-1 pr-3 font-normal">{keyLabel}</th>
                <th className="pb-1 pr-3 text-right font-normal">Admitted</th>
                <th className="pb-1 text-right font-normal">Share</th>
              </tr>
            </thead>
            <tbody className="font-mono text-slate-300">
              {rows.map(([key, n]) => (
                <tr key={key} className="border-t border-slate-800/70">
                  <td className="py-1 pr-3 font-sans break-all text-slate-300">{key}</td>
                  <td className="py-1 pr-3 text-right text-slate-100">{n}</td>
                  <td className="py-1 text-right text-slate-500">
                    {total > 0 ? `${((n / total) * 100).toFixed(1)}%` : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="mt-1 text-xs text-slate-500">{note}</p>
    </div>
  );
}

export default function CandidateEvidence({ proposal }: Props) {
  const [open, setOpen] = useState(false);

  const validation = proposal.validation ?? {};
  const rocAuc = (validation.rocAuc ?? {}) as RocAuc;
  const perCategory = (validation.perCategory ?? {}) as Record<string, CategoryRow>;
  const dataset = (validation.dataset ?? {}) as DatasetIdentity;
  const threshold = validation.threshold as number | undefined;

  const categories = Object.entries(perCategory);
  const augmentation = proposal.augmentation;
  const augmentationStatus = proposal.augmentationStatus;

  const hasEvidence =
    rocAuc.candidate !== undefined ||
    categories.length > 0 ||
    Boolean(dataset.name) ||
    Boolean(augmentation) ||
    // A proposal whose candidate model has vanished must still open: "this is
    // unevidenced" is the single most important thing an approver can be told,
    // and hiding the panel would present it as an ordinary proposal.
    augmentationStatus === "candidate_model_unavailable";

  if (!hasEvidence) {
    return (
      <p className="mt-3 text-xs text-slate-500">
        No evaluation evidence recorded. Nothing here was measured, so there is
        nothing for an approver to weigh.
      </p>
    );
  }

  const aucDelta = formatDelta(rocAuc.candidate, rocAuc.baseline);

  return (
    <div className="mt-3">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:border-slate-500"
      >
        {open ? "Hide evidence" : "Show evidence"}
      </button>

      {open && (
        <div className="mt-3 space-y-4 rounded border border-slate-800 bg-slate-950/60 p-3">
          <section>
            <h4 className="text-xs font-medium uppercase tracking-wide text-slate-400">
              Discrimination (threshold-free)
            </h4>
            <div className="mt-2 flex flex-wrap items-baseline gap-4 text-sm">
              <span className="text-slate-500">
                baseline{" "}
                <span className="font-mono text-slate-300">
                  {formatMetric(rocAuc.baseline)}
                </span>
              </span>
              <span className="text-slate-500">
                candidate{" "}
                <span className="font-mono text-slate-100">
                  {formatMetric(rocAuc.candidate)}
                </span>
              </span>
              <span className={`font-mono ${aucDelta.tone}`}>ΔAUC {aucDelta.text}</span>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              ROC-AUC is comparable between models fitted on different data; a
              metric read at a fixed threshold is not. Compare on this first.
            </p>
          </section>

          {categories.length > 0 && (
            <section>
              <h4 className="text-xs font-medium uppercase tracking-wide text-slate-400">
                Recall per category
              </h4>
              <div className="mt-2 overflow-x-auto">
                <table className="w-full min-w-[28rem] text-left text-xs">
                  <thead className="text-slate-500">
                    <tr>
                      <th className="pb-1 pr-3 font-normal">Category</th>
                      <th className="pb-1 pr-3 text-right font-normal">Malicious</th>
                      <th className="pb-1 pr-3 text-right font-normal">Baseline</th>
                      <th className="pb-1 pr-3 text-right font-normal">Candidate</th>
                      <th className="pb-1 text-right font-normal">Δ</th>
                    </tr>
                  </thead>
                  <tbody className="font-mono text-slate-300">
                    {categories.map(([category, row]) => {
                      const delta = formatDelta(row.candidateRecall, row.baselineRecall);
                      return (
                        <tr key={category} className="border-t border-slate-800/70">
                          <td className="py-1 pr-3 font-sans text-slate-300">
                            {category}
                          </td>
                          <td className="py-1 pr-3 text-right text-slate-500">
                            {row.maliciousSamples ?? "—"}
                          </td>
                          <td className="py-1 pr-3 text-right">
                            {formatMetric(row.baselineRecall)}
                          </td>
                          <td className="py-1 pr-3 text-right text-slate-100">
                            {formatMetric(row.candidateRecall)}
                          </td>
                          <td className={`py-1 text-right ${delta.tone}`}>{delta.text}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <p className="mt-1 text-xs text-slate-500">
                An aggregate can hide a targeted attack. A category that drops
                while the total holds is the shape worth stopping on.
              </p>
            </section>
          )}

          <section>
            <h4 className="text-xs font-medium uppercase tracking-wide text-slate-400">
              Measured on
            </h4>
            <dl className="mt-2 grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
              <div>
                <dt className="text-slate-500">Dataset</dt>
                <dd className="font-mono text-slate-300">
                  {dataset.name ? `${dataset.name}@${dataset.version ?? "?"}` : "—"}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Fingerprint</dt>
                <dd className="font-mono text-slate-300">{dataset.fingerprint ?? "—"}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Prevalence</dt>
                <dd className="font-mono text-slate-300">
                  {dataset.samples && dataset.malicious !== undefined
                    ? `${dataset.malicious}/${dataset.samples}`
                    : "—"}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Threshold</dt>
                <dd className="font-mono text-slate-300">
                  {threshold !== undefined ? threshold : "—"}
                </dd>
              </div>
            </dl>
            <p className="mt-1 text-xs text-slate-500">
              A result is only comparable against another produced on the same
              fingerprint at the same prevalence.
            </p>
          </section>

          <section>
            <h4 className="text-xs font-medium uppercase tracking-wide text-slate-400">
              Trained on — feedback admitted
            </h4>

            {!augmentation ? (
              <p className="mt-2 text-xs text-slate-500">
                {augmentationStatus && augmentationStatus !== "recorded"
                  ? AUGMENTATION_ABSENCE[augmentationStatus]
                  : "Not recorded."}
              </p>
            ) : (
              <div className="mt-2 space-y-4">
                <dl className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
                  <div>
                    <dt className="text-slate-500">Admitted</dt>
                    <dd className="font-mono text-slate-100">
                      {augmentation.admitted ?? "—"}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Cap policy</dt>
                    <dd className="font-mono text-slate-300">
                      {augmentation.capPolicy ?? "—"}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Actor cap</dt>
                    <dd className="font-mono text-slate-300">
                      {augmentation.actorCapPolicy ?? "off"}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Feedback fingerprint</dt>
                    <dd className="font-mono text-slate-300">
                      {augmentation.datasetFingerprint ?? "—"}
                    </dd>
                  </div>
                </dl>

                {augmentation.actorCounts && (
                  <CountTable
                    title="Per analyst"
                    counts={augmentation.actorCounts}
                    keyLabel="Analyst"
                    note="One actor supplying most of a fit set is the shape a compromised account makes. The cap bounds it; this makes it visible."
                  />
                )}

                {augmentation.groupCounts && (
                  <CountTable
                    title="Per group"
                    counts={augmentation.groupCounts}
                    keyLabel="Group"
                    note="The per-group cap's key is partly attacker-influenced, so concentration here and concentration above are evaded by opposite behaviours."
                  />
                )}

                {augmentation.baselineAssessment && (
                  <div>
                    <h5 className="text-xs font-medium text-slate-400">
                      Baseline monitor
                    </h5>
                    {augmentation.baselineAssessment.unavailableReason ? (
                      <p className="mt-1 text-xs text-amber-300/90">
                        Not assessed: {augmentation.baselineAssessment.unavailableReason}
                      </p>
                    ) : augmentation.baselineAssessment.flagged?.length ? (
                      <p className="mt-1 font-mono text-xs text-amber-300">
                        Flagged: {augmentation.baselineAssessment.flagged.join(", ")}
                      </p>
                    ) : (
                      <p className="mt-1 text-xs text-slate-500">
                        No group's feedback rate drifted beyond its band.
                      </p>
                    )}
                    <p className="mt-1 text-xs text-slate-500">
                      Advisory, and it blocks nothing. A patient campaign stays
                      within policy on every batch; this is where it becomes
                      visible.
                    </p>
                  </div>
                )}

                {augmentation.skipped && (
                  <div>
                    <h5 className="text-xs font-medium text-slate-400">
                      Not admitted
                    </h5>
                    <dl className="mt-1 grid grid-cols-2 gap-2 text-xs sm:grid-cols-5">
                      {(
                        [
                          ["By cap", augmentation.skipped.byCap],
                          ["Not benign", augmentation.skipped.notBenign],
                          ["Non-event", augmentation.skipped.nonEvent],
                          ["No inference", augmentation.skipped.noInference],
                          ["Incomplete vector", augmentation.skipped.incompleteVector],
                        ] as const
                      ).map(([label, value]) => (
                        <div key={label}>
                          <dt className="text-slate-500">{label}</dt>
                          <dd className="font-mono text-slate-300">{value ?? "—"}</dd>
                        </div>
                      ))}
                    </dl>
                    <p className="mt-1 text-xs text-slate-500">
                      A high &ldquo;by cap&rdquo; count means the cap was doing
                      work on this batch — which is worth knowing before
                      approving the next one.
                    </p>
                  </div>
                )}
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
