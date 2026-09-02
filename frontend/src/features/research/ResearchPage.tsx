import { useMemo, useState } from "react";
import { FlaskConical } from "lucide-react";

import ErrorBoundary from "@/components/ErrorBoundary";
import { ErrorState, SkeletonBlock } from "@/components/ui";
import UnavailablePanel from "@/features/detection/components/UnavailablePanel";

import ConfusionMatrixPanel from "./components/ConfusionMatrixPanel";
import DatasetCardPanel from "./components/DatasetCardPanel";
import DetectorComparison from "./components/DetectorComparison";
import PerClassPanel from "./components/PerClassPanel";
import ReproducibilityPanel from "./components/ReproducibilityPanel";
import ThresholdAnalysis from "./components/ThresholdAnalysis";
import { detectorLabel, splitLabel } from "./components/metricFormat";
import {
  useEvaluationDatasets,
  useEvaluationStatus,
  useExperiment,
  useExperiments,
} from "./hooks/useEvaluation";

/**
 * Research and evaluation.
 *
 * This section reports how well AEGISX actually performs, on named data, under
 * a recorded configuration. It is deliberately separate from the operational
 * dashboard: nothing here participates in detecting anything, and nothing here
 * can start an experiment.
 *
 * The empty state matters as much as the populated one. "No experiments have
 * been run" and "experiments ran and found nothing" are different facts, and
 * this page states which one it is, with the command that would change it.
 */

function Panel({ label, children }: { label: string; children: React.ReactNode }) {
  return <ErrorBoundary label={label}>{children}</ErrorBoundary>;
}

export default function ResearchPage() {
  const status = useEvaluationStatus();
  const [split, setSplit] = useState<string>("");
  const experiments = useExperiments(split ? { split } : {});
  const datasets = useEvaluationDatasets();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const items = useMemo(() => experiments.data?.items ?? [], [experiments.data]);
  const detail = useExperiment(selectedId ?? items[0]?.experimentId ?? null);

  const splitOptions = useMemo(
    () => Array.from(new Set(items.map((item) => item.split.strategy))),
    [items],
  );

  if (status.isLoading) {
    return (
      <div className="space-y-6">
        <SkeletonBlock className="h-24 w-full" />
        <SkeletonBlock className="h-64 w-full" />
      </div>
    );
  }

  if (status.isError) {
    return (
      <ErrorState
        title="Could not load evaluation results"
        error={status.error}
        onRetry={() => status.refetch()}
      />
    );
  }

  const state = status.data;

  return (
    <div className="space-y-8">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <span className="rounded-xl border border-cyan-500/30 bg-cyan-500/10 p-2.5">
            <FlaskConical size={20} className="text-cyan-400" />
          </span>
          <div>
            <h1 className="text-2xl font-semibold tracking-tight text-white">
              Research &amp; Evaluation
            </h1>
            <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-400">
              Measured detection quality on labelled corpora. Every number here
              carries the dataset, split, feature schema and threshold that produced
              it. Thresholds were frozen on a validation split before the test split
              was read.
            </p>
          </div>
        </div>

        {splitOptions.length > 1 && (
          <div className="flex items-center gap-2">
            <label htmlFor="split" className="text-xs text-slate-500">
              Split
            </label>
            <select
              id="split"
              value={split}
              onChange={(event) => {
                setSplit(event.target.value);
                setSelectedId(null);
              }}
              className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-sm text-slate-200"
            >
              <option value="">All</option>
              {splitOptions.map((option) => (
                <option key={option} value={option}>
                  {splitLabel(option)}
                </option>
              ))}
            </select>
          </div>
        )}
      </header>

      {!state?.available && (
        <UnavailablePanel
          title="No evaluation results have been recorded"
          reason={state?.reason ?? undefined}
          hint="python -m app.evaluation.run_experiments --dataset unsw-nb15 --persist"
        />
      )}

      {state?.available && (
        <>
          {Object.entries(state.corpora).map(([name, corpus]) =>
            corpus.onDisk ? null : (
              <UnavailablePanel
                key={name}
                title={`The ${name} corpus is not on this machine`}
                reason={corpus.reason ?? undefined}
                hint={corpus.fetchCommand}
                tone="info"
              />
            ),
          )}

          <Panel label="Detector comparison">
            {experiments.isLoading ? (
              <SkeletonBlock className="h-64 w-full" />
            ) : (
              <DetectorComparison experiments={items} />
            )}
          </Panel>

          {items.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {items.map((item) => {
                const active =
                  (selectedId ?? items[0].experimentId) === item.experimentId;
                return (
                  <button
                    key={item.experimentId}
                    type="button"
                    onClick={() => setSelectedId(item.experimentId)}
                    className={`rounded-lg border px-3 py-1.5 text-xs transition ${
                      active
                        ? "border-cyan-500/50 bg-cyan-500/10 text-cyan-200"
                        : "border-slate-800 bg-slate-900/60 text-slate-400 hover:border-slate-700"
                    }`}
                  >
                    {detectorLabel(item.detector.name)}
                  </button>
                );
              })}
            </div>
          )}

          {detail.data && (
            <>
              <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
                <Panel label="Confusion matrix">
                  <ConfusionMatrixPanel experiment={detail.data} />
                </Panel>
                <Panel label="Per class">
                  <PerClassPanel experiment={detail.data} />
                </Panel>
              </div>

              <Panel label="Threshold analysis">
                <ThresholdAnalysis experiment={detail.data} />
              </Panel>

              <Panel label="Reproducibility">
                <ReproducibilityPanel experiment={detail.data} />
              </Panel>
            </>
          )}

          <Panel label="Datasets">
            <div className="space-y-6">
              {(datasets.data?.items ?? []).map((dataset) => (
                <DatasetCardPanel key={dataset.id} dataset={dataset} />
              ))}
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}
