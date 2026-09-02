/**
 * Research evaluation endpoints (V4).
 *
 * Read only. There is no client function that starts an experiment, because
 * there is no endpoint that starts one - running an experiment is minutes of
 * CPU over a whole corpus and belongs to an operator at a CLI, not to a click.
 *
 * Every type here carries the provenance of the number beside it. `scoreKind`
 * in particular travels with every detector so the UI can never render an
 * anomaly ranking as though it were a probability.
 */

import { api } from "./client";

/** What a detector's number actually means. Never interchangeable. */
export type ScoreKind = string;

export interface EvaluationDatasetSummary {
  name: string;
  version: string;
  fingerprint: string;
  totalSamples: number;
}

export interface EvaluationStatus {
  available: boolean;
  /** Why the research views are empty. Rendered verbatim, never invented. */
  reason: string | null;
  experimentCount: number;
  datasetCount: number;
  datasets: EvaluationDatasetSummary[];
  detectors: string[];
  corpora: Record<
    string,
    { onDisk: boolean; reason: string | null; fetchCommand: string }
  >;
}

export interface ConfusionCounts {
  truePositives: number;
  trueNegatives: number;
  falsePositives: number;
  falseNegatives: number;
}

/** A metric is `null` when it is undefined, never 0. The UI must show "n/a". */
export interface RunMetrics {
  precision: number | null;
  recall: number | null;
  f1: number | null;
  specificity: number | null;
  accuracy: number | null;
  falsePositiveRate: number | null;
  falseNegativeRate: number | null;
  mcc: number | null;
  balancedAccuracy: number | null;
  rocAuc: number | null;
  prAuc: number | null;
}

export interface ThresholdSelection {
  method: string;
  objective: string | null;
  chosenThreshold: number;
  atGridBoundary?: boolean;
  warning?: string | null;
  note?: string;
}

export interface ExperimentRun {
  id: number;
  seed: number;
  executedAt: string;
  threshold: number;
  thresholdSelection: ThresholdSelection;
  confusion: ConfusionCounts;
  metrics: RunMetrics;
  alertVolume: { alerts: number | null; alertsPerThousandEvents: number | null };
  latency: { meanMs: number | null; p95Ms: number | null };
  confusionNormalized?: ConfusionNormalized;
  perClass?: Record<string, PerClassEntry>;
  thresholdSweep?: SweepPoint[];
  leakageAudit?: LeakageAudit | null;
  environment?: Record<string, unknown>;
  notes?: string[];
}

export interface ConfusionNormalized {
  normalization: string;
  actualMalicious: {
    predictedMalicious: number | null;
    predictedBenign: number | null;
    support: number;
  };
  actualBenign: {
    predictedMalicious: number | null;
    predictedBenign: number | null;
    support: number;
  };
}

export interface PerClassEntry {
  total: number;
  detected: number;
  missed: number;
  detectionRate: number | null;
  sufficientData: boolean;
}

export interface SweepPoint {
  threshold: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  falsePositiveRate: number | null;
  falseNegativeRate: number | null;
  alerts: number;
  alertsPerThousandEvents: number | null;
}

export interface LeakageAudit {
  method?: string;
  splits: Record<
    string,
    { samples: number; sharingATrainingFeatureVector: number; share: number | null }
  >;
  interpretation?: string;
  concerning: boolean;
}

export interface Experiment {
  experimentId: string;
  detector: { name: string; kind: string; scoreKind: ScoreKind };
  dataset: { name: string; version: string; fingerprint: string };
  split: { strategy: string; fingerprint: string; seed: number };
  provenance: {
    featureSchemaVersion: string;
    rulesetFingerprint: string | null;
    modelName: string | null;
    modelVersion: string | null;
    modelArtifactSha256: string | null;
  };
  objective: string | null;
  runCount: number;
  createdAt: string;
  latestRun: ExperimentRun | null;
  runs?: ExperimentRun[];
  detectorConfig?: Record<string, unknown>;
}

/** The label schema, including every transformation applied to reach it. */
export interface LabelSchemaDocument {
  name?: string;
  version?: string;
  benignCategory?: string;
  maliciousCategories?: string[];
  /** Original label (verbatim) -> normalized category. */
  mapping?: Record<string, string>;
  /** Original label -> why it was excluded. Empty means nothing was dropped. */
  excluded?: Record<string, string>;
  notes?: string[];
}

export interface DatasetProvenanceDocument {
  source?: string;
  license?: string;
  citation?: string;
  description?: string;
  fileDigests?: Record<string, string>;
  retrievedAt?: string | null;
  notes?: string[];
}

export interface DatasetCardDocument {
  name?: string;
  version?: string;
  fingerprint?: string;
  totalSamples?: number;
  maliciousSamples?: number;
  benignSamples?: number;
  maliciousRate?: number | null;
  distinctGroups?: number | null;
  classCounts?: Record<string, number>;
  provenance?: DatasetProvenanceDocument;
  labelSchema?: LabelSchemaDocument;
  sampling?: Record<string, unknown> | null;
}

export interface DatasetCard {
  id: number;
  name: string;
  version: string;
  fingerprint: string;
  source: string | null;
  license: string | null;
  citation: string | null;
  description: string | null;
  totalSamples: number;
  maliciousSamples: number;
  benignSamples: number;
  distinctGroups: number | null;
  /** The full dataset card document, read whole and rendered as-is. */
  card: DatasetCardDocument;
  createdAt: string;
}

export async function fetchEvaluationStatus(): Promise<EvaluationStatus> {
  const { data } = await api.get<EvaluationStatus>("/evaluation/status");
  return data;
}

export async function fetchExperiments(query: {
  dataset?: string;
  detector?: string;
  split?: string;
  limit?: number;
} = {}): Promise<{ items: Experiment[]; total: number }> {
  const params: Record<string, string | number> = { limit: query.limit ?? 100 };
  if (query.dataset) params.dataset = query.dataset;
  if (query.detector) params.detector = query.detector;
  if (query.split) params.split = query.split;
  const { data } = await api.get<{ items: Experiment[]; total: number }>(
    "/evaluation/experiments",
    { params },
  );
  return data;
}

export async function fetchExperiment(experimentId: string): Promise<Experiment> {
  const { data } = await api.get<Experiment>(
    `/evaluation/experiments/${experimentId}`,
  );
  return data;
}

export async function fetchDatasets(): Promise<{ items: DatasetCard[]; total: number }> {
  const { data } = await api.get<{ items: DatasetCard[]; total: number }>(
    "/evaluation/datasets",
  );
  return data;
}

export async function fetchDataset(datasetId: number): Promise<DatasetCard> {
  const { data } = await api.get<DatasetCard>(`/evaluation/datasets/${datasetId}`);
  return data;
}
