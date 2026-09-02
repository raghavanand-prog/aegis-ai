import { describe, expect, it, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";

import ResearchPage from "../ResearchPage";
import { renderWithProviders } from "@/test/render";
import type {
  DatasetCard,
  EvaluationStatus,
  Experiment,
} from "@/services/api/evaluation";

const fetchEvaluationStatus = vi.fn();
const fetchExperiments = vi.fn();
const fetchExperiment = vi.fn();
const fetchDatasets = vi.fn();

vi.mock("@/services/api/evaluation", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/services/api/evaluation")>();
  return {
    ...actual,
    fetchEvaluationStatus: () => fetchEvaluationStatus(),
    fetchExperiments: (...args: unknown[]) => fetchExperiments(...args),
    fetchExperiment: (...args: unknown[]) => fetchExperiment(...args),
    fetchDatasets: () => fetchDatasets(),
  };
});

const RULES_EXPERIMENT: Experiment = {
  experimentId: "EXP-rules0000000001",
  detector: {
    name: "rules",
    kind: "deterministic-rules",
    scoreKind: "rule_hit (binary indicator, not a score)",
  },
  dataset: { name: "unsw-nb15", version: "1.0-full", fingerprint: "f24e4a1e47b7753e" },
  split: { strategy: "stratified_group", fingerprint: "abc1234567890def", seed: 1337 },
  provenance: {
    featureSchemaVersion: "1.0",
    rulesetFingerprint: "da203c91430a47a1",
    modelName: null,
    modelVersion: null,
    modelArtifactSha256: null,
  },
  objective: null,
  runCount: 1,
  createdAt: new Date().toISOString(),
  latestRun: {
    id: 1,
    seed: 1337,
    executedAt: new Date().toISOString(),
    threshold: 0.5,
    thresholdSelection: {
      method: "not applicable",
      objective: null,
      chosenThreshold: 0.5,
      note: "Deterministic rules either match or they do not.",
    },
    // The real measured result on flow telemetry: the rules cannot fire.
    confusion: {
      truePositives: 0,
      trueNegatives: 35_640,
      falsePositives: 0,
      falseNegatives: 4_465,
    },
    metrics: {
      precision: null,
      recall: 0,
      f1: null,
      specificity: 1,
      accuracy: 0.8887,
      falsePositiveRate: 0,
      falseNegativeRate: 1,
      mcc: null,
      balancedAccuracy: 0.5,
      rocAuc: null,
      prAuc: null,
    },
    alertVolume: { alerts: 0, alertsPerThousandEvents: 0 },
    latency: { meanMs: 0.004, p95Ms: 0.007 },
    confusionNormalized: {
      normalization: "row (by true class)",
      actualMalicious: {
        predictedMalicious: 0,
        predictedBenign: 1,
        support: 4_465,
      },
      actualBenign: {
        predictedMalicious: 0,
        predictedBenign: 1,
        support: 35_640,
      },
    },
    perClass: {
      exploits: {
        total: 780,
        detected: 0,
        missed: 780,
        detectionRate: 0,
        sufficientData: true,
      },
      worms: { total: 3, detected: 0, missed: 3, detectionRate: 0, sufficientData: false },
    },
    thresholdSweep: [],
    leakageAudit: {
      splits: {
        test: { samples: 40_105, sharingATrainingFeatureVector: 0, share: 0 },
      },
      concerning: false,
    },
  },
};

const DATASET: DatasetCard = {
  id: 1,
  name: "unsw-nb15",
  version: "1.0-full",
  fingerprint: "f24e4a1e47b7753e",
  source: "https://huggingface.co/datasets/Mouwiya/UNSW-NB15",
  license: "Free for academic research with attribution",
  citation: "Moustafa, N. & Slay, J. (2015).",
  description: "Labelled network flows.",
  totalSamples: 200_526,
  maliciousSamples: 22_325,
  benignSamples: 178_201,
  distinctGroups: 136_075,
  card: {
    classCounts: { benign: 178_201, generic: 14_000, exploits: 3_500 },
    provenance: { notes: ["Passive flow capture from a testbed of 45 addresses."] },
    labelSchema: {
      name: "unsw-nb15-attack-category",
      version: "1.0",
      mapping: { "": "benign", Generic: "generic" },
      excluded: {},
      notes: ["Nothing is excluded."],
    },
  },
  createdAt: new Date().toISOString(),
};

const AVAILABLE: EvaluationStatus = {
  available: true,
  reason: null,
  experimentCount: 1,
  datasetCount: 1,
  datasets: [
    {
      name: "unsw-nb15",
      version: "1.0-full",
      fingerprint: "f24e4a1e47b7753e",
      totalSamples: 200_526,
    },
  ],
  detectors: ["rules"],
  corpora: {
    "unsw-nb15": { onDisk: true, reason: null, fetchCommand: "python -m ...fetch" },
  },
};

beforeEach(() => {
  vi.clearAllMocks();
  fetchEvaluationStatus.mockResolvedValue(AVAILABLE);
  fetchExperiments.mockResolvedValue({ items: [RULES_EXPERIMENT], total: 1 });
  fetchExperiment.mockResolvedValue(RULES_EXPERIMENT);
  fetchDatasets.mockResolvedValue({ items: [DATASET], total: 1 });
});

describe("ResearchPage", () => {
  it("explains why it is empty rather than rendering a blank page", async () => {
    fetchEvaluationStatus.mockResolvedValue({
      ...AVAILABLE,
      available: false,
      reason: "No evaluation experiments have been recorded yet.",
      experimentCount: 0,
    });

    renderWithProviders(<ResearchPage />);

    expect(
      await screen.findByText(/No evaluation results have been recorded/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/No evaluation experiments have been recorded yet/i),
    ).toBeInTheDocument();
    // The command that would populate it, so the empty state is actionable.
    expect(screen.getByText(/run_experiments/)).toBeInTheDocument();
  });

  it("renders an undefined metric as n/a, never as zero", async () => {
    renderWithProviders(<ResearchPage />);

    await screen.findByText(/Detector comparison/i);
    // Precision is undefined for a detector that never fires. A 0% here would
    // claim a measurement that was never made.
    const cells = await screen.findAllByText("n/a");
    expect(cells.length).toBeGreaterThan(0);
  });

  it("never presents an anomaly ranking as a probability", async () => {
    const anomaly: Experiment = {
      ...RULES_EXPERIMENT,
      experimentId: "EXP-anomaly000000001",
      detector: {
        name: "isolation_forest",
        kind: "isolation-forest",
        scoreKind: "anomaly_score (ranking, NOT a probability)",
      },
    };
    fetchExperiments.mockResolvedValue({ items: [anomaly], total: 1 });
    fetchExperiment.mockResolvedValue(anomaly);

    renderWithProviders(<ResearchPage />);

    expect(await screen.findByText("anomaly ranking")).toBeInTheDocument();
    expect(screen.queryByText(/^probability$/)).not.toBeInTheDocument();
  });

  it("shows the provenance a result needs to be a result", async () => {
    renderWithProviders(<ResearchPage />);

    expect(await screen.findByText(/Reproducibility and provenance/i)).toBeInTheDocument();
    expect(screen.getAllByText("f24e4a1e47b7753e").length).toBeGreaterThan(0);
    expect(screen.getByText("da203c91430a47a1")).toBeInTheDocument();
  });

  it("declines to draw a threshold curve for a detector with no ordering", async () => {
    renderWithProviders(<ResearchPage />);

    expect(
      await screen.findByText(/No threshold curve for this detector/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/either match or they do not/i),
    ).toBeInTheDocument();
  });

  it("marks a class with too few samples as indicative only", async () => {
    renderWithProviders(<ResearchPage />);

    expect(await screen.findByText(/Detection by class/i)).toBeInTheDocument();
    expect(
      screen.getByText(/Fewer than 20 samples/i),
    ).toBeInTheDocument();
  });

  it("shows the dataset's documented limitations alongside its counts", async () => {
    renderWithProviders(<ResearchPage />);

    expect(await screen.findByText(/Limitations and caveats/i)).toBeInTheDocument();
    expect(
      screen.getByText(/testbed of 45 addresses/i),
    ).toBeInTheDocument();
  });
});
