import { describe, expect, it, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import DetectionQualityPanel from "../components/DetectionQualityPanel";
import { renderWithProviders, ANALYST } from "@/test/render";
import type { ApiDetectionQuality } from "@/services/api/types";

const fetchDetectionQuality = vi.fn();
const runDetectionEvaluation = vi.fn();

vi.mock("@/services/api/detection", () => ({
  fetchDetectionQuality: (...args: unknown[]) => fetchDetectionQuality(...args),
  runDetectionEvaluation: (...args: unknown[]) => runDetectionEvaluation(...args),
  fetchDetectionRules: vi.fn(),
}));

const REPORT: ApiDetectionQuality = {
  schemaVersion: "1.0",
  generatedAt: new Date().toISOString(),
  dataset: {
    name: "aegisx-detection-eval",
    version: "1.0",
    seed: 1337,
    fingerprint: "abc123",
    totalEvents: 1950,
    maliciousEvents: 780,
    benignEvents: 1170,
    classCounts: {},
    generator: "app.evaluation.datasets.labeled_dataset.build_dataset",
  },
  engine: { type: "deterministic-rules", ruleCount: 12, fingerprint: "def456", rules: [] },
  overall: {
    truePositives: 720,
    falsePositives: 64,
    trueNegatives: 1106,
    falseNegatives: 60,
    total: 1950,
    precision: 0.9184,
    recall: 0.9231,
    f1: 0.9207,
    falsePositiveRate: 0.0547,
    falseNegativeRate: 0.0769,
    accuracy: 0.9364,
    specificity: 0.9453,
    sufficientData: true,
  },
  perClass: [
    {
      label: "LATERAL_MOVEMENT",
      total: 60,
      detected: 0,
      missed: 60,
      detectionRate: 0,
      coveredByRules: false,
      sufficientData: true,
      ruleHits: {},
    },
  ],
  perRule: [
    {
      ruleId: "DET-EXEC-002",
      ruleVersion: "1.0",
      ruleName: "Living-off-the-land binary",
      fires: 214,
      onMalicious: 150,
      onBenign: 64,
      correctClass: 150,
      wrongClass: 0,
      rulePrecision: 0.7009,
      attributionAccuracy: 1,
    },
  ],
  latency: {
    measured: "detection engine only",
    samples: 1950,
    meanMs: 0.0038,
    p50Ms: 0.0037,
    p95Ms: 0.0063,
    p99Ms: 0.0097,
    maxMs: 0.0289,
    minMs: 0.002,
    totalMs: 7.4,
    eventsPerSecond: 263000,
  },
  volume: {
    eventsProcessed: 1950,
    maliciousEvents: 780,
    benignEvents: 1170,
    alertsGenerated: 784,
    detectionsTotal: 934,
    incidentCandidates: 540,
  },
  coverage: {
    coveredLabels: [],
    uncoveredLabels: ["LATERAL_MOVEMENT"],
    minSamplesOverall: 100,
    minSamplesPerClass: 20,
  },
  notes: [],
  stale: false,
};

describe("Detection Engine Evaluation panel", () => {
  beforeEach(() => vi.clearAllMocks());

  it("says nothing has been measured rather than showing zeros", async () => {
    fetchDetectionQuality.mockResolvedValue(null);
    renderWithProviders(<DetectionQualityPanel />);

    expect(await screen.findByText(/No evaluation has been run yet/i)).toBeInTheDocument();
    expect(screen.getByText(/run_detection_eval/)).toBeInTheDocument();
    expect(screen.queryByText("0.0%")).not.toBeInTheDocument();
  });

  it("shows measured precision, recall, F1 and error rates", async () => {
    fetchDetectionQuality.mockResolvedValue(REPORT);
    renderWithProviders(<DetectionQualityPanel />);

    expect(await screen.findByText("91.8%")).toBeInTheDocument(); // precision
    expect(screen.getByText("92.3%")).toBeInTheDocument(); // recall
    expect(screen.getByText("92.1%")).toBeInTheDocument(); // F1
    expect(screen.getByText("5.5%")).toBeInTheDocument(); // false positive rate
    expect(screen.getByText("7.7%")).toBeInTheDocument(); // false negative rate
    expect(screen.getByText("0.004 ms")).toBeInTheDocument(); // latency
  });

  it("names the classes no rule covers", async () => {
    fetchDetectionQuality.mockResolvedValue(REPORT);
    renderWithProviders(<DetectionQualityPanel />);

    expect(await screen.findByText(/Known blind spots/i)).toBeInTheDocument();
    expect(screen.getByText("LATERAL_MOVEMENT")).toBeInTheDocument();
  });

  it("labels the metrics as rule-engine metrics, not model metrics", async () => {
    fetchDetectionQuality.mockResolvedValue(REPORT);
    renderWithProviders(<DetectionQualityPanel />);

    expect(
      await screen.findByText(/Not a machine learning model/i),
    ).toBeInTheDocument();
  });

  it("warns when the rules changed after the evaluation", async () => {
    fetchDetectionQuality.mockResolvedValue({ ...REPORT, stale: true });
    renderWithProviders(<DetectionQualityPanel />);

    expect(await screen.findByText(/rules have changed since this evaluation/i)).toBeInTheDocument();
  });

  it("only offers to re-run for a role that may run it", async () => {
    fetchDetectionQuality.mockResolvedValue(REPORT);
    const analystWithoutEval = { ...ANALYST, permissions: ["detection:read"] };
    renderWithProviders(<DetectionQualityPanel />, { user: analystWithoutEval });

    await screen.findByText("91.8%");
    expect(screen.queryByRole("button", { name: /re-run evaluation/i })).not.toBeInTheDocument();
  });

  it("lets an administrator re-run the evaluation", async () => {
    const user = userEvent.setup();
    fetchDetectionQuality.mockResolvedValue(REPORT);
    runDetectionEvaluation.mockResolvedValue(REPORT);

    renderWithProviders(<DetectionQualityPanel />, {
      user: { ...ANALYST, role: "admin", permissions: ["detection:read", "detection:evaluate"] },
    });

    await user.click(await screen.findByRole("button", { name: /re-run evaluation/i }));
    expect(runDetectionEvaluation).toHaveBeenCalled();
  });
});
