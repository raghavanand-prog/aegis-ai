import { describe, expect, it, vi, beforeEach } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import AdaptivePage from "../AdaptivePage";
import { renderWithProviders } from "@/test/render";
import type {
  DriftStatusResponse,
  Feedback,
  Proposal,
  ReviewQueueResponse,
} from "@/services/api/adaptation";

const fetchFeedback = vi.fn();
const fetchDriftStatus = vi.fn();
const fetchReviewQueue = vi.fn();
const fetchProposals = vi.fn();

vi.mock("@/services/api/adaptation", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/services/api/adaptation")>();
  return {
    ...actual,
    fetchFeedback: (...args: unknown[]) => fetchFeedback(...args),
    fetchDriftStatus: () => fetchDriftStatus(),
    fetchReviewQueue: (...args: unknown[]) => fetchReviewQueue(...args),
    fetchProposals: (...args: unknown[]) => fetchProposals(...args),
  };
});

const FEEDBACK: Feedback[] = [
  {
    id: 1,
    targetType: "event",
    targetId: "EVT-000001",
    label: "false_positive",
    confidence: null,
    comment: "Backup job.",
    mitreTechniques: [],
    analyst: "analyst@aegisx.dev",
    source: "analyst",
    featureSchemaVersion: "1.0",
    modelIdentity: null,
    submittedAt: "2026-09-03T00:00:00Z",
    supersedesId: null,
    supersededById: null,
    correctionReason: null,
  },
  {
    id: 2,
    targetType: "event",
    targetId: "EVT-000002",
    label: "uncertain",
    confidence: 0.4,
    comment: null,
    mitreTechniques: [],
    analyst: "analyst@aegisx.dev",
    source: "analyst",
    featureSchemaVersion: "1.0",
    modelIdentity: null,
    submittedAt: "2026-09-03T00:00:00Z",
    supersedesId: null,
    supersededById: null,
    correctionReason: null,
  },
];

const DRIFT: DriftStatusResponse = {
  features: [
    {
      id: 1,
      kind: "data",
      feature: "bytes_out",
      baselineLabel: "model-fit-window",
      windowLabel: "last-24h",
      metricName: "psi",
      metricValue: 0.4594,
      secondaryMetricName: "wasserstein",
      secondaryMetricValue: 14319.16,
      status: "significant",
      moderateThreshold: 0.1,
      significantThreshold: 0.25,
      referenceSamples: 500,
      currentSamples: 500,
      modelIdentity: "isolation_forest@1.0",
      measuredAt: "2026-09-03T00:00:00Z",
    },
  ],
  countsByStatus: { significant: 1 },
  interpretation:
    "These readings describe how the input distribution has moved. A changed "
    + "distribution is not evidence that the model has become wrong.",
};

const QUEUE: ReviewQueueResponse = {
  candidates: [],
  weights: { disagreement: 0.45, uncertainty: 0.35, novelty: 0.2 },
  interpretation: "These events are recommended for analyst review.",
};

const UNVALIDATED_PROPOSAL: Proposal = {
  id: 7,
  proposalType: "threshold_update",
  status: "pending",
  title: "Raise the anomaly threshold to 0.68",
  reason: "AI-assisted recommendation.",
  affectedComponent: "ml.anomaly_threshold",
  beforeState: { threshold: 0.65 },
  afterState: { threshold: 0.68 },
  evidence: {},
  validation: { status: "not_validated" },
  expectedImpact: {},
  riskAssessment: "Recall may fall on low-scoring true positives.",
  candidateModelId: null,
  feedbackDatasetId: null,
  proposedBy: "ai:stub",
  approvedBy: null,
  rejectedBy: null,
  deployedBy: null,
  rolledBackBy: null,
  selfApproved: false,
  rejectionReason: null,
  rollbackReason: null,
  rollbackState: {},
  createdAt: "2026-09-03T00:00:00Z",
  approvedAt: null,
  deployedAt: null,
  rolledBackAt: null,
};

beforeEach(() => {
  vi.clearAllMocks();
  fetchFeedback.mockResolvedValue(FEEDBACK);
  fetchDriftStatus.mockResolvedValue(DRIFT);
  fetchReviewQueue.mockResolvedValue(QUEUE);
  fetchProposals.mockResolvedValue([UNVALIDATED_PROPOSAL]);
});

describe("AdaptivePage", () => {
  it("states that the platform cannot apply an adaptation by itself", async () => {
    renderWithProviders(<AdaptivePage />);
    expect(await screen.findByText(/It cannot apply one/i)).toBeInTheDocument();
  });

  it("summarises drift without calling it a model failure", async () => {
    renderWithProviders(<AdaptivePage />);
    expect(
      await screen.findByText(/distribution changed — not a model failure/i),
    ).toBeInTheDocument();
  });

  it("renders the backend's drift interpretation verbatim", async () => {
    const user = userEvent.setup();
    renderWithProviders(<AdaptivePage />);
    await user.click(await screen.findByRole("button", { name: "Drift" }));
    expect(
      await screen.findByText(/not evidence that the model has become wrong/i),
    ).toBeInTheDocument();
  });

  it("shows the threshold bands beside a drift verdict", async () => {
    const user = userEvent.setup();
    renderWithProviders(<AdaptivePage />);
    await user.click(await screen.findByRole("button", { name: "Drift" }));
    expect(await screen.findByText("0.10 / 0.25")).toBeInTheDocument();
  });

  it("renders an unstated confidence as n/a, never as zero", async () => {
    const user = userEvent.setup();
    renderWithProviders(<AdaptivePage />);
    await user.click(await screen.findByRole("button", { name: "Feedback" }));
    expect(await screen.findByText("n/a")).toBeInTheDocument();
  });

  it("marks labels that can never enter a training set", async () => {
    const user = userEvent.setup();
    renderWithProviders(<AdaptivePage />);
    await user.click(await screen.findByRole("button", { name: "Feedback" }));
    expect(await screen.findByText("not trainable")).toBeInTheDocument();
  });

  it("warns on the proposal's face when it has not been validated", async () => {
    const user = userEvent.setup();
    renderWithProviders(<AdaptivePage />);
    await user.click(await screen.findByRole("button", { name: "Proposals" }));
    expect(
      await screen.findByText(/Not validated — no evaluation has been run/i),
    ).toBeInTheDocument();
  });

  it("marks an AI-drafted proposal as advisory", async () => {
    const user = userEvent.setup();
    renderWithProviders(<AdaptivePage />);
    await user.click(await screen.findByRole("button", { name: "Proposals" }));
    expect(await screen.findByText(/AI-drafted — advisory only/i)).toBeInTheDocument();
  });
});
