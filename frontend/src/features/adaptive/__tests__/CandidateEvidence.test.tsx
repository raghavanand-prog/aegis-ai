import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import type { Proposal } from "@/services/api/adaptation";

import CandidateEvidence from "../components/CandidateEvidence";

/**
 * The V6 evidence an approver could not see.
 *
 * V6 recorded `rocAuc`, `perCategory` and the dataset identity on every
 * validated proposal and surfaced none of it: "Three new evidence blocks are
 * recorded on candidates and invisible to approvers." These tests hold the
 * three properties that make the panel worth having rather than decorative.
 */

const BASE: Proposal = {
  id: 12,
  proposalType: "model_update",
  status: "pending",
  title: "Promote candidate isolation_forest@v7",
  reason: "Feedback-augmented candidate.",
  affectedComponent: "ml.anomaly_model",
  beforeState: { model: "v6" },
  afterState: { model: "v7" },
  evidence: { feedbackIds: [1, 2] },
  validation: {},
  expectedImpact: {},
  riskAssessment: null,
  candidateModelId: 44,
  feedbackDatasetId: 9,
  proposedBy: "analyst@aegisx.dev",
  approvedBy: null,
  rejectedBy: null,
  deployedBy: null,
  rolledBackBy: null,
  proposedByRole: "analyst",
  approvedByRole: null,
  rejectedByRole: null,
  selfApproved: false,
  rejectionReason: null,
  rollbackReason: null,
  rollbackState: {},
  createdAt: "2026-09-04T00:00:00Z",
  approvedAt: null,
  rejectedAt: null,
  deployedAt: null,
  rolledBackAt: null,
};

function withValidation(validation: Record<string, unknown>): Proposal {
  return { ...BASE, validation };
}

const FULL = withValidation({
  rocAuc: { candidate: 0.9312, baseline: 0.8974 },
  perCategory: {
    credential_access: {
      maliciousSamples: 41,
      candidateRecall: 0.7805,
      baselineRecall: 0.5854,
    },
    ransomware_behavior: {
      maliciousSamples: 30,
      candidateRecall: 0.9667,
      baselineRecall: 0.9667,
    },
    data_exfiltration: {
      maliciousSamples: 22,
      candidateRecall: 0.5,
      baselineRecall: 0.6364,
    },
  },
  dataset: {
    name: "telemetry-labelled",
    version: "1.0",
    fingerprint: "a1b2c3d4e5f60718",
    samples: 6000,
    malicious: 600,
  },
  threshold: 0.65,
  gates: { passed: true },
});

describe("CandidateEvidence", () => {
  it("says plainly when nothing was measured", () => {
    render(<CandidateEvidence proposal={withValidation({})} />);

    expect(screen.getByText(/Nothing here was measured/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /show evidence/i })).toBeNull();
  });

  it("leads with the threshold-free measure", async () => {
    render(<CandidateEvidence proposal={FULL} />);
    await userEvent.click(screen.getByRole("button", { name: /show evidence/i }));

    // V6 §14: a fixed threshold is not comparable between models fitted on
    // different data, so AUC is what an approver should compare on first.
    expect(screen.getByText(/Discrimination \(threshold-free\)/i)).toBeInTheDocument();
    expect(screen.getByText("0.9312")).toBeInTheDocument();
    expect(screen.getByText("0.8974")).toBeInTheDocument();
    expect(screen.getByText(/ΔAUC \+0\.0338/)).toBeInTheDocument();
  });

  it("shows a per-category regression the aggregate would hide", async () => {
    render(<CandidateEvidence proposal={FULL} />);
    await userEvent.click(screen.getByRole("button", { name: /show evidence/i }));

    // AUC rose overall, and data_exfiltration recall fell 0.1364. That is the
    // shape of a targeted attack, and an approver who saw only the summary
    // could not see it.
    expect(screen.getByText("data_exfiltration")).toBeInTheDocument();
    expect(screen.getByText("-0.1364")).toBeInTheDocument();
    expect(screen.getByText("+0.1951")).toBeInTheDocument();
  });

  it("states the corpus identity beside the numbers", async () => {
    render(<CandidateEvidence proposal={FULL} />);
    await userEvent.click(screen.getByRole("button", { name: /show evidence/i }));

    // V6's second standing rule: state a corpus's contamination and prevalence
    // before quoting any metric on it.
    expect(screen.getByText("telemetry-labelled@1.0")).toBeInTheDocument();
    expect(screen.getByText("a1b2c3d4e5f60718")).toBeInTheDocument();
    expect(screen.getByText("600/6000")).toBeInTheDocument();
  });

  it("renders an unmeasured metric as unavailable rather than zero", async () => {
    render(
      <CandidateEvidence
        proposal={withValidation({
          rocAuc: { candidate: 0.91, baseline: null },
          dataset: { name: "telemetry-labelled", version: "1.0" },
        })}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: /show evidence/i }));

    // V4's rule: a metric that was not measured is never reported as zero.
    expect(screen.getByText("0.9100")).toBeInTheDocument();
    expect(screen.getByText(/ΔAUC —/)).toBeInTheDocument();
  });

  it("starts collapsed so the queue stays readable", () => {
    render(<CandidateEvidence proposal={FULL} />);

    expect(screen.getByRole("button", { name: /show evidence/i })).toHaveAttribute(
      "aria-expanded",
      "false",
    );
    expect(screen.queryByText("data_exfiltration")).toBeNull();
  });
});
