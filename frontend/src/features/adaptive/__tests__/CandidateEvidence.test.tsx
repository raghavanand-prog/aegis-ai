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
  augmentation: null,
  augmentationStatus: "not_recorded",
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

/**
 * V8: the provenance an approver still could not see.
 *
 * V6 recorded `actorCounts`, `groupCounts` and `baselineAssessment` on the
 * candidate *model's* parameters and the V7 handoff closed by naming it as
 * outstanding: the evidence panel covered the evaluation blocks only. So an
 * approver could see how a candidate *scored* and not what it was *trained
 * on* — which is the half an adversary controls.
 */
describe("CandidateEvidence — augmentation provenance", () => {
  const AUGMENTED: Proposal = {
    ...FULL,
    augmentationStatus: "recorded",
    augmentation: {
      admitted: 42,
      capPolicy: "baseline_relative",
      actorCapPolicy: null,
      datasetFingerprint: "9f8e7d6c5b4a3021",
      actorCounts: { "mallory@aegisx.dev": 33, "chidi@aegisx.dev": 9 },
      groupCounts: { authentication: 30, process: 12 },
      baselineAssessment: { flagged: ["authentication"], findings: {} },
      skipped: {
        byCap: 118,
        notBenign: 4,
        nonEvent: 0,
        noInference: 2,
        incompleteVector: 1,
      },
    },
  };

  it("shows who the fit set came from", async () => {
    render(<CandidateEvidence proposal={AUGMENTED} />);
    await userEvent.click(screen.getByRole("button", { name: /show evidence/i }));

    // One actor supplying 33 of 42 admitted rows is the shape a compromised
    // account makes. The cap bounds it; the panel is what makes it visible.
    expect(screen.getByText(/Trained on — feedback admitted/i)).toBeInTheDocument();
    expect(screen.getByText("mallory@aegisx.dev")).toBeInTheDocument();
    expect(screen.getByText("33")).toBeInTheDocument();
    expect(screen.getByText("78.6%")).toBeInTheDocument();
  });

  it("surfaces a flagged baseline rather than leaving it advisory and unseen", async () => {
    render(<CandidateEvidence proposal={AUGMENTED} />);
    await userEvent.click(screen.getByRole("button", { name: /show evidence/i }));

    expect(screen.getByText(/Flagged: authentication/)).toBeInTheDocument();
    expect(screen.getByText(/blocks nothing/i)).toBeInTheDocument();
  });

  it("reports what the cap refused", async () => {
    render(<CandidateEvidence proposal={AUGMENTED} />);
    await userEvent.click(screen.getByRole("button", { name: /show evidence/i }));

    expect(screen.getByText(/Not admitted/i)).toBeInTheDocument();
    expect(screen.getByText("118")).toBeInTheDocument();
  });

  it("distinguishes 'no model to describe' from 'nobody recorded it'", async () => {
    // These are opposite facts and one shared dash would hide both.
    const noModel: Proposal = {
      ...FULL,
      augmentation: null,
      augmentationStatus: "no_candidate_model",
    };
    const { unmount } = render(<CandidateEvidence proposal={noModel} />);
    await userEvent.click(screen.getByRole("button", { name: /show evidence/i }));
    expect(screen.getByText(/does not train a model/i)).toBeInTheDocument();
    unmount();

    const notRecorded: Proposal = {
      ...FULL,
      augmentation: null,
      augmentationStatus: "not_recorded",
    };
    render(<CandidateEvidence proposal={notRecorded} />);
    await userEvent.click(screen.getByRole("button", { name: /show evidence/i }));
    expect(screen.getByText(/fitted on telemetry alone/i)).toBeInTheDocument();
  });

  it("opens the panel for a proposal whose candidate model has vanished", async () => {
    // The most important thing an approver can be told about this proposal is
    // that it is unevidenced. Hiding the panel would present it as ordinary.
    const orphaned: Proposal = {
      ...BASE,
      augmentation: null,
      augmentationStatus: "candidate_model_unavailable",
    };
    render(<CandidateEvidence proposal={orphaned} />);

    await userEvent.click(screen.getByRole("button", { name: /show evidence/i }));
    expect(screen.getByText(/no longer be read/i)).toBeInTheDocument();
  });
});
