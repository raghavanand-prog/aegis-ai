/**
 * Controlled adaptation endpoints (V5).
 *
 * Two rules shape every type here.
 *
 * **Nothing in this module can train a model.** There is no client function for
 * it because there is no endpoint - training is minutes of CPU and belongs to an
 * operator at a CLI, exactly as running an experiment does.
 *
 * **A drift reading is not a verdict on the model.** Every drift response
 * carries an `interpretation` string written by the backend, and the UI renders
 * it verbatim rather than paraphrasing it into something more alarming.
 */

import { api } from "./client";

export type FeedbackLabel =
  | "true_positive"
  | "false_positive"
  | "benign"
  | "suspicious"
  | "confirmed_malicious"
  | "uncertain";

export type ProposalStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "deployed"
  | "rolled_back"
  | "superseded";

export interface Feedback {
  id: number;
  targetType: string;
  targetId: string;
  label: FeedbackLabel;
  /** Null means the analyst stated no confidence. Never render it as 0. */
  confidence: number | null;
  comment: string | null;
  mitreTechniques: string[];
  analyst: string;
  source: string;
  featureSchemaVersion: string;
  modelIdentity: string | null;
  submittedAt: string;
  supersedesId: number | null;
  supersededById: number | null;
  correctionReason: string | null;
}

export interface DriftMeasurement {
  id: number;
  kind: "data" | "prediction" | "concept";
  feature: string;
  baselineLabel: string;
  windowLabel: string;
  metricName: string;
  metricValue: number;
  secondaryMetricName: string | null;
  secondaryMetricValue: number | null;
  status: "stable" | "moderate" | "significant";
  /** The bands that produced `status`. A verdict without them is unreadable. */
  moderateThreshold: number;
  significantThreshold: number;
  referenceSamples: number;
  currentSamples: number;
  modelIdentity: string | null;
  measuredAt: string;
}

export interface DriftStatusResponse {
  features: DriftMeasurement[];
  countsByStatus: Record<string, number>;
  /** Rendered verbatim. Written by the backend, never paraphrased here. */
  interpretation: string;
}

export interface ReviewCandidate {
  eventId: string;
  title: string;
  priority: number;
  reason: string;
  signals: Record<string, number>;
  anomalyScore: number | null;
  threshold: number | null;
  ruleHit: boolean;
  mlFlagged: boolean;
  riskScore: number;
}

export interface ReviewQueueResponse {
  candidates: ReviewCandidate[];
  weights: Record<string, number>;
  interpretation: string;
}

export interface FeedbackDataset {
  id: number;
  name: string;
  version: string;
  fingerprint: string;
  sampleCount: number;
  labelDistribution: Record<string, number>;
  featureSchemaVersion: string;
  createdBy: string;
  createdAt: string;
  notes: string | null;
}

export interface Proposal {
  id: number;
  proposalType: string;
  status: ProposalStatus;
  title: string;
  reason: string;
  affectedComponent: string;
  beforeState: Record<string, unknown>;
  afterState: Record<string, unknown>;
  evidence: Record<string, unknown>;
  validation: Record<string, unknown>;
  expectedImpact: Record<string, unknown>;
  riskAssessment: string | null;
  candidateModelId: number | null;
  feedbackDatasetId: number | null;
  proposedBy: string;
  approvedBy: string | null;
  rejectedBy: string | null;
  deployedBy: string | null;
  rolledBackBy: string | null;
  /**
   * V7. The role each actor held when they acted — the authority a decision was
   * made under, not the authority its author holds today. Null on rows written
   * before V7, which is a fact about them rather than a gap.
   */
  proposedByRole: string | null;
  approvedByRole: string | null;
  rejectedByRole: string | null;
  /**
   * Always false for anything approved from V7 onwards: `proposals.approve`
   * refuses a self-approval rather than flagging it. Still rendered, because
   * rows approved before V7 may carry true and an approver reading old history
   * should see what actually happened.
   */
  selfApproved: boolean;
  rejectionReason: string | null;
  rollbackReason: string | null;
  rollbackState: Record<string, unknown>;
  createdAt: string;
  approvedAt: string | null;
  /** V7. Every other terminal decision recorded its time; rejection did not. */
  rejectedAt: string | null;
  deployedAt: string | null;
  rolledBackAt: string | null;
}

export async function fetchFeedback(params: { limit?: number } = {}) {
  const { data } = await api.get<Feedback[]>("/adaptation/feedback", { params });
  return data;
}

export async function fetchDriftStatus() {
  const { data } = await api.get<DriftStatusResponse>("/adaptation/drift");
  return data;
}

export async function fetchDriftHistory(feature: string) {
  const { data } = await api.get<DriftMeasurement[]>("/adaptation/drift/history", {
    params: { feature },
  });
  return data;
}

export async function fetchReviewQueue(limit = 25) {
  const { data } = await api.get<ReviewQueueResponse>("/adaptation/review-queue", {
    params: { limit },
  });
  return data;
}

export async function fetchFeedbackDatasets() {
  const { data } = await api.get<FeedbackDataset[]>("/adaptation/datasets");
  return data;
}

export async function fetchProposals(params: { status?: ProposalStatus } = {}) {
  const { data } = await api.get<Proposal[]>("/adaptation/proposals", { params });
  return data;
}

export async function approveProposal(id: number) {
  const { data } = await api.post<Proposal>(`/adaptation/proposals/${id}/approve`);
  return data;
}

export async function rejectProposal(id: number, reason: string) {
  const { data } = await api.post<Proposal>(`/adaptation/proposals/${id}/reject`, { reason });
  return data;
}

export async function deployProposal(id: number) {
  const { data } = await api.post<Proposal>(`/adaptation/proposals/${id}/deploy`);
  return data;
}

export async function rollbackProposal(id: number, reason: string) {
  const { data } = await api.post<Proposal>(`/adaptation/proposals/${id}/rollback`, { reason });
  return data;
}
