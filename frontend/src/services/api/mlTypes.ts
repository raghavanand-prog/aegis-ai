/**
 * V3 wire types: ML, correlation, threat intelligence and AI.
 *
 * Field names deliberately mirror the backend's, including the ones that exist
 * to stop a number being misread. `anomalyScore` is a ranking; `scoreKind`
 * says so; an AI `confidence` is the model's own stated confidence and is not
 * calibrated. The UI is written against these names so it cannot quietly
 * present one as another.
 */

import type { Severity } from "./types";

// --------------------------------------------------------------------- ML
export interface ApiFeatureContribution {
  name: string;
  value: number;
  /** Standard deviations from the training mean. Signed. */
  deviation: number;
  direction: "above" | "below";
}

export interface ApiMLFinding {
  eventId: string;
  model: string;
  modelVersion: string;
  featureSchemaVersion: string;
  /** 0..1 ranking from an unsupervised model. NOT a probability. */
  anomalyScore: number;
  scoreKind: string;
  isAnomaly: boolean;
  threshold: number;
  topContributors: ApiFeatureContribution[];
  latencyMs: number;
  inferredAt: string;
}

export interface ApiMLStatus {
  enabled: boolean;
  available: boolean;
  modelName: string;
  modelVersion: string | null;
  featureSchemaVersion: string;
  featureCount: number;
  threshold: number;
  loadedAt: string | null;
  eventsScored: number;
  anomaliesFlagged: number;
  failures: number;
  /** Plain-language explanation whenever `available` is false. */
  reason: string | null;
  context: Record<string, number>;
}

export interface ApiMLModel {
  id: number;
  name: string;
  version: string;
  identity: string;
  modelType: string;
  featureSchemaVersion: string;
  datasetVersion: string;
  datasetFingerprint: string | null;
  trainingSamples: number;
  parameters: Record<string, unknown>;
  metrics: Record<string, unknown>;
  featureNames: string[];
  featureCount: number;
  artifactName: string;
  artifactSha256: string | null;
  status: "active" | "archived" | "failed";
  notes: string | null;
  createdBy: string;
  trainedAt: string | null;
  activatedAt: string | null;
}

export interface ApiMLModelList {
  models: ApiMLModel[];
  active: ApiMLModel | null;
  previous: ApiMLModel | null;
  total: number;
}

export interface ApiEventMLFindings {
  eventId: string;
  modelAvailable: boolean;
  reason: string | null;
  riskScore: number;
  riskLevel: Severity;
  riskSignals: ApiRiskSignal[];
  findings: Array<Omit<ApiMLFinding, "eventId"> & { featuresUsed: string[] }>;
}

// ------------------------------------------------------------------- risk
export type RiskSignalType =
  | "rule"
  | "ml"
  | "threat_intel"
  | "correlation"
  | "context";

export interface ApiRiskSignal {
  type: RiskSignalType;
  source: string;
  contribution: number;
  detail: string;
  metadata?: Record<string, unknown>;
}

export interface ApiScoringStrategy {
  version: string;
  weights: Record<string, unknown>;
  bands: { low: number; medium: number; high: number; critical: number };
  notes: string[];
}

// ----------------------------------------------------------- threat intel
export type IntelReputation = "malicious" | "suspicious" | "harmless" | "unknown";
export type IntelStatus =
  | "ok"
  | "not_found"
  | "rate_limited"
  | "timeout"
  | "error"
  | "unavailable";

export interface ApiThreatIntel {
  provider: string;
  iocType: string;
  iocValue: string;
  status: IntelStatus;
  reputation: IntelReputation;
  confidence: number;
  maliciousCount: number;
  suspiciousCount: number;
  harmlessCount: number;
  undetectedCount: number;
  lastAnalysisAt: string | null;
  lookedUpAt: string | null;
  expiresAt: string | null;
  error: string | null;
  details: Record<string, unknown>;
  /** True only when a verdict was actually obtained. */
  isActionable: boolean;
}

export interface ApiThreatIntelStatus {
  enabled: boolean;
  provider: string;
  configured: boolean;
  supports: string[];
  cacheTtlHours: number;
  failureRetryMinutes: number;
  budget: { day: string | null; used: number; limit: number; remaining: number };
}

// --------------------------------------------------------------- sequences
export type TechniqueProvenance = "mapped" | "inferred" | "contextual";

export interface ApiTechnique {
  technique: string;
  provenance: TechniqueProvenance;
  source: string;
  detail: string;
}

export interface ApiSequenceEvent {
  id: string;
  timestamp: string;
  source: string;
  eventType: string;
  title: string;
  severity: Severity;
  riskScore: number;
  hostname: string | null;
  username: string | null;
  sourceIp: string | null;
  isAnomaly: boolean;
}

export interface ApiSequence {
  id: string;
  title: string;
  description: string;
  pattern: string;
  correlationKey: string;
  severity: Severity;
  status: "Open" | "Promoted" | "Dismissed";
  riskScore: number;
  /** Correlation confidence, 0..1. Not a probability of compromise. */
  confidence: number;
  startTime: string;
  endTime: string;
  eventCount: number;
  techniques: ApiTechnique[];
  entities: Record<string, string[]>;
  rationale: string[];
  riskSignals: ApiRiskSignal[];
  incidentId: string | null;
  eventIds: string[];
  createdAt: string | null;
  updatedAt: string | null;
  events?: ApiSequenceEvent[];
}

export interface ApiCorrelationPattern {
  id: string;
  name: string;
  description: string;
  minEvents: number;
  inferredTechniques: string[];
}

// --------------------------------------------------------------------- AI
export type AIConfidence =
  | "high"
  | "medium"
  | "low"
  | "insufficient_evidence"
  | "unknown";

export interface ApiAIEvidenceRef {
  claim: string;
  evidenceRef: string;
}

export interface ApiAITechniqueClaim {
  technique: string;
  provenance: string;
  rationale: string;
}

export interface ApiAIAnalysis {
  id: number;
  kind: "analyze" | "explain" | "recommend";
  provider: string;
  model: string;
  promptVersion: string;
  analysisVersion: string;
  summary: string;
  whyItMatters: string;
  riskAssessment: string;
  likelyBehaviour: string;
  supportingEvidence: ApiAIEvidenceRef[];
  mitreTechniques: ApiAITechniqueClaim[];
  investigationSteps: string[];
  containmentActions: string[];
  /** The model's own stated confidence. Not calibrated. */
  confidence: AIConfidence;
  uncertainty: string;
  evidenceFingerprint: string;
  evidenceSummary: Record<string, number>;
  /** False when the answer cited evidence the package does not contain. */
  grounded: boolean;
  groundingWarnings: string[];
  latencyMs: number;
  tokensUsed: number;
  requestedBy: string;
  createdAt: string | null;
  generatedBy: "ai";
  isTemplateProvider: boolean;
  disclaimer: string;
}

export interface ApiAIStatus {
  enabled: boolean;
  available: boolean;
  provider: string;
  model?: string;
  reason: string | null;
  isTemplateProvider: boolean;
  sendsDataExternally: boolean;
  promptVersion: string;
  analysisVersion: string;
  maxEvidenceEvents?: number;
  budget: { day: string | null; used: number; limit: number; remaining: number };
}

export interface ApiAIAnalysisList {
  incidentId: string;
  total: number;
  analyses: ApiAIAnalysis[];
  status: ApiAIStatus;
}

// ------------------------------------------------------------- analytics
export interface ApiMLAnalytics {
  modelAvailable: boolean;
  modelName: string | null;
  modelVersion: string | null;
  featureSchemaVersion: string | null;
  reason: string | null;
  threshold: number | null;
  totalScoredEvents: number;
  anomaliesDetected: number;
  anomalyRate: number | null;
  mlAssistedIncidents: number;
  anomaliesCorrelated: number;
  anomaliesBySource: { key: string; count: number }[];
  anomaliesBySeverity: { key: string; count: number }[];
  anomaliesOverTime: { bucket: string; count: number; critical: number; high: number }[];
  scoreDistribution: { key: string; count: number }[];
  detectionOverlap: { mlOnly?: number; ruleAndMl?: number; ruleOnly?: number };
}

export interface ApiCorrelationAnalytics {
  enabled: boolean;
  totalSequences: number;
  openSequences: number;
  promotedSequences: number;
  sequencesByPattern: { key: string; count: number }[];
  meanConfidence: number | null;
}

export interface ApiThreatIntelAnalytics {
  enabled: boolean;
  provider: string;
  configured: boolean;
  totalLookups: number;
  malicious: number;
  suspicious: number;
  harmless: number;
  unknown: number;
  /** Lookups that produced no verdict. Not the same as "clean". */
  failedLookups: number;
}
